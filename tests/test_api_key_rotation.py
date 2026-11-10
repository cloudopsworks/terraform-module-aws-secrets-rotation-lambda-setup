"""Offline tests for the OpenAI/OpenRouter rotation Lambda."""

import importlib.util
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


SOURCE = Path(__file__).resolve().parents[1] / "lambda_code/api_keys/single/lambda_function.py"
sys.path.insert(0, str(SOURCE.parent))
sys.modules.setdefault("boto3", types.SimpleNamespace(client=lambda name: None))
spec = importlib.util.spec_from_file_location("api_key_rotation", SOURCE)
rotation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rotation)
openai_keys = rotation.openai_keys
openrouter_keys = rotation.openrouter_keys
http_api = sys.modules["http_api"]


class NotFound(Exception):
    pass


class FakeSecrets:
    exceptions = types.SimpleNamespace(ResourceNotFoundException=NotFound)

    def __init__(self):
        self.values = {"current": {"api_key": "old-workload", "api_key_id": "old-id",
                                   "project_id": "proj_123", "service_account_id": "svc_456",
                                   "scopes": ["api.model.read"], "name": "worker-token-12"}}
        self.stages = {"current": ["AWSCURRENT"], "token-123456789": ["AWSPENDING"]}
        self.management = json.dumps({"api_key": "management-credential"})
        self.fail_put = False
        self.fail_pending_put = False
        self.fail_put_after_commit = False
        self.fail_pending_read_after_put = False
        self.put_attempted = False
        self.promote_on_put = False
        self.get_calls = []
        self.stage_updates = []
        self.fail_pending_removal = False
        self.fail_pending_removal_after_commit = False
        self.rotation_enabled = True
        self.rotation_rules = {"ScheduleExpression": "rate(1 day)"}
        self.deleted_date = None
        self.arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:target-secret-ABC123"
        self.name = "target-secret"
        self.fail_config_reads = False
        self.put_calls = []

    def describe_secret(self, **kwargs):
        return {"ARN": self.arn, "Name": self.name, "DeletedDate": self.deleted_date,
                "RotationEnabled": self.rotation_enabled, "RotationRules": self.rotation_rules,
                "VersionIdsToStages": self.stages}

    def get_secret_value(self, SecretId, VersionId=None, VersionStage=None):
        self.get_calls.append((SecretId, VersionId, VersionStage))
        if SecretId == "management-secret":
            return {"SecretString": self.management}
        if VersionStage == "TFCONFIG" and self.fail_config_reads:
            raise NotFound()
        if self.put_attempted and self.fail_pending_read_after_put and VersionId == "token-123456789":
            raise RuntimeError("AWS read unavailable")
        if VersionStage == "AWSPREVIOUS":
            version = next((name for name, stages in self.stages.items() if "AWSPREVIOUS" in stages), None)
        elif VersionId:
            version = VersionId
        else:
            version = next((name for name, stages in self.stages.items() if VersionStage in stages), None)
        if version not in self.values or (VersionStage and VersionStage not in self.stages.get(version, [])):
            raise NotFound()
        return {"SecretString": json.dumps(self.values[version]), "VersionId": version}

    def put_secret_value(self, **kwargs):
        self.put_attempted = True
        self.put_calls.append(kwargs)
        if self.fail_put:
            raise RuntimeError("AWS failure exposing secret")
        if self.fail_pending_put and kwargs.get("VersionStages") == ["AWSPENDING"]:
            raise RuntimeError("AWS pending write failed")
        version = kwargs["ClientRequestToken"]
        value = json.loads(kwargs["SecretString"])
        if version in self.values:
            if self.values[version] != value:
                raise ValueError("Secret version is immutable")
            return  # AWS treats the same token and payload as an idempotent no-op.
        self.values[version] = value
        for stage in kwargs.get("VersionStages", []):
            for stages in self.stages.values():
                if stage in stages:
                    stages.remove(stage)
            if stage not in self.stages.setdefault(version, []):
                self.stages[version].append(stage)
        if self.promote_on_put:
            self.stages["current"] = ["AWSPREVIOUS"]
            self.stages[version] = ["AWSCURRENT"]
        if self.fail_put_after_commit:
            raise RuntimeError("AWS timeout after commit")

    def update_secret_version_stage(self, **kwargs):
        self.stage_updates.append(kwargs)
        if "MoveToVersionId" not in kwargs:
            assert "MoveToVersionId" not in kwargs
            version = kwargs["RemoveFromVersionId"]
            stage = kwargs["VersionStage"]
            if stage not in self.stages.get(version, []):
                raise NotFound()
            if stage == "AWSPENDING" and self.fail_pending_removal:
                raise RuntimeError("pending removal failed before commit")
            self.stages[version].remove(stage)
            if stage == "AWSPENDING" and self.fail_pending_removal_after_commit:
                raise RuntimeError("pending removal failed after commit")
            return
        assert kwargs["VersionStage"] == "AWSCURRENT"
        current = kwargs["RemoveFromVersionId"]
        pending = kwargs["MoveToVersionId"]
        for stages in self.stages.values():
            if "AWSPREVIOUS" in stages:
                stages.remove("AWSPREVIOUS")
        self.stages[current].remove("AWSCURRENT")
        self.stages[current].append("AWSPREVIOUS")
        self.stages[pending].append("AWSCURRENT")


class RotationTests(unittest.TestCase):
    OMITTED_KEY_FIELDS = ("rotation", "limit", "limit_reset", "include_byok_in_limit", "creator_user_id")

    def assert_omits_rotation_metadata(self, secret):
        for field in self.OMITTED_KEY_FIELDS:
            with self.subTest(field=field):
                self.assertNotIn(field, secret)



    def pending(self, **changes):
        current = self.secrets.values["current"]
        if os.environ["API_PROVIDER"] == "openrouter":
            value = {
                "api_key": "pending", "api_key_id": "new-id",
                "name": current.get("name"), "workspace_id": current.get("workspace_id"),
            }
        else:
            value = {**current, "api_key": "pending", "api_key_id": "new-id"}
            value.pop("rotation", None)
        value.update(changes)
        return value

    def setUp(self):
        self.secrets = FakeSecrets()
        self.event = {"SecretId": "target-secret", "ClientRequestToken": "token-123456789", "Step": "createSecret"}
        self.env = patch.dict(os.environ, {
            "API_PROVIDER": "openai",
            "MANAGEMENT_SECRET_ARN": "management-secret",
            "OPENAI_PROJECT_ID": "proj_123",
            "OPENAI_SERVICE_ACCOUNT_ID": "svc_456",
            "ROTATION_KEY_NAME": "worker",
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_openai_create_uses_service_account_and_persists_pending(self):
        self.secrets.values["current"]["rotation"] = {
            "previous_version_id": "obsolete", "previous_api_key_id": "obsolete-id",
        }
        calls = []

        def api(method, url, key, payload=None, **kwargs):
            calls.append((method, url, key, payload))
            return {"value": "new-workload", "id": "new-id"}

        with patch.object(openai_keys, "call_api", side_effect=api):
            rotation.rotate(self.event, self.secrets)
            rotation.rotate(self.event, self.secrets)  # no second upstream key
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], (
            "POST", "https://api.openai.com/v1/organization/projects/proj_123/service_accounts/svc_456/api_keys",
            "management-credential", {"name": "worker-token-12", "scopes": ["api.model.read"]},
        ))
        self.assertEqual(self.secrets.values["token-123456789"], {
            "api_key": "new-workload", "api_key_id": "new-id",
            "project_id": "proj_123", "service_account_id": "svc_456", "scopes": ["api.model.read"],
            "name": "worker-token-12",
        })

    def test_openai_uses_configured_provider_without_secret_field(self):
        self.secrets.values["current"]["provider"] = "openrouter"  # Legacy field is inert.
        with patch.object(openai_keys, "call_api", return_value={"value": "new-workload", "id": "new-id"}):
            rotation.rotate(self.event, self.secrets)
        self.assertNotIn("provider", self.secrets.values["token-123456789"])


    def test_openai_create_passes_scopes_and_expiration(self):
        os.environ["OPENAI_KEY_OPTIONS_JSON"] = json.dumps({
            "scopes": ["api.model.write"], "expires_in_seconds": 86400, "name": "ignored",
        })
        with patch.object(openai_keys, "call_api", return_value={"value": "new", "id": "new-id"}) as api:
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(api.call_args.args[3], {
            "scopes": ["api.model.read"], "expires_in_seconds": 86400,
            "name": "worker-token-12",
        })

    def test_openai_uses_secret_name_and_scopes_but_not_old_expiration(self):
        self.secrets.values["current"].update(
            name="original-service-key", scopes=["api.model.read", "api.model.write"],
            expires_in_seconds=20,
        )
        os.environ["OPENAI_KEY_OPTIONS_JSON"] = '{"scopes":["api.model.read"],"expires_in_seconds":86400}'
        with patch.object(openai_keys, "call_api", return_value={"value": "new", "id": "new-id"}) as api:
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(api.call_args.args[3], {
            "name": "original-service-key", "scopes": ["api.model.read", "api.model.write"],
            "expires_in_seconds": 86400,
        })
        pending = self.secrets.values["token-123456789"]
        self.assertEqual(pending["name"], "original-service-key")
        self.assertEqual(pending["scopes"], ["api.model.read", "api.model.write"])
        self.assertNotIn("expires_in_seconds", pending)

    def test_openai_requires_recorded_scopes_before_key_creation(self):
        del self.secrets.values["current"]["scopes"]
        with patch.object(openai_keys, "create_key") as create:
            with self.assertRaisesRegex(ValueError, "record its scopes"):
                rotation.rotate(self.event, self.secrets)
        create.assert_not_called()

    def test_openai_requires_recorded_name_before_key_creation(self):
        del self.secrets.values["current"]["name"]
        with patch.object(openai_keys, "create_key") as create:
            with self.assertRaisesRegex(ValueError, "record its name"):
                rotation.rotate(self.event, self.secrets)
        create.assert_not_called()

















    def test_second_rotation_uses_current_stage_without_persisting_predecessor(self):
        with patch.object(openai_keys, "create_key", side_effect=[
            ("first-workload", "first-id"), ("second-workload", "second-id"),
        ]), patch.object(openai_keys, "delete_key"):
            rotation.rotate(self.event, self.secrets)
            self.event["Step"] = "finishSecret"
            rotation.rotate(self.event, self.secrets)
            self.secrets.stages["token-234567890"] = ["AWSPENDING"]
            self.event["ClientRequestToken"] = "token-234567890"
            self.event["Step"] = "createSecret"
            rotation.rotate(self.event, self.secrets)

        second = self.secrets.values["token-234567890"]
        self.assertEqual(second["api_key_id"], "second-id")
        self.assert_omits_rotation_metadata(second)
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])

    def test_create_requires_seeded_openai_binding_and_rejects_configuration_drift(self):
        self.secrets.values["current"].pop("service_account_id")
        with patch.object(openai_keys, "create_key") as create:
            with self.assertRaisesRegex(ValueError, "missing its project or service account"):
                rotation.rotate(self.event, self.secrets)
        create.assert_not_called()
        self.secrets.values["current"]["service_account_id"] = "svc_456"
        os.environ["OPENAI_PROJECT_ID"] = "other-project"
        with patch.object(openai_keys, "create_key") as create:
            with self.assertRaisesRegex(ValueError, "binding differs"):
                rotation.rotate(self.event, self.secrets)
        create.assert_not_called()

    def test_test_rejects_openai_binding_drift_before_validation(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "testSecret"
        os.environ["OPENAI_SERVICE_ACCOUNT_ID"] = "other-account"
        with patch.object(openai_keys, "validate_key") as validate:
            with self.assertRaisesRegex(ValueError, "binding differs"):
                rotation.rotate(self.event, self.secrets)
        validate.assert_not_called()

    def test_test_step_validates_workload_key(self):
        self.secrets.values["token-123456789"] = self.pending(api_key_id="id")
        self.event["Step"] = "testSecret"
        with patch.object(openai_keys, "call_api", return_value={}) as api:
            rotation.rotate(self.event, self.secrets)
        api.assert_called_once_with("GET", "https://api.openai.com/v1/models", "pending")


    def test_finish_promotes_then_retires_old_key_and_retries_cleanup(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key", side_effect=[RuntimeError("temporary"), None]) as delete:
            with self.assertRaisesRegex(RuntimeError, "temporary"):
                rotation.rotate(self.event, self.secrets)
            self.assertEqual(self.secrets.stages["token-123456789"], ["AWSPENDING", "AWSCURRENT"])
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(delete.call_count, 2)
        delete.assert_called_with("management-credential", "old-id", "proj_123")
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])

    def test_finish_removes_only_pending_after_retiring_previous_key(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        def retire(*args):
            self.assertIn("AWSPENDING", self.secrets.stages["token-123456789"])
            self.assertEqual(len(self.secrets.stage_updates), 1)
        with patch.object(openai_keys, "delete_key", side_effect=retire) as delete:
            rotation.rotate(self.event, self.secrets)
        delete.assert_called_once()
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])
        self.assertEqual(self.secrets.stages["current"], ["AWSPREVIOUS"])
        self.assertEqual(self.secrets.stage_updates[-1], {
            "SecretId": "target-secret", "VersionStage": "AWSPENDING",
            "RemoveFromVersionId": "token-123456789",
        })

    def test_finish_retry_when_pending_label_already_absent(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.secrets.stages = {"current": ["AWSPREVIOUS"], "token-123456789": ["AWSCURRENT"]}
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key") as delete:
            rotation.rotate(self.event, self.secrets)
        delete.assert_called_once()
        self.assertEqual(self.secrets.stage_updates, [])
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])

    def test_finish_retries_pending_removal_failure_before_commit(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        self.secrets.fail_pending_removal = True
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(RuntimeError, "before commit"):
                rotation.rotate(self.event, self.secrets)
            self.assertEqual(self.secrets.stages["token-123456789"], ["AWSPENDING", "AWSCURRENT"])
            self.secrets.fail_pending_removal = False
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(delete.call_count, 2)
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])

    def test_finish_retries_pending_removal_failure_after_commit(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        self.secrets.fail_pending_removal_after_commit = True
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(RuntimeError, "after commit"):
                rotation.rotate(self.event, self.secrets)
            self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])
            self.secrets.fail_pending_removal_after_commit = False
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(delete.call_count, 2)
        self.assertEqual(len([call for call in self.secrets.stage_updates if call["VersionStage"] == "AWSPENDING"]), 1)

    def test_finish_does_not_remove_other_tokens_pending_label(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.secrets.stages = {
            "current": ["AWSPREVIOUS"], "token-123456789": ["AWSCURRENT"],
            "other-token": ["AWSPENDING"],
        }
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key"):
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(self.secrets.stages["other-token"], ["AWSPENDING"])
        self.assertEqual(self.secrets.stage_updates, [])

    def test_finish_rejects_current_drift_before_pending_cleanup(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.secrets.stages["other-token"] = []
        self.event["Step"] = "finishSecret"
        original_describe = self.secrets.describe_secret
        descriptions = 0
        def describe(**kwargs):
            nonlocal descriptions
            descriptions += 1
            if descriptions == 3:
                self.secrets.stages["token-123456789"].remove("AWSCURRENT")
                self.secrets.stages["other-token"] = ["AWSCURRENT", "AWSPENDING"]
            return original_describe(**kwargs)
        with patch.object(self.secrets, "describe_secret", side_effect=describe), \
             patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaises((ValueError, RuntimeError)):
                rotation.rotate(self.event, self.secrets)
        delete.assert_called_once()
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSPENDING"])
        self.assertEqual(self.secrets.stages["other-token"], ["AWSCURRENT", "AWSPENDING"])
        self.assertEqual(len([call for call in self.secrets.stage_updates if call["VersionStage"] == "AWSPENDING"]), 0)

    def test_finish_requires_current_stage_before_promotion(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.secrets.stages["current"] = []
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaises(NotFound):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSPENDING"])

    def test_finish_rejects_same_api_key_identifier(self):
        self.secrets.values["token-123456789"] = self.pending(api_key_id="old-id")
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "matches its predecessor"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])

    def test_finish_rejects_tampered_openai_scopes(self):
        self.secrets.values["token-123456789"] = self.pending(scopes=["api.model.write"])
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "binding differs"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])



    def test_finish_before_promotion_uses_stage_current_as_predecessor(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.secrets.values["other"] = {**self.secrets.values["current"], "api_key_id": "other-id"}
        self.secrets.stages["current"] = []
        self.secrets.stages["other"] = ["AWSCURRENT"]
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key") as delete:
            rotation.rotate(self.event, self.secrets)
        # Without a predecessor link, AWS's current stage is the sole authority.
        delete.assert_called_once_with("management-credential", "other-id", "proj_123")
        self.assertEqual(self.secrets.stages["other"], ["AWSPREVIOUS"])

    def test_finish_before_promotion_rejects_environment_drift(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        os.environ["OPENAI_PROJECT_ID"] = "other-project"
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "binding differs"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])

    def test_finish_ignores_legacy_provider_field_but_rejects_unidentified_previous_key(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        self.secrets.values["current"]["provider"] = "openrouter"
        with patch.object(openai_keys, "delete_key") as delete:
            rotation.rotate(self.event, self.secrets)
        delete.assert_called_once_with("management-credential", "old-id", "proj_123")
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])

        self.secrets.stages = {"current": ["AWSCURRENT"], "token-123456789": ["AWSPENDING"]}
        self.secrets.values["current"] = {"api_key": "old-workload"}
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "Key secret"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()

    def test_create_rejects_unidentified_or_unbound_current_key(self):
        self.secrets.values["current"].pop("api_key_id")
        with patch.object(openai_keys, "create_key") as create:
            with self.assertRaisesRegex(ValueError, "Key secret"):
                rotation.rotate(self.event, self.secrets)
        create.assert_not_called()
        self.secrets.values["current"] = {"api_key": "old", "api_key_id": "old-id"}
        with patch.object(openai_keys, "create_key") as create:
            with self.assertRaisesRegex(ValueError, "project or service account"):
                rotation.rotate(self.event, self.secrets)
        create.assert_not_called()

    def test_create_rejects_legacy_or_conflicting_id_field(self):
        self.secrets.values["current"]["key_id"] = "legacy-id"
        with patch.object(openai_keys, "create_key") as create:
            with self.assertRaisesRegex(ValueError, "Key secret"):
                rotation.rotate(self.event, self.secrets)
        create.assert_not_called()

    def test_failed_persistence_preserves_key_if_version_read_is_absent(self):
        self.secrets.fail_put = True
        with patch.object(openai_keys, "call_api", return_value={"value": "new-workload", "id": "new-id"}), \
             patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(RuntimeError, "Could not verify pending secret write"):
                rotation.rotate(self.event, self.secrets)
            delete.assert_not_called()
        self.assertIn(("target-secret", "token-123456789", None), self.secrets.get_calls)

    def test_handler_logs_only_safe_diagnostics(self):
        self.secrets.fail_put = True

        with patch.object(rotation.boto3, "client", return_value=self.secrets), \
             patch.object(openai_keys, "create_key", side_effect=RuntimeError("management-credential")):
            with self.assertLogs(rotation.LOG, level="ERROR") as logs:
                with self.assertRaisesRegex(RuntimeError, "^API key rotation failed$") as captured:
                    rotation.lambda_handler(self.event, None)
        self.assertNotIn("management-credential", str(captured.exception))
        self.assertNotIn("management-credential", " ".join(logs.output))
        self.assertIn("provider=openai step=createSecret error_type=RuntimeError", logs.output[0])

    def test_ambiguous_put_that_committed_keeps_new_key(self):
        self.secrets.fail_put_after_commit = True
        self.secrets.promote_on_put = True
        with patch.object(openai_keys, "create_key", return_value=("new-workload", "new-id")) as create, \
             patch.object(openai_keys, "delete_key") as delete:
            rotation.rotate(self.event, self.secrets)
            rotation.rotate(self.event, self.secrets)
        create.assert_called_once()
        delete.assert_not_called()
        self.assertEqual(self.secrets.values["token-123456789"]["api_key_id"], "new-id")
        self.assertIn(("target-secret", "token-123456789", None), self.secrets.get_calls)

    def test_finish_retry_rejects_missing_previous_stage(self):
        self.secrets.values["token-123456789"] = self.pending(api_key="new")
        self.secrets.stages = {"token-123456789": ["AWSCURRENT"]}
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaises((ValueError, NotFound)):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()

    def test_finish_retry_rejects_previous_stage_binding_drift(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.secrets.values["other"] = {
            **self.secrets.values["current"], "api_key_id": "other-id", "project_id": "other-project",
        }
        self.secrets.stages = {"token-123456789": ["AWSCURRENT"], "other": ["AWSPREVIOUS"]}
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "binding differs"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()

    def test_finish_rechecks_stages_before_old_key_retirement(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        original_describe = self.secrets.describe_secret
        calls = 0

        def describe(**kwargs):
            nonlocal calls
            calls += 1
            result = original_describe(**kwargs)
            if calls == 2:
                result = {**result, "VersionIdsToStages": {
                    **result["VersionIdsToStages"], "current": [],
                }}
            return result

        with patch.object(self.secrets, "describe_secret", side_effect=describe), \
             patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "stages changed"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSPENDING", "AWSCURRENT"])

    def test_finish_retry_rejects_stale_describe_snapshot(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        # Describe reports promotion, but GetSecretValue still identifies the
        # predecessor as AWSCURRENT. It must never be revoked in this state.
        with patch.object(self.secrets, "describe_secret", return_value={
            "RotationEnabled": True,
            "VersionIdsToStages": {"token-123456789": ["AWSCURRENT"]},
        }), patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaises((ValueError, NotFound)):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()

    def test_finish_retry_uses_persisted_project_when_environment_changes(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.secrets.stages = {"current": ["AWSPREVIOUS"], "token-123456789": ["AWSCURRENT"]}
        self.event["Step"] = "finishSecret"
        os.environ["OPENAI_PROJECT_ID"] = "other-project"
        with patch.object(openai_keys, "call_api", return_value={"deleted": True}) as api:
            rotation.rotate(self.event, self.secrets)
        self.assertIn("/projects/proj_123/api_keys/old-id", api.call_args.args[1])

    def test_audit_trace_contains_ids_but_not_credentials(self):
        with patch.object(openai_keys, "create_key", return_value=("new-workload", "new-id")), \
             self.assertLogs(rotation.LOG, level="INFO") as logs:
            rotation.rotate(self.event, self.secrets)
            self.event["Step"] = "finishSecret"
            with patch.object(openai_keys, "delete_key"):
                rotation.rotate(self.event, self.secrets)
        records = [json.loads(line.split("api_key_rotation ", 1)[1]) for line in logs.output]
        self.assertEqual([record["event"] for record in records],
                         ["issued", "pending_persisted", "promoted", "retired", "pending_cleared"])
        self.assertTrue(all("delivery" not in record for record in records))
        self.assertEqual(records[0]["api_key_id"], "new-id")
        self.assertEqual(records[0]["version_id"], "token-123456789")
        self.assertEqual(records[-2]["api_key_id"], "old-id")
        self.assertEqual(records[-1]["api_key_id"], "new-id")
        self.assertTrue(all(record["secret_id"] == "target-secret" and
                            record["project_id"] == "proj_123" and
                            record["service_account_id"] == "svc_456" for record in records))
        joined = " ".join(logs.output)
        for credential in ("new-workload", "old-workload", "management-credential"):
            self.assertNotIn(credential, joined)

    def test_ambiguous_write_logs_id_without_plaintext(self):
        self.secrets.fail_put_after_commit = True
        self.secrets.fail_pending_read_after_put = True
        with patch.object(openai_keys, "create_key", return_value=("new-workload", "new-id")), \
             self.assertLogs(rotation.LOG, level="INFO") as logs:
            with self.assertRaisesRegex(RuntimeError, "Could not verify pending secret write"):
                rotation.rotate(self.event, self.secrets)
        self.assertIn('"event": "pending_write_unconfirmed"', " ".join(logs.output))
        self.assertIn('"api_key_id": "new-id"', " ".join(logs.output))
        self.assertNotIn("new-workload", " ".join(logs.output))

    def test_audit_falls_back_to_safe_stdout_when_logger_fails(self):
        output = io.StringIO()
        with patch.object(rotation.LOG, "info", side_effect=RuntimeError("logger unavailable")), \
             patch.object(openai_keys, "create_key", return_value=("new-workload", "new-id")), \
             patch.object(openai_keys, "delete_key"), redirect_stdout(output):
            rotation.rotate(self.event, self.secrets)
            self.event["Step"] = "finishSecret"
            rotation.rotate(self.event, self.secrets)
        lines = output.getvalue().splitlines()
        records = [json.loads(line.split("api_key_rotation ", 1)[1]) for line in lines]
        self.assertEqual([record["event"] for record in records],
                         ["issued", "pending_persisted", "promoted", "retired", "pending_cleared"])
        self.assertTrue(all(record["delivery"] == "stdout_fallback" for record in records))
        self.assertEqual(records[0]["api_key_id"], "new-id")
        self.assertEqual(records[-2]["api_key_id"], "old-id")
        self.assertEqual(records[-1]["api_key_id"], "new-id")
        for credential in ("new-workload", "old-workload", "management-credential"):
            self.assertNotIn(credential, output.getvalue())

    def test_ambiguous_put_with_unavailable_read_preserves_key(self):
        self.secrets.fail_put_after_commit = True
        self.secrets.fail_pending_read_after_put = True
        with patch.object(openai_keys, "create_key", return_value=("new-workload", "new-id")), \
             patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(RuntimeError, "Could not verify pending secret write"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()

    def test_invalid_stage_does_not_call_provider(self):
        self.secrets.stages["token-123456789"] = []
        with patch.object(openai_keys, "call_api") as api:
            with self.assertRaises(ValueError):
                rotation.rotate(self.event, self.secrets)
        api.assert_not_called()

    def test_unsupported_configured_provider_fails_before_secret_access(self):
        os.environ["API_PROVIDER"] = "other"
        with patch.object(self.secrets, "describe_secret") as describe:
            with self.assertRaisesRegex(ValueError, "Unsupported API provider"):
                rotation.rotate(self.event, self.secrets)
        describe.assert_not_called()

    def test_delete_treats_already_absent_upstream_key_as_success(self):
        missing = HTTPError("https://api.openai.com", 404, "Not Found", {}, io.BytesIO(b"private"))
        with patch.object(http_api.request, "urlopen", side_effect=missing):
            openai_keys.delete_key("management-credential", "old-id", "proj_123")

    def test_provider_specific_revoke_paths(self):
        with patch.object(openai_keys, "call_api", return_value={"deleted": True}) as openai_api, \
             patch.object(openrouter_keys, "call_api", return_value={"deleted": True}) as openrouter_api:
            openai_keys.delete_key("admin", "key/id", "proj_123")
            openrouter_keys.delete_key("management", "hash/id")
        self.assertEqual(openai_api.call_args.args[:3], (
            "DELETE", "https://api.openai.com/v1/organization/projects/proj_123/api_keys/key%2Fid", "admin",
        ))
        self.assertEqual(openrouter_api.call_args.args[:3], (
            "DELETE", "https://openrouter.ai/api/v1/keys/hash%2Fid", "management",
        ))

    def test_provider_create_rejects_incomplete_response(self):
        with patch.object(openai_keys, "call_api", return_value={"id": "new-id"}):
            with self.assertRaisesRegex(ValueError, "OpenAI did not return"):
                openai_keys.create_key("admin", "token-123456789")
        with patch.object(openrouter_keys, "call_api", return_value={"key": "new-key", "data": {}}):
            with self.assertRaisesRegex(ValueError, "OpenRouter did not return"):
                openrouter_keys.create_key("management", {
                    "name": "resolved-name", "workspace_id": None, "limit": None,
                    "limit_reset": None, "include_byok_in_limit": None,
                    "disabled": None, "expires_at": None, "creator_user_id": None,
                })

    def test_http_error_does_not_expose_provider_response_body(self):
        denied = HTTPError("https://api.openai.com", 403, "Forbidden", {}, io.BytesIO(b"api_key=private"))
        with patch.object(http_api.request, "urlopen", side_effect=denied):
            with self.assertRaisesRegex(RuntimeError, "Provider request returned HTTP 403") as captured:
                http_api.call_api("GET", "https://api.openai.com/v1/models", "private")
        self.assertNotIn("private", str(captured.exception))

    def test_management_key_can_be_seeded_as_plaintext(self):
        self.secrets.management = "management-credential"
        self.assertEqual(rotation.management_key(self.secrets), "management-credential")


class OpenRouterConfigRotationTests(unittest.TestCase):
    """Contract for Terraform-owned configuration and Lambda-owned credentials."""

    def setUp(self):
        self.secrets = FakeSecrets()
        self.secrets.values["current"] = {
            "api_key": "old-workload", "api_key_id": "old-id",
            "name": "old-name", "workspace_id": None,
        }
        self.config = {
            "schema_version": 1, "name": "resolved-name", "workspace_id": None,
            "limit": 0, "limit_reset": None, "include_byok_in_limit": False,
            "disabled": None, "expires_at": None, "creator_user_id": None,
        }
        self.secrets.values["config-v1"] = self.config.copy()
        self.secrets.stages["config-v1"] = ["TFCONFIG"]
        self.event = {
            "SecretId": "target-secret", "ClientRequestToken": "token-123456789", "Step": "createSecret",
        }
        self.env = patch.dict(os.environ, {
            "API_PROVIDER": "openrouter", "MANAGEMENT_SECRET_ARN": "management-secret",
            "OPENROUTER_KEY_OPTIONS_JSON": '{"name":"wrong-env-name","limit":999}',
            "ROTATION_KEY_NAME": "wrong-env-name",
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.clock = patch.object(rotation.openrouter_rotation, "utcnow",
                                  return_value=datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc))
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.calls = []
        self.key_status = {}
        self.provider_workspace = None
        self.provider_name = "resolved-name"
        self.provider_expiry = None

    def provider(self, method, url, key, payload=None, **kwargs):
        self.calls.append((method, url, key, payload))
        if method == "POST":
            self.provider_expiry = payload["expires_at"]
            return {"key": "new-workload", "data": {"hash": "new-id", "workspace_id": None}}
        if method == "PATCH":
            self.key_status[url.rsplit("/", 1)[-1]] = payload["disabled"]
            return {"data": {"hash": "new-id", "disabled": payload["disabled"]}}
        if method == "GET" and url.endswith("/key"):
            return {"data": {"hash": "new-id"}}
        if method == "GET" and "/keys/" in url:
            key_id = url.rsplit("/", 1)[-1]
            return {"data": {"hash": key_id, "disabled": self.key_status.get(key_id, False),
                             "workspace_id": self.provider_workspace, "name": self.provider_name,
                             "expires_at": self.provider_expiry}}
        if method == "DELETE":
            return {"deleted": True}
        raise AssertionError(f"Unexpected provider operation: {method} {url}")

    def rotate(self, step):
        self.event["Step"] = step
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            rotation.rotate(self.event, self.secrets)

    def pending(self):
        return self.secrets.values["token-123456789"]

    def intent_snapshot(self):
        version = rotation.openrouter_rotation.intent_version(
            self.secrets.arn, self.event["ClientRequestToken"])
        return self.secrets.values[version]["snapshot"]

    def create_unresolved_orphan(self, *, abandon=True):
        self.secrets.fail_pending_put = True
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.secrets.fail_pending_put = False
        if abandon:
            self.secrets.stages["token-123456789"].remove("AWSPENDING")
        return next(version for version, stages in self.secrets.stages.items()
                    if "ROTATIONINTENT" in stages)

    def reconcile_event(self, intent_version, orphan_key_id="new-id"):
        return {**self.event, "Step": "reconcileOrphan",
                "IntentVersionId": intent_version, "OrphanKeyId": orphan_key_id}



    def test_bootstrap_creates_tests_promotes_without_deleting_sentinel(self):
        self.secrets.values["current"] = {"api_key": None, "api_key_id": "__CREATE_NEW__"}
        self.secrets.stages["current"].append("TFBOOTSTRAP")
        for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
            self.rotate(step)
        self.assertEqual(self.pending()["api_key"], "new-workload")
        self.assertEqual(self.pending()["api_key_id"], "new-id")
        self.assertEqual(self.pending()["name"], "resolved-name")
        self.assertIsNone(self.pending()["workspace_id"])
        self.assertEqual(set(self.pending()), {"api_key", "api_key_id", "name", "workspace_id"})
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])
        self.assertIn("TFBOOTSTRAP", self.secrets.stages["current"])
        self.assertEqual(self.secrets.stages["config-v1"], ["TFCONFIG"])
        self.assertFalse(any(call.get("VersionStage") in ("TFCONFIG", "TFBOOTSTRAP")
                             for call in self.secrets.stage_updates))
        self.assertFalse(any(call[0] == "DELETE" for call in self.calls))

    def test_normal_rotation_uses_config_not_old_key_or_environment(self):
        self.rotate("createSecret")
        self.assertEqual(set(self.pending()), {"api_key", "api_key_id", "name", "workspace_id"})
        posts = [call for call in self.calls if call[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][3], {
            "name": "resolved-name", "limit": 0, "include_byok_in_limit": False,
            "expires_at": "2026-11-12T14:24:00Z",
        })
        self.assertEqual(self.pending()["name"], "resolved-name")
        snapshot = self.intent_snapshot()
        self.assertEqual(snapshot["config_version_id"], "config-v1")
        self.assertEqual(snapshot["config"], self.config)
        self.assertEqual(snapshot["effective_expires_at"], "2026-11-12T14:24:00Z")
        self.assertEqual(snapshot["expiry_safety_seconds"], 95040)
        self.assertEqual(snapshot["previous_version_id"], "current")
        self.assertEqual(snapshot["previous_api_key_id"], "old-id")
        self.assertEqual(snapshot["schema_version"], 1)
        self.assertTrue(snapshot["intent_version_id"])
        self.assertEqual([call["VersionStages"] for call in self.secrets.put_calls],
                         [["ROTATIONINTENT"], ["AWSPENDING"]])

    def test_default_hourly_rate_expiry_includes_one_hour_window_and_guard(self):
        self.secrets.rotation_rules = {"ScheduleExpression": "rate(6 hours)"}
        self.rotate("createSecret")
        self.assertEqual(self.intent_snapshot()["effective_expires_at"],
                         "2026-11-10T21:00:00Z")
        self.assertEqual(self.intent_snapshot()["expiry_safety_seconds"], 10800)
        post = next(call for call in self.calls if call[0] == "POST")
        self.assertEqual(post[3]["expires_at"], "2026-11-10T21:00:00Z")

    def test_default_daily_window_extends_to_end_of_day(self):
        self.rotate("createSecret")
        self.assertEqual(self.intent_snapshot()["effective_expires_at"],
                         "2026-11-12T14:24:00Z")

    def test_explicit_rotation_duration_is_fully_added(self):
        self.secrets.rotation_rules = {"ScheduleExpression": "rate(1 day)", "Duration": "4h"}
        self.rotate("createSecret")
        self.assertEqual(self.intent_snapshot()["effective_expires_at"],
                         "2026-11-11T18:24:00Z")

    def test_long_interval_guard_is_capped_at_twenty_four_hours(self):
        self.secrets.rotation_rules = {"ScheduleExpression": "rate(30 days)"}
        self.rotate("createSecret")
        self.assertEqual(self.intent_snapshot()["effective_expires_at"],
                         "2026-12-12T12:00:00Z")

    def test_legacy_automatically_after_days_uses_daily_default_window(self):
        self.secrets.rotation_rules = {"AutomaticallyAfterDays": 7}
        self.rotate("createSecret")
        self.assertEqual(self.intent_snapshot()["effective_expires_at"],
                         "2026-11-19T04:48:00Z")

    def test_explicit_tfconfig_expiration_wins_unchanged(self):
        self.config["expires_at"] = "2027-01-01T00:00:00Z"
        self.secrets.values["config-v1"] = self.config.copy()
        self.secrets.rotation_rules = {"ScheduleExpression": "cron(0 1 ? * MON *)"}
        self.rotate("createSecret")
        self.assertEqual(self.intent_snapshot()["effective_expires_at"],
                         "2027-01-01T00:00:00Z")
        self.assertEqual(self.intent_snapshot()["expiry_safety_seconds"], 0)
        post = next(call for call in self.calls if call[0] == "POST")
        self.assertEqual(post[3]["expires_at"], "2027-01-01T00:00:00Z")

    def test_past_explicit_expiry_fails_before_intent_or_create(self):
        self.config["expires_at"] = "2026-11-10T11:59:59Z"
        self.secrets.values["config-v1"] = self.config.copy()
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertFalse(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        self.assertFalse(any(call[0] == "POST" for call in self.calls))

    def test_unsupported_or_missing_schedule_fails_before_intent_or_create(self):
        invalid = (
            {}, {"ScheduleExpression": "cron(0 1 ? * MON *)"},
            {"ScheduleExpression": "rate(0 hours)"},
            {"ScheduleExpression": "rate(2 weeks)"},
            {"ScheduleExpression": "rate(1 day)", "Duration": "0h"},
        )
        for rules in invalid:
            self.secrets.rotation_rules = rules
            with self.subTest(rules=rules), \
                 patch.object(openrouter_keys, "call_api", side_effect=self.provider), \
                 self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
            self.assertFalse(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
            self.assertFalse(any(call[0] == "POST" for call in self.calls))

    def test_effective_expiration_is_pinned_on_retry_after_schedule_change(self):
        self.rotate("createSecret")
        pinned = self.intent_snapshot()["effective_expires_at"]
        self.secrets.rotation_rules = {"ScheduleExpression": "rate(6 hours)", "Duration": "2h"}
        self.secrets.values["config-v2"] = {**self.config, "name": "future-name"}
        self.secrets.stages["config-v1"].remove("TFCONFIG")
        self.secrets.stages["config-v2"] = ["TFCONFIG"]
        self.rotate("createSecret")
        self.assertEqual(self.intent_snapshot()["effective_expires_at"], pinned)
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)

    def test_delayed_finish_does_not_promote_near_expired_derived_key(self):
        self.rotate("createSecret")
        later = datetime(2026, 11, 11, 13, 0, tzinfo=timezone.utc)
        with patch.object(rotation.openrouter_rotation, "utcnow", return_value=later):
            with self.assertRaises(Exception):
                self.rotate("testSecret")
            with self.assertRaises(Exception):
                self.rotate("finishSecret")
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSPENDING"])
        self.assertFalse(any(call[0] == "DELETE" for call in self.calls))

    def test_explicit_expiry_uses_actual_expiry_not_derived_safety_window(self):
        self.config["expires_at"] = "2026-11-10T13:00:00Z"
        self.secrets.values["config-v1"] = self.config.copy()
        self.rotate("createSecret")
        later = datetime(2026, 11, 10, 12, 30, tzinfo=timezone.utc)
        with patch.object(rotation.openrouter_rotation, "utcnow", return_value=later):
            self.rotate("testSecret")
            self.rotate("finishSecret")
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])

    def test_migrated_four_field_active_key_rotates_and_retires(self):
        for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
            self.rotate(step)
        self.assertEqual(self.secrets.stages["current"], ["AWSPREVIOUS"])
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])
        self.assertEqual(self.secrets.stages["config-v1"], ["TFCONFIG"])
        self.assertEqual(set(self.pending()), {"api_key", "api_key_id", "name", "workspace_id"})
        self.assertFalse(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        self.assertIn(("DELETE", "https://openrouter.ai/api/v1/keys/old-id",
                       "management-credential", None), self.calls)

    def test_legacy_active_metadata_is_not_copied_to_new_credential(self):
        self.secrets.values["current"]["_rotation"] = {"legacy": "metadata"}
        for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
            self.rotate(step)
        self.assertEqual(set(self.pending()), {"api_key", "api_key_id", "name", "workspace_id"})
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])

    def test_predecessor_is_retired_only_after_current_promotion(self):
        def retire(management, key_id):
            self.assertEqual(key_id, "old-id")
            self.assertIn("AWSCURRENT", self.secrets.stages["token-123456789"])
            self.assertIn("AWSPREVIOUS", self.secrets.stages["current"])
        with patch.object(openrouter_keys, "delete_key", side_effect=retire):
            for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
                self.rotate(step)

    def test_retries_reuse_pending_without_second_provider_creation(self):
        self.rotate("createSecret")
        self.rotate("createSecret")
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)
        self.assertTrue(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))

    def test_intent_survives_until_retirement_not_in_current_payload(self):
        for step in ("createSecret", "setSecret", "testSecret"):
            self.rotate(step)
            self.assertTrue(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
            self.assertEqual(set(self.pending()), {"api_key", "api_key_id", "name", "workspace_id"})
        self.rotate("finishSecret")
        self.assertFalse(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])

    def test_retirement_failure_keeps_intent_and_retries_same_predecessor(self):
        self.rotate("createSecret")
        self.rotate("setSecret")
        self.rotate("testSecret")
        with patch.object(openrouter_keys, "delete_key", side_effect=RuntimeError("temporary")):
            with self.assertRaises(RuntimeError):
                self.rotate("finishSecret")
        self.assertTrue(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        self.assertIn("AWSCURRENT", self.secrets.stages["token-123456789"])
        self.rotate("finishSecret")
        self.assertIn(("DELETE", "https://openrouter.ai/api/v1/keys/old-id",
                       "management-credential", None), self.calls)
        self.assertFalse(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))

    def test_intent_removal_after_commit_failure_is_safe_to_retry(self):
        for step in ("createSecret", "setSecret", "testSecret"):
            self.rotate(step)
        original_update = self.secrets.update_secret_version_stage
        def fail_after_intent_removal(**kwargs):
            original_update(**kwargs)
            if kwargs.get("VersionStage") == "ROTATIONINTENT":
                raise RuntimeError("AWS response lost after intent removal")
        with patch.object(self.secrets, "update_secret_version_stage", side_effect=fail_after_intent_removal):
            with self.assertRaises(RuntimeError):
                self.rotate("finishSecret")
        delete_count = sum(call[0] == "DELETE" for call in self.calls)
        self.rotate("finishSecret")
        self.assertEqual(sum(call[0] == "DELETE" for call in self.calls), delete_count)
        self.assertEqual(set(self.pending()), {"api_key", "api_key_id", "name", "workspace_id"})

    def test_intent_removal_before_commit_failure_retries_cleanup(self):
        for step in ("createSecret", "setSecret", "testSecret"):
            self.rotate(step)
        original_update = self.secrets.update_secret_version_stage
        def fail_before_intent_removal(**kwargs):
            if kwargs.get("VersionStage") == "ROTATIONINTENT":
                raise RuntimeError("AWS removal unavailable")
            return original_update(**kwargs)
        with patch.object(self.secrets, "update_secret_version_stage", side_effect=fail_before_intent_removal):
            with self.assertRaises(RuntimeError):
                self.rotate("finishSecret")
        self.assertTrue(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        self.rotate("finishSecret")
        self.assertFalse(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        self.assertEqual(set(self.pending()), {"api_key", "api_key_id", "name", "workspace_id"})

    def test_new_token_cannot_replace_unfinished_intent(self):
        self.rotate("createSecret")
        self.event["ClientRequestToken"] = "next-token"
        self.secrets.stages["next-token"] = ["AWSPENDING"]
        with patch.object(openrouter_keys, "create_key") as create:
            with self.assertRaises(RuntimeError):
                self.rotate("createSecret")
        create.assert_not_called()
        self.assertIn("ROTATIONINTENT", self.secrets.stages[
            rotation.openrouter_rotation.intent_version(self.secrets.arn, "token-123456789")])

    def test_legacy_pending_without_intent_fails_closed(self):
        self.rotate("createSecret")
        intent = self.intent_snapshot()["intent_version_id"]
        self.secrets.stages[intent].remove("ROTATIONINTENT")
        self.pending()["_rotation"] = self.intent_snapshot().copy()
        for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
            with self.subTest(step=step), self.assertRaises(Exception):
                self.rotate(step)
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])
        self.assertFalse(any(call[0] == "DELETE" for call in self.calls))

    def test_legacy_current_without_intent_does_not_claim_retirement(self):
        self.secrets.values["current"]["_rotation"] = {"legacy": "possibly unfinished"}
        self.event["ClientRequestToken"] = "current"
        with self.assertRaises(ValueError):
            self.rotate("finishSecret")
        self.assertFalse(any(call[0] == "DELETE" for call in self.calls))

    def test_old_finish_retry_does_not_clear_newer_rotation_intent(self):
        for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
            self.rotate(step)
        self.event["ClientRequestToken"] = "next-token"
        self.secrets.stages["next-token"] = ["AWSPENDING"]
        with patch.object(openrouter_keys, "create_key", return_value=("next-workload", "next-id")):
            self.rotate("createSecret")
        next_intent = self.intent_snapshot()["intent_version_id"]
        self.event["ClientRequestToken"] = "token-123456789"
        self.rotate("finishSecret")
        self.assertIn("ROTATIONINTENT", self.secrets.stages[next_intent])

    def test_unstaged_credential_receipt_does_not_clear_intent(self):
        self.rotate("createSecret")
        intent = self.intent_snapshot()["intent_version_id"]
        self.secrets.stages[intent] = ["ROTATIONINTENT"]
        self.secrets.stages["token-123456789"] = []
        with self.assertRaises(Exception):
            rotation.openrouter_rotation.clear_completed_intent(
                self.secrets, self.secrets.arn, self.event["ClientRequestToken"])
        self.assertIn("ROTATIONINTENT", self.secrets.stages[intent])

    def test_missing_config_fails_before_provider_creation_then_retries(self):
        self.secrets.fail_config_reads = True
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertEqual(self.calls, [])
        self.secrets.fail_config_reads = False
        self.rotate("createSecret")
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)

    def test_transient_missing_config_retries_within_create(self):
        original_get = self.secrets.get_secret_value
        missing = 0
        def intermittent_get(**kwargs):
            nonlocal missing
            if kwargs.get("VersionStage") == "TFCONFIG" and missing < 2:
                missing += 1
                raise NotFound()
            return original_get(**kwargs)
        with patch.object(self.secrets, "get_secret_value", side_effect=intermittent_get), \
             patch.object(rotation.openrouter_rotation.time, "sleep") as sleep, \
             patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(missing, 2)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(self.intent_snapshot()["config_version_id"], "config-v1")

    def test_management_secret_read_failure_does_not_claim_intent(self):
        original_get = self.secrets.get_secret_value
        def failed_management_read(**kwargs):
            if kwargs.get("SecretId") == "management-secret":
                raise RuntimeError("management secret temporarily unreadable")
            return original_get(**kwargs)
        with patch.object(self.secrets, "get_secret_value", side_effect=failed_management_read), \
             patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(RuntimeError):
                rotation.rotate(self.event, self.secrets)
        self.assertFalse(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        self.assertFalse(any(call[0] == "POST" for call in self.calls))
        self.rotate("createSecret")
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)

    def test_changed_config_after_create_does_not_change_token_snapshot(self):
        self.rotate("createSecret")
        self.secrets.values["config-v2"] = {**self.config, "name": "future-name", "limit": 9}
        self.secrets.stages["config-v1"].remove("TFCONFIG")
        self.secrets.stages["config-v2"] = ["TFCONFIG"]
        for step in ("setSecret", "testSecret", "finishSecret"):
            self.rotate(step)
        self.assertEqual(self.intent_snapshot()["config_version_id"], "config-v1")
        self.assertEqual(self.pending()["name"], "resolved-name")

    def test_malformed_config_fails_closed(self):
        for change in ({"schema_version": 2}, {"name": ""}, {"limit": True},
                       {"include_byok_in_limit": "false"}, {"disabled": 0}):
            self.secrets.values["config-v1"] = {**self.config, **change}
            with self.subTest(change=change), patch.object(openrouter_keys, "call_api", side_effect=self.provider):
                with self.assertRaises(Exception):
                    rotation.rotate(self.event, self.secrets)
                self.assertEqual(self.calls, [])
        incomplete = self.config.copy()
        del incomplete["creator_user_id"]
        self.secrets.values["config-v1"] = incomplete
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertEqual(self.calls, [])

    def test_bootstrap_requires_exact_null_sentinel_pair_and_label(self):
        for payload, bootstrap_label in (
            ({"api_key": None, "api_key_id": "wrong"}, True),
            ({"api_key": "not-null", "api_key_id": "__CREATE_NEW__"}, True),
            ({"api_key": None, "api_key_id": "__CREATE_NEW__"}, False),
        ):
            self.secrets.values["current"] = payload
            self.secrets.stages["current"] = ["AWSCURRENT"] + (["TFBOOTSTRAP"] if bootstrap_label else [])
            with self.subTest(payload=payload, bootstrap_label=bootstrap_label), \
                 patch.object(openrouter_keys, "call_api", side_effect=self.provider):
                with self.assertRaises(Exception):
                    rotation.rotate(self.event, self.secrets)
                self.assertEqual(self.calls, [])

    def test_disabled_is_patch_only_and_tested_with_management_key(self):
        self.config["disabled"] = True
        self.secrets.values["config-v1"] = self.config.copy()
        self.rotate("createSecret")
        self.rotate("setSecret")
        self.rotate("testSecret")
        post = next(call for call in self.calls if call[0] == "POST")
        self.assertNotIn("disabled", post[3])
        patch_call = next(call for call in self.calls if call[0] == "PATCH")
        self.assertEqual(patch_call[3], {"disabled": True})
        self.assertEqual(patch_call[1], "https://openrouter.ai/api/v1/keys/new-id")
        self.assertIn(("GET", "https://openrouter.ai/api/v1/keys/new-id",
                       "management-credential", None), self.calls)
        self.assertFalse(any(call[0] == "GET" and call[1].endswith("/key") for call in self.calls))

    def test_explicit_enabled_false_is_patched_not_dropped(self):
        self.config["disabled"] = False
        self.secrets.values["config-v1"] = self.config.copy()
        self.rotate("createSecret")
        self.rotate("setSecret")
        post = next(call for call in self.calls if call[0] == "POST")
        self.assertNotIn("disabled", post[3])
        patch_call = next(call for call in self.calls if call[0] == "PATCH")
        self.assertEqual(patch_call[3], {"disabled": False})

    def test_disabled_replacement_promotes_and_retires_previous_key(self):
        self.config["disabled"] = True
        self.secrets.values["config-v1"] = self.config.copy()
        for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
            self.rotate(step)
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])
        self.assertEqual(self.secrets.stages["current"], ["AWSPREVIOUS"])
        self.assertIn(("DELETE", "https://openrouter.ai/api/v1/keys/old-id",
                       "management-credential", None), self.calls)
        self.assertTrue(any(call[0] == "GET" and call[1].endswith("/keys/new-id")
                            for call in self.calls))
        self.assertFalse(any(call[0] == "GET" and call[1].endswith("/key")
                             for call in self.calls))

    def test_set_retries_patch_without_creating_another_key(self):
        self.config["disabled"] = True
        self.secrets.values["config-v1"] = self.config.copy()
        self.rotate("createSecret")
        first = True
        original_provider = self.provider
        def flaky_patch(method, url, key, payload=None, **kwargs):
            nonlocal first
            if method == "PATCH" and first:
                first = False
                raise RuntimeError("temporary PATCH failure")
            return original_provider(method, url, key, payload, **kwargs)
        self.event["Step"] = "setSecret"
        with patch.object(openrouter_keys, "call_api", side_effect=flaky_patch):
            with self.assertRaises(RuntimeError):
                rotation.rotate(self.event, self.secrets)
        self.rotate("setSecret")
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)
        self.assertEqual(self.key_status["new-id"], True)

    def test_provider_default_workspace_is_recorded_when_config_omits_it(self):
        original_provider = self.provider
        def default_workspace(method, url, key, payload=None, **kwargs):
            result = original_provider(method, url, key, payload, **kwargs)
            if method == "POST":
                result["data"]["workspace_id"] = "default-workspace"
                self.provider_workspace = "default-workspace"
            return result
        with patch.object(openrouter_keys, "call_api", side_effect=default_workspace):
            rotation.rotate(self.event, self.secrets)
        self.assertIsNone(self.config["workspace_id"])
        self.assertEqual(self.pending()["workspace_id"], "default-workspace")

    def test_intent_marker_blocks_duplicate_create_after_crash(self):
        def crash_after_create(method, url, key, payload=None, **kwargs):
            if method == "POST":
                raise RuntimeError("simulated transport loss after upstream creation")
            return self.provider(method, url, key, payload, **kwargs)
        with patch.object(openrouter_keys, "call_api", side_effect=crash_after_create):
            with self.assertRaises(RuntimeError):
                rotation.rotate(self.event, self.secrets)
        self.assertTrue(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertFalse(any(call[0] == "POST" for call in self.calls))
        self.assertNotIn("token-123456789", self.secrets.values)

    def test_failed_pending_write_leaves_intent_for_orphan_reconciliation(self):
        self.secrets.fail_pending_put = True
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)
        self.assertTrue(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        self.secrets.fail_pending_put = False
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)

    def test_missing_provider_workspace_keeps_intent_without_pending(self):
        original_provider = self.provider
        def missing_workspace(method, url, key, payload=None, **kwargs):
            result = original_provider(method, url, key, payload, **kwargs)
            if method == "GET" and "/keys/" in url:
                result["data"].pop("workspace_id")
            return result
        with patch.object(openrouter_keys, "call_api", side_effect=missing_workspace):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertNotIn("token-123456789", self.secrets.values)
        self.assertTrue(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)

    def test_provider_name_mismatch_keeps_intent_without_pending(self):
        self.provider_name = "wrong-provider-name"
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)
        self.assertNotIn("token-123456789", self.secrets.values)
        self.assertTrue(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        self.provider_name = "resolved-name"
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)

    def test_missing_provider_expiry_keeps_intent_without_pending(self):
        original_provider = self.provider
        def missing_expiry(method, url, key, payload=None, **kwargs):
            result = original_provider(method, url, key, payload, **kwargs)
            if method == "GET" and "/keys/" in url:
                result["data"].pop("expires_at")
            return result
        with patch.object(openrouter_keys, "call_api", side_effect=missing_expiry):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertNotIn("token-123456789", self.secrets.values)
        self.assertTrue(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)

    def test_mismatched_provider_expiry_keeps_intent_without_pending(self):
        original_provider = self.provider
        def wrong_expiry(method, url, key, payload=None, **kwargs):
            result = original_provider(method, url, key, payload, **kwargs)
            if method == "GET" and "/keys/" in url:
                result["data"]["expires_at"] = "2027-01-01T00:00:00Z"
            return result
        with patch.object(openrouter_keys, "call_api", side_effect=wrong_expiry):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertNotIn("token-123456789", self.secrets.values)
        self.assertTrue(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertEqual(sum(call[0] == "POST" for call in self.calls), 1)

    def test_manual_orphan_reconciliation_requires_a_new_rotation_token(self):
        def crash_after_create(method, url, key, payload=None, **kwargs):
            if method == "POST":
                raise RuntimeError("simulated lost Create response")
            return self.provider(method, url, key, payload, **kwargs)
        with patch.object(openrouter_keys, "call_api", side_effect=crash_after_create):
            with self.assertRaises(RuntimeError):
                rotation.rotate(self.event, self.secrets)
        intent = next(version for version, stages in self.secrets.stages.items()
                      if "ROTATIONINTENT" in stages)
        self.secrets.update_secret_version_stage(
            SecretId="target-secret", VersionStage="ROTATIONINTENT", RemoveFromVersionId=intent)
        # The old intent version is immutable; retrying its token could produce
        # a no-op intent write. Reconciliation ends that rotation and starts a
        # fresh token after the operator has verified/revoked any orphan key.
        self.secrets.stages["token-123456789"].remove("AWSPENDING")
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertFalse(any(call[0] == "POST" for call in self.calls))
        self.event["ClientRequestToken"] = "token-new-987654321"
        self.secrets.stages["token-new-987654321"] = ["AWSPENDING"]
        self.rotate("createSecret")
        self.assertEqual(self.secrets.values["token-new-987654321"]["api_key_id"], "new-id")

    def test_competing_intent_writer_cannot_issue_a_second_key(self):
        original_put = self.secrets.put_secret_value
        def competing_put(**kwargs):
            if kwargs.get("VersionStages") == ["ROTATIONINTENT"]:
                intent = json.loads(kwargs["SecretString"])
                self.assertTrue(intent["owner_nonce"])
                competing = {**intent, "owner_nonce": "another-invocation"}
                version = kwargs["ClientRequestToken"]
                self.secrets.values[version] = competing
                self.secrets.stages[version] = ["ROTATIONINTENT"]
            return original_put(**kwargs)
        with patch.object(self.secrets, "put_secret_value", side_effect=competing_put), \
             patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.assertEqual(self.calls, [])

    def test_finish_uses_snapshot_predecessor_on_retry(self):
        self.rotate("createSecret")
        self.rotate("setSecret")
        self.rotate("testSecret")
        self.secrets.fail_pending_removal = True
        with self.assertRaises(RuntimeError):
            self.rotate("finishSecret")
        self.secrets.fail_pending_removal = False
        self.rotate("finishSecret")
        self.assertEqual(sum(call[0] == "DELETE" for call in self.calls), 2)
        self.assertTrue(all(call[1].endswith("/keys/old-id") for call in self.calls if call[0] == "DELETE"))
        self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])

    def test_finish_rejects_snapshot_predecessor_drift_before_promotion(self):
        self.rotate("createSecret")
        self.intent_snapshot()["previous_api_key_id"] = "different-id"
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate({**self.event, "Step": "finishSecret"}, self.secrets)
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])
        self.assertFalse(any(call[0] == "DELETE" for call in self.calls))

    def test_canonical_arn_is_accepted_as_secret_id(self):
        self.event["SecretId"] = self.secrets.arn
        self.rotate("createSecret")
        self.assertEqual(self.pending()["api_key_id"], "new-id")

    def test_identity_disabled_rotation_and_deletion_fail_closed(self):
        self.event["SecretId"] = "wrong-secret"
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.event["SecretId"] = "target-secret"
        self.secrets.rotation_enabled = False
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
                with self.subTest(state="rotation_disabled", step=step), self.assertRaises(Exception):
                    rotation.rotate({**self.event, "Step": step}, self.secrets)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])
        self.secrets.rotation_enabled = True
        self.secrets.deleted_date = "2026-11-10T00:00:00Z"
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
                with self.subTest(state="deleting", step=step), self.assertRaises(Exception):
                    rotation.rotate({**self.event, "Step": step}, self.secrets)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.secrets.stages["config-v1"], ["TFCONFIG"])

    def test_custom_decommission_step_is_rejected_without_provider_calls(self):
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate({**self.event, "Step": "decommission"}, self.secrets)
        self.assertEqual(self.calls, [])

    def test_reconcile_orphan_deletes_key_and_only_its_intent_label(self):
        self.secrets.values["current"] = {"api_key": None, "api_key_id": "__CREATE_NEW__"}
        self.secrets.stages["current"].append("TFBOOTSTRAP")
        intent = self.create_unresolved_orphan()
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            rotation.rotate(self.reconcile_event(intent), self.secrets)
        self.assertIn(("DELETE", "https://openrouter.ai/api/v1/keys/new-id",
                       "management-credential", None), self.calls)
        self.assertNotIn("ROTATIONINTENT", self.secrets.stages[intent])
        self.assertEqual(self.secrets.stages["config-v1"], ["TFCONFIG"])
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT", "TFBOOTSTRAP"])
        self.assertFalse(any(call.get("VersionStage") in ("TFCONFIG", "TFBOOTSTRAP", "AWSCURRENT")
                             for call in self.secrets.stage_updates))
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.event, self.secrets)
        self.event["ClientRequestToken"] = "fresh-token-987654321"
        self.secrets.stages["fresh-token-987654321"] = ["AWSPENDING"]
        self.rotate("createSecret")
        self.assertEqual(self.secrets.values["fresh-token-987654321"]["api_key_id"], "new-id")

    def test_reconcile_orphan_rejects_missing_or_mismatched_identifiers(self):
        intent = self.create_unresolved_orphan()
        good = self.reconcile_event(intent)
        invalid = (
            {key: value for key, value in good.items() if key != "IntentVersionId"},
            {key: value for key, value in good.items() if key != "OrphanKeyId"},
            {**good, "IntentVersionId": "wrong-intent"},
            {**good, "ClientRequestToken": "other-token"},
            {**good, "OrphanKeyId": ""},
        )
        with patch.object(openrouter_keys, "delete_key") as delete:
            for event in invalid:
                with self.subTest(event=event), self.assertRaises(Exception):
                    rotation.rotate(event, self.secrets)
        delete.assert_not_called()
        self.assertIn("ROTATIONINTENT", self.secrets.stages[intent])

    def test_reconcile_orphan_rejects_unabandoned_pending_token(self):
        intent = self.create_unresolved_orphan(abandon=False)
        original_get = self.secrets.get_secret_value
        before_provider_calls = len(self.calls)
        def transient_token_miss(**kwargs):
            if kwargs.get("VersionId") == "token-123456789":
                raise NotFound()
            return original_get(**kwargs)
        with patch.object(self.secrets, "get_secret_value", side_effect=transient_token_miss), \
             patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.reconcile_event(intent), self.secrets)
        self.assertEqual(len(self.calls), before_provider_calls)
        self.assertIn("AWSPENDING", self.secrets.stages["token-123456789"])
        self.assertIn("ROTATIONINTENT", self.secrets.stages[intent])

    def test_reconcile_orphan_no_key_created_confirmation_clears_only_intent(self):
        # The intent was saved, but execution stopped before provider Create.
        # An operator must still confirm no key was issued before this event.
        with patch.object(openrouter_keys, "create_key", side_effect=RuntimeError("pre-create crash")):
            with self.assertRaises(RuntimeError):
                rotation.rotate(self.event, self.secrets)
        intent = next(version for version, stages in self.secrets.stages.items()
                      if "ROTATIONINTENT" in stages)
        self.secrets.stages["token-123456789"].remove("AWSPENDING")
        before_provider_calls = len(self.calls)
        event = {**self.event, "Step": "reconcileOrphan",
                 "IntentVersionId": intent, "NoKeyCreatedConfirmed": True}
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider), \
             patch.object(openrouter_keys, "delete_key") as delete:
            rotation.rotate(event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(len(self.calls), before_provider_calls)
        self.assertNotIn("ROTATIONINTENT", self.secrets.stages[intent])
        self.assertEqual(self.secrets.stages["config-v1"], ["TFCONFIG"])
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])

    def test_reconcile_orphan_rejects_conflicting_no_key_and_key_id(self):
        intent = self.create_unresolved_orphan()
        event = {**self.reconcile_event(intent), "NoKeyCreatedConfirmed": True}
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider), \
             patch.object(openrouter_keys, "delete_key") as delete:
            with self.assertRaises(Exception):
                rotation.rotate(event, self.secrets)
        delete.assert_not_called()
        self.assertIn("ROTATIONINTENT", self.secrets.stages[intent])

    def test_reconcile_orphan_rejects_active_and_saved_credentials(self):
        intent = self.create_unresolved_orphan()
        self.secrets.values["previous"] = {
            "api_key": "previous-key", "api_key_id": "previous-id", "name": "previous",
            "workspace_id": None,
        }
        self.secrets.stages["previous"] = ["AWSPREVIOUS"]
        self.secrets.values["another-pending"] = {
            "api_key": "pending-key", "api_key_id": "pending-id", "name": "pending",
            "workspace_id": None,
        }
        self.secrets.stages["another-pending"] = ["AWSPENDING"]
        with patch.object(openrouter_keys, "delete_key") as delete:
            for key_id in ("old-id", "previous-id", "pending-id"):
                with self.subTest(key_id=key_id), self.assertRaises(Exception):
                    rotation.rotate(self.reconcile_event(intent, key_id), self.secrets)
        delete.assert_not_called()
        self.assertIn("ROTATIONINTENT", self.secrets.stages[intent])

    def test_reconcile_orphan_refuses_when_token_has_credential_version(self):
        intent = self.create_unresolved_orphan()
        self.secrets.values["token-123456789"] = {
            "api_key": "saved-key", "api_key_id": "new-id", "name": "resolved-name",
            "workspace_id": None,
        }
        with patch.object(openrouter_keys, "delete_key") as delete:
            with self.assertRaises(Exception):
                rotation.rotate(self.reconcile_event(intent), self.secrets)
        delete.assert_not_called()
        self.assertIn("ROTATIONINTENT", self.secrets.stages[intent])

    def test_reconcile_orphan_rejects_provider_key_with_wrong_name(self):
        intent = self.create_unresolved_orphan()
        self.provider_name = "unrelated-key"
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.reconcile_event(intent), self.secrets)
        self.assertFalse(any(call[0] == "DELETE" for call in self.calls))
        self.assertIn("ROTATIONINTENT", self.secrets.stages[intent])

    def test_reconcile_orphan_deletion_failure_keeps_intent_for_retry(self):
        intent = self.create_unresolved_orphan()
        event = self.reconcile_event(intent)
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider), \
             patch.object(openrouter_keys, "delete_key", side_effect=[RuntimeError("temporary"), None]) as delete:
            with self.assertRaises(RuntimeError):
                rotation.rotate(event, self.secrets)
            self.assertIn("ROTATIONINTENT", self.secrets.stages[intent])
            rotation.rotate(event, self.secrets)
        self.assertEqual(delete.call_count, 2)
        self.assertNotIn("ROTATIONINTENT", self.secrets.stages[intent])

    def test_reconcile_orphan_accepts_key_already_absent_upstream(self):
        intent = self.create_unresolved_orphan()
        original_provider = self.provider
        def absent_key(method, url, key, payload=None, **kwargs):
            if method == "GET" and url.endswith("/keys/new-id"):
                return {"deleted": True}
            return original_provider(method, url, key, payload, **kwargs)
        with patch.object(openrouter_keys, "call_api", side_effect=absent_key):
            rotation.rotate(self.reconcile_event(intent), self.secrets)
        self.assertNotIn("ROTATIONINTENT", self.secrets.stages[intent])
        self.assertEqual(self.secrets.stages["config-v1"], ["TFCONFIG"])

    def test_reconcile_orphan_after_rotation_abort_and_disable(self):
        intent = self.create_unresolved_orphan()
        self.secrets.rotation_enabled = False
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            rotation.rotate(self.reconcile_event(intent), self.secrets)
        self.assertIn(("DELETE", "https://openrouter.ai/api/v1/keys/new-id",
                       "management-credential", None), self.calls)
        self.assertNotIn("ROTATIONINTENT", self.secrets.stages[intent])
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])
        self.assertEqual(self.secrets.stages["config-v1"], ["TFCONFIG"])

    def test_reconcile_orphan_rejects_secret_scheduled_for_deletion(self):
        intent = self.create_unresolved_orphan()
        self.secrets.rotation_enabled = False
        self.secrets.deleted_date = "2026-11-10T00:00:00Z"
        with patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(Exception):
                rotation.rotate(self.reconcile_event(intent), self.secrets)
        self.assertFalse(any(call[0] == "DELETE" for call in self.calls))
        self.assertIn("ROTATIONINTENT", self.secrets.stages[intent])
        self.assertEqual(self.secrets.stages["config-v1"], ["TFCONFIG"])

    def test_reconcile_orphan_fails_closed_when_current_is_unreadable(self):
        intent = self.create_unresolved_orphan()
        original_get = self.secrets.get_secret_value
        before_provider_calls = len(self.calls)
        def unreadable_current(**kwargs):
            if kwargs.get("VersionId") == "current":
                raise RuntimeError("staged credential unreadable")
            return original_get(**kwargs)
        with patch.object(self.secrets, "get_secret_value", side_effect=unreadable_current), \
             patch.object(openrouter_keys, "call_api", side_effect=self.provider):
            with self.assertRaises(RuntimeError):
                rotation.rotate(self.reconcile_event(intent), self.secrets)
        self.assertEqual(len(self.calls), before_provider_calls)
        self.assertIn("ROTATIONINTENT", self.secrets.stages[intent])







if __name__ == "__main__":
    unittest.main()
