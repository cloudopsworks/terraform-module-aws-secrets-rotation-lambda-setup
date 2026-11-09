"""Offline tests for the OpenAI/OpenRouter rotation Lambda."""

import importlib.util
from contextlib import redirect_stdout
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
        self.values = {"current": {"api_key": "old-workload", "api_key_id": "old-id", "provider": "openai",
                                   "project_id": "proj_123", "service_account_id": "svc_456",
                                   "scopes": ["api.model.read"], "name": "worker-token-12"}}
        self.stages = {"current": ["AWSCURRENT"], "token-123456789": ["AWSPENDING"]}
        self.management = json.dumps({"api_key": "management-credential"})
        self.fail_put = False
        self.fail_put_after_commit = False
        self.fail_pending_read_after_put = False
        self.put_attempted = False
        self.promote_on_put = False
        self.get_calls = []

    def describe_secret(self, **kwargs):
        return {"RotationEnabled": True, "VersionIdsToStages": self.stages}

    def get_secret_value(self, SecretId, VersionId=None, VersionStage=None):
        self.get_calls.append((SecretId, VersionId, VersionStage))
        if SecretId == "management-secret":
            return {"SecretString": self.management}
        if self.put_attempted and self.fail_pending_read_after_put and VersionId == "token-123456789":
            raise RuntimeError("AWS read unavailable")
        if VersionStage == "AWSPREVIOUS":
            version = next((name for name, stages in self.stages.items() if "AWSPREVIOUS" in stages), None)
        elif VersionId:
            version = VersionId
        else:
            version = next((name for name, stages in self.stages.items() if VersionStage in stages), None)
        if version not in self.values:
            raise NotFound()
        return {"SecretString": json.dumps(self.values[version]), "VersionId": version}

    def put_secret_value(self, **kwargs):
        self.put_attempted = True
        if self.fail_put:
            raise RuntimeError("AWS failure exposing secret")
        self.values[kwargs["ClientRequestToken"]] = json.loads(kwargs["SecretString"])
        if self.promote_on_put:
            self.stages["current"] = ["AWSPREVIOUS"]
            self.stages[kwargs["ClientRequestToken"]] = ["AWSCURRENT"]
        if self.fail_put_after_commit:
            raise RuntimeError("AWS timeout after commit")

    def update_secret_version_stage(self, **kwargs):
        current = kwargs["RemoveFromVersionId"]
        pending = kwargs["MoveToVersionId"]
        self.stages[current] = ["AWSPREVIOUS"]
        self.stages[pending] = ["AWSCURRENT"]


class RotationTests(unittest.TestCase):
    def router_current(self, **changes):
        value = {
            "api_key": "old-workload", "api_key_id": "old-id", "provider": "openrouter",
            "name": "worker-token-12", "limit": 10, "limit_reset": "monthly",
            "include_byok_in_limit": False, "creator_user_id": None, "workspace_id": None,
        }
        value.update(changes)
        return value

    def pending(self, **changes):
        value = {**self.secrets.values["current"], "api_key": "pending", "api_key_id": "new-id",
                 "rotation": {"previous_version_id": "current", "previous_api_key_id": "old-id"}}
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
            "api_key": "new-workload", "api_key_id": "new-id", "provider": "openai",
            "project_id": "proj_123", "service_account_id": "svc_456", "scopes": ["api.model.read"],
            "name": "worker-token-12",
            "rotation": {"previous_version_id": "current", "previous_api_key_id": "old-id"},
        })

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

    def test_openrouter_uses_top_level_key_and_nested_hash(self):
        os.environ["API_PROVIDER"] = "openrouter"
        self.secrets.values["current"] = self.router_current()
        os.environ["OPENROUTER_KEY_OPTIONS_JSON"] = '{"limit":10,"limit_reset":"monthly"}'
        calls = []

        def api(method, url, key, payload=None, **kwargs):
            calls.append((method, url, key, payload))
            return {"key": "new-router-key", "data": {"hash": "router-hash", "workspace_id": None}}

        with patch.object(openrouter_keys, "call_api", side_effect=api):
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(calls[0], (
            "POST", "https://openrouter.ai/api/v1/keys", "management-credential",
            {"limit": 10, "limit_reset": "monthly", "include_byok_in_limit": False,
             "creator_user_id": None, "name": "worker-token-12"},
        ))
        self.assertEqual(self.secrets.values["token-123456789"]["api_key_id"], "router-hash")
        self.assertEqual(self.secrets.values["token-123456789"]["rotation"], {
            "previous_version_id": "current", "previous_api_key_id": "old-id",
        })

    def test_openrouter_replicates_secret_fields_including_false_zero_and_null(self):
        os.environ["API_PROVIDER"] = "openrouter"
        os.environ["OPENROUTER_KEY_OPTIONS_JSON"] = json.dumps({
            "limit": 10, "limit_reset": "monthly", "include_byok_in_limit": True,
            "workspace_id": "configured-workspace", "expires_at": "2028-01-01T00:00:00Z",
        })
        self.secrets.values["current"] = {
            "api_key": "old-workload", "api_key_id": "old-id", "provider": "openrouter",
            "name": "existing-name", "limit": 0, "limit_reset": None,
            "include_byok_in_limit": False, "workspace_id": None,
            "creator_user_id": "existing-user", "expires_at": "2026-01-01T00:00:00Z",
        }
        response = {"key": "new-router-key", "data": {"hash": "router-hash", "workspace_id": None}}
        with patch.object(openrouter_keys, "call_api", return_value=response) as api:
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(api.call_args.args[3], {
            "name": "existing-name", "limit": 0, "limit_reset": None,
            "include_byok_in_limit": False,
            "creator_user_id": "existing-user", "expires_at": "2028-01-01T00:00:00Z",
        })
        pending = self.secrets.values["token-123456789"]
        self.assertEqual(pending["limit"], 0)
        self.assertIsNone(pending["limit_reset"])
        self.assertFalse(pending["include_byok_in_limit"])
        self.assertIsNone(pending["workspace_id"])
        self.assertNotIn("expires_at", pending)

    def test_openrouter_null_workspace_rejects_provider_assignment(self):
        os.environ["API_PROVIDER"] = "openrouter"
        self.secrets.values["current"] = self.router_current()
        response = {"key": "new-router-key", "data": {
            "hash": "router-hash", "workspace_id": "other-workspace",
        }}
        with patch.object(openrouter_keys, "call_api", return_value=response), \
             patch.object(openrouter_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "did not confirm"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_called_once_with("management-credential", "router-hash")
        self.assertNotIn("token-123456789", self.secrets.values)

    def test_openrouter_null_workspace_requires_explicit_provider_confirmation(self):
        os.environ["API_PROVIDER"] = "openrouter"
        self.secrets.values["current"] = self.router_current()
        response = {"key": "new-router-key", "data": {"hash": "router-hash"}}
        with patch.object(openrouter_keys, "call_api", return_value=response), \
             patch.object(openrouter_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "did not confirm"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_called_once_with("management-credential", "router-hash")
        self.assertNotIn("token-123456789", self.secrets.values)

    def test_openrouter_rejects_unreproducible_existing_key(self):
        os.environ["API_PROVIDER"] = "openrouter"
        for field, value in (("disabled", True), ("external_user", "user_123"),
                             ("external", {"api_key": "another-secret"})):
            self.secrets.values["current"] = self.router_current(**{field: value})
            with self.subTest(field=field), patch.object(openrouter_keys, "create_key") as create:
                with self.assertRaisesRegex(ValueError, "cannot be reproduced"):
                    rotation.rotate(self.event, self.secrets)
                create.assert_not_called()

    def test_openrouter_secret_workspace_overrides_parameter_and_is_preserved(self):
        os.environ["API_PROVIDER"] = "openrouter"
        os.environ["OPENROUTER_KEY_OPTIONS_JSON"] = '{"workspace_id":"configured-workspace","limit":10}'
        self.secrets.values["current"] = self.router_current(workspace_id="secret-workspace")
        response = {"key": "new-router-key", "data": {
            "hash": "router-hash", "workspace_id": "secret-workspace",
        }}
        with patch.object(openrouter_keys, "call_api", return_value=response) as api:
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(api.call_args.args[3]["workspace_id"], "secret-workspace")
        self.assertEqual(self.secrets.values["token-123456789"]["workspace_id"], "secret-workspace")

    def test_openrouter_requires_secret_options_even_with_configuration(self):
        os.environ["API_PROVIDER"] = "openrouter"
        os.environ["OPENROUTER_KEY_OPTIONS_JSON"] = '{"workspace_id":"configured-workspace"}'
        self.secrets.values["current"] = {
            "api_key": "old-workload", "api_key_id": "old-id", "provider": "openrouter",
        }
        with patch.object(openrouter_keys, "create_key") as create:
            with self.assertRaisesRegex(ValueError, "record all key options"):
                rotation.rotate(self.event, self.secrets)
        create.assert_not_called()

    def test_openrouter_captured_workspace_survives_parameter_change(self):
        os.environ["API_PROVIDER"] = "openrouter"
        os.environ["OPENROUTER_KEY_OPTIONS_JSON"] = '{"workspace_id":"first-workspace"}'
        self.secrets.values["current"] = self.router_current(workspace_id="first-workspace")
        responses = [
            {"key": "first-key", "data": {"hash": "first-id", "workspace_id": "first-workspace"}},
            {"key": "second-key", "data": {"hash": "second-id", "workspace_id": "first-workspace"}},
        ]
        with patch.object(openrouter_keys, "call_api", side_effect=responses) as api, \
             patch.object(openrouter_keys, "delete_key"):
            rotation.rotate(self.event, self.secrets)
            self.event["Step"] = "finishSecret"
            rotation.rotate(self.event, self.secrets)
            os.environ["OPENROUTER_KEY_OPTIONS_JSON"] = '{"workspace_id":"changed-workspace"}'
            self.secrets.stages["token-234567890"] = ["AWSPENDING"]
            self.event.update(ClientRequestToken="token-234567890", Step="createSecret")
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(api.call_args_list[1].args[3]["workspace_id"], "first-workspace")
        self.assertEqual(self.secrets.values["token-234567890"]["workspace_id"], "first-workspace")

    def test_openrouter_workspace_mismatch_revokes_unstored_key(self):
        os.environ["API_PROVIDER"] = "openrouter"
        os.environ["OPENROUTER_KEY_OPTIONS_JSON"] = '{"workspace_id":"configured-workspace"}'
        self.secrets.values["current"] = self.router_current(workspace_id="secret-workspace")
        response = {"key": "new-router-key", "data": {
            "hash": "router-hash", "workspace_id": "other-workspace",
        }}
        with patch.object(openrouter_keys, "call_api", return_value=response), \
             patch.object(openrouter_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "did not confirm"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_called_once_with("management-credential", "router-hash")
        self.assertNotIn("token-123456789", self.secrets.values)

    def test_openrouter_secret_workspace_requires_matching_provider_confirmation(self):
        os.environ["API_PROVIDER"] = "openrouter"
        os.environ["OPENROUTER_KEY_OPTIONS_JSON"] = '{"workspace_id":"configured-workspace"}'
        self.secrets.values["current"] = self.router_current(workspace_id="secret-workspace")
        for returned_workspace in (None, "other-workspace"):
            response = {"key": "new-router-key", "data": {"hash": "router-hash"}}
            if returned_workspace is not None:
                response["data"]["workspace_id"] = returned_workspace
            with self.subTest(returned_workspace=returned_workspace), \
                 patch.object(openrouter_keys, "call_api", return_value=response), \
                 patch.object(openrouter_keys, "delete_key") as delete:
                with self.assertRaisesRegex(ValueError, "did not confirm"):
                    rotation.rotate(self.event, self.secrets)
                delete.assert_called_once_with("management-credential", "router-hash")
                self.assertNotIn("token-123456789", self.secrets.values)

    def test_second_rotation_replaces_predecessor_trace_without_nesting(self):
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
        self.assertEqual(second["rotation"], {
            "previous_version_id": "token-123456789", "previous_api_key_id": "first-id",
        })
        self.assertEqual(second["api_key_id"], "second-id")

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
        os.environ["API_PROVIDER"] = "openrouter"
        self.secrets.values["token-123456789"] = self.router_current(api_key="pending", api_key_id="id")
        with patch.object(openrouter_keys, "call_api", return_value={}) as api:
            rotation.rotate(self.event, self.secrets)
        api.assert_called_once_with("GET", "https://openrouter.ai/api/v1/key", "pending")

    def test_finish_promotes_then_retires_old_key_and_retries_cleanup(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key", side_effect=[RuntimeError("temporary"), None]) as delete:
            with self.assertRaisesRegex(RuntimeError, "temporary"):
                rotation.rotate(self.event, self.secrets)
            self.assertEqual(self.secrets.stages["token-123456789"], ["AWSCURRENT"])
            rotation.rotate(self.event, self.secrets)
        self.assertEqual(delete.call_count, 2)
        delete.assert_called_with("management-credential", "old-id", "proj_123")

    def test_finish_rejects_tampered_previous_link_before_promotion(self):
        self.secrets.values["token-123456789"] = self.pending(
            rotation={"previous_version_id": "current", "previous_api_key_id": "wrong-id"})
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "identifier differs"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])

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
            with self.assertRaisesRegex(ValueError, "scopes differ"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])

    def test_finish_rejects_tampered_openrouter_limit(self):
        os.environ["API_PROVIDER"] = "openrouter"
        self.secrets.values["current"] = self.router_current(limit=0)
        self.secrets.values["token-123456789"] = self.pending(limit=10)
        self.event["Step"] = "finishSecret"
        with patch.object(openrouter_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "options differ"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])

    def test_finish_rejects_missing_nullable_openrouter_option(self):
        os.environ["API_PROVIDER"] = "openrouter"
        self.secrets.values["current"] = self.router_current()
        pending = self.pending()
        del pending["limit_reset"]
        self.secrets.values["token-123456789"] = pending
        self.event["Step"] = "finishSecret"
        with patch.object(openrouter_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "record all key options"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()

    def test_openrouter_finish_rejects_workspace_change(self):
        os.environ["API_PROVIDER"] = "openrouter"
        self.secrets.values["current"] = self.router_current(workspace_id="original-workspace")
        self.secrets.values["token-123456789"] = self.pending(workspace_id="other-workspace")
        self.event["Step"] = "finishSecret"
        with patch.object(openrouter_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "workspace differs"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])

    def test_finish_rejects_unrelated_current_version(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.secrets.values["other"] = self.secrets.values["current"].copy()
        self.secrets.stages["current"] = []
        self.secrets.stages["other"] = ["AWSCURRENT"]
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "Current key differs"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()

    def test_finish_before_promotion_rejects_environment_drift(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        os.environ["OPENAI_PROJECT_ID"] = "other-project"
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "binding differs"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])

    def test_finish_rejects_cross_provider_or_unidentified_previous_key(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        self.secrets.values["current"]["provider"] = "openrouter"
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "Key secret"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()
        self.assertEqual(self.secrets.stages["current"], ["AWSCURRENT"])

        self.secrets.stages = {"current": ["AWSCURRENT"], "token-123456789": ["AWSPENDING"]}
        self.secrets.values["current"] = {"api_key": "old-workload", "provider": "openai"}
        with patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "Key secret"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()

    def test_create_rejects_unidentified_or_other_provider_current_key(self):
        self.secrets.values["current"].pop("api_key_id")
        with patch.object(openai_keys, "create_key") as create:
            with self.assertRaisesRegex(ValueError, "Key secret"):
                rotation.rotate(self.event, self.secrets)
        create.assert_not_called()
        self.secrets.values["current"] = {"api_key": "old", "api_key_id": "old-id", "provider": "openrouter"}
        with patch.object(openai_keys, "create_key") as create:
            with self.assertRaisesRegex(ValueError, "Key secret"):
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

    def test_finish_retry_uses_link_without_previous_stage(self):
        self.secrets.values["token-123456789"] = self.pending(api_key="new")
        self.secrets.stages = {"token-123456789": ["AWSCURRENT"]}
        self.event["Step"] = "finishSecret"
        with patch.object(openai_keys, "delete_key") as delete:
            rotation.rotate(self.event, self.secrets)
        delete.assert_called_once_with("management-credential", "old-id", "proj_123")

    def test_finish_retry_rejects_stale_describe_snapshot(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.event["Step"] = "finishSecret"
        # Describe reports promotion, but GetSecretValue still identifies the
        # predecessor as AWSCURRENT. It must never be revoked in this state.
        with patch.object(self.secrets, "describe_secret", return_value={
            "RotationEnabled": True,
            "VersionIdsToStages": {"token-123456789": ["AWSCURRENT"]},
        }), patch.object(openai_keys, "delete_key") as delete:
            with self.assertRaisesRegex(ValueError, "Current key differs from promoted pending"):
                rotation.rotate(self.event, self.secrets)
        delete.assert_not_called()

    def test_finish_retry_uses_persisted_project_when_environment_changes(self):
        self.secrets.values["token-123456789"] = self.pending()
        self.secrets.stages = {"token-123456789": ["AWSCURRENT"]}
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
                         ["issued", "pending_persisted", "promoted", "retired"])
        self.assertTrue(all("delivery" not in record for record in records))
        self.assertEqual(records[0]["api_key_id"], "new-id")
        self.assertEqual(records[0]["version_id"], "token-123456789")
        self.assertEqual(records[-1]["api_key_id"], "old-id")
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
                         ["issued", "pending_persisted", "promoted", "retired"])
        self.assertTrue(all(record["delivery"] == "stdout_fallback" for record in records))
        self.assertEqual(records[0]["api_key_id"], "new-id")
        self.assertEqual(records[-1]["api_key_id"], "old-id")
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
                openrouter_keys.create_key("management", "token-123456789")

    def test_http_error_does_not_expose_provider_response_body(self):
        denied = HTTPError("https://api.openai.com", 403, "Forbidden", {}, io.BytesIO(b"api_key=private"))
        with patch.object(http_api.request, "urlopen", side_effect=denied):
            with self.assertRaisesRegex(RuntimeError, "Provider request returned HTTP 403") as captured:
                http_api.call_api("GET", "https://api.openai.com/v1/models", "private")
        self.assertNotIn("private", str(captured.exception))

    def test_management_key_can_be_seeded_as_plaintext(self):
        self.secrets.management = "management-credential"
        self.assertEqual(rotation.management_key(self.secrets), "management-credential")


if __name__ == "__main__":
    unittest.main()
