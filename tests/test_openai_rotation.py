"""Offline state-transition tests for Terraform-configured OpenAI rotation."""

from datetime import datetime, timezone
import copy
import hashlib
import json
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from tests.test_api_key_rotation import FakeSecrets, rotation, openai_keys


class OpenAIRotationTests(unittest.TestCase):
    def setUp(self):
        self.secrets = FakeSecrets()
        self.arn = self.secrets.arn
        self.token = "token-123456789"
        self.config = {
            "schema_version": 1, "key_type": "admin", "name": "resolved-key",
            "project_id": None, "service_account_id": None, "scopes": None,
            "role": None, "expires_in_seconds": 3600,
        }
        self.secrets.values["config-v1"] = copy.deepcopy(self.config)
        self.secrets.stages["config-v1"] = ["TFCONFIG"]
        self.secrets.values["current"] = {"api_key": None, "api_key_id": "__CREATE_NEW__"}
        self.secrets.stages["current"] = ["AWSCURRENT", "TFBOOTSTRAP"]
        self.secrets.management = json.dumps({
            "api_key": "management-credential", "organization_id": "org_123",
        })
        self.environment = patch.dict(os.environ, {
            "API_PROVIDER": "openai", "MANAGEMENT_SECRET_ARN": "management-secret",
            "OPENAI_ORGANIZATION_ID": "org_123",
        }, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
        self.clock = patch.object(rotation.openai_rotation, "utcnow", return_value=self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.calls = []
        self.new_id = "key_new"
        self.new_value = "sk-new-workload"
        self.provider_name = "resolved-key"
        self.provider_role = "owner"
        self.provider_account = "svc_456"
        self.provider_project_access = "active"
        self.provider_expiry = self.now.timestamp() + 3600

    def project(self, *, scopes=None, bootstrap=True, role="owner"):
        self.config.update({
            "key_type": "project", "project_id": "proj_123",
            "service_account_id": "svc_456", "scopes": scopes, "role": role,
        })
        self.secrets.values["config-v1"] = copy.deepcopy(self.config)
        self.secrets.values["current"] = self.credential(
            "project", "sk-bootstrap", "key_bootstrap", "bootstrap-key",
            "proj_123", "svc_456",
        )
        self.secrets.stages["current"] = (["AWSCURRENT", "TFBOOTSTRAP"] if bootstrap
                                           else ["AWSCURRENT"])

    def keyless_project(self, *, scopes=None, role="owner"):
        self.project(scopes=scopes, role=role)
        self.secrets.values["current"] = {
            "key_type": "project", "api_key": None,
            "api_key_id": "__CREATE_NEW__", "name": "resolved-key",
            "project_id": "proj_123", "service_account_id": "svc_456",
        }

    @staticmethod
    def credential(key_type, key, key_id, name, project_id=None, service_account_id=None):
        return {
            "key_type": key_type, "api_key": key, "api_key_id": key_id,
            "name": name, "project_id": project_id,
            "service_account_id": service_account_id,
        }

    def provider(self, method, url, key, payload=None, **kwargs):
        self.calls.append((method, url, key, payload, kwargs))
        if method == "POST":
            self.provider_expiry = self.now.timestamp() + payload["expires_in_seconds"]
            obj = ("organization.admin_api_key" if self.config["key_type"] == "admin"
                   else "organization.project.service_account.api_key")
            return {"object": obj, "id": self.new_id, "value": self.new_value,
                    "name": self.provider_name}
        if method == "GET" and url.endswith("/admin_api_keys"):
            return {"data": []}
        if method == "GET" and url.endswith("/models"):
            return {"data": []}
        if method == "GET" and "/service_accounts/" in url:
            return {"object": "organization.project.service_account",
                    "id": self.provider_account, "role": self.provider_role}
        if method == "GET":
            key_id = url.rsplit("/", 1)[-1]
            result = {
                "object": ("organization.admin_api_key" if "/admin_api_keys/" in url
                           else "organization.project.api_key"),
                "id": key_id, "name": self.provider_name,
                "expires_at": self.provider_expiry,
            }
            if "/projects/" in url:
                result.update({
                    "owner": {"type": "service_account", "service_account": {
                        "id": self.provider_account, "role": self.provider_role}},
                    "owner_project_access": self.provider_project_access,
                })
            return result
        if method == "DELETE":
            return {"deleted": True, "id": url.rsplit("/", 1)[-1]}
        raise AssertionError(f"Unexpected provider request: {method} {url}")

    def rotate(self, step, **extra):
        event = {"SecretId": self.arn, "ClientRequestToken": self.token,
                 "Step": step, **extra}
        with patch.object(openai_keys, "call_api", side_effect=self.provider):
            rotation.openai_rotation.rotate(event, self.secrets)

    def calls_for(self, method):
        return [call for call in self.calls if call[0] == method]

    def intent(self):
        version = next(version for version, stages in self.secrets.stages.items()
                       if "ROTATIONINTENT" in stages)
        return self.secrets.values[version]

    def test_first_admin_creation_promotes_without_deleting_bootstrap(self):
        for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
            self.rotate(step)
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])
        self.assertEqual(self.credential("admin", self.new_value, self.new_id,
                                         "resolved-key"), self.secrets.values[self.token])
        self.assertEqual([], self.calls_for("DELETE"))
        self.assertEqual(["TFBOOTSTRAP", "AWSPREVIOUS"],
                         self.secrets.stages["current"])
        self.assertFalse(any("ROTATIONINTENT" in stages
                             for stages in self.secrets.stages.values()))

    def test_project_bootstrap_retired_only_after_successful_promotion(self):
        self.project(scopes=["api.model.read"])
        self.rotate("createSecret")
        self.rotate("testSecret")
        self.assertEqual([], self.calls_for("DELETE"))
        self.rotate("finishSecret")
        self.assertEqual("AWSCURRENT", self.secrets.stages[self.token][0])
        self.assertEqual("key_bootstrap", self.calls_for("DELETE")[0][1].rsplit("/", 1)[-1])
        self.assertIn("TFBOOTSTRAP", self.secrets.stages["current"])
        self.assertEqual(self.credential("project", "sk-bootstrap", "key_bootstrap",
                                         "bootstrap-key", "proj_123", "svc_456"),
                         self.secrets.values["current"])
        self.assertEqual(1, len(self.calls_for("POST")))
        self.assertIn("/service_accounts/svc_456/api_keys",
                      self.calls_for("POST")[0][1])

    def test_rotation_logs_step_actions_without_credentials(self):
        self.project(scopes=["api.model.read"])
        steps = {
            "createSecret": ("read_configuration", "load_management_key",
                             "verify_management_key", "write_intent",
                             "issue_replacement", "write_pending"),
            "setSecret": ("check_pending_staging",),
            "testSecret": ("check_provider_metadata", "pending_auth_verified"),
            "finishSecret": ("promote_pending", "retire_predecessor", "clear_intent"),
        }
        for step, actions in steps.items():
            with self.subTest(step=step):
                with self.assertLogs(rotation.openai_rotation.LOG, level="INFO") as logs:
                    self.rotate(step)
                messages = [record.getMessage() for record in logs.records]
                self.assertEqual(f"openai_rotation step={step} status=started", messages[0])
                self.assertEqual(f"openai_rotation step={step} status=completed", messages[-1])
                correlation = hashlib.sha256(f"{self.arn}:{self.token}".encode()).hexdigest()
                self.assertIn(f"openai_rotation invocation correlation={correlation}", messages)
                positions = [messages.index(f"openai_rotation action={action}") for action in actions]
                self.assertEqual(sorted(positions), positions)
                for credential in ("management-credential", "sk-bootstrap", self.new_value):
                    self.assertNotIn(credential, "\n".join(messages))

    def test_keyless_project_bootstrap_creates_first_key_without_retirement(self):
        self.keyless_project(scopes=["api.model.read"])
        for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
            self.rotate(step)
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])
        self.assertEqual(["TFBOOTSTRAP", "AWSPREVIOUS"],
                         self.secrets.stages["current"])
        self.assertEqual("project", self.secrets.values[self.token]["key_type"])
        self.assertEqual(self.new_value, self.secrets.values[self.token]["api_key"])
        self.assertEqual([], self.calls_for("DELETE"))
        self.assertEqual(1, len(self.calls_for("POST")))
        self.rotate("finishSecret")
        self.assertEqual([], self.calls_for("DELETE"))

    def test_keyless_project_then_normal_rotation_retires_only_lambda_key(self):
        self.keyless_project()
        self.rotate("createSecret")
        self.rotate("finishSecret")
        self.token = "token-second-rotation"
        self.secrets.stages[self.token] = ["AWSPENDING"]
        self.new_id = "key_second"
        self.new_value = "sk-second-workload"
        self.rotate("createSecret")
        self.rotate("finishSecret")
        self.assertEqual("key_new", self.calls_for("DELETE")[0][1].rsplit("/", 1)[-1])
        self.assertEqual(1, len(self.calls_for("DELETE")))
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])

    def test_keyless_project_requires_matching_config_before_create(self):
        self.keyless_project()
        self.secrets.values["current"]["service_account_id"] = "svc_other"
        with self.assertRaisesRegex(ValueError, "identity"):
            self.rotate("createSecret")
        self.assertEqual([], self.calls_for("POST"))

    def test_keyless_project_and_successor_both_receive_schedule_derived_expiry(self):
        self.config["expires_in_seconds"] = None
        self.keyless_project()
        self.secrets.rotation_rules = {"AutomaticallyAfterDays": 30}
        for number in range(2):
            with self.subTest(issuance=number):
                if number:
                    self.token = "token-second-rotation"
                    self.secrets.stages[self.token] = ["AWSPENDING"]
                    self.new_id = "key_second"
                    self.new_value = "sk-second-workload"
                self.rotate("createSecret")
                self.assertEqual(2764800,
                                 self.calls_for("POST")[-1][3]["expires_in_seconds"])
                self.assertEqual(2764800,
                                 self.intent()["snapshot"]["effective_ttl_seconds"])
                for step in ("setSecret", "testSecret", "finishSecret"):
                    self.rotate(step)
                self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])
        self.assertEqual(2, len(self.calls_for("POST")))
        self.assertEqual(1, len(self.calls_for("DELETE")))

    def test_keyless_project_without_confirmed_expiry_cannot_be_promoted(self):
        self.keyless_project()
        self.rotate("createSecret")
        pending_values = copy.deepcopy(self.secrets.values)
        pending_stages = copy.deepcopy(self.secrets.stages)
        for expiry in (None, float("nan"), float("inf"), float("-inf")):
            self.provider_expiry = expiry
            for step in ("testSecret", "finishSecret"):
                with self.subTest(expiry=expiry, step=step):
                    self.secrets.values = copy.deepcopy(pending_values)
                    self.secrets.stages = copy.deepcopy(pending_stages)
                    with self.assertRaisesRegex(ValueError, "expiration"):
                        self.rotate(step)
                    self.assertIn("AWSCURRENT", self.secrets.stages["current"])
                    self.assertEqual(["AWSPENDING"], self.secrets.stages[self.token])
                    self.assertEqual([], self.calls_for("DELETE"))

    def test_keyless_project_requires_bootstrap_label(self):
        self.keyless_project()
        self.secrets.stages["current"] = ["AWSCURRENT"]
        with self.assertRaisesRegex(ValueError, "bootstrap"):
            self.rotate("createSecret")
        self.assertEqual([], self.calls_for("POST"))

    def test_migrated_active_admin_key_rotates_without_bootstrap_label(self):
        self.secrets.values["current"] = self.credential(
            "admin", "sk-old", "key_old", "previous-name")
        self.secrets.stages["current"] = ["AWSCURRENT"]
        self.rotate("createSecret")
        self.rotate("finishSecret")
        self.assertEqual("key_old", self.calls_for("DELETE")[0][1].rsplit("/", 1)[-1])
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])

    def test_normal_project_rotation_retires_existing_key(self):
        self.project(scopes=["api.model.read"], bootstrap=False)
        self.rotate("createSecret")
        self.rotate("setSecret")
        self.rotate("testSecret")
        self.rotate("finishSecret")
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])
        self.assertEqual("key_bootstrap", self.calls_for("DELETE")[0][1].rsplit("/", 1)[-1])
        self.assertNotIn("TFBOOTSTRAP", self.secrets.stages["current"])

    def test_duplicate_create_reuses_pending_without_second_provider_create(self):
        self.rotate("createSecret")
        self.rotate("createSecret")
        self.assertEqual(1, len(self.calls_for("POST")))
        self.assertEqual(["AWSPENDING"], self.secrets.stages[self.token])

    def test_transient_metadata_failure_after_create_keeps_plaintext_pending(self):
        self.rotate("createSecret")
        self.assertEqual(self.new_value, self.secrets.values[self.token]["api_key"])
        with patch.object(openai_keys, "get_key", side_effect=RuntimeError("transient")):
            with self.assertRaisesRegex(RuntimeError, "transient"):
                self.rotate("testSecret")
        self.assertEqual(["AWSPENDING"], self.secrets.stages[self.token])
        self.rotate("createSecret")
        self.rotate("testSecret")
        self.rotate("finishSecret")
        self.assertEqual(1, len(self.calls_for("POST")))
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])

    def test_duplicate_finish_is_safe_and_does_not_recreate_key(self):
        self.rotate("createSecret")
        self.rotate("finishSecret")
        self.rotate("finishSecret")
        self.assertEqual(1, len(self.calls_for("POST")))
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])

    def test_snapshot_survives_tfconfig_replacement_after_create(self):
        self.rotate("createSecret")
        self.secrets.stages["config-v1"] = []
        changed = {**self.config, "name": "terraform-new-name"}
        self.secrets.values["config-v2"] = changed
        self.secrets.stages["config-v2"] = ["TFCONFIG"]
        self.rotate("setSecret")
        self.rotate("testSecret")
        self.rotate("finishSecret")
        self.assertEqual("resolved-key", self.secrets.values[self.token]["name"])
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])

    def test_temporarily_missing_tfconfig_is_retried_without_defaulting(self):
        original = self.secrets.get_secret_value
        misses = {"count": 0}

        def transient(**kwargs):
            if kwargs.get("VersionStage") == "TFCONFIG" and misses["count"] < 2:
                misses["count"] += 1
                raise self.secrets.exceptions.ResourceNotFoundException()
            return original(**kwargs)

        with patch.object(self.secrets, "get_secret_value", side_effect=transient), \
                patch.object(rotation.openai_rotation.time, "sleep"):
            self.rotate("createSecret")
        self.assertEqual(2, misses["count"])
        self.assertEqual("resolved-key", self.secrets.values[self.token]["name"])

    def test_missing_tfconfig_fails_without_creating_key(self):
        self.secrets.fail_config_reads = True
        with patch.object(rotation.openai_rotation.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "TFCONFIG"):
                self.rotate("createSecret")
        self.assertEqual([], self.calls_for("POST"))
        self.assertNotIn(self.token, self.secrets.values)

    def test_explicit_ttl_is_preserved_in_create_request(self):
        self.config["expires_in_seconds"] = 7200
        self.secrets.values["config-v1"] = copy.deepcopy(self.config)
        self.rotate("createSecret")
        self.assertEqual(7200, self.calls_for("POST")[0][3]["expires_in_seconds"])
        self.assertEqual(7200, self.intent()["snapshot"]["effective_ttl_seconds"])

    def test_explicit_ttl_near_expiry_blocks_candidate_validation(self):
        self.rotate("createSecret")
        self.provider_expiry = self.now.timestamp()
        with self.assertRaisesRegex(ValueError, "expiration"):
            self.rotate("testSecret")
        self.assertIn("AWSCURRENT", self.secrets.stages["current"])
        self.assertEqual([], self.calls_for("DELETE"))

    def test_null_ttl_is_derived_from_rotation_schedule_with_guard(self):
        self.config["expires_in_seconds"] = None
        self.secrets.values["config-v1"] = copy.deepcopy(self.config)
        self.secrets.rotation_rules = {"ScheduleExpression": "rate(1 day)", "Duration": "2h"}
        self.rotate("createSecret")
        ttl = self.calls_for("POST")[0][3]["expires_in_seconds"]
        self.assertGreater(ttl, 86400 + 7200)
        self.assertEqual(ttl, self.intent()["snapshot"]["effective_ttl_seconds"])

    def test_project_null_scopes_are_omitted_from_create_request(self):
        self.project(scopes=None)
        self.rotate("createSecret")
        self.assertNotIn("scopes", self.calls_for("POST")[0][3])

    def test_project_empty_scopes_are_preserved_not_conflated_with_null(self):
        self.project(scopes=[])
        self.rotate("createSecret")
        self.assertEqual([], self.calls_for("POST")[0][3]["scopes"])

    def test_restricted_project_scopes_use_metadata_validation_without_models_probe(self):
        self.project(scopes=["api.assistants.read"])
        self.rotate("createSecret")
        self.rotate("testSecret")
        self.assertFalse(any(call[1].endswith("/models") for call in self.calls))
        self.assertTrue(any(call[1].endswith("/api_keys/" + self.new_id)
                            for call in self.calls_for("GET")))

    def test_unrestricted_member_validates_with_pending_key_against_models(self):
        self.project(role="member")
        self.provider_role = "member"
        self.rotate("createSecret")
        self.rotate("testSecret")
        probes = [call for call in self.calls_for("GET") if call[1].endswith("/models")]
        self.assertEqual([self.new_value], [call[2] for call in probes])
        self.rotate("finishSecret")
        self.assertIn("AWSCURRENT", self.secrets.stages[self.token])

    def test_positive_plaintext_probe_auth_failure_blocks_promotion(self):
        self.project(scopes=["api.model.read"])
        self.rotate("createSecret")
        original = self.provider
        for status in (401, 403):
            with self.subTest(status=status):
                def unauthorized_models(method, url, key, payload=None, **kwargs):
                    if method == "GET" and url.endswith("/models"):
                        raise HTTPError(url, status, "Unauthorized", {}, None)
                    return original(method, url, key, payload, **kwargs)

                with patch.object(openai_keys, "call_api", side_effect=unauthorized_models):
                    with self.assertRaises(HTTPError) as caught:
                        rotation.openai_rotation.rotate({
                            "SecretId": self.arn, "ClientRequestToken": self.token,
                            "Step": "testSecret"}, self.secrets)
                self.assertEqual(status, caught.exception.code)
        self.assertIn("AWSCURRENT", self.secrets.stages["current"])
        self.assertEqual([], self.calls_for("DELETE"))

    def test_project_role_drift_blocks_validation_and_promotion(self):
        self.project(scopes=["api.model.read"])
        self.rotate("createSecret")
        self.provider_role = "member"
        with self.assertRaisesRegex(ValueError, "role"):
            self.rotate("testSecret")
        self.assertIn("AWSCURRENT", self.secrets.stages["current"])
        self.assertEqual([], self.calls_for("DELETE"))

    def test_project_role_drift_preflight_blocks_provider_create(self):
        self.project(scopes=["api.model.read"])
        self.provider_role = "member"
        with self.assertRaisesRegex(ValueError, "role"):
            self.rotate("createSecret")
        self.assertEqual([], self.calls_for("POST"))
        self.assertNotIn(self.token, self.secrets.values)

    def test_project_identity_drift_from_tfconfig_fails_before_create(self):
        self.project()
        self.config["service_account_id"] = "svc_other"
        self.secrets.values["config-v1"] = copy.deepcopy(self.config)
        with self.assertRaisesRegex(ValueError, "identity"):
            self.rotate("createSecret")
        self.assertEqual([], self.calls_for("POST"))

    def test_supplied_management_organization_must_match_before_create(self):
        for organization_id in ("org_other", "", None, 42):
            with self.subTest(organization_id=organization_id):
                self.secrets.management = json.dumps({
                    "admin_api_key": "management-credential", "organization_id": organization_id,
                })
                with self.assertRaises(rotation.openai_rotation.OpenAIManagementSecretError), \
                        self.assertLogs(rotation.openai_rotation.LOG, level="WARNING") as logs:
                    self.rotate("createSecret")
                self.assertEqual("openai_rotation action=reject_management_key reason=organization_mismatch",
                                 logs.records[-1].getMessage())
        self.assertEqual([], self.calls)
        self.assertEqual([], self.secrets.put_calls)

    def test_management_key_accepts_each_supported_field(self):
        for field in ("api_key", "admin_api_key", "management_api_key"):
            for metadata in ({}, {"organization_id": "org_123"}):
                with self.subTest(field=field, metadata=metadata):
                    self.secrets.management = json.dumps({field: "management-credential", **metadata})
                    self.assertEqual(
                        ("management-credential", "org_123"),
                        rotation.openai_rotation.management_key(self.secrets, self.arn),
                    )

    def test_management_key_rejects_invalid_or_multiple_fields_before_intent(self):
        for fields in ({}, {"management_api_key": ""}, {"admin_api_key": 42},
                       {"api_key": "management-credential", "admin_api_key": "other-credential"}):
            with self.subTest(fields=tuple(fields)):
                self.secrets.management = json.dumps({**fields, "organization_id": "org_123"})
                with self.assertRaises(rotation.openai_rotation.OpenAIManagementSecretError):
                    self.rotate("createSecret")
        self.assertEqual([], self.calls)
        self.assertEqual([], self.secrets.put_calls)

    def test_missing_configured_organization_fails_with_safe_diagnostic_before_intent(self):
        self.project(role="member")
        self.secrets.rotation_rules = {"AutomaticallyAfterDays": 30}
        self.secrets.management = json.dumps({"api_key": "management-credential"})
        del os.environ["OPENAI_ORGANIZATION_ID"]
        event = {"SecretId": self.arn, "ClientRequestToken": self.token,
                 "Step": "createSecret"}
        with patch.object(rotation.boto3, "client", return_value=self.secrets), \
                patch.object(openai_keys, "call_api") as provider, \
                self.assertLogs(rotation.LOG, level="ERROR") as logs, \
                self.assertLogs(rotation.openai_rotation.LOG, level="INFO") as phases:
            with self.assertRaisesRegex(RuntimeError, "^API key rotation failed$"):
                rotation.lambda_handler(event, None)
        failures = [record.getMessage() for record in logs.records]
        self.assertEqual("API key rotation failed: provider=openai step=createSecret "
                         "error_type=OpenAIManagementSecretError", failures[0])
        self.assertRegex(failures[1], r"^rotation_failure source=openai_rotation\.py line=[1-9][0-9]*$")
        self.assertEqual(2, len(failures))
        messages = [record.getMessage() for record in phases.records]
        self.assertEqual("openai_rotation action=reject_management_key reason=organization_env_invalid",
                         messages[-1])
        self.assertNotIn("management-credential", "\n".join(messages))
        provider.assert_not_called()
        self.assertEqual([], self.secrets.put_calls)
        self.assertIn("AWSCURRENT", self.secrets.stages["current"])

    def test_dispatcher_failure_location_does_not_log_exception_text(self):
        event = {"SecretId": self.arn, "ClientRequestToken": self.token, "Step": "createSecret"}
        with patch.object(rotation.boto3, "client", return_value=self.secrets), \
                patch.object(rotation, "rotate", side_effect=ValueError("private-credential-payload")), \
                self.assertLogs(rotation.LOG, level="ERROR") as logs:
            with self.assertRaisesRegex(RuntimeError, "^API key rotation failed$"):
                rotation.lambda_handler(event, None)
        failures = [record.getMessage() for record in logs.records]
        self.assertRegex(failures[-1], r"^rotation_failure source=lambda_function\.py line=[1-9][0-9]*$")
        self.assertNotIn("private-credential-payload", "\n".join(failures))

    def test_invalid_configured_organization_cannot_fall_back_to_secret(self):
        for value in ("", " ", "org_123\n"):
            with self.subTest(value=value), patch.dict(os.environ, {"OPENAI_ORGANIZATION_ID": value}):
                with self.assertRaises(rotation.openai_rotation.OpenAIManagementSecretError):
                    self.rotate("createSecret")
        self.assertEqual([], self.calls)
        self.assertEqual([], self.secrets.put_calls)

    def test_key_only_management_secret_rotates_existing_project_key_with_configured_organization(self):
        self.project(bootstrap=False, role="member")
        self.provider_role = "member"
        self.secrets.management = json.dumps({"api_key": "management-credential"})
        for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
            self.rotate(step)
        self.assertEqual({"org_123"}, {call[4]["organization_id"] for call in self.calls})
        self.assertEqual("management-credential", self.calls_for("POST")[0][2])
        self.assertEqual("key_bootstrap", self.calls_for("DELETE")[0][1].rsplit("/", 1)[-1])
        self.assertIn("AWSCURRENT", self.secrets.stages[self.token])
        self.assertFalse(any("ROTATIONINTENT" in stages for stages in self.secrets.stages.values()))

    def test_management_key_is_independent_and_organization_bound_on_create(self):
        self.rotate("createSecret")
        post = self.calls_for("POST")[0]
        self.assertEqual("management-credential", post[2])
        self.assertEqual("org_123", post[4]["organization_id"])
        self.assertNotEqual(post[2], self.secrets.values[self.token]["api_key"])

    def test_target_key_cannot_be_its_own_management_credential(self):
        self.secrets.management = json.dumps({
            "management_api_key": "management-credential", "organization_id": "org_123"})
        self.secrets.values["current"] = self.credential(
            "admin", "management-credential", "key_old", "previous-name")
        self.secrets.stages["current"] = ["AWSCURRENT"]
        with self.assertRaisesRegex(ValueError, "Independent"):
            self.rotate("createSecret")
        self.assertEqual([], self.calls_for("POST"))

    def test_management_secret_cannot_be_rotation_target(self):
        os.environ["MANAGEMENT_SECRET_ARN"] = self.arn
        with self.assertRaisesRegex(ValueError, "Management secret cannot"):
            self.rotate("createSecret")
        self.assertEqual([], self.calls)

    def test_legacy_current_payload_is_rejected(self):
        self.secrets.values["current"] = {"api_key": "sk-old", "api_key_id": "old-id",
                                           "name": "old-name", "project_id": None}
        self.secrets.stages["current"] = ["AWSCURRENT"]
        with self.assertRaisesRegex(ValueError, "incomplete or legacy"):
            self.rotate("createSecret")
        self.assertEqual([], self.calls_for("POST"))

    def test_malformed_bootstrap_pair_does_not_trigger_first_creation(self):
        self.secrets.values["current"] = {
            "api_key": None, "api_key_id": "__CREATE_NEW__", "name": "extra-field"}
        with self.assertRaisesRegex(ValueError, "bootstrap"):
            self.rotate("createSecret")
        self.assertEqual([], self.calls_for("POST"))

    def test_pending_cleanup_failure_retries_after_current_promotion(self):
        self.project(scopes=["api.model.read"])
        self.rotate("createSecret")
        self.secrets.fail_pending_removal = True
        with self.assertRaisesRegex(RuntimeError, "pending removal"):
            self.rotate("finishSecret")
        self.assertIn("AWSCURRENT", self.secrets.stages[self.token])
        self.assertIn("AWSPENDING", self.secrets.stages[self.token])
        self.assertTrue(any("ROTATIONINTENT" in stages
                            for stages in self.secrets.stages.values()))
        self.secrets.fail_pending_removal = False
        self.rotate("finishSecret")
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])
        self.assertFalse(any("ROTATIONINTENT" in stages
                             for stages in self.secrets.stages.values()))

    def test_provider_retirement_failure_keeps_retryable_intent(self):
        self.project(scopes=["api.model.read"])
        self.rotate("createSecret")
        original = self.provider

        def failed_retirement(method, url, key, payload=None, **kwargs):
            if method == "DELETE":
                raise RuntimeError("provider retirement unavailable")
            return original(method, url, key, payload, **kwargs)

        with patch.object(openai_keys, "call_api", side_effect=failed_retirement):
            with self.assertRaisesRegex(RuntimeError, "retirement unavailable"):
                rotation.openai_rotation.rotate({
                    "SecretId": self.arn, "ClientRequestToken": self.token,
                    "Step": "finishSecret"}, self.secrets)
        self.assertIn("AWSCURRENT", self.secrets.stages[self.token])
        self.assertIn("AWSPENDING", self.secrets.stages[self.token])
        self.assertTrue(any("ROTATIONINTENT" in stages
                            for stages in self.secrets.stages.values()))
        self.rotate("finishSecret")
        self.assertEqual("key_bootstrap", self.calls_for("DELETE")[0][1].rsplit("/", 1)[-1])
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])

    def test_intent_removal_timeout_after_commit_is_safe_on_finish_retry(self):
        self.project(scopes=["api.model.read"])
        self.rotate("createSecret")
        original = self.secrets.update_secret_version_stage

        def timeout_after_intent_removal(**kwargs):
            original(**kwargs)
            if kwargs["VersionStage"] == "ROTATIONINTENT":
                raise RuntimeError("AWS timeout after intent removal")

        with patch.object(self.secrets, "update_secret_version_stage",
                          side_effect=timeout_after_intent_removal):
            with self.assertRaisesRegex(RuntimeError, "intent removal"):
                self.rotate("finishSecret")
        self.rotate("finishSecret")
        self.assertEqual(["AWSCURRENT"], self.secrets.stages[self.token])
        self.assertEqual(1, len(self.calls_for("DELETE")))
        self.assertFalse(any("ROTATIONINTENT" in stages
                             for stages in self.secrets.stages.values()))

    def test_uncertain_pending_write_requires_orphan_reconciliation(self):
        self.secrets.fail_pending_put = True
        with self.assertRaisesRegex(RuntimeError, "reconcile"):
            self.rotate("createSecret")
        with self.assertRaisesRegex(RuntimeError, "reconcile"):
            self.rotate("createSecret")
        self.assertEqual(1, len(self.calls_for("POST")))
        self.assertTrue(any("ROTATIONINTENT" in stages
                            for stages in self.secrets.stages.values()))

    def test_pending_write_timeout_after_commit_reuses_written_version(self):
        original = self.secrets.put_secret_value

        def timeout_after_pending_write(**kwargs):
            original(**kwargs)
            if kwargs.get("VersionStages") == ["AWSPENDING"]:
                raise RuntimeError("AWS timeout after commit")

        with patch.object(self.secrets, "put_secret_value", side_effect=timeout_after_pending_write):
            self.rotate("createSecret")
        self.rotate("createSecret")
        self.assertEqual(1, len(self.calls_for("POST")))
        self.assertEqual(["AWSPENDING"], self.secrets.stages[self.token])

    def test_no_key_created_reconciliation_clears_abandoned_intent(self):
        self.secrets.fail_pending_put = True
        with self.assertRaises(RuntimeError):
            self.rotate("createSecret")
        intent_id = self.intent()["intent_version_id"]
        self.secrets.stages[self.token].remove("AWSPENDING")
        self.rotate("reconcileOrphan", IntentVersionId=intent_id,
                    NoKeyCreatedConfirmed=True)
        self.assertEqual([], self.calls_for("DELETE"))
        self.assertFalse(any("ROTATIONINTENT" in stages
                             for stages in self.secrets.stages.values()))

    def test_orphan_reconciliation_revokes_reported_key_and_clears_intent(self):
        self.secrets.fail_pending_put = True
        with self.assertRaises(RuntimeError):
            self.rotate("createSecret")
        intent_id = self.intent()["intent_version_id"]
        self.secrets.stages[self.token].remove("AWSPENDING")
        self.rotate("reconcileOrphan", IntentVersionId=intent_id, OrphanKeyId=self.new_id)
        self.assertEqual(self.new_id, self.calls_for("DELETE")[0][1].rsplit("/", 1)[-1])
        self.assertFalse(any("ROTATIONINTENT" in stages
                             for stages in self.secrets.stages.values()))

    def test_decommissioned_or_deleting_secret_fails_safe(self):
        for attribute, value in (("rotation_enabled", False), ("deleted_date", self.now)):
            with self.subTest(attribute=attribute):
                setattr(self.secrets, attribute, value)
                with self.assertRaises(ValueError):
                    self.rotate("createSecret")
                setattr(self.secrets, attribute, None if attribute == "deleted_date" else True)
        self.assertEqual([], self.calls)


if __name__ == "__main__":
    unittest.main()
