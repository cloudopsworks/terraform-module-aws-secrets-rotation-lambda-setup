"""Secrets Manager rotation for Terraform-configured OpenAI API keys.

TFCONFIG and TFBOOTSTRAP are read-only. ROTATIONINTENT holds the immutable
per-token snapshot until the predecessor has been retired. A lost Create
response cannot be reconstructed from OpenAI; an unresolved intent requires
explicit operator reconciliation rather than another Create request.
"""

import hashlib
import json
import logging
import math
import os
import re
import time
import uuid
from datetime import datetime, timezone

import openai_keys


LOG = logging.getLogger(__name__)
INTENT_STAGE = "ROTATIONINTENT"
BOOTSTRAP_ID = "__CREATE_NEW__"
MANAGEMENT_KEY_FIELDS = frozenset({"api_key", "admin_api_key", "management_api_key"})
CONFIG_FIELDS = frozenset({
    "schema_version", "key_type", "name", "project_id", "service_account_id",
    "scopes", "role", "expires_in_seconds",
})
CREDENTIAL_FIELDS = frozenset({
    "key_type", "api_key", "api_key_id", "name", "project_id", "service_account_id",
})
SNAPSHOT_FIELDS = frozenset({
    "schema_version", "config_version_id", "config", "previous_version_id",
    "previous_api_key_id", "previous_key_type", "previous_project_id",
    "previous_service_account_id", "bootstrap_kind", "intent_version_id",
    "organization_id", "effective_ttl_seconds", "expiry_safety_seconds",
})
RATE_PATTERN = re.compile(r"^rate\((\d+) (hour|hours|day|days)\)$")
DURATION_PATTERN = re.compile(r"^(\d+)h$")


class OpenAIManagementSecretError(ValueError):
    """The management credential or configured organization is invalid."""


def utcnow():
    return datetime.now(timezone.utc)


def read_json(secrets, arn, **version):
    result = secrets.get_secret_value(SecretId=arn, **version)
    value = json.loads(result["SecretString"])
    if not isinstance(value, dict):
        raise ValueError("Secret version must be a JSON object")
    return value, result["VersionId"]


def intent_version(arn, token):
    return hashlib.sha256(f"openai-intent:{arn}:{token}".encode("utf-8")).hexdigest()


def secret_metadata(secrets, arn):
    if arn == os.environ["MANAGEMENT_SECRET_ARN"]:
        raise ValueError("Management secret cannot be a rotation target")
    metadata = secrets.describe_secret(SecretId=arn)
    if metadata.get("ARN") != arn or metadata.get("DeletedDate") is not None:
        raise ValueError("Secret identity is invalid or scheduled for deletion")
    if not isinstance(metadata.get("VersionIdsToStages"), dict):
        raise ValueError("Secret version stages are unavailable")
    return metadata


def rotation_metadata(secrets, arn, token):
    metadata = secret_metadata(secrets, arn)
    if not metadata.get("RotationEnabled", False):
        raise ValueError("Rotation is not enabled")
    stages = metadata["VersionIdsToStages"].get(token, ())
    if "AWSPENDING" not in stages and "AWSCURRENT" not in stages:
        raise ValueError("Rotation token is not pending or current")
    if "AWSPENDING" in stages and ({"TFCONFIG", "TFBOOTSTRAP"} & set(stages)):
        raise ValueError("Rotation token carries a Terraform-owned stage")
    return metadata


def check_config(config):
    if (not isinstance(config, dict) or set(config) != CONFIG_FIELDS or
            type(config["schema_version"]) is not int or config["schema_version"] != 1 or
            config["key_type"] not in ("admin", "project")):
        raise ValueError("TFCONFIG schema version or fields are invalid")
    if not isinstance(config["name"], str) or not config["name"].strip():
        raise ValueError("TFCONFIG key name is invalid")
    ttl = config["expires_in_seconds"]
    if ttl is not None and (type(ttl) is not int or not 1 <= ttl <= 31536000):
        raise ValueError("TFCONFIG key lifetime is invalid")
    if config["key_type"] == "admin":
        if any(config[field] is not None for field in (
                "project_id", "service_account_id", "scopes", "role")):
            raise ValueError("Admin key has project-only TFCONFIG fields")
    else:
        if any(not isinstance(config[field], str) or not config[field]
               for field in ("project_id", "service_account_id")):
            raise ValueError("Project identity is missing from TFCONFIG")
        scopes = config["scopes"]
        if scopes is not None and (not isinstance(scopes, list) or
                                   any(not isinstance(scope, str) or not scope for scope in scopes)):
            raise ValueError("TFCONFIG scopes must be null or a list of strings")
        if config["role"] is not None and config["role"] not in ("owner", "member"):
            raise ValueError("TFCONFIG service-account role is invalid")


def read_config(secrets, arn):
    for attempt in range(3):
        try:
            config, version_id = read_json(secrets, arn, VersionStage="TFCONFIG")
            check_config(config)
            return config, version_id
        except secrets.exceptions.ResourceNotFoundException:
            if attempt == 2:
                raise RuntimeError("TFCONFIG is unavailable") from None
            time.sleep(0.2 * (attempt + 1))


def check_credential(value, *, bootstrap_allowed=False, stages=()):
    if not isinstance(value, dict):
        raise ValueError("Credential is not a JSON object")
    key, key_id = value.get("api_key"), value.get("api_key_id")
    if key is None or key_id == BOOTSTRAP_ID:
        if (not bootstrap_allowed or "TFBOOTSTRAP" not in stages or
                key is not None or key_id != BOOTSTRAP_ID):
            raise ValueError("Malformed OpenAI bootstrap credential")
        if set(value) == {"api_key", "api_key_id"}:
            return "admin_new"
        if (set(value) == CREDENTIAL_FIELDS and value["key_type"] == "project" and
                all(isinstance(value[field], str) and value[field]
                    for field in ("name", "project_id", "service_account_id"))):
            return "project_new"
        raise ValueError("Malformed OpenAI bootstrap credential")
    if set(value) != CREDENTIAL_FIELDS or any(
            not isinstance(value[field], str) or not value[field]
            for field in ("api_key", "api_key_id", "name")):
        raise ValueError("OpenAI credential is incomplete or legacy")
    if value["key_type"] == "admin":
        if value["project_id"] is not None or value["service_account_id"] is not None:
            raise ValueError("Admin credential has project identity")
    elif value["key_type"] == "project":
        if any(not isinstance(value[field], str) or not value[field]
               for field in ("project_id", "service_account_id")):
            raise ValueError("Project credential identity is incomplete")
    else:
        raise ValueError("OpenAI credential key type is invalid")
    if "TFBOOTSTRAP" in stages:
        if not bootstrap_allowed or value["key_type"] != "project":
            raise ValueError("Active credential carries unexpected TFBOOTSTRAP")
        return "project_existing"
    return "existing"


def effective_ttl(config, metadata):
    if config["expires_in_seconds"] is not None:
        return config["expires_in_seconds"], 0
    rules = metadata.get("RotationRules") or {}
    expression = rules.get("ScheduleExpression")
    if expression is None and type(rules.get("AutomaticallyAfterDays")) is int:
        interval = rules["AutomaticallyAfterDays"] * 86400
        hourly = False
    else:
        match = RATE_PATTERN.fullmatch(expression) if isinstance(expression, str) else None
        if match is None:
            raise ValueError("Explicit expires_in_seconds is required for this rotation schedule")
        interval = int(match.group(1)) * (3600 if match.group(2).startswith("hour") else 86400)
        hourly = match.group(2).startswith("hour")
    if interval < 3600:
        raise ValueError("Rotation interval is invalid")
    if "Duration" in rules:
        duration = rules["Duration"]
        match = DURATION_PATTERN.fullmatch(duration) if isinstance(duration, str) else None
        if match is None or not 1 <= int(match.group(1)) <= 23:
            raise ValueError("Rotation window duration is invalid")
        window = int(match.group(1)) * 3600
    else:
        window = 3600 if hourly else 86400
    guard = max(7200, min(86400, math.ceil(interval / 10)))
    ttl = interval + window + guard
    if ttl > 31536000:
        raise ValueError("Derived key lifetime exceeds OpenAI maximum")
    return ttl, window + guard


def management_key(secrets, target_arn, target_key=None):
    management_arn = os.environ["MANAGEMENT_SECRET_ARN"]
    if target_arn == management_arn:
        raise ValueError("Target secret cannot be its own management credential")
    LOG.info("openai_rotation action=load_management_key")
    value = secrets.get_secret_value(SecretId=management_arn)
    data = json.loads(value["SecretString"])
    organization_id = os.environ.get("OPENAI_ORGANIZATION_ID")
    fields = MANAGEMENT_KEY_FIELDS.intersection(data) if isinstance(data, dict) else ()
    key = data[next(iter(fields))] if len(fields) == 1 else None
    if not isinstance(key, str) or not key.strip():
        reason = "invalid_credential_field"
    elif (not organization_id or not organization_id.strip()
          or "\r" in organization_id or "\n" in organization_id):
        reason = "organization_env_invalid"
    elif "organization_id" in data and data["organization_id"] != organization_id:
        reason = "organization_mismatch"
    elif key == target_key:
        reason = "matches_target_key"
    else:
        return key, organization_id
    LOG.warning("openai_rotation action=reject_management_key reason=%s", reason)
    raise OpenAIManagementSecretError(
        "Independent organization-bound OpenAI management key is required"
    )


def check_snapshot(snapshot, arn, token):
    if (not isinstance(snapshot, dict) or set(snapshot) != SNAPSHOT_FIELDS or
            type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1 or
            snapshot["intent_version_id"] != intent_version(arn, token) or
            not isinstance(snapshot["config_version_id"], str) or not snapshot["config_version_id"] or
            not isinstance(snapshot["previous_version_id"], str) or not snapshot["previous_version_id"] or
            snapshot["previous_version_id"] == token or
            snapshot["organization_id"] != os.environ["OPENAI_ORGANIZATION_ID"]):
        raise ValueError("Rotation snapshot is invalid")
    check_config(snapshot["config"])
    ttl, safety = snapshot["effective_ttl_seconds"], snapshot["expiry_safety_seconds"]
    if (type(ttl) is not int or not 1 <= ttl <= 31536000 or
            type(safety) is not int or safety < 0 or safety >= ttl or
            (snapshot["config"]["expires_in_seconds"] is not None and
             (ttl != snapshot["config"]["expires_in_seconds"] or safety != 0))):
        raise ValueError("Rotation lifetime snapshot is invalid")
    kind, previous_id = snapshot["bootstrap_kind"], snapshot["previous_api_key_id"]
    if kind not in ("admin_new", "project_new", "project_existing", "existing"):
        raise ValueError("Rotation predecessor kind is invalid")
    if kind == "admin_new":
        if previous_id is not None or snapshot["config"]["key_type"] != "admin":
            raise ValueError("Admin bootstrap snapshot is invalid")
    elif kind == "project_new":
        if previous_id is not None or snapshot["config"]["key_type"] != "project":
            raise ValueError("Project bootstrap snapshot is invalid")
    elif not isinstance(previous_id, str) or not previous_id or previous_id == BOOTSTRAP_ID:
        raise ValueError("Rotation predecessor ID is invalid")
    if snapshot["previous_key_type"] != snapshot["config"]["key_type"]:
        raise ValueError("Rotation key type changed")
    if (snapshot["previous_project_id"] != snapshot["config"]["project_id"] or
            snapshot["previous_service_account_id"] != snapshot["config"]["service_account_id"]):
        raise ValueError("Rotation project identity changed")


def read_intent(secrets, arn):
    try:
        intent, version_id = read_json(secrets, arn, VersionStage=INTENT_STAGE)
    except secrets.exceptions.ResourceNotFoundException:
        return None
    token = intent.get("token")
    if (not isinstance(token, str) or not token or intent.get("secret_arn") != arn or
            intent.get("intent_version_id") != version_id or
            not isinstance(intent.get("owner_nonce"), str) or not intent["owner_nonce"]):
        raise ValueError("Rotation intent identity is invalid")
    check_snapshot(intent.get("snapshot"), arn, token)
    return intent


def token_intent(secrets, arn, token):
    intent = read_intent(secrets, arn)
    if intent is None or intent["token"] != token:
        raise ValueError("Rotation intent does not match token")
    return intent


def check_pending(value, snapshot):
    check_credential(value)
    config = snapshot["config"]
    if (value["api_key_id"] == snapshot["previous_api_key_id"] or
            any(value[field] != config[field] for field in (
                "key_type", "name", "project_id", "service_account_id"))):
        raise ValueError("Pending OpenAI credential differs from pinned configuration")


def check_provider_key(details, snapshot, key_id, *, require_lifetime=True):
    config = snapshot["config"]
    if details.get("id") != key_id or details.get("name") != config["name"]:
        raise ValueError("OpenAI did not confirm configured key identity")
    if config["key_type"] == "project":
        owner = details.get("owner")
        service_account = owner.get("service_account") if isinstance(owner, dict) else None
        if (not isinstance(owner, dict) or owner.get("type") != "service_account" or
                not isinstance(service_account, dict) or
                service_account.get("id") != config["service_account_id"] or
                details.get("owner_project_access") != "active"):
            raise ValueError("OpenAI project-key owner changed")
        if config["role"] is not None and service_account.get("role") != config["role"]:
            raise ValueError("OpenAI service-account role changed")
    if require_lifetime:
        expires_at = details.get("expires_at")
        if (type(expires_at) not in (int, float) or not math.isfinite(expires_at) or
                expires_at <= utcnow().timestamp() + snapshot["expiry_safety_seconds"]):
            raise ValueError("OpenAI key expiration is missing or too near")


def clear_completed_intent(secrets, arn, token):
    intent = token_intent(secrets, arn, token)
    stages = secrets.describe_secret(SecretId=arn)["VersionIdsToStages"]
    if "AWSCURRENT" not in stages.get(token, ()) or "AWSPENDING" in stages.get(token, ()):
        raise RuntimeError("Rotation credential has not finished")
    credential, _ = read_json(secrets, arn, VersionId=token, VersionStage="AWSCURRENT")
    check_pending(credential, intent["snapshot"])
    secrets.update_secret_version_stage(
        SecretId=arn, VersionStage=INTENT_STAGE,
        RemoveFromVersionId=intent["intent_version_id"],
    )


def rotate(event, secrets):
    arn, token, step = event["SecretId"], event["ClientRequestToken"], event["Step"]
    if not isinstance(arn, str) or not arn or not isinstance(token, str) or not token:
        raise ValueError("Rotation secret or token is invalid")
    if step not in ("createSecret", "setSecret", "testSecret", "finishSecret", "reconcileOrphan"):
        raise ValueError("Unsupported rotation step")
    LOG.info("openai_rotation step=%s status=started", step)
    metadata = (secret_metadata(secrets, arn) if step == "reconcileOrphan"
                else rotation_metadata(secrets, arn, token))
    correlation = hashlib.sha256(f"{metadata['ARN']}:{token}".encode()).hexdigest()
    LOG.info("openai_rotation invocation correlation=%s", correlation)
    if step == "reconcileOrphan":
        reconcile_orphan(secrets, metadata, event)
    else:
        if "AWSCURRENT" in metadata["VersionIdsToStages"].get(token, ()) and step != "finishSecret":
            LOG.info("openai_rotation action=skip_already_current")
        elif step == "createSecret":
            create_secret(secrets, metadata, event)
        elif step == "setSecret":
            set_secret(secrets, arn, token)
        elif step == "testSecret":
            test_secret(secrets, arn, token)
        else:
            finish_secret(secrets, metadata, token)
    LOG.info("openai_rotation step=%s status=completed", step)


def create_secret(secrets, metadata, event):
    arn, token = metadata["ARN"], event["ClientRequestToken"]
    LOG.info("openai_rotation action=check_existing_pending")
    try:
        pending, _ = read_json(secrets, arn, VersionId=token, VersionStage="AWSPENDING")
    except secrets.exceptions.ResourceNotFoundException:
        pending = None
    if pending is not None:
        check_pending(pending, token_intent(secrets, arn, token)["snapshot"])
        LOG.info("openai_rotation action=reuse_pending")
        return
    intent = read_intent(secrets, arn)
    if intent is not None:
        if intent["token"] != token:
            raise RuntimeError("Another OpenAI rotation is unfinished")
        LOG.error("openai_rotation orphan_reconciliation_required secret_id=%s version_id=%s", arn, token)
        raise RuntimeError("Possible orphaned OpenAI key; reconcile ROTATIONINTENT")
    LOG.info("openai_rotation action=read_configuration")
    config, config_version_id = read_config(secrets, arn)
    current, previous_version_id = read_json(secrets, arn, VersionStage="AWSCURRENT")
    stages = metadata["VersionIdsToStages"].get(previous_version_id, ())
    kind = check_credential(current, bootstrap_allowed=True, stages=stages)
    if kind in ("admin_new", "project_new"):
        if (config["key_type"] != ("admin" if kind == "admin_new" else "project") or
                (kind == "project_new" and any(current[field] != config[field]
                 for field in ("name", "project_id", "service_account_id")))):
            raise ValueError("Bootstrap identity conflicts with TFCONFIG")
        previous_id = None
        previous_type = config["key_type"]
        previous_project = config["project_id"]
        previous_account = config["service_account_id"]
    else:
        if (current["key_type"] != config["key_type"] or
                current["project_id"] != config["project_id"] or
                current["service_account_id"] != config["service_account_id"]):
            raise ValueError("Current key identity differs from TFCONFIG")
        previous_id, previous_type = current["api_key_id"], current["key_type"]
        previous_project = current["project_id"]
        previous_account = current["service_account_id"]
    ttl, safety = effective_ttl(config, metadata)
    admin_key, organization_id = management_key(secrets, arn, current.get("api_key"))
    LOG.info("openai_rotation action=verify_management_key")
    openai_keys.validate_key(admin_key, {"key_type": "admin"}, organization_id)
    if config["key_type"] == "project":
        LOG.info("openai_rotation action=verify_service_account")
        service_account = openai_keys.get_service_account(admin_key, config, organization_id)
        if config["role"] is not None and service_account.get("role") != config["role"]:
            raise ValueError("OpenAI service-account role differs from TFCONFIG")
    snapshot = {
        "schema_version": 1, "config_version_id": config_version_id,
        "config": config, "previous_version_id": previous_version_id,
        "previous_api_key_id": previous_id, "previous_key_type": previous_type,
        "previous_project_id": previous_project,
        "previous_service_account_id": previous_account,
        "bootstrap_kind": kind, "intent_version_id": intent_version(arn, token),
        "organization_id": organization_id,
        "effective_ttl_seconds": ttl, "expiry_safety_seconds": safety,
    }
    intent = {
        "intent_version_id": snapshot["intent_version_id"], "secret_arn": arn,
        "token": token, "snapshot": snapshot, "owner_nonce": uuid.uuid4().hex,
    }
    extra = {"RotationToken": event["RotationToken"]} if event.get("RotationToken") else {}
    # If this write errors ambiguously, do not call the non-idempotent API.
    LOG.info("openai_rotation action=write_intent")
    secrets.put_secret_value(
        SecretId=arn, ClientRequestToken=snapshot["intent_version_id"],
        SecretString=json.dumps(intent, sort_keys=True), VersionStages=[INTENT_STAGE], **extra,
    )
    saved_intent = token_intent(secrets, arn, token)
    if saved_intent != intent:
        raise RuntimeError("Rotation intent ownership changed")
    LOG.info("openai_rotation action=issue_replacement")
    key, key_id = openai_keys.create_key(admin_key, {**config, "expires_in_seconds": ttl}, organization_id)
    LOG.info("openai_rotation issued secret_id=%s version_id=%s key_id=%s", arn, token, key_id)
    if key == admin_key or key_id == previous_id:
        raise ValueError("OpenAI returned a non-independent replacement key")
    pending = {
        "key_type": config["key_type"], "api_key": key, "api_key_id": key_id,
        "name": config["name"], "project_id": config["project_id"],
        "service_account_id": config["service_account_id"],
    }
    LOG.info("openai_rotation action=write_pending")
    try:
        secrets.put_secret_value(
            SecretId=arn, ClientRequestToken=token,
            SecretString=json.dumps(pending, sort_keys=True), VersionStages=["AWSPENDING"], **extra,
        )
    except Exception:
        LOG.info("openai_rotation action=verify_pending_after_write_error")
        try:
            saved, _ = read_json(secrets, arn, VersionId=token)
        except Exception:
            raise RuntimeError("Pending write unconfirmed; reconcile ROTATIONINTENT") from None
        if saved != pending:
            raise RuntimeError("Pending version differs; reconcile ROTATIONINTENT") from None
    saved, _ = read_json(secrets, arn, VersionId=token)
    if saved != pending:
        raise RuntimeError("Pending version differs; reconcile ROTATIONINTENT")
    check_pending(saved, token_intent(secrets, arn, token)["snapshot"])


def set_secret(secrets, arn, token):
    LOG.info("openai_rotation action=check_pending_staging")
    pending, _ = read_json(secrets, arn, VersionId=token, VersionStage="AWSPENDING")
    snapshot = token_intent(secrets, arn, token)["snapshot"]
    check_pending(pending, snapshot)
    # OpenAI key role is Terraform-owned service-account identity, not a PATCH.


def test_secret(secrets, arn, token):
    LOG.info("openai_rotation action=check_pending_staging")
    pending, _ = read_json(secrets, arn, VersionId=token, VersionStage="AWSPENDING")
    snapshot = token_intent(secrets, arn, token)["snapshot"]
    check_pending(pending, snapshot)
    admin_key, organization_id = management_key(secrets, arn, pending["api_key"])
    LOG.info("openai_rotation action=check_provider_metadata")
    details = openai_keys.get_key(admin_key, snapshot["config"], pending["api_key_id"], organization_id)
    check_provider_key(details, snapshot, pending["api_key_id"])
    LOG.info("openai_rotation action=check_pending_auth")
    try:
        openai_keys.validate_key(pending["api_key"], snapshot["config"], organization_id)
    except NotImplementedError:
        # OpenAI has no universal read-only auth probe for arbitrary project
        # scopes. A provider-created value and management-key owner lookup are
        # the strongest available checks for these keys; never accept 401/403.
        LOG.info("openai_rotation management_metadata_only secret_id=%s version_id=%s key_id=%s",
                 arn, token, pending["api_key_id"])
    else:
        LOG.info("openai_rotation action=pending_auth_verified")


def finish_secret(secrets, metadata, token):
    arn = metadata["ARN"]
    LOG.info("openai_rotation action=check_promotion_state")
    already_current = "AWSCURRENT" in metadata["VersionIdsToStages"].get(token, ())
    intent = read_intent(secrets, arn)
    if already_current and (intent is None or intent["token"] != token):
        if "AWSPENDING" in metadata["VersionIdsToStages"].get(token, ()):
            raise ValueError("Pending label remains without rotation intent")
        current, _ = read_json(secrets, arn, VersionId=token, VersionStage="AWSCURRENT")
        check_credential(current)
        LOG.info("openai_rotation action=skip_completed_rotation")
        return
    if intent is None or intent["token"] != token:
        raise ValueError("Rotation intent does not match token")
    snapshot = intent["snapshot"]
    stage = "AWSCURRENT" if already_current else "AWSPENDING"
    pending, _ = read_json(secrets, arn, VersionId=token, VersionStage=stage)
    check_pending(pending, snapshot)
    previous_id = snapshot["previous_version_id"]
    previous, _ = read_json(secrets, arn, VersionId=previous_id)
    previous_stages = metadata["VersionIdsToStages"].get(previous_id, ())
    kind = check_credential(previous, bootstrap_allowed=True, stages=previous_stages)
    if (kind != snapshot["bootstrap_kind"] or previous.get("api_key_id") != (
            BOOTSTRAP_ID if kind in ("admin_new", "project_new") else snapshot["previous_api_key_id"]) or
            (kind != "admin_new" and (
                previous["key_type"] != snapshot["previous_key_type"] or
                previous["project_id"] != snapshot["previous_project_id"] or
                previous["service_account_id"] != snapshot["previous_service_account_id"]))):
        raise ValueError("Rotation predecessor differs from saved snapshot")
    if not already_current:
        current, current_version = read_json(secrets, arn, VersionStage="AWSCURRENT")
        if current_version != previous_id or current != previous:
            raise ValueError("Current key changed before promotion")
        test_secret(secrets, arn, token)
        LOG.info("openai_rotation action=promote_pending")
        secrets.update_secret_version_stage(
            SecretId=arn, VersionStage="AWSCURRENT",
            MoveToVersionId=token, RemoveFromVersionId=previous_id,
        )
    else:
        LOG.info("openai_rotation action=resume_after_promotion")
    stages = secrets.describe_secret(SecretId=arn)["VersionIdsToStages"]
    if "AWSCURRENT" not in stages.get(token, ()) or "AWSPREVIOUS" not in stages.get(previous_id, ()):
        raise ValueError("Rotation stages changed before predecessor retirement")
    current, current_version = read_json(secrets, arn, VersionStage="AWSCURRENT")
    if current_version != token or current != pending:
        raise ValueError("Promoted credential differs from saved pending version")
    if kind not in ("admin_new", "project_new"):
        admin_key, organization_id = management_key(secrets, arn, previous["api_key"])
        LOG.info("openai_rotation action=retire_predecessor")
        openai_keys.delete_key(admin_key, snapshot["config"], snapshot["previous_api_key_id"], organization_id)
        LOG.info("openai_rotation retired secret_id=%s version_id=%s key_id=%s", arn, previous_id, snapshot["previous_api_key_id"])
    else:
        LOG.info("openai_rotation action=no_predecessor_to_retire")
    stages = secrets.describe_secret(SecretId=arn)["VersionIdsToStages"]
    if "AWSCURRENT" not in stages.get(token, ()):
        raise ValueError("Current stage changed before pending cleanup")
    if "AWSPENDING" in stages.get(token, ()):
        LOG.info("openai_rotation action=clear_pending_stage")
        secrets.update_secret_version_stage(
            SecretId=arn, VersionStage="AWSPENDING", RemoveFromVersionId=token,
        )
    LOG.info("openai_rotation action=clear_intent")
    clear_completed_intent(secrets, arn, token)


def reconcile_orphan(secrets, metadata, event):
    arn, token = metadata["ARN"], event["ClientRequestToken"]
    LOG.info("openai_rotation action=check_orphan_intent")
    key_id, intent_id = event.get("OrphanKeyId"), event.get("IntentVersionId")
    no_key_created = event.get("NoKeyCreatedConfirmed") is True
    if (not isinstance(intent_id, str) or not intent_id or
            (no_key_created and key_id is not None) or
            (not no_key_created and (not isinstance(key_id, str) or not key_id))):
        raise ValueError("Orphan reconciliation requires intent and one confirmed outcome")
    intent = token_intent(secrets, arn, token)
    if intent["intent_version_id"] != intent_id:
        raise ValueError("Orphan reconciliation intent differs from token")
    if {"AWSPENDING", "AWSCURRENT", "AWSPREVIOUS"} & set(
            metadata["VersionIdsToStages"].get(token, ())):
        raise ValueError("Abandon token stages before orphan reconciliation")
    try:
        read_json(secrets, arn, VersionId=token)
    except secrets.exceptions.ResourceNotFoundException:
        pass
    else:
        raise ValueError("Credential version exists; this is not an orphan")
    if key_id is not None and key_id == intent["snapshot"]["previous_api_key_id"]:
        raise ValueError("Cannot reconcile predecessor as orphan")
    if not no_key_created:
        LOG.info("openai_rotation action=verify_orphan_identity")
        for version_id, stages in metadata["VersionIdsToStages"].items():
            if not ({"AWSCURRENT", "AWSPENDING", "AWSPREVIOUS"} & set(stages)):
                continue
            credential, _ = read_json(secrets, arn, VersionId=version_id)
            if credential.get("api_key_id") == key_id:
                raise ValueError("Orphan ID is referenced by a staged credential")
        admin_key, organization_id = management_key(secrets, arn)
        details = openai_keys.get_key_if_present(
            admin_key, intent["snapshot"]["config"], key_id, organization_id)
        if details is not None:
            check_provider_key(details, intent["snapshot"], key_id, require_lifetime=False)
        LOG.info("openai_rotation action=revoke_orphan_key")
        openai_keys.delete_key(admin_key, intent["snapshot"]["config"], key_id, organization_id)
    else:
        LOG.info("openai_rotation action=no_orphan_key_confirmed")
    LOG.info("openai_rotation action=clear_intent")
    secrets.update_secret_version_stage(
        SecretId=arn, VersionStage=INTENT_STAGE, RemoveFromVersionId=intent_id,
    )
