"""Secrets Manager four-step rotation for Terraform-configured OpenRouter keys.

TFCONFIG and TFBOOTSTRAP are Terraform-owned, read-only staging labels. An
intent version is written before the non-idempotent provider Create request.
If Create may have happened without a durable credential version, retries stop
instead of issuing a second key. An IAM-authorized operator must determine
whether a key was created, identify any orphan hash from provider evidence,
abandon the old token's AWSPENDING
stage, then invoke this Lambda with Step
``reconcileOrphan``, SecretId, the old ClientRequestToken, IntentVersionId, and
either OrphanKeyId or NoKeyCreatedConfirmed=true before starting a new
rotation. The Lambda
refuses to identify an orphan by name alone. If its hash cannot be confirmed,
the intent remains and rotation stays blocked rather than deleting an
unrelated key. There is no automatic final-key decommission on secret deletion.
"""

import hashlib
import json
import logging
import math
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

import openrouter_keys


LOG = logging.getLogger(__name__)
INTENT_STAGE = "ROTATIONINTENT"
BOOTSTRAP_ID = "__CREATE_NEW__"
CONFIG_FIELDS = frozenset({
    "schema_version", "name", "workspace_id", "limit", "limit_reset",
    "include_byok_in_limit", "disabled", "expires_at", "creator_user_id",
})
SNAPSHOT_FIELDS = frozenset({
    "schema_version", "config_version_id", "config", "previous_version_id",
    "previous_api_key_id", "intent_version_id", "effective_expires_at",
    "expiry_safety_seconds",
})
CREDENTIAL_FIELDS = frozenset({"api_key", "api_key_id", "name", "workspace_id"})
RATE_PATTERN = re.compile(r"^rate\((\d+) (hour|hours|day|days)\)$")
DURATION_PATTERN = re.compile(r"^(\d+)h$")


def read_json(secrets, arn, **version):
    result = secrets.get_secret_value(SecretId=arn, **version)
    value = json.loads(result["SecretString"])
    if not isinstance(value, dict):
        raise ValueError("Secret version must be a JSON object")
    return value, result["VersionId"]


def parse_expiry(value):
    if not isinstance(value, str) or not value:
        raise ValueError("TFCONFIG expires_at is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("TFCONFIG expires_at is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("TFCONFIG expires_at must be UTC")
    return parsed


def check_config(config):
    if (not isinstance(config, dict) or set(config) != CONFIG_FIELDS or
            type(config["schema_version"]) is not int or config["schema_version"] != 1):
        raise ValueError("TFCONFIG schema version or fields are invalid")
    name = config["name"]
    if not isinstance(name, str) or not 1 <= len(name) <= 256 or not name.strip():
        raise ValueError("TFCONFIG name is invalid")
    for field in ("workspace_id", "creator_user_id"):
        value = config[field]
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError(f"TFCONFIG {field} is invalid")
    expiry = config["expires_at"]
    if expiry is not None:
        parse_expiry(expiry)
    limit = config["limit"]
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, (int, float)) or
                              not math.isfinite(limit) or limit < 0):
        raise ValueError("TFCONFIG limit is invalid")
    if config["limit_reset"] not in (None, "daily", "weekly", "monthly"):
        raise ValueError("TFCONFIG limit_reset is invalid")
    for field in ("include_byok_in_limit", "disabled"):
        if config[field] is not None and not isinstance(config[field], bool):
            raise ValueError(f"TFCONFIG {field} is invalid")


def utcnow():
    return datetime.now(timezone.utc)


def effective_expiry(config, metadata):
    """Pin a key lifetime longer than one supported rotation interval.

    NextRotationDate can refer to the rotation already in progress, so it is
    not used as the only expiry bound. Cron cannot be bounded correctly here
    without a full AWS cron evaluator; require explicit TFCONFIG.expires_at.
    """
    if config["expires_at"] is not None:
        if parse_expiry(config["expires_at"]) <= utcnow():
            raise ValueError("Explicit TFCONFIG expiration has already passed")
        return config["expires_at"], 0
    rules = metadata.get("RotationRules")
    if not isinstance(rules, dict):
        raise ValueError("Rotation rules are required to derive expiration")
    expression = rules.get("ScheduleExpression")
    if expression is None:
        days = rules.get("AutomaticallyAfterDays")
        if type(days) is not int or days < 1:
            raise ValueError("Rotation interval is unavailable")
        interval = timedelta(days=days)
        hourly = False
    else:
        match = RATE_PATTERN.fullmatch(expression) if isinstance(expression, str) else None
        if match is None:
            raise ValueError("Explicit expires_at is required for non-rate rotation schedules")
        count = int(match.group(1))
        unit = match.group(2)
        if count < 1:
            raise ValueError("Rotation interval is invalid")
        hourly = unit.startswith("hour")
        interval = timedelta(hours=count) if hourly else timedelta(days=count)
    # When Duration is omitted, AWS's hourly window defaults to one hour;
    # daily windows can extend to the end of the UTC day. A full-day allowance
    # is conservative when the exact aligned window start is unknown here.
    if "Duration" not in rules:
        window = timedelta(hours=1) if hourly else timedelta(days=1)
    else:
        duration = rules["Duration"]
        match = DURATION_PATTERN.fullmatch(duration) if isinstance(duration, str) else None
        if match is None or not 1 <= int(match.group(1)) <= 23:
            raise ValueError("Rotation window duration is invalid")
        window = timedelta(hours=int(match.group(1)))
    guard = max(timedelta(hours=2), min(timedelta(hours=24), interval / 10))
    expires = utcnow() + interval + window + guard
    return expires.strftime("%Y-%m-%dT%H:%M:%SZ"), int((window + guard).total_seconds())


def read_config(secrets, arn):
    # A Terraform stage replacement can briefly hide TFCONFIG. Never use
    # Lambda environment or old-key metadata as a fallback.
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
    key = value.get("api_key")
    key_id = value.get("api_key_id")
    if key is None or key_id == BOOTSTRAP_ID:
        if (not bootstrap_allowed or key is not None or key_id != BOOTSTRAP_ID or
                "TFBOOTSTRAP" not in stages):
            raise ValueError("Malformed bootstrap credential")
        return True
    if "TFBOOTSTRAP" in stages:
        raise ValueError("Active credential carries TFBOOTSTRAP")
    if (not isinstance(key, str) or not key or not isinstance(key_id, str) or not key_id or
            not isinstance(value.get("name"), str) or not value["name"] or
            (value.get("workspace_id") is not None and
             (not isinstance(value["workspace_id"], str) or not value["workspace_id"])) or
            "workspace_id" not in value):
        raise ValueError("OpenRouter credential is incomplete")
    return False


def management_key(secrets):
    value = secrets.get_secret_value(SecretId=os.environ["MANAGEMENT_SECRET_ARN"])
    secret = value["SecretString"].strip()
    if secret.startswith("{"):
        data = json.loads(secret)
        secret = data.get("api_key") or data.get("admin_api_key") or data.get("management_api_key")
    if not isinstance(secret, str) or not secret:
        raise ValueError("Management key secret is empty")
    return secret


def intent_version(arn, token):
    return hashlib.sha256(f"openrouter-intent:{arn}:{token}".encode("utf-8")).hexdigest()


def check_snapshot(snapshot, arn, token):
    if (not isinstance(snapshot, dict) or set(snapshot) != SNAPSHOT_FIELDS or
            type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1 or
            not isinstance(snapshot["config_version_id"], str) or not snapshot["config_version_id"] or
            not isinstance(snapshot["previous_version_id"], str) or not snapshot["previous_version_id"] or
            snapshot["previous_version_id"] == token or
            snapshot["intent_version_id"] != intent_version(arn, token)):
        raise ValueError("Rotation snapshot is invalid")
    check_config(snapshot["config"])
    parse_expiry(snapshot["effective_expires_at"])
    safety = snapshot["expiry_safety_seconds"]
    if type(safety) is not int or safety < 0:
        raise ValueError("Rotation expiry safety margin is invalid")
    if (snapshot["config"]["expires_at"] is not None and
            (snapshot["effective_expires_at"] != snapshot["config"]["expires_at"] or safety != 0)):
        raise ValueError("Rotation expiry differs from explicit TFCONFIG")
    if snapshot["config"]["expires_at"] is None and safety == 0:
        raise ValueError("Derived rotation expiry lacks safety margin")
    previous_id = snapshot["previous_api_key_id"]
    if previous_id is not None and (not isinstance(previous_id, str) or not previous_id or previous_id == BOOTSTRAP_ID):
        raise ValueError("Rotation predecessor identifier is invalid")


def check_pending(value, snapshot):
    if set(value) != CREDENTIAL_FIELDS:
        raise ValueError("Pending credential must contain only four fields")
    check_credential(value)
    if value["api_key_id"] == snapshot["previous_api_key_id"]:
        raise ValueError("Pending key identifier matches predecessor")
    if value["name"] != snapshot["config"]["name"]:
        raise ValueError("Pending key name differs from pinned TFCONFIG")
    requested_workspace = snapshot["config"]["workspace_id"]
    if requested_workspace is not None and value["workspace_id"] != requested_workspace:
        raise ValueError("Pending workspace differs from pinned TFCONFIG")


def token_intent(secrets, arn, token):
    intent = read_intent(secrets, arn)
    if intent is None or intent["token"] != token:
        raise ValueError("Rotation intent does not match token")
    return intent


def read_intent(secrets, arn):
    try:
        intent, version_id = read_json(secrets, arn, VersionStage=INTENT_STAGE)
    except secrets.exceptions.ResourceNotFoundException:
        return None
    if intent.get("intent_version_id") != version_id or intent.get("secret_arn") != arn:
        raise ValueError("Rotation intent identity is invalid")
    token = intent.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError("Rotation intent token is invalid")
    if not isinstance(intent.get("owner_nonce"), str) or not intent["owner_nonce"]:
        raise ValueError("Rotation intent owner is invalid")
    check_snapshot(intent.get("snapshot"), arn, token)
    if intent["snapshot"]["intent_version_id"] != version_id:
        raise ValueError("Rotation intent version differs from snapshot")
    return intent


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


def secret_metadata(secrets, arn):
    metadata = secrets.describe_secret(SecretId=arn)
    if arn not in (metadata.get("ARN"), metadata.get("Name")):
        raise ValueError("SecretId does not match described secret identity")
    if metadata.get("DeletedDate") is not None:
        raise ValueError("Secret is scheduled for deletion")
    if not isinstance(metadata.get("VersionIdsToStages"), dict):
        raise ValueError("Secret version stages are unavailable")
    return metadata


def rotation_metadata(secrets, arn, token):
    metadata = secret_metadata(secrets, arn)
    if not metadata.get("RotationEnabled", False):
        raise ValueError("Rotation is not enabled")
    stages = {version: tuple(labels) for version, labels in metadata["VersionIdsToStages"].items()}
    if "AWSPENDING" not in stages.get(token, ()) and "AWSCURRENT" not in stages.get(token, ()):
        raise ValueError("Rotation token is not pending or current")
    return metadata


def rotate(event, secrets):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    if not isinstance(arn, str) or not arn or not isinstance(token, str) or not token:
        raise ValueError("Rotation secret or token is invalid")
    if step not in ("createSecret", "setSecret", "testSecret", "finishSecret", "reconcileOrphan"):
        raise ValueError("Unsupported rotation step")
    if step == "reconcileOrphan":
        metadata = secret_metadata(secrets, arn)
        reconcile_orphan(secrets, metadata, event)
        return
    metadata = rotation_metadata(secrets, arn, token)
    if "AWSCURRENT" in metadata["VersionIdsToStages"].get(token, ()) and step != "finishSecret":
        return
    if step == "createSecret":
        create_secret(secrets, metadata, token)
    elif step == "setSecret":
        set_secret(secrets, metadata["ARN"], token)
    elif step == "testSecret":
        test_secret(secrets, metadata["ARN"], token)
    else:
        finish_secret(secrets, metadata, token)


def reconcile_orphan(secrets, metadata, event):
    """Revoke an operator-confirmed orphan after abandoning its old token.

    This is an explicit IAM-authorized Lambda invocation, not an automatic
    Secrets Manager rotation step. The caller must identify the provider hash;
    a name match alone is not proof that a key belongs to this intent.
    """
    arn = metadata["ARN"]
    token = event["ClientRequestToken"]
    key_id = event.get("OrphanKeyId")
    intent_id = event.get("IntentVersionId")
    no_key_created = event.get("NoKeyCreatedConfirmed") is True
    if (not isinstance(intent_id, str) or not intent_id or
            (no_key_created and key_id is not None) or
            (not no_key_created and (not isinstance(key_id, str) or not key_id))):
        raise ValueError("Orphan reconciliation requires an intent and one confirmed outcome")
    intent = read_intent(secrets, arn)
    if intent is None or intent["token"] != token or intent["intent_version_id"] != intent_id:
        raise ValueError("Orphan reconciliation intent does not match token")
    if {"AWSPENDING", "AWSCURRENT", "AWSPREVIOUS"} & set(metadata["VersionIdsToStages"].get(token, ())):
        raise ValueError("Abandon the token's rotation stage before orphan reconciliation")
    if key_id is not None and key_id == intent["snapshot"]["previous_api_key_id"]:
        raise ValueError("Cannot reconcile the predecessor as an orphan")
    try:
        saved, _ = read_json(secrets, arn, VersionId=token)
    except secrets.exceptions.ResourceNotFoundException:
        saved = None
    if saved is not None:
        # An abandoned pending version records its own key hash. That is the
        # strongest ownership evidence available, but the operator must still
        # confirm the exact hash before it is revoked.
        check_pending(saved, intent["snapshot"])
        if no_key_created:
            raise ValueError("Saved credential proves a key was created")
        if key_id != saved["api_key_id"]:
            raise ValueError("OrphanKeyId differs from the abandoned saved credential")
    if no_key_created:
        secrets.update_secret_version_stage(
            SecretId=arn, VersionStage=INTENT_STAGE, RemoveFromVersionId=intent_id,
        )
        LOG.info("openrouter_rotation no_key_confirmed secret_id=%s version_id=%s", arn, token)
        return
    # Never delete any key referenced by a staged credential. AWSPREVIOUS may
    # still be serving clients during an unrelated rotation or retry.
    for version_id, stages in metadata["VersionIdsToStages"].items():
        if not ({"AWSCURRENT", "AWSPENDING", "AWSPREVIOUS"} & set(stages)):
            continue
        try:
            credential, _ = read_json(secrets, arn, VersionId=version_id)
        except secrets.exceptions.ResourceNotFoundException:
            # A new rotation's AWSPENDING placeholder has no value yet and
            # therefore cannot reference any provider key.
            continue
        if credential.get("api_key_id") == key_id:
            raise ValueError("Orphan key is referenced by a staged credential")
    admin_key = management_key(secrets)
    details = openrouter_keys.get_key_if_present(admin_key, key_id)
    if details is not None:
        config = intent["snapshot"]["config"]
        if details.get("name") != config["name"]:
            raise ValueError("Orphan key name differs from pinned TFCONFIG")
        if config["workspace_id"] is not None and details.get("workspace_id") != config["workspace_id"]:
            raise ValueError("Orphan key workspace differs from pinned TFCONFIG")
    openrouter_keys.delete_key(admin_key, key_id)
    secrets.update_secret_version_stage(
        SecretId=arn, VersionStage=INTENT_STAGE, RemoveFromVersionId=intent_id,
    )
    LOG.info("openrouter_rotation orphan_retired secret_id=%s version_id=%s key_id=%s", arn, token, key_id)


def resume_completed_intent(secrets, metadata, intent):
    """Finish a promoted rotation whose cleanup was interrupted.

    finishSecret removes AWSPENDING before ROTATIONINTENT. If it stops between
    those calls, Secrets Manager starts the next rotation with a new token
    while the old intent remains. Its token is already AWSCURRENT, so resuming
    its finishSecret only repeats idempotent predecessor retirement and label
    cleanup; no provider key is created. Any other intent is left in place.
    """
    old_token = intent["token"]
    if "AWSCURRENT" not in metadata["VersionIdsToStages"].get(old_token, ()):
        return intent
    LOG.info("openrouter_rotation resume_completed_intent secret_id=%s version_id=%s", metadata["ARN"], old_token)
    finish_secret(secrets, metadata, old_token)
    return read_intent(secrets, metadata["ARN"])


def create_secret(secrets, metadata, token):
    arn = metadata["ARN"]
    # Reuse a durable pending credential, but retain the intent snapshot
    # through predecessor retirement and pending-label cleanup.
    try:
        pending, _ = read_json(secrets, arn, VersionId=token, VersionStage="AWSPENDING")
    except secrets.exceptions.ResourceNotFoundException:
        pending = None
    if pending is not None:
        check_pending(pending, token_intent(secrets, arn, token)["snapshot"])
        return
    intent = read_intent(secrets, arn)
    if intent is not None and intent["token"] != token:
        intent = resume_completed_intent(secrets, metadata, intent)
    if intent is not None:
        if intent["token"] != token:
            LOG.error("openrouter_rotation orphan_reconciliation_required secret_id=%s version_id=%s intent_version_id=%s",
                      arn, intent["token"], intent["intent_version_id"])
            raise RuntimeError("Another OpenRouter rotation is unfinished; reconcile ROTATIONINTENT")
        LOG.error("openrouter_rotation orphan_reconciliation_required secret_id=%s version_id=%s", arn, token)
        raise RuntimeError("Possible orphaned OpenRouter key; reconcile ROTATIONINTENT")
    config, config_version_id = read_config(secrets, arn)
    expires_at, expiry_safety_seconds = effective_expiry(config, metadata)
    current, previous_version_id = read_json(secrets, arn, VersionStage="AWSCURRENT")
    previous_stages = metadata["VersionIdsToStages"].get(previous_version_id, ())
    bootstrap = check_credential(current, bootstrap_allowed=True, stages=previous_stages)
    previous_id = None if bootstrap else current["api_key_id"]
    snapshot = {
        "schema_version": 1, "config_version_id": config_version_id,
        "config": config, "previous_version_id": previous_version_id,
        "previous_api_key_id": previous_id,
        "intent_version_id": intent_version(arn, token),
        "effective_expires_at": expires_at,
        "expiry_safety_seconds": expiry_safety_seconds,
    }
    intent = {
        "intent_version_id": snapshot["intent_version_id"], "secret_arn": arn,
        "token": token, "snapshot": snapshot, "owner_nonce": uuid.uuid4().hex,
    }
    admin_key = management_key(secrets)
    # A successful intent write is the point of no automatic retry. If the
    # call errors ambiguously, no provider Create is sent by this invocation.
    secrets.put_secret_value(
        SecretId=arn, ClientRequestToken=snapshot["intent_version_id"],
        SecretString=json.dumps(intent, sort_keys=True), VersionStages=[INTENT_STAGE],
    )
    key, key_id = openrouter_keys.create_key(admin_key, {**config, "expires_at": expires_at})
    # This ID is safe to log and helps an operator identify a possible orphan
    # if the plaintext cannot be saved after Create.
    LOG.info("openrouter_rotation issued secret_id=%s version_id=%s key_id=%s", arn, token, key_id)
    details = openrouter_keys.get_key(admin_key, key_id)
    if details.get("name") != config["name"]:
        raise ValueError("OpenRouter did not confirm configured key name")
    if "expires_at" not in details or parse_expiry(details["expires_at"]) != parse_expiry(expires_at):
        raise ValueError("OpenRouter did not confirm configured expiration")
    if "workspace_id" not in details:
        raise ValueError("OpenRouter key metadata omitted workspace")
    workspace = details["workspace_id"]
    if workspace is not None and (not isinstance(workspace, str) or not workspace):
        raise ValueError("OpenRouter returned an invalid workspace")
    if config["workspace_id"] is not None and workspace != config["workspace_id"]:
        raise ValueError("OpenRouter did not confirm configured workspace")
    pending = {
        "api_key": key, "api_key_id": key_id, "name": config["name"],
        "workspace_id": workspace,
    }
    try:
        secrets.put_secret_value(
            SecretId=arn, ClientRequestToken=token,
            SecretString=json.dumps(pending, sort_keys=True), VersionStages=["AWSPENDING"],
        )
    except Exception:
        # The AWS write may have committed despite an error. A successful
        # immutable read-back is the only proof that this key is recoverable.
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
    LOG.info("openrouter_rotation pending_persisted secret_id=%s version_id=%s key_id=%s", arn, token, key_id)


def set_secret(secrets, arn, token):
    pending, _ = read_json(secrets, arn, VersionId=token, VersionStage="AWSPENDING")
    snapshot = token_intent(secrets, arn, token)["snapshot"]
    check_pending(pending, snapshot)
    disabled = snapshot["config"]["disabled"]
    if disabled is not None:
        admin_key = management_key(secrets)
        openrouter_keys.update_disabled(admin_key, pending["api_key_id"], disabled)
        details = openrouter_keys.get_key(admin_key, pending["api_key_id"])
        if details.get("disabled") is not disabled:
            raise ValueError("OpenRouter did not retain configured disabled setting")


def test_secret(secrets, arn, token):
    pending, _ = read_json(secrets, arn, VersionId=token, VersionStage="AWSPENDING")
    snapshot = token_intent(secrets, arn, token)["snapshot"]
    check_pending(pending, snapshot)
    if (snapshot["config"]["expires_at"] is None and
            parse_expiry(snapshot["effective_expires_at"]) <=
            utcnow() + timedelta(seconds=snapshot["expiry_safety_seconds"])):
        raise ValueError("Derived key expiration is too near to promote")
    admin_key = management_key(secrets)
    details = openrouter_keys.get_key(admin_key, pending["api_key_id"])
    if details.get("workspace_id") != pending["workspace_id"]:
        raise ValueError("OpenRouter key workspace changed")
    disabled = snapshot["config"]["disabled"]
    if disabled is not None and details.get("disabled") is not disabled:
        raise ValueError("OpenRouter key disabled setting changed")
    if disabled is not True:
        openrouter_keys.validate_key(pending["api_key"])


def finish_secret(secrets, metadata, token):
    arn = metadata["ARN"]
    already_current = "AWSCURRENT" in metadata["VersionIdsToStages"].get(token, ())
    intent = read_intent(secrets, arn)
    if already_current and (intent is None or intent["token"] != token):
        if "AWSPENDING" in metadata["VersionIdsToStages"].get(token, ()):
            raise ValueError("Pending label remains without rotation intent")
        current, _ = read_json(secrets, arn, VersionId=token, VersionStage="AWSCURRENT")
        if set(current) != CREDENTIAL_FIELDS:
            raise ValueError("Completed credential has unexpected fields")
        check_credential(current)
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
    bootstrap = check_credential(previous, bootstrap_allowed=True, stages=previous_stages)
    if previous.get("api_key_id") != (BOOTSTRAP_ID if bootstrap else snapshot["previous_api_key_id"]):
        raise ValueError("Rotation predecessor differs from saved snapshot")
    if bootstrap != (snapshot["previous_api_key_id"] is None):
        raise ValueError("Rotation bootstrap snapshot is inconsistent")
    if not already_current:
        current, current_version = read_json(secrets, arn, VersionStage="AWSCURRENT")
        if current_version != previous_id or current != previous:
            raise ValueError("Current key changed before promotion")
        # finishSecret validates the provider key itself before promotion even
        # if an out-of-order invocation skipped testSecret.
        test_secret(secrets, arn, token)
        secrets.update_secret_version_stage(
            SecretId=arn, VersionStage="AWSCURRENT",
            MoveToVersionId=token, RemoveFromVersionId=previous_id,
        )
        LOG.info("openrouter_rotation promoted secret_id=%s version_id=%s key_id=%s", arn, token, pending["api_key_id"])
    stages = secrets.describe_secret(SecretId=arn)["VersionIdsToStages"]
    if "AWSCURRENT" not in stages.get(token, ()) or "AWSPREVIOUS" not in stages.get(previous_id, ()):
        raise ValueError("Rotation stages changed before predecessor retirement")
    current, current_version = read_json(secrets, arn, VersionStage="AWSCURRENT")
    if current_version != token or current != pending:
        raise ValueError("Promoted credential differs from saved pending version")
    if not bootstrap:
        openrouter_keys.delete_key(management_key(secrets), snapshot["previous_api_key_id"])
        LOG.info("openrouter_rotation retired secret_id=%s version_id=%s key_id=%s", arn, previous_id, snapshot["previous_api_key_id"])
    # The previous request explicitly requires AWSPENDING cleanup. Only the
    # token's label is removed; TFCONFIG, TFBOOTSTRAP and AWSCURRENT are never
    # targets of this removal-only API call.
    stages = secrets.describe_secret(SecretId=arn)["VersionIdsToStages"]
    if "AWSCURRENT" not in stages.get(token, ()):
        raise ValueError("Current stage changed before pending cleanup")
    if "AWSPENDING" in stages.get(token, ()):
        secrets.update_secret_version_stage(
            SecretId=arn, VersionStage="AWSPENDING", RemoveFromVersionId=token,
        )
    clear_completed_intent(secrets, arn, token)
