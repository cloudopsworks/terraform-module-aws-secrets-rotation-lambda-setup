"""Dispatch provider-specific Secrets Manager API-key rotation."""

import json
import logging
import os

import boto3
import openai_keys
import openrouter_keys
import openrouter_rotation


LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)
PROVIDERS = {provider.NAME: provider for provider in (openai_keys, openrouter_keys)}


def lambda_handler(event, context):
    """Handle one of Secrets Manager's four rotation steps."""
    del context
    try:
        rotate(event, boto3.client("secretsmanager"))
    except Exception as exc:
        # HTTP, AWS, and JSON exceptions may include a credential or response
        # body. Log only fixed enum values and the exception class, never the
        # original text or traceback.
        provider = os.environ.get("API_PROVIDER", "unknown")
        provider = provider if provider in ("openai", "openrouter") else "unknown"
        step = event.get("Step") if isinstance(event, dict) else None
        step = step if step in ("createSecret", "setSecret", "testSecret", "finishSecret", "reconcileOrphan") else "unknown"
        LOG.error("API key rotation failed: provider=%s step=%s error_type=%s", provider, step, type(exc).__name__)
        raise RuntimeError("API key rotation failed") from None


def rotate(event, secrets):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    provider = os.environ["API_PROVIDER"]
    if provider not in PROVIDERS:
        raise ValueError("Unsupported API provider")
    if provider == "openrouter":
        openrouter_rotation.rotate(event, secrets)
        return
    if step not in ("createSecret", "setSecret", "testSecret", "finishSecret"):
        raise ValueError("Unsupported rotation step")

    metadata = secrets.describe_secret(SecretId=arn)
    if not metadata.get("RotationEnabled", False):
        raise ValueError("Rotation is not enabled")
    stages = metadata["VersionIdsToStages"].get(token, [])
    if "AWSCURRENT" in stages and step != "finishSecret":
        return
    if "AWSPENDING" not in stages and "AWSCURRENT" not in stages:
        raise ValueError("Rotation token is not pending or current")

    if step == "createSecret":
        create_secret(secrets, arn, token, provider)
    elif step == "setSecret":
        pending = get_secret(secrets, arn, VersionId=token, VersionStage="AWSPENDING")
        check_pending_secret(pending, provider, check_environment=True)
    elif step == "testSecret":
        pending = get_secret(secrets, arn, VersionId=token, VersionStage="AWSPENDING")
        check_pending_secret(pending, provider, check_environment=True)
        PROVIDERS[provider].validate_key(pending["api_key"])
    else:
        finish_secret(secrets, arn, token, provider, metadata)


def get_secret(secrets, arn, **version):
    return get_secret_version(secrets, arn, **version)[0]


def get_secret_version(secrets, arn, **version):
    value = secrets.get_secret_value(SecretId=arn, **version)
    secret = json.loads(value["SecretString"])
    if not isinstance(secret, dict):
        raise ValueError("Secret must be a JSON object")
    return secret, value["VersionId"]


def check_secret(secret, provider, check_environment=False):
    if (not isinstance(secret.get("api_key"), str) or not secret["api_key"] or
            not isinstance(secret.get("api_key_id"), str) or not secret["api_key_id"] or
            "key_id" in secret):
        raise ValueError("Key secret is incomplete")
    if provider != "openai":
        raise ValueError("Unsupported provider in OpenAI rotation path")
    project = secret.get("project_id")
    account = secret.get("service_account_id")
    if not isinstance(project, str) or not project or not isinstance(account, str) or not account:
        raise ValueError("OpenAI key secret is missing its project or service account")
    if check_environment and (project != os.environ["OPENAI_PROJECT_ID"] or
                              account != os.environ["OPENAI_SERVICE_ACCOUNT_ID"]):
        raise ValueError("OpenAI key secret binding differs from configuration")
    scopes = secret.get("scopes")
    if not isinstance(scopes, list) or any(not isinstance(scope, str) or not scope for scope in scopes):
        raise ValueError("OpenAI key secret must record its scopes")
    if not isinstance(secret.get("name"), str) or not secret["name"]:
        raise ValueError("OpenAI key secret must record its name")


def check_pending_secret(secret, provider, check_environment=False):
    check_secret(secret, provider, check_environment=check_environment)


def audit(action, provider, arn, version_id, key_id, secret):
    # Only identifiers: no credential, provider response, or exception text.
    record = {
        "event": action, "provider": provider, "secret_id": arn,
        "version_id": version_id, "api_key_id": key_id,
    }
    if provider == "openai":
        record.update(project_id=secret["project_id"], service_account_id=secret["service_account_id"])
    line = "api_key_rotation " + json.dumps(record, sort_keys=True)
    try:
        LOG.info("%s", line)
    except Exception:
        try:
            print("api_key_rotation " + json.dumps({**record, "delivery": "stdout_fallback"}, sort_keys=True))
        except Exception:
            # Both log sinks may fail; never interrupt rotation after key creation.
            pass


def revoke_key(provider, management, secret):
    if provider != "openai":
        raise ValueError("Unsupported provider in OpenAI rotation path")
    openai_keys.delete_key(management, secret["api_key_id"], secret["project_id"])


def management_key(secrets):
    value = secrets.get_secret_value(SecretId=os.environ["MANAGEMENT_SECRET_ARN"])
    secret = value["SecretString"].strip()
    if secret.startswith("{"):
        data = json.loads(secret)
        secret = data.get("api_key") or data.get("admin_api_key") or data.get("management_api_key")
    if not isinstance(secret, str) or not secret:
        raise ValueError("Management key secret is empty")
    return secret


def create_secret(secrets, arn, token, provider):
    current = get_secret(secrets, arn, VersionStage="AWSCURRENT")
    check_secret(current, provider, check_environment=True)
    try:
        pending = get_secret(secrets, arn, VersionId=token, VersionStage="AWSPENDING")
        check_pending_secret(pending, provider, check_environment=True)
        return
    except secrets.exceptions.ResourceNotFoundException:
        pass
    admin_key = management_key(secrets)
    parameters = openai_keys.key_options(current)
    key, key_id = openai_keys.create_key(admin_key, token, parameters)
    pending = {**current, "api_key": key, "api_key_id": key_id}
    pending.pop("provider", None)
    pending.pop("rotation", None)
    pending.pop("expires_at", None)
    pending.pop("expires_in_seconds", None)
    pending.update(parameters)
    audit("issued", provider, arn, token, key_id, pending)
    try:
        secrets.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=json.dumps(pending),
            VersionStages=["AWSPENDING"],
        )
    except Exception:
        # A timeout/error from PutSecretValue does not prove the write failed.
        # Read by immutable version ID: another invocation may already have
        # promoted the version and removed its AWSPENDING stage.
        try:
            stored = get_secret(secrets, arn, VersionId=token)
        except Exception:
            # A missing version may still be an eventually consistent read.
            # Preserve the key rather than revoke one AWS might have stored.
            audit("pending_write_unconfirmed", provider, arn, token, key_id, pending)
            raise RuntimeError("Could not verify pending secret write") from None
        if stored == pending:
            audit("pending_persisted", provider, arn, token, key_id, pending)
            return
        # A different version is present under the same token. Avoid touching
        # it; revoke only the new, unreferenced upstream key.
        audit("pending_write_conflict", provider, arn, token, key_id, pending)
        revoke_key(provider, admin_key, pending)
        audit("revoked_unreferenced", provider, arn, token, key_id, pending)
        raise RuntimeError("Pending secret differs from created key") from None
    audit("pending_persisted", provider, arn, token, key_id, pending)


def check_predecessor(previous, pending, provider):
    check_secret(previous, provider)
    if previous["api_key_id"] == pending["api_key_id"]:
        raise ValueError("Pending key identifier matches its predecessor")
    if (previous["project_id"] != pending["project_id"] or
            previous["service_account_id"] != pending["service_account_id"] or
            previous["scopes"] != pending["scopes"]):
        raise ValueError("OpenAI previous key binding differs from pending")


def finish_secret(secrets, arn, token, provider, metadata):
    already_current = "AWSCURRENT" in metadata["VersionIdsToStages"].get(token, [])
    pending = get_secret(
        secrets, arn, VersionId=token,
        VersionStage="AWSCURRENT" if already_current else "AWSPENDING")
    check_pending_secret(pending, provider, check_environment=not already_current)
    previous_version_before_promotion = None
    if not already_current:
        previous, previous_version_before_promotion = get_secret_version(
            secrets, arn, VersionStage="AWSCURRENT")
        check_predecessor(previous, pending, provider)
        secrets.update_secret_version_stage(
            SecretId=arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=previous_version_before_promotion,
        )
        audit("promoted", provider, arn, token, pending["api_key_id"], pending)

    current, current_version = get_secret_version(secrets, arn, VersionStage="AWSCURRENT")
    check_pending_secret(current, provider)
    if current_version != token or current["api_key_id"] != pending["api_key_id"]:
        raise ValueError("Current key differs from promoted pending key")
    previous, previous_version = get_secret_version(secrets, arn, VersionStage="AWSPREVIOUS")
    if previous_version_before_promotion is not None and previous_version != previous_version_before_promotion:
        raise ValueError("Previous stage differs from promoted predecessor")
    check_predecessor(previous, pending, provider)
    admin_key = management_key(secrets)
    stages = secrets.describe_secret(SecretId=arn)["VersionIdsToStages"]
    if ("AWSCURRENT" not in stages.get(token, []) or
            "AWSPREVIOUS" not in stages.get(previous_version, [])):
        raise ValueError("Rotation stages changed before old key retirement")
    revoke_key(provider, admin_key, previous)
    audit("retired", provider, arn, previous_version, previous["api_key_id"], previous)

    # Keep AWSCURRENT in place. AWS may retain AWSPENDING on the newly
    # promoted version; remove only that token's pending label after the old
    # provider key has been retired. A retry may find it already removed.
    stages = secrets.describe_secret(SecretId=arn)["VersionIdsToStages"]
    if "AWSCURRENT" not in stages.get(token, []):
        raise ValueError("Current stage changed before pending cleanup")
    if "AWSPENDING" in stages.get(token, []):
        secrets.update_secret_version_stage(
            SecretId=arn,
            VersionStage="AWSPENDING",
            RemoveFromVersionId=token,
        )
        audit("pending_cleared", provider, arn, token, pending["api_key_id"], pending)
