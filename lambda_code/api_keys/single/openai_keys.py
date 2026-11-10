"""OpenAI admin and project service-account API-key operations."""

from urllib import parse

from http_api import call_api


NAME = "openai"
BASE_URL = "https://api.openai.com/v1"


def _organization(organization_id):
    if (not isinstance(organization_id, str) or not organization_id
            or "\r" in organization_id or "\n" in organization_id):
        raise ValueError("OpenAI organization ID is required")
    return organization_id


def _key_path(config, key_id):
    encoded = parse.quote(key_id, safe="")
    if config["key_type"] == "admin":
        return f"/organization/admin_api_keys/{encoded}"
    if config["key_type"] == "project":
        project = parse.quote(config["project_id"], safe="")
        return f"/organization/projects/{project}/api_keys/{encoded}"
    raise ValueError("Unsupported OpenAI key type")


def _check_key_metadata(result, config, key_id):
    expected_object = ("organization.admin_api_key" if config["key_type"] == "admin"
                       else "organization.project.api_key")
    if (not isinstance(result, dict) or result.get("id") != key_id
            or result.get("object") != expected_object):
        raise ValueError("OpenAI key metadata does not match its identifier and type")
    if config["key_type"] == "project":
        owner = result.get("owner")
        service_account = owner.get("service_account") if isinstance(owner, dict) else None
        if (not isinstance(service_account, dict)
                or service_account.get("id") != config["service_account_id"]):
            raise ValueError("OpenAI key belongs to a different service account")
    return result


def create_key(management_key, config, organization_id):
    """Create one key; its plaintext value is returned only by this request."""
    options = {"name": config["name"]}
    if config["expires_in_seconds"] is not None:
        options["expires_in_seconds"] = config["expires_in_seconds"]

    if config["key_type"] == "admin":
        path = "/organization/admin_api_keys"
        expected_object = "organization.admin_api_key"
    elif config["key_type"] == "project":
        project = parse.quote(config["project_id"], safe="")
        service_account = parse.quote(config["service_account_id"], safe="")
        path = (f"/organization/projects/{project}/service_accounts/"
                f"{service_account}/api_keys")
        expected_object = "organization.project.service_account.api_key"
        if config["scopes"] is not None:
            options["scopes"] = config["scopes"]
    else:
        raise ValueError("Unsupported OpenAI key type")

    result = call_api(
        "POST", f"{BASE_URL}{path}", management_key, options,
        organization_id=_organization(organization_id),
    )
    if not isinstance(result, dict):
        raise ValueError("OpenAI returned an invalid key response")
    key, key_id = result.get("value"), result.get("id")
    if (result.get("object") != expected_object or result.get("name") != config["name"]
            or not isinstance(key, str) or not key
            or not isinstance(key_id, str) or not key_id):
        raise ValueError("OpenAI did not return the expected key and identifier")
    return key, key_id


def get_key(management_key, config, key_id, organization_id):
    """Read provider metadata without exposing a key's plaintext value."""
    result = call_api(
        "GET", f"{BASE_URL}{_key_path(config, key_id)}", management_key,
        organization_id=_organization(organization_id),
    )
    return _check_key_metadata(result, config, key_id)


def get_service_account(management_key, config, organization_id):
    """Check the Terraform-owned project service-account identity."""
    if config["key_type"] != "project":
        raise ValueError("Only project keys have a service account")
    project = parse.quote(config["project_id"], safe="")
    service_account_id = config["service_account_id"]
    service_account = parse.quote(service_account_id, safe="")
    result = call_api(
        "GET", (f"{BASE_URL}/organization/projects/{project}/service_accounts/"
                f"{service_account}"), management_key,
        organization_id=_organization(organization_id),
    )
    if (not isinstance(result, dict) or result.get("id") != service_account_id
            or result.get("object") != "organization.project.service_account"):
        raise ValueError("OpenAI service account metadata does not match its identity")
    return result


def get_key_if_present(management_key, config, key_id, organization_id):
    """Read metadata for orphan reconciliation, or return None on 404."""
    result = call_api(
        "GET", f"{BASE_URL}{_key_path(config, key_id)}", management_key,
        allow_not_found=True, organization_id=_organization(organization_id),
    )
    if result == {"deleted": True}:
        return None
    return _check_key_metadata(result, config, key_id)


def delete_key(management_key, config, key_id, organization_id):
    """Retire a provider key after its replacement is current."""
    result = call_api(
        "DELETE", f"{BASE_URL}{_key_path(config, key_id)}", management_key,
        allow_not_found=True, organization_id=_organization(organization_id),
    )
    if (not isinstance(result, dict) or result.get("deleted") is not True
            or ("id" in result and result["id"] != key_id)):
        raise RuntimeError("OpenAI did not confirm key deletion")


def validate_key(plaintext, config, organization_id):
    """Probe candidate auth only where the endpoint is authorized.

    Project keys without a known owner role and model-read permission cannot
    safely use /models. Their provider metadata is checked with get_key.
    """
    if config["key_type"] == "admin":
        path = "/organization/admin_api_keys"
    elif config["key_type"] == "project":
        scopes = config["scopes"]
        if (config["role"] != "owner" or
                (scopes is not None and scopes and "api.model.read" not in scopes)):
            raise NotImplementedError("No safe plaintext probe for these OpenAI key scopes")
        path = "/models"
    else:
        raise ValueError("Unsupported OpenAI key type")
    call_api("GET", f"{BASE_URL}{path}", plaintext,
             organization_id=_organization(organization_id))
