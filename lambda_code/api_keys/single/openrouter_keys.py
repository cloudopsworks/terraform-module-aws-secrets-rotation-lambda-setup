"""OpenRouter management operations for a single rotation token."""

from urllib import parse

from http_api import call_api


NAME = "openrouter"
BASE_URL = "https://openrouter.ai/api/v1"
CREATE_FIELDS = (
    "name", "workspace_id", "limit", "limit_reset", "include_byok_in_limit",
    "expires_at", "creator_user_id",
)


def create_key(management_key, config):
    """Create a key from pinned TFCONFIG values, never old-key metadata."""
    options = {field: config[field] for field in CREATE_FIELDS if config[field] is not None}
    result = call_api("POST", f"{BASE_URL}/keys", management_key, options)
    data = result.get("data") if isinstance(result, dict) else None
    key = result.get("key") if isinstance(result, dict) else None
    key_id = data.get("hash") if isinstance(data, dict) else None
    if not isinstance(key, str) or not key or not isinstance(key_id, str) or not key_id:
        raise ValueError("OpenRouter did not return a key and hash")
    return key, key_id


def get_key(management_key, key_id):
    result = call_api("GET", f"{BASE_URL}/keys/{parse.quote(key_id, safe='')}", management_key)
    data = result.get("data") if isinstance(result, dict) else None
    if not isinstance(data, dict) or data.get("hash") != key_id:
        raise ValueError("OpenRouter key metadata does not match its hash")
    return data


def get_key_if_present(management_key, key_id):
    result = call_api(
        "GET", f"{BASE_URL}/keys/{parse.quote(key_id, safe='')}",
        management_key, allow_not_found=True,
    )
    if result == {"deleted": True}:
        return None
    data = result.get("data") if isinstance(result, dict) else None
    if not isinstance(data, dict) or data.get("hash") != key_id:
        raise ValueError("OpenRouter key metadata does not match its hash")
    return data


def update_disabled(management_key, key_id, disabled):
    result = call_api(
        "PATCH", f"{BASE_URL}/keys/{parse.quote(key_id, safe='')}",
        management_key, {"disabled": disabled},
    )
    data = result.get("data") if isinstance(result, dict) else None
    if not isinstance(data, dict) or data.get("hash") != key_id or data.get("disabled") is not disabled:
        raise ValueError("OpenRouter did not confirm key disabled setting")


def validate_key(key):
    call_api("GET", f"{BASE_URL}/key", key)


def delete_key(management_key, key_id):
    result = call_api(
        "DELETE", f"{BASE_URL}/keys/{parse.quote(key_id, safe='')}",
        management_key, allow_not_found=True,
    )
    if result.get("deleted") is not True:
        raise RuntimeError("OpenRouter did not confirm key deletion")
