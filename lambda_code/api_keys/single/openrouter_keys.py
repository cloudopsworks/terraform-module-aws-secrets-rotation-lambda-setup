"""OpenRouter management API-key operations used by rotation."""

import json
import os
from urllib import parse

from http_api import call_api


NAME = "openrouter"
BASE_URL = "https://openrouter.ai/api/v1"


def create_key(management_key, token, workspace_id=None):
    options = json.loads(os.environ.get("OPENROUTER_KEY_OPTIONS_JSON", "{}"))
    if not isinstance(options, dict):
        raise ValueError("OpenRouter key options must be an object")
    if workspace_id is not None:
        options["workspace_id"] = workspace_id
    selected_workspace = options.get("workspace_id")
    if selected_workspace is not None and (not isinstance(selected_workspace, str) or not selected_workspace):
        raise ValueError("OpenRouter workspace ID must be a nonempty string")
    name = os.environ.get("ROTATION_KEY_NAME", "rotated-api-key") + "-" + token[:8]
    result = call_api("POST", f"{BASE_URL}/keys", management_key, {**options, "name": name})
    data = result.get("data") or {}
    key, key_id = result.get("key"), data.get("hash")
    if not isinstance(key, str) or not key or not isinstance(key_id, str) or not key_id:
        raise ValueError("OpenRouter did not return a key and hash")
    returned_workspace = data.get("workspace_id")
    return key, key_id, selected_workspace, returned_workspace


def validate_key(key):
    call_api("GET", f"{BASE_URL}/key", key)


def delete_key(management_key, key_id):
    encoded = parse.quote(key_id, safe="")
    result = call_api("DELETE", f"{BASE_URL}/keys/{encoded}", management_key, allow_not_found=True)
    if result.get("deleted") is not True:
        raise RuntimeError("OpenRouter did not confirm key deletion")
