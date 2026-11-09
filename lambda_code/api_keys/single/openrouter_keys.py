"""OpenRouter management API-key operations used by rotation."""

import json
import os
from urllib import parse

from http_api import call_api


NAME = "openrouter"
BASE_URL = "https://openrouter.ai/api/v1"


KEY_OPTIONS = (
    "name", "limit", "limit_reset", "include_byok_in_limit", "creator_user_id", "workspace_id",
)


def key_options(current):
    """Copy the recorded workload-key fields, excluding old expiration."""
    if current.get("disabled") is True or current.get("external_user") is not None or current.get("external") is not None:
        raise ValueError("OpenRouter key cannot be reproduced")
    if any(key not in current for key in KEY_OPTIONS):
        raise ValueError("OpenRouter key secret must record all key options")
    options = {key: current[key] for key in KEY_OPTIONS}
    if not isinstance(options["name"], str) or not options["name"]:
        raise ValueError("OpenRouter key name is invalid")
    if options["limit"] is not None and (isinstance(options["limit"], bool) or
                                          not isinstance(options["limit"], (int, float)) or
                                          options["limit"] < 0):
        raise ValueError("OpenRouter key limit is invalid")
    if options["limit_reset"] not in (None, "daily", "weekly", "monthly"):
        raise ValueError("OpenRouter key limit reset is invalid")
    if not isinstance(options["include_byok_in_limit"], bool):
        raise ValueError("OpenRouter BYOK limit option is invalid")
    creator = options["creator_user_id"]
    if creator is not None and (not isinstance(creator, str) or not creator):
        raise ValueError("OpenRouter creator user ID is invalid")
    workspace = options["workspace_id"]
    if workspace is not None and (not isinstance(workspace, str) or not workspace):
        raise ValueError("OpenRouter workspace ID is invalid")
    return options


def create_key(management_key, token, workspace_id=None, parameters=None):
    options = json.loads(os.environ.get("OPENROUTER_KEY_OPTIONS_JSON", "{}"))
    if not isinstance(options, dict):
        raise ValueError("OpenRouter key options must be an object")
    if parameters is not None:
        if not isinstance(parameters, dict):
            raise ValueError("OpenRouter key parameters must be an object")
        options.update({key: value for key, value in parameters.items() if key in KEY_OPTIONS})
    if workspace_id is not None:
        options["workspace_id"] = workspace_id
    selected_workspace = options.get("workspace_id")
    if selected_workspace is not None and (not isinstance(selected_workspace, str) or not selected_workspace):
        raise ValueError("OpenRouter workspace ID must be a nonempty string")
    if selected_workspace is None:
        options.pop("workspace_id", None)
    if parameters is None or "name" not in parameters:
        options["name"] = os.environ.get("ROTATION_KEY_NAME", "rotated-api-key") + "-" + token[:8]
    result = call_api("POST", f"{BASE_URL}/keys", management_key, options)
    data = result.get("data") or {}
    key, key_id = result.get("key"), data.get("hash")
    if not isinstance(key, str) or not key or not isinstance(key_id, str) or not key_id:
        raise ValueError("OpenRouter did not return a key and hash")
    # Missing is not proof of an unscoped key; an empty marker fails the
    # caller's workspace confirmation and triggers cleanup.
    returned_workspace = data.get("workspace_id", "")
    return key, key_id, selected_workspace, returned_workspace


def validate_key(key):
    call_api("GET", f"{BASE_URL}/key", key)


def delete_key(management_key, key_id):
    encoded = parse.quote(key_id, safe="")
    result = call_api("DELETE", f"{BASE_URL}/keys/{encoded}", management_key, allow_not_found=True)
    if result.get("deleted") is not True:
        raise RuntimeError("OpenRouter did not confirm key deletion")
