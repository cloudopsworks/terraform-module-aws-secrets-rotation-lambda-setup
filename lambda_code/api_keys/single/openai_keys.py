"""OpenAI service-account API-key operations used by rotation."""

import json
import os
from urllib import parse

from http_api import call_api


NAME = "openai"
BASE_URL = "https://api.openai.com/v1"


def create_key(management_key, token):
    project = parse.quote(os.environ["OPENAI_PROJECT_ID"], safe="")
    service_account = parse.quote(os.environ["OPENAI_SERVICE_ACCOUNT_ID"], safe="")
    options = json.loads(os.environ.get("OPENAI_KEY_OPTIONS_JSON", "{}"))
    if not isinstance(options, dict):
        raise ValueError("OpenAI key options must be an object")
    name = os.environ.get("ROTATION_KEY_NAME", "rotated-api-key") + "-" + token[:8]
    result = call_api(
        "POST",
        f"{BASE_URL}/organization/projects/{project}/service_accounts/{service_account}/api_keys",
        management_key,
        {**options, "name": name},
    )
    key, key_id = result.get("value"), result.get("id")
    if not isinstance(key, str) or not key or not isinstance(key_id, str) or not key_id:
        raise ValueError("OpenAI did not return a key and identifier")
    return key, key_id


def validate_key(key):
    # Requires api.model.read for both the key and its service-account role.
    call_api("GET", f"{BASE_URL}/models", key)


def delete_key(management_key, key_id, project_id):
    project = parse.quote(project_id, safe="")
    encoded = parse.quote(key_id, safe="")
    result = call_api(
        "DELETE", f"{BASE_URL}/organization/projects/{project}/api_keys/{encoded}",
        management_key, allow_not_found=True,
    )
    if result.get("deleted") is not True:
        raise RuntimeError("OpenAI did not confirm key deletion")
