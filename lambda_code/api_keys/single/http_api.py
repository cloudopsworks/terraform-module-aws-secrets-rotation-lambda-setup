"""Small JSON HTTP client for the upstream key-management APIs."""

import json
from urllib import error, request


HTTP_TIMEOUT_SECONDS = 15


def call_api(method, url, key, payload=None, *, allow_not_found=False):
    headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=body, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
            content = response.read()
    except error.HTTPError as exc:
        if allow_not_found and exc.code == 404:
            return {"deleted": True}
        # Provider response bodies can contain credentials; never expose them.
        raise RuntimeError(f"Provider request returned HTTP {exc.code}") from None
    except error.URLError:
        raise RuntimeError("Provider request failed") from None
    return json.loads(content) if content else {}
