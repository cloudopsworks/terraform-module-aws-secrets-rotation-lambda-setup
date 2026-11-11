"""Small JSON HTTP client for the upstream key-management APIs."""

import json
import logging
from urllib import error, request


HTTP_TIMEOUT_SECONDS = 15
LOG = logging.getLogger(__name__)


def call_api(method, url, key, payload=None, *, allow_not_found=False,
             organization_id=None):
    headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    if organization_id is not None:
        if (not isinstance(organization_id, str) or not organization_id
                or "\r" in organization_id or "\n" in organization_id):
            raise ValueError("OpenAI organization ID must be a nonempty header value")
        headers["OpenAI-Organization"] = organization_id
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=body, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
            response_headers = getattr(response, "headers", None)
            response_org = (response_headers.get("openai-organization")
                            if organization_id is not None and response_headers is not None
                            else None)
            if response_org and response_org != organization_id:
                LOG.warning("http_api action=request_failed reason=organization_mismatch")
                raise RuntimeError("OpenAI response belongs to a different organization")
            content = response.read()
    except error.HTTPError as exc:
        if allow_not_found and exc.code == 404:
            return {"deleted": True}
        # Provider response bodies can contain credentials; never expose them.
        LOG.warning("http_api action=request_failed reason=http_status status_code=%d", exc.code)
        raise RuntimeError(f"Provider request returned HTTP {exc.code}") from None
    except error.URLError:
        LOG.warning("http_api action=request_failed reason=transport_error")
        raise RuntimeError("Provider request failed") from None
    return json.loads(content) if content else {}
