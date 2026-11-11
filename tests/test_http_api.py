"""Credential-safe diagnostics for upstream API failures."""

import io
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from tests.test_api_key_rotation import http_api


class HttpApiTests(unittest.TestCase):
    def test_http_errors_log_only_status_not_request_or_provider_body(self):
        for status in (401, 403, 429, 500):
            with self.subTest(status=status):
                body = io.BytesIO(b'{"error":"private-provider-payload"}')
                failure = HTTPError("https://example.com/private-id", status,
                                    "private-provider-message", {}, body)
                with patch.object(http_api.request, "urlopen", side_effect=failure), \
                        self.assertLogs(http_api.__name__, level="WARNING") as logs:
                    with self.assertRaisesRegex(RuntimeError, f"^Provider request returned HTTP {status}$"):
                        http_api.call_api("GET", "https://example.com/private-id", "private-credential")
                self.assertEqual(
                    [f"http_api action=request_failed reason=http_status status_code={status}"],
                    [record.getMessage() for record in logs.records],
                )
                self.assertEqual(0, body.tell())
                failure.close()

    def test_transport_error_diagnostic_does_not_include_exception(self):
        with patch.object(http_api.request, "urlopen", side_effect=URLError("private-data")), \
                self.assertLogs(http_api.__name__, level="WARNING") as logs:
            with self.assertRaisesRegex(RuntimeError, "^Provider request failed$"):
                http_api.call_api("GET", "https://example.com/private-id", "private-credential")
        self.assertEqual(["http_api action=request_failed reason=transport_error"],
                         [record.getMessage() for record in logs.records])

    def test_request_organization_is_authoritative_not_response_metadata(self):
        for response_org in (None, "org_123", "organization-display-name", "org_other"):
            with self.subTest(response_org=response_org):
                response = MagicMock()
                response.headers.get.return_value = response_org
                response.read.return_value = b"{}"
                response.__enter__.return_value = response
                with patch.object(http_api.request, "urlopen", return_value=response) as urlopen, \
                        self.assertNoLogs(http_api.__name__, level="WARNING"):
                    self.assertEqual({}, http_api.call_api(
                        "GET", "https://example.com", "private-credential", organization_id="org_123"))
                    self.assertEqual("org_123", urlopen.call_args.args[0].get_header("Openai-organization"))

    def test_invalid_request_organization_fails_before_network_request(self):
        with patch.object(http_api.request, "urlopen") as urlopen:
            for organization_id in ("", "org_123\n", "org_123\r", 42):
                with self.subTest(organization_id=organization_id), self.assertRaises(ValueError):
                    http_api.call_api("GET", "https://example.com", "private-credential",
                                      organization_id=organization_id)
            urlopen.assert_not_called()

    def test_allowed_not_found_stays_idempotent_without_failure_log(self):
        failure = HTTPError("https://example.com/private-id", 404, "private-message", {}, io.BytesIO())
        with patch.object(http_api.request, "urlopen", side_effect=failure), \
                self.assertNoLogs(http_api.__name__, level="WARNING"):
            self.assertEqual({"deleted": True}, http_api.call_api(
                "DELETE", "https://example.com/private-id", "private-credential", allow_not_found=True))
        failure.close()
