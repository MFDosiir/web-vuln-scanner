"""
Tests for security header checks.

Run with: pytest tests/
"""

from unittest.mock import MagicMock, patch
from scanner.checks.headers import check_security_headers


def _mock_response(headers: dict, status_code: int = 200):
    """Helper: create a mock requests.Response with given headers."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.headers = headers
    return mock


def test_all_headers_present():
    """When all security headers are present, all findings should PASS."""
    good_headers = {
        "Strict-Transport-Security":  "max-age=63072000; includeSubDomains",
        "Content-Security-Policy":    "default-src 'self'",
        "X-Frame-Options":            "DENY",
        "X-Content-Type-Options":     "nosniff",
        "Referrer-Policy":            "strict-origin-when-cross-origin",
        "Permissions-Policy":         "geolocation=()",
    }
    with patch("scanner.checks.headers.requests.get", return_value=_mock_response(good_headers)):
        result = check_security_headers("https://example.com")

    assert result["status"] == "ok"
    assert result["summary"]["failed"] == 0
    assert result["summary"]["passed"] == 6
    for f in result["findings"]:
        assert f["result"] == "PASS"


def test_missing_headers_flagged():
    """When headers are absent, findings should FAIL with correct severity."""
    with patch("scanner.checks.headers.requests.get", return_value=_mock_response({})):
        result = check_security_headers("https://example.com")

    assert result["status"] == "ok"
    assert result["summary"]["passed"] == 0
    assert result["summary"]["failed"] == 6
    for f in result["findings"]:
        assert f["result"] == "FAIL"
        assert f["severity"] in ("HIGH", "MEDIUM", "LOW", "CRITICAL")


def test_partial_headers():
    """With some headers present, counts should reflect the split."""
    partial_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options":    "nosniff",
    }
    with patch("scanner.checks.headers.requests.get", return_value=_mock_response(partial_headers)):
        result = check_security_headers("https://example.com")

    assert result["summary"]["passed"] == 2
    assert result["summary"]["failed"] == 4


def test_network_error_returns_error_status():
    """If the request fails, status should be 'error' with a message."""
    from requests.exceptions import ConnectionError as ReqConnError
    with patch("scanner.checks.headers.requests.get", side_effect=ReqConnError("unreachable")):
        result = check_security_headers("https://doesnotexist.invalid")

    assert result["status"] == "error"
    assert "error" in result
    assert result["findings"] == []
