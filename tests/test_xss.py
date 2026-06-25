"""
Tests for reflected XSS checks.

Run with: pytest tests/
"""

from unittest.mock import MagicMock, patch
from scanner.checks.xss import check_xss, XSS_PAYLOAD


def _mock_response(text: str, status_code: int = 200, url: str = "https://example.com"):
    mock = MagicMock()
    mock.status_code = status_code
    mock.text = text
    mock.url = url
    mock.raise_for_status = MagicMock()
    return mock


PAGE_WITH_FORM = """
<html>
<body>
  <form action="/search" method="get">
    <input type="text" name="q" value="">
    <input type="hidden" name="token" value="abc">
  </form>
</body>
</html>
"""


def test_reflected_xss_detected():
    """When the payload is reflected unescaped, flag the field as vulnerable."""
    page = _mock_response(PAGE_WITH_FORM)
    reflected = _mock_response(f"<p>Results for {XSS_PAYLOAD}</p>")

    with patch("scanner.checks.xss.requests.get", side_effect=[page, reflected]), patch(
        "scanner.checks.xss.requests.post"
    ) as mock_post:
        result = check_xss("https://example.com")

    mock_post.assert_not_called()
    assert result["status"] == "ok"
    assert result["summary"]["forms_found"] == 1
    assert result["summary"]["fields_tested"] == 1
    assert result["summary"]["vulnerable"] == 1
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["field"] == "q"
    assert finding["form_action"] == "https://example.com/search"
    assert finding["result"] == "VULNERABLE"
    assert finding["severity"] == "HIGH"


def test_encoded_payload_not_flagged():
    """When the payload is HTML-encoded in the response, no finding is returned."""
    page = _mock_response(PAGE_WITH_FORM)
    safe = _mock_response("<p>Results for &lt;script&gt;xsstest&lt;/script&gt;</p>")

    with patch("scanner.checks.xss.requests.get", side_effect=[page, safe]):
        result = check_xss("https://example.com")

    assert result["status"] == "ok"
    assert result["summary"]["vulnerable"] == 0
    assert result["findings"] == []


def test_no_forms_returns_empty_findings():
    """A page with no forms should complete with zero fields tested."""
    page = _mock_response("<html><body><p>No forms here</p></body></html>")

    with patch("scanner.checks.xss.requests.get", return_value=page):
        result = check_xss("https://example.com")

    assert result["status"] == "ok"
    assert result["summary"]["forms_found"] == 0
    assert result["summary"]["fields_tested"] == 0
    assert result["findings"] == []


def test_network_error_returns_error_status():
    """If the initial page fetch fails, status should be 'error'."""
    from requests.exceptions import ConnectionError as ReqConnError

    with patch("scanner.checks.xss.requests.get", side_effect=ReqConnError("unreachable")):
        result = check_xss("https://doesnotexist.invalid")

    assert result["status"] == "error"
    assert "error" in result
    assert result["findings"] == []
