"""
Reflected XSS Check
-------------------
Discovers HTML forms on the target page and probes text inputs with a benign
XSS payload to detect unescaped reflection in the response body.
"""

from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

XSS_PAYLOAD = "<script>xsstest</script>"
TEXT_INPUT_TYPES = {"", "text", "search", "email", "url", "tel"}


def _get_text_fields(form) -> list[tuple[str, str]]:
    """Return (field_name, default_value) for each text-like input in a form."""
    fields = []

    for inp in form.find_all("input"):
        input_type = (inp.get("type") or "text").lower()
        if input_type not in TEXT_INPUT_TYPES:
            continue
        name = inp.get("name")
        if name:
            fields.append((name, inp.get("value", "")))

    for textarea in form.find_all("textarea"):
        name = textarea.get("name")
        if name:
            fields.append((name, textarea.get_text(strip=True)))

    return fields


def _build_form_data(form, target_field: str, payload: str) -> dict[str, str]:
    """Build submission data, injecting payload into the target text field."""
    data: dict[str, str] = {}

    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        input_type = (inp.get("type") or "text").lower()
        if input_type in ("submit", "button", "reset", "image"):
            continue
        if input_type == "checkbox" or input_type == "radio":
            if inp.has_attr("checked"):
                data[name] = inp.get("value", "on")
            continue
        if name == target_field:
            data[name] = payload
        elif input_type == "hidden":
            data[name] = inp.get("value", "")
        elif input_type in TEXT_INPUT_TYPES:
            data[name] = inp.get("value", "")

    for textarea in form.find_all("textarea"):
        name = textarea.get("name")
        if not name:
            continue
        data[name] = payload if name == target_field else textarea.get_text(strip=True)

    for select in form.find_all("select"):
        name = select.get("name")
        if not name:
            continue
        selected = select.find("option", selected=True) or select.find("option")
        if selected is not None:
            data[name] = selected.get("value", selected.get_text(strip=True))

    return data


def _resolve_action(form, page_url: str) -> str:
    action = form.get("action") or page_url
    return urljoin(page_url, action)


def check_xss(url: str) -> dict:
    """
    Probe text inputs on discovered forms for reflected XSS.

    Returns a dict with:
      - status:   'ok' | 'error'
      - findings: list of finding dicts (one per vulnerable field)
      - summary:  counts of forms, fields tested, and vulnerabilities
    """
    findings = []

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        response.raise_for_status()
    except RequestException as exc:
        return {"status": "error", "error": str(exc), "findings": [], "summary": {}}

    page_url = response.url
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")

    forms_found = len(forms)
    fields_tested = 0

    for form in forms:
        text_fields = _get_text_fields(form)
        if not text_fields:
            continue

        action_url = _resolve_action(form, page_url)
        method = (form.get("method") or "get").lower()

        for field_name, _ in text_fields:
            fields_tested += 1
            data = _build_form_data(form, field_name, XSS_PAYLOAD)

            try:
                if method == "post":
                    probe = requests.post(
                        action_url, data=data, timeout=10, allow_redirects=True
                    )
                else:
                    probe = requests.get(
                        action_url, params=data, timeout=10, allow_redirects=True
                    )
            except RequestException:
                continue

            if XSS_PAYLOAD in probe.text:
                findings.append(
                    {
                        "field": field_name,
                        "form_action": action_url,
                        "method": method.upper(),
                        "payload": XSS_PAYLOAD,
                        "severity": "HIGH",
                        "result": "VULNERABLE",
                        "owasp_ref": "OWASP A03 – Injection (XSS)",
                        "description": (
                            "User-supplied input is reflected in the response without "
                            "HTML encoding, which may allow Cross-Site Scripting (XSS)."
                        ),
                    }
                )

    return {
        "status": "ok",
        "findings": findings,
        "summary": {
            "forms_found": forms_found,
            "fields_tested": fields_tested,
            "vulnerable": len(findings),
        },
    }
