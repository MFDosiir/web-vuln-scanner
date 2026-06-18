"""
Security Headers Check
----------------------
Inspects HTTP response headers for missing or misconfigured security controls.

Each header maps to a real-world attack. Understanding *why* each one matters
is what separates tool users from security engineers — make sure you can explain
each one in an interview without looking it up.
"""

import requests
from requests.exceptions import RequestException

# ---------------------------------------------------------------------------
# Header definitions
# Each entry: (header_name, severity, owasp_ref, why_it_matters, good_example)
# ---------------------------------------------------------------------------
SECURITY_HEADERS = [
    (
        "Strict-Transport-Security",
        "HIGH",
        "OWASP A02 – Cryptographic Failures",
        (
            "Forces browsers to connect over HTTPS only, preventing SSL-stripping "
            "attacks where an attacker downgrades your connection to plain HTTP."
        ),
        "max-age=63072000; includeSubDomains; preload",
    ),
    (
        "Content-Security-Policy",
        "HIGH",
        "OWASP A03 – Injection (XSS)",
        (
            "Tells the browser which sources of scripts, styles, and other resources "
            "are trusted. A missing CSP makes Cross-Site Scripting (XSS) attacks far "
            "easier because injected scripts can load freely from anywhere."
        ),
        "default-src 'self'; script-src 'self'; object-src 'none'",
    ),
    (
        "X-Frame-Options",
        "MEDIUM",
        "OWASP A05 – Security Misconfiguration",
        (
            "Prevents your page from being embedded in an <iframe> on another site, "
            "which is the core mechanism behind Clickjacking attacks."
        ),
        "DENY",
    ),
    (
        "X-Content-Type-Options",
        "MEDIUM",
        "OWASP A05 – Security Misconfiguration",
        (
            "Stops browsers from guessing (sniffing) a file's content type. Without "
            "this, an attacker could upload a file the browser interprets as executable "
            "JavaScript even if the server labels it as plain text."
        ),
        "nosniff",
    ),
    (
        "Referrer-Policy",
        "LOW",
        "OWASP A01 – Broken Access Control",
        (
            "Controls how much URL information is passed to other sites when a user "
            "clicks a link. A missing policy can leak session tokens or private paths "
            "in the Referer header to third-party sites."
        ),
        "strict-origin-when-cross-origin",
    ),
    (
        "Permissions-Policy",
        "LOW",
        "OWASP A05 – Security Misconfiguration",
        (
            "Restricts which browser features (camera, microphone, geolocation, etc.) "
            "a page can use. Limits the blast radius if your page is ever compromised."
        ),
        "geolocation=(), camera=(), microphone=()",
    ),
]


def check_security_headers(url: str) -> dict:
    """
    Fetch the URL and evaluate its security response headers.

    Returns a dict with:
      - status:   'ok' | 'error'
      - findings: list of finding dicts (one per header checked)
      - summary:  counts of pass/fail/warn
    """
    findings = []

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        response_headers = {k.lower(): v for k, v in response.headers.items()}
    except RequestException as exc:
        return {"status": "error", "error": str(exc), "findings": [], "summary": {}}

    for header_name, severity, owasp_ref, why, example in SECURITY_HEADERS:
        header_key = header_name.lower()
        present = header_key in response_headers
        current_value = response_headers.get(header_key, None)

        findings.append(
            {
                "header": header_name,
                "present": present,
                "current_value": current_value,
                "severity": severity,
                "owasp_ref": owasp_ref,
                "why_it_matters": why,
                "recommended_value": example,
                "result": "PASS" if present else "FAIL",
            }
        )

    passed = sum(1 for f in findings if f["result"] == "PASS")
    failed = sum(1 for f in findings if f["result"] == "FAIL")

    return {
        "status": "ok",
        "findings": findings,
        "summary": {
            "total": len(findings),
            "passed": passed,
            "failed": failed,
        },
    }
