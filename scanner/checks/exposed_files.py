"""
Exposed Sensitive Files Check
------------------------------
Probes for common files and paths that should never be publicly accessible.

Real attackers run lists like this constantly — automated scanners probe millions
of sites for these paths every day. Finding them first (on sites you own) is the
job of a penetration tester or AppSec engineer.

IMPORTANT: Only run this against sites you own or intentionally-vulnerable
practice targets (DVWA, Juice Shop, HackTheBox labs). Probing sites without
permission is illegal under the CFAA and equivalent laws worldwide.
"""

import requests
from requests.exceptions import RequestException

# ---------------------------------------------------------------------------
# Sensitive path definitions
# Each entry: (path, severity, description)
# ---------------------------------------------------------------------------
SENSITIVE_PATHS = [
    # Version control — exposes your entire source code history
    ("/.git/config", "CRITICAL", "Git config file — can expose repo URL and credentials"),
    ("/.git/HEAD", "CRITICAL", "Git HEAD ref — confirms .git directory is accessible"),
    ("/.svn/entries", "CRITICAL", "SVN metadata — source code exposure risk"),

    # Environment / config files — often contain API keys, DB passwords
    ("/.env", "CRITICAL", "Environment file — may contain secrets and credentials"),
    ("/.env.local", "CRITICAL", "Local environment file — likely contains dev secrets"),
    ("/.env.production", "CRITICAL", "Production environment file — high-value target"),
    ("/config.php", "HIGH", "PHP config — may contain database credentials"),
    ("/wp-config.php.bak", "HIGH", "WordPress config backup — plaintext DB credentials"),
    ("/config.yml", "HIGH", "YAML config file — may contain service secrets"),
    ("/database.yml", "HIGH", "Database config — common in Rails apps"),

    # Backup and temp files left by developers or editors
    ("/backup.sql", "HIGH", "Database dump — exposes all data"),
    ("/db.sql", "HIGH", "Database dump — exposes all data"),
    ("/site.tar.gz", "HIGH", "Site archive — full source code exposure"),
    ("/backup.zip", "HIGH", "Backup archive — may contain source + credentials"),

    # Admin interfaces
    ("/admin", "MEDIUM", "Admin panel — should not be publicly discoverable"),
    ("/admin/login", "MEDIUM", "Admin login page — target for brute force"),
    ("/phpmyadmin", "MEDIUM", "phpMyAdmin — direct DB access if unprotected"),
    ("/wp-admin", "MEDIUM", "WordPress admin — target for credential attacks"),

    # Debug and server info pages
    ("/phpinfo.php", "HIGH", "PHP info page — reveals server config, paths, and versions"),
    ("/server-status", "MEDIUM", "Apache server status — reveals internal request details"),
    ("/elmah.axd", "MEDIUM", "ASP.NET error log — can expose stack traces and data"),

    # Common log files
    ("/logs/error.log", "HIGH", "Error log — may reveal internal paths and stack traces"),
    ("/access.log", "MEDIUM", "Access log — reveals user activity and URL patterns"),
]


def check_exposed_files(url: str) -> dict:
    """
    Probe the target for exposed sensitive files and directories.

    A 200 response to any of these paths is a finding.
    We also flag 403 Forbidden — the path exists but is blocked,
    which is better than 200 but still worth noting.

    Returns a dict with status, findings, and a summary.
    """
    findings = []

    for path, severity, description in SENSITIVE_PATHS:
        target = url + path
        result = "SKIP"
        status_code = None

        try:
            response = requests.get(target, timeout=8, allow_redirects=False)
            status_code = response.status_code

            if status_code == 200:
                result = "EXPOSED"       # Definitely accessible — critical finding
            elif status_code == 403:
                result = "BLOCKED"       # Exists but server refuses — still noteworthy
            elif status_code in (301, 302):
                result = "REDIRECT"      # Redirects somewhere — low signal
            else:
                result = "NOT_FOUND"     # 404 / 410 — clean

        except RequestException:
            result = "ERROR"

        # Only include findings worth reporting
        if result in ("EXPOSED", "BLOCKED"):
            findings.append(
                {
                    "path": path,
                    "url": target,
                    "status_code": status_code,
                    "result": result,
                    "severity": severity,
                    "description": description,
                }
            )

    exposed = sum(1 for f in findings if f["result"] == "EXPOSED")
    blocked = sum(1 for f in findings if f["result"] == "BLOCKED")

    return {
        "status": "ok",
        "findings": findings,
        "summary": {
            "paths_checked": len(SENSITIVE_PATHS),
            "exposed": exposed,
            "blocked": blocked,
        },
    }
