"""
web-vuln-scanner · main entry point
Usage: python -m scanner.main <url> [--output html]
"""

import argparse
import sys
from .checks.headers import check_security_headers
from .checks.exposed_files import check_exposed_files
from .checks.xss import check_xss
from .report import print_terminal_report, save_html_report


def run_scan(url: str) -> dict:
    """Run all checks against the target URL and return aggregated results."""
    print(f"\n[*] Starting scan of: {url}\n")

    results = {
        "target": url,
        "checks": {}
    }

    print("[*] Checking security headers...")
    results["checks"]["security_headers"] = check_security_headers(url)

    print("[*] Checking for exposed sensitive files...")
    results["checks"]["exposed_files"] = check_exposed_files(url)

    print("[*] Checking for reflected XSS...")
    results["checks"]["xss"] = check_xss(url)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner — educational tool for testing sites you own."
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument(
        "--output",
        choices=["terminal", "html"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    args = parser.parse_args()

    # Normalise URL
    url = args.url.rstrip("/")
    if not url.startswith(("http://", "https://")):
        print("[!] Error: URL must start with http:// or https://")
        sys.exit(1)

    results = run_scan(url)

    if args.output == "html":
        path = save_html_report(results)
        print(f"\n[+] HTML report saved to: {path}\n")
    else:
        print_terminal_report(results)


if __name__ == "__main__":
    main()
