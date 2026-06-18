# 🔍 Web Vulnerability Scanner

A lightweight, educational command-line tool that scans websites for common
security misconfigurations — built to learn real-world AppSec concepts and
demonstrate them in a portfolio context.

> **⚠️ Legal notice:** Only scan websites you own or have explicit written
> permission to test. Unauthorised scanning is illegal under the Computer Fraud
> and Abuse Act (CFAA) and equivalent laws worldwide. Use intentionally
> vulnerable practice targets like [DVWA](https://dvwa.co.uk/) or
> [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/).

---

## What it checks

### 1 · Security Headers
Inspects HTTP response headers for missing or misconfigured controls.
Each header maps to a real-world attack category in the [OWASP Top 10](https://owasp.org/www-project-top-ten/).

| Header | Attack it prevents | OWASP ref |
|---|---|---|
| `Strict-Transport-Security` | SSL stripping / downgrade attacks | A02 |
| `Content-Security-Policy` | Cross-Site Scripting (XSS) | A03 |
| `X-Frame-Options` | Clickjacking | A05 |
| `X-Content-Type-Options` | MIME-type sniffing attacks | A05 |
| `Referrer-Policy` | Session token leakage | A01 |
| `Permissions-Policy` | Feature abuse (camera, mic, location) | A05 |

### 2 · Exposed Sensitive Files
Probes ~25 common paths for files that should never be publicly accessible:
`.git/config`, `.env`, `phpinfo.php`, database dumps, admin panels, and more.

---

## Quick start

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/web-vuln-scanner.git
cd web-vuln-scanner

# 2. Install dependencies (Python 3.8+ required)
pip install -r requirements.txt

# 3. Scan a target — terminal output
python -m scanner.main https://example.com

# 4. Generate an HTML report
python -m scanner.main https://example.com --output html
# → report saved to reports/report_YYYYMMDD_HHMMSS.html

# 5. Run the tests
pytest tests/ -v
```

---

## Example output (terminal)

```
============================================================
  SCAN REPORT
  Target : https://juice-shop.herokuapp.com
  Time   : 2024-12-01 14:32:11
============================================================

[ Security Headers ]  1 passed  5 failed  (of 6 checked)

  ✔  Strict-Transport-Security
  ✘  Content-Security-Policy             [HIGH]
      Why: Missing CSP makes XSS attacks far easier ...
      Ref: OWASP A03 – Injection (XSS)
      Fix: Add header → default-src 'self'; script-src 'self'
  ...

[ Exposed Files ]  Checked 25 paths · 2 exposed · 0 blocked

  [EXPOSED]  CRITICAL  /.git/config
      Git config file — can expose repo URL and credentials
      URL: https://juice-shop.herokuapp.com/.git/config
```

---

## Project structure

```
web-vuln-scanner/
├── scanner/
│   ├── main.py              # CLI entry point
│   ├── report.py            # Terminal + HTML report generator
│   └── checks/
│       ├── headers.py       # Security headers check (+ OWASP refs)
│       └── exposed_files.py # Sensitive file/path probing
├── tests/
│   └── test_headers.py      # Unit tests (pytest)
├── reports/                 # Generated HTML reports (git-ignored)
├── requirements.txt
└── README.md
```

---

## Roadmap (planned features)

- [ ] Basic XSS payload injection into discovered forms
- [ ] SQL injection detection (error-based)
- [ ] Server banner / version disclosure detection
- [ ] Cookie flag analysis (`Secure`, `HttpOnly`, `SameSite`)
- [ ] Multi-threaded scanning for speed
- [ ] JSON output for CI/CD pipeline integration
- [ ] Config file for custom path lists and payloads

---

## Concepts covered

Building this project teaches you:

- How HTTP request/response cycles work at the header level
- The OWASP Top 10 and what each category means in practice
- Why `.git`, `.env`, and similar files are catastrophic to expose
- How professional scanners (Nikto, OWASP ZAP) approach enumeration
- Python `requests`, argument parsing, file I/O, and unit testing

---

## Safe practice targets

These are **intentionally vulnerable** apps designed for learning:

| Target | How to run |
|---|---|
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | `docker run -p 3000:3000 bkimminich/juice-shop` |
| [DVWA](https://dvwa.co.uk/) | `docker run -p 80:80 vulnerables/web-dvwa` |
| [HackTheBox](https://www.hackthebox.com/) | Web-based labs (free tier available) |

---

## License

MIT — free to use, study, and extend.
