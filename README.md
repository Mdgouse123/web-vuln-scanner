# Web Vulnerability Scanner

A Python-based CLI tool that scans web applications for common security vulnerabilities. Built for educational purposes and authorized security testing.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Topic-Cybersecurity-red)

---

## Features

| Module | What it checks |
|---|---|
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **SSL/TLS** | Certificate validity, expiry date, issuer |
| **Sensitive Files** | `.env`, `.git`, backups, admin panels, config files (40+ paths) |
| **SQL Injection** | Error-based detection across all URL query parameters |
| **Reflected XSS** | Payload injection and unescaped reflection detection |
| **Open Redirect** | Tests common redirect parameters with external canary payloads |

---

## Preview

```
╔══════════════════════════════════════════╗
║       Web Vulnerability Scanner v1.0     ║
║   For authorized security testing only   ║
╚══════════════════════════════════════════╝

  Target: https://example.com

──────────────── Target Info ────────────────
  URL            https://example.com
  Status Code    200
  Server         ECS (dcb/7F18)
  Response Time  210 ms

──────────────── Security Headers ───────────
  Header Score: 1/10  (10%)

  Missing Headers:
    ✖ CRITICAL  Content-Security-Policy
    ● HIGH      Strict-Transport-Security
    ◆ MEDIUM    X-Frame-Options
    ...

──────────────── Scan Summary ───────────────
  CRITICAL   Exposed file: /.git/HEAD [200]
  HIGH       Missing header: Content-Security-Policy
  MEDIUM     Missing header: X-Frame-Options

  Total findings: 7
```

---

## Installation

**Requirements:** Python 3.8+

```bash
# Clone the repository
git clone https://github.com/Mdgouse123/web-vuln-scanner.git
cd web-vuln-scanner

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
#general command to run any vuln website
python scanner.py "website link" --report all

# Basic scan — terminal output only
python scanner.py https://example.com

# Save results as HTML report
python scanner.py https://example.com --report html

# Save results as JSON report
python scanner.py https://example.com --report json

# Save both HTML and JSON
python scanner.py https://example.com --report both

# Test SQLi and XSS (URL needs query parameters)
python scanner.py "http://testphp.vulnweb.com/listproducts.php?cat=1" --report both

# Show help
python scanner.py --help
```

Reports are saved to the `reports/` folder with the format:
```
reports/scan_<hostname>_<timestamp>.html
reports/scan_<hostname>_<timestamp>.json
```

---

## Project Structure

```
web_vuln_scanner/
├── scanner.py              # Main CLI entry point
├── requirements.txt        # Python dependencies
├── reports/                # Generated scan reports (git-ignored)
└── modules/
    ├── core.py             # HTTP fetcher, SSL checker, base info
    ├── headers.py          # Security headers analyzer
    ├── sensitive_files.py  # Sensitive path exposure checker
    ├── sqli.py             # SQL injection detector
    ├── xss.py              # Reflected XSS detector
    └── open_redirect.py    # Open redirect tester
```

---

## Safe Test Targets

These are intentionally vulnerable or public test sites — legal and safe to scan:

| Site | What it tests |
|---|---|
| `https://httpbin.org` | Headers, SSL, base info |
| `http://testphp.vulnweb.com/listproducts.php?cat=1` | SQLi, XSS, sensitive files |
| `https://example.com` | Headers, SSL |

> Never scan sites you do not own or have explicit written permission to test.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `requests` | 2.31.0 | HTTP requests |
| `beautifulsoup4` | 4.12.3 | HTML parsing |
| `rich` | 13.7.1 | Terminal output formatting |
| `urllib3` | 2.2.1 | HTTP connection handling |
| `certifi` | 2024.2.2 | SSL certificate verification |
| `colorama` | 0.4.6 | Windows terminal color support |

---

## Legal Disclaimer

> This tool is intended for **educational purposes** and **authorized security testing only**.
> Unauthorized scanning of systems you do not own may violate computer crime laws including the
> Computer Fraud and Abuse Act (CFAA) and similar legislation in your jurisdiction.
> The author is not responsible for any misuse of this tool.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
