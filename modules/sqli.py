"""
sqli.py — Basic error-based SQL injection detection.
Probes URL query parameters with common SQLi payloads and looks for DB error signatures.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from .core import DEFAULT_HEADERS, TIMEOUT

# Common SQLi test payloads (error-based detection only — safe, non-destructive)
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1' AND SLEEP(0)--",   # Won't actually sleep (0s) but triggers syntax errors
    "1; SELECT 1--",
    "' UNION SELECT NULL--",
    "admin'--",
]

# DB error signatures that indicate SQL injection vulnerability
ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    # MSSQL
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sql server",
    "unclosed quotation mark",
    # Oracle
    "ora-00933",
    "ora-00907",
    "ora-01756",
    "oracle error",
    # PostgreSQL
    "pg_query",
    "postgresql",
    "psql error",
    "pg::syntaxerror",
    # SQLite
    "sqlite_",
    "sqlite3::query",
    "sqliteexception",
    # Generic
    "sql syntax",
    "syntax error",
    "database error",
    "db error",
    "sql error",
    "invalid query",
    "unrecognized token",
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Build a new URL with the given param replaced by payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _has_sql_error(response_text: str) -> str | None:
    """Return the matched error signature if found in the response, else None."""
    lower_text = response_text.lower()
    for sig in ERROR_SIGNATURES:
        if sig in lower_text:
            return sig
    return None


def check_sqli(url: str) -> dict:
    """
    Test each query parameter in the URL with SQLi payloads.
    Returns a dict with 'vulnerable_params' and 'tested_params'.
    """
    results = {
        "vulnerable_params": [],
        "tested_params": [],
        "has_params": False,
        "error": None,
    }

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        results["has_params"] = False
        return results

    results["has_params"] = True
    results["tested_params"] = list(params.keys())

    for param in params:
        for payload in SQLI_PAYLOADS:
            injected_url = _inject_param(url, param, payload)
            try:
                response = requests.get(
                    injected_url,
                    headers=DEFAULT_HEADERS,
                    timeout=TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                )
                matched_sig = _has_sql_error(response.text)
                if matched_sig:
                    results["vulnerable_params"].append({
                        "param": param,
                        "payload": payload,
                        "matched_signature": matched_sig,
                        "injected_url": injected_url,
                        "status_code": response.status_code,
                    })
                    break  # One confirmed hit per param is enough
            except requests.exceptions.RequestException:
                continue

    return results
