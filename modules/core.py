"""
core.py — Core HTTP scanner: sends requests, checks SSL, collects base info.
"""

import ssl
import socket
import requests
import urllib3
from urllib.parse import urlparse
from datetime import datetime

# Suppress SSL warnings for intentional unverified scans
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
DEFAULT_HEADERS = {
    "User-Agent": "WebVulnScanner/1.0 (Security Research)"
}


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def fetch(url: str, verify_ssl: bool = True, allow_redirects: bool = True) -> requests.Response | None:
    """
    Perform a GET request and return the response.
    Returns None on connection failure.
    """
    try:
        response = requests.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=TIMEOUT,
            verify=verify_ssl,
            allow_redirects=allow_redirects,
        )
        return response
    except requests.exceptions.SSLError:
        # Retry without SSL verification to still get response data
        try:
            return requests.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=allow_redirects,
            )
        except requests.exceptions.RequestException:
            return None
    except requests.exceptions.RequestException:
        return None


def check_ssl(url: str) -> dict:
    """
    Check SSL/TLS certificate validity and expiry.
    Returns a dict with ssl_valid, ssl_expiry, ssl_issuer, error.
    """
    result = {
        "ssl_valid": False,
        "ssl_expiry": None,
        "ssl_issuer": None,
        "days_remaining": None,
        "error": None,
    }

    parsed = urlparse(normalize_url(url))
    if parsed.scheme != "https":
        result["error"] = "Not an HTTPS URL"
        return result

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Parse expiry
        expiry_str = cert.get("notAfter", "")
        expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry_dt - datetime.utcnow()).days

        # Parse issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_dict.get("organizationName", "Unknown")

        result["ssl_valid"] = True
        result["ssl_expiry"] = expiry_str
        result["ssl_issuer"] = issuer
        result["days_remaining"] = days_remaining

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


def get_base_info(url: str) -> dict:
    """
    Collect basic info about the target: status code, server, content-type, redirect chain.
    """
    url = normalize_url(url)
    response = fetch(url, verify_ssl=False)

    if response is None:
        return {"error": f"Could not connect to {url}"}

    # Collect redirect chain
    redirect_chain = [r.url for r in response.history] + [response.url]

    return {
        "url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "server": response.headers.get("Server", "Not disclosed"),
        "content_type": response.headers.get("Content-Type", "Unknown"),
        "redirect_chain": redirect_chain,
        "response_time_ms": int(response.elapsed.total_seconds() * 1000),
    }
