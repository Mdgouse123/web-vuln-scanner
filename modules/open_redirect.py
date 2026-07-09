"""
open_redirect.py — Detect open redirect vulnerabilities in URL parameters.
Tests parameters that commonly contain redirect URLs (next, url, redirect, etc.)
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .core import DEFAULT_HEADERS, TIMEOUT

# Parameters commonly used for redirects
REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "returnUrl", "returnTo", "goto",
    "target", "destination", "dest", "continue", "forward",
    "location", "ref", "referer", "callback", "back",
]

# External domain to use as redirect target in tests
CANARY_DOMAIN = "https://evil-redirect-canary.example.com"

REDIRECT_PAYLOADS = [
    CANARY_DOMAIN,
    f"//{CANARY_DOMAIN.replace('https://', '')}",  # Protocol-relative
    f"\\\\{CANARY_DOMAIN.replace('https://', '')}",  # Backslash bypass
    f"https:/{CANARY_DOMAIN.replace('https://', '')}",  # Single slash bypass
    f"{CANARY_DOMAIN}%2F%2F",  # URL-encoded slashes
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Build a new URL with the given param replaced by payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _is_redirected_to_canary(response: requests.Response) -> bool:
    """Check if the response chain redirected to our canary domain."""
    canary_host = urlparse(CANARY_DOMAIN).netloc
    for r in response.history:
        location = r.headers.get("Location", "")
        if canary_host in location:
            return True
    # Also check the final URL
    if canary_host in response.url:
        return True
    return False


def check_open_redirect(url: str) -> dict:
    """
    Test URL parameters for open redirect vulnerabilities.
    Checks both existing params and appends common redirect param names.
    Returns a dict with 'vulnerable_params'.
    """
    results = {
        "vulnerable_params": [],
        "tested_params": [],
        "error": None,
    }

    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query, keep_blank_values=True)

    # Build the set of params to test: existing ones + common redirect param names
    params_to_test = set(existing_params.keys())
    # Also inject common redirect params even if not present in original URL
    for rp in REDIRECT_PARAMS:
        params_to_test.add(rp)

    results["tested_params"] = list(params_to_test)

    for param in params_to_test:
        for payload in REDIRECT_PAYLOADS:
            injected_url = _inject_param(url, param, payload)
            try:
                response = requests.get(
                    injected_url,
                    headers=DEFAULT_HEADERS,
                    timeout=TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                )
                if _is_redirected_to_canary(response):
                    results["vulnerable_params"].append({
                        "param": param,
                        "payload": payload,
                        "injected_url": injected_url,
                        "redirect_location": response.url,
                    })
                    break
            except requests.exceptions.TooManyRedirects:
                # TooManyRedirects can also indicate a redirect loop — not a canary hit
                continue
            except requests.exceptions.RequestException:
                continue

    return results
