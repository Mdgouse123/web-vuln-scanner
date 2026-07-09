"""
xss.py — Basic reflected XSS detection.
Injects XSS payloads into query parameters and checks if they appear unescaped in the response.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .core import DEFAULT_HEADERS, TIMEOUT

# Unique markers embedded in payloads so we can detect reflection
XSS_MARKER = "xss7331probe"

XSS_PAYLOADS = [
    f'<script>{XSS_MARKER}</script>',
    f'"><script>{XSS_MARKER}</script>',
    f"'><script>{XSS_MARKER}</script>",
    f'<img src=x onerror="{XSS_MARKER}">',
    f'javascript:{XSS_MARKER}',
    f'<svg onload={XSS_MARKER}>',
    f'"><img src=1 onerror="{XSS_MARKER}">',
    f"<body onload='{XSS_MARKER}'>",
]

# Signs that the payload was NOT properly escaped (reflects raw)
DANGEROUS_REFLECTIONS = [
    f"<script>{XSS_MARKER}</script>",
    f"onerror=\"{XSS_MARKER}\"",
    f"onerror='{XSS_MARKER}'",
    f"onload={XSS_MARKER}",
    f"javascript:{XSS_MARKER}",
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Build a new URL with the given param replaced by payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _is_reflected_unescaped(response_text: str, payload: str) -> bool:
    """
    Check if any dangerous form of the payload appears unescaped in the response.
    Simple marker-based check — if the raw marker appears inside a tag context, flag it.
    """
    # First check: does the marker appear at all?
    if XSS_MARKER not in response_text:
        return False

    # Second check: does it appear in a dangerous (unescaped) context?
    for pattern in DANGEROUS_REFLECTIONS:
        if pattern in response_text:
            return True

    # Third check: marker inside a tag attribute or script block (heuristic)
    lower = response_text.lower()
    marker_lower = XSS_MARKER.lower()
    idx = lower.find(marker_lower)
    while idx != -1:
        # Look at surrounding chars — if inside < > it's suspicious
        context_start = max(0, idx - 50)
        context_end = min(len(response_text), idx + len(XSS_MARKER) + 50)
        context = response_text[context_start:context_end]
        if "<" in context or ">" in context or "on" in context.lower():
            return True
        idx = lower.find(marker_lower, idx + 1)

    return False


def check_xss(url: str) -> dict:
    """
    Test each query parameter in the URL with XSS reflection payloads.
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
        for payload in XSS_PAYLOADS:
            injected_url = _inject_param(url, param, payload)
            try:
                response = requests.get(
                    injected_url,
                    headers=DEFAULT_HEADERS,
                    timeout=TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                )
                if _is_reflected_unescaped(response.text, payload):
                    results["vulnerable_params"].append({
                        "param": param,
                        "payload": payload,
                        "injected_url": injected_url,
                        "status_code": response.status_code,
                    })
                    break  # One confirmed hit per param is enough
            except requests.exceptions.RequestException:
                continue

    return results
