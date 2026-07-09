"""
headers.py — Check HTTP security headers for presence and correct configuration.
"""

from .core import fetch, normalize_url

# Each entry: (header_name, severity, description, recommendation)
SECURITY_HEADERS = [
    (
        "Content-Security-Policy",
        "HIGH",
        "Prevents XSS and data injection attacks by controlling resource origins.",
        "Add a strict CSP policy, e.g.: default-src 'self'",
    ),
    (
        "Strict-Transport-Security",
        "HIGH",
        "Forces browsers to use HTTPS, preventing downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "X-Frame-Options",
        "MEDIUM",
        "Prevents clickjacking by disallowing the page to be embedded in iframes.",
        "Add: X-Frame-Options: DENY  or  SAMEORIGIN",
    ),
    (
        "X-Content-Type-Options",
        "MEDIUM",
        "Prevents MIME-type sniffing attacks.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    (
        "Referrer-Policy",
        "LOW",
        "Controls how much referrer info is sent with requests.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "Permissions-Policy",
        "LOW",
        "Restricts access to browser features (camera, mic, geolocation).",
        "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    ),
    (
        "X-XSS-Protection",
        "LOW",
        "Legacy XSS filter for older browsers (mostly superseded by CSP).",
        "Add: X-XSS-Protection: 1; mode=block  (for legacy browser support)",
    ),
]

# Headers that should NOT be present (information disclosure)
DISCOURAGED_HEADERS = [
    (
        "X-Powered-By",
        "LOW",
        "Discloses the backend technology (e.g., PHP/7.4). Helps attackers fingerprint the stack.",
        "Remove this header from your server/framework configuration.",
    ),
    (
        "Server",
        "INFO",
        "Discloses server software and version. Useful for attacker recon.",
        "Configure your server to omit or obscure this header.",
    ),
]


def check_security_headers(url: str) -> dict:
    """
    Fetch the target URL and analyze security-related response headers.
    Returns a dict with 'missing', 'present', and 'discouraged' lists.
    """
    url = normalize_url(url)
    response = fetch(url, verify_ssl=False)

    if response is None:
        return {"error": f"Could not connect to {url}"}

    headers = {k.lower(): v for k, v in response.headers.items()}
    results = {
        "missing": [],
        "present": [],
        "discouraged": [],
        "score": 0,
        "max_score": 0,
    }

    severity_weight = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    for header, severity, description, recommendation in SECURITY_HEADERS:
        weight = severity_weight[severity]
        results["max_score"] += weight

        if header.lower() in headers:
            results["present"].append({
                "header": header,
                "value": headers[header.lower()],
                "severity": severity,
                "description": description,
            })
            results["score"] += weight
        else:
            results["missing"].append({
                "header": header,
                "severity": severity,
                "description": description,
                "recommendation": recommendation,
            })

    for header, severity, description, recommendation in DISCOURAGED_HEADERS:
        if header.lower() in headers:
            results["discouraged"].append({
                "header": header,
                "value": headers[header.lower()],
                "severity": severity,
                "description": description,
                "recommendation": recommendation,
            })

    return results
