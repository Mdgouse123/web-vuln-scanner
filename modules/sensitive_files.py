"""
sensitive_files.py — Probe for commonly exposed sensitive files and directories.
"""

import requests
from .core import normalize_url, DEFAULT_HEADERS, TIMEOUT

# (path, severity, description)
SENSITIVE_PATHS = [
    # Environment & config files
    ("/.env",                   "CRITICAL", "Environment file — may contain DB passwords, API keys, secrets."),
    ("/.env.local",             "CRITICAL", "Local environment override file."),
    ("/.env.production",        "CRITICAL", "Production environment file."),
    ("/config.php",             "HIGH",     "PHP config file — may contain database credentials."),
    ("/wp-config.php",          "HIGH",     "WordPress config — contains DB credentials."),
    ("/config.yml",             "HIGH",     "YAML config file — may contain sensitive settings."),
    ("/config.json",            "HIGH",     "JSON config file — may contain API keys or secrets."),
    ("/settings.py",            "HIGH",     "Django/Python settings — may expose SECRET_KEY and DB info."),
    ("/database.yml",           "HIGH",     "Rails database config — may expose DB credentials."),

    # Version control
    ("/.git/HEAD",              "CRITICAL", "Exposed Git repository — source code may be downloadable."),
    ("/.git/config",            "CRITICAL", "Git config — may expose remote URLs and credentials."),
    ("/.svn/entries",           "HIGH",     "Exposed SVN repository."),
    ("/.hg/hgrc",               "HIGH",     "Exposed Mercurial repository."),

    # Backup & log files
    ("/backup.zip",             "CRITICAL", "Backup archive — may contain full application source."),
    ("/backup.tar.gz",          "CRITICAL", "Backup archive."),
    ("/db.sql",                 "CRITICAL", "SQL database dump."),
    ("/dump.sql",               "CRITICAL", "SQL database dump."),
    ("/error.log",              "MEDIUM",   "Error log — may expose stack traces and internal paths."),
    ("/access.log",             "MEDIUM",   "Access log — may expose internal request patterns."),
    ("/debug.log",              "MEDIUM",   "Debug log — may expose sensitive debug information."),

    # Admin & default pages
    ("/admin",                  "MEDIUM",   "Admin panel exposed — should be restricted."),
    ("/admin/",                 "MEDIUM",   "Admin panel exposed."),
    ("/wp-admin/",              "MEDIUM",   "WordPress admin panel."),
    ("/phpmyadmin/",            "HIGH",     "phpMyAdmin exposed — database management interface."),
    ("/adminer.php",            "HIGH",     "Adminer DB tool exposed."),
    ("/manager/html",           "HIGH",     "Tomcat Manager exposed."),

    # Info disclosure
    ("/robots.txt",             "INFO",     "robots.txt — may disclose hidden paths."),
    ("/sitemap.xml",            "INFO",     "Sitemap — discloses site structure."),
    ("/.htaccess",              "MEDIUM",   ".htaccess — may expose rewrite rules and access controls."),
    ("/server-status",          "HIGH",     "Apache server-status page — exposes request info."),
    ("/server-info",            "HIGH",     "Apache server-info page — exposes configuration."),
    ("/.DS_Store",              "LOW",      ".DS_Store — macOS metadata file, exposes directory structure."),
    ("/Thumbs.db",              "LOW",      "Windows thumbnail cache — minor info disclosure."),

    # Package / dependency files
    ("/package.json",           "MEDIUM",   "Node.js package file — discloses dependencies and versions."),
    ("/composer.json",          "MEDIUM",   "PHP Composer file — discloses dependencies."),
    ("/Gemfile",                "MEDIUM",   "Ruby Gemfile — discloses dependencies."),
    ("/requirements.txt",       "LOW",      "Python requirements — discloses dependency versions."),
    ("/yarn.lock",              "LOW",      "Yarn lock file — discloses exact dependency versions."),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def check_sensitive_files(url: str) -> dict:
    """
    Probe the target for exposed sensitive files and directories.
    Returns a dict with 'found' and 'checked' counts.
    """
    base_url = normalize_url(url)
    results = {
        "found": [],
        "checked": len(SENSITIVE_PATHS),
        "error": None,
    }

    for path, severity, description in SENSITIVE_PATHS:
        target = base_url + path
        try:
            response = requests.get(
                target,
                headers=DEFAULT_HEADERS,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=False,  # Don't follow redirects — 301/302 to login != exposed
            )

            # Consider it found if status is 200 or certain 4xx that indicate existence
            # 403 = exists but forbidden (still worth reporting)
            if response.status_code == 200:
                content_length = len(response.content)
                results["found"].append({
                    "path": path,
                    "url": target,
                    "status_code": response.status_code,
                    "severity": severity,
                    "description": description,
                    "content_length": content_length,
                    "snippet": _safe_snippet(response.text),
                })
            elif response.status_code == 403:
                results["found"].append({
                    "path": path,
                    "url": target,
                    "status_code": response.status_code,
                    "severity": "LOW" if SEVERITY_ORDER[severity] > 1 else severity,
                    "description": f"{description} (Access forbidden — resource exists but restricted.)",
                    "content_length": 0,
                    "snippet": None,
                })

        except requests.exceptions.RequestException:
            # Skip unreachable paths silently
            continue

    # Sort by severity
    results["found"].sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 5))
    return results


def _safe_snippet(text: str, max_chars: int = 200) -> str:
    """Return a safe preview snippet of response content."""
    text = text.strip()
    if not text:
        return None
    return text[:max_chars] + ("..." if len(text) > max_chars else "")
