"""
scanner.py - Main CLI entry point for the Web Vulnerability Scanner.
Usage: python scanner.py <url> [--report json|html|both]
"""

import argparse
import json
import sys
import os

# Fix Windows terminal encoding so rich output renders correctly
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
from datetime import datetime
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn

from modules.core import get_base_info, check_ssl, normalize_url
from modules.headers import check_security_headers
from modules.sensitive_files import check_sensitive_files
from modules.sqli import check_sqli
from modules.xss import check_xss
from modules.open_redirect import check_open_redirect

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}

SEVERITY_ICONS = {
    "CRITICAL": "[bold red][X] CRITICAL[/bold red]",
    "HIGH": "[red][!] HIGH[/red]",
    "MEDIUM": "[yellow][~] MEDIUM[/yellow]",
    "LOW": "[cyan][>] LOW[/cyan]",
    "INFO": "[dim][i] INFO[/dim]",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner():
    console.print(Panel(
        "[bold cyan]Web Vulnerability Scanner[/bold cyan]  [dim]v1.0[/dim]\n"
        "[dim]For authorized security testing only[/dim]",
        border_style="cyan",
        expand=False,
    ))
    console.print()


# ---------------------------------------------------------------------------
# Section helpers
# ---------------------------------------------------------------------------

def section(title):
    console.print()
    console.print(Rule(f"[bold white]{title}[/bold white]", style="cyan"))


def badge(severity):
    return SEVERITY_ICONS.get(severity, severity)


# ---------------------------------------------------------------------------
# Per-module printers
# ---------------------------------------------------------------------------

def print_base_info(info):
    section("Target Info")
    if "error" in info:
        console.print(f"  [red]Error:[/red] {info['error']}")
        return
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column("Key", style="dim", width=20)
    t.add_column("Value", style="white")
    t.add_row("URL", info["url"])
    t.add_row("Final URL", info["final_url"])
    t.add_row("Status Code", str(info["status_code"]))
    t.add_row("Server", info["server"])
    t.add_row("Content-Type", info["content_type"])
    t.add_row("Response Time", f"{info['response_time_ms']} ms")
    if len(info["redirect_chain"]) > 1:
        t.add_row("Redirects", " â†’ ".join(info["redirect_chain"]))
    console.print(t)


def print_ssl_info(ssl_info):
    section("SSL / TLS Certificate")
    if ssl_info.get("error"):
        console.print(f"  [red]âœ– SSL Error:[/red] {ssl_info['error']}")
        return
    days = ssl_info.get("days_remaining")
    if days is None:
        console.print("  [dim]Not applicable (HTTP).[/dim]")
        return
    color = "green" if days > 30 else ("yellow" if days > 7 else "red")
    console.print(f"  [green]âœ”[/green] Certificate valid")
    console.print(f"  Issuer:  [white]{ssl_info['ssl_issuer']}[/white]")
    console.print(
        f"  Expires: [{color}]{ssl_info['ssl_expiry']}[/{color}]"
        f"  ([{color}]{days} days remaining[/{color}])"
    )


def print_headers_report(result):
    section("Security Headers")
    if "error" in result:
        console.print(f"  [red]Error:[/red] {result['error']}")
        return
    score, max_score = result["score"], result["max_score"]
    pct = int((score / max_score) * 100) if max_score else 0
    sc = "green" if pct >= 70 else ("yellow" if pct >= 40 else "red")
    console.print(f"  Header Score: [{sc}]{score}/{max_score}[/{sc}]  ({pct}%)\n")

    if result["missing"]:
        console.print("  [bold red]Missing Headers:[/bold red]")
        for h in result["missing"]:
            console.print(f"    {badge(h['severity'])}  [white]{h['header']}[/white]")
            console.print(f"      [dim]{h['description']}[/dim]")
            console.print(f"      [green]Fix:[/green] {h['recommendation']}\n")

    if result["present"]:
        console.print("  [bold green]Present Headers:[/bold green]")
        for h in result["present"]:
            console.print(
                f"    [green]âœ”[/green] [white]{h['header']}[/white]: "
                f"[dim]{h['value'][:80]}[/dim]"
            )

    if result["discouraged"]:
        console.print()
        console.print("  [bold yellow]Information Disclosure Headers:[/bold yellow]")
        for h in result["discouraged"]:
            console.print(f"    {badge(h['severity'])}  [white]{h['header']}[/white]: [dim]{h['value']}[/dim]")
            console.print(f"      [dim]{h['description']}[/dim]")
            console.print(f"      [green]Fix:[/green] {h['recommendation']}")


def print_sensitive_files_report(result):
    section("Sensitive Files & Directories")
    if result.get("error"):
        console.print(f"  [red]Error:[/red] {result['error']}")
        return
    found = result["found"]
    color = "red" if found else "green"
    console.print(
        f"  Probed [white]{result['checked']}[/white] paths â€” "
        f"found [{color}]{len(found)}[/{color}] exposed.\n"
    )
    if not found:
        console.print("  [green]âœ” No sensitive files exposed.[/green]")
        return
    for item in found:
        sc_color = "green" if item["status_code"] == 200 else "yellow"
        console.print(
            f"  {badge(item['severity'])}  [white]{item['path']}[/white]  "
            f"[[{sc_color}]{item['status_code']}[/{sc_color}]]"
        )
        console.print(f"    [dim]{item['description']}[/dim]")
        if item.get("snippet"):
            console.print(f"    [dim]Preview: {item['snippet'][:100]}[/dim]")
        console.print()


def print_sqli_report(result):
    section("SQL Injection Detection")
    if result.get("error"):
        console.print(f"  [red]Error:[/red] {result['error']}")
        return
    if not result["has_params"]:
        console.print("  [dim]No query parameters in URL. Skipping.[/dim]")
        console.print("  [dim]Tip: Try https://example.com/page?id=1[/dim]")
        return
    console.print(f"  Tested params: [white]{', '.join(result['tested_params'])}[/white]\n")
    if not result["vulnerable_params"]:
        console.print("  [green]âœ” No SQL injection errors detected.[/green]")
        return
    console.print("  [bold red]Potential SQL Injection Found:[/bold red]")
    for v in result["vulnerable_params"]:
        console.print(f"    [red]âœ–[/red] Parameter: [white]{v['param']}[/white]")
        console.print(f"      Payload:   [dim]{v['payload']}[/dim]")
        console.print(f"      Triggered: [dim]{v['matched_signature']}[/dim]")
        console.print(f"      URL:       [dim]{v['injected_url'][:100]}[/dim]\n")


def print_xss_report(result):
    section("XSS (Cross-Site Scripting) Detection")
    if result.get("error"):
        console.print(f"  [red]Error:[/red] {result['error']}")
        return
    if not result["has_params"]:
        console.print("  [dim]No query parameters in URL. Skipping.[/dim]")
        console.print("  [dim]Tip: Try https://example.com/search?q=test[/dim]")
        return
    console.print(f"  Tested params: [white]{', '.join(result['tested_params'])}[/white]\n")
    if not result["vulnerable_params"]:
        console.print("  [green]âœ” No reflected XSS detected.[/green]")
        return
    console.print("  [bold red]Potential Reflected XSS Found:[/bold red]")
    for v in result["vulnerable_params"]:
        console.print(f"    [red]âœ–[/red] Parameter: [white]{v['param']}[/white]")
        console.print(f"      Payload: [dim]{v['payload']}[/dim]")
        console.print(f"      URL:     [dim]{v['injected_url'][:100]}[/dim]\n")


def print_redirect_report(result):
    section("Open Redirect Detection")
    if result.get("error"):
        console.print(f"  [red]Error:[/red] {result['error']}")
        return
    if not result["vulnerable_params"]:
        console.print("  [green]âœ” No open redirect vulnerabilities detected.[/green]")
        return
    console.print("  [bold red]Open Redirect Found:[/bold red]")
    for v in result["vulnerable_params"]:
        console.print(f"    [red]âœ–[/red] Parameter: [white]{v['param']}[/white]")
        console.print(f"      Payload: [dim]{v['payload']}[/dim]")
        console.print(f"      URL:     [dim]{v['injected_url'][:100]}[/dim]\n")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def build_findings(all_results):
    findings = []

    for h in all_results.get("headers", {}).get("missing", []):
        findings.append((h["severity"], f"Missing header: {h['header']}"))
    for h in all_results.get("headers", {}).get("discouraged", []):
        findings.append((h["severity"], f"Info-disclosing header: {h['header']}: {h['value']}"))

    for f in all_results.get("sensitive_files", {}).get("found", []):
        findings.append((f["severity"], f"Exposed file: {f['path']} [{f['status_code']}]"))

    for v in all_results.get("sqli", {}).get("vulnerable_params", []):
        findings.append(("HIGH", f"SQL Injection â€” param: {v['param']}"))

    for v in all_results.get("xss", {}).get("vulnerable_params", []):
        findings.append(("HIGH", f"Reflected XSS â€” param: {v['param']}"))

    for v in all_results.get("open_redirect", {}).get("vulnerable_params", []):
        findings.append(("MEDIUM", f"Open Redirect â€” param: {v['param']}"))

    ssl_info = all_results.get("ssl", {})
    if ssl_info.get("error"):
        findings.append(("HIGH", f"SSL issue: {ssl_info['error']}"))
    elif ssl_info.get("days_remaining") is not None and ssl_info["days_remaining"] < 30:
        findings.append(("MEDIUM", f"SSL cert expiring in {ssl_info['days_remaining']} days"))

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x[0], 5))
    return findings


def print_summary(all_results):
    section("Scan Summary")
    findings = build_findings(all_results)

    if not findings:
        console.print("  [bold green]âœ” No significant vulnerabilities detected![/bold green]")
    else:
        t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold white")
        t.add_column("Severity", width=12)
        t.add_column("Finding")
        for sev, desc in findings:
            color = SEVERITY_COLORS.get(sev, "white")
            t.add_row(f"[{color}]{sev}[/{color}]", desc)
        console.print(t)
        console.print(f"\n  Total findings: [bold red]{len(findings)}[/bold red]")

    console.print(f"\n  [dim]Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
    return findings


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------

def export_json(url, all_results, findings):
    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = urlparse(normalize_url(url)).hostname or "unknown"
    path = f"reports/scan_{host}_{ts}.json"
    payload = {
        "scan_target": url,
        "scan_time": datetime.now().isoformat(),
        "summary": [{"severity": s, "finding": d} for s, d in findings],
        "details": all_results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    console.print(f"\n  [green]âœ” JSON report:[/green] [white]{path}[/white]")


def export_html(url, all_results, findings):
    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = urlparse(normalize_url(url)).hostname or "unknown"
    path = f"reports/scan_{host}_{ts}.html"

    sev_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM": "#d97706", "LOW": "#0891b2", "INFO": "#6b7280",
    }
    rows = "".join(
        f'<tr><td style="color:{sev_colors.get(s,"#fff")};font-weight:bold">{s}</td>'
        f"<td>{d}</td></tr>\n"
        for s, d in findings
    )
    base = all_results.get("base_info", {})
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Scan Report â€” {url}</title>
  <style>
    body{{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px}}
    h1{{color:#38bdf8}}h2{{color:#7dd3fc;border-bottom:1px solid #1e3a5f;padding-bottom:6px}}
    table{{width:100%;border-collapse:collapse;margin-bottom:24px}}
    th{{background:#1e3a5f;color:#bae6fd;padding:10px;text-align:left}}
    td{{padding:8px 10px;border-bottom:1px solid #1e293b}}
    tr:hover td{{background:#1e293b}}
    .meta{{color:#94a3b8;font-size:.9em;margin-bottom:24px}}
    .footer{{margin-top:40px;color:#475569;font-size:.8em}}
  </style>
</head>
<body>
  <h1>Web Vulnerability Scan Report</h1>
  <div class="meta">
    <strong>Target:</strong> {url}<br>
    <strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
    <strong>Status:</strong> {base.get('status_code','N/A')} &nbsp;|&nbsp;
    <strong>Server:</strong> {base.get('server','N/A')} &nbsp;|&nbsp;
    <strong>Response:</strong> {base.get('response_time_ms','N/A')} ms
  </div>
  <h2>Summary â€” {len(findings)} Finding(s)</h2>
  <table>
    <tr><th>Severity</th><th>Finding</th></tr>
    {rows or '<tr><td colspan="2" style="color:#22c55e">No significant vulnerabilities detected.</td></tr>'}
  </table>
  <div class="footer">Generated by WebVulnScanner v1.0 â€” For authorized security testing only.</div>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"  [green]âœ” HTML report:[/green] [white]{path}[/white]")


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def run_scan(url, report_format=None):
    print_banner()
    url = normalize_url(url)
    console.print(f"  [bold white]Target:[/bold white] [cyan]{url}[/cyan]\n")

    all_results = {}

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        t = progress.add_task("[cyan]Collecting base info...", total=None)
        all_results["base_info"] = get_base_info(url)
        progress.update(t, description="[cyan]Checking SSL certificate...")
        all_results["ssl"] = check_ssl(url)
        progress.update(t, description="[cyan]Analyzing security headers...")
        all_results["headers"] = check_security_headers(url)
        progress.update(t, description="[cyan]Probing sensitive files...")
        all_results["sensitive_files"] = check_sensitive_files(url)
        progress.update(t, description="[cyan]Testing SQL injection...")
        all_results["sqli"] = check_sqli(url)
        progress.update(t, description="[cyan]Testing XSS reflection...")
        all_results["xss"] = check_xss(url)
        progress.update(t, description="[cyan]Testing open redirects...")
        all_results["open_redirect"] = check_open_redirect(url)
        progress.update(t, description="[green]Done.")

    print_base_info(all_results["base_info"])
    print_ssl_info(all_results["ssl"])
    print_headers_report(all_results["headers"])
    print_sensitive_files_report(all_results["sensitive_files"])
    print_sqli_report(all_results["sqli"])
    print_xss_report(all_results["xss"])
    print_redirect_report(all_results["open_redirect"])
    findings = print_summary(all_results)

    if report_format in ("json", "both"):
        export_json(url, all_results, findings)
    if report_format in ("html", "both"):
        export_html(url, all_results, findings)

    console.print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py https://example.com
  python scanner.py https://example.com --report html
  python scanner.py "https://example.com/page?id=1" --report both

Checks performed:
  - HTTP security headers analysis
  - SSL/TLS certificate validity
  - Sensitive file & directory exposure
  - SQL injection (error-based)
  - Reflected XSS detection
  - Open redirect detection

WARNING: Only use on systems you own or have explicit written permission to test.
        """,
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument(
        "--report",
        choices=["json", "html", "both"],
        default=None,
        help="Export results to a report file",
    )
    args = parser.parse_args()

    console.print()
    console.print(
        "[bold yellow]! Legal Notice:[/bold yellow] Only scan systems you own "
        "or have explicit written permission to test.\n"
    )

    try:
        run_scan(args.url, report_format=args.report)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()

