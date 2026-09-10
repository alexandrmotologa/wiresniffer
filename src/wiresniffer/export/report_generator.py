"""Security audit report generator in standalone HTML and Markdown formats."""

import datetime
from typing import List

from wiresniffer.decoders.base import HttpTransaction

OWASP_MAPPINGS = {
    "PLAINTEXT_BASIC_AUTH": ("API2:2023 Broken Authentication", "CWE-319: Cleartext Transmission"),
    "PLAINTEXT_BEARER_TOKEN": (
        "API2:2023 Broken Authentication",
        "CWE-319: Cleartext Transmission",
    ),
    "CREDENTIAL_LEAK_OPENAI": (
        "API10:2023 Unsafe API Consumption",
        "CWE-798: Hard-coded Credentials",
    ),
    "CREDENTIAL_LEAK_GITHUB": (
        "API10:2023 Unsafe API Consumption",
        "CWE-798: Hard-coded Credentials",
    ),
    "CREDENTIAL_LEAK_AWS": ("API10:2023 Unsafe API Consumption", "CWE-798: Hard-coded Credentials"),
    "CREDENTIAL_LEAK_STRIPE": (
        "API10:2023 Unsafe API Consumption",
        "CWE-798: Hard-coded Credentials",
    ),
    "CREDENTIAL_LEAK_SLACK": (
        "API10:2023 Unsafe API Consumption",
        "CWE-798: Hard-coded Credentials",
    ),
    "CREDENTIAL_LEAK_DATABASE": (
        "API10:2023 Unsafe API Consumption",
        "CWE-522: Insufficiently Protected Credentials",
    ),
    "PRIVATE_KEY_EXPOSURE": (
        "API10:2023 Unsafe API Consumption",
        "CWE-522: Insufficiently Protected Credentials",
    ),
    "PII_CREDIT_CARD": ("API3:2023 Sensitive Data Exposure", "CWE-359: Privacy Violation"),
    "PII_SSN": ("API3:2023 Sensitive Data Exposure", "CWE-359: Privacy Violation"),
    "EXPIRED_JWT": ("API2:2023 Broken Authentication", "CWE-613: Insufficient Session Expiration"),
    "INSECURE_JWT_ALG_NONE": (
        "API2:2023 Broken Authentication",
        "CWE-345: Insufficient Verification",
    ),
    "SENSITIVE_JWT_PAYLOAD": ("API3:2023 Sensitive Data Exposure", "CWE-200: Information Exposure"),
    "STACK_TRACE_EXPOSURE": (
        "API8:2023 Security Misconfiguration",
        "CWE-209: Error Message Info Leak",
    ),
    "SQL_ERROR_EXPOSURE": (
        "API8:2023 Security Misconfiguration",
        "CWE-209: Error Message Info Leak",
    ),
    "INSECURE_CORS_WILDCARD": (
        "API8:2023 Security Misconfiguration",
        "CWE-942: Permissive CORS Policy",
    ),
    "GRAPHQL_INTROSPECTION_ENABLED": (
        "API8:2023 Security Misconfiguration",
        "CWE-200: Schema Disclosure",
    ),
    "GRAPHQL_FIELD_SUGGESTIONS": (
        "API8:2023 Security Misconfiguration",
        "CWE-200: Field Disclosure",
    ),
}


def generate_markdown_report(transactions: List[HttpTransaction]) -> str:
    """Generate a GitHub-flavored Markdown security audit report."""
    all_findings = []
    for tx in transactions:
        for alert in tx.security_alerts:
            all_findings.append((tx, alert))

    total = len(all_findings)
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# WireSniffer Security Audit Report",
        f"**Generated:** {now_str} | **Total Findings:** {total}\n",
        "## Executive Summary\n",
    ]

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for _, alert in all_findings:
        s = alert.get("severity", "LOW")
        if hasattr(s, "value"):
            s = s.value
        s = str(s).upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines.append("| Severity | Findings Count |")
    lines.append("| --- | --- |")
    lines.append(f"| **CRITICAL** | {sev_counts['CRITICAL']} |")
    lines.append(f"| **HIGH** | {sev_counts['HIGH']} |")
    lines.append(f"| **MEDIUM** | {sev_counts['MEDIUM']} |")
    lines.append(f"| **LOW** | {sev_counts['LOW']} |\n")

    lines.append("## Detailed Findings\n")
    if not all_findings:
        lines.append("No security vulnerabilities or policy violations detected.\n")
        return "\n".join(lines)

    for idx, (tx, alert) in enumerate(all_findings, 1):
        rule_id = alert.get("rule_id", "")
        owasp, cwe = OWASP_MAPPINGS.get(rule_id, ("API Security Violation", "CWE-200"))
        sev = alert.get("severity", "LOW")
        if hasattr(sev, "value"):
            sev = sev.value
        sev = str(sev).upper()

        lines.append(f"### {idx}. [{sev}] {alert.get('title')}")
        lines.append(f"- **Rule ID:** `{rule_id}`")
        lines.append(f"- **Endpoint:** `{tx.method} {tx.full_url}`")
        lines.append(f"- **Category:** {alert.get('category', 'General')}")
        lines.append(f"- **Standard:** {owasp} ({cwe})")
        lines.append(f"- **Evidence:** `{alert.get('evidence')}`")
        lines.append(f"- **Description:** {alert.get('description')}")
        lines.append(f"- **Remediation:** {alert.get('remediation')}\n")

    return "\n".join(lines)


def generate_html_report(transactions: List[HttpTransaction]) -> str:
    """Generate a clean standalone HTML security audit report."""
    all_findings = []
    for tx in transactions:
        for alert in tx.security_alerts:
            all_findings.append((tx, alert))

    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for _, alert in all_findings:
        s = alert.get("severity", "LOW")
        if hasattr(s, "value"):
            s = s.value
        s = str(s).upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    findings_html = []
    for idx, (tx, alert) in enumerate(all_findings, 1):
        rule_id = alert.get("rule_id", "")
        owasp, cwe = OWASP_MAPPINGS.get(rule_id, ("API Security Violation", "CWE-200"))
        sev = alert.get("severity", "LOW")
        if hasattr(sev, "value"):
            sev = sev.value
        sev = str(sev).upper()

        badge_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
        }.get(sev, "#64748b")

        card = f"""
        <div class="finding-card">
            <div class="finding-header">
                <span class="sev-badge" style="background-color: {badge_color};">{sev}</span>
                <span class="finding-title">{idx}. {alert.get("title")}</span>
            </div>
            <div class="meta-row">
                <strong>Rule:</strong> <code>{rule_id}</code> |
                <strong>Endpoint:</strong> <code>{tx.method} {tx.full_url}</code> |
                <strong>Standard:</strong> {owasp} ({cwe})
            </div>
            <p class="desc">{alert.get("description")}</p>
            <div class="evidence"><strong>Evidence:</strong> <code>{alert.get("evidence")}</code></div>
            <div class="remediation"><strong>Remediation:</strong> {alert.get("remediation")}</div>
        </div>
        """
        findings_html.append(card)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WireSniffer Security Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ color: #38bdf8; margin-bottom: 0.5rem; }}
  .date {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 2rem; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: #1e293b; padding: 1.25rem; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
  .stat-num {{ font-size: 2rem; font-weight: bold; margin-top: 0.5rem; }}
  .finding-card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
  .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }}
  .sev-badge {{ padding: 0.25rem 0.5rem; border-radius: 4px; font-weight: bold; font-size: 0.75rem; color: #fff; }}
  .finding-title {{ font-size: 1.15rem; font-weight: 600; color: #f1f5f9; }}
  .meta-row {{ font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.75rem; }}
  code {{ background: #0f172a; padding: 0.2rem 0.4rem; border-radius: 4px; color: #38bdf8; font-family: monospace; }}
  .desc {{ color: #cbd5e1; line-height: 1.5; }}
  .evidence {{ background: #0f172a; border-left: 3px solid #f97316; padding: 0.75rem; margin: 0.75rem 0; border-radius: 4px; }}
  .remediation {{ background: #0f172a; border-left: 3px solid #10b981; padding: 0.75rem; border-radius: 4px; color: #a7f3d0; }}
</style>
</head>
<body>
<div class="container">
  <h1>WireSniffer Security Audit Report</h1>
  <div class="date">Generated on {now_str}</div>

  <div class="stats-grid">
    <div class="stat-card"><div style="color: #ef4444;">CRITICAL</div><div class="stat-num">{sev_counts["CRITICAL"]}</div></div>
    <div class="stat-card"><div style="color: #f97316;">HIGH</div><div class="stat-num">{sev_counts["HIGH"]}</div></div>
    <div class="stat-card"><div style="color: #eab308;">MEDIUM</div><div class="stat-num">{sev_counts["MEDIUM"]}</div></div>
    <div class="stat-card"><div style="color: #3b82f6;">LOW</div><div class="stat-num">{sev_counts["LOW"]}</div></div>
  </div>

  <h2>Findings Breakdown ({len(all_findings)})</h2>
  {"".join(findings_html) if findings_html else '<p style="color: #10b981;">No security vulnerabilities detected.</p>'}
</div>
</body>
</html>"""
