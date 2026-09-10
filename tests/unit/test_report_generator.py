"""Unit tests for standalone HTML and Markdown security audit report generator."""

from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.export.report_generator import generate_html_report, generate_markdown_report


def test_reports_empty_findings():
    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        method="GET",
        path="/healthy",
        response_status=200,
    )

    md = generate_markdown_report([tx])
    assert "# WireSniffer Security Audit Report" in md
    assert "No security vulnerabilities" in md

    html = generate_html_report([tx])
    assert "<!DOCTYPE html>" in html
    assert "WireSniffer Security Audit Report" in html
    assert "No security vulnerabilities detected" in html


def test_reports_with_findings():
    alert = {
        "rule_id": "CREDENTIAL_LEAK_OPENAI",
        "severity": "CRITICAL",
        "title": "OpenAI API Secret Key Leaked in Request",
        "description": "Exposed OpenAI API key in HTTP request.",
        "evidence": "sk-proj-abc1234567890",
        "remediation": "Revoke and rotate API key.",
        "category": "Credential Leak",
    }
    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        method="POST",
        path="/v1/chat",
        security_alerts=[alert],
    )

    md = generate_markdown_report([tx])
    assert "CRITICAL" in md
    assert "API10:2023 Unsafe API Consumption" in md
    assert "CWE-798" in md
    assert "sk-proj-abc1234567890" in md

    html = generate_html_report([tx])
    assert "CRITICAL" in html
    assert "API10:2023 Unsafe API Consumption" in html
    assert "CWE-798" in html
    assert "sk-proj-abc1234567890" in html
    assert "Revoke and rotate API key" in html
