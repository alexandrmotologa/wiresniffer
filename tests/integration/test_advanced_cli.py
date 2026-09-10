"""Integration tests for advanced CLI commands (metrics, report, replay)."""

import os
import tempfile
from unittest.mock import MagicMock, patch

from scapy.all import IP, TCP, Ether, wrpcap
from typer.testing import CliRunner

from wiresniffer.cli import app

runner = CliRunner(env={"COLUMNS": "160"})


def _create_sample_pcap() -> str:
    """Create a temporary PCAP file containing an HTTP request and response."""
    client_ip = "192.168.1.50"
    server_ip = "192.168.1.100"

    req_body = b'{"query": "{ __schema { types { name } } }"}'
    req_payload = (
        b"POST /graphql HTTP/1.1\r\n"
        b"Host: api.local\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(req_body)).encode("ascii") + b"\r\n\r\n" + req_body
    )
    req_pkt = (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=54321, dport=80, seq=1000, ack=2000, flags="PA")
        / req_payload
    )

    res_body = b'{"data": {"__schema": {"types": [{"name": "Query"}]}}}'
    res_payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(res_body)).encode("ascii") + b"\r\n\r\n" + res_body
    )
    res_pkt = (
        Ether()
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=80, dport=54321, seq=2000, ack=1000 + len(req_payload), flags="PA")
        / res_payload
    )

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        pcap_path = tmp.name

    wrpcap(pcap_path, [req_pkt, res_pkt])
    return pcap_path


def test_cli_metrics_command():
    pcap_path = _create_sample_pcap()
    try:
        res = runner.invoke(app, ["metrics", pcap_path])
        assert res.exit_code == 0
        assert "Traffic Analytics" in res.stdout
        assert "Total Requests" in res.stdout
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


def test_cli_report_markdown_and_html():
    pcap_path = _create_sample_pcap()
    with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as tmp_md:
        md_path = tmp_md.name
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp_html:
        html_path = tmp_html.name

    try:
        # Markdown report
        res_md = runner.invoke(app, ["report", pcap_path, "--output", md_path, "--format", "md"])
        assert res_md.exit_code == 0
        assert os.path.exists(md_path)
        with open(md_path, "r", encoding="utf-8") as f:
            content_md = f.read()
            assert "WireSniffer Security Audit Report" in content_md
            assert "GRAPHQL_INTROSPECTION_ENABLED" in content_md

        # HTML report
        res_html = runner.invoke(
            app, ["report", pcap_path, "--output", html_path, "--format", "html"]
        )
        assert res_html.exit_code == 0
        assert os.path.exists(html_path)
        with open(html_path, "r", encoding="utf-8") as f:
            content_html = f.read()
            assert "<!DOCTYPE html>" in content_html
            assert "WireSniffer Security Audit Report" in content_html

    finally:
        for p in (pcap_path, md_path, html_path):
            if os.path.exists(p):
                os.remove(p)


@patch("urllib.request.urlopen")
def test_cli_replay_command(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.reason = "OK"
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.read.return_value = b'{"data": {"__schema": {"types": [{"name": "Query"}]}}}'
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    pcap_path = _create_sample_pcap()
    try:
        res = runner.invoke(app, ["replay", pcap_path, "--flow", "0"])
        assert res.exit_code == 0
        assert "Replaying flow #0" in res.stdout
        assert "identical" in res.stdout.lower() or "Status Code" in res.stdout
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
