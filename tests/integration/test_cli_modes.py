"""Integration tests for WireSniffer CLI commands and audit scanner."""

import os
import tempfile

from scapy.all import IP, TCP, Ether, wrpcap
from typer.testing import CliRunner

from wiresniffer.cli import app

runner = CliRunner(env={"COLUMNS": "160"})


def test_cli_help():
    """Verify wiresniffer --help exits with code 0."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Developer-first API traffic and security sniffer" in result.stdout


def test_cli_interfaces():
    """Verify wiresniffer interfaces lists available network adapters."""
    result = runner.invoke(app, ["interfaces"])
    assert result.exit_code == 0
    assert "Available Network Interfaces" in result.stdout


def test_cli_inspect_and_scan():
    """Verify inspect and scan commands against a synthetic PCAP."""
    # Build synthetic packet with a leaked secret
    client_ip = "10.0.0.1"
    server_ip = "10.0.0.2"

    req_body = b'{"token": "ghp_123456789012345678901234567890123456"}'
    req_payload = (
        b"POST /api/deploy HTTP/1.1\r\n"
        b"Host: internal.corp\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(req_body)).encode("ascii") + b"\r\n\r\n" + req_body
    )
    req_pkt = (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=50000, dport=80, seq=1000, ack=2000, flags="PA")
        / req_payload
    )

    res_body = b'{"status": "deployed"}'
    res_payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(res_body)).encode("ascii") + b"\r\n\r\n" + res_body
    )
    res_pkt = (
        Ether()
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=80, dport=50000, seq=2000, ack=1000 + len(req_payload), flags="PA")
        / res_payload
    )

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        pcap_path = tmp.name

    try:
        wrpcap(pcap_path, [req_pkt, res_pkt])

        # Test inspect --no-tui
        inspect_res = runner.invoke(app, ["inspect", pcap_path, "--no-tui"])
        assert inspect_res.exit_code == 0
        assert "Captured Flows" in inspect_res.stdout

        # Test scan mode with fail-on critical
        scan_res = runner.invoke(app, ["scan", pcap_path, "--fail-on", "critical"])
        assert scan_res.exit_code == 1
        assert "Security Violations Detected" in scan_res.stdout
        assert (
            "CREDENTIAL_LEAK_GITHUB" in scan_res.stdout
            or "GitHub Personal Access Token" in scan_res.stdout
        )

    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
