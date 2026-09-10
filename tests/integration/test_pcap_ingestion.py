"""Integration tests generating synthetic PCAP files and verifying end-to-end ingestion."""

import os
import tempfile

from scapy.all import IP, TCP, Ether, wrpcap

from wiresniffer.capture.pcap_reader import read_pcap_packets
from wiresniffer.cli import create_pipeline
from wiresniffer.export.har_exporter import export_transactions_to_har
from wiresniffer.security.engine import SecurityEngine
from wiresniffer.tui.state import TuiState


def test_synthetic_pcap_full_pipeline():
    """Build a synthetic TCP conversation into PCAP and verify end-to-end analysis."""
    client_ip = "192.168.1.50"
    server_ip = "192.168.1.100"
    client_port = 45678
    server_port = 80

    packets = []

    # 1. 3-Way Handshake
    syn = (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, seq=1000, ack=0, flags="S")
    )
    syn_ack = (
        Ether()
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, seq=2000, ack=1001, flags="SA")
    )
    ack = (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, seq=1001, ack=2001, flags="A")
    )
    packets.extend([syn, syn_ack, ack])

    # 2. HTTP Request containing Basic Auth
    req_body = b'{"prompt": "hello world"}'
    req_payload = (
        b"POST /v1/chat HTTP/1.1\r\n"
        b"Host: api.ai.internal\r\n"
        b"Authorization: Basic YWRtaW46c2VjcmV0MTIz\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(req_body)).encode("ascii") + b"\r\n\r\n" + req_body
    )
    req_pkt = (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, seq=1001, ack=2001, flags="PA")
        / req_payload
    )
    packets.append(req_pkt)

    # 3. HTTP Response containing a valid credit card PAN
    res_body = b'{"card": "4532015112830366", "status": "processed"}'
    res_payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(res_body)).encode("ascii") + b"\r\n\r\n" + res_body
    )
    res_pkt = (
        Ether()
        / IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=server_port, dport=client_port, seq=2001, ack=1001 + len(req_payload), flags="PA"
        )
        / res_payload
    )
    packets.append(res_pkt)

    # 4. Connection Termination
    fin = (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=client_port,
            dport=server_port,
            seq=1001 + len(req_payload),
            ack=2001 + len(res_payload),
            flags="FA",
        )
    )
    packets.append(fin)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_pcap = tmp.name

    try:
        wrpcap(tmp_pcap, packets)

        state = TuiState()
        sec_engine = SecurityEngine()
        tracker = create_pipeline(state, sec_engine)

        read_count = 0
        for pkt in read_pcap_packets(tmp_pcap):
            tracker.process_packet(pkt)
            read_count += 1

        assert read_count == len(packets)
        assert len(state.transactions) == 1

        tx = state.transactions[0]
        assert tx.method == "POST"
        assert tx.path == "/v1/chat"
        assert tx.response_status == 200
        assert tx.host == "api.ai.internal"

        # Verify security alerts were triggered
        rule_ids = [a["rule_id"] for a in tx.security_alerts]
        assert "PLAINTEXT_BASIC_AUTH" in rule_ids
        assert "PII_CREDIT_CARD" in rule_ids

        # Test HAR Export
        with tempfile.NamedTemporaryFile(suffix=".har", delete=False) as tmp_har:
            har_path = tmp_har.name
        try:
            export_transactions_to_har(state.transactions, har_path)
            assert os.path.exists(har_path)
            assert os.path.getsize(har_path) > 100
        finally:
            if os.path.exists(har_path):
                os.remove(har_path)

    finally:
        if os.path.exists(tmp_pcap):
            os.remove(tmp_pcap)
