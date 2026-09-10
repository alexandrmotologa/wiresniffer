"""Unit tests for BPF filter builder, JSONL exporter, hex formatter, and TuiState."""

import io

from wiresniffer.capture.bpf_filter import build_bpf_filter
from wiresniffer.capture.interface import find_default_interface, get_available_interfaces
from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.export.jsonl_exporter import write_transaction_jsonl
from wiresniffer.tui.hex_view import format_hex_dump
from wiresniffer.tui.state import TuiState


def test_build_bpf_filter():
    """Verify BPF filter generation for various port and host combinations."""
    assert build_bpf_filter(custom_filter="tcp and port 443") == "tcp and port 443"
    assert build_bpf_filter(ports=[80]) == "tcp and port 80"
    assert build_bpf_filter(ports=[80, 8080]) == "tcp and (port 80 or port 8080)"
    assert build_bpf_filter(ports=[80], hosts=["127.0.0.1"]) == "tcp and port 80 and host 127.0.0.1"


def test_jsonl_exporter():
    """Verify streaming JSONL writer."""
    tx = HttpTransaction(
        client_endpoint=("10.0.0.1", 1234),
        server_endpoint=("10.0.0.2", 80),
        method="GET",
        path="/status",
        response_status=200,
    )
    buf = io.StringIO()
    write_transaction_jsonl(tx, buf)
    line = buf.getvalue().strip()
    assert '"method": "GET"' in line
    assert '"path": "/status"' in line
    assert '"status": 200' in line


def test_format_hex_dump():
    """Verify hexadecimal and ASCII side-by-side dump formatting."""
    assert format_hex_dump(b"") == "<empty payload>"
    dump = format_hex_dump(b"Hello World 1234567890", max_bytes=10)
    assert "00000000" in dump
    assert "Hello" in dump
    assert "truncated" in dump


def test_tui_state_filtering_and_navigation():
    """Verify TuiState flow selection, filtering, and alert toggles."""
    state = TuiState()

    tx1 = HttpTransaction(
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        method="GET",
        path="/public",
        response_status=200,
    )
    tx2 = HttpTransaction(
        client_endpoint=("127.0.0.1", 1001),
        server_endpoint=("127.0.0.1", 80),
        method="POST",
        path="/admin",
        response_status=403,
        security_alerts=[{"rule_id": "TEST_ALERT"}],
    )

    state.add_transaction(tx1)
    state.add_transaction(tx2)

    assert len(state.get_filtered_transactions()) == 2

    # Filter query
    state.filter_query = "admin"
    filtered = state.get_filtered_transactions()
    assert len(filtered) == 1
    assert filtered[0].path == "/admin"

    # Alerts only
    state.filter_query = ""
    state.alerts_only = True
    alerts_filtered = state.get_filtered_transactions()
    assert len(alerts_filtered) == 1
    assert alerts_filtered[0].path == "/admin"

    # Selected transaction
    state.selected_index = 0
    selected = state.get_selected_transaction()
    assert selected is not None
    assert selected.path == "/admin"

    state.clear()
    assert len(state.transactions) == 0


def test_interfaces_discovery():
    """Verify get_available_interfaces and find_default_interface return valid items."""
    ifaces = get_available_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0

    default_iface = find_default_interface()
    assert default_iface is not None
