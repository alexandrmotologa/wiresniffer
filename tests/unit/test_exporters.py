"""Unit tests for HAR 1.2 and cURL export generators."""

import json
import tempfile

from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.export.curl_generator import generate_curl_command
from wiresniffer.export.har_exporter import (
    export_transactions_to_har,
    transaction_to_har_entry,
)


def test_har_entry_serialization():
    """Verify transaction conversion into valid HAR 1.2 entry schema."""
    tx = HttpTransaction(
        flow_id="test1234",
        timestamp=1700000000.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 54321),
        server_endpoint=("127.0.0.1", 8080),
        method="POST",
        path="/v1/payment",
        query_params={"dry_run": "true"},
        request_headers={"Content-Type": "application/json", "Host": "api.shop.com"},
        request_body=b'{"amount": 99.99}',
        response_status=200,
        response_reason="OK",
        response_headers={"Content-Type": "application/json"},
        response_body=b'{"receipt": "xyz"}',
        latency_ms=45.2,
    )

    entry = transaction_to_har_entry(tx)
    assert entry["_flowId"] == "test1234"
    assert entry["time"] == 45.2
    assert entry["request"]["method"] == "POST"
    assert entry["request"]["url"] == "http://api.shop.com/v1/payment"
    assert entry["request"]["queryString"][0]["name"] == "dry_run"
    assert entry["request"]["postData"]["text"] == '{"amount": 99.99}'
    assert entry["response"]["status"] == 200
    assert entry["response"]["content"]["text"] == '{"receipt": "xyz"}'


def test_export_transactions_to_har_file():
    """Verify writing full HAR log file to disk."""
    tx = HttpTransaction(
        client_endpoint=("127.0.0.1", 54321),
        server_endpoint=("127.0.0.1", 8080),
        method="GET",
        path="/health",
        response_status=200,
    )

    with tempfile.NamedTemporaryFile(suffix=".har", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        export_transactions_to_har([tx], tmp_path)
        with open(tmp_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["log"]["version"] == "1.2"
        assert len(data["log"]["entries"]) == 1
    finally:
        import os

        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_curl_command_generation():
    """Verify cURL command syntax formatting."""
    tx = HttpTransaction(
        client_endpoint=("127.0.0.1", 54321),
        server_endpoint=("127.0.0.1", 8080),
        method="PUT",
        path="/items/123",
        request_headers={"Authorization": "Bearer test-token", "Host": "api.test.io"},
        request_body=b'{"active": true}',
    )
    curl_str = generate_curl_command(tx)
    assert curl_str.startswith("curl -X PUT")
    assert "http://api.test.io/items/123" in curl_str
    assert "Authorization: Bearer test-token" in curl_str
    assert '{"active": true}' in curl_str
