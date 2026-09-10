"""Unit tests for HTTP/1.1 request/response decoding, chunked transfers, and gzip."""

import gzip

from wiresniffer.decoders.http1_decoder import (
    Http1StreamParser,
    decode_chunked_body,
    decompress_body,
)
from wiresniffer.reassembly.tcp_stream import StreamDirection, TcpStream


def test_decode_chunked_body():
    """Verify decoding of HTTP chunked transfer encoding."""
    raw_chunked = b"4\r\nWiki\r\n6\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n"
    decoded, is_complete = decode_chunked_body(raw_chunked)
    assert is_complete is True
    assert decoded == b"Wikipedia in \r\n\r\nchunks."


def test_decompress_gzip():
    """Verify automatic decompression of gzip compressed response payloads."""
    original = b'{"status": "ok", "message": "hello world"}'
    compressed = gzip.compress(original)
    decompressed = decompress_body(compressed, "gzip")
    assert decompressed == original


def test_http1_stream_parser_flow():
    """Verify complete request and response pairing with latency calculation."""
    emitted = []

    def on_transaction(tx):
        emitted.append(tx)

    stream = TcpStream(
        client_endpoint=("127.0.0.1", 42000),
        server_endpoint=("127.0.0.1", 8080),
        on_payload=lambda d, p, ts: None,
    )
    parser = Http1StreamParser(stream=stream, on_transaction=on_transaction)

    # Client Request
    req = (
        b"POST /api/v1/orders?priority=high HTTP/1.1\r\n"
        b"Host: api.example.com\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 16\r\n\r\n"
        b'{"order_id": 42}'
    )
    parser.feed(StreamDirection.CLIENT_TO_SERVER, req, timestamp=100.0)

    assert len(parser.pending_requests) == 1
    pending = parser.pending_requests[0]
    assert pending.method == "POST"
    assert pending.path == "/api/v1/orders"
    assert pending.query_params == {"priority": "high"}
    assert pending.request_headers["Content-Type"] == "application/json"
    assert pending.request_body == b'{"order_id": 42}'

    # Server Response
    res = (
        b"HTTP/1.1 201 Created\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 15\r\n\r\n"
        b'{"status":"ok"}'
    )
    parser.feed(StreamDirection.SERVER_TO_CLIENT, res, timestamp=100.05)

    assert len(emitted) == 1
    tx = emitted[0]
    assert tx.response_status == 201
    assert tx.response_reason == "Created"
    assert tx.response_body == b'{"status":"ok"}'
    assert tx.latency_ms == 50.0
    assert tx.host == "api.example.com"
    assert tx.to_curl().startswith("curl -X POST")
