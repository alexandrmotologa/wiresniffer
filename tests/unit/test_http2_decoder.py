"""Unit tests for HTTP/2 h2c frame parsing and HPACK decompression."""

import struct

import hpack

from wiresniffer.decoders.base import ProtocolType
from wiresniffer.decoders.http2_decoder import (
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FRAME_DATA,
    FRAME_HEADERS,
    H2_PREFACE,
    Http2StreamParser,
)
from wiresniffer.reassembly.tcp_stream import StreamDirection, TcpStream


def test_http2_stream_reconstruction():
    """Verify decoding of HTTP/2 headers and data frames into HttpTransaction."""
    emitted = []

    def on_tx(tx):
        emitted.append(tx)

    stream = TcpStream(
        client_endpoint=("127.0.0.1", 33000),
        server_endpoint=("127.0.0.1", 8080),
        on_payload=lambda d, p, ts: None,
    )
    parser = Http2StreamParser(stream=stream, on_transaction=on_tx)

    # 1. Send client preface
    parser.feed(StreamDirection.CLIENT_TO_SERVER, H2_PREFACE, timestamp=10.0)

    # 2. Client sends HEADERS frame on stream 1
    encoder = hpack.Encoder()
    req_headers = [
        (b":method", b"GET"),
        (b":path", b"/api/v2/items"),
        (b":scheme", b"http"),
        (b"accept", b"application/json"),
    ]
    encoded_req_headers = encoder.encode(req_headers)

    header_frame = (
        struct.pack(
            ">BHBBI",
            0,
            len(encoded_req_headers),
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
        )
        + encoded_req_headers
    )
    parser.feed(StreamDirection.CLIENT_TO_SERVER, header_frame, timestamp=10.01)

    assert 1 in parser.inflight_streams
    tx = parser.inflight_streams[1]
    assert tx.method == "GET"
    assert tx.path == "/api/v2/items"
    assert tx.request_headers["accept"] == "application/json"

    # 3. Server sends response HEADERS frame on stream 1
    server_encoder = hpack.Encoder()
    res_headers = [
        (b":status", b"200"),
        (b"content-type", b"application/json"),
    ]
    encoded_res_headers = server_encoder.encode(res_headers)
    res_header_frame = (
        struct.pack(">BHBBI", 0, len(encoded_res_headers), FRAME_HEADERS, FLAG_END_HEADERS, 1)
        + encoded_res_headers
    )
    parser.feed(StreamDirection.SERVER_TO_CLIENT, res_header_frame, timestamp=10.05)

    # 4. Server sends DATA frame with payload and END_STREAM
    body = b'{"items":["a","b"]}'
    res_data_frame = struct.pack(">BHBBI", 0, len(body), FRAME_DATA, FLAG_END_STREAM, 1) + body
    parser.feed(StreamDirection.SERVER_TO_CLIENT, res_data_frame, timestamp=10.06)

    assert len(emitted) == 1
    completed_tx = emitted[0]
    assert completed_tx.protocol == ProtocolType.HTTP2
    assert completed_tx.response_status == 200
    assert completed_tx.response_body == body
    assert completed_tx.latency_ms == 50.0
