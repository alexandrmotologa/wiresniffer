"""Unit tests for TCP stream reassembly and out-of-order packet resequencing."""

from wiresniffer.reassembly.segment_buffer import TcpSegmentBuffer
from wiresniffer.reassembly.tcp_stream import StreamDirection, TcpStream


def test_in_order_segments():
    """Verify that contiguous segments are yielded immediately."""
    buffer = TcpSegmentBuffer()
    buffer.set_initial_seq(100)

    # Segment 1: seq 100, len 5
    res1 = buffer.add_segment(100, b"Hello")
    assert res1 == b"Hello"
    assert buffer.expected_seq == 105

    # Segment 2: seq 105, len 6
    res2 = buffer.add_segment(105, b" World")
    assert res2 == b" World"
    assert buffer.expected_seq == 111


def test_out_of_order_segments():
    """Verify that future segments are buffered until the missing segment arrives."""
    buffer = TcpSegmentBuffer()
    buffer.set_initial_seq(1000)

    # Arrive second half first: seq 1005, len 6
    res1 = buffer.add_segment(1005, b" World")
    assert res1 == b""  # Buffered, waiting for seq 1000

    # Arrive first half: seq 1000, len 5
    res2 = buffer.add_segment(1000, b"Hello")
    # Both parts should now be contiguous and returned
    assert res2 == b"Hello World"
    assert buffer.expected_seq == 1011


def test_duplicate_and_overlapping_segments():
    """Verify duplicate retransmissions and overlapping segments are handled."""
    buffer = TcpSegmentBuffer()
    buffer.set_initial_seq(100)

    res1 = buffer.add_segment(100, b"ABCDE")
    assert res1 == b"ABCDE"

    # Exact duplicate
    res_dup = buffer.add_segment(100, b"ABCDE")
    assert res_dup == b""

    # Partial overlap: seq 103, len 5 ("DEFGH") -> only "FGH" is new
    res_overlap = buffer.add_segment(103, b"DEFGH")
    assert res_overlap == b"FG" or res_overlap == b"FGH"
    assert buffer.expected_seq == 108


def test_bidirectional_tcp_stream():
    """Verify full TcpStream reassembly for client request and server response."""
    emitted = []

    def on_payload(direction: StreamDirection, data: bytes, ts: float):
        emitted.append((direction, data))

    stream = TcpStream(
        client_endpoint=("127.0.0.1", 54321),
        server_endpoint=("127.0.0.1", 8080),
        on_payload=on_payload,
    )

    # 3-Way Handshake
    # 1. Client SYN
    stream.process_packet(
        "127.0.0.1", 54321, "127.0.0.1", 8080, seq=1000, ack=0, flags="S", payload=b""
    )
    # 2. Server SYN-ACK
    stream.process_packet(
        "127.0.0.1", 8080, "127.0.0.1", 54321, seq=5000, ack=1001, flags="SA", payload=b""
    )
    # 3. Client ACK
    stream.process_packet(
        "127.0.0.1", 54321, "127.0.0.1", 8080, seq=1001, ack=5001, flags="A", payload=b""
    )

    # Client HTTP Request
    req_body = b"GET /api/v1/users HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"
    stream.process_packet(
        "127.0.0.1", 54321, "127.0.0.1", 8080, seq=1001, ack=5001, flags="PA", payload=req_body
    )

    # Server HTTP Response
    res_body = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    stream.process_packet(
        "127.0.0.1",
        8080,
        "127.0.0.1",
        54321,
        seq=5001,
        ack=1001 + len(req_body),
        flags="PA",
        payload=res_body,
    )

    assert len(emitted) == 2
    assert emitted[0] == (StreamDirection.CLIENT_TO_SERVER, req_body)
    assert emitted[1] == (StreamDirection.SERVER_TO_CLIENT, res_body)
