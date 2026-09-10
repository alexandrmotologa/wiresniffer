"""Unit tests for WebSocket frame decoding and payload unmasking."""

from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.decoders.websocket_decoder import WebSocketParser
from wiresniffer.reassembly.tcp_stream import StreamDirection


def test_websocket_client_masked_text_frame():
    """Verify unmasking of client-to-server text frames."""
    tx = HttpTransaction(
        protocol=ProtocolType.WEBSOCKET,
        client_endpoint=("127.0.0.1", 50000),
        server_endpoint=("127.0.0.1", 8080),
    )
    parser = WebSocketParser(transaction=tx)

    # Client frame: FIN=1, Opcode=1 (Text), Mask=1, Length=5 ("Hello")
    # Masking key = 0x12, 0x34, 0x56, 0x78
    raw_payload = b"Hello"
    mask_key = b"\x12\x34\x56\x78"
    masked_bytes = bytearray(5)
    for i in range(5):
        masked_bytes[i] = raw_payload[i] ^ mask_key[i % 4]

    frame_bytes = bytes([0x81, 0x85]) + mask_key + bytes(masked_bytes)

    messages = parser.feed(StreamDirection.CLIENT_TO_SERVER, frame_bytes, timestamp=10.0)
    assert len(messages) == 1
    msg = messages[0]
    assert msg.opcode == 1
    assert msg.opcode_name == "TEXT"
    assert msg.payload == b"Hello"
    assert msg.text_preview == "Hello"
    assert len(tx.websocket_messages) == 1


def test_websocket_server_unmasked_binary_frame():
    """Verify server-to-client unmasked binary frames."""
    tx = HttpTransaction(
        protocol=ProtocolType.WEBSOCKET,
        client_endpoint=("127.0.0.1", 50000),
        server_endpoint=("127.0.0.1", 8080),
    )
    parser = WebSocketParser(transaction=tx)

    # Server frame: FIN=1, Opcode=2 (Binary), Mask=0, Length=4
    frame_bytes = bytes([0x82, 0x04]) + b"\xca\xfe\xba\xbe"

    messages = parser.feed(StreamDirection.SERVER_TO_CLIENT, frame_bytes, timestamp=10.1)
    assert len(messages) == 1
    msg = messages[0]
    assert msg.opcode == 2
    assert msg.opcode_name == "BINARY"
    assert msg.payload == b"\xca\xfe\xba\xbe"
