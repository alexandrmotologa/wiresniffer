"""Unit tests for gRPC message unboxing and protobuf wire-format parsing."""

import struct

from wiresniffer.decoders.grpc_decoder import (
    parse_protobuf_wire,
    unwrap_grpc_frames,
)


def test_parse_protobuf_wire():
    """Verify decoding of protobuf varints and length-delimited strings."""
    # Field 1 (tag: 1 << 3 | 0 = 0x08): varint 150 (0x96, 0x01)
    # Field 2 (tag: 2 << 3 | 2 = 0x12): string len 7 "testing"
    wire_data = bytes([0x08, 0x96, 0x01]) + bytes([0x12, 0x07]) + b"testing"

    parsed = parse_protobuf_wire(wire_data)
    assert parsed["1"] == 150
    assert parsed["2"] == "testing"


def test_unwrap_grpc_frames():
    """Verify 5-byte length-delimited gRPC envelope extraction."""
    body = bytes([0x08, 0x2A])  # Field 1 = 42
    # 1 byte compressed flag (0) + 4 bytes length
    envelope = struct.pack(">BI", 0, len(body)) + body

    frames = unwrap_grpc_frames(envelope)
    assert len(frames) == 1
    is_compressed, raw_bytes, parsed_dict = frames[0]
    assert is_compressed is False
    assert raw_bytes == body
    assert parsed_dict["1"] == 42
