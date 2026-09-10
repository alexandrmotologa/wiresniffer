"""gRPC length-delimited message unwrapper and pure Protobuf wire-format parser."""

import struct
from typing import Any, Dict, List, Tuple


def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a protobuf varint from byte array at offset.

    Returns:
        (value, new_offset)
    """
    res = 0
    shift = 0
    idx = offset
    length = len(data)

    while idx < length:
        byte = data[idx]
        idx += 1
        res |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return res, idx
        shift += 7
        if shift >= 64:
            break

    return res, idx


def parse_protobuf_wire(data: bytes, max_depth: int = 3) -> Dict[str, Any]:
    """Parse raw protobuf wire bytes into a nested dictionary without .proto schemas."""
    fields: Dict[str, Any] = {}
    offset = 0
    length = len(data)

    while offset < length:
        tag_varint, offset = read_varint(data, offset)
        if offset > length:
            break

        field_num = tag_varint >> 3
        wire_type = tag_varint & 0x07

        key = str(field_num)

        if wire_type == 0:  # Varint
            val, offset = read_varint(data, offset)
            fields[key] = val
        elif wire_type == 1:  # 64-bit
            if offset + 8 > length:
                break
            val = struct.unpack("<Q", data[offset : offset + 8])[0]
            offset += 8
            fields[key] = val
        elif wire_type == 2:  # Length-delimited
            length_val, offset = read_varint(data, offset)
            if offset + length_val > length:
                break
            val_bytes = data[offset : offset + length_val]
            offset += length_val

            # Attempt to parse as UTF-8 string or recursive message
            try:
                text = val_bytes.decode("utf-8")
                # Check if it looks like plain text
                if all(c.isprintable() or c in "\r\n\t" for c in text):
                    fields[key] = text
                    continue
            except Exception:
                pass

            if max_depth > 0:
                try:
                    nested = parse_protobuf_wire(val_bytes, max_depth - 1)
                    if nested:
                        fields[key] = nested
                        continue
                except Exception:
                    pass

            # Fallback to hex preview
            fields[key] = f"<binary {len(val_bytes)} bytes: {val_bytes[:16].hex()}...>"

        elif wire_type == 5:  # 32-bit
            if offset + 4 > length:
                break
            val = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4
            fields[key] = val
        else:
            # Unknown wire type, cannot parse rest accurately
            break

    return fields


def unwrap_grpc_frames(payload: bytes) -> List[Tuple[bool, bytes, Dict[str, Any]]]:
    """Unwrap 5-byte length-delimited gRPC message envelopes.

    Returns:
        List of (is_compressed, raw_message_bytes, parsed_protobuf_dict).
    """
    messages: List[Tuple[bool, bytes, Dict[str, Any]]] = []
    idx = 0
    total_len = len(payload)

    while idx + 5 <= total_len:
        compressed_flag = payload[idx] != 0
        msg_len = struct.unpack(">I", payload[idx + 1 : idx + 5])[0]
        idx += 5

        if idx + msg_len > total_len:
            break

        msg_bytes = payload[idx : idx + msg_len]
        idx += msg_len

        parsed = {}
        if not compressed_flag:
            parsed = parse_protobuf_wire(msg_bytes)

        messages.append((compressed_flag, msg_bytes, parsed))

    return messages
