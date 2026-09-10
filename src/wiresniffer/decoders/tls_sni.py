"""TLS ClientHello record parser and Server Name Indication (SNI) extractor."""

import struct
from typing import Optional


def extract_tls_sni(data: bytes) -> Optional[str]:
    """Parse a raw TLS Handshake record and extract the Server Name Indication (SNI).

    Args:
        data: Raw TCP byte payload from client.

    Returns:
        The target domain name string (e.g. "api.github.com"), or None.
    """
    if len(data) < 44:
        return None

    # Verify TLS Record Layer: ContentType 22 (Handshake)
    content_type = data[0]
    if content_type != 22:
        return None

    record_len = struct.unpack(">H", data[3:5])[0]
    if len(data) < 5 + min(record_len, 40):
        return None

    offset = 5  # Handshake header starts

    # Verify Handshake Type 1 (ClientHello)
    handshake_type = data[offset]
    if handshake_type != 1:
        return None

    offset += 4  # Skip handshake type (1) + length (3)
    offset += 2  # Skip client version
    offset += 32  # Skip 32-byte client random

    # Skip Session ID
    if offset >= len(data):
        return None
    session_id_len = data[offset]
    offset += 1 + session_id_len

    # Skip Cipher Suites
    if offset + 2 > len(data):
        return None
    cipher_suites_len = struct.unpack(">H", data[offset : offset + 2])[0]
    offset += 2 + cipher_suites_len

    # Skip Compression Methods
    if offset >= len(data):
        return None
    compression_len = data[offset]
    offset += 1 + compression_len

    # Parse Extensions
    if offset + 2 > len(data):
        return None
    extensions_len = struct.unpack(">H", data[offset : offset + 2])[0]
    offset += 2
    ext_end = min(len(data), offset + extensions_len)

    while offset + 4 <= ext_end:
        ext_type = struct.unpack(">H", data[offset : offset + 2])[0]
        ext_len = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
        offset += 4

        if offset + ext_len > ext_end:
            break

        if ext_type == 0x0000:  # server_name extension
            sni_data = data[offset : offset + ext_len]
            if len(sni_data) >= 5:
                # 2 bytes list len, 1 byte name type (0=host_name), 2 bytes name len
                name_type = sni_data[2]
                name_len = struct.unpack(">H", sni_data[3:5])[0]
                if name_type == 0 and len(sni_data) >= 5 + name_len:
                    try:
                        return sni_data[5 : 5 + name_len].decode("utf-8")
                    except Exception:
                        return None
            return None

        offset += ext_len

    return None
