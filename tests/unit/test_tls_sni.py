"""Unit tests for TLS ClientHello SNI domain extraction."""

import struct

from wiresniffer.decoders.tls_sni import extract_tls_sni


def test_extract_tls_sni():
    """Verify SNI domain extraction from a synthetic ClientHello record."""
    domain = "api.github.com"
    domain_bytes = domain.encode("utf-8")

    # Extension 0x0000 (server_name)
    # 2 bytes list len, 1 byte type (0), 2 bytes name len, domain bytes
    sni_ext_data = struct.pack(">HBH", len(domain_bytes) + 3, 0, len(domain_bytes)) + domain_bytes
    ext_block = struct.pack(">HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    extensions = struct.pack(">H", len(ext_block)) + ext_block

    # ClientHello body
    client_version = b"\x03\x03"
    random_bytes = b"\x00" * 32
    session_id = b"\x00"  # length 0
    cipher_suites = struct.pack(">H", 2) + b"\x13\x01"  # 1 cipher suite
    compression = b"\x01\x00"  # 1 compression method (null)

    ch_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions

    # Handshake Header: Type 1 (ClientHello), 3 bytes length
    hs_len = len(ch_body)
    hs_header = struct.pack(">B", 1) + bytes(
        [(hs_len >> 16) & 0xFF, (hs_len >> 8) & 0xFF, hs_len & 0xFF]
    )
    handshake_payload = hs_header + ch_body

    # TLS Record Header: ContentType 22, Version 0x0301, 2 bytes length
    record_header = struct.pack(">BHH", 22, 0x0301, len(handshake_payload))
    record_packet = record_header + handshake_payload

    extracted_sni = extract_tls_sni(record_packet)
    assert extracted_sni == "api.github.com"


def test_extract_tls_sni_non_tls():
    """Verify non-TLS payload returns None safely."""
    assert extract_tls_sni(b"GET / HTTP/1.1\r\n\r\n") is None
    assert extract_tls_sni(b"") is None
