"""Hexadecimal and ASCII side-by-side formatter."""


def format_hex_dump(data: bytes, max_bytes: int = 4096) -> str:
    """Format a byte sequence into standard 16-byte hex + ASCII view.

    Example:
        00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
    """
    if not data:
        return "<empty payload>"

    truncated = False
    if len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True

    lines = []
    length = len(data)

    for i in range(0, length, 16):
        chunk = data[i : i + 16]
        offset_str = f"{i:08x}"

        hex_parts = []
        for j, b in enumerate(chunk):
            hex_parts.append(f"{b:02x}")
            if j == 7:
                hex_parts.append("")  # extra space between 8-byte halves

        # Pad remaining space if chunk < 16
        hex_str = " ".join(hex_parts).ljust(49)

        ascii_chars = []
        for b in chunk:
            if 32 <= b <= 126:
                ascii_chars.append(chr(b))
            else:
                ascii_chars.append(".")
        ascii_str = "".join(ascii_chars)

        lines.append(f"{offset_str}  {hex_str}  |{ascii_str}|")

    if truncated:
        lines.append(f"... [truncated, showing first {max_bytes} bytes] ...")

    return "\n".join(lines)
