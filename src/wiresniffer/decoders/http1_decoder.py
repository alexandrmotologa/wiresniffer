"""HTTP/1.1 protocol decoder supporting chunked transfers and compression."""

import gzip
import urllib.parse
import zlib
from typing import Callable, Dict, List, Optional, Tuple

from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.reassembly.tcp_stream import StreamDirection, TcpStream


def decompress_body(data: bytes, encoding: Optional[str]) -> bytes:
    """Decompress gzip or deflate HTTP payloads if applicable."""
    if not data or not encoding:
        return data

    enc = encoding.strip().lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(data)
        elif "deflate" in enc:
            try:
                return zlib.decompress(data)
            except zlib.error:
                # Raw deflate without zlib header
                return zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        return data

    return data


def decode_chunked_body(raw_data: bytes) -> Tuple[bytes, bool]:
    """Decode a chunked transfer encoding byte stream.

    Returns:
        (un線上chunked_bytes, is_complete)
    """
    decoded = bytearray()
    idx = 0
    length = len(raw_data)

    while idx < length:
        crlf_pos = raw_data.find(b"\r\n", idx)
        if crlf_pos == -1:
            return bytes(decoded), False

        chunk_header = raw_data[idx:crlf_pos].strip()
        # Header may contain chunk extensions (e.g. "1a;ext=val")
        chunk_size_str = chunk_header.split(b";")[0].strip()
        try:
            chunk_size = int(chunk_size_str, 16)
        except ValueError:
            return bytes(decoded), False

        if chunk_size == 0:
            # Reached terminal chunk (0\r\n\r\n)
            return bytes(decoded), True

        chunk_data_start = crlf_pos + 2
        chunk_data_end = chunk_data_start + chunk_size

        if chunk_data_end > length:
            # Need more data for full chunk
            return bytes(decoded), False

        decoded.extend(raw_data[chunk_data_start:chunk_data_end])
        idx = chunk_data_end + 2  # Skip trailing \r\n

    return bytes(decoded), False


class Http1StreamParser:
    """Stateful HTTP/1.1 connection parser tracking pipelined request/response pairs."""

    def __init__(
        self,
        stream: TcpStream,
        on_transaction: Callable[[HttpTransaction], None],
    ) -> None:
        self.stream = stream
        self.on_transaction = on_transaction

        self.c2s_buffer = bytearray()
        self.s2c_buffer = bytearray()

        self.pending_requests: List[HttpTransaction] = []

    def feed(self, direction: StreamDirection, data: bytes, timestamp: float) -> None:
        """Feed contiguous bytes for client or server direction."""
        if direction == StreamDirection.CLIENT_TO_SERVER:
            self.c2s_buffer.extend(data)
            self._parse_requests(timestamp)
        else:
            self.s2c_buffer.extend(data)
            self._parse_responses(timestamp)

    def _parse_requests(self, timestamp: float) -> None:
        """Parse one or more HTTP requests from client buffer."""
        while self.c2s_buffer:
            header_end = self.c2s_buffer.find(b"\r\n\r\n")
            if header_end == -1:
                return

            header_bytes = bytes(self.c2s_buffer[:header_end])
            try:
                header_text = header_bytes.decode("iso-8859-1")
            except Exception:
                header_text = header_bytes.decode("utf-8", errors="replace")

            lines = header_text.split("\r\n")
            if not lines or not lines[0]:
                self.c2s_buffer = self.c2s_buffer[header_end + 4 :]
                continue

            # Parse Request Line (e.g. "GET /api/v1/resource?id=123 HTTP/1.1")
            request_line_parts = lines[0].split(" ")
            if len(request_line_parts) < 2:
                # Malformed request line, discard
                self.c2s_buffer = self.c2s_buffer[header_end + 4 :]
                continue

            method = request_line_parts[0].upper()
            full_path = request_line_parts[1]

            # Parse headers
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()

            # Parse path and query parameters
            parsed_url = urllib.parse.urlsplit(full_path)
            path = parsed_url.path or "/"
            query_params = {
                k: v[0] if len(v) == 1 else ",".join(v)
                for k, v in urllib.parse.parse_qs(parsed_url.query).items()
            }

            # Check body length
            content_length = 0
            if "Content-Length" in headers:
                try:
                    content_length = int(headers["Content-Length"])
                except ValueError:
                    content_length = 0

            body_start = header_end + 4
            body_end = body_start + content_length

            if len(self.c2s_buffer) < body_end:
                # Awaiting more body bytes
                return

            raw_body = bytes(self.c2s_buffer[body_start:body_end])
            self.c2s_buffer = self.c2s_buffer[body_end:]

            tx = HttpTransaction(
                timestamp=timestamp,
                protocol=ProtocolType.HTTP1,
                client_endpoint=self.stream.client_endpoint,
                server_endpoint=self.stream.server_endpoint,
                method=method,
                path=path,
                query_params=query_params,
                request_headers=headers,
                request_body=raw_body,
            )
            self.pending_requests.append(tx)

    def _parse_responses(self, timestamp: float) -> None:
        """Parse one or more HTTP responses and pair with pending requests."""
        while self.s2c_buffer:
            header_end = self.s2c_buffer.find(b"\r\n\r\n")
            if header_end == -1:
                return

            header_bytes = bytes(self.s2c_buffer[:header_end])
            try:
                header_text = header_bytes.decode("iso-8859-1")
            except Exception:
                header_text = header_bytes.decode("utf-8", errors="replace")

            lines = header_text.split("\r\n")
            if not lines or not lines[0].startswith("HTTP/"):
                # Not HTTP response header, advance
                self.s2c_buffer = self.s2c_buffer[header_end + 4 :]
                continue

            # Parse Status Line (e.g. "HTTP/1.1 200 OK")
            status_parts = lines[0].split(" ", 2)
            status_code = 200
            reason = "OK"
            if len(status_parts) >= 2:
                try:
                    status_code = int(status_parts[1])
                except ValueError:
                    pass
            if len(status_parts) >= 3:
                reason = status_parts[2]

            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()

            body_start = header_end + 4
            is_chunked = headers.get("Transfer-Encoding", "").lower() == "chunked"
            content_length = None
            if "Content-Length" in headers:
                try:
                    content_length = int(headers["Content-Length"])
                except ValueError:
                    content_length = None

            raw_body = b""
            consumed_len = 0

            if is_chunked:
                chunked_data = bytes(self.s2c_buffer[body_start:])
                decoded, is_complete = decode_chunked_body(chunked_data)
                if not is_complete:
                    # Wait for all chunks
                    return
                raw_body = decoded
                # Find terminal chunk in buffer to slice cleanly
                term_pos = self.s2c_buffer.find(b"0\r\n\r\n", body_start)
                if term_pos != -1:
                    consumed_len = (term_pos + 5) - body_start
                else:
                    consumed_len = len(self.s2c_buffer) - body_start
            elif content_length is not None:
                if len(self.s2c_buffer) < body_start + content_length:
                    return
                raw_body = bytes(self.s2c_buffer[body_start : body_start + content_length])
                consumed_len = content_length
            else:
                # 304 Not Modified, 204 No Content, or HEAD response
                raw_body = b""
                consumed_len = 0

            self.s2c_buffer = self.s2c_buffer[body_start + consumed_len :]

            # Decompress body if needed
            content_encoding = headers.get("Content-Encoding")
            decompressed = decompress_body(raw_body, content_encoding)

            # Match with oldest pending request
            if self.pending_requests:
                tx = self.pending_requests.pop(0)
            else:
                # Orphaned response (captured after request was sent)
                tx = HttpTransaction(
                    timestamp=timestamp,
                    protocol=ProtocolType.HTTP1,
                    client_endpoint=self.stream.client_endpoint,
                    server_endpoint=self.stream.server_endpoint,
                    method="UNKNOWN",
                    path="/",
                )

            tx.response_status = status_code
            tx.response_reason = reason
            tx.response_headers = headers
            tx.response_body = decompressed
            tx.completed_at = timestamp
            tx.latency_ms = max(0.0, round((timestamp - tx.timestamp) * 1000.0, 2))

            # Detect WebSocket Upgrade
            if headers.get("Upgrade", "").lower() == "websocket" and status_code == 101:
                tx.protocol = ProtocolType.WEBSOCKET

            self.on_transaction(tx)
