"""HTTP/2 cleartext (h2c) frame decoder and HPACK stream rebuilder."""

import struct
from typing import Callable, Dict

import hpack

from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.reassembly.tcp_stream import StreamDirection, TcpStream

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame types
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20


class Http2StreamParser:
    """Parses binary HTTP/2 h2c frame streams and reconstructs multiplexed flows."""

    def __init__(
        self,
        stream: TcpStream,
        on_transaction: Callable[[HttpTransaction], None],
    ) -> None:
        self.stream = stream
        self.on_transaction = on_transaction

        self.c2s_buffer = bytearray()
        self.s2c_buffer = bytearray()

        self.c2s_hpack = hpack.Decoder()
        self.s2c_hpack = hpack.Decoder()

        # In-flight streams keyed by stream_id
        self.inflight_streams: Dict[int, HttpTransaction] = {}
        self.client_preface_received = False

    def feed(self, direction: StreamDirection, data: bytes, timestamp: float) -> None:
        """Feed HTTP/2 frame bytes from client or server."""
        if direction == StreamDirection.CLIENT_TO_SERVER:
            self.c2s_buffer.extend(data)
            if not self.client_preface_received and len(self.c2s_buffer) >= len(H2_PREFACE):
                if self.c2s_buffer.startswith(H2_PREFACE):
                    self.c2s_buffer = self.c2s_buffer[len(H2_PREFACE) :]
                    self.client_preface_received = True
            self._parse_frames(direction, self.c2s_buffer, self.c2s_hpack, timestamp)
        else:
            self.s2c_buffer.extend(data)
            self._parse_frames(direction, self.s2c_buffer, self.s2c_hpack, timestamp)

    def _parse_frames(
        self,
        direction: StreamDirection,
        buffer: bytearray,
        hpack_dec: hpack.Decoder,
        timestamp: float,
    ) -> None:
        """Parse 9-byte frame headers and frame payloads from buffer."""
        while len(buffer) >= 9:
            # 24-bit length, 8-bit type, 8-bit flags, 31-bit stream ID
            length_high, length_low, frame_type, flags, stream_id_raw = struct.unpack(
                ">BHBBI", buffer[:9]
            )
            frame_len = (length_high << 16) | length_low
            stream_id = stream_id_raw & 0x7FFFFFFF

            total_frame_len = 9 + frame_len
            if len(buffer) < total_frame_len:
                # Incomplete frame, wait for more bytes
                return

            frame_payload = bytes(buffer[9:total_frame_len])
            buffer[:total_frame_len] = b""

            self._handle_frame(
                direction=direction,
                stream_id=stream_id,
                frame_type=frame_type,
                flags=flags,
                payload=frame_payload,
                hpack_dec=hpack_dec,
                timestamp=timestamp,
            )

    def _handle_frame(
        self,
        direction: StreamDirection,
        stream_id: int,
        frame_type: int,
        flags: int,
        payload: bytes,
        hpack_dec: hpack.Decoder,
        timestamp: float,
    ) -> None:
        if stream_id == 0:
            # Control frame (SETTINGS, PING, WINDOW_UPDATE)
            return

        tx = self.inflight_streams.get(stream_id)
        if tx is None and direction == StreamDirection.CLIENT_TO_SERVER:
            tx = HttpTransaction(
                timestamp=timestamp,
                protocol=ProtocolType.HTTP2,
                client_endpoint=self.stream.client_endpoint,
                server_endpoint=self.stream.server_endpoint,
            )
            self.inflight_streams[stream_id] = tx

        if tx is None:
            return

        if frame_type == FRAME_HEADERS:
            raw_headers = payload
            # Handle padding / priority if flags present
            offset = 0
            if flags & FLAG_PADDED and len(raw_headers) > 0:
                pad_len = raw_headers[0]
                offset += 1
                raw_headers = raw_headers[offset : len(raw_headers) - pad_len]
            if flags & FLAG_PRIORITY and len(raw_headers) >= 5:
                raw_headers = raw_headers[5:]

            try:
                decoded_headers = hpack_dec.decode(raw_headers)
                headers_dict: Dict[str, str] = {}
                for k_raw, v_raw in decoded_headers:
                    k = (
                        k_raw.decode("utf-8", errors="replace")
                        if isinstance(k_raw, (bytes, bytearray))
                        else str(k_raw)
                    )
                    v = (
                        v_raw.decode("utf-8", errors="replace")
                        if isinstance(v_raw, (bytes, bytearray))
                        else str(v_raw)
                    )
                    if k == ":method":
                        tx.method = v
                    elif k == ":path":
                        tx.path = v
                    elif k == ":status":
                        try:
                            tx.response_status = int(v)
                        except ValueError:
                            pass
                    else:
                        headers_dict[k] = v

                if direction == StreamDirection.CLIENT_TO_SERVER:
                    tx.request_headers.update(headers_dict)
                    # Check for gRPC
                    if headers_dict.get("content-type", "").startswith("application/grpc"):
                        tx.protocol = ProtocolType.GRPC
                else:
                    tx.response_headers.update(headers_dict)
            except Exception:
                pass

        elif frame_type == FRAME_DATA:
            data_bytes = payload
            if flags & FLAG_PADDED and len(data_bytes) > 0:
                pad_len = data_bytes[0]
                data_bytes = data_bytes[1 : len(data_bytes) - pad_len]

            if direction == StreamDirection.CLIENT_TO_SERVER:
                tx.request_body += data_bytes
            else:
                tx.response_body += data_bytes

        # Check end of stream
        if flags & FLAG_END_STREAM:
            if direction == StreamDirection.SERVER_TO_CLIENT:
                tx.completed_at = timestamp
                tx.latency_ms = max(0.0, round((timestamp - tx.timestamp) * 1000.0, 2))
                self.on_transaction(tx)
                self.inflight_streams.pop(stream_id, None)
