"""WebSocket binary frame decoder with client payload unmasking."""

import struct
from typing import Callable, List, Optional

from wiresniffer.decoders.base import HttpTransaction, WebSocketMessage
from wiresniffer.reassembly.tcp_stream import StreamDirection

OPCODE_NAMES = {
    0x0: "CONTINUATION",
    0x1: "TEXT",
    0x2: "BINARY",
    0x8: "CLOSE",
    0x9: "PING",
    0xA: "PONG",
}


class WebSocketParser:
    """Decodes full-duplex RFC 6455 WebSocket frames."""

    def __init__(
        self,
        transaction: HttpTransaction,
        on_message: Optional[Callable[[WebSocketMessage], None]] = None,
    ) -> None:
        self.transaction = transaction
        self.on_message = on_message
        self.c2s_buffer = bytearray()
        self.s2c_buffer = bytearray()

    def feed(
        self, direction: StreamDirection, data: bytes, timestamp: float
    ) -> List[WebSocketMessage]:
        """Feed bytes into WebSocket frame parser and return any completed messages."""
        buffer = (
            self.c2s_buffer if direction == StreamDirection.CLIENT_TO_SERVER else self.s2c_buffer
        )
        buffer.extend(data)

        emitted: List[WebSocketMessage] = []

        while len(buffer) >= 2:
            byte0 = buffer[0]
            byte1 = buffer[1]

            _fin = (byte0 & 0x80) != 0
            opcode = byte0 & 0x0F
            is_masked = (byte1 & 0x80) != 0
            payload_len = byte1 & 0x7F

            offset = 2

            if payload_len == 126:
                if len(buffer) < offset + 2:
                    break
                payload_len = struct.unpack(">H", buffer[offset : offset + 2])[0]
                offset += 2
            elif payload_len == 127:
                if len(buffer) < offset + 8:
                    break
                payload_len = struct.unpack(">Q", buffer[offset : offset + 8])[0]
                offset += 8

            mask_key = b""
            if is_masked:
                if len(buffer) < offset + 4:
                    break
                mask_key = bytes(buffer[offset : offset + 4])
                offset += 4

            if len(buffer) < offset + payload_len:
                # Frame body not completely received yet
                break

            raw_payload = bytes(buffer[offset : offset + payload_len])
            buffer[: offset + payload_len] = b""

            # Unmask if needed
            if is_masked and mask_key:
                unmasked = bytearray(payload_len)
                for i in range(payload_len):
                    unmasked[i] = raw_payload[i] ^ mask_key[i % 4]
                final_payload = bytes(unmasked)
            else:
                final_payload = raw_payload

            msg = WebSocketMessage(
                direction=direction.value,
                opcode=opcode,
                opcode_name=OPCODE_NAMES.get(opcode, f"UNKNOWN(0x{opcode:X})"),
                payload=final_payload,
                timestamp=timestamp,
            )

            self.transaction.websocket_messages.append(msg)
            emitted.append(msg)
            if self.on_message:
                self.on_message(msg)

        return emitted
