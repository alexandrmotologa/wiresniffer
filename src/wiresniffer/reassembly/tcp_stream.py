"""Bidirectional TCP connection state machine and stream tracking."""

import time
from enum import Enum
from typing import Callable, Optional, Tuple

from wiresniffer.reassembly.segment_buffer import TcpSegmentBuffer


class TcpState(str, Enum):
    NEW = "NEW"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"


class StreamDirection(str, Enum):
    CLIENT_TO_SERVER = "C2S"
    SERVER_TO_CLIENT = "S2C"


class TcpStream:
    """Tracks a bidirectional TCP connection 4-tuple and reassembles stream payloads."""

    def __init__(
        self,
        client_endpoint: Tuple[str, int],
        server_endpoint: Tuple[str, int],
        on_payload: Callable[[StreamDirection, bytes, float], None],
    ) -> None:
        self.client_endpoint = client_endpoint  # (client_ip, client_port)
        self.server_endpoint = server_endpoint  # (server_ip, server_port)
        self.on_payload = on_payload

        self.c2s_buffer = TcpSegmentBuffer()
        self.s2c_buffer = TcpSegmentBuffer()

        self.state = TcpState.NEW
        self.created_at = time.time()
        self.last_activity = time.time()
        self.total_client_bytes = 0
        self.total_server_bytes = 0

    @property
    def connection_id(self) -> str:
        return f"{self.client_endpoint[0]}:{self.client_endpoint[1]}->{self.server_endpoint[0]}:{self.server_endpoint[1]}"

    def process_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        seq: int,
        ack: int,
        flags: str,
        payload: bytes,
        timestamp: Optional[float] = None,
    ) -> None:
        """Process an incoming TCP segment, update state, and emit contiguous bytes."""
        now = timestamp if timestamp is not None else time.time()
        self.last_activity = now

        # Determine packet direction
        is_client = src_ip == self.client_endpoint[0] and src_port == self.client_endpoint[1]
        direction = (
            StreamDirection.CLIENT_TO_SERVER if is_client else StreamDirection.SERVER_TO_CLIENT
        )

        # State transitions
        if "S" in flags and "A" not in flags:
            # SYN from client
            self.state = TcpState.SYN_SENT
            self.c2s_buffer.set_initial_seq((seq + 1) & 0xFFFFFFFF)
            return

        if "S" in flags and "A" in flags:
            # SYN-ACK from server
            self.state = TcpState.SYN_RECEIVED
            self.s2c_buffer.set_initial_seq((seq + 1) & 0xFFFFFFFF)
            return

        if self.state in (TcpState.SYN_SENT, TcpState.SYN_RECEIVED) and "A" in flags:
            self.state = TcpState.ESTABLISHED

        # Connection termination flags
        if "F" in flags or "R" in flags:
            self.state = TcpState.CLOSING

        # Feed segment buffer if payload exists
        if payload:
            if is_client:
                self.total_client_bytes += len(payload)
                assembled = self.c2s_buffer.add_segment(seq, payload)
            else:
                self.total_server_bytes += len(payload)
                assembled = self.s2c_buffer.add_segment(seq, payload)

            if assembled:
                self.on_payload(direction, assembled, now)

        if "F" in flags or "R" in flags:
            # Flush any remaining buffer upon closure
            if is_client:
                remaining = self.c2s_buffer.force_flush()
            else:
                remaining = self.s2c_buffer.force_flush()

            if remaining:
                self.on_payload(direction, remaining, now)

            if "R" in flags:
                self.state = TcpState.CLOSED
