"""TCP segment resequencer for out-of-order packet reassembly."""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class QueuedSegment:
    """Represents a buffered TCP segment awaiting contiguous sequencing."""

    seq: int
    payload: bytes

    @property
    def end_seq(self) -> int:
        return self.seq + len(self.payload)


class TcpSegmentBuffer:
    """Manages out-of-order TCP segments and delivers contiguous byte streams."""

    def __init__(self, max_buffer_bytes: int = 10 * 1024 * 1024) -> None:
        self.expected_seq: Optional[int] = None
        self.segments: List[QueuedSegment] = []
        self.max_buffer_bytes = max_buffer_bytes
        self.buffered_bytes = 0

    def set_initial_seq(self, seq: int) -> None:
        """Set the initial sequence number (e.g. after SYN handshake)."""
        if self.expected_seq is None:
            self.expected_seq = seq

    def add_segment(self, seq: int, payload: bytes) -> bytes:
        """Add a TCP segment and return any newly contiguous payload bytes.

        Args:
            seq: Sequence number of the incoming TCP segment.
            payload: Raw byte payload of the segment.

        Returns:
            Contiguous byte sequence ready for application protocol parsing.
        """
        if not payload:
            return b""

        # If sequence tracking has not started, initialize with the first seen segment
        if self.expected_seq is None:
            self.expected_seq = seq

        contiguous_data = bytearray()

        # Case 1: Segment arrives right on time
        if seq == self.expected_seq:
            contiguous_data.extend(payload)
            self.expected_seq = (self.expected_seq + len(payload)) & 0xFFFFFFFF
            contiguous_data.extend(self._drain_buffered_segments())
            return bytes(contiguous_data)

        # Case 2: Segment is an old duplicate or overlaps with already processed bytes
        # Calculate distance considering 32-bit sequence wrap-around
        diff = (self.expected_seq - seq) & 0xFFFFFFFF
        if diff < 0x7FFFFFFF and diff > 0:
            # Segment starts before expected_seq
            if len(payload) <= diff:
                # Completely redundant duplicate retransmission
                return b""
            # Partial overlap: trim the already processed prefix
            trimmed_payload = payload[diff:]
            contiguous_data.extend(trimmed_payload)
            self.expected_seq = (self.expected_seq + len(trimmed_payload)) & 0xFFFFFFFF
            contiguous_data.extend(self._drain_buffered_segments())
            return bytes(contiguous_data)

        # Case 3: Out-of-order future segment (seq > expected_seq)
        self._insert_segment(seq, payload)
        return b""

    def _insert_segment(self, seq: int, payload: bytes) -> None:
        """Insert out-of-order segment sorted by sequence number."""
        # Evict oldest segments if buffer exceeds threshold
        if self.buffered_bytes + len(payload) > self.max_buffer_bytes:
            if self.segments:
                dropped = self.segments.pop(0)
                self.buffered_bytes -= len(dropped.payload)

        new_segment = QueuedSegment(seq=seq, payload=payload)
        self.buffered_bytes += len(payload)

        # Binary or linear insertion
        for i, existing in enumerate(self.segments):
            if seq < existing.seq:
                self.segments.insert(i, new_segment)
                return
            if seq == existing.seq:
                # Redundant duplicate of an already buffered segment
                if len(payload) <= len(existing.payload):
                    self.buffered_bytes -= len(payload)
                    return
                # Replace with larger payload
                self.buffered_bytes -= len(existing.payload)
                self.segments[i] = new_segment
                return

        self.segments.append(new_segment)

    def _drain_buffered_segments(self) -> bytes:
        """Extract all consecutive segments that can now be assembled."""
        drained = bytearray()

        while self.segments and self.expected_seq is not None:
            first = self.segments[0]

            if first.seq == self.expected_seq:
                drained.extend(first.payload)
                self.expected_seq = (self.expected_seq + len(first.payload)) & 0xFFFFFFFF
                self.buffered_bytes -= len(first.payload)
                self.segments.pop(0)
            elif ((self.expected_seq - first.seq) & 0xFFFFFFFF) < 0x7FFFFFFF:
                # Segment overlaps with current expected_seq
                diff = (self.expected_seq - first.seq) & 0xFFFFFFFF
                if len(first.payload) > diff:
                    chunk = first.payload[diff:]
                    drained.extend(chunk)
                    self.expected_seq = (self.expected_seq + len(chunk)) & 0xFFFFFFFF
                self.buffered_bytes -= len(first.payload)
                self.segments.pop(0)
            else:
                # Gap in sequence; wait for missing packet
                break

        return bytes(drained)

    def force_flush(self) -> bytes:
        """Force flush all remaining segments in the buffer regardless of gaps."""
        flushed = bytearray()
        for seg in self.segments:
            flushed.extend(seg.payload)
        self.segments.clear()
        self.buffered_bytes = 0
        return bytes(flushed)
