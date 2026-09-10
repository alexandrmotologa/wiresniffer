"""Flow tracker managing concurrent TCP streams and protocol dispatch."""

import time
from typing import Callable, Dict, Optional, Tuple

from scapy.all import IP, TCP, IPv6, Packet

from wiresniffer.reassembly.tcp_stream import StreamDirection, TcpState, TcpStream


def normalize_flow_key(
    ep1: Tuple[str, int], ep2: Tuple[str, int]
) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    """Create a symmetric 4-tuple key regardless of packet direction."""
    return (ep1, ep2) if ep1 <= ep2 else (ep2, ep1)


class FlowTracker:
    """Manages active TCP connections and dispatches contiguous payloads."""

    def __init__(
        self,
        on_stream_payload: Callable[[TcpStream, StreamDirection, bytes, float], None],
        stream_timeout: float = 30.0,
    ) -> None:
        self.on_stream_payload = on_stream_payload
        self.stream_timeout = stream_timeout
        self.active_streams: Dict[Tuple[Tuple[str, int], Tuple[str, int]], TcpStream] = {}
        self.total_streams_created = 0

    def process_packet(self, packet: Packet) -> Optional[TcpStream]:
        """Process an incoming Scapy packet and route TCP segment to its stream.

        Returns:
            The associated TcpStream, or None if packet is not TCP.
        """
        if not packet.haslayer(TCP):
            return None

        # Extract IP addresses
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return None

        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        seq = tcp.seq
        ack = tcp.ack
        flags = str(tcp.flags)
        payload = bytes(tcp.payload)
        pkt_time = float(packet.time) if hasattr(packet, "time") else time.time()

        src_endpoint = (src_ip, src_port)
        dst_endpoint = (dst_ip, dst_port)
        flow_key = normalize_flow_key(src_endpoint, dst_endpoint)

        stream = self.active_streams.get(flow_key)

        if stream is None:
            # Create a new stream
            # Determine client vs server: SYN initiator is client
            if "S" in flags and "A" not in flags:
                client_ep = src_endpoint
                server_ep = dst_endpoint
            else:
                # Heuristic: well-known server port (< 10000 or common ports)
                common_ports = {80, 443, 3000, 5000, 8000, 8080, 8443, 50051}
                if dst_port in common_ports or dst_port < src_port:
                    client_ep = src_endpoint
                    server_ep = dst_endpoint
                else:
                    client_ep = dst_endpoint
                    server_ep = src_endpoint

            def _payload_bridge(direction: StreamDirection, data: bytes, ts: float) -> None:
                if stream:
                    self.on_stream_payload(stream, direction, data, ts)

            stream = TcpStream(
                client_endpoint=client_ep,
                server_endpoint=server_ep,
                on_payload=_payload_bridge,
            )
            self.active_streams[flow_key] = stream
            self.total_streams_created += 1

        stream.process_packet(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            payload=payload,
            timestamp=pkt_time,
        )

        # Remove closed streams
        if stream.state == TcpState.CLOSED:
            self.active_streams.pop(flow_key, None)

        return stream

    def prune_idle_streams(self, now: Optional[float] = None) -> int:
        """Remove streams that have been inactive longer than stream_timeout.

        Returns:
            Number of pruned streams.
        """
        current_time = now if now is not None else time.time()
        to_remove = [
            key
            for key, st in self.active_streams.items()
            if (current_time - st.last_activity) > self.stream_timeout
        ]
        for key in to_remove:
            self.active_streams.pop(key, None)
        return len(to_remove)
