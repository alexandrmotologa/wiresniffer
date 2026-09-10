"""Offline PCAP / PCAPNG packet capture file ingestion."""

import os
from typing import Callable, Iterator, Optional

from scapy.all import Packet, PcapReader


def read_pcap_packets(
    file_path: str,
    filter_fn: Optional[Callable[[Packet], bool]] = None,
) -> Iterator[Packet]:
    """Read packets sequentially from a PCAP or PCAPNG file.

    Args:
        file_path: Path to the .pcap or .pcapng capture file.
        filter_fn: Optional predicate to discard unwanted packets early.

    Yields:
        Scapy Packet instances.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Capture file not found: {file_path}")

    with PcapReader(file_path) as reader:
        for packet in reader:
            if filter_fn is None or filter_fn(packet):
                yield packet
