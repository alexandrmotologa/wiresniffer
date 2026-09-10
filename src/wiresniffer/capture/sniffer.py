"""Asynchronous live network packet capture using Scapy."""

import threading
from typing import Callable, Optional

from scapy.all import AsyncSniffer, Packet

from wiresniffer.capture.bpf_filter import build_bpf_filter
from wiresniffer.capture.interface import find_default_interface
from wiresniffer.config import SnifferConfig


class PacketCaptureEngine:
    """Manages asynchronous live packet capture with Berkeley Packet Filters."""

    def __init__(
        self,
        config: SnifferConfig,
        on_packet: Callable[[Packet], None],
        on_error: Optional[Callable[[Exception], None]] = None,
    ) -> None:
        self.config = config
        self.on_packet = on_packet
        self.on_error = on_error
        self.sniffer: Optional[AsyncSniffer] = None
        self.is_running = False
        self.packets_captured = 0
        self.bytes_captured = 0
        self._lock = threading.Lock()

    def _packet_handler(self, packet: Packet) -> None:
        """Internal callback invoked for each captured frame."""
        with self._lock:
            self.packets_captured += 1
            self.bytes_captured += len(packet)

        try:
            self.on_packet(packet)
        except Exception as exc:
            if self.on_error:
                self.on_error(exc)

    def start(self) -> None:
        """Start capturing packets in a background worker thread."""
        if self.is_running:
            return

        iface = self.config.interface
        if not iface:
            default_iface = find_default_interface()
            if default_iface:
                iface = default_iface.name

        bpf = build_bpf_filter(
            ports=self.config.ports,
            custom_filter=self.config.custom_bpf,
        )

        try:
            # Configure Scapy AsyncSniffer
            sniffer_kwargs = {
                "prn": self._packet_handler,
                "store": False,
                "filter": bpf,
            }
            if iface:
                sniffer_kwargs["iface"] = iface

            self.sniffer = AsyncSniffer(**sniffer_kwargs)
            self.sniffer.start()
            self.is_running = True
        except PermissionError as exc:
            hint = (
                "Administrator privileges required to sniff raw sockets. "
                "On Windows, install Npcap and run terminal as Administrator. "
                "On Linux, run with sudo or grant CAP_NET_RAW capability."
            )
            raise PermissionError(f"{exc}. {hint}") from exc
        except Exception as exc:
            if "pcap" in str(exc).lower() or "winpcap" in str(exc).lower():
                hint = (
                    "Npcap/libpcap driver not detected or inaccessible. "
                    "You can still inspect .pcap files using 'wiresniffer inspect <file>'."
                )
                raise RuntimeError(f"{exc}. {hint}") from exc
            raise

    def stop(self) -> None:
        """Stop packet capture cleanly."""
        if not self.is_running:
            return

        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None

        self.is_running = False

    def get_stats(self) -> dict:
        """Return capture statistics."""
        with self._lock:
            return {
                "packets": self.packets_captured,
                "bytes": self.bytes_captured,
                "running": self.is_running,
            }
