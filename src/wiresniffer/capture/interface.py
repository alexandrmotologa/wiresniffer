"""Network interface discovery and selection for packet capture."""

import os
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class NetworkInterface:
    """Represents a discovered network interface."""

    name: str
    description: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    is_loopback: bool = False


def get_available_interfaces() -> List[NetworkInterface]:
    """Discover active network interfaces on the local operating system.

    Returns:
        List of NetworkInterface objects.
    """
    interfaces: List[NetworkInterface] = []

    try:
        from scapy.all import conf

        for iface_name, iface_data in conf.ifaces.items():
            name = getattr(iface_data, "name", str(iface_name))
            description = getattr(iface_data, "description", name)
            ip = getattr(iface_data, "ip", None)
            mac = getattr(iface_data, "mac", None)

            # Determine loopback
            is_lo = False
            lower_name = name.lower()
            lower_desc = str(description).lower()
            if "loopback" in lower_name or "loopback" in lower_desc or name in ("lo", "lo0"):
                is_lo = True
            elif ip and (ip.startswith("127.") or ip == "::1"):
                is_lo = True

            interfaces.append(
                NetworkInterface(
                    name=name,
                    description=description or name,
                    ip_address=ip if ip != "0.0.0.0" else None,
                    mac_address=mac,
                    is_loopback=is_lo,
                )
            )
    except Exception:
        # Fallback for systems where Scapy interface scanning raises an error
        interfaces.append(
            NetworkInterface(
                name="lo" if os.name != "nt" else "\\Device\\NPF_Loopback",
                description="Local Loopback",
                ip_address="127.0.0.1",
                is_loopback=True,
            )
        )

    return interfaces


def find_default_interface() -> Optional[NetworkInterface]:
    """Select the best candidate interface for sniffing local developer API traffic.

    Prefers loopback or standard active interfaces.
    """
    ifaces = get_available_interfaces()
    if not ifaces:
        return None

    # Priority 1: Loopback interface
    for iface in ifaces:
        if iface.is_loopback:
            return iface

    # Priority 2: Interface with an active IPv4 address
    for iface in ifaces:
        if iface.ip_address and not iface.ip_address.startswith("169.254"):
            return iface

    return ifaces[0]
