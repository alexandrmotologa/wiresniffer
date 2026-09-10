"""Berkeley Packet Filter (BPF) expression generator and validator."""

from typing import List, Optional


def build_bpf_filter(
    ports: Optional[List[int]] = None,
    hosts: Optional[List[str]] = None,
    custom_filter: Optional[str] = None,
) -> str:
    """Build a standard BPF filter string for TCP traffic.

    Args:
        ports: Optional list of integer TCP ports.
        hosts: Optional list of IP addresses or hostnames.
        custom_filter: Raw BPF expression that overrides automatic construction.

    Returns:
        BPF filter string suitable for Scapy, tcpdump, or raw socket filters.
    """
    if custom_filter and custom_filter.strip():
        return custom_filter.strip()

    clauses: List[str] = ["tcp"]

    if ports:
        port_clauses = [f"port {p}" for p in sorted(set(ports))]
        if len(port_clauses) == 1:
            clauses.append(port_clauses[0])
        else:
            clauses.append(f"({' or '.join(port_clauses)})")

    if hosts:
        host_clauses = [f"host {h}" for h in sorted(set(hosts))]
        if len(host_clauses) == 1:
            clauses.append(host_clauses[0])
        else:
            clauses.append(f"({' or '.join(host_clauses)})")

    return " and ".join(clauses)
