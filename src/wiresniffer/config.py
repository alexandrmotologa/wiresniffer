"""Configuration models for WireSniffer using Pydantic v2."""

from typing import List, Optional

from pydantic import BaseModel, Field


class SnifferConfig(BaseModel):
    """Runtime configuration for packet capture and stream processing."""

    interface: Optional[str] = Field(
        default=None,
        description="Network interface name to bind to (e.g. lo, eth0, docker0). None for auto-select.",
    )
    ports: List[int] = Field(
        default_factory=lambda: [80, 8080, 3000, 5000, 8000, 8443, 50051],
        description="Target TCP ports to capture and reassemble.",
    )
    custom_bpf: Optional[str] = Field(
        default=None,
        description="User-supplied raw Berkeley Packet Filter (BPF) string.",
    )
    max_flow_buffer: int = Field(
        default=1000,
        description="Maximum number of historical transactions kept in memory.",
    )
    stream_timeout_seconds: float = Field(
        default=30.0,
        description="Inactive duration before TCP stream buffers are garbage collected.",
    )
    enable_security_scanner: bool = Field(
        default=True,
        description="Whether to run real-time security heuristics on decoded flows.",
    )
    security_fail_severity: Optional[str] = Field(
        default=None,
        description="Minimum severity that triggers non-zero exit in scan mode (critical, high, medium, low).",
    )
    export_path: Optional[str] = Field(
        default=None,
        description="File path to save captured transactions upon completion.",
    )
