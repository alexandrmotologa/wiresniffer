"""Base models and definitions for protocol decoders and transactions."""

import json
import shlex
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


class ProtocolType(str, Enum):
    HTTP1 = "HTTP/1.1"
    HTTP2 = "HTTP/2"
    WEBSOCKET = "WebSocket"
    GRPC = "gRPC"
    TLS_SNI = "TLS (SNI)"
    UNKNOWN = "TCP"


class WebSocketMessage(BaseModel):
    """Represents an intercepted WebSocket frame or message."""

    direction: str  # C2S or S2C
    opcode: int  # 1=text, 2=binary, 8=close, 9=ping, 10=pong
    opcode_name: str
    payload: bytes
    timestamp: float = Field(default_factory=time.time)

    @property
    def text_preview(self) -> str:
        try:
            return self.payload.decode("utf-8", errors="replace")
        except Exception:
            return f"<{len(self.payload)} binary bytes>"


class HttpTransaction(BaseModel):
    """Represents a fully reconstructed or ongoing API transaction."""

    flow_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = Field(default_factory=time.time)
    protocol: ProtocolType = ProtocolType.HTTP1

    client_endpoint: Tuple[str, int]
    server_endpoint: Tuple[str, int]

    # Request Details
    method: str = "GET"
    path: str = "/"
    query_params: Dict[str, str] = Field(default_factory=dict)
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: bytes = b""

    # Response Details
    response_status: Optional[int] = None
    response_reason: Optional[str] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: bytes = b""

    # Timing
    latency_ms: Optional[float] = None
    completed_at: Optional[float] = None

    # Protocol-specific attachments
    websocket_messages: List[WebSocketMessage] = Field(default_factory=list)
    grpc_service: Optional[str] = None
    grpc_method: Optional[str] = None
    grpc_status: Optional[int] = None
    tls_sni: Optional[str] = None

    # Security Annotations (populated by security heuristics engine)
    security_alerts: List[Dict[str, Any]] = Field(default_factory=list)

    @property
    def host(self) -> str:
        """Extract host header or fallback to server endpoint."""
        for k, v in self.request_headers.items():
            if k.lower() == "host":
                return v
        if self.tls_sni:
            return self.tls_sni
        return f"{self.server_endpoint[0]}:{self.server_endpoint[1]}"

    @property
    def full_url(self) -> str:
        scheme = (
            "https"
            if self.server_endpoint[1] in (443, 8443) or self.protocol == ProtocolType.TLS_SNI
            else "http"
        )
        return f"{scheme}://{self.host}{self.path}"

    @property
    def is_completed(self) -> bool:
        return self.response_status is not None or self.protocol in (
            ProtocolType.TLS_SNI,
            ProtocolType.WEBSOCKET,
        )

    @property
    def request_body_text(self) -> str:
        try:
            return self.request_body.decode("utf-8", errors="replace")
        except Exception:
            return f"<{len(self.request_body)} binary bytes>"

    @property
    def response_body_text(self) -> str:
        try:
            return self.response_body.decode("utf-8", errors="replace")
        except Exception:
            return f"<{len(self.response_body)} binary bytes>"

    def request_json(self) -> Optional[Any]:
        if not self.request_body:
            return None
        try:
            return json.loads(self.request_body.decode("utf-8"))
        except Exception:
            return None

    def response_json(self) -> Optional[Any]:
        if not self.response_body:
            return None
        try:
            return json.loads(self.response_body.decode("utf-8"))
        except Exception:
            return None

    def to_curl(self) -> str:
        """Generate a reproducible cURL command string."""
        cmd = ["curl", "-X", self.method, shlex.quote(self.full_url)]
        for k, v in self.request_headers.items():
            if k.lower() not in ("content-length", "host"):
                cmd.extend(["-H", shlex.quote(f"{k}: {v}")])
        if self.request_body:
            try:
                body_str = self.request_body.decode("utf-8")
                cmd.extend(["--data-raw", shlex.quote(body_str)])
            except Exception:
                cmd.extend(["--data-binary", "@data.bin"])
        return " ".join(cmd)
