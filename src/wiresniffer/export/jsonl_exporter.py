"""Streaming JSONL transaction exporter for unix pipelines."""

import json
from typing import TextIO

from wiresniffer.decoders.base import HttpTransaction


def write_transaction_jsonl(tx: HttpTransaction, stream: TextIO) -> None:
    """Serialize transaction to a single JSON line and flush to output stream."""
    record = {
        "flow_id": tx.flow_id,
        "timestamp": tx.timestamp,
        "protocol": tx.protocol.value,
        "client": f"{tx.client_endpoint[0]}:{tx.client_endpoint[1]}",
        "server": f"{tx.server_endpoint[0]}:{tx.server_endpoint[1]}",
        "method": tx.method,
        "path": tx.path,
        "query_params": tx.query_params,
        "request_headers": tx.request_headers,
        "status": tx.response_status,
        "latency_ms": tx.latency_ms,
        "security_alerts": tx.security_alerts,
    }
    stream.write(json.dumps(record) + "\n")
    stream.flush()
