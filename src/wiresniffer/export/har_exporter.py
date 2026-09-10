"""HTTP Archive (HAR 1.2) exporter for captured API transactions."""

import datetime
import json
from typing import Any, Dict, List

from wiresniffer.decoders.base import HttpTransaction


def transaction_to_har_entry(tx: HttpTransaction) -> Dict[str, Any]:
    """Convert a single HttpTransaction to a HAR 1.2 entry object."""
    dt = datetime.datetime.fromtimestamp(tx.timestamp, tz=datetime.timezone.utc)
    started_iso = dt.isoformat()

    # Query string array
    qs_array = [{"name": k, "value": v} for k, v in tx.query_params.items()]

    # Request headers array
    req_headers_array = [{"name": k, "value": v} for k, v in tx.request_headers.items()]

    # Request postData
    post_data = None
    if tx.request_body:
        mime = tx.request_headers.get("content-type", "application/octet-stream")
        post_data = {
            "mimeType": mime,
            "text": tx.request_body_text,
        }

    # Response headers array
    res_headers_array = [{"name": k, "value": v} for k, v in tx.response_headers.items()]

    # Response content
    res_mime = tx.response_headers.get("content-type", "application/octet-stream")
    res_content = {
        "size": len(tx.response_body),
        "mimeType": res_mime,
        "text": tx.response_body_text,
    }

    latency = tx.latency_ms if tx.latency_ms is not None else 0.0

    entry: Dict[str, Any] = {
        "_flowId": tx.flow_id,
        "startedDateTime": started_iso,
        "time": latency,
        "request": {
            "method": tx.method,
            "url": tx.full_url,
            "httpVersion": tx.protocol.value,
            "headers": req_headers_array,
            "queryString": qs_array,
            "headersSize": -1,
            "bodySize": len(tx.request_body),
        },
        "response": {
            "status": tx.response_status if tx.response_status is not None else 0,
            "statusText": tx.response_reason or "",
            "httpVersion": tx.protocol.value,
            "headers": res_headers_array,
            "content": res_content,
            "redirectURL": tx.response_headers.get("location", ""),
            "headersSize": -1,
            "bodySize": len(tx.response_body),
        },
        "cache": {},
        "timings": {
            "send": 0.0,
            "wait": latency,
            "receive": 0.0,
        },
    }

    if post_data:
        entry["request"]["postData"] = post_data

    if tx.security_alerts:
        entry["_securityAlerts"] = tx.security_alerts

    return entry


def export_transactions_to_har(
    transactions: List[HttpTransaction],
    output_path: str,
) -> None:
    """Save a list of transactions to a valid HAR 1.2 file."""
    entries = [transaction_to_har_entry(tx) for tx in transactions]

    har_data = {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "WireSniffer",
                "version": "0.1.0",
            },
            "entries": entries,
        }
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(har_data, f, indent=2)
