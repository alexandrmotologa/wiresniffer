"""HTTP request replay engine for re-executing captured transactions."""

import time
import urllib.error
import urllib.request
from typing import Dict, Optional

from wiresniffer.decoders.base import HttpTransaction, ProtocolType


def replay_transaction(
    tx: HttpTransaction,
    url_override: Optional[str] = None,
    header_overrides: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
) -> HttpTransaction:
    """Re-issue a captured HTTP request and capture the new response.

    Args:
        tx: The original captured transaction.
        url_override: Optional base URL or full URL to redirect the request to.
        header_overrides: Optional dictionary of headers to add or replace.
        timeout: Network timeout in seconds.

    Returns:
        A new HttpTransaction containing the replayed request and response.
    """
    target_url = url_override if url_override else tx.full_url

    headers = dict(tx.request_headers)
    # Strip hop-by-hop headers
    headers.pop("content-length", None)
    headers.pop("host", None)

    if header_overrides:
        headers.update(header_overrides)

    body = tx.request_body if tx.method in ("POST", "PUT", "PATCH") and tx.request_body else None

    req = urllib.request.Request(
        url=target_url,
        data=body,
        headers=headers,
        method=tx.method,
    )

    replayed = HttpTransaction(
        timestamp=time.time(),
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 0),
        server_endpoint=tx.server_endpoint,
        method=tx.method,
        path=tx.path,
        query_params=tx.query_params,
        request_headers=headers,
        request_body=body or b"",
    )

    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_body = response.read()
            end_time = time.time()
            replayed.response_status = response.status
            replayed.response_reason = response.reason
            replayed.response_headers = dict(response.headers.items())
            replayed.response_body = res_body
            replayed.completed_at = end_time
            replayed.latency_ms = max(0.0, round((end_time - start_time) * 1000.0, 2))
    except urllib.error.HTTPError as exc:
        end_time = time.time()
        res_body = exc.read()
        replayed.response_status = exc.code
        replayed.response_reason = exc.reason
        replayed.response_headers = dict(exc.headers.items()) if exc.headers else {}
        replayed.response_body = res_body
        replayed.completed_at = end_time
        replayed.latency_ms = max(0.0, round((end_time - start_time) * 1000.0, 2))
    except Exception as exc:
        end_time = time.time()
        replayed.response_status = 0
        replayed.response_reason = f"Connection Failed: {exc}"
        replayed.response_body = str(exc).encode("utf-8")
        replayed.completed_at = end_time
        replayed.latency_ms = max(0.0, round((end_time - start_time) * 1000.0, 2))

    return replayed
