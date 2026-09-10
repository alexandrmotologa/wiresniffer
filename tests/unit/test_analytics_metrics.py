"""Unit tests for traffic performance metrics and latency analytics."""

from wiresniffer.analytics.metrics import compute_traffic_metrics
from wiresniffer.decoders.base import HttpTransaction, ProtocolType


def test_compute_traffic_metrics_empty():
    m = compute_traffic_metrics([])
    assert m.total_requests == 0
    assert m.total_bytes_sent == 0
    assert m.latency_p50 == 0.0


def test_compute_traffic_metrics_aggregated():
    txs = []
    # Create 10 transactions with known latencies: 10, 20, 30, 40, 50, 60, 70, 80, 90, 100
    for i in range(1, 11):
        status = 200 if i <= 8 else 500
        path = "/fast" if i <= 7 else "/slow-api"
        tx = HttpTransaction(
            timestamp=100.0 + i,
            protocol=ProtocolType.HTTP1,
            client_endpoint=("127.0.0.1", 1000 + i),
            server_endpoint=("127.0.0.1", 80),
            method="GET",
            path=path,
            response_status=status,
            latency_ms=float(i * 10),
            request_body=b"req",
            response_body=b"resp-data" if i <= 7 else b"huge-error-body-here",
        )
        txs.append(tx)

    m = compute_traffic_metrics(txs)
    assert m.total_requests == 10
    assert m.total_bytes_sent == 30
    assert m.status_counts["2xx"] == 8
    assert m.status_counts["5xx"] == 2
    assert m.latency_min == 10.0
    assert m.latency_max == 100.0
    assert m.latency_avg == 55.0

    # Sorted: [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    # 50th percentile (index 5) -> 60.0
    assert m.latency_p50 == 60.0
    assert m.latency_p95 >= 90.0

    # Slowest endpoints: /slow-api should have higher average than /fast
    assert len(m.slowest_endpoints) == 2
    assert m.slowest_endpoints[0][0] == "GET /slow-api"
    assert m.slowest_endpoints[0][1] == 90.0  # (80+90+100)/3 = 90.0

    # Error rates: /slow-api had 2 errors out of 3 requests -> 66.7%
    assert len(m.highest_error_endpoints) == 1
    assert m.highest_error_endpoints[0][0] == "GET /slow-api"
    assert m.highest_error_endpoints[0][1] == 66.7
