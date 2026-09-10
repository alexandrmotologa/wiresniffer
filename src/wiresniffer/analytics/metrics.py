"""Traffic analytics, percentile latency computation, and endpoint ranking."""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from wiresniffer.decoders.base import HttpTransaction


@dataclass
class TrafficMetrics:
    """Aggregated performance and traffic metrics."""

    total_requests: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    status_counts: Dict[str, int] = field(
        default_factory=lambda: {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    )
    latency_min: float = 0.0
    latency_avg: float = 0.0
    latency_p50: float = 0.0
    latency_p95: float = 0.0
    latency_p99: float = 0.0
    latency_max: float = 0.0
    slowest_endpoints: List[Tuple[str, float]] = field(default_factory=list)
    highest_error_endpoints: List[Tuple[str, float, int]] = field(
        default_factory=list
    )  # (path, error_rate_pct, total)
    largest_endpoints: List[Tuple[str, int]] = field(default_factory=list)  # (path, avg_bytes)


def compute_traffic_metrics(transactions: List[HttpTransaction]) -> TrafficMetrics:
    """Compute comprehensive traffic, error, and latency percentiles."""
    metrics = TrafficMetrics()
    if not transactions:
        return metrics

    metrics.total_requests = len(transactions)

    latencies: List[float] = []
    endpoint_latencies: Dict[str, List[float]] = defaultdict(list)
    endpoint_errors: Dict[str, List[bool]] = defaultdict(list)
    endpoint_sizes: Dict[str, List[int]] = defaultdict(list)

    for tx in transactions:
        req_len = len(tx.request_body)
        res_len = len(tx.response_body)
        metrics.total_bytes_sent += req_len
        metrics.total_bytes_received += res_len

        status = tx.response_status or 0
        if 200 <= status < 300:
            metrics.status_counts["2xx"] += 1
        elif 300 <= status < 400:
            metrics.status_counts["3xx"] += 1
        elif 400 <= status < 500:
            metrics.status_counts["4xx"] += 1
        elif 500 <= status < 600:
            metrics.status_counts["5xx"] += 1
        else:
            metrics.status_counts["other"] += 1

        path_key = f"{tx.method} {tx.path.split('?')[0]}"

        if tx.latency_ms is not None and tx.latency_ms >= 0:
            lat = tx.latency_ms
            latencies.append(lat)
            endpoint_latencies[path_key].append(lat)

        is_err = status >= 400 or status == 0
        endpoint_errors[path_key].append(is_err)
        endpoint_sizes[path_key].append(res_len)

    # Compute latency percentiles
    if latencies:
        sorted_lats = sorted(latencies)
        count = len(sorted_lats)
        metrics.latency_min = sorted_lats[0]
        metrics.latency_max = sorted_lats[-1]
        metrics.latency_avg = round(sum(sorted_lats) / count, 2)
        metrics.latency_p50 = sorted_lats[int(count * 0.50)]
        metrics.latency_p95 = sorted_lats[min(count - 1, int(count * 0.95))]
        metrics.latency_p99 = sorted_lats[min(count - 1, int(count * 0.99))]

    # Compute slowest endpoints
    avg_lats = []
    for ep, lats in endpoint_latencies.items():
        avg_lats.append((ep, round(sum(lats) / len(lats), 2)))
    metrics.slowest_endpoints = sorted(avg_lats, key=lambda x: x[1], reverse=True)[:5]

    # Compute error rates
    err_rates = []
    for ep, errs in endpoint_errors.items():
        err_pct = round((sum(1 for e in errs if e) / len(errs)) * 100.0, 1)
        if err_pct > 0:
            err_rates.append((ep, err_pct, len(errs)))
    metrics.highest_error_endpoints = sorted(err_rates, key=lambda x: x[1], reverse=True)[:5]

    # Compute largest endpoints
    avg_sizes = []
    for ep, sizes in endpoint_sizes.items():
        avg_sizes.append((ep, int(sum(sizes) / len(sizes))))
    metrics.largest_endpoints = sorted(avg_sizes, key=lambda x: x[1], reverse=True)[:5]

    return metrics
