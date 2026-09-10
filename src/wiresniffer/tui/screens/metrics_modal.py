"""Modal screen displaying aggregated API performance and traffic analytics."""

from typing import List

from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

from wiresniffer.analytics.metrics import compute_traffic_metrics
from wiresniffer.decoders.base import HttpTransaction


class MetricsModal(ModalScreen):
    """Modal displaying latency percentiles, slowest endpoints, and traffic metrics."""

    def __init__(self, transactions: List[HttpTransaction]) -> None:
        super().__init__()
        self.transactions = transactions

    def compose(self) -> ComposeResult:
        metrics = compute_traffic_metrics(self.transactions)
        lines = [
            "[bold cyan]API Traffic & Latency Performance Analytics[/bold cyan]\n",
            f"[bold]Total Transactions:[/bold] {metrics.total_requests}",
            f"[bold]Data Transferred:[/bold] Sent {metrics.total_bytes_sent:,} B | Received {metrics.total_bytes_received:,} B\n",
            "[bold yellow]HTTP Status Distribution:[/bold yellow]",
            f"  [green]2xx:[/green] {metrics.status_counts['2xx']} | [cyan]3xx:[/cyan] {metrics.status_counts['3xx']} | [yellow]4xx:[/yellow] {metrics.status_counts['4xx']} | [red]5xx:[/red] {metrics.status_counts['5xx']}\n",
            "[bold yellow]Latency Percentiles:[/bold yellow]",
            f"  [white]Min:[/white] {metrics.latency_min:.1f}ms | [white]Avg:[/white] {metrics.latency_avg:.1f}ms | [cyan]p50:[/cyan] {metrics.latency_p50:.1f}ms | [yellow]p95:[/yellow] {metrics.latency_p95:.1f}ms | [red]p99:[/red] {metrics.latency_p99:.1f}ms | [red]Max:[/red] {metrics.latency_max:.1f}ms\n",
        ]

        if metrics.slowest_endpoints:
            lines.append("[bold yellow]Top Slowest Endpoints (Avg Latency):[/bold yellow]")
            for ep, avg_lat in metrics.slowest_endpoints:
                lines.append(f"  [red]{avg_lat:.1f}ms[/red] - [white]{ep}[/white]")
            lines.append("")

        if metrics.highest_error_endpoints:
            lines.append("[bold yellow]Highest Error Rate Endpoints:[/bold yellow]")
            for ep, pct, tot in metrics.highest_error_endpoints:
                lines.append(f"  [red]{pct:.1f}%[/red] ({tot} reqs) - [white]{ep}[/white]")
            lines.append("")

        lines.append("[dim]Press Escape, Enter, or 'q' to return to traffic list[/dim]")

        with Container(id="modal-dialog"):
            yield VerticalScroll(Static("\n".join(lines)))

    def on_key(self, event) -> None:
        if event.key in ("escape", "enter", "q"):
            self.dismiss()
