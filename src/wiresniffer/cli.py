"""Command-line interface for WireSniffer using Typer and Rich."""

import sys
import time
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from wiresniffer.analytics.metrics import compute_traffic_metrics
from wiresniffer.capture.interface import get_available_interfaces
from wiresniffer.capture.pcap_reader import read_pcap_packets
from wiresniffer.capture.sniffer import PacketCaptureEngine
from wiresniffer.config import SnifferConfig
from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.decoders.http1_decoder import Http1StreamParser
from wiresniffer.decoders.http2_decoder import Http2StreamParser
from wiresniffer.decoders.tls_sni import extract_tls_sni
from wiresniffer.export.har_exporter import export_transactions_to_har
from wiresniffer.export.report_generator import generate_html_report, generate_markdown_report
from wiresniffer.reassembly.flow_tracker import FlowTracker
from wiresniffer.reassembly.tcp_stream import StreamDirection, TcpStream
from wiresniffer.replay.diff import calculate_transaction_diff, format_diff_markup
from wiresniffer.replay.engine import replay_transaction
from wiresniffer.security.engine import SecurityEngine
from wiresniffer.tui.app import WireSnifferApp
from wiresniffer.tui.state import TuiState

app = typer.Typer(
    name="wiresniffer",
    help="Developer-first API traffic and security sniffer at the socket level.",
    add_completion=False,
)
console = Console(width=120)


def create_pipeline(
    state: TuiState,
    security_engine: SecurityEngine,
    on_transaction_cb: Optional[callable] = None,
) -> FlowTracker:
    """Instantiate the TCP reassembly and protocol decoding pipeline."""
    # Active parsers per stream
    http1_parsers = {}
    http2_parsers = {}
    ws_parsers = {}

    def on_transaction(tx: HttpTransaction) -> None:
        # Run security evaluation
        security_engine.analyze_transaction(tx)
        state.add_transaction(tx)
        if on_transaction_cb:
            on_transaction_cb(tx)

    def on_stream_payload(
        stream: TcpStream, direction: StreamDirection, data: bytes, ts: float
    ) -> None:
        conn_id = stream.connection_id

        # 1. Check for TLS SNI on client traffic
        if direction == StreamDirection.CLIENT_TO_SERVER and (
            stream.server_endpoint[1] in (443, 8443) or not data.startswith(b"PRI ")
        ):
            sni = extract_tls_sni(data)
            if sni:
                tx = HttpTransaction(
                    timestamp=ts,
                    protocol=ProtocolType.TLS_SNI,
                    client_endpoint=stream.client_endpoint,
                    server_endpoint=stream.server_endpoint,
                    method="CONNECT",
                    path="/",
                    tls_sni=sni,
                )
                on_transaction(tx)
                return

        # 2. Check for HTTP/2 cleartext preface
        if data.startswith(b"PRI * HTTP/2.0") or conn_id in http2_parsers:
            if conn_id not in http2_parsers:
                http2_parsers[conn_id] = Http2StreamParser(stream, on_transaction)
            http2_parsers[conn_id].feed(direction, data, ts)
            return

        # 3. Check for existing WebSocket
        if conn_id in ws_parsers:
            ws_parsers[conn_id].feed(direction, data, ts)
            return

        # 4. Default to HTTP/1.1
        if conn_id not in http1_parsers:
            http1_parsers[conn_id] = Http1StreamParser(stream, on_transaction)
        http1_parsers[conn_id].feed(direction, data, ts)

    return FlowTracker(on_stream_payload=on_stream_payload)


@app.command()
def sniff(
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="Network interface (e.g. lo, eth0)"
    ),
    port: List[int] = typer.Option(
        [80, 8080, 3000, 5000, 8000, 8443, 50051], "--port", "-p", help="Target ports"
    ),
    filter_expr: Optional[str] = typer.Option(
        None, "--filter", "-f", help="Custom BPF filter expression"
    ),
    no_tui: bool = typer.Option(
        False, "--no-tui", help="Run without terminal UI; stream to stdout"
    ),
    export: Optional[str] = typer.Option(
        None, "--export", "-e", help="Save captured traffic to HAR file on exit"
    ),
    alerts_only: bool = typer.Option(
        False, "--alerts-only", help="Filter view to transactions with security alerts"
    ),
) -> None:
    """Sniff network interface for live API traffic and security issues."""
    config = SnifferConfig(
        interface=interface,
        ports=port,
        custom_bpf=filter_expr,
        export_path=export,
    )
    state = TuiState(alerts_only=alerts_only)
    sec_engine = SecurityEngine()

    if no_tui:
        console.print(f"[bold green]Starting WireSniffer[/bold green] on ports {port}...")

        def _on_cli_tx(tx: HttpTransaction) -> None:
            alert_badge = (
                f" [red bold]🚨 {len(tx.security_alerts)} Alert(s)[/red bold]"
                if tx.security_alerts
                else ""
            )
            status_color = "green" if (tx.response_status or 200) < 400 else "red"
            console.print(
                f"[{status_color}]{tx.protocol.value} {tx.method} {tx.full_url} -> {tx.response_status or '...'}[/{status_color}] "
                f"({tx.latency_ms or 0:.0f}ms){alert_badge}"
            )

        tracker = create_pipeline(state, sec_engine, on_transaction_cb=_on_cli_tx)
        engine = PacketCaptureEngine(config, on_packet=tracker.process_packet)
        engine.start()
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            engine.stop()
            if export:
                export_transactions_to_har(state.transactions, export)
                console.print(f"[green]Saved {len(state.transactions)} flows to {export}[/green]")
    else:
        tracker = create_pipeline(state, sec_engine)
        engine = PacketCaptureEngine(config, on_packet=tracker.process_packet)
        try:
            engine.start()
            tui_app = WireSnifferApp(state)
            tui_app.run()
        finally:
            engine.stop()
            if export:
                export_transactions_to_har(state.transactions, export)


@app.command()
def inspect(
    pcap_file: str = typer.Argument(..., help="Path to .pcap or .pcapng file"),
    no_tui: bool = typer.Option(
        False, "--no-tui", help="Dump flows to stdout rather than opening TUI"
    ),
) -> None:
    """Replay and inspect an existing PCAP capture file."""
    state = TuiState()
    sec_engine = SecurityEngine()

    tracker = create_pipeline(state, sec_engine)
    packet_count = 0
    for pkt in read_pcap_packets(pcap_file):
        tracker.process_packet(pkt)
        packet_count += 1

    if no_tui:
        console.print(
            f"[bold]Loaded {packet_count} packets, {len(state.transactions)} flows from {pcap_file}[/bold]\n"
        )
        table = Table(title="Captured Flows")
        table.add_column("Proto", style="cyan")
        table.add_column("Method", style="magenta")
        table.add_column("Status", style="green")
        table.add_column("URL", style="white")
        table.add_column("Latency", style="dim")
        table.add_column("Alerts", style="red")

        for tx in state.transactions:
            alerts_str = f"🚨 {len(tx.security_alerts)}" if tx.security_alerts else ""
            table.add_row(
                tx.protocol.value,
                tx.method,
                str(tx.response_status or "..."),
                tx.full_url,
                f"{tx.latency_ms or 0:.0f}ms",
                alerts_str,
            )
        console.print(table)
    else:
        tui_app = WireSnifferApp(state)
        tui_app.run()


@app.command()
def scan(
    pcap_file: str = typer.Argument(..., help="PCAP capture file to audit"),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Minimum severity to fail CI: critical, high, medium, low"
    ),
) -> None:
    """Security audit mode for CI/CD pipelines. Exits status 1 if vulnerabilities are found."""
    state = TuiState()
    sec_engine = SecurityEngine()

    tracker = create_pipeline(state, sec_engine)
    for pkt in read_pcap_packets(pcap_file):
        tracker.process_packet(pkt)

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    threshold = severity_order.get(fail_on.lower(), 3)

    all_alerts = []
    for tx in state.transactions:
        for alert in tx.security_alerts:
            all_alerts.append((tx, alert))

    if not all_alerts:
        console.print(
            "[bold green]✔ Security Audit Clean: No vulnerabilities detected.[/bold green]"
        )
        sys.exit(0)

    table = Table(title=f"Security Violations Detected ({len(all_alerts)})", border_style="red")
    table.add_column("Severity", style="bold red")
    table.add_column("Rule", style="yellow", overflow="fold")
    table.add_column("Endpoint", style="white", overflow="fold")
    table.add_column("Evidence", style="cyan", overflow="fold")
    table.add_column("Remediation", style="green", overflow="fold")

    failed = False
    for tx, alert in all_alerts:
        sev = alert.get("severity", "LOW")
        sev_rank = severity_order.get(sev.lower(), 1)
        if sev_rank >= threshold:
            failed = True
        table.add_row(
            sev,
            alert.get("rule_id", ""),
            f"{tx.method} {tx.path}",
            alert.get("evidence", "")[:40],
            alert.get("remediation", "")[:50],
        )

    console.print(table)

    if failed:
        console.print(
            f"\n[bold red]❌ Audit Failed: Vulnerabilities meeting or exceeding '{fail_on.upper()}' severity found.[/bold red]"
        )
        sys.exit(1)
    else:
        console.print(
            f"\n[bold yellow]⚠ Violations detected, but none exceeded '{fail_on.upper()}' failure threshold.[/bold yellow]"
        )
        sys.exit(0)


@app.command()
def interfaces() -> None:
    """List available network interfaces and loopback status."""
    ifaces = get_available_interfaces()
    table = Table(title="Available Network Interfaces")
    table.add_column("Name", style="bold cyan")
    table.add_column("Description", style="white")
    table.add_column("IP Address", style="green")
    table.add_column("Loopback", style="yellow")

    for iface in ifaces:
        table.add_row(
            iface.name,
            iface.description,
            iface.ip_address or "-",
            "Yes" if iface.is_loopback else "No",
        )
    console.print(table)


@app.command()
def replay(
    pcap_file: str = typer.Argument(..., help="Path to .pcap capture file"),
    flow_id: int = typer.Option(0, "--flow", "-f", help="Index of flow to replay (0-based)"),
    url_override: Optional[str] = typer.Option(
        None, "--url", "-u", help="Override target destination URL"
    ),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Timeout in seconds"),
) -> None:
    """Replay a captured HTTP transaction and show live response diff."""
    state = TuiState()
    sec_engine = SecurityEngine()
    tracker = create_pipeline(state, sec_engine)

    for pkt in read_pcap_packets(pcap_file):
        tracker.process_packet(pkt)

    if not state.transactions:
        console.print("[red]No transactions found in PCAP capture.[/red]")
        sys.exit(1)

    if flow_id < 0 or flow_id >= len(state.transactions):
        console.print(
            f"[red]Invalid flow index {flow_id}. Total flows: {len(state.transactions)}[/red]"
        )
        sys.exit(1)

    tx = state.transactions[flow_id]
    target_url = url_override or tx.full_url
    console.print(
        f"[bold]Replaying flow #{flow_id}:[/bold] [cyan]{tx.method} {target_url}[/cyan]..."
    )

    replayed = replay_transaction(tx, url_override=url_override, timeout=timeout)
    diff = calculate_transaction_diff(tx, replayed)

    console.print("\n" + format_diff_markup(diff))


@app.command()
def metrics(
    pcap_file: str = typer.Argument(..., help="Path to .pcap capture file"),
) -> None:
    """Compute traffic analytics, latency percentiles (p50/p95/p99), and error rates."""
    state = TuiState()
    sec_engine = SecurityEngine()
    tracker = create_pipeline(state, sec_engine)

    for pkt in read_pcap_packets(pcap_file):
        tracker.process_packet(pkt)

    if not state.transactions:
        console.print("[red]No transactions found in PCAP capture.[/red]")
        sys.exit(1)

    m = compute_traffic_metrics(state.transactions)
    console.print(f"[bold cyan]WireSniffer Traffic Analytics[/bold cyan] ({pcap_file})\n")

    # Overview table
    t_overview = Table(title="Traffic Overview")
    t_overview.add_column("Metric", style="bold white")
    t_overview.add_column("Value", style="green")
    t_overview.add_row("Total Requests", str(m.total_requests))
    t_overview.add_row("Bytes Sent", f"{m.total_bytes_sent:,} B")
    t_overview.add_row("Bytes Received", f"{m.total_bytes_received:,} B")
    t_overview.add_row(
        "Status Distribution (2xx / 3xx / 4xx / 5xx)",
        f"{m.status_counts['2xx']} / {m.status_counts['3xx']} / {m.status_counts['4xx']} / {m.status_counts['5xx']}",
    )
    t_overview.add_row(
        "Latency Min / Avg / Max",
        f"{m.latency_min:.1f}ms / {m.latency_avg:.1f}ms / {m.latency_max:.1f}ms",
    )
    t_overview.add_row(
        "Latency p50 / p95 / p99",
        f"{m.latency_p50:.1f}ms / {m.latency_p95:.1f}ms / {m.latency_p99:.1f}ms",
    )
    console.print(t_overview)
    console.print("")

    # Slowest endpoints table
    if m.slowest_endpoints:
        t_slow = Table(title="Top Slowest Endpoints")
        t_slow.add_column("Endpoint", style="white")
        t_slow.add_column("Average Latency", style="yellow")
        for ep, lat in m.slowest_endpoints:
            t_slow.add_row(ep, f"{lat:.1f}ms")
        console.print(t_slow)
        console.print("")

    # Error rate table
    if m.highest_error_endpoints:
        t_err = Table(title="Endpoints with Highest Error Rate")
        t_err.add_column("Endpoint", style="white")
        t_err.add_column("Error Rate", style="bold red")
        t_err.add_column("Total Requests", style="dim")
        for ep, rate, count in m.highest_error_endpoints:
            t_err.add_row(ep, f"{rate:.1f}%", str(count))
        console.print(t_err)


@app.command()
def report(
    pcap_file: str = typer.Argument(..., help="Path to .pcap capture file"),
    output: str = typer.Option(
        "report.html", "--output", "-o", help="Output file path (.html or .md)"
    ),
    format: str = typer.Option("html", "--format", "-F", help="Report format: html or md"),
) -> None:
    """Generate a standalone security audit report mapped to OWASP API Top 10."""
    state = TuiState()
    sec_engine = SecurityEngine()
    tracker = create_pipeline(state, sec_engine)

    for pkt in read_pcap_packets(pcap_file):
        tracker.process_packet(pkt)

    fmt = format.lower()
    if fmt in ("md", "markdown") or output.endswith(".md"):
        content = generate_markdown_report(state.transactions)
    else:
        content = generate_html_report(state.transactions)

    with open(output, "w", encoding="utf-8") as f:
        f.write(content)

    console.print(
        f"[bold green]✔ Security audit report successfully saved to {output}[/bold green]"
    )
