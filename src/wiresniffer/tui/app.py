"""Textual terminal user interface application for WireSniffer."""

import json
from typing import Optional

from rich.markup import escape
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, Static

from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.export.curl_generator import generate_curl_command
from wiresniffer.tui.hex_view import format_hex_dump
from wiresniffer.tui.state import TuiState

TUI_CSS = """
Screen {
    background: #0f172a;
    color: #e2e8f0;
}

#stats-banner {
    dock: top;
    height: 1;
    background: #1e293b;
    color: #94a3b8;
    padding: 0 1;
}

#filter-bar {
    dock: top;
    height: 3;
    display: none;
    background: #1e293b;
    padding: 0 1;
}

#main-container {
    height: 1fr;
}

#left-pane {
    width: 45%;
    border-right: vkey #334155;
}

#right-pane {
    width: 55%;
}

#flow-table {
    height: 100%;
}

#request-pane {
    height: 50%;
    border-bottom: hkey #334155;
    padding: 0 1;
}

#response-pane {
    height: 50%;
    padding: 0 1;
}

.pane-title {
    text-style: bold;
    color: #38bdf8;
    background: #1e293b;
    padding: 0 1;
    margin-bottom: 1;
}

.alert-badge {
    color: #ef4444;
    text-style: bold;
}

/* Modal Screen */
AlertModalScreen {
    align: center middle;
}

#modal-dialog {
    width: 70%;
    height: 70%;
    background: #1e293b;
    border: thick #ef4444;
    padding: 1 2;
}
"""


class AlertModal(ModalScreen):
    """Modal displaying full details of security alerts on selected flow."""

    def __init__(self, tx: HttpTransaction) -> None:
        super().__init__()
        self.tx = tx

    def compose(self) -> ComposeResult:
        content = []
        content.append(
            f"[bold red]Security Vulnerabilities Detected ({len(self.tx.security_alerts)})[/bold red]\n"
        )
        content.append(f"[dim]Flow: {self.tx.method} {self.tx.full_url}[/dim]\n\n")

        for idx, alert in enumerate(self.tx.security_alerts, 1):
            severity = alert.get("severity", "UNKNOWN")
            sev_color = "red" if severity in ("CRITICAL", "HIGH") else "yellow"
            content.append(
                f"[{sev_color} bold]{idx}. [{severity}] {alert.get('title')}[/{sev_color} bold]\n"
            )
            content.append(f"[white]{alert.get('description')}[/white]\n")
            content.append(f"[cyan]Evidence: {alert.get('evidence')}[/cyan]\n")
            content.append(f"[green]Remediation: {alert.get('remediation')}[/green]\n\n")

        content.append("[dim]Press Escape or Enter to close[/dim]")

        with Container(id="modal-dialog"):
            yield VerticalScroll(Static("".join(content)))

    def on_key(self, event) -> None:
        if event.key in ("escape", "enter", "q"):
            self.dismiss()


class WireSnifferApp(App):
    """Interactive terminal traffic sniffer inspired by LazyGit."""

    CSS = TUI_CSS
    TITLE = "WireSniffer"
    SUB_TITLE = "Developer API Traffic & Security Sniffer"

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("tab", "switch_pane", "Switch Pane"),
        Binding("slash", "toggle_filter", "Filter (/)"),
        Binding("s", "toggle_alerts_only", "Alerts Only (s)"),
        Binding("h", "toggle_hex", "Toggle Hex (h)"),
        Binding("r", "replay_request", "Replay (r)"),
        Binding("d", "view_diff", "Diff (d)"),
        Binding("m", "view_metrics", "Metrics (m)"),
        Binding("y", "copy_curl", "Copy cURL (y)"),
        Binding("Y", "copy_response_body", "Copy Res Body (Y)", show=False),
        Binding("b", "copy_request_body", "Copy Req Body (b)", show=False),
        Binding("u", "copy_url", "Copy URL (u)", show=False),
        Binding("a", "view_alerts", "Alerts (a)"),
        Binding("p", "toggle_pause", "Pause (p)"),
        Binding("c", "clear_flows", "Clear (c)"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, state: TuiState) -> None:
        super().__init__()
        self.state = state
        self.state.on_new_transaction = self._on_new_transaction_threadsafe
        self.table_row_keys = []
        self.latest_replayed: Optional[HttpTransaction] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Packets: 0 | Streams: 0 | Flows: 0 | Alerts: 0", id="stats-banner")
        with Horizontal(id="filter-bar"):
            yield Input(
                placeholder="Filter by method, path, host, or status... (Press Enter or Esc)",
                id="filter-input",
            )

        with Horizontal(id="main-container"):
            with Vertical(id="left-pane"):
                yield DataTable(id="flow-table", cursor_type="row")
            with Vertical(id="right-pane"):
                with VerticalScroll(id="request-pane"):
                    yield Static("Request Inspector", classes="pane-title")
                    yield Static("Select a flow to inspect details.", id="request-content")
                with VerticalScroll(id="response-pane"):
                    yield Static("Response Inspector", classes="pane-title", id="response-title")
                    yield Static("Select a flow to inspect response.", id="response-content")

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#flow-table", DataTable)
        table.add_columns("ID", "Proto", "Method", "Status", "Path", "Host", "Latency", "Alerts")
        self._refresh_table()

    def _refresh_table(self) -> None:
        table = self.query_one("#flow-table", DataTable)
        table.clear()
        self.table_row_keys.clear()

        filtered = self.state.get_filtered_transactions()
        for idx, tx in enumerate(filtered):
            # Status badge
            status_text = Text(str(tx.response_status or "..."))
            if tx.response_status:
                if 200 <= tx.response_status < 300:
                    status_text.stylize("bold green")
                elif 300 <= tx.response_status < 400:
                    status_text.stylize("bold cyan")
                elif 400 <= tx.response_status < 500:
                    status_text.stylize("bold yellow")
                else:
                    status_text.stylize("bold red")

            # Method badge
            method_text = Text(tx.method)
            if tx.method in ("GET", "HEAD"):
                method_text.stylize("bold blue")
            elif tx.method in ("POST", "PUT", "PATCH"):
                method_text.stylize("bold magenta")
            elif tx.method == "DELETE":
                method_text.stylize("bold red")

            # Latency
            latency_str = f"{tx.latency_ms:.0f}ms" if tx.latency_ms is not None else "-"

            # Alerts
            alerts_str = f"🚨 {len(tx.security_alerts)}" if tx.security_alerts else ""

            row_key = table.add_row(
                tx.flow_id,
                tx.protocol.value,
                method_text,
                status_text,
                tx.path[:30],
                tx.host[:25],
                latency_str,
                alerts_str,
            )
            self.table_row_keys.append(row_key)

        self._update_stats_banner()
        self._update_inspectors()

    def _on_new_transaction_threadsafe(self, tx: HttpTransaction) -> None:
        self.call_from_thread(self._refresh_table)

    def _update_stats_banner(self) -> None:
        total = len(self.state.transactions)
        alerts = sum(len(tx.security_alerts) for tx in self.state.transactions)
        filtered = len(self.state.get_filtered_transactions())
        paused = " [PAUSED]" if self.state.capture_paused else ""
        text = f"Flows: {filtered}/{total} | Security Alerts: {alerts}{paused}"
        if self.state.alerts_only:
            text += " | [Filter: ALERTS ONLY]"
        self.query_one("#stats-banner", Static).update(text)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.state.selected_index = event.cursor_row
        self._update_inspectors()

    def on_data_table_cell_highlighted(self, event: DataTable.CellHighlighted) -> None:
        self.state.selected_index = event.coordinate.row
        self._update_inspectors()

    def _update_inspectors(self) -> None:
        tx = self.state.get_selected_transaction()
        req_widget = self.query_one("#request-content", Static)
        res_widget = self.query_one("#response-content", Static)
        res_title = self.query_one("#response-title", Static)

        if not tx:
            req_widget.update("No transaction selected.")
            res_widget.update("No transaction selected.")
            return

        # 1. Format Request View
        req_lines = []
        req_lines.append(
            f"[bold cyan]{tx.method}[/bold cyan] [bold white]{escape(tx.full_url)}[/bold white]"
        )
        req_lines.append(
            f"[dim]Client: {tx.client_endpoint[0]}:{tx.client_endpoint[1]} -> Server: {tx.server_endpoint[0]}:{tx.server_endpoint[1]}[/dim]\n"
        )

        from wiresniffer.decoders.graphql_decoder import inspect_graphql

        gql_meta = inspect_graphql(tx)
        if gql_meta:
            req_lines.append(
                f"[bold magenta]GraphQL Operation:[/bold magenta] [yellow]{gql_meta.operation_type.upper()}[/yellow] [white]{escape(gql_meta.operation_name or '<anonymous>')}[/white]\n"
            )

        if tx.query_params:
            req_lines.append("[bold yellow]Query Parameters:[/bold yellow]")
            for k, v in tx.query_params.items():
                req_lines.append(f"  [cyan]{escape(k)}[/cyan]: {escape(v)}")
            req_lines.append("")

        req_lines.append("[bold yellow]Headers:[/bold yellow]")
        for k, v in tx.request_headers.items():
            req_lines.append(f"  [dim]{escape(k)}:[/dim] {escape(v)}")
        req_lines.append("")

        if tx.request_body:
            req_lines.append(f"[bold yellow]Body ({len(tx.request_body)} bytes):[/bold yellow]")
            parsed_json = tx.request_json()
            if parsed_json is not None:
                try:
                    formatted_json = json.dumps(parsed_json, indent=2)
                    req_lines.append(f"[green]{escape(formatted_json)}[/green]")
                except Exception:
                    req_lines.append(escape(tx.request_body_text))
            else:
                req_lines.append(escape(tx.request_body_text[:2000]))

        req_widget.update("\n".join(req_lines))

        # 2. Format Response View
        res_lines = []
        status_code = tx.response_status or "Awaiting Response..."
        res_lines.append(
            f"[bold]Status:[/bold] [bold green]{status_code}[/bold green] ({escape(tx.response_reason or '')})"
        )
        if tx.latency_ms is not None:
            res_lines.append(f"[bold]Latency:[/bold] {tx.latency_ms:.2f} ms")
        res_lines.append("")

        from wiresniffer.decoders.sse_decoder import is_sse_response, parse_sse_stream

        if is_sse_response(tx):
            sse_sum = parse_sse_stream(tx.response_body)
            res_lines.append(
                f"[bold cyan]Server-Sent Events (SSE) AI Streaming Stream ({sse_sum.total_events} events):[/bold cyan]"
            )
            if sse_sum.accumulated_ai_text:
                res_lines.append(
                    f"[bold green]Reconstructed AI Completion:[/bold green]\n{escape(sse_sum.accumulated_ai_text)}\n"
                )
            res_lines.append("[dim]--- Raw SSE Chunks ---[/dim]")

        if self.state.hex_view_mode:
            res_title.update("Response Inspector [Hex Dump Mode - Press 'h' to toggle]")
            res_lines.append(format_hex_dump(tx.response_body))
        else:
            res_title.update("Response Inspector [Press 'h' for Hex Dump]")
            res_lines.append("[bold yellow]Headers:[/bold yellow]")
            for k, v in tx.response_headers.items():
                res_lines.append(f"  [dim]{escape(k)}:[/dim] {escape(v)}")
            res_lines.append("")

            if tx.response_body and not is_sse_response(tx):
                res_lines.append(
                    f"[bold yellow]Body ({len(tx.response_body)} bytes):[/bold yellow]"
                )
                parsed_json = tx.response_json()
                if parsed_json is not None:
                    try:
                        formatted_json = json.dumps(parsed_json, indent=2)
                        res_lines.append(f"[green]{escape(formatted_json)}[/green]")
                    except Exception:
                        res_lines.append(escape(tx.response_body_text))
                else:
                    res_lines.append(escape(tx.response_body_text[:2000]))

        res_widget.update("\n".join(res_lines))

    def action_cursor_down(self) -> None:
        table = self.query_one("#flow-table", DataTable)
        table.action_cursor_down()

    def action_cursor_up(self) -> None:
        table = self.query_one("#flow-table", DataTable)
        table.action_cursor_up()

    def action_toggle_filter(self) -> None:
        bar = self.query_one("#filter-bar", Horizontal)
        inp = self.query_one("#filter-input", Input)
        if bar.styles.display == "none":
            bar.styles.display = "block"
            inp.focus()
        else:
            bar.styles.display = "none"
            self.query_one("#flow-table", DataTable).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.state.filter_query = event.value
        self.query_one("#filter-bar", Horizontal).styles.display = "none"
        self.query_one("#flow-table", DataTable).focus()
        self._refresh_table()

    def action_toggle_alerts_only(self) -> None:
        self.state.alerts_only = not self.state.alerts_only
        self._refresh_table()

    def action_toggle_hex(self) -> None:
        self.state.hex_view_mode = not self.state.hex_view_mode
        self._update_inspectors()

    def action_copy_curl(self) -> None:
        tx = self.state.get_selected_transaction()
        if tx:
            cmd = generate_curl_command(tx)
            self.notify(f"cURL command: {cmd[:60]}...", title="cURL Export")

    def action_view_alerts(self) -> None:
        tx = self.state.get_selected_transaction()
        if tx and tx.security_alerts:
            self.push_screen(AlertModal(tx))
        else:
            self.notify("No security violations detected on this transaction.", title="Security")

    def action_toggle_pause(self) -> None:
        self.state.capture_paused = not self.state.capture_paused
        self._update_stats_banner()

    def action_clear_flows(self) -> None:
        self.state.clear()
        self._refresh_table()

    def action_replay_request(self) -> None:
        tx = self.state.get_selected_transaction()
        if not tx:
            self.notify("No transaction selected to replay.", title="Replay Error")
            return

        from wiresniffer.replay.engine import replay_transaction

        self.notify(f"Replaying {tx.method} {tx.full_url}...", title="Replaying Request")
        replayed = replay_transaction(tx)
        self.latest_replayed = replayed
        self.state.add_transaction(replayed)
        self.notify(
            f"Replay finished: Status {replayed.response_status} ({replayed.latency_ms:.0f}ms). Press 'd' to view diff.",
            title="Replay Complete",
        )

    def action_view_diff(self) -> None:
        tx = self.state.get_selected_transaction()
        if not tx or not self.latest_replayed:
            self.notify(
                "Press 'r' first to replay a request before viewing diff.", title="Diff Error"
            )
            return

        from wiresniffer.replay.diff import calculate_transaction_diff
        from wiresniffer.tui.screens.diff_modal import DiffModal

        diff = calculate_transaction_diff(tx, self.latest_replayed)
        self.push_screen(DiffModal(diff))

    def action_view_metrics(self) -> None:
        if not self.state.transactions:
            self.notify("No transactions captured yet for metrics.", title="Metrics")
            return

        from wiresniffer.tui.screens.metrics_modal import MetricsModal

        self.push_screen(MetricsModal(self.state.transactions))

    def action_copy_response_body(self) -> None:
        tx = self.state.get_selected_transaction()
        if tx and tx.response_body:
            body = tx.response_body_text
            self.notify(f"Response body copied ({len(body)} chars).", title="Clipboard")
        else:
            self.notify("No response body to copy.", title="Clipboard")

    def action_copy_request_body(self) -> None:
        tx = self.state.get_selected_transaction()
        if tx and tx.request_body:
            body = tx.request_body_text
            self.notify(f"Request body copied ({len(body)} chars).", title="Clipboard")
        else:
            self.notify("No request body to copy.", title="Clipboard")

    def action_copy_url(self) -> None:
        tx = self.state.get_selected_transaction()
        if tx:
            self.notify(f"URL: {tx.full_url}", title="URL")

    def action_switch_pane(self) -> None:
        focused = self.focused
        table = self.query_one("#flow-table", DataTable)
        req = self.query_one("#request-pane", VerticalScroll)
        res = self.query_one("#response-pane", VerticalScroll)

        if focused == table:
            req.focus()
        elif focused == req:
            res.focus()
        else:
            table.focus()
