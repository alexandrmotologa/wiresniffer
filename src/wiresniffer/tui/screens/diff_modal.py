"""Modal screen displaying side-by-side or unified transaction differences."""

from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

from wiresniffer.replay.diff import TransactionDiff, format_diff_markup


class DiffModal(ModalScreen):
    """Modal displaying comparison between original and replayed transactions."""

    def __init__(self, diff: TransactionDiff) -> None:
        super().__init__()
        self.diff = diff

    def compose(self) -> ComposeResult:
        markup = format_diff_markup(self.diff)
        content = [
            "[bold cyan]Replay Response Comparison[/bold cyan]\n",
            markup,
            "\n[dim]Press Escape, Enter, or 'q' to return to traffic list[/dim]",
        ]

        with Container(id="modal-dialog"):
            yield VerticalScroll(Static("\n".join(content)))

    def on_key(self, event) -> None:
        if event.key in ("escape", "enter", "q"):
            self.dismiss()
