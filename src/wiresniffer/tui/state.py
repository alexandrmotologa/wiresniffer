"""Shared state for the WireSniffer Textual terminal interface."""

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from wiresniffer.decoders.base import HttpTransaction


@dataclass
class TuiState:
    """Reactive state container for the TUI."""

    transactions: List[HttpTransaction] = field(default_factory=list)
    selected_index: int = 0
    filter_query: str = ""
    alerts_only: bool = False
    hex_view_mode: bool = False
    capture_paused: bool = False

    # Callbacks
    on_new_transaction: Optional[Callable[[HttpTransaction], None]] = None

    def add_transaction(self, tx: HttpTransaction) -> None:
        """Append transaction and notify listeners."""
        self.transactions.append(tx)
        if self.on_new_transaction:
            self.on_new_transaction(tx)

    def get_filtered_transactions(self) -> List[HttpTransaction]:
        """Return transactions matching the active filter and alerts criteria."""
        results = self.transactions

        if self.alerts_only:
            results = [tx for tx in results if tx.security_alerts]

        if self.filter_query.strip():
            q = self.filter_query.strip().lower()
            filtered = []
            for tx in results:
                match = (
                    q in tx.method.lower()
                    or q in tx.path.lower()
                    or q in tx.host.lower()
                    or (tx.response_status and q in str(tx.response_status))
                    or q in tx.protocol.value.lower()
                )
                if match:
                    filtered.append(tx)
            results = filtered

        return results

    def get_selected_transaction(self) -> Optional[HttpTransaction]:
        """Return currently highlighted transaction."""
        filtered = self.get_filtered_transactions()
        if 0 <= self.selected_index < len(filtered):
            return filtered[self.selected_index]
        return None

    def clear(self) -> None:
        """Clear all transactions."""
        self.transactions.clear()
        self.selected_index = 0
