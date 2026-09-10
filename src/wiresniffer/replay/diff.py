"""Response comparison and difference calculation."""

import difflib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from wiresniffer.decoders.base import HttpTransaction


@dataclass
class TransactionDiff:
    """Structured delta between two HTTP transactions."""

    original_status: Optional[int]
    replayed_status: Optional[int]
    status_changed: bool
    headers_added: Dict[str, str] = field(default_factory=dict)
    headers_removed: Dict[str, str] = field(default_factory=dict)
    headers_modified: Dict[str, Dict[str, str]] = field(default_factory=dict)
    body_diff_lines: List[str] = field(default_factory=list)
    is_identical: bool = False


def calculate_transaction_diff(
    original: HttpTransaction,
    replayed: HttpTransaction,
) -> TransactionDiff:
    """Compare two transactions and compute their differences."""
    status_changed = original.response_status != replayed.response_status

    # Headers comparison
    orig_headers = {k.lower(): v for k, v in original.response_headers.items()}
    repl_headers = {k.lower(): v for k, v in replayed.response_headers.items()}

    added = {k: repl_headers[k] for k in repl_headers if k not in orig_headers}
    removed = {k: orig_headers[k] for k in orig_headers if k not in repl_headers}
    modified = {
        k: {"original": orig_headers[k], "replayed": repl_headers[k]}
        for k in orig_headers
        if k in repl_headers and orig_headers[k] != repl_headers[k]
    }

    # Body comparison
    orig_body_str = original.response_body_text
    repl_body_str = replayed.response_body_text

    # Format JSON if applicable
    orig_json = original.response_json()
    repl_json = replayed.response_json()

    if orig_json is not None:
        orig_body_str = json.dumps(orig_json, indent=2)
    if repl_json is not None:
        repl_body_str = json.dumps(repl_json, indent=2)

    diff_lines = list(
        difflib.unified_diff(
            orig_body_str.splitlines(),
            repl_body_str.splitlines(),
            fromfile="original",
            tofile="replayed",
            lineterm="",
        )
    )

    is_identical = (
        not status_changed and not added and not removed and not modified and not diff_lines
    )

    return TransactionDiff(
        original_status=original.response_status,
        replayed_status=replayed.response_status,
        status_changed=status_changed,
        headers_added=added,
        headers_removed=removed,
        headers_modified=modified,
        body_diff_lines=diff_lines,
        is_identical=is_identical,
    )


def format_diff_markup(diff: TransactionDiff) -> str:
    """Render TransactionDiff as formatted Rich markup."""
    lines = []

    if diff.is_identical:
        return "[bold green]✔ Responses are 100% identical.[/bold green]"

    # Status
    if diff.status_changed:
        lines.append(
            f"[bold]Status Code Changed:[/bold] [red]{diff.original_status}[/red] -> [green]{diff.replayed_status}[/green]\n"
        )
    else:
        lines.append(f"[bold]Status Code:[/bold] {diff.replayed_status} (unchanged)\n")

    # Headers
    if diff.headers_added or diff.headers_removed or diff.headers_modified:
        lines.append("[bold yellow]Header Differences:[/bold yellow]")
        for k, v in diff.headers_added.items():
            lines.append(f"  [green]+ {k}: {v}[/green]")
        for k, v in diff.headers_removed.items():
            lines.append(f"  [red]- {k}: {v}[/red]")
        for k, vals in diff.headers_modified.items():
            lines.append(
                f"  [cyan]~ {k}: [red]{vals['original']}[/red] -> [green]{vals['replayed']}[/green][/cyan]"
            )
        lines.append("")

    # Body Diff
    if diff.body_diff_lines:
        lines.append("[bold yellow]Body Delta (Unified Diff):[/bold yellow]")
        for line in diff.body_diff_lines:
            if line.startswith("+"):
                lines.append(f"[green]{line}[/green]")
            elif line.startswith("-"):
                lines.append(f"[red]{line}[/red]")
            elif line.startswith("@"):
                lines.append(f"[cyan]{line}[/cyan]")
            else:
                lines.append(f"[dim]{line}[/dim]")
    else:
        lines.append("[dim]Body is identical.[/dim]")

    return "\n".join(lines)
