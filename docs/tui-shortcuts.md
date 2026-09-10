# Terminal UI Shortcut Reference

WireSniffer provides an interactive terminal user interface inspired by LazyGit.

## General Navigation

| Key | Description |
| --- | --- |
| `j` / `Down` | Move selection down in the flow table |
| `k` / `Up` | Move selection up in the flow table |
| `g` / `Home` | Jump to the first flow |
| `G` / `End` | Jump to the latest flow |
| `Tab` | Switch focus between panels (Traffic, Request, Response) |
| `Shift+Tab` | Switch focus in reverse |
| `Enter` | Expand or inspect selected flow details |
| `q` | Quit WireSniffer |

## Filtering and Search

| Key | Description |
| --- | --- |
| `/` | Activate structured query filter input bar |
| `Esc` | Clear active filter and dismiss modals |
| `s` | Toggle filter: show only flows with security alerts |
| `1` | Filter by status 2xx (Success) |
| `4` | Filter by status 4xx (Client Errors) |
| `5` | Filter by status 5xx (Server Errors) |

### Structured Query Filter Syntax

The query input bar (`/`) supports structured predicates combined with spaces:

- `status:200`, `status:4xx`, `status:>=400`, `status:<300`
- `latency:>200ms`, `latency:<=50`
- `method:POST`, `method:GET`
- `proto:http2`, `proto:grpc`, `proto:ws`
- `header:authorization`, `header:content-type=application/json`
- `alert:any`, `alert:critical`, `alert:high`
- `json:user.id=42`, `json:errors`
- Free text search across URLs, paths, methods, and body payloads

## Inspector, Actions, and Modals

| Key | Description |
| --- | --- |
| `r` | Replay selected HTTP transaction against target server |
| `d` | Open diff modal comparing captured response with replayed response |
| `m` | Open traffic metrics and latency percentiles (p50/p95/p99) modal |
| `h` | Toggle between formatted body and side-by-side hex/ASCII view |
| `y` | Copy selected transaction as a reproducible `curl` command |
| `Y` | Copy raw request payload to system clipboard |
| `b` | Copy response body to system clipboard |
| `u` | Copy target URL to system clipboard |
| `e` | Open export dialog (HAR 1.2, PCAP, JSONL) |
| `a` | Open security vulnerability details modal |
| `p` | Pause or resume live network packet capture |
| `c` | Clear captured flows from screen buffer |

## Command-Line Arguments

WireSniffer supports standard CLI flags when starting the TUI:

```bash
# Sniff on specific interface and ports
wiresniffer sniff --interface lo --port 8080 --port 3000

# Apply custom BPF filter
wiresniffer sniff --filter "tcp and dst port 8000"

# Open directly with security filter enabled
wiresniffer sniff --alerts-only

# Run without TUI (stdout streaming)
wiresniffer sniff --no-tui
```
