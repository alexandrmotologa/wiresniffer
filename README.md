# WireSniffer

WireSniffer is an API traffic inspector and security sniffer for developers. It captures network traffic directly from local sockets, loopback interfaces, and container bridges. You do not need to configure an HTTP proxy, modify system certificates, or adjust environment variables in your application.

WireSniffer reassembles TCP streams into complete HTTP/1.1, HTTP/2, WebSocket, and gRPC exchanges. It inspects payloads in real time for leaked credentials, plaintext tokens, Luhn-valid credit card numbers, and expired JWTs, presenting the data in a keyboard-driven terminal user interface.

## Key Capabilities

- **Zero-config socket inspection**: Captures packets on loopback (`127.0.0.1`), Docker bridges (`docker0`), or local Ethernet adapters without proxy settings.
- **TCP stream reassembly**: Resequences out-of-order segments, eliminates duplicate retransmissions, and matches request/response pairs across connection lifecycles.
- **Multi-protocol decoding**:
  - HTTP/1.1: Parses methods, headers, chunked transfer encoding, gzip/deflate decompression, and measures latency.
  - HTTP/2: Parses cleartext `h2c` frames (HEADERS, DATA, SETTINGS) and maintains dynamic HPACK tables.
  - Server-Sent Events (SSE) & AI Streaming: Parses live token streams for OpenAI, Anthropic, and Gemini completions, reconstructing the full generated response text.
  - GraphQL Inspector: Extracts operation types (query, mutation, subscription), operation names, variables, and detects active schema introspection or field suggestions.
  - WebSocket: Detects upgrade handshakes, unmasks client payloads, and decodes text and binary frames.
  - gRPC: Unwraps length-delimited envelopes and decodes Protobuf wire fields into JSON structures.
  - TLS SNI: Extracts domain names from `ClientHello` packets without decrypting encrypted traffic.
- **Real-time security scanner**:
  - Flags Basic Auth credentials and Bearer tokens sent over unencrypted HTTP.
  - Detects API keys with high entropy: OpenAI, GitHub, AWS, Stripe, Slack, and database credentials.
  - Validates credit card numbers with the Luhn checksum algorithm and detects SSN patterns.
  - Decodes JWT tokens to verify expiration timestamps (`exp`) and flags insecure algorithms (`none`).
  - Alerts on exposed stack traces (Python tracebacks, Spring Boot error pages, SQL errors).
  - Enforces custom team policies loaded from `.wiresniffer.yaml` (required headers, forbidden tokens, custom regexes).
- **Interactive Replay and Diff Engine**:
  - Re-issues captured HTTP requests against live or staging servers with a single keypress (`r`).
  - Calculates status code changes, added/removed headers, and unified line-by-line body diffs (`d`).
- **Traffic and Latency Analytics**:
  - Calculates p50, p95, and p99 latency percentiles, response size averages, and error rates per endpoint (`m` or `wiresniffer metrics`).
- **LazyGit-style terminal UI**:
  - Status-coded traffic stream (2xx green, 3xx cyan, 4xx yellow, 5xx red).
  - Split request and response inspectors with formatted JSON tree views and synchronized hex/ASCII viewer.
  - Structured query filtering (`status:>=400`, `latency:>200ms`, `header:x`, `json:path=val`, `alert:critical`).
- **Export and automation**:
  - Generates standalone security audit reports in HTML and Markdown mapped to OWASP API Security Top 10 and CWE IDs (`wiresniffer report`).
  - Exports sessions to standard HAR 1.2 format for import into Chrome DevTools or Postman.
  - Copies requests as `curl` commands (`y`), raw request bytes (`Y`), response bodies (`b`), or full URLs (`u`).
  - Runs in headless scan mode (`wiresniffer scan`) inside CI pipelines to catch leaks during automated tests.

## Installation

### From Source

Ensure Python 3.12 or newer is installed.

```bash
git clone https://github.com/alexandrmotologa/wiresniffer.git
cd wiresniffer
pip install -e .
```

### Using uv

```bash
uv venv
uv pip install -e ".[dev]"
```

### Docker

```bash
docker build -t wiresniffer .
docker run --rm -it --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW wiresniffer
```

> Note: Live packet capture on raw network interfaces requires root or `CAP_NET_RAW` privileges on Linux, and administrator privileges with Npcap on Windows. Offline PCAP file inspection and synthetic tests run without elevated privileges.

## Quick Start

### 1. Sniff Local API Calls Interactively

Start WireSniffer on your local loopback interface:

```bash
wiresniffer sniff --interface lo --port 8080
```

On Windows:

```bash
wiresniffer sniff --port 8080
```

### 2. Inspect an Existing PCAP Capture

```bash
wiresniffer inspect capture.pcap
```

### 3. Generate an OWASP Security Audit Report

```bash
wiresniffer report capture.pcap --output security-audit.html --format html
```

Or as Markdown for pull request comments:

```bash
wiresniffer report capture.pcap --output audit.md --format md
```

### 4. Analyze Performance and Latency Metrics

```bash
wiresniffer metrics capture.pcap
```

### 5. Replay Captured Requests and Inspect Diffs

```bash
wiresniffer replay capture.pcap --flow 0 --url http://staging.internal/api/v1
```

### 6. Run as a CI Security Gate

Scan a network capture during end-to-end integration tests. Exit with status 1 if any high-severity credentials or credit cards leak:

```bash
wiresniffer scan traffic.pcap --fail-on high
```

## Terminal UI Navigation

| Key | Action |
| --- | --- |
| `j` / `k` or `Down` / `Up` | Navigate through captured flows |
| `Tab` / `Shift+Tab` | Switch focus between panels (Flows, Request, Response) |
| `/` | Open query filter input (`status:>=400`, `latency:>200ms`, `alert:any`) |
| `r` | Replay selected HTTP transaction against target server |
| `d` | Open diff modal to inspect changes between original and replayed response |
| `m` | Open traffic metrics and latency percentiles dashboard |
| `s` | Toggle security alerts filter |
| `h` | Toggle hex viewer in response panel |
| `y` | Copy selected request as a reproducible `curl` command |
| `Y` | Copy raw request payload to clipboard |
| `b` | Copy response body to clipboard |
| `u` | Copy endpoint URL to clipboard |
| `e` | Export captured session (HAR, PCAP, JSONL) |
| `p` | Pause or resume live capture |
| `c` | Clear capture buffer |
| `q` | Quit WireSniffer |

## Documentation

Detailed architectural and decoder references are available in the `docs` directory:

- [Architecture Guide](docs/architecture.md): Packet ingestion, sliding window reassembly, and state machines.
- [Protocol Decoders](docs/decoders.md): Technical details for HTTP/1.1, HTTP/2, WebSocket, gRPC, and TLS SNI.
- [Security Rules](docs/security-rules.md): Rule definitions, severity levels, and detection heuristics.
- [TUI Shortcut Reference](docs/tui-shortcuts.md): Keybindings and configuration settings.

## License

WireSniffer is licensed under the MIT License. See [LICENSE](LICENSE) for details.
