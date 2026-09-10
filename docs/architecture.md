# WireSniffer Architecture

WireSniffer captures raw network packets, reassembles bidirectional TCP byte streams, and decodes application protocols without proxy configurations.

```
                    ┌────────────────────────┐
                    │ Network Socket / PCAP  │
                    └───────────┬────────────┘
                                │ Raw Packets (Ethernet / IP / TCP)
                                ▼
                    ┌────────────────────────┐
                    │ Capture & BPF Filter   │
                    └───────────┬────────────┘
                                │ Filtered TCP Segments
                                ▼
                    ┌────────────────────────┐
                    │ TCP Stream Resequencer │
                    │ (4-tuple Flow Tracker) │
                    └───────────┬────────────┘
                                │ Contiguous Byte Streams
                                ▼
                    ┌────────────────────────┐
                    │   Protocol Decoders    │
                    │ HTTP/1.1, H2, WS, gRPC │
                    └─────┬────────────┬─────┘
                          │            │
         Reconstructed    │            │ Decoded Payloads
         Transactions     ▼            ▼
             ┌────────────────┐   ┌───────────────────────────┐
             │ Textual TUI /  │   │ Security Heuristics       │
             │ HAR Exporters  │◄──┤ Plaintext Auth, PII, JWT  │
             └────────────────┘   └───────────────────────────┘
```

## Ingestion Layer

The ingestion subsystem captures raw packets using two mechanisms:
1. **Live Socket Sniffing**: Uses Scapy with Berkeley Packet Filters (BPF) to intercept traffic on designated interfaces (`lo`, `docker0`, `eth0`). When running without pcap drivers, an asynchronous raw socket fallback handles loopback traffic.
2. **Offline File Ingestion**: Ingests recorded `.pcap` or `.pcapng` capture files, streaming them sequentially through the reassembly pipeline. This mode requires no administrative privileges and operates identically across Windows, macOS, and Linux.

## TCP Stream Resequencer

Network packets often arrive out of sequence, contain duplicate retransmissions, or split single application payloads across multiple MTU windows.

The reassembly engine manages connections using a 4-tuple key: `(source_ip, source_port, destination_ip, destination_port)`.

Each direction maintains:
- `expected_seq`: The next expected continuous TCP byte sequence number.
- `segment_buffer`: A priority queue of segments indexed by their sequence number.
- `state`: TCP handshake state (`SYN_SENT`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`).

When a segment arrives:
1. If `seq == expected_seq`, the payload passes immediately to the protocol parser, and `expected_seq` advances by payload length.
2. If `seq > expected_seq`, the packet is held in `segment_buffer`.
3. If `seq < expected_seq`, the payload is discarded as a duplicate retransmission, or trimmed if it overlaps.
4. After processing, the buffer is checked. Any newly contiguous segments are flushed in order.

When a `FIN` or `RST` flag appears, the stream marks connection closure and signals the active decoder to complete any pending message pairs.

## Flow Tracking and Latency

HTTP and RPC protocols operate on request-response lifecycles. WireSniffer correlates requests and responses across bidirectional streams:
- The client-to-server direction receives the request, parses headers and body, assigns a unique `flow_id`, and records a high-resolution start timestamp.
- The server-to-client direction parses the response, matches it to the pending request on that 4-tuple, and computes round-trip latency (`response_time - request_time`).
- The matched flow emits to the security engine and user interface.
