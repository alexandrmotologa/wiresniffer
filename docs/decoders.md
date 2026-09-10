# Protocol Decoders

WireSniffer inspects raw TCP byte streams and reconstructs high-level application messages across five primary protocols.

## 1. HTTP/1.1 Decoder

The HTTP/1.1 decoder parses plain text ASCII/UTF-8 streams:
- **Request Parsing**: Extracts HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD), URI path, query parameters, and header dictionaries.
- **Response Parsing**: Extracts HTTP status code (200, 404, 500), status reason phrase, and headers.
- **Framing Modes**:
  - `Content-Length`: Reads exact byte lengths declared in headers.
  - `Transfer-Encoding: chunked`: Reads hex chunk size prefixes, unchunks payloads, and strips trailing chunk markers.
  - Connection close: Consumes data until the TCP connection closes.
- **Decompression**: Automatically decompresses bodies encoded with `gzip` and `deflate`.

## 2. HTTP/2 (Cleartext h2c) Decoder

The HTTP/2 decoder parses binary framing defined in RFC 7540:
- **Connection Preface**: Identifies the 24-byte client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).
- **Frame Parser**: Processes 9-byte frame headers (length, type, flags, stream ID). Decodes:
  - `SETTINGS`: Captures stream concurrency and window parameters.
  - `HEADERS`: Decompresses pseudo-headers (`:method`, `:path`, `:status`, `:scheme`) and standard headers using an internal HPACK dynamic table.
  - `DATA`: Reconstructs stream-multiplexed message bodies.
  - `RST_STREAM`: Flushes or terminates aborted streams.

## 3. WebSocket Decoder

The WebSocket decoder handles full-duplex framing over upgraded HTTP/1.1 connections:
- **Handshake Verification**: Detects `Upgrade: websocket` and `Sec-WebSocket-Key` headers.
- **Frame Decoding**: Decodes WebSocket frame headers (FIN bit, opcode, mask flag, payload length).
- **Client Unmasking**: Applies the 4-byte client masking key with XOR transformation to reveal the original payload.
- **Opcodes**: Handles text (opcode 0x1), binary (opcode 0x2), close (opcode 0x8), ping (opcode 0x9), and pong (opcode 0xA).

## 4. gRPC Protocol Buffers Decoder

gRPC runs over HTTP/2 streams with `content-type: application/grpc`:
- **Envelope Unwrapping**: Strips the 5-byte gRPC framing header (1 compression flag byte + 4-byte big-endian message length).
- **Protobuf Wire Inspection**: Parses binary protobuf fields (varints, 64-bit integers, length-delimited strings/embedded messages, 32-bit words) without requiring compiled `.proto` schema files.
- **Status Codes**: Extracts `grpc-status` (0 OK, 7 PERMISSION_DENIED, 16 UNAUTHENTICATED) and `grpc-message` trailer headers.

## 5. TLS Server Name Indication (SNI) Extractor

For encrypted HTTPS traffic over port 443, WireSniffer extracts host metadata from the plaintext handshake:
- **Record Header**: Matches ContentType 22 (Handshake).
- **ClientHello**: Parses the ClientHello message structure, identifies extension 0x0000 (server_name), and extracts the target domain name.
- **Metadata**: Records the target hostname, advertised TLS version, and supported cipher suites while leaving encrypted payloads untouched.
