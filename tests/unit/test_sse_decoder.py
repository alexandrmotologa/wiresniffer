"""Unit tests for Server-Sent Events (SSE) decoder and AI stream accumulator."""

from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.decoders.sse_decoder import is_sse_response, parse_sse_stream


def test_is_sse_response():
    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        response_headers={"content-type": "text/event-stream; charset=utf-8"},
    )
    assert is_sse_response(tx) is True

    tx_json = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        response_headers={"content-type": "application/json"},
    )
    assert is_sse_response(tx_json) is False


def test_parse_openai_sse_stream():
    payload = (
        b": keep-alive ping\n\n"
        b'data: {"choices": [{"delta": {"content": "Hello "}}]}\n\n'
        b'data: {"choices": [{"delta": {"content": "World!"}}]}\n\n'
        b"data: [DONE]\n\n"
    )

    summary = parse_sse_stream(payload)
    assert summary.total_events == 3
    assert summary.accumulated_ai_text == "Hello World!"


def test_parse_anthropic_sse_stream():
    payload = (
        b"event: content_block_delta\n"
        b'data: {"type": "content_block_delta", "delta": {"text": "Antigravity"}}\n\n'
        b"event: content_block_delta\n"
        b'data: {"type": "content_block_delta", "delta": {"text": " Engine"}}\n\n'
    )

    summary = parse_sse_stream(payload)
    assert summary.total_events == 2
    assert summary.accumulated_ai_text == "Antigravity Engine"
    assert summary.events[0].event == "content_block_delta"


def test_parse_gemini_sse_stream():
    payload = (
        b'data: {"candidates": [{"content": {"parts": [{"text": "DeepMind "}]}}]}\n\n'
        b'data: {"candidates": [{"content": {"parts": [{"text": "WireSniffer"}]}}]}\n\n'
    )

    summary = parse_sse_stream(payload)
    assert summary.total_events == 2
    assert summary.accumulated_ai_text == "DeepMind WireSniffer"
