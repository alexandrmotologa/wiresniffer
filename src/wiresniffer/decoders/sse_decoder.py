"""Server-Sent Events (SSE) streaming decoder and AI completion accumulator."""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from wiresniffer.decoders.base import HttpTransaction


@dataclass
class SseEvent:
    """Represents a single parsed SSE event block."""

    event: str = "message"
    data: str = ""
    event_id: Optional[str] = None
    retry: Optional[int] = None


@dataclass
class SseStreamSummary:
    """Accumulated state and metrics from an SSE stream."""

    total_events: int = 0
    ttft_ms: Optional[float] = None  # Time-to-First-Token
    accumulated_ai_text: str = ""
    events: List[SseEvent] = field(default_factory=list)


def is_sse_response(tx: HttpTransaction) -> bool:
    """Check if the transaction response is an SSE stream."""
    content_type = tx.response_headers.get("content-type", "").lower()
    return "text/event-stream" in content_type


def parse_sse_stream(raw_payload: bytes, req_timestamp: Optional[float] = None) -> SseStreamSummary:
    """Parse raw SSE payload bytes into structured events and extract AI completions.

    Supports OpenAI, Anthropic, Gemini, and standard event-stream payloads.
    """
    summary = SseStreamSummary()
    try:
        text = raw_payload.decode("utf-8", errors="replace")
    except Exception:
        return summary

    lines = text.splitlines()
    current_event = "message"
    current_data_lines: List[str] = []
    current_id = None

    ai_text_parts: List[str] = []

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            # Empty line dispatches current event
            if current_data_lines:
                data_str = "\n".join(current_data_lines)
                summary.total_events += 1
                ev = SseEvent(event=current_event, data=data_str, event_id=current_id)
                summary.events.append(ev)

                # Attempt to extract AI token
                extracted_token = _extract_ai_token(data_str)
                if extracted_token:
                    ai_text_parts.append(extracted_token)

                current_data_lines = []
                current_event = "message"
                current_id = None
            continue

        if line.startswith(":"):
            # SSE comment (often keep-alives or pings)
            continue

        if ":" in line:
            field_name, field_val = line.split(":", 1)
            field_name = field_name.strip()
            if field_val.startswith(" "):
                field_val = field_val[1:]

            if field_name == "event":
                current_event = field_val
            elif field_name == "data":
                current_data_lines.append(field_val)
            elif field_name == "id":
                current_id = field_val

    # Flush final pending event
    if current_data_lines:
        data_str = "\n".join(current_data_lines)
        summary.total_events += 1
        summary.events.append(SseEvent(event=current_event, data=data_str, event_id=current_id))
        extracted_token = _extract_ai_token(data_str)
        if extracted_token:
            ai_text_parts.append(extracted_token)

    summary.accumulated_ai_text = "".join(ai_text_parts)
    return summary


def _extract_ai_token(data_str: str) -> Optional[str]:
    """Attempt to extract text delta from OpenAI / Anthropic / Vercel JSON payloads."""
    data_str = data_str.strip()
    if data_str == "[DONE]":
        return None

    try:
        payload: Dict[str, Any] = json.loads(data_str)

        # 1. OpenAI Chat Completion format: choices[0].delta.content
        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            delta = choices[0].get("delta", {})
            if "content" in delta and delta["content"]:
                return delta["content"]

        # 2. Anthropic format: type == "content_block_delta", delta.text
        if payload.get("type") == "content_block_delta":
            return payload.get("delta", {}).get("text", "")

        # 3. Gemini format: candidates[0].content.parts[0].text
        candidates = payload.get("candidates")
        if isinstance(candidates, list) and candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            if parts and "text" in parts[0]:
                return parts[0]["text"]

    except Exception:
        pass

    return None
