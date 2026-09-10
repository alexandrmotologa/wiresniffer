"""JSON Web Token (JWT) inspection for expiration, alg:none, and sensitive claims."""

import base64
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.security.models import AlertSeverity, SecurityAlert

JWT_REGEX = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?")


def decode_jwt_segment(segment: str) -> Optional[Dict[str, Any]]:
    """Decode a base64url encoded JWT segment (header or payload)."""
    padding = len(segment) % 4
    if padding > 0:
        segment += "=" * (4 - padding)
    try:
        raw_bytes = base64.urlsafe_b64decode(segment.encode("ascii"))
        return json.loads(raw_bytes.decode("utf-8"))
    except Exception:
        return None


def parse_jwt(token: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Split and decode JWT into (header, payload)."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    header = decode_jwt_segment(parts[0])
    payload = decode_jwt_segment(parts[1])
    if header is not None and payload is not None:
        return header, payload
    return None


def check_jwt_tokens(tx: HttpTransaction) -> List[SecurityAlert]:
    """Inspect request and response surfaces for insecure or expired JWTs."""
    alerts: List[SecurityAlert] = []

    surfaces = [
        ("request_headers", " ".join(f"{k}: {v}" for k, v in tx.request_headers.items())),
        ("request_body", tx.request_body_text),
        ("response_headers", " ".join(f"{k}: {v}" for k, v in tx.response_headers.items())),
        ("response_body", tx.response_body_text),
    ]

    seen_tokens = set()
    now = time.time()

    for surface_name, content in surfaces:
        if not content:
            continue

        for match in JWT_REGEX.finditer(content):
            token_str = match.group(0)
            if token_str in seen_tokens:
                continue
            seen_tokens.add(token_str)

            parsed = parse_jwt(token_str)
            if not parsed:
                continue

            header, payload = parsed

            # 1. Check alg: none
            alg = str(header.get("alg", "")).lower()
            if alg in ("none", ""):
                alerts.append(
                    SecurityAlert(
                        rule_id="INSECURE_JWT_ALG_NONE",
                        severity=AlertSeverity.HIGH,
                        title="Unsigned JWT (alg: none) Detected",
                        description=(
                            "The JWT header explicitly declares algorithm 'none', meaning the token is not "
                            "digitally signed and can be forged by any client."
                        ),
                        evidence=f"Header: {json.dumps(header)}",
                        remediation="Enforce cryptographic signature algorithms (RS256 or ES256) on authentication servers.",
                        category="Token Security",
                    )
                )

            # 2. Check expiration
            exp = payload.get("exp")
            if isinstance(exp, (int, float)):
                if exp < now:
                    alerts.append(
                        SecurityAlert(
                            rule_id="EXPIRED_JWT",
                            severity=AlertSeverity.MEDIUM,
                            title="Expired JWT Transmitted",
                            description=(
                                f"The JWT expired at Unix timestamp {int(exp)}, which is in the past. "
                                f"Client is actively transmitting stale session tokens."
                            ),
                            evidence=f"Token sub: {payload.get('sub', 'N/A')}, exp: {int(exp)}",
                            remediation="Implement automatic token refresh on clients and reject expired tokens on APIs.",
                            category="Token Security",
                        )
                    )

            # 3. Sensitive claims in payload
            sensitive_keys = {"password", "secret", "ssn", "credit_card", "pass", "pwd"}
            found_sensitive = [k for k in payload.keys() if k.lower() in sensitive_keys]
            if found_sensitive:
                alerts.append(
                    SecurityAlert(
                        rule_id="SENSITIVE_JWT_PAYLOAD",
                        severity=AlertSeverity.MEDIUM,
                        title="Sensitive Data Stored in JWT Payload",
                        description=(
                            f"The JWT contains sensitive keys ({', '.join(found_sensitive)}). "
                            f"JWT payloads are Base64 encoded and publicly readable by anyone who handles the token."
                        ),
                        evidence=f"Sensitive keys: {found_sensitive}",
                        remediation="Store sensitive information in server-side session stores, never in JWT claims.",
                        category="Token Security",
                    )
                )

    return alerts
