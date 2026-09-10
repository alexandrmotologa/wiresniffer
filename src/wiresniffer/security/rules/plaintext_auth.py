"""Detects unencrypted authentication credentials and tokens over cleartext HTTP."""

import base64
from typing import List

from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.security.models import AlertSeverity, SecurityAlert


def mask_secret(secret: str, visible_chars: int = 4) -> str:
    """Mask sensitive string, leaving first few characters visible."""
    if len(secret) <= visible_chars:
        return "*" * len(secret)
    return secret[:visible_chars] + "*" * (len(secret) - visible_chars)


def check_plaintext_auth(tx: HttpTransaction) -> List[SecurityAlert]:
    """Inspect request headers for cleartext authentication."""
    alerts: List[SecurityAlert] = []

    is_cleartext = tx.server_endpoint[1] not in (443, 8443)

    for header_name, header_val in tx.request_headers.items():
        if header_name.lower() != "authorization":
            continue

        val_lower = header_val.strip().lower()

        if val_lower.startswith("basic "):
            encoded = header_val.strip()[6:].strip()
            decoded_str = "<unparseable>"
            try:
                decoded_bytes = base64.b64decode(encoded)
                decoded_str = decoded_bytes.decode("utf-8", errors="replace")
            except Exception:
                pass

            if ":" in decoded_str:
                username, password = decoded_str.split(":", 1)
                evidence = (
                    f"Decoded Basic Auth -> user: {username}, password: {mask_secret(password)}"
                )
            else:
                evidence = f"Decoded Basic Auth -> {mask_secret(decoded_str)}"

            alerts.append(
                SecurityAlert(
                    rule_id="PLAINTEXT_BASIC_AUTH",
                    severity=AlertSeverity.CRITICAL if is_cleartext else AlertSeverity.MEDIUM,
                    title="Plaintext Basic Auth Header Detected",
                    description=(
                        "Basic Auth transmits credentials encoded with simple Base64 rather than encryption. "
                        "Anyone with network access can decode username and password immediately."
                    ),
                    evidence=evidence,
                    remediation="Use TLS (HTTPS) and transition to token-based authentication (OAuth2 / OIDC).",
                    category="Authentication",
                )
            )

        elif val_lower.startswith("bearer ") and is_cleartext:
            token = header_val.strip()[7:].strip()
            alerts.append(
                SecurityAlert(
                    rule_id="PLAINTEXT_BEARER_TOKEN",
                    severity=AlertSeverity.HIGH,
                    title="Bearer Token Transmitted over Cleartext HTTP",
                    description=(
                        "Bearer token transmitted over unencrypted HTTP port. An attacker on the local network "
                        "can intercept this token and impersonate the caller."
                    ),
                    evidence=f"Bearer {mask_secret(token, 6)}",
                    remediation="Enforce HTTPS for all endpoints accepting Bearer tokens.",
                    category="Authentication",
                )
            )

    return alerts
