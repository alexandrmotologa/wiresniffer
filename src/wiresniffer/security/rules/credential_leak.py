"""Scans HTTP headers, queries, and payloads for leaked API keys and secrets."""

import re
from typing import List, Tuple

from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.security.models import AlertSeverity, SecurityAlert
from wiresniffer.security.rules.plaintext_auth import mask_secret

PATTERNS: List[Tuple[str, str, AlertSeverity, str, str]] = [
    (
        "CREDENTIAL_LEAK_OPENAI",
        r"\bsk-[a-zA-Z0-9_-]{20,}\b",
        AlertSeverity.CRITICAL,
        "OpenAI API Secret Key Leaked",
        "Revoke and rotate the exposed OpenAI secret key via the OpenAI developer portal.",
    ),
    (
        "CREDENTIAL_LEAK_GITHUB",
        r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|gho_[a-zA-Z0-9]{36})\b",
        AlertSeverity.CRITICAL,
        "GitHub Personal Access Token Leaked",
        "Revoke the token immediately from GitHub Settings -> Developer Settings.",
    ),
    (
        "CREDENTIAL_LEAK_AWS",
        r"\b(AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b",
        AlertSeverity.CRITICAL,
        "AWS Access Key ID Detected",
        "Rotate the IAM access key and check AWS CloudTrail for unauthorized API calls.",
    ),
    (
        "CREDENTIAL_LEAK_STRIPE",
        r"\bsk_live_[0-9a-zA-Z]{24}\b",
        AlertSeverity.CRITICAL,
        "Stripe Live Secret Key Leaked",
        "Immediately roll the compromised key in the Stripe Dashboard to prevent fraudulent charges.",
    ),
    (
        "CREDENTIAL_LEAK_SLACK",
        r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b",
        AlertSeverity.HIGH,
        "Slack Bot/User Token Leaked",
        "Revoke the token from your Slack App management portal.",
    ),
    (
        "CREDENTIAL_LEAK_DATABASE",
        r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:]+:([^@\s]+)@[^/\s]+(?:/[^\s]*)?\b",
        AlertSeverity.CRITICAL,
        "Database URI with Embedded Password Exposed",
        "Remove raw database connection strings from client-facing requests; use backend secrets.",
    ),
    (
        "PRIVATE_KEY_EXPOSURE",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        AlertSeverity.CRITICAL,
        "Cryptographic Private Key Block Exposed",
        "Rotate this cryptographic key immediately. Never transmit private keys over network APIs.",
    ),
]


def check_credential_leaks(tx: HttpTransaction) -> List[SecurityAlert]:
    """Scan request/response headers, paths, queries, and bodies for secrets."""
    alerts: List[SecurityAlert] = []

    # Aggregate text surfaces
    surfaces = [
        ("path", tx.path),
        ("query", " ".join(f"{k}={v}" for k, v in tx.query_params.items())),
        ("request_headers", " ".join(f"{k}: {v}" for k, v in tx.request_headers.items())),
        ("request_body", tx.request_body_text),
        ("response_headers", " ".join(f"{k}: {v}" for k, v in tx.response_headers.items())),
        ("response_body", tx.response_body_text),
    ]

    seen_rules = set()

    for rule_id, regex, severity, title, remediation in PATTERNS:
        compiled = re.compile(regex)
        for surface_name, content in surfaces:
            if not content:
                continue
            match = compiled.search(content)
            if match and rule_id not in seen_rules:
                seen_rules.add(rule_id)
                raw_secret = match.group(0)
                alerts.append(
                    SecurityAlert(
                        rule_id=rule_id,
                        severity=severity,
                        title=title,
                        description=f"Found pattern matching {title} inside {surface_name}.",
                        evidence=f"Matched in {surface_name}: {mask_secret(raw_secret, 8)}",
                        remediation=remediation,
                        category="Secrets",
                    )
                )
                break

    return alerts
