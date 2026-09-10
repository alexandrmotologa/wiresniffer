"""Detects personally identifiable information (PII) such as credit cards and SSNs."""

import re
from typing import List

from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.security.models import AlertSeverity, SecurityAlert


def luhn_checksum_valid(number_str: str) -> bool:
    """Validate digits using the Luhn mod-10 algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d

    return checksum % 10 == 0


def mask_card(number_str: str) -> str:
    """Mask credit card digits, displaying only the last 4 digits."""
    clean = re.sub(r"\D", "", number_str)
    if len(clean) < 4:
        return "****"
    return f"****-****-****-{clean[-4:]}"


# Match 13 to 19 digit candidate numbers with optional dashes/spaces
CARD_CANDIDATE_REGEX = re.compile(r"\b(?:\d{4}[- ]?){3}\d{1,4}\b|\b\d{13,19}\b")

# Standard SSN pattern
SSN_REGEX = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")


def check_pii_leaks(tx: HttpTransaction) -> List[SecurityAlert]:
    """Inspect request and response bodies for exposed PII."""
    alerts: List[SecurityAlert] = []

    bodies = [
        ("request_body", tx.request_body_text),
        ("response_body", tx.response_body_text),
    ]

    # Credit Card Check
    found_card = False
    for surface_name, text in bodies:
        if found_card or not text:
            continue

        for match in CARD_CANDIDATE_REGEX.finditer(text):
            candidate = match.group(0)
            clean_digits = re.sub(r"\D", "", candidate)
            # Prefix heuristics for major card networks
            if clean_digits[0] in ("3", "4", "5", "6") and luhn_checksum_valid(clean_digits):
                alerts.append(
                    SecurityAlert(
                        rule_id="PII_CREDIT_CARD",
                        severity=AlertSeverity.HIGH,
                        title="Unmasked Credit Card PAN Detected",
                        description=(
                            f"A payment card primary account number (PAN) passing Luhn checksum verification "
                            f"was observed in {surface_name}."
                        ),
                        evidence=f"Card Number: {mask_card(clean_digits)}",
                        remediation="Tokenize card numbers or mask them before logging and transmission (PCI-DSS requirement).",
                        category="Data Privacy",
                    )
                )
                found_card = True
                break

    # SSN Check
    found_ssn = False
    for surface_name, text in bodies:
        if found_ssn or not text:
            continue

        match = SSN_REGEX.search(text)
        if match:
            ssn = match.group(0)
            alerts.append(
                SecurityAlert(
                    rule_id="PII_SSN",
                    severity=AlertSeverity.HIGH,
                    title="Social Security Number (SSN) Pattern Exposed",
                    description=f"A plain Social Security Number pattern was detected in {surface_name}.",
                    evidence=f"SSN: ***-**-{ssn[-4:]}",
                    remediation="Mask or tokenize government identification numbers in API responses.",
                    category="Data Privacy",
                )
            )
            found_ssn = True
            break

    return alerts
