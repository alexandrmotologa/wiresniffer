"""Detects server stack trace leaks, database syntax errors, and permissive CORS."""

import re
from typing import List

from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.security.models import AlertSeverity, SecurityAlert

STACK_TRACE_PATTERNS = [
    (r"Traceback \(most recent call last\):", "Python Stack Trace"),
    (r"org\.springframework\.\w+", "Java/Spring Stack Trace"),
    (r"Exception in thread \"[^\"]+\" java\.lang\.", "Java Runtime Exception Trace"),
    (r"Fatal error: Uncaught Exception:", "PHP Fatal Error Trace"),
    (r"at (?:async )?[a-zA-Z0-9_$.]+\s+\([^)]+:\d+:\d+\)", "Node.js Stack Trace"),
]

SQL_ERROR_PATTERNS = [
    (r"syntax error at or near \"[^\"]+\"", "PostgreSQL Syntax Error"),
    (r"You have an error in your SQL syntax; check the manual", "MySQL Syntax Error"),
    (r"sqlite3\.OperationalError:", "SQLite Operational Error"),
    (r"ORA-\d{5}:", "Oracle Database Error"),
]


def check_info_exposure(tx: HttpTransaction) -> List[SecurityAlert]:
    """Inspect response headers and body for sensitive server information disclosures."""
    alerts: List[SecurityAlert] = []
    resp_text = tx.response_body_text

    # 1. Stack Trace Detection
    for pattern, label in STACK_TRACE_PATTERNS:
        if re.search(pattern, resp_text):
            alerts.append(
                SecurityAlert(
                    rule_id="STACK_TRACE_EXPOSURE",
                    severity=AlertSeverity.MEDIUM,
                    title=f"Server Information Disclosure: {label}",
                    description=(
                        "An unhandled application exception or stack trace was returned to the client. "
                        "Stack traces reveal internal file paths, module versions, and implementation logic."
                    ),
                    evidence=f"Matched: {label}",
                    remediation="Configure a generic error handler in production to return friendly error messages.",
                    category="Information Leak",
                )
            )
            break

    # 2. SQL Error Detection
    for pattern, label in SQL_ERROR_PATTERNS:
        if re.search(pattern, resp_text):
            alerts.append(
                SecurityAlert(
                    rule_id="SQL_ERROR_EXPOSURE",
                    severity=AlertSeverity.HIGH,
                    title=f"Database Query Error Disclosure: {label}",
                    description=(
                        "A raw database syntax error was returned in the API response. "
                        "This indicates potential SQL injection vulnerability or poor error sanitation."
                    ),
                    evidence=f"Matched: {label}",
                    remediation="Use parameterized queries / ORMs and suppress internal database errors.",
                    category="Information Leak",
                )
            )
            break

    # 3. Permissive CORS Check
    origin = tx.response_headers.get("Access-Control-Allow-Origin", "").strip()
    credentials = tx.response_headers.get("Access-Control-Allow-Credentials", "").strip().lower()

    if origin == "*" and credentials == "true":
        alerts.append(
            SecurityAlert(
                rule_id="INSECURE_CORS_WILDCARD",
                severity=AlertSeverity.LOW,
                title="Insecure Wildcard CORS Origin with Credentials",
                description=(
                    "The API returns 'Access-Control-Allow-Origin: *' while allowing credentials. "
                    "Modern browsers reject this, and it violates CORS security policy."
                ),
                evidence="Origin: *, Credentials: true",
                remediation="Specify explicit trusted origin domains rather than wildcard '*'.",
                category="Configuration",
            )
        )

    return alerts
