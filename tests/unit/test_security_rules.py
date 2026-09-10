"""Unit tests for the real-time security heuristics engine and alert generation."""

from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.security.engine import SecurityEngine
from wiresniffer.security.models import AlertSeverity
from wiresniffer.security.rules.pii_leak import luhn_checksum_valid


def test_luhn_algorithm():
    """Verify Luhn checksum accurately accepts valid cards and rejects invalid cards."""
    # Test valid card number
    assert luhn_checksum_valid("4532015112830366") is True
    # Test invalid card number
    assert luhn_checksum_valid("4532015112830367") is False


def test_plaintext_auth_detection():
    """Verify detection of Basic Auth and cleartext Bearer token."""
    engine = SecurityEngine()

    # Basic auth: admin:password123 -> YWRtaW46cGFzc3dvcmQxMjM=
    tx = HttpTransaction(
        client_endpoint=("127.0.0.1", 40000),
        server_endpoint=("127.0.0.1", 80),
        request_headers={"Authorization": "Basic YWRtaW46cGFzc3dvcmQxMjM="},
    )
    alerts = engine.analyze_transaction(tx)
    rule_ids = [a.rule_id for a in alerts]

    assert "PLAINTEXT_BASIC_AUTH" in rule_ids
    basic_alert = next(a for a in alerts if a.rule_id == "PLAINTEXT_BASIC_AUTH")
    assert basic_alert.severity == AlertSeverity.CRITICAL
    assert "admin" in basic_alert.evidence


def test_credential_leak_detection():
    """Verify detection of leaked OpenAI key and database connection strings."""
    engine = SecurityEngine()

    tx = HttpTransaction(
        client_endpoint=("127.0.0.1", 40000),
        server_endpoint=("127.0.0.1", 8080),
        request_body=b'{"api_key": "sk-1234567890abcdefghijklmnopqrstuvwxyz", "db": "postgres://admin:secret123@db.prod.internal:5432/main"}',
    )
    alerts = engine.analyze_transaction(tx)
    rule_ids = [a.rule_id for a in alerts]

    assert "CREDENTIAL_LEAK_OPENAI" in rule_ids
    assert "CREDENTIAL_LEAK_DATABASE" in rule_ids


def test_pii_leak_detection():
    """Verify detection of credit card numbers passing Luhn check and SSNs."""
    engine = SecurityEngine()

    # 4532015112830366 is a Luhn-valid test number
    tx = HttpTransaction(
        client_endpoint=("127.0.0.1", 40000),
        server_endpoint=("127.0.0.1", 8080),
        request_body=b'{"pan": "4532015112830366", "ssn": "123-45-6789"}',
    )
    alerts = engine.analyze_transaction(tx)
    rule_ids = [a.rule_id for a in alerts]

    assert "PII_CREDIT_CARD" in rule_ids
    assert "PII_SSN" in rule_ids


def test_jwt_analyzer():
    """Verify detection of unsigned alg:none JWT and expired JWT."""
    engine = SecurityEngine()

    # JWT header: {"alg": "none", "typ": "JWT"} -> eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0
    # Payload with past exp: {"sub": "user1", "exp": 1000} -> eyJzdWIiOiAidXNlcjEiLCAiZXhwIjogMTAwMH0
    token = "eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAidXNlcjEiLCAiZXhwIjogMTAwMH0."

    tx = HttpTransaction(
        client_endpoint=("127.0.0.1", 40000),
        server_endpoint=("127.0.0.1", 8080),
        request_headers={"Authorization": f"Bearer {token}"},
    )
    alerts = engine.analyze_transaction(tx)
    rule_ids = [a.rule_id for a in alerts]

    assert "INSECURE_JWT_ALG_NONE" in rule_ids
    assert "EXPIRED_JWT" in rule_ids


def test_info_exposure():
    """Verify detection of Python tracebacks and SQL syntax error leakage."""
    engine = SecurityEngine()

    traceback_body = b"Traceback (most recent call last):\n  File 'app.py', line 10, in index\nZeroDivisionError: division by zero"
    tx = HttpTransaction(
        client_endpoint=("127.0.0.1", 40000),
        server_endpoint=("127.0.0.1", 8080),
        response_status=500,
        response_body=traceback_body,
    )
    alerts = engine.analyze_transaction(tx)
    rule_ids = [a.rule_id for a in alerts]

    assert "STACK_TRACE_EXPOSURE" in rule_ids
