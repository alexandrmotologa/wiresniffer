"""Unit tests for custom YAML-based security rules engine."""

import os
import tempfile

from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.security.custom_rules import CustomRulesEngine


def test_custom_yaml_rules():
    yaml_content = """
rules:
  - id: ORG_REQ_CORRELATION_ID
    title: Missing X-Correlation-ID Header
    severity: HIGH
    description: All internal requests must provide X-Correlation-ID for tracing.
    target: request_headers
    missing_header: X-Correlation-ID

  - id: ORG_FORBIDDEN_SERVER_VERSION
    title: Server Header Disclosing Version
    severity: LOW
    description: Production servers should not expose detailed server tokens.
    target: response_headers
    forbidden_header: Server

  - id: ORG_INTERNAL_IP_LEAK
    title: Internal RFC1918 IP Exposure in Response
    severity: MEDIUM
    description: Internal network IP found in response payload.
    target: response_body
    regex: '10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}'
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        f.write(yaml_content)
        temp_path = f.name

    try:
        engine = CustomRulesEngine(config_path=temp_path)
        assert len(engine.rules) == 3

        # Test 1: Transaction missing X-Correlation-ID
        tx1 = HttpTransaction(
            timestamp=100.0,
            protocol=ProtocolType.HTTP1,
            client_endpoint=("127.0.0.1", 1000),
            server_endpoint=("127.0.0.1", 80),
            request_headers={"accept": "application/json"},
        )
        alerts1 = engine.evaluate(tx1)
        assert any(a.rule_id == "ORG_REQ_CORRELATION_ID" for a in alerts1)

        # Test 2: Transaction with X-Correlation-ID but has Server header and internal IP in body
        tx2 = HttpTransaction(
            timestamp=100.0,
            protocol=ProtocolType.HTTP1,
            client_endpoint=("127.0.0.1", 1000),
            server_endpoint=("127.0.0.1", 80),
            request_headers={"x-correlation-id": "abcd-1234"},
            response_headers={"server": "nginx/1.24.0"},
            response_body=b'{"cluster_node": "10.244.1.15"}',
        )
        alerts2 = engine.evaluate(tx2)
        rule_ids2 = [a.rule_id for a in alerts2]
        assert "ORG_REQ_CORRELATION_ID" not in rule_ids2
        assert "ORG_FORBIDDEN_SERVER_VERSION" in rule_ids2
        assert "ORG_INTERNAL_IP_LEAK" in rule_ids2
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
