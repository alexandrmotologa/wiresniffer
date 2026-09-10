"""Unit tests for structured query parsing and transaction filtering."""

import json

from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.filtering.query_parser import FilterPredicate, get_nested_key


def test_get_nested_key():
    data = {"user": {"id": 42, "profile": {"role": "admin"}}}
    assert get_nested_key(data, "user.id") == 42
    assert get_nested_key(data, "user.profile.role") == "admin"
    assert get_nested_key(data, "user.missing") is None
    assert get_nested_key(data, "other.key") is None


def test_filter_predicate_status():
    tx200 = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        response_status=200,
    )
    tx404 = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        response_status=404,
    )
    tx500 = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        response_status=500,
    )

    pred_2xx = FilterPredicate("status:2xx")
    assert pred_2xx.matches(tx200) is True
    assert pred_2xx.matches(tx404) is False

    pred_gte400 = FilterPredicate("status:>=400")
    assert pred_gte400.matches(tx200) is False
    assert pred_gte400.matches(tx404) is True
    assert pred_gte400.matches(tx500) is True

    pred_lt500 = FilterPredicate("status:<500")
    assert pred_lt500.matches(tx200) is True
    assert pred_lt500.matches(tx404) is True
    assert pred_lt500.matches(tx500) is False


def test_filter_predicate_latency():
    fast_tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        latency_ms=12.5,
    )
    slow_tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        latency_ms=350.0,
    )

    pred_slow = FilterPredicate("latency:>200ms")
    assert pred_slow.matches(fast_tx) is False
    assert pred_slow.matches(slow_tx) is True

    pred_fast = FilterPredicate("latency:<=50")
    assert pred_fast.matches(fast_tx) is True
    assert pred_fast.matches(slow_tx) is False


def test_filter_predicate_headers_and_method():
    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        method="POST",
        request_headers={"Authorization": "Bearer token123", "Content-Type": "application/json"},
    )

    pred1 = FilterPredicate("method:post")
    assert pred1.matches(tx) is True

    pred2 = FilterPredicate("header:authorization")
    assert pred2.matches(tx) is True

    pred3 = FilterPredicate("header:content-type=application/json")
    assert pred3.matches(tx) is True

    pred4 = FilterPredicate("method:get")
    assert pred4.matches(tx) is False


def test_filter_predicate_json_path():
    req_body = json.dumps({"data": {"user_id": 99, "role": "admin"}}).encode("utf-8")
    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        request_body=req_body,
    )

    pred1 = FilterPredicate("json:data.user_id=99")
    assert pred1.matches(tx) is True

    pred2 = FilterPredicate("json:data.role=admin")
    assert pred2.matches(tx) is True

    pred3 = FilterPredicate("json:data.user_id=100")
    assert pred3.matches(tx) is False

    pred_has_role = FilterPredicate("json:data.role")
    assert pred_has_role.matches(tx) is True


def test_filter_predicate_alerts():
    clean_tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
    )
    vulnerable_tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        security_alerts=[{"severity": "CRITICAL", "rule_id": "TEST"}],
    )

    pred_alert_any = FilterPredicate("alert:any")
    assert pred_alert_any.matches(clean_tx) is False
    assert pred_alert_any.matches(vulnerable_tx) is True

    pred_alert_crit = FilterPredicate("alert:critical")
    assert pred_alert_crit.matches(vulnerable_tx) is True

    pred_alert_med = FilterPredicate("alert:medium")
    assert pred_alert_med.matches(vulnerable_tx) is False
