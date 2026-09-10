"""Unit tests for GraphQL inspector and security rules."""

import json

from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.decoders.graphql_decoder import inspect_graphql, is_graphql_transaction
from wiresniffer.security.rules.graphql_rules import check_graphql_security


def test_graphql_detection_and_query_extraction():
    body = json.dumps(
        {
            "query": "query GetUser($id: ID!) { user(id: $id) { name email } }",
            "variables": {"id": "123"},
            "operationName": "GetUser",
        }
    ).encode("utf-8")

    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        method="POST",
        path="/api/graphql",
        request_body=body,
    )

    assert is_graphql_transaction(tx) is True
    meta = inspect_graphql(tx)
    assert meta is not None
    assert meta.operation_type == "query"
    assert meta.operation_name == "GetUser"
    assert meta.variables == {"id": "123"}
    assert meta.is_introspection is False


def test_graphql_mutation_extraction():
    body = json.dumps(
        {
            "query": "mutation DeleteAccount { deleteUser { success } }",
        }
    ).encode("utf-8")

    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        method="POST",
        path="/graphql",
        request_body=body,
    )

    meta = inspect_graphql(tx)
    assert meta is not None
    assert meta.operation_type == "mutation"
    assert meta.operation_name == "DeleteAccount"


def test_graphql_introspection_security_alert():
    body = json.dumps(
        {
            "query": "{ __schema { types { name } } }",
        }
    ).encode("utf-8")

    res_body = json.dumps(
        {"data": {"__schema": {"types": [{"name": "User"}, {"name": "Admin"}]}}}
    ).encode("utf-8")

    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        method="POST",
        path="/graphql",
        request_body=body,
        response_status=200,
        response_body=res_body,
    )

    meta = inspect_graphql(tx)
    assert meta is not None
    assert meta.is_introspection is True

    alerts = check_graphql_security(tx)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "GRAPHQL_INTROSPECTION_ENABLED"
    assert alerts[0].severity.value == "MEDIUM"


def test_graphql_field_suggestion_security_alert():
    body = json.dumps(
        {
            "query": "{ usr { name } }",
        }
    ).encode("utf-8")

    res_body = json.dumps(
        {"errors": [{"message": "Cannot query field 'usr' on type 'Query'. Did you mean 'user'?"}]}
    ).encode("utf-8")

    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        method="POST",
        path="/graphql",
        request_body=body,
        response_status=400,
        response_body=res_body,
    )

    meta = inspect_graphql(tx)
    assert meta is not None
    assert len(meta.errors) == 1

    alerts = check_graphql_security(tx)
    assert any(a.rule_id == "GRAPHQL_FIELD_SUGGESTIONS" for a in alerts)
