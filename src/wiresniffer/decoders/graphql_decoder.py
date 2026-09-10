"""GraphQL query, mutation, and response error inspector."""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from wiresniffer.decoders.base import HttpTransaction

OPERATION_REGEX = re.compile(
    r"\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)?",
    re.IGNORECASE,
)


@dataclass
class GraphQLMetadata:
    """Extracted GraphQL query metadata."""

    operation_type: str = "query"
    operation_name: Optional[str] = None
    query_text: str = ""
    variables: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    is_introspection: bool = False


def is_graphql_transaction(tx: HttpTransaction) -> bool:
    """Determine whether transaction is a GraphQL operation."""
    if "/graphql" in tx.path.lower():
        return True

    # Check body for "query" JSON field
    if tx.method in ("POST", "GET") and tx.request_body:
        parsed = tx.request_json()
        if isinstance(parsed, dict) and "query" in parsed:
            return True

    return False


def inspect_graphql(tx: HttpTransaction) -> Optional[GraphQLMetadata]:
    """Parse GraphQL operation name, type, and response errors from transaction."""
    if not is_graphql_transaction(tx):
        return None

    meta = GraphQLMetadata()

    # Extract query and variables
    parsed_req = tx.request_json()
    if isinstance(parsed_req, dict):
        meta.query_text = parsed_req.get("query", "")
        meta.variables = parsed_req.get("variables", {}) or {}
        meta.operation_name = parsed_req.get("operationName")
    elif "query" in tx.query_params:
        meta.query_text = tx.query_params["query"]
        meta.operation_name = tx.query_params.get("operationName")

    # If operation name not explicitly provided, regex search in query
    if meta.query_text:
        if "__schema" in meta.query_text or "__type" in meta.query_text:
            meta.is_introspection = True

        match = OPERATION_REGEX.search(meta.query_text)
        if match:
            meta.operation_type = match.group(1).lower()
            if not meta.operation_name and match.group(2):
                meta.operation_name = match.group(2)

    # Inspect response for GraphQL errors
    parsed_res = tx.response_json()
    if isinstance(parsed_res, dict):
        res_errors = parsed_res.get("errors")
        if isinstance(res_errors, list):
            meta.errors = res_errors

    return meta
