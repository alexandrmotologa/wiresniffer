"""Security heuristic rules for GraphQL introspection and field disclosures."""

from typing import List

from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.decoders.graphql_decoder import inspect_graphql
from wiresniffer.security.models import AlertSeverity, SecurityAlert


def check_graphql_security(tx: HttpTransaction) -> List[SecurityAlert]:
    """Inspect GraphQL transactions for introspection and suggestion leaks."""
    alerts: List[SecurityAlert] = []

    meta = inspect_graphql(tx)
    if not meta:
        return alerts

    # 1. Introspection Enabled
    if meta.is_introspection:
        # Check if response actually returned schema details
        res_text = tx.response_body_text
        if "__schema" in res_text or "types" in res_text:
            alerts.append(
                SecurityAlert(
                    rule_id="GRAPHQL_INTROSPECTION_ENABLED",
                    severity=AlertSeverity.MEDIUM,
                    title="GraphQL Schema Introspection Enabled",
                    description=(
                        "GraphQL introspection is active and returned the internal API schema. "
                        "Introspection allows attackers to discover hidden mutations, admin types, and deprecated fields."
                    ),
                    evidence="Query contained __schema / __type introspection query.",
                    remediation="Disable GraphQL introspection in production environments.",
                    category="GraphQL Security",
                )
            )

    # 2. Field Suggestions / Did You Mean Leaks
    res_text = tx.response_body_text
    if "Did you mean " in res_text or "did you mean " in res_text:
        alerts.append(
            SecurityAlert(
                rule_id="GRAPHQL_FIELD_SUGGESTIONS",
                severity=AlertSeverity.LOW,
                title="GraphQL Field Suggestion Leak in Errors",
                description=(
                    "The GraphQL server suggests internal field names on invalid queries ('Did you mean ...?'). "
                    "This helps attackers map unpublished fields through error enumeration."
                ),
                evidence="Matched 'Did you mean ...?' in GraphQL error response.",
                remediation="Disable field suggestions in production GraphQL engine configuration.",
                category="GraphQL Security",
            )
        )

    return alerts
