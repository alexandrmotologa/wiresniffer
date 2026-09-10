"""Security evaluation engine coordinating all heuristic scanning rules."""

from typing import List, Optional

from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.security.custom_rules import CustomRulesEngine
from wiresniffer.security.models import AlertSeverity, SecurityAlert
from wiresniffer.security.rules.credential_leak import check_credential_leaks
from wiresniffer.security.rules.graphql_rules import check_graphql_security
from wiresniffer.security.rules.info_exposure import check_info_exposure
from wiresniffer.security.rules.jwt_analyzer import check_jwt_tokens
from wiresniffer.security.rules.pii_leak import check_pii_leaks
from wiresniffer.security.rules.plaintext_auth import check_plaintext_auth

SEVERITY_WEIGHTS = {
    AlertSeverity.LOW: 1,
    AlertSeverity.MEDIUM: 2,
    AlertSeverity.HIGH: 3,
    AlertSeverity.CRITICAL: 4,
}


class SecurityEngine:
    """Evaluates transactions against the registry of security heuristic rules."""

    def __init__(
        self,
        enabled: bool = True,
        custom_rules_path: Optional[str] = None,
    ) -> None:
        self.enabled = enabled
        self.custom_engine = CustomRulesEngine(custom_rules_path)

    def analyze_transaction(self, tx: HttpTransaction) -> List[SecurityAlert]:
        """Run all security checks against the given transaction."""
        if not self.enabled:
            return []

        alerts: List[SecurityAlert] = []

        # Execute rules
        alerts.extend(check_plaintext_auth(tx))
        alerts.extend(check_credential_leaks(tx))
        alerts.extend(check_pii_leaks(tx))
        alerts.extend(check_jwt_tokens(tx))
        alerts.extend(check_info_exposure(tx))
        alerts.extend(check_graphql_security(tx))
        alerts.extend(self.custom_engine.evaluate(tx))

        # Store alert dicts inside transaction model
        tx.security_alerts = [alert.model_dump() for alert in alerts]
        return alerts

    @staticmethod
    def max_severity(alerts: List[SecurityAlert]) -> Optional[AlertSeverity]:
        """Determine highest severity level among detected alerts."""
        if not alerts:
            return None
        return max(alerts, key=lambda a: SEVERITY_WEIGHTS[a.severity]).severity
