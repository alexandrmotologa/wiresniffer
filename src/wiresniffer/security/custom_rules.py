"""Custom organizational security rules loaded from YAML configuration files."""

import os
import re
from typing import List, Optional

import yaml
from pydantic import BaseModel

from wiresniffer.decoders.base import HttpTransaction
from wiresniffer.security.models import AlertSeverity, SecurityAlert


class CustomRule(BaseModel):
    """Definition of a team-specific or compliance security rule."""

    id: str
    title: str
    severity: AlertSeverity = AlertSeverity.MEDIUM
    description: str
    remediation: str = "Follow organization security guidelines."
    category: str = "Custom Compliance"
    target: str = "request_headers"  # request_headers, response_headers, request_body, response_body, path, query
    regex: Optional[str] = None
    missing_header: Optional[str] = None
    forbidden_header: Optional[str] = None


class CustomRulesEngine:
    """Loads and evaluates custom YAML-defined rules."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.rules: List[CustomRule] = []
        if config_path:
            self.load_from_file(config_path)
        else:
            # Look for .wiresniffer.yaml in current working directory
            default_path = os.path.join(os.getcwd(), ".wiresniffer.yaml")
            if os.path.exists(default_path):
                self.load_from_file(default_path)

    def load_from_file(self, file_path: str) -> None:
        """Parse rules from a YAML file."""
        if not os.path.exists(file_path):
            return

        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if isinstance(data, dict) and "rules" in data:
            for rule_dict in data["rules"]:
                try:
                    self.rules.append(CustomRule(**rule_dict))
                except Exception:
                    pass

    def evaluate(self, tx: HttpTransaction) -> List[SecurityAlert]:
        """Evaluate all custom rules against transaction."""
        alerts: List[SecurityAlert] = []

        for rule in self.rules:
            # 1. Check missing header
            if rule.missing_header:
                target_headers = (
                    tx.request_headers if "request" in rule.target else tx.response_headers
                )
                header_names = {k.lower(): v for k, v in target_headers.items()}
                if rule.missing_header.lower() not in header_names:
                    alerts.append(
                        SecurityAlert(
                            rule_id=rule.id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            evidence=f"Missing required header: '{rule.missing_header}'",
                            remediation=rule.remediation,
                            category=rule.category,
                        )
                    )
                    continue

            # 2. Check forbidden header
            if rule.forbidden_header:
                target_headers = (
                    tx.request_headers if "request" in rule.target else tx.response_headers
                )
                header_names = {k.lower(): v for k, v in target_headers.items()}
                if rule.forbidden_header.lower() in header_names:
                    alerts.append(
                        SecurityAlert(
                            rule_id=rule.id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            evidence=f"Forbidden header present: '{rule.forbidden_header}'",
                            remediation=rule.remediation,
                            category=rule.category,
                        )
                    )
                    continue

            # 3. Check Regex Pattern
            if rule.regex:
                content = ""
                if rule.target == "request_headers":
                    content = " ".join(f"{k}: {v}" for k, v in tx.request_headers.items())
                elif rule.target == "response_headers":
                    content = " ".join(f"{k}: {v}" for k, v in tx.response_headers.items())
                elif rule.target == "request_body":
                    content = tx.request_body_text
                elif rule.target == "response_body":
                    content = tx.response_body_text
                elif rule.target == "path":
                    content = tx.path
                elif rule.target == "query":
                    content = " ".join(f"{k}={v}" for k, v in tx.query_params.items())

                match = re.search(rule.regex, content)
                if match:
                    matched_str = match.group(0)
                    preview = matched_str[:20] + "..." if len(matched_str) > 20 else matched_str
                    alerts.append(
                        SecurityAlert(
                            rule_id=rule.id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            evidence=f"Matched pattern '{rule.regex}' in {rule.target}: '{preview}'",
                            remediation=rule.remediation,
                            category=rule.category,
                        )
                    )

        return alerts
