"""Security alert models and severity classifications."""

from enum import Enum

from pydantic import BaseModel


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityAlert(BaseModel):
    """Represents a security heuristic violation detected in traffic."""

    rule_id: str
    severity: AlertSeverity
    title: str
    description: str
    evidence: str
    remediation: str
    category: str = "General"
