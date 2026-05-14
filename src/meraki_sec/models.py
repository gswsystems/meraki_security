from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"
    SKIP = "skip"
    NOT_APPLICABLE = "n/a"


class Scope(str, Enum):
    ORG = "organization"
    NETWORK = "network"
    DEVICE = "device"


# Severity weights used for the aggregate risk score.
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class Target:
    """Identifies the object a finding is about."""
    scope: Scope
    org_id: str | None = None
    org_name: str | None = None
    network_id: str | None = None
    network_name: str | None = None
    device_serial: str | None = None
    device_name: str | None = None

    def label(self) -> str:
        parts: list[str] = []
        if self.org_name or self.org_id:
            name = self.org_name or "?"
            parts.append(f"org={name} [{self.org_id}]" if self.org_id else f"org={name}")
        if self.network_name:
            parts.append(f"net={self.network_name}")
        if self.device_name or self.device_serial:
            parts.append(f"dev={self.device_name or self.device_serial}")
        return " ".join(parts) or self.scope.value


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    status: Status
    target: Target
    message: str
    remediation: str = ""
    sources: list[str] = field(default_factory=list)
    mappings: dict[str, list[str]] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        d["target"]["scope"] = self.target.scope.value
        return d


@dataclass
class CheckMeta:
    id: str
    title: str
    severity: Severity
    scope: Scope
    product_type: str | None  # "appliance", "wireless", "switch", "camera", "sensor", or None for org/any
    sources: list[str]
    mappings: dict[str, list[str]] = field(default_factory=dict)
    description: str = ""


# Human-readable framework labels used when deriving `sources` from `mappings`.
FRAMEWORK_LABELS: dict[str, str] = {
    "CIS": "CIS Meraki",
    "NIST_CSF": "NIST CSF",
    "CIS_CSC": "CIS CSC v8",
    "Cisco": "Cisco",
    "E8": "ASD Essential Eight",
    "ISM": "ASD ISM",
}
