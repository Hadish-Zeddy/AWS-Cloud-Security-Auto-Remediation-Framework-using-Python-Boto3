from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    finding_id: str
    service: str
    resource: str
    severity: str
    title: str
    description: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)
    remediated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "service": self.service,
            "resource": self.resource,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "metadata": self.metadata,
            "remediated": self.remediated,
        }
