"""What an alert looks like. An alert is a suspicious INDICATOR, never proof of an attack."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

LOW, MEDIUM, HIGH = "low", "medium", "high"


@dataclass(frozen=True)
class Rule:
    rule_id: str  # stable identifier, e.g. "NS-001"
    name: str
    description: str
    mitre_attack: str  # closest MITRE ATT&CK technique, for analysts (a hint, not a verdict)


@dataclass(frozen=True)
class Alert:
    rule: Rule
    severity: str
    start: float  # Unix time of the first packet/flow in the evidence
    end: float
    src_ip: str
    dst_ip: str | None  # None when the alert is about one source talking to many hosts
    dst_port: int | None
    summary: str  # one human-readable sentence
    thresholds: dict[str, Any] = field(default_factory=dict)  # the config values that fired
    evidence: dict[str, Any] = field(default_factory=dict)  # numbers an analyst can verify

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "rule_name": self.rule.name,
            "rule_description": self.rule.description,
            "mitre_attack": self.rule.mitre_attack,
            "severity": self.severity,
            "start": self.start,
            "end": self.end,
            "start_iso": datetime.fromtimestamp(self.start, tz=UTC).isoformat(),
            "duration_seconds": round(self.end - self.start, 6),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "summary": self.summary,
            "thresholds": self.thresholds,
            "evidence": self.evidence,
        }
