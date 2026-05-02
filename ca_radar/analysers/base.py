"""Analyser base classes, Finding model, and supporting types.

Every detection is a subclass of Analyser. It declares what it needs,
runs against the resolver, and emits zero or more Finding objects.

Design rules:
- One class = one file = one test file.
- Adding a new detection never requires touching the renderer.
- Findings carry stable IDs so dashboards can track them across scans.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ca_radar.resolver.effective_controls import PolicyResolver
    from ca_radar.resolver.policy_graph import SnapshotData

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def weight(self) -> int:
        """Numeric weight for posture score calculation."""
        return {
            Severity.critical: 15,
            Severity.high: 7,
            Severity.medium: 3,
            Severity.low: 1,
            Severity.info: 0,
        }[self]

    @property
    def emoji(self) -> str:
        return {
            Severity.critical: "🔴",
            Severity.high: "🟠",
            Severity.medium: "🟡",
            Severity.low: "🔵",
            Severity.info: "⚪",
        }[self]


# ---------------------------------------------------------------------------
# Baseline reference
# ---------------------------------------------------------------------------


@dataclass
class BaselineRef:
    """A reference to a control in an external security baseline."""

    framework: str  # "SCuBA" | "CIS" | "NCSC" | "E8"
    control_id: str  # e.g. "MS.AAD.3.1v1"
    title: str = ""


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


@dataclass
class Remediation:
    """Human-readable guidance plus optional code snippets."""

    description: str
    # List of (label, code) tuples, e.g. [("Entra Portal", "..."), ("PowerShell", "...")]
    snippets: list[tuple[str, str]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single detected gap or misconfiguration.

    The `id` is stable across runs — used to deduplicate, track trends,
    and map to baseline controls.
    """

    id: str  # stable, e.g. "CA-MFA-001"
    title: str
    severity: Severity
    summary: str  # 1–3 sentence explanation
    why_it_matters: str  # training paragraph for report
    evidence: dict[str, Any]  # raw resource IDs and excerpts
    affected_principals: list[str]  # user/group/SP IDs
    baselines: list[BaselineRef] = field(default_factory=list)
    remediation: Remediation | None = None
    confidence: float = 1.0  # 0.0–1.0; < 1.0 = uncertain
    owner: dict[str, Any] = field(default_factory=dict)
    exception: dict[str, Any] = field(default_factory=dict)
    priority: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "summary": self.summary,
            "why_it_matters": self.why_it_matters,
            "evidence": self.evidence,
            "affected_principals": self.affected_principals,
            "baselines": [
                {"framework": b.framework, "control_id": b.control_id, "title": b.title}
                for b in self.baselines
            ],
            "remediation": {
                "description": self.remediation.description,
                "snippets": self.remediation.snippets,
                "references": self.remediation.references,
            }
            if self.remediation
            else None,
            "confidence": self.confidence,
            "owner": self.owner,
            "exception": self.exception,
            "priority": self.priority,
        }


# ---------------------------------------------------------------------------
# Analyser ABC
# ---------------------------------------------------------------------------


class Analyser(ABC):
    """Base class for all detection analysers.

    Subclasses implement `analyse()` and return a list of Finding objects.
    The method receives the full SnapshotData and a PolicyResolver, both
    already loaded — no I/O happens inside analyse().
    """

    @property
    @abstractmethod
    def finding_ids(self) -> list[str]:
        """The stable finding IDs this analyser can emit."""

    @abstractmethod
    def analyse(
        self,
        data: SnapshotData,  # ca_radar.resolver.policy_graph.SnapshotData
        resolver: PolicyResolver,  # ca_radar.resolver.effective_controls.PolicyResolver
    ) -> list[Finding]:
        """Run the detection logic and return findings (may be empty)."""

    # Convenience: name for logging
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ids={self.finding_ids}>"
