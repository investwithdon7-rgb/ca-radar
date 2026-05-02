"""Tests for owner, exception, and priority enrichment."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from ca_radar.analysers.base import Finding, Severity
from ca_radar.enrichment import enrich_findings, load_enrichment_inputs


def _finding(
    finding_id: str = "CA-SP-001",
    *,
    severity: Severity = Severity.high,
    principals: list[str] | None = None,
    confidence: float = 1.0,
) -> Finding:
    return Finding(
        id=finding_id,
        title="Test finding",
        severity=severity,
        summary="Summary",
        why_it_matters="Why",
        evidence={},
        affected_principals=principals or ["sp-1"],
        confidence=confidence,
    )


def test_loads_owner_and_exception_yaml(tmp_path: Path) -> None:
    owners = tmp_path / "owners.yaml"
    owners.write_text(
        """
owners:
  principals:
    sp-1: Platform Team
  findings:
    CA-EXCL-001: Identity Governance
  default: Security Operations
""",
        encoding="utf-8",
    )
    exceptions = tmp_path / "exceptions.yaml"
    exceptions.write_text(
        """
exceptions:
  - finding_id: CA-SP-001
    principal: sp-1
    status: accepted_risk
    reason: Approved exception
    owner: Platform Team
    approved_by: CISO
    expires: "2026-12-31"
""",
        encoding="utf-8",
    )

    config = load_enrichment_inputs(str(owners), str(exceptions))

    assert config.owners.principals["sp-1"] == "Platform Team"
    assert config.owners.findings["CA-EXCL-001"] == "Identity Governance"
    assert config.exceptions[0].finding_id == "CA-SP-001"


def test_enriches_owner_from_affected_principal() -> None:
    finding = _finding(principals=["sp-1"])

    enrich_findings(
        [finding],
        owner_map={"principals": {"sp-1": "Platform Team"}},
        today=date(2026, 5, 2),
    )

    assert finding.owner["names"] == ["Platform Team"]
    assert finding.owner["source"] == "principal"


def test_enriches_owner_from_finding_fallback() -> None:
    finding = _finding("CA-EXCL-001", principals=["group-1"])

    enrich_findings(
        [finding],
        owner_map={"findings": {"CA-EXCL-001": "Identity Governance"}},
        today=date(2026, 5, 2),
    )

    assert finding.owner["names"] == ["Identity Governance"]
    assert finding.owner["source"] == "finding"


def test_enriches_default_owner_when_no_specific_match() -> None:
    finding = _finding("CA-MFA-001", principals=["user-1"])

    enrich_findings([finding], owner_map={"default": "Security Operations"}, today=date(2026, 5, 2))

    assert finding.owner["names"] == ["Security Operations"]
    assert finding.owner["source"] == "default"


def test_active_exception_lowers_priority() -> None:
    finding = _finding("CA-SP-001", severity=Severity.high, principals=["sp-1"])

    enrich_findings(
        [finding],
        exception_items=[
            {
                "finding_id": "CA-SP-001",
                "principal": "sp-1",
                "status": "accepted_risk",
                "reason": "Approved temporarily",
                "owner": "Platform Team",
                "approved_by": "CISO",
                "expires": "2026-12-31",
            }
        ],
        today=date(2026, 5, 2),
    )

    assert finding.exception["status"] == "accepted_risk"
    assert finding.exception["active"] is True
    assert finding.priority["band"] == "medium"
    assert "active exception" in finding.priority["factors"]


def test_expired_exception_raises_priority() -> None:
    finding = _finding("CA-SP-001", severity=Severity.high, principals=["sp-1"])

    enrich_findings(
        [finding],
        exception_items=[
            {
                "finding_id": "CA-SP-001",
                "principal": "sp-1",
                "status": "accepted_risk",
                "expires": "2026-01-01",
            }
        ],
        today=date(2026, 5, 2),
    )

    assert finding.exception["status"] == "expired"
    assert finding.exception["expired"] is True
    assert finding.priority["band"] in {"high", "urgent"}
    assert "expired exception" in finding.priority["factors"]


def test_finding_dict_includes_enrichment_fields() -> None:
    finding = _finding("CA-SP-001", severity=Severity.critical, principals=["sp-1"])
    enrich_findings([finding], owner_map={"principals": {"sp-1": "Platform Team"}})

    doc = finding.to_dict()

    assert doc["owner"]["names"] == ["Platform Team"]
    assert doc["exception"]["status"] == "none"
    assert doc["priority"]["score"] > 0
