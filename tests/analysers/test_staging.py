"""Unit tests for StagingHygieneAnalyser (CA-STAGING-001)."""

from ca_radar.analysers.packs.staging.staging import StagingHygieneAnalyser
from ca_radar.resolver.effective_controls import PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import (
    CaConditions,
    CaGrantControl,
    ConditionalAccessPolicy,
    PolicyState,
)


def test_staging_hygiene_triggers_when_report_only_policies_exist() -> None:
    data = SnapshotData(
        policies=[
            ConditionalAccessPolicy(
                id="pol-1",
                display_name="Test Policy - Report Only",
                state=PolicyState.enabledForReportingButNotEnforced,
                conditions=CaConditions(),
                grant_controls=CaGrantControl(built_in_controls=["mfa"]),
            )
        ]
    )
    resolver = PolicyResolver(data)
    analyser = StagingHygieneAnalyser()

    findings = analyser.analyse(data, resolver)

    assert len(findings) == 1
    assert findings[0].id == "CA-STAGING-001"
    assert findings[0].severity.value == "medium"
    assert "Test Policy - Report Only" in findings[0].affected_principals


def test_staging_hygiene_passes_when_no_report_only_policies() -> None:
    data = SnapshotData(
        policies=[
            ConditionalAccessPolicy(
                id="pol-1",
                display_name="Enforced Policy",
                state=PolicyState.enabled,
                conditions=CaConditions(),
                grant_controls=CaGrantControl(built_in_controls=["mfa"]),
            )
        ]
    )
    resolver = PolicyResolver(data)
    analyser = StagingHygieneAnalyser()

    findings = analyser.analyse(data, resolver)

    assert len(findings) == 0
