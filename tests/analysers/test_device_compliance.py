"""Unit tests for DeviceComplianceAnalyser (CA-DEV-001)."""

from ca_radar.analysers.packs.device_compliance.device_compliance import (
    DeviceComplianceAnalyser,
)
from ca_radar.resolver.effective_controls import PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import (
    CaConditions,
    CaGrantControl,
    ConditionalAccessPolicy,
    PolicyState,
)


def test_device_compliance_triggers_when_no_policy_enforces_it() -> None:
    data = SnapshotData(
        policies=[
            ConditionalAccessPolicy(
                id="pol-1",
                display_name="Basic MFA",
                state=PolicyState.enabled,
                conditions=CaConditions(),
                grant_controls=CaGrantControl(built_in_controls=["mfa"]),
            )
        ]
    )
    resolver = PolicyResolver(data)
    analyser = DeviceComplianceAnalyser()

    findings = analyser.analyse(data, resolver)

    assert len(findings) == 1
    assert findings[0].id == "CA-DEV-001"
    assert findings[0].severity.value == "high"


def test_device_compliance_passes_when_compliant_device_required() -> None:
    data = SnapshotData(
        policies=[
            ConditionalAccessPolicy(
                id="pol-1",
                display_name="Require Compliant Device",
                state=PolicyState.enabled,
                conditions=CaConditions(),
                grant_controls=CaGrantControl(built_in_controls=["compliantDevice"]),
            )
        ]
    )
    resolver = PolicyResolver(data)
    analyser = DeviceComplianceAnalyser()

    findings = analyser.analyse(data, resolver)

    assert len(findings) == 0


def test_device_compliance_passes_when_domain_joined_device_required() -> None:
    data = SnapshotData(
        policies=[
            ConditionalAccessPolicy(
                id="pol-1",
                display_name="Require Hybrid Join Device",
                state=PolicyState.enabled,
                conditions=CaConditions(),
                grant_controls=CaGrantControl(built_in_controls=["domainJoinedDevice"]),
            )
        ]
    )
    resolver = PolicyResolver(data)
    analyser = DeviceComplianceAnalyser()

    findings = analyser.analyse(data, resolver)

    assert len(findings) == 0
