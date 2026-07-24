"""Device compliance CA coverage detections.

CA-DEV-001  No Conditional Access policy requires compliant or hybrid joined devices  [high]
"""

from __future__ import annotations

import logging

from ca_radar.analysers.base import (
    Analyser,
    BaselineRef,
    Finding,
    Remediation,
    Severity,
)
from ca_radar.resolver.effective_controls import PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import PolicyState

log = logging.getLogger(__name__)

_DEVICE_CONTROLS = frozenset({"compliantDevice", "domainJoinedDevice"})


class DeviceComplianceAnalyser(Analyser):
    """Detects missing device compliance or hybrid Entra join enforcement in CA policies."""

    @property
    def finding_ids(self) -> list[str]:
        return ["CA-DEV-001"]

    def analyse(self, data: SnapshotData, resolver: PolicyResolver) -> list[Finding]:
        findings: list[Finding] = []

        enabled_policies = [p for p in data.policies if p.state == PolicyState.enabled]

        device_policies = [
            p
            for p in enabled_policies
            if p.grant_controls
            and any(c in _DEVICE_CONTROLS for c in p.grant_controls.built_in_controls)
        ]

        if not device_policies:
            findings.append(
                Finding(
                    id="CA-DEV-001",
                    title="No Conditional Access policy requires compliant or Entra hybrid joined devices",
                    severity=Severity.high,
                    summary=(
                        "No enabled CA policy enforces device compliance ('compliantDevice') "
                        "or Microsoft Entra hybrid join ('domainJoinedDevice') grant controls. "
                        "Unmanaged and non-compliant personal devices can access corporate data."
                    ),
                    why_it_matters=(
                        "Device compliance enforcement ensures that only health-verified, "
                        "managed devices meeting corporate security baselines can access organizational "
                        "applications and data. Requiring compliant devices prevents compromised "
                        "personal devices from exfiltrating corporate data even if user credentials are valid."
                    ),
                    evidence={
                        "device_compliant_policy_count": 0,
                        "enabled_policy_count": len(enabled_policies),
                    },
                    affected_principals=[],
                    baselines=[
                        BaselineRef(
                            "SCuBA", "MS.AAD.2.1v1", "Device compliance and access controls"
                        ),
                        BaselineRef("CIS", "1.2.1", "Enforce device compliance controls"),
                        BaselineRef("NCSC", "NCSC.CA.2", "Require compliant devices"),
                        BaselineRef(
                            "Essential Eight", "E8.MFA.1", "Corporate device health verification"
                        ),
                    ],
                    remediation=Remediation(
                        description=(
                            "Create a Conditional Access policy requiring compliant devices or Microsoft Entra "
                            "hybrid joined devices for all users accessing sensitive cloud applications."
                        ),
                    ),
                )
            )

        return findings
