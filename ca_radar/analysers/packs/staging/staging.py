"""Staging & Report-Only policy hygiene detections.

CA-STAGING-001  Report-only Conditional Access policies left un-enforced  [medium]
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


class StagingHygieneAnalyser(Analyser):
    """Detects Conditional Access policies remaining in report-only mode without enforcement."""

    @property
    def finding_ids(self) -> list[str]:
        return ["CA-STAGING-001"]

    def analyse(self, data: SnapshotData, resolver: PolicyResolver) -> list[Finding]:
        findings: list[Finding] = []

        report_only_policies = [
            p
            for p in data.policies
            if p.state == PolicyState.enabledForReportingButNotEnforced
        ]

        if report_only_policies:
            policy_names = [p.display_name for p in report_only_policies]
            findings.append(
                Finding(
                    id="CA-STAGING-001",
                    title="Report-only Conditional Access policies are present and not enforced",
                    severity=Severity.medium,
                    summary=(
                        f"{len(report_only_policies)} Conditional Access policy/policies are configured in "
                        "'Report-only' mode (enabledForReportingButNotEnforced) and are not actively enforcing controls."
                    ),
                    why_it_matters=(
                        "Report-only mode evaluates policies without enforcing access blocks or MFA prompts. "
                        "Leaving policies in report-only mode indefinitely creates a false sense of security, "
                        "as security controls are simulated rather than enforced. CISA SCuBA MS.AAD.2.1 explicitly "
                        "states that report-only mode does not satisfy baseline security requirements."
                    ),
                    evidence={
                        "report_only_policy_count": len(report_only_policies),
                        "report_only_policies": policy_names,
                    },
                    affected_principals=policy_names,
                    baselines=[
                        BaselineRef(
                            "SCuBA",
                            "MS.AAD.2.1v1",
                            "Report-only mode does not satisfy enforcement requirement",
                        ),
                        BaselineRef("CIS", "1.2.1", "Enforce Conditional Access policies"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Review sign-in logs for report-only policy impact and transition fully evaluated "
                            "policies from 'Report-only' to 'On' (enabled)."
                        ),
                    ),
                )
            )

        return findings
