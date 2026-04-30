"""Service principal / workload identity CA detections.

CA-SP-001  No Conditional Access policy governs workload identities   [high]
CA-SP-002  Service principals present but no app-specific CA policies  [medium]

Detection rationale
-------------------
CA-SP-001 (Workload identity CA not configured)
  Microsoft Entra supports CA policies for workload identities (service
  principals / managed identities) via the `clientApplications` condition.
  Without such a policy, any service principal credential leak grants
  unrestricted access — no MFA prompt, no location check, no session limit.
  This feature requires Entra Workload Identities Premium.

CA-SP-002 (App-specific CA not configured)
  When service principals are present in the tenant but all CA policies
  target apps using the "All" sentinel (no specific app IDs), there is no
  differentiated access control for high-value applications.  Attackers
  who gain access to one app can pivot without triggering stronger controls.
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

# App IDs commonly worth scoping specific CA policies to
_HIGH_VALUE_APP_IDS = frozenset(
    {
        "797f4846-ba00-4fd7-ba43-dac1f8f63013",  # Azure Management
        "00000002-0000-0ff1-ce00-000000000000",  # Exchange Online
        "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
    }
)


class ServicePrincipalAnalyser(Analyser):
    """Detects tenants where workload identities are ungoverned by CA."""

    @property
    def finding_ids(self) -> list[str]:
        return ["CA-SP-001", "CA-SP-002"]

    def analyse(self, data: SnapshotData, resolver: PolicyResolver) -> list[Finding]:
        findings: list[Finding] = []

        enabled_policies = [p for p in data.policies if p.state == PolicyState.enabled]

        # ----------------------------------------------------------------
        # CA-SP-001: No workload identity CA policy
        # A policy governs workload identities if it sets client_applications.
        # ----------------------------------------------------------------
        workload_policies = [p for p in enabled_policies if p.conditions.client_applications]

        if not workload_policies:
            sp_count = len(data.service_principals)
            findings.append(
                Finding(
                    id="CA-SP-001",
                    title="No Conditional Access policy governs workload identities",
                    severity=Severity.high,
                    summary=(
                        "No enabled CA policy uses the `clientApplications` condition to govern "
                        "service principal sign-ins. "
                        + (
                            f"{sp_count} service principal(s) are registered in this tenant. "
                            if sp_count
                            else ""
                        )
                        + "Service principal credential leaks grant unrestricted access with no CA controls."
                    ),
                    why_it_matters=(
                        "Service accounts and managed identities are high-value targets because they "
                        "authenticate silently without user interaction — there is no MFA challenge to "
                        "interrupt an attacker. Entra Workload Identities CA policies let you restrict "
                        "service principal sign-ins by location, time-of-day, and token binding, and "
                        "alert on anomalous service principal sign-in patterns. Without them, a leaked "
                        "client secret or certificate gives an adversary persistent, undetected access."
                    ),
                    evidence={
                        "workload_identity_policy_count": 0,
                        "service_principal_count": sp_count,
                    },
                    affected_principals=[sp.id for sp in data.service_principals[:20]],
                    baselines=[
                        BaselineRef(
                            "SCuBA", "MS.AAD.8.1v1", "Restrict workload identity sign-ins via CA"
                        ),
                    ],
                    remediation=Remediation(
                        description=(
                            "Entra Workload Identities Premium (P1/P2) is required. Once licensed, "
                            "create a CA policy with `clientApplications` conditions targeting your "
                            "registered service principals. At minimum, restrict to known IP ranges "
                            "and block sign-ins from unknown locations."
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity",
                        ],
                    ),
                    confidence=0.9,
                )
            )

        # ----------------------------------------------------------------
        # CA-SP-002: No app-specific CA policies (all policies use 'All' apps)
        # ----------------------------------------------------------------
        app_specific_policies = [
            p
            for p in enabled_policies
            if p.conditions.applications
            and any(
                aid not in ("All", "None") for aid in p.conditions.applications.include_applications
            )
        ]

        high_value_apps_in_tenant = {
            sp.app_id
            for sp in data.service_principals
            if sp.app_id and sp.app_id in _HIGH_VALUE_APP_IDS
        }

        if not app_specific_policies and (data.service_principals or high_value_apps_in_tenant):
            findings.append(
                Finding(
                    id="CA-SP-002",
                    title="No CA policy targets specific high-value applications",
                    severity=Severity.medium,
                    summary=(
                        "All enabled CA policies use the 'All cloud apps' sentinel. "
                        "No policy applies differentiated controls to specific high-value applications "
                        "such as the Azure Management portal or Exchange Online."
                    ),
                    why_it_matters=(
                        "Blanket 'All apps' policies apply the same controls to a low-risk productivity "
                        "app as to the Azure Management API. Scoped policies let you enforce stricter "
                        "requirements (phishing-resistant MFA, compliant device, narrow IP ranges) for "
                        "applications that carry higher blast radius — such as the Azure portal, "
                        "Exchange Online admin, or the Microsoft Graph — while keeping friction low "
                        "for standard productivity apps."
                    ),
                    evidence={
                        "app_specific_policy_count": 0,
                        "high_value_app_ids_found": sorted(high_value_apps_in_tenant),
                    },
                    affected_principals=[],
                    baselines=[
                        BaselineRef(
                            "CIS", "1.1.2", "Scope CA policies to specific high-value apps"
                        ),
                    ],
                    remediation=Remediation(
                        description=(
                            "Create separate CA policies for high-value application IDs "
                            "(Azure Management: 797f4846-ba00-4fd7-ba43-dac1f8f63013, "
                            "Exchange Online: 00000002-0000-0ff1-ce00-000000000000) "
                            "that require phishing-resistant MFA and a compliant device."
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps",
                        ],
                    ),
                    confidence=0.75,
                )
            )

        return findings
