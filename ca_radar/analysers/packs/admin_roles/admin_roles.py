"""Admin role CA coverage detections.

CA-ADMIN-001  No role-targeted Conditional Access policy for privileged roles   [high]
CA-ADMIN-002  PIM-eligible users for privileged roles not covered by MFA        [high]

Detection rationale
-------------------
CA-ADMIN-001
  Best practice is to have at least one CA policy that *specifically* names
  privileged directory roles (include_roles) with strengthened controls.
  A tenant that relies only on "All users" MFA policies applies the same
  friction to a Global Admin as to a regular employee — losing the defence-
  in-depth that role-scoped policies provide.

CA-ADMIN-002
  PIM eligible assignments let a user *elevate* to a privileged role on demand.
  Until activation the user holds no active role, so `user_role_index` misses
  them. If that user's day-to-day account has no MFA coverage, an attacker who
  compromises it can activate PIM with a plain password.
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
from ca_radar.analysers.packs.coverage.mfa_coverage import PRIVILEGED_ROLE_IDS
from ca_radar.resolver.effective_controls import EvaluationConditions, PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import PolicyState

log = logging.getLogger(__name__)

_BROWSER_CONDITIONS = EvaluationConditions(client_app_type="browser")


class AdminRolesAnalyser(Analyser):
    """Detects privileged roles without dedicated or adequate CA coverage."""

    @property
    def finding_ids(self) -> list[str]:
        return ["CA-ADMIN-001", "CA-ADMIN-002"]

    def analyse(self, data: SnapshotData, resolver: PolicyResolver) -> list[Finding]:
        findings: list[Finding] = []

        enabled_policies = [p for p in data.policies if p.state == PolicyState.enabled]

        # ----------------------------------------------------------------
        # CA-ADMIN-001: No role-targeted CA policy for privileged roles
        # ----------------------------------------------------------------
        role_targeted_policies = [
            p
            for p in enabled_policies
            if p.conditions.users
            and any(rid in PRIVILEGED_ROLE_IDS for rid in p.conditions.users.include_roles)
        ]

        if not role_targeted_policies:
            findings.append(
                Finding(
                    id="CA-ADMIN-001",
                    title="No Conditional Access policy specifically targets privileged directory roles",
                    severity=Severity.high,
                    summary=(
                        "No enabled CA policy uses role-based inclusion to target privileged directory "
                        "roles such as Global Administrator, Security Administrator, or Exchange Administrator. "
                        "Privileged accounts rely solely on generic 'All users' policies with no additional "
                        "layered controls."
                    ),
                    why_it_matters=(
                        "A role-targeted CA policy enables you to enforce stronger controls specifically for "
                        "privileged accounts: phishing-resistant MFA, no persistent sessions, restricted "
                        "locations, and sign-in frequency. Without it, a Global Admin account receives "
                        "exactly the same friction (or lack thereof) as a standard employee account. "
                        "CISA SCuBA MS.AAD.3.1 and CIS Control 1.1.8 both require stronger MFA for admins."
                    ),
                    evidence={
                        "role_targeted_policy_count": 0,
                        "privileged_role_ids_checked": len(PRIVILEGED_ROLE_IDS),
                    },
                    affected_principals=[],
                    baselines=[
                        BaselineRef(
                            "SCuBA", "MS.AAD.3.1v1", "Phishing-resistant MFA for privileged roles"
                        ),
                        BaselineRef("CIS", "1.1.8", "Require stronger MFA for admins"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Create a Conditional Access policy targeting all highly privileged directory "
                            "roles with phishing-resistant authentication strength (FIDO2 or CBA). "
                            "Use the built-in 'Privileged administrator roles' template in the Entra portal."
                        ),
                        snippets=[
                            (
                                "Entra Portal",
                                (
                                    "Conditional Access → New policy (from template: 'Require phishing-resistant "
                                    "MFA for admins')\n"
                                    "  Users → Directory roles → [all privileged roles]\n"
                                    "  Grant → Require authentication strength → Phishing-resistant MFA\n"
                                    "  Session → Sign-in frequency: Every time\n"
                                    "  State: On"
                                ),
                            ),
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa",
                        ],
                    ),
                )
            )

        # ----------------------------------------------------------------
        # CA-ADMIN-002: PIM-eligible users not covered by MFA
        # ----------------------------------------------------------------
        # Get users who are eligible (not just active) for privileged roles
        eligible_user_ids = {
            user_id
            for user_id, role_ids in data.user_pim_role_index.items()
            if role_ids & PRIVILEGED_ROLE_IDS
        }

        if eligible_user_ids:
            real_enabled_users = {
                u.id for u in data.users if u.account_enabled and u.user_type != "Guest"
            }
            pim_users_to_check = eligible_user_ids & real_enabled_users

            uncovered_pim: list[str] = []
            for uid in pim_users_to_check:
                policies = resolver.effective_policies(uid, "All", _BROWSER_CONDITIONS)
                has_mfa = any(
                    p.state == PolicyState.enabled
                    and p.grant_controls
                    and "mfa" in [c.lower() for c in p.grant_controls.built_in_controls]
                    for p in policies
                )
                if not has_mfa:
                    uncovered_pim.append(uid)

            if uncovered_pim:
                upns = [
                    data.users_by_id[uid].user_principal_name
                    for uid in uncovered_pim
                    if uid in data.users_by_id
                ]
                findings.append(
                    Finding(
                        id="CA-ADMIN-002",
                        title="PIM-eligible users for privileged roles are not covered by MFA",
                        severity=Severity.high,
                        summary=(
                            f"{len(uncovered_pim)} user(s) hold PIM eligible assignments for privileged roles "
                            "but are not covered by any MFA-enforcing CA policy in their day-to-day state. "
                            "An attacker who compromises their account can activate PIM elevation without MFA."
                        ),
                        why_it_matters=(
                            "PIM eligible assignments are activated interactively — the user's current session "
                            "is used to request role elevation. If the account has no MFA requirement before "
                            "activation, a stolen password is sufficient to elevate to Global Admin. "
                            "The CA policy set should cover PIM-eligible accounts with at least standard MFA "
                            "even in their non-elevated state."
                        ),
                        evidence={
                            "uncovered_pim_user_count": len(uncovered_pim),
                            "sample_upns": upns[:10],
                        },
                        affected_principals=uncovered_pim,
                        baselines=[
                            BaselineRef(
                                "SCuBA", "MS.AAD.3.2v1", "MFA for all users including PIM-eligible"
                            ),
                            BaselineRef("CIS", "1.1.4", "Ensure MFA is enabled for all users"),
                        ],
                        remediation=Remediation(
                            description=(
                                "Ensure that the 'Require MFA for all users' CA policy does not exclude "
                                "any account that holds a PIM eligible role assignment. "
                                "Review the PIM policy settings to also require MFA at activation time."
                            ),
                            references=[
                                "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-require-mfa",
                            ],
                        ),
                        confidence=0.9,
                    )
                )

        return findings
