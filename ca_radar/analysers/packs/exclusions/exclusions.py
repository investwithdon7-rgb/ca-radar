"""Exclusion hygiene detections.

CA-EXCL-001  Policy exclusion references a non-existent user or group       [medium]
CA-EXCL-002  MFA policy excludes a group with many members (over-broad)     [high]

Detection rationale
-------------------
CA-EXCL-001 (Ghost exclusions)
  A policy that excludes a user/group ID that no longer exists in the tenant
  creates a latent security gap.  The exclusion is effectively dead weight,
  and in some IdP implementations a deleted-and-re-created object can inherit
  the same ID — meaning a future account could slide straight past MFA.

CA-EXCL-002 (Over-broad exclusion)
  An MFA-enforcing policy whose exclusion group contains a large number of
  users defeats the purpose of the policy.  This usually happens when a
  distribution list or "everyone in IT" group is added to the exclusion set
  by mistake.  The threshold is deliberately low (> _LARGE_GROUP_THRESHOLD).
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

# Exclusion group size that triggers CA-EXCL-002
_LARGE_GROUP_THRESHOLD = 10


class ExclusionAnalyser(Analyser):
    """Detects ghost exclusions and over-broad MFA exclusion groups."""

    @property
    def finding_ids(self) -> list[str]:
        return ["CA-EXCL-001", "CA-EXCL-002"]

    def analyse(self, data: SnapshotData, resolver: PolicyResolver) -> list[Finding]:
        findings: list[Finding] = []

        enabled_policies = [p for p in data.policies if p.state == PolicyState.enabled]

        # ----------------------------------------------------------------
        # CA-EXCL-001: Ghost exclusions
        # ----------------------------------------------------------------
        ghost_entries: list[dict] = []
        for policy in enabled_policies:
            uc = policy.conditions.users
            if not uc:
                continue
            for uid in uc.exclude_users:
                if uid not in data.users_by_id:
                    ghost_entries.append(
                        {
                            "policy_id": policy.id,
                            "policy_name": policy.display_name,
                            "kind": "user",
                            "ref_id": uid,
                        }
                    )
            for gid in uc.exclude_groups:
                if gid not in data.groups_by_id:
                    ghost_entries.append(
                        {
                            "policy_id": policy.id,
                            "policy_name": policy.display_name,
                            "kind": "group",
                            "ref_id": gid,
                        }
                    )

        if ghost_entries:
            affected_policies = list({e["policy_id"] for e in ghost_entries})
            findings.append(
                Finding(
                    id="CA-EXCL-001",
                    title="CA policies contain exclusions referencing non-existent users or groups",
                    severity=Severity.medium,
                    summary=(
                        f"{len(ghost_entries)} exclusion reference(s) in {len(affected_policies)} policy(ies) "
                        "point to user or group IDs that do not exist in this tenant. "
                        "These are dead exclusions that provide no protection if a new object "
                        "is created with the same ID."
                    ),
                    why_it_matters=(
                        "Conditional Access exclusions are access control decisions. A ghost exclusion "
                        "is invisible noise that can mask a real security gap: if the deleted account or "
                        "group is ever recreated — intentionally or by an attacker who controls object "
                        "creation — the new principal inherits the bypass automatically. Ghost exclusions "
                        "also indicate poor lifecycle hygiene: the CA policy set has drifted from the "
                        "current identity state."
                    ),
                    evidence={
                        "ghost_count": len(ghost_entries),
                        "affected_policy_count": len(affected_policies),
                        "sample_ghosts": ghost_entries[:10],
                    },
                    affected_principals=[e["ref_id"] for e in ghost_entries],
                    baselines=[
                        BaselineRef("CIS", "1.1.6", "Regularly review CA policy exclusions"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Audit every Conditional Access policy exclusion list and remove references "
                            "to users, groups, or service principals that no longer exist. "
                            "Automate this review with an access review or a periodic script that "
                            "cross-references policy exclusions against current directory objects."
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups",
                        ],
                    ),
                    confidence=0.95,
                )
            )

        # ----------------------------------------------------------------
        # CA-EXCL-002: Over-broad exclusion groups in MFA policies
        # ----------------------------------------------------------------
        mfa_policies = [
            p
            for p in enabled_policies
            if p.grant_controls and "mfa" in [c.lower() for c in p.grant_controls.built_in_controls]
        ]

        large_exclusions: list[dict] = []
        for policy in mfa_policies:
            uc = policy.conditions.users
            if not uc:
                continue
            for gid in uc.exclude_groups:
                group = data.groups_by_id.get(gid)
                if not group:
                    continue  # ghost — already handled above
                member_count = len(group.transitive_member_ids) or len(group.member_ids)
                if member_count > _LARGE_GROUP_THRESHOLD:
                    large_exclusions.append(
                        {
                            "policy_id": policy.id,
                            "policy_name": policy.display_name,
                            "group_id": gid,
                            "group_name": group.display_name,
                            "member_count": member_count,
                        }
                    )

        if large_exclusions:
            findings.append(
                Finding(
                    id="CA-EXCL-002",
                    title="MFA policy excludes a large group — potential MFA bypass for many users",
                    severity=Severity.high,
                    summary=(
                        f"{len(large_exclusions)} MFA policy exclusion(s) reference groups with more than "
                        f"{_LARGE_GROUP_THRESHOLD} members. A large exclusion group means many users can "
                        "sign in without MFA, defeating the purpose of the policy."
                    ),
                    why_it_matters=(
                        "Break-glass exclusions should target tiny, dedicated groups containing only the "
                        "emergency access accounts (typically 2). When a large group — such as a team, "
                        "department, or distribution list — is excluded from an MFA policy, every member "
                        "of that group becomes an unenforced weak link. Credential-spray attackers "
                        "explicitly target accounts with known MFA bypasses."
                    ),
                    evidence={
                        "large_exclusion_count": len(large_exclusions),
                        "threshold_used": _LARGE_GROUP_THRESHOLD,
                        "details": large_exclusions,
                    },
                    affected_principals=[e["group_id"] for e in large_exclusions],
                    baselines=[
                        BaselineRef(
                            "SCuBA", "MS.AAD.3.2v1", "MFA exclusions must be tightly scoped"
                        ),
                        BaselineRef("CIS", "1.1.4", "Ensure MFA exclusions are minimal"),
                    ],
                    remediation=Remediation(
                        description=(
                            f"Replace any exclusion group with more than {_LARGE_GROUP_THRESHOLD} members "
                            "with a dedicated break-glass group containing only 2–3 emergency access accounts. "
                            "Move legitimate service accounts to app-based authentication flows that do not "
                            "require user MFA."
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa#exclude-emergency-access-accounts",
                        ],
                    ),
                    confidence=0.9,
                )
            )

        return findings
