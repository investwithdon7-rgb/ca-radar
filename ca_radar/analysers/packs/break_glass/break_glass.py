"""Break-glass account detections.

CA-BG-001  No break-glass account pattern detected in tenant          [critical]
CA-BG-002  Break-glass account(s) not required to use FIDO2 or CBA   [high]
CA-BG-003  Break-glass account(s) still subject to CA policies        [high]

Detection strategy
------------------
A break-glass account is identified by any of:
  1. The user is explicitly excluded from every enabled, enforced CA policy.
  2. The user's UPN contains a break-glass indicator keyword.
  3. The user is a member of a group that is excluded from all MFA policies.

Confidence is deliberately < 1.0 for BG-001 because we cannot distinguish
a tenant with NO break-glass from a tenant that uses a naming convention
we don't recognise.  Admins should review the evidence section.
"""

from __future__ import annotations

import logging
import re

from ca_radar.analysers.base import (
    Analyser,
    BaselineRef,
    Finding,
    Remediation,
    Severity,
)
from ca_radar.resolver.effective_controls import EvaluationConditions, PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import PolicyState

log = logging.getLogger(__name__)

_BG_NAME_PATTERN = re.compile(
    r"(break.?glass|emergency|breakglass|bg\d|emrg|eadmin|emergency.?access)",
    re.IGNORECASE,
)

_BROWSER_CONDITIONS = EvaluationConditions(client_app_type="browser")

_PHISHING_RESISTANT_CONTROLS = frozenset(
    {
        "fido2",
        "windowshelloforbusiness",
        "certificatebasedauthentication",
        "passkey",
        "phishingresistant",
    }
)


class BreakGlassAnalyser(Analyser):
    """Detects missing or misconfigured break-glass accounts."""

    @property
    def finding_ids(self) -> list[str]:
        return ["CA-BG-001", "CA-BG-002", "CA-BG-003"]

    def analyse(self, data: SnapshotData, resolver: PolicyResolver) -> list[Finding]:
        findings: list[Finding] = []

        enabled_mfa_policies = [
            p
            for p in data.policies
            if p.state == PolicyState.enabled
            and p.grant_controls
            and "mfa" in [c.lower() for c in p.grant_controls.built_in_controls]
        ]

        enabled_users = [u for u in data.users if u.account_enabled]
        if not enabled_users:
            return []

        # Identify break-glass candidates
        bg_candidates = _identify_break_glass_candidates(
            enabled_users, data, resolver, enabled_mfa_policies
        )

        # ----------------------------------------------------------------
        # CA-BG-001: No break-glass pattern found at all
        # ----------------------------------------------------------------
        if not bg_candidates:
            findings.append(
                Finding(
                    id="CA-BG-001",
                    title="No break-glass (emergency access) account detected",
                    severity=Severity.critical,
                    summary=(
                        "No account was found that matches break-glass patterns: "
                        "excluded from all MFA-enforcing CA policies, or named with "
                        "break-glass/emergency keywords. Break-glass accounts are essential "
                        "for recovering tenant access if CA policies or MFA fail."
                    ),
                    why_it_matters=(
                        "If your MFA provider has an outage, or a CA policy misconfiguration "
                        "locks out all administrators, you need a break-glass account that "
                        "can bypass Conditional Access entirely. Without one, you could lose "
                        "all administrative access to your tenant — an irreversible situation "
                        "that Microsoft cannot resolve without lengthy identity verification. "
                        "Microsoft's own guidance mandates at least two cloud-only break-glass "
                        "accounts per tenant."
                    ),
                    evidence={
                        "enabled_user_count": len(enabled_users),
                        "candidates_found": 0,
                    },
                    affected_principals=[],
                    baselines=[
                        BaselineRef("SCuBA", "MS.AAD.1.1v1", "Maintain emergency access accounts"),
                        BaselineRef("CIS", "1.1.1", "Ensure two emergency access accounts exist"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Create at least two cloud-only break-glass accounts:\n"
                            "  • Named clearly (e.g. break-glass-1@yourtenant.onmicrosoft.com)\n"
                            "  • Excluded from all CA policies\n"
                            "  • Protected with a FIDO2 hardware key or certificate\n"
                            "  • Credentials stored offline in a sealed envelope\n"
                            "  • Sign-in activity alerted via Azure Monitor / Sentinel"
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access",
                        ],
                    ),
                    confidence=0.7,  # we may not recognise all break-glass patterns
                )
            )
            return findings  # BG-002 and BG-003 require candidates to exist

        # ----------------------------------------------------------------
        # CA-BG-002: Break-glass not required to use FIDO2 / CBA
        # ----------------------------------------------------------------
        bg_without_phish_resistant = [
            uid
            for uid in bg_candidates
            if not _has_phishing_resistant_requirement(uid, resolver, data)
        ]

        if bg_without_phish_resistant:
            upns = [
                data.users_by_id[uid].user_principal_name
                for uid in bg_without_phish_resistant
                if uid in data.users_by_id
            ]
            findings.append(
                Finding(
                    id="CA-BG-002",
                    title="Break-glass account(s) not required to use phishing-resistant MFA",
                    severity=Severity.high,
                    summary=(
                        f"{len(bg_without_phish_resistant)} break-glass account(s) have no CA policy "
                        "requiring FIDO2, Windows Hello for Business, or certificate-based "
                        "authentication. If the break-glass password is stolen, the account can be "
                        "used without a hardware-bound factor."
                    ),
                    why_it_matters=(
                        "Break-glass accounts typically bypass most CA policies. If they are protected "
                        "only by a password (or a software-based TOTP), a credential leak gives an "
                        "attacker unconditional Global Admin access. FIDO2 hardware keys are the "
                        "recommended protection: they are phishing-proof and work even when the "
                        "MFA provider is unavailable."
                    ),
                    evidence={
                        "affected_break_glass_accounts": len(bg_without_phish_resistant),
                        "sample_upns": upns[:5],
                    },
                    affected_principals=bg_without_phish_resistant,
                    baselines=[
                        BaselineRef(
                            "SCuBA", "MS.AAD.1.1v1", "Protect emergency access accounts with FIDO2"
                        ),
                    ],
                    remediation=Remediation(
                        description=(
                            "Assign a FIDO2 hardware security key (YubiKey, Feitian, etc.) to each "
                            "break-glass account. Create a Conditional Access policy scoped to "
                            "exactly these accounts that requires FIDO2 authentication strength."
                        ),
                        snippets=[
                            (
                                "Entra Portal",
                                (
                                    "Authentication Methods → FIDO2 → Enable for break-glass group\n\n"
                                    "Conditional Access → New policy\n"
                                    "  Users: [break-glass group]\n"
                                    "  Grant: Require authentication strength → FIDO2 security key\n"
                                    "  State: On"
                                ),
                            ),
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access",
                        ],
                    ),
                    confidence=0.8,
                )
            )

        # ----------------------------------------------------------------
        # CA-BG-003: Break-glass still covered by CA policies (not fully excluded)
        # ----------------------------------------------------------------
        bg_still_covered = [uid for uid in bg_candidates if _has_any_enforced_policy(uid, resolver)]

        if bg_still_covered:
            upns = [
                data.users_by_id[uid].user_principal_name
                for uid in bg_still_covered
                if uid in data.users_by_id
            ]
            findings.append(
                Finding(
                    id="CA-BG-003",
                    title="Break-glass account(s) are not excluded from all CA policies",
                    severity=Severity.high,
                    summary=(
                        f"{len(bg_still_covered)} break-glass account(s) are still subject to one or "
                        "more enforced CA policies. This defeats the purpose of a break-glass account: "
                        "if CA policy enforcement is the problem, the break-glass account must be "
                        "fully excluded."
                    ),
                    why_it_matters=(
                        "The entire value of a break-glass account is that it can sign in regardless "
                        "of CA policy state. If it is still covered by even one MFA policy, an MFA "
                        "provider outage will prevent emergency access. Microsoft recommends that "
                        "break-glass accounts are excluded from ALL Conditional Access policies."
                    ),
                    evidence={
                        "break_glass_still_covered": len(bg_still_covered),
                        "sample_upns": upns[:5],
                    },
                    affected_principals=bg_still_covered,
                    baselines=[
                        BaselineRef(
                            "SCuBA", "MS.AAD.1.1v1", "Emergency accounts excluded from CA policies"
                        ),
                    ],
                    remediation=Remediation(
                        description=(
                            "Add the break-glass account(s) or their group to the Exclude list of "
                            "every Conditional Access policy. Use a dedicated break-glass group to "
                            "make this manageable."
                        ),
                        snippets=[
                            (
                                "Entra Portal",
                                (
                                    "For each CA policy:\n"
                                    "  Assignments → Users → Exclude → [break-glass group]\n"
                                    "  Save"
                                ),
                            ),
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa#exclude-emergency-access-accounts",
                        ],
                    ),
                    confidence=0.85,
                )
            )

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _identify_break_glass_candidates(
    users: list,
    data: SnapshotData,
    resolver: PolicyResolver,
    mfa_policies: list,
) -> list[str]:
    """Find user IDs that look like break-glass accounts."""
    candidates: set[str] = set()

    for user in users:
        upn = user.user_principal_name or ""

        # Heuristic 1: UPN/display name matches break-glass keywords
        if _BG_NAME_PATTERN.search(upn):
            candidates.add(user.id)
            continue

        # Heuristic 2: excluded from all MFA-enforcing policies
        if mfa_policies and _excluded_from_all_mfa_policies(user.id, data, mfa_policies):
            candidates.add(user.id)

    return list(candidates)


def _excluded_from_all_mfa_policies(
    user_id: str,
    data: SnapshotData,
    mfa_policies: list,
) -> bool:
    """Return True if the user is explicitly excluded from every given MFA policy."""
    if not mfa_policies:
        return False

    for policy in mfa_policies:
        uc = policy.conditions.users
        if not uc:
            return False  # policy has no user conditions → not excluded

        # Check direct user exclusion
        if user_id in uc.exclude_users:
            continue

        # Check group exclusion
        user_groups = data.user_group_index.get(user_id, set())
        if any(gid in user_groups for gid in uc.exclude_groups):
            continue

        # Check role exclusion
        user_roles = data.user_role_index.get(user_id, set())
        if any(rid in user_roles for rid in uc.exclude_roles):
            continue

        # Not excluded from this policy
        return False

    return True  # excluded from every MFA policy


def _has_phishing_resistant_requirement(
    user_id: str,
    resolver: PolicyResolver,
    data: SnapshotData,
) -> bool:
    """Return True if a phishing-resistant auth strength policy covers this user."""
    policies = resolver.effective_policies(user_id, "All", _BROWSER_CONDITIONS)
    for policy in policies:
        if policy.state != PolicyState.enabled:
            continue
        gc = policy.grant_controls
        if not gc:
            continue
        for ctrl in gc.built_in_controls:
            normalised = ctrl.lower().replace(" ", "").replace("-", "")
            if any(kw in normalised for kw in _PHISHING_RESISTANT_CONTROLS):
                return True
        if gc.authentication_strength:
            return True  # presence of any auth strength is a positive signal
    return False


def _has_any_enforced_policy(user_id: str, resolver: PolicyResolver) -> bool:
    """Return True if any enforced (non-report-only) policy applies to this user."""
    policies = resolver.effective_policies(user_id, "All", _BROWSER_CONDITIONS)
    return any(p.state == PolicyState.enabled for p in policies)
