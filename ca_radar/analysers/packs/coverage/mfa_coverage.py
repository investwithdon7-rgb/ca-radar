"""MFA coverage detections.

CA-MFA-001  Users not covered by any MFA-enforcing policy          [critical]
CA-MFA-002  Admin users not covered by phishing-resistant auth      [critical]
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
from ca_radar.resolver.effective_controls import EvaluationConditions, PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData
from ca_radar.snapshot.models import PolicyState

log = logging.getLogger(__name__)

# Role template IDs for highly-privileged Entra roles
PRIVILEGED_ROLE_IDS: frozenset[str] = frozenset(
    {
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
        "966707d0-3269-4727-9be2-8c3a10f19b9d",  # Password Administrator
        "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
        "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Exchange Online P1 (preview)
        "3a2c62db-5318-420d-8d74-23affee5d9d5",  # Intune Administrator
        "4d6ac14f-3453-41d0-bef9-a3e0c569773a",  # License Administrator (not critical but included)
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
        "e6d1a23a-da11-4be4-9570-befc86d067a7",  # Privileged Role Administrator equivalent
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    }
)

# Entra CA built-in control name for MFA
_MFA_CONTROL = "mfa"

# Authentication strength policies considered phishing-resistant
_PHISHING_RESISTANT_KEYWORDS = frozenset(
    {
        "phishingresistant",
        "fido2",
        "windowshelloforbusiness",
        "certificatebasedauthentication",
        "passkey",
    }
)

# Browser + mobile is the most common sign-in scenario
_BROWSER_CONDITIONS = EvaluationConditions(client_app_type="browser")


class MfaCoverageAnalyser(Analyser):
    """Detects users and admins lacking adequate MFA coverage."""

    @property
    def finding_ids(self) -> list[str]:
        return ["CA-MFA-001", "CA-MFA-002"]

    def analyse(self, data: SnapshotData, resolver: PolicyResolver) -> list[Finding]:
        findings: list[Finding] = []

        # Only analyse enabled (non-guest, non-service-account) users
        real_users = [u for u in data.users if u.account_enabled and u.user_type != "Guest"]
        if not real_users:
            log.warning("CA-MFA: no enabled member users in snapshot — skipping")
            return []

        # ----------------------------------------------------------------
        # CA-MFA-001: users with NO MFA-enforcing policy
        # ----------------------------------------------------------------
        uncovered: list[str] = []
        for user in real_users:
            policies = resolver.effective_policies(user.id, "All", _BROWSER_CONDITIONS)
            enforced = [
                p
                for p in policies
                if p.state == PolicyState.enabled
                and p.grant_controls
                and _MFA_CONTROL in [c.lower() for c in p.grant_controls.built_in_controls]
            ]
            if not enforced:
                uncovered.append(user.id)

        if uncovered:
            upns = [
                data.users_by_id[uid].user_principal_name
                for uid in uncovered
                if uid in data.users_by_id
            ]
            findings.append(
                Finding(
                    id="CA-MFA-001",
                    title="Users not covered by any MFA-enforcing Conditional Access policy",
                    severity=Severity.critical,
                    summary=(
                        f"{len(uncovered)} user(s) can authenticate without MFA because no enabled, "
                        "enforced CA policy requires it for their account."
                    ),
                    why_it_matters=(
                        "Multi-factor authentication is the single most effective control against "
                        "credential-based attacks, including phishing and password spray. An attacker "
                        "who obtains a password for an uncovered account has unrestricted access to "
                        "all resources that account can reach. CISA SCuBA and CIS M365 both require "
                        "MFA for all users."
                    ),
                    evidence={
                        "uncovered_user_count": len(uncovered),
                        "sample_upns": upns[:10],
                    },
                    affected_principals=uncovered,
                    baselines=[
                        BaselineRef("SCuBA", "MS.AAD.3.2v1", "MFA for all users"),
                        BaselineRef("CIS", "1.1.4", "Ensure MFA is enabled for all users"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Create or update a Conditional Access policy that requires MFA for all users. "
                            "Exclude only your break-glass account(s) from this policy."
                        ),
                        snippets=[
                            (
                                "Entra Portal",
                                (
                                    "Entra ID → Protection → Conditional Access → New policy\n"
                                    "  Users: All users\n"
                                    "  Cloud apps: All cloud apps\n"
                                    "  Grant: Require multifactor authentication\n"
                                    "  State: On"
                                ),
                            ),
                            (
                                "Microsoft Graph (PowerShell)",
                                (
                                    "# Requires Policy.ReadWrite.ConditionalAccess\n"
                                    "$params = @{\n"
                                    "  displayName = 'Require MFA for all users'\n"
                                    "  state = 'enabled'\n"
                                    "  conditions = @{ users = @{ includeUsers = @('All') }; ... }\n"
                                    "  grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }\n"
                                    "}\n"
                                    "New-MgIdentityConditionalAccessPolicy -BodyParameter $params"
                                ),
                            ),
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa",
                            "https://www.cisa.gov/sites/default/files/2023-06/ScubaGear_M365_Authentication.pdf",
                        ],
                    ),
                    confidence=1.0,
                )
            )

        # ----------------------------------------------------------------
        # CA-MFA-002: admins not covered by phishing-resistant auth strength
        # ----------------------------------------------------------------
        admin_users = [
            u for u in real_users if data.user_role_index.get(u.id, set()) & PRIVILEGED_ROLE_IDS
        ]

        admins_without_phish_resistant: list[str] = []
        for user in admin_users:
            policies = resolver.effective_policies(user.id, "All", _BROWSER_CONDITIONS)
            has_phish_resistant = _has_phishing_resistant_strength(policies, data)
            if not has_phish_resistant:
                admins_without_phish_resistant.append(user.id)

        if admins_without_phish_resistant:
            upns = [
                data.users_by_id[uid].user_principal_name
                for uid in admins_without_phish_resistant
                if uid in data.users_by_id
            ]
            findings.append(
                Finding(
                    id="CA-MFA-002",
                    title="Privileged admin accounts not protected by phishing-resistant authentication",
                    severity=Severity.critical,
                    summary=(
                        f"{len(admins_without_phish_resistant)} admin account(s) are covered only by "
                        "basic MFA (e.g. SMS, voice, or authenticator app push) rather than a "
                        "phishing-resistant authentication strength such as FIDO2, Windows Hello, or "
                        "certificate-based authentication."
                    ),
                    why_it_matters=(
                        "Privileged roles are the primary target of adversary-in-the-middle (AiTM) "
                        "phishing kits such as Evilginx2 and Modlishka. These tools can intercept and "
                        "replay any MFA factor that passes through the browser — TOTP codes, push "
                        "notifications, and even Conditional Access claims. Only hardware-bound or "
                        "channel-binding authentication methods (FIDO2, Windows Hello, CBA) defeat "
                        "AiTM. CISA SCuBA MS.AAD.3.1 and CIS Control 1.1.8 both require phishing-"
                        "resistant MFA for highly privileged roles."
                    ),
                    evidence={
                        "affected_admin_count": len(admins_without_phish_resistant),
                        "sample_upns": upns[:10],
                    },
                    affected_principals=admins_without_phish_resistant,
                    baselines=[
                        BaselineRef(
                            "SCuBA", "MS.AAD.3.1v1", "Phishing-resistant MFA for privileged roles"
                        ),
                        BaselineRef("CIS", "1.1.8", "Require phishing-resistant MFA for admins"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Create an Authentication Strength policy requiring FIDO2 security key, "
                            "Windows Hello for Business, or Certificate-Based Authentication. Apply it "
                            "via a CA policy that targets all highly privileged directory roles."
                        ),
                        snippets=[
                            (
                                "Entra Portal",
                                (
                                    "Entra ID → Protection → Authentication strengths → New strength\n"
                                    "  Allowed combinations: FIDO2 security key, Windows Hello for Business\n\n"
                                    "Then: Conditional Access → New policy\n"
                                    "  Users: Directory roles → [all privileged roles]\n"
                                    "  Grant: Require authentication strength → [your new strength]\n"
                                    "  State: On"
                                ),
                            ),
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-strengths",
                            "https://www.cisa.gov/sites/default/files/2023-06/ScubaGear_M365_Authentication.pdf",
                        ],
                    ),
                    confidence=0.9,  # auth strength presence in CA may not equal enforcement
                )
            )

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_phishing_resistant_strength(
    policies: list,
    data: SnapshotData,
) -> bool:
    """Return True if any enforced policy requires a phishing-resistant auth strength."""
    for policy in policies:
        if policy.state != PolicyState.enabled:
            continue
        gc = policy.grant_controls
        if not gc:
            continue
        # Check for explicit phishing-resistant built-in control (newer Graph representation).
        # Use the full keywords set so fido2, windowshelloforbusiness, passkey, etc. also match.
        for ctrl in gc.built_in_controls:
            normalised = ctrl.lower().replace(" ", "").replace("-", "")
            if any(kw in normalised for kw in _PHISHING_RESISTANT_KEYWORDS):
                return True
        # Check auth strength reference
        if gc.authentication_strength:
            strength_id = gc.authentication_strength.get("id", "")
            # Look up the strength policy by ID to check allowed combinations
            for strength in data.authentication_strength_policies:
                if strength.id == strength_id:
                    for combo in strength.allowed_combinations:
                        combo_str = " ".join(combo).lower().replace(" ", "").replace("-", "")
                        if any(kw in combo_str for kw in _PHISHING_RESISTANT_KEYWORDS):
                            return True
    return False
