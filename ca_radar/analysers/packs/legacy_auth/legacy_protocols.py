"""Legacy authentication detections.

CA-LEGACY-001  Legacy authentication permitted for at least one user/app combo  [critical]
CA-LEGACY-002  No CA policy explicitly blocks legacy authentication protocols    [high]
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

# Client app types that represent legacy authentication
_LEGACY_CLIENT_TYPES = ("exchangeActiveSync", "other")

_LEGACY_CONDITIONS_EAS = EvaluationConditions(client_app_type="exchangeActiveSync")
_LEGACY_CONDITIONS_OTHER = EvaluationConditions(client_app_type="other")


class LegacyAuthAnalyser(Analyser):
    """Detects tenants where legacy authentication is not fully blocked."""

    @property
    def finding_ids(self) -> list[str]:
        return ["CA-LEGACY-001", "CA-LEGACY-002"]

    def analyse(self, data: SnapshotData, resolver: PolicyResolver) -> list[Finding]:
        findings: list[Finding] = []

        enabled_policies = [p for p in data.policies if p.state == PolicyState.enabled]

        # ----------------------------------------------------------------
        # CA-LEGACY-002 (check this first — simpler, informs CA-LEGACY-001)
        # Does ANY policy explicitly block legacy client app types?
        # ----------------------------------------------------------------
        blocking_policies = _find_legacy_blocking_policies(enabled_policies)

        if not blocking_policies:
            findings.append(
                Finding(
                    id="CA-LEGACY-002",
                    title="No Conditional Access policy explicitly blocks legacy authentication",
                    severity=Severity.high,
                    summary=(
                        "No enabled CA policy targets the legacy client app types "
                        "(exchangeActiveSync, other) with a Block grant control. "
                        "Legacy authentication protocols such as IMAP, POP3, SMTP AUTH, "
                        "and Basic Auth cannot enforce MFA and are trivially bypassed."
                    ),
                    why_it_matters=(
                        "Legacy protocols pre-date modern authentication and do not support "
                        "multi-factor authentication or Conditional Access evaluation. Attackers "
                        "routinely use password spray attacks against legacy endpoints because a "
                        "stolen password is sufficient — there is no MFA prompt to intercept. "
                        "Microsoft has recorded that over 99% of password spray attacks use legacy "
                        "protocols. CISA SCuBA MS.AAD.7.3 and CIS M365 1.1.3 both require blocking "
                        "legacy authentication."
                    ),
                    evidence={
                        "legacy_client_types_checked": list(_LEGACY_CLIENT_TYPES),
                        "blocking_policy_ids": [],
                    },
                    affected_principals=[],
                    baselines=[
                        BaselineRef("SCuBA", "MS.AAD.7.3v1", "Block legacy authentication"),
                        BaselineRef("CIS", "1.1.3", "Block legacy authentication protocols"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Create a CA policy that targets all users and blocks "
                            "exchangeActiveSync and 'Other clients' (legacy protocols). "
                            "Test in report-only mode first to identify any affected workflows."
                        ),
                        snippets=[
                            (
                                "Entra Portal",
                                (
                                    "Conditional Access → New policy\n"
                                    "  Users: All users\n"
                                    "  Cloud apps: All cloud apps\n"
                                    "  Conditions → Client apps: Exchange ActiveSync clients, Other clients\n"
                                    "  Grant: Block access\n"
                                    "  State: Report-only → On"
                                ),
                            ),
                            (
                                "Microsoft Graph (PowerShell)",
                                (
                                    "$params = @{\n"
                                    "  displayName = 'Block legacy authentication'\n"
                                    "  state = 'enabled'\n"
                                    "  conditions = @{\n"
                                    "    users = @{ includeUsers = @('All') }\n"
                                    "    applications = @{ includeApplications = @('All') }\n"
                                    "    clientAppTypes = @('exchangeActiveSync', 'other')\n"
                                    "  }\n"
                                    "  grantControls = @{ operator = 'OR'; builtInControls = @('block') }\n"
                                    "}\n"
                                    "New-MgIdentityConditionalAccessPolicy -BodyParameter $params"
                                ),
                            ),
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication",
                            "https://techcommunity.microsoft.com/t5/microsoft-entra-blog/99-9-of-compromised-accounts-didn-t-use-mfa/ba-p/1173371",
                        ],
                    ),
                )
            )

        # ----------------------------------------------------------------
        # CA-LEGACY-001: Are there users who can still authenticate via legacy?
        # A user is "exposed" if no blocking policy covers them for legacy client types.
        # ----------------------------------------------------------------
        real_users = [u for u in data.users if u.account_enabled and u.user_type != "Guest"]

        exposed_users: list[str] = []
        for user in real_users:
            # Check both legacy client types
            for conds in (_LEGACY_CONDITIONS_EAS, _LEGACY_CONDITIONS_OTHER):
                policies = resolver.effective_policies(user.id, "All", conds)
                is_blocked = any(
                    p.state == PolicyState.enabled
                    and p.grant_controls
                    and "block" in [c.lower() for c in p.grant_controls.built_in_controls]
                    for p in policies
                )
                if not is_blocked:
                    exposed_users.append(user.id)
                    break  # Only count each user once

        if exposed_users:
            upns = [
                data.users_by_id[uid].user_principal_name
                for uid in exposed_users
                if uid in data.users_by_id
            ]
            findings.append(
                Finding(
                    id="CA-LEGACY-001",
                    title="Legacy authentication is not blocked for all users",
                    severity=Severity.critical,
                    summary=(
                        f"{len(exposed_users)} user(s) can authenticate using legacy protocols "
                        "(Exchange ActiveSync, IMAP, POP3, SMTP AUTH) without MFA. "
                        "Legacy protocols cannot enforce Conditional Access."
                    ),
                    why_it_matters=(
                        "Legacy authentication endpoints are the path of least resistance for "
                        "credential-based attacks. Password spray campaigns targeting EWS, IMAP, "
                        "and POP3 bypass every MFA control in your tenant because these protocols "
                        "were designed before MFA existed. A single compromised account with "
                        "mailbox access can be used for business email compromise (BEC), data "
                        "exfiltration, and lateral movement."
                    ),
                    evidence={
                        "exposed_user_count": len(exposed_users),
                        "sample_upns": upns[:10],
                        "legacy_client_types": list(_LEGACY_CLIENT_TYPES),
                        "blocking_policy_ids": [p.id for p in blocking_policies],
                    },
                    affected_principals=exposed_users,
                    baselines=[
                        BaselineRef("SCuBA", "MS.AAD.7.3v1", "Block legacy authentication"),
                        BaselineRef("CIS", "1.1.3", "Block legacy authentication protocols"),
                        BaselineRef("NCSC", "IAA-3", "Disable legacy authentication protocols"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Ensure your legacy-block CA policy covers all users without exclusions. "
                            "If business applications require legacy protocols, migrate them to modern "
                            "authentication before enabling the block."
                        ),
                        snippets=[
                            (
                                "Find apps using legacy auth (PowerShell)",
                                (
                                    "# Check Sign-in logs for legacy auth usage\n"
                                    "Get-MgAuditLogSignIn -Filter \"clientAppUsed ne 'Browser' and "
                                    "clientAppUsed ne 'Mobile Apps and Desktop clients'\" "
                                    "-Top 100 | Select UserPrincipalName, ClientAppUsed, AppDisplayName"
                                ),
                            ),
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication",
                        ],
                    ),
                )
            )

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_legacy_blocking_policies(policies: list) -> list:
    """Return policies that block at least one legacy client app type."""
    result = []
    for p in policies:
        cat = p.conditions.client_app_types
        if not cat:
            continue
        legacy_targeted = any(t in cat for t in _LEGACY_CLIENT_TYPES)
        if not legacy_targeted:
            continue
        gc = p.grant_controls
        if gc and "block" in [c.lower() for c in gc.built_in_controls]:
            result.append(p)
    return result
