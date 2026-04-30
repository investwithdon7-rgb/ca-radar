"""Risk-based and session control detections.

CA-RISK-001  No sign-in risk-based Conditional Access policy              [high]
CA-RISK-002  No user risk-based Conditional Access policy                 [high]
CA-SESS-001  No CA policy enforces sign-in frequency (session lifetime)   [medium]

Detection rationale
-------------------
CA-RISK-001 / CA-RISK-002
  Entra Identity Protection evaluates sign-in and user risk in real time.
  Without CA policies that ACT on those risk signals (require MFA or block),
  a detected risky sign-in or compromised account has no automated response —
  it just generates an alert that may or may not be reviewed.

CA-SESS-001
  Without a sign-in frequency session control, authentication tokens can
  remain valid for extended periods (Entra default: up to 90 days for
  persistent browser sessions).  This means a stolen refresh token gives
  long-lived access with no re-authentication prompt.
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


class RiskSessionAnalyser(Analyser):
    """Detects missing risk-based and session lifetime controls."""

    @property
    def finding_ids(self) -> list[str]:
        return ["CA-RISK-001", "CA-RISK-002", "CA-SESS-001"]

    def analyse(self, data: SnapshotData, resolver: PolicyResolver) -> list[Finding]:
        findings: list[Finding] = []

        enabled_policies = [p for p in data.policies if p.state == PolicyState.enabled]

        # ----------------------------------------------------------------
        # CA-RISK-001: No sign-in risk policy
        # ----------------------------------------------------------------
        sign_in_risk_policies = [p for p in enabled_policies if p.conditions.sign_in_risk_levels]

        if not sign_in_risk_policies:
            findings.append(
                Finding(
                    id="CA-RISK-001",
                    title="No Conditional Access policy responds to sign-in risk",
                    severity=Severity.high,
                    summary=(
                        "No enabled CA policy uses sign-in risk levels as a condition. "
                        "Entra Identity Protection detects anomalous sign-in patterns (unfamiliar location, "
                        "password spray, token replay) in real time, but these signals have no automated "
                        "enforcement action."
                    ),
                    why_it_matters=(
                        "Identity Protection sign-in risk is one of the most effective early-warning signals "
                        "for active attacks. Without a CA policy that triggers MFA or blocks on medium/high "
                        "sign-in risk, a risky sign-in generates only an alert — no friction is added for "
                        "the attacker. CISA SCuBA MS.AAD.6.1 requires sign-in risk-based CA policies for "
                        "all users."
                    ),
                    evidence={
                        "sign_in_risk_policy_count": 0,
                    },
                    affected_principals=[],
                    baselines=[
                        BaselineRef(
                            "SCuBA", "MS.AAD.6.1v1", "Require MFA on medium/high sign-in risk"
                        ),
                        BaselineRef("CIS", "1.1.6", "Configure risk-based CA policies"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Enable Entra Identity Protection (P2) and create a CA policy that requires "
                            "MFA when sign-in risk is medium or high, and blocks access on high risk."
                        ),
                        snippets=[
                            (
                                "Entra Portal",
                                (
                                    "Conditional Access → New policy\n"
                                    "  Users: All users\n"
                                    "  Conditions → Sign-in risk: Medium, High\n"
                                    "  Grant: Require multifactor authentication\n"
                                    "  State: On"
                                ),
                            ),
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-risk",
                        ],
                    ),
                )
            )

        # ----------------------------------------------------------------
        # CA-RISK-002: No user risk policy
        # ----------------------------------------------------------------
        user_risk_policies = [p for p in enabled_policies if p.conditions.user_risk_levels]

        if not user_risk_policies:
            findings.append(
                Finding(
                    id="CA-RISK-002",
                    title="No Conditional Access policy responds to user risk",
                    severity=Severity.high,
                    summary=(
                        "No enabled CA policy uses user risk levels as a condition. "
                        "User risk represents Identity Protection's confidence that an account is "
                        "compromised (e.g. leaked credentials, confirmed compromise). "
                        "Without a policy, compromised accounts continue to operate unimpeded."
                    ),
                    why_it_matters=(
                        "User risk is a higher-fidelity signal than sign-in risk: it indicates that "
                        "Identity Protection has detected strong evidence of credential compromise, such "
                        "as the account's password appearing in a breach database or confirmed attacker "
                        "activity. A CA policy that requires password reset (or blocks) on high user risk "
                        "provides automated incident response for the majority of credential-based attacks. "
                        "CISA SCuBA MS.AAD.6.2 requires user risk-based CA policies."
                    ),
                    evidence={
                        "user_risk_policy_count": 0,
                    },
                    affected_principals=[],
                    baselines=[
                        BaselineRef(
                            "SCuBA", "MS.AAD.6.2v1", "Require password change on high user risk"
                        ),
                        BaselineRef("CIS", "1.1.6", "Configure user risk CA policies"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Create a CA policy that requires password change when user risk is high, "
                            "and MFA when user risk is medium. Ensure Identity Protection (P2) is licensed."
                        ),
                        snippets=[
                            (
                                "Entra Portal",
                                (
                                    "Conditional Access → New policy\n"
                                    "  Users: All users\n"
                                    "  Conditions → User risk: High\n"
                                    "  Grant: Require password change\n"
                                    "  State: On"
                                ),
                            ),
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-risk-user",
                        ],
                    ),
                )
            )

        # ----------------------------------------------------------------
        # CA-SESS-001: No sign-in frequency session control
        # ----------------------------------------------------------------
        freq_policies = [
            p
            for p in enabled_policies
            if p.session_controls and p.session_controls.sign_in_frequency
        ]

        if not freq_policies:
            findings.append(
                Finding(
                    id="CA-SESS-001",
                    title="No CA policy enforces session sign-in frequency (token lifetime)",
                    severity=Severity.medium,
                    summary=(
                        "No enabled CA policy uses a sign-in frequency session control to limit "
                        "how long authentication tokens remain valid. Entra's default allows refresh "
                        "tokens to persist for up to 90 days, giving a stolen token long-lived access."
                    ),
                    why_it_matters=(
                        "Post-authentication token theft (pass-the-token, session hijacking) is the "
                        "primary technique used after a successful AiTM phishing attack. By enforcing "
                        "a sign-in frequency, you limit the window during which a stolen token is "
                        "useful. For privileged accounts, a low frequency (e.g. 'Every time' for "
                        "persistent sessions, or 1-hour for privileged portals) dramatically reduces "
                        "attacker dwell time."
                    ),
                    evidence={
                        "sign_in_frequency_policy_count": 0,
                    },
                    affected_principals=[],
                    baselines=[
                        BaselineRef(
                            "SCuBA",
                            "MS.AAD.5.3v1",
                            "Configure sign-in frequency for privileged sessions",
                        ),
                        BaselineRef("CIS", "1.1.7", "Set session controls for privileged access"),
                    ],
                    remediation=Remediation(
                        description=(
                            "Create a CA policy targeting privileged directory roles that sets sign-in "
                            "frequency to 'Every time' for persistent browser sessions, and sets an "
                            "inactivity timeout of 1 hour. For all users, consider disabling persistent "
                            "browser sessions on unmanaged devices."
                        ),
                        snippets=[
                            (
                                "Entra Portal",
                                (
                                    "Conditional Access → New policy\n"
                                    "  Users: Directory roles → [privileged roles]\n"
                                    "  Session → Sign-in frequency: Every time (for persistent sessions)\n"
                                    "         → Persistent browser session: Never persistent\n"
                                    "  State: On"
                                ),
                            ),
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime",
                        ],
                    ),
                )
            )

        return findings
