"""Bicep remediation export.

Generates a `.bicep` file using the Microsoft Graph Bicep extension
(https://learn.microsoft.com/en-us/graph/templates/overview) that creates
Conditional Access policies to address detected gaps.

Each finding ID that has a known Bicep template contributes one or more
`Microsoft.Graph/conditionalAccessPolicies@v1.0` resources to the output.
All generated policies are initialised in `enabledForReportingButNotEnforced`
(report-only) mode so operators can validate impact before enforcing.

Finding IDs with Bicep templates
---------------------------------
CA-MFA-001     → Require MFA for all users
CA-LEGACY-001  → Block legacy authentication (EAS + Other)
CA-LEGACY-002  → Block legacy authentication (EAS + Other)   [same template]
CA-ADMIN-001   → Require phishing-resistant MFA for privileged roles
CA-RISK-001    → Require MFA on medium/high sign-in risk
CA-RISK-002    → Require password change on high user risk
CA-SESS-001    → Enforce sign-in frequency for privileged roles
CA-BG-001      → Break-glass group + exclusion placeholder (comment only)
"""

from __future__ import annotations

from ca_radar.analysers.runner import AnalysisResult

# Privileged role IDs used in admin / session policies
_PRIVILEGED_ROLES = [
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
    "e6d1a23a-da11-4be4-9570-befc86d067a7",  # Privileged Role Administrator
]

_HEADER = """\
// ============================================================
// ca-radar auto-generated Bicep remediation
// Tenant  : {tenant_id}
// Scan    : {captured_at}
// Findings: {finding_ids}
//
// ALL policies are created in report-only mode.
// Review sign-in logs for 1–2 weeks, then change
// state to 'enabled' once you are confident in the impact.
//
// Requires: Microsoft Graph Bicep extension
//   https://learn.microsoft.com/en-us/graph/templates/overview
// ============================================================

extension microsoftGraph

"""

# ── Individual policy templates ─────────────────────────────────────────────

_TMPL_MFA_ALL = """\
// CA-MFA-001: Require MFA for all users
// TODO: Add break-glass account IDs to excludeUsers before enabling.
resource requireMfaAllUsers 'Microsoft.Graph/conditionalAccessPolicies@v1.0' = {{
  displayName: 'CA-RADAR: Require MFA for all users'
  state: 'enabledForReportingButNotEnforced'
  conditions: {{
    users: {{
      includeUsers: ['All']
      excludeUsers: []  // <-- insert break-glass UPNs / object IDs
    }}
    applications: {{
      includeApplications: ['All']
    }}
    clientAppTypes: ['browser', 'mobileAppsAndDesktopClients']
  }}
  grantControls: {{
    operator: 'OR'
    builtInControls: ['mfa']
  }}
}}

"""

_TMPL_BLOCK_LEGACY = """\
// CA-LEGACY-001 / CA-LEGACY-002: Block legacy authentication
resource blockLegacyAuth 'Microsoft.Graph/conditionalAccessPolicies@v1.0' = {{
  displayName: 'CA-RADAR: Block legacy authentication'
  state: 'enabledForReportingButNotEnforced'
  conditions: {{
    users: {{
      includeUsers: ['All']
    }}
    applications: {{
      includeApplications: ['All']
    }}
    clientAppTypes: ['exchangeActiveSync', 'other']
  }}
  grantControls: {{
    operator: 'OR'
    builtInControls: ['block']
  }}
}}

"""

_TMPL_ADMIN_PHISH = """\
// CA-ADMIN-001: Require phishing-resistant MFA for privileged roles
resource requirePhishResistantAdmins 'Microsoft.Graph/conditionalAccessPolicies@v1.0' = {{
  displayName: 'CA-RADAR: Require phishing-resistant MFA for admins'
  state: 'enabledForReportingButNotEnforced'
  conditions: {{
    users: {{
      includeRoles: [
        {role_ids}
      ]
    }}
    applications: {{
      includeApplications: ['All']
    }}
    clientAppTypes: ['browser', 'mobileAppsAndDesktopClients']
  }}
  grantControls: {{
    operator: 'OR'
    authenticationStrength: {{
      id: '00000000-0000-0000-0000-000000000004'  // Built-in: Phishing-resistant MFA
    }}
  }}
}}

"""

_TMPL_SIGN_IN_RISK = """\
// CA-RISK-001: Require MFA when sign-in risk is medium or high
resource requireMfaOnSignInRisk 'Microsoft.Graph/conditionalAccessPolicies@v1.0' = {{
  displayName: 'CA-RADAR: Require MFA on sign-in risk'
  state: 'enabledForReportingButNotEnforced'
  conditions: {{
    users: {{
      includeUsers: ['All']
    }}
    applications: {{
      includeApplications: ['All']
    }}
    signInRiskLevels: ['medium', 'high']
    clientAppTypes: ['browser', 'mobileAppsAndDesktopClients']
  }}
  grantControls: {{
    operator: 'OR'
    builtInControls: ['mfa']
  }}
}}

"""

_TMPL_USER_RISK = """\
// CA-RISK-002: Require password change when user risk is high
resource requirePasswordChangeOnUserRisk 'Microsoft.Graph/conditionalAccessPolicies@v1.0' = {{
  displayName: 'CA-RADAR: Require password change on high user risk'
  state: 'enabledForReportingButNotEnforced'
  conditions: {{
    users: {{
      includeUsers: ['All']
    }}
    applications: {{
      includeApplications: ['All']
    }}
    userRiskLevels: ['high']
    clientAppTypes: ['browser', 'mobileAppsAndDesktopClients']
  }}
  grantControls: {{
    operator: 'AND'
    builtInControls: ['mfa', 'passwordChange']
  }}
}}

"""

_TMPL_SESSION_FREQ = """\
// CA-SESS-001: Enforce sign-in frequency for privileged roles
resource signInFrequencyAdmins 'Microsoft.Graph/conditionalAccessPolicies@v1.0' = {{
  displayName: 'CA-RADAR: Sign-in frequency for privileged roles'
  state: 'enabledForReportingButNotEnforced'
  conditions: {{
    users: {{
      includeRoles: [
        {role_ids}
      ]
    }}
    applications: {{
      includeApplications: ['All']
    }}
    clientAppTypes: ['browser']
  }}
  sessionControls: {{
    signInFrequency: {{
      value: 1
      type: 'hours'
      authenticationType: 'primaryAndSecondaryAuthentication'
      frequencyInterval: 'everyTime'
      isEnabled: true
    }}
    persistentBrowser: {{
      mode: 'never'
      isEnabled: true
    }}
  }}
}}

"""

_TMPL_BG_COMMENT = """\
// CA-BG-001: No break-glass account detected
// ─────────────────────────────────────────────────────────────────────────
// Bicep cannot create user accounts. Complete these manual steps:
//   1. Create two cloud-only accounts named e.g.
//      break-glass-1@{tenant_id}
//      break-glass-2@{tenant_id}
//   2. Assign Global Administrator role to both.
//   3. Create a security group "Break Glass Accounts" and add both.
//   4. In EVERY CA policy, add that group to the Exclude list.
//   5. Register a FIDO2 hardware key for each account.
//   6. Store credentials offline in a sealed envelope.
//   Reference: https://aka.ms/break-glass
// ─────────────────────────────────────────────────────────────────────────

"""

# ── Mapping: finding ID → template function ──────────────────────────────────


def _render_role_ids() -> str:
    return "\n        ".join(f"'{rid}'" for rid in _PRIVILEGED_ROLES)


def _templates_for(finding_ids: set[str], tenant_id: str) -> list[str]:
    """Return ordered list of rendered template strings for the given finding IDs."""
    blocks: list[str] = []
    seen: set[str] = set()

    def _add(key: str, block: str) -> None:
        if key not in seen:
            seen.add(key)
            blocks.append(block)

    for fid in sorted(finding_ids):
        if fid == "CA-MFA-001":
            _add("mfa-all", _TMPL_MFA_ALL)
        elif fid in ("CA-LEGACY-001", "CA-LEGACY-002"):
            _add("block-legacy", _TMPL_BLOCK_LEGACY)
        elif fid == "CA-ADMIN-001":
            _add("admin-phish", _TMPL_ADMIN_PHISH.format(role_ids=_render_role_ids()))
        elif fid == "CA-RISK-001":
            _add("sign-in-risk", _TMPL_SIGN_IN_RISK)
        elif fid == "CA-RISK-002":
            _add("user-risk", _TMPL_USER_RISK)
        elif fid == "CA-SESS-001":
            _add("session-freq", _TMPL_SESSION_FREQ.format(role_ids=_render_role_ids()))
        elif fid == "CA-BG-001":
            _add("bg-comment", _TMPL_BG_COMMENT.format(tenant_id=tenant_id))

    return blocks


def export_bicep(
    analysis: AnalysisResult,
    tenant_id: str,
    captured_at: object,
    *,
    tool_version: str = "",
) -> str:
    """Generate a Bicep remediation file from an AnalysisResult.

    Returns an empty string if no findings have Bicep templates.

    Args:
        analysis:     Completed AnalysisResult from run_analysers().
        tenant_id:    Tenant identifier (used in resource names and comments).
        captured_at:  Snapshot timestamp (ISO string or datetime).
        tool_version: ca-radar version string for the header comment.

    Returns:
        Bicep source string, or "" if there is nothing to generate.
    """
    finding_ids = {f.id for f in analysis.findings}
    blocks = _templates_for(finding_ids, tenant_id)

    if not blocks:
        return ""

    header = _HEADER.format(
        tenant_id=tenant_id,
        captured_at=str(captured_at),
        finding_ids=", ".join(sorted(finding_ids)),
    )

    return header + "".join(blocks)
