"""Terraform / OpenTofu remediation export.

Generates a `.tf` file using the HashiCorp AzureAD Terraform provider
(azuread_conditional_access_policy) that creates Conditional Access policies to address detected gaps.
"""

from __future__ import annotations

from datetime import datetime

from ca_radar.analysers.runner import AnalysisResult

_HEADER = """# ============================================================
# ca-radar auto-generated Terraform remediation
# Tenant  : {tenant_id}
# Scan    : {captured_at}
# Findings: {finding_ids}
#
# ALL policies are created in report-only ('disabledForReportingButNotEnforced') mode.
# Review sign-in logs before enabling.
# ============================================================

terraform {{
  required_providers {{
    azuread = {{
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }}
  }}
}}

"""

_TMPL_MFA_ALL = """resource "azuread_conditional_access_policy" "require_mfa_all_users" {
  display_name = "CA-MFA-001: Require MFA for All Users [ca-radar]"
  state        = "disabledForReportingButNotEnforced"

  conditions {
    client_app_types = ["all"]

    users {
      included_users = ["All"]
      excluded_users = [] # TODO: Add break-glass user IDs here
    }

    applications {
      included_applications = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}
"""

_TMPL_BLOCK_LEGACY = """resource "azuread_conditional_access_policy" "block_legacy_authentication" {
  display_name = "CA-LEGACY-001: Block Legacy Authentication [ca-radar]"
  state        = "disabledForReportingButNotEnforced"

  conditions {
    client_app_types = ["other", "exchangeActiveSync"]

    users {
      included_users = ["All"]
    }

    applications {
      included_applications = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}
"""

_TMPL_ADMIN_MFA = """resource "azuread_conditional_access_policy" "require_phishing_resistant_mfa_admins" {
  display_name = "CA-ADMIN-001: Require Phishing-Resistant MFA for Privileged Roles [ca-radar]"
  state        = "disabledForReportingButNotEnforced"

  conditions {
    client_app_types = ["all"]

    users {
      included_roles = [
        "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", # Conditional Access Administrator
      ]
    }

    applications {
      included_applications = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}
"""

_TMPL_DEVICE_COMPLIANCE = """resource "azuread_conditional_access_policy" "require_device_compliance" {
  display_name = "CA-DEV-001: Require Compliant or Hybrid Joined Device [ca-radar]"
  state        = "disabledForReportingButNotEnforced"

  conditions {
    client_app_types = ["all"]

    users {
      included_users = ["All"]
    }

    applications {
      included_applications = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["compliantDevice", "domainJoinedDevice"]
  }
}
"""

_TEMPLATES: dict[str, str] = {
    "CA-MFA-001": _TMPL_MFA_ALL,
    "CA-LEGACY-001": _TMPL_BLOCK_LEGACY,
    "CA-LEGACY-002": _TMPL_BLOCK_LEGACY,
    "CA-ADMIN-001": _TMPL_ADMIN_MFA,
    "CA-DEV-001": _TMPL_DEVICE_COMPLIANCE,
}


def export_terraform(
    analysis: AnalysisResult,
    tenant_id: str = "",
    captured_at: datetime | str = "",
) -> str:
    """Generate a .tf Terraform HCL file addressing detected findings.

    Args:
        analysis:    Completed AnalysisResult from run_analysers().
        tenant_id:   Tenant identifier.
        captured_at: Snapshot timestamp.

    Returns:
        HCL content string (empty if no findings have Terraform templates).
    """
    active_ids = {f.id for f in analysis.findings}
    matching_ids = sorted(active_ids & set(_TEMPLATES.keys()))

    if not matching_ids:
        return ""

    cap_str = captured_at.isoformat() if isinstance(captured_at, datetime) else str(captured_at)
    header = _HEADER.format(
        tenant_id=tenant_id or "unknown",
        captured_at=cap_str or datetime.utcnow().isoformat(),
        finding_ids=", ".join(matching_ids),
    )

    emitted_templates: set[str] = set()
    blocks: list[str] = []

    for fid in matching_ids:
        tmpl = _TEMPLATES[fid]
        if tmpl not in emitted_templates:
            emitted_templates.add(tmpl)
            blocks.append(tmpl)

    return header + "\n\n".join(blocks)
