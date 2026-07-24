"""Unit tests for Terraform export module."""

from ca_radar.analysers.base import Finding, Remediation, Severity
from ca_radar.analysers.runner import AnalysisResult
from ca_radar.exports.terraform_export import export_terraform


def test_export_terraform_empty_when_no_matching_findings() -> None:
    finding = Finding(
        id="CA-UNKNOWN-999",
        title="Unknown Finding",
        severity=Severity.low,
        summary="Test",
        why_it_matters="Test",
        evidence={},
        affected_principals=[],
        remediation=Remediation(description="Test"),
    )
    analysis = AnalysisResult(findings=[finding])

    tf_str = export_terraform(analysis, tenant_id="contoso.com")
    assert tf_str == ""


def test_export_terraform_generates_hcl_resource_blocks() -> None:
    finding1 = Finding(
        id="CA-MFA-001",
        title="Require MFA",
        severity=Severity.critical,
        summary="Test",
        why_it_matters="Test",
        evidence={},
        affected_principals=[],
        remediation=Remediation(description="Test"),
    )
    finding2 = Finding(
        id="CA-DEV-001",
        title="Require Device Compliance",
        severity=Severity.high,
        summary="Test",
        why_it_matters="Test",
        evidence={},
        affected_principals=[],
        remediation=Remediation(description="Test"),
    )
    analysis = AnalysisResult(findings=[finding1, finding2])

    tf_str = export_terraform(analysis, tenant_id="contoso.com", captured_at="2026-07-24T10:00:00Z")

    assert 'resource "azuread_conditional_access_policy" "require_mfa_all_users"' in tf_str
    assert 'resource "azuread_conditional_access_policy" "require_device_compliance"' in tf_str
    assert 'state        = "disabledForReportingButNotEnforced"' in tf_str
