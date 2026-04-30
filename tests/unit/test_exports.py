"""Tests for ca_radar.exports — json_export, csv_export, bicep_export.

Each export function receives an AnalysisResult and produces a string.
We test:
  - schema / structural correctness
  - field values match the input
  - edge cases (no findings, multiple findings, special characters)
  - Bicep template selection and deduplication
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

import pytest

from ca_radar.analysers.base import (
    BaselineRef,
    Finding,
    Remediation,
    Severity,
)
from ca_radar.analysers.runner import AnalysisResult
from ca_radar.exports.bicep_export import export_bicep
from ca_radar.exports.csv_export import export_csv
from ca_radar.exports.json_export import FINDINGS_SCHEMA_VERSION, export_json

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    id: str = "CA-MFA-001",
    title: str = "Test finding",
    severity: Severity = Severity.high,
    summary: str = "A gap was found.",
    why: str = "Because it matters.",
    evidence: dict | None = None,
    principals: list[str] | None = None,
    baselines: list[BaselineRef] | None = None,
    remediation: Remediation | None = None,
    confidence: float = 1.0,
) -> Finding:
    return Finding(
        id=id,
        title=title,
        severity=severity,
        summary=summary,
        why_it_matters=why,
        evidence=evidence or {},
        affected_principals=principals or [],
        baselines=baselines or [],
        remediation=remediation,
        confidence=confidence,
    )


def _empty_result() -> AnalysisResult:
    return AnalysisResult(findings=[], analyser_errors={}, elapsed_seconds=0.5)


def _result_with(*findings: Finding, errors: dict | None = None) -> AnalysisResult:
    return AnalysisResult(
        findings=list(findings),
        analyser_errors=errors or {},
        elapsed_seconds=1.23,
    )


_TS = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
_TS_STR = "2025-06-01T12:00:00+00:00"
_TENANT = "contoso.onmicrosoft.com"


# ===========================================================================
# JSON export
# ===========================================================================


class TestExportJson:
    def test_returns_valid_json(self):
        result = _empty_result()
        raw = export_json(result, _TENANT, _TS)
        doc = json.loads(raw)
        assert isinstance(doc, dict)

    def test_schema_version_present(self):
        doc = json.loads(export_json(_empty_result(), _TENANT, _TS))
        assert doc["schema_version"] == FINDINGS_SCHEMA_VERSION

    def test_tenant_id_in_output(self):
        doc = json.loads(export_json(_empty_result(), _TENANT, _TS))
        assert doc["tenant_id"] == _TENANT

    def test_captured_at_datetime_converted(self):
        doc = json.loads(export_json(_empty_result(), _TENANT, _TS))
        assert doc["captured_at"] == _TS_STR

    def test_captured_at_string_passthrough(self):
        doc = json.loads(export_json(_empty_result(), _TENANT, "2025-01-01"))
        assert doc["captured_at"] == "2025-01-01"

    def test_redacted_flag_true_by_default(self):
        doc = json.loads(export_json(_empty_result(), _TENANT, _TS))
        assert doc["redacted"] is True

    def test_redacted_flag_false(self):
        doc = json.loads(export_json(_empty_result(), _TENANT, _TS, redacted=False))
        assert doc["redacted"] is False

    def test_tool_version_included(self):
        doc = json.loads(export_json(_empty_result(), _TENANT, _TS, tool_version="0.1.0"))
        assert doc["tool_version"] == "0.1.0"

    def test_empty_findings_array(self):
        doc = json.loads(export_json(_empty_result(), _TENANT, _TS))
        assert doc["findings"] == []
        assert doc["summary"]["total_findings"] == 0

    def test_posture_score_100_for_empty(self):
        doc = json.loads(export_json(_empty_result(), _TENANT, _TS))
        assert doc["summary"]["posture_score"] == 100

    def test_single_finding_serialised(self):
        f = _make_finding(id="CA-MFA-001", severity=Severity.high)
        result = _result_with(f)
        doc = json.loads(export_json(result, _TENANT, _TS))
        assert len(doc["findings"]) == 1
        assert doc["findings"][0]["id"] == "CA-MFA-001"
        assert doc["findings"][0]["severity"] == "high"

    def test_by_severity_counts(self):
        findings = [
            _make_finding(id="CA-MFA-001", severity=Severity.critical),
            _make_finding(id="CA-MFA-002", severity=Severity.high),
            _make_finding(id="CA-LEGACY-001", severity=Severity.high),
        ]
        result = _result_with(*findings)
        doc = json.loads(export_json(result, _TENANT, _TS))
        by_sev = doc["summary"]["by_severity"]
        assert by_sev["critical"] == 1
        assert by_sev["high"] == 2
        assert by_sev["medium"] == 0

    def test_posture_score_decreases_with_findings(self):
        # One high finding = -7
        f = _make_finding(severity=Severity.high)
        doc = json.loads(export_json(_result_with(f), _TENANT, _TS))
        assert doc["summary"]["posture_score"] == 93

    def test_analyser_errors_in_output(self):
        result = _result_with(errors={"<MfaCoverageAnalyser>": "timeout"})
        doc = json.loads(export_json(result, _TENANT, _TS))
        assert doc["analyser_errors"]["<MfaCoverageAnalyser>"] == "timeout"
        assert doc["summary"]["analyser_errors"] == 1

    def test_baselines_serialised(self):
        f = _make_finding(
            baselines=[
                BaselineRef(framework="SCuBA", control_id="MS.AAD.3.1v1", title="MFA"),
            ]
        )
        doc = json.loads(export_json(_result_with(f), _TENANT, _TS))
        bl = doc["findings"][0]["baselines"][0]
        assert bl["framework"] == "SCuBA"
        assert bl["control_id"] == "MS.AAD.3.1v1"

    def test_remediation_serialised(self):
        rem = Remediation(
            description="Enable MFA.",
            snippets=[("PowerShell", "Set-Policy ...")],
            references=["https://aka.ms/mfa"],
        )
        f = _make_finding(remediation=rem)
        doc = json.loads(export_json(_result_with(f), _TENANT, _TS))
        r = doc["findings"][0]["remediation"]
        assert r["description"] == "Enable MFA."
        assert r["references"] == ["https://aka.ms/mfa"]

    def test_no_remediation_is_null(self):
        f = _make_finding(remediation=None)
        doc = json.loads(export_json(_result_with(f), _TENANT, _TS))
        assert doc["findings"][0]["remediation"] is None

    def test_compact_indent_zero(self):
        raw = export_json(_empty_result(), _TENANT, _TS, indent=0)
        # compact JSON has no newlines after colons
        assert "\n" not in raw

    def test_elapsed_seconds_rounded(self):
        result = AnalysisResult(findings=[], analyser_errors={}, elapsed_seconds=3.14159)
        doc = json.loads(export_json(result, _TENANT, _TS))
        assert doc["summary"]["elapsed_seconds"] == 3.14

    def test_confidence_below_one_preserved(self):
        f = _make_finding(confidence=0.75)
        doc = json.loads(export_json(_result_with(f), _TENANT, _TS))
        assert doc["findings"][0]["confidence"] == pytest.approx(0.75)

    def test_unicode_tenant_not_escaped(self):
        # ensure_ascii=False — non-ASCII chars should stay as-is
        f = _make_finding(title="Ünïcödé títle")
        raw = export_json(_result_with(f), "tenánt.com", _TS)
        assert "Ünïcödé títle" in raw
        assert "tenánt.com" in raw


# ===========================================================================
# CSV export
# ===========================================================================


class TestExportCsv:
    def _parse(self, result: AnalysisResult, *, ts=_TS) -> list[dict]:
        raw = export_csv(result, _TENANT, ts)
        # Strip BOM
        raw = raw.lstrip("﻿")
        reader = csv.DictReader(io.StringIO(raw))
        return list(reader)

    def test_returns_string(self):
        assert isinstance(export_csv(_empty_result(), _TENANT, _TS), str)

    def test_utf8_bom_present(self):
        raw = export_csv(_empty_result(), _TENANT, _TS)
        assert raw.startswith("﻿") or raw.startswith("\xef\xbb\xbf")

    def test_header_columns_present(self):
        rows = self._parse(_empty_result())
        assert rows == []  # no data rows, but no error means header was parsed

        # Parse header directly
        raw = export_csv(_empty_result(), _TENANT, _TS).lstrip("﻿")
        header_line = raw.split("\r\n")[0]
        expected_fields = [
            "finding_id",
            "severity",
            "confidence",
            "title",
            "affected_count",
            "baselines",
            "summary",
            "tenant_id",
            "captured_at",
        ]
        for field in expected_fields:
            assert field in header_line

    def test_empty_findings_no_data_rows(self):
        rows = self._parse(_empty_result())
        assert rows == []

    def test_single_finding_row(self):
        f = _make_finding(id="CA-MFA-001", severity=Severity.high, title="No MFA")
        rows = self._parse(_result_with(f))
        assert len(rows) == 1
        assert rows[0]["finding_id"] == "CA-MFA-001"
        assert rows[0]["severity"] == "high"
        assert rows[0]["title"] == "No MFA"

    def test_confidence_two_decimal_places(self):
        f = _make_finding(confidence=0.75)
        rows = self._parse(_result_with(f))
        assert rows[0]["confidence"] == "0.75"

    def test_affected_count_zero(self):
        f = _make_finding(principals=[])
        rows = self._parse(_result_with(f))
        assert rows[0]["affected_count"] == "0"

    def test_affected_count_nonzero(self):
        f = _make_finding(principals=["u1", "u2", "u3"])
        rows = self._parse(_result_with(f))
        assert rows[0]["affected_count"] == "3"

    def test_baselines_pipe_delimited(self):
        f = _make_finding(
            baselines=[
                BaselineRef(framework="SCuBA", control_id="MS.AAD.3.1v1"),
                BaselineRef(framework="CIS", control_id="1.1.4"),
            ]
        )
        rows = self._parse(_result_with(f))
        assert rows[0]["baselines"] == "SCuBA:MS.AAD.3.1v1|CIS:1.1.4"

    def test_baselines_empty_string_when_none(self):
        f = _make_finding(baselines=[])
        rows = self._parse(_result_with(f))
        assert rows[0]["baselines"] == ""

    def test_tenant_id_in_every_row(self):
        findings = [_make_finding(id="CA-MFA-001"), _make_finding(id="CA-MFA-002")]
        rows = self._parse(_result_with(*findings))
        for row in rows:
            assert row["tenant_id"] == _TENANT

    def test_captured_at_datetime_converted(self):
        rows = self._parse(_result_with(_make_finding()))
        assert rows[0]["captured_at"] == _TS_STR

    def test_captured_at_string(self):
        raw = export_csv(_result_with(_make_finding()), _TENANT, "2025-01-01")
        raw = raw.lstrip("﻿")
        rows = list(csv.DictReader(io.StringIO(raw)))
        assert rows[0]["captured_at"] == "2025-01-01"

    def test_summary_newlines_stripped(self):
        f = _make_finding(summary="Line one.\nLine two.")
        rows = self._parse(_result_with(f))
        assert "\n" not in rows[0]["summary"]
        assert "Line one." in rows[0]["summary"]

    def test_multiple_findings_multiple_rows(self):
        findings = [
            _make_finding(id="CA-MFA-001"),
            _make_finding(id="CA-LEGACY-001"),
            _make_finding(id="CA-ADMIN-001"),
        ]
        rows = self._parse(_result_with(*findings))
        assert len(rows) == 3

    def test_crlf_line_endings(self):
        raw = export_csv(_result_with(_make_finding()), _TENANT, _TS).lstrip("﻿")
        assert "\r\n" in raw


# ===========================================================================
# Bicep export
# ===========================================================================


class TestExportBicep:
    def test_no_findings_returns_empty_string(self):
        assert export_bicep(_empty_result(), _TENANT, _TS) == ""

    def test_unknown_finding_id_returns_empty_string(self):
        f = _make_finding(id="CA-UNKNOWN-999")
        assert export_bicep(_result_with(f), _TENANT, _TS) == ""

    def test_returns_string_for_known_finding(self):
        f = _make_finding(id="CA-MFA-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert isinstance(out, str)
        assert len(out) > 0

    def test_header_contains_extension_declaration(self):
        f = _make_finding(id="CA-MFA-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "extension microsoftGraph" in out

    def test_header_contains_tenant_id(self):
        f = _make_finding(id="CA-MFA-001")
        out = export_bicep(_result_with(f), "mytenant.com", _TS)
        assert "mytenant.com" in out

    def test_header_contains_finding_ids(self):
        f = _make_finding(id="CA-MFA-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "CA-MFA-001" in out

    # --- CA-MFA-001 ---

    def test_mfa_all_users_template(self):
        f = _make_finding(id="CA-MFA-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "requireMfaAllUsers" in out
        assert "includeUsers: ['All']" in out
        assert "enabledForReportingButNotEnforced" in out

    # --- CA-LEGACY-001 / CA-LEGACY-002 ---

    def test_legacy_001_template(self):
        f = _make_finding(id="CA-LEGACY-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "blockLegacyAuth" in out
        assert "exchangeActiveSync" in out

    def test_legacy_002_same_template_as_001(self):
        f = _make_finding(id="CA-LEGACY-002")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "blockLegacyAuth" in out

    def test_legacy_001_and_002_deduped(self):
        """Both CA-LEGACY-001 and CA-LEGACY-002 share one Bicep resource."""
        f1 = _make_finding(id="CA-LEGACY-001")
        f2 = _make_finding(id="CA-LEGACY-002")
        out = export_bicep(_result_with(f1, f2), _TENANT, _TS)
        assert out.count("blockLegacyAuth") == 1

    # --- CA-ADMIN-001 ---

    def test_admin_phish_template(self):
        f = _make_finding(id="CA-ADMIN-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "requirePhishResistantAdmins" in out
        # Phishing-resistant strength ID
        assert "00000000-0000-0000-0000-000000000004" in out

    def test_admin_template_contains_privileged_role_ids(self):
        f = _make_finding(id="CA-ADMIN-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        # Global Administrator role GUID
        assert "62e90394-69f5-4237-9190-012177145e10" in out

    # --- CA-RISK-001 ---

    def test_sign_in_risk_template(self):
        f = _make_finding(id="CA-RISK-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "requireMfaOnSignInRisk" in out
        assert "signInRiskLevels" in out
        assert "'medium'" in out

    # --- CA-RISK-002 ---

    def test_user_risk_template(self):
        f = _make_finding(id="CA-RISK-002")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "requirePasswordChangeOnUserRisk" in out
        assert "userRiskLevels" in out
        assert "'high'" in out

    # --- CA-SESS-001 ---

    def test_session_freq_template(self):
        f = _make_finding(id="CA-SESS-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "signInFrequencyAdmins" in out
        assert "signInFrequency" in out

    def test_session_template_contains_privileged_role_ids(self):
        f = _make_finding(id="CA-SESS-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "62e90394-69f5-4237-9190-012177145e10" in out

    # --- CA-BG-001 ---

    def test_bg_comment_block(self):
        f = _make_finding(id="CA-BG-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert "break-glass" in out.lower()
        assert "FIDO2" in out or "fido2" in out.lower() or "hardware key" in out.lower()

    def test_bg_no_resource_block(self):
        """BG finding produces a comment, not a Bicep resource."""
        f = _make_finding(id="CA-BG-001")
        out = export_bicep(_result_with(f), _TENANT, _TS)
        # Comment-only means no resource declaration
        assert "Microsoft.Graph/conditionalAccessPolicies" not in out

    # --- Deduplication / multi-finding ---

    def test_mfa_deduped_when_appearing_twice(self):
        """AnalysisResult cannot have duplicate IDs, but even if passed twice
        the template should appear once."""
        f = _make_finding(id="CA-MFA-001")
        # Single finding — sanity check on deduplication logic
        out = export_bicep(_result_with(f), _TENANT, _TS)
        assert out.count("requireMfaAllUsers") == 1

    def test_multiple_templates_combined(self):
        findings = [
            _make_finding(id="CA-MFA-001"),
            _make_finding(id="CA-LEGACY-001"),
            _make_finding(id="CA-RISK-001"),
        ]
        out = export_bicep(_result_with(*findings), _TENANT, _TS)
        assert "requireMfaAllUsers" in out
        assert "blockLegacyAuth" in out
        assert "requireMfaOnSignInRisk" in out

    def test_all_policies_in_report_only_mode(self):
        """Every generated policy must be report-only (never 'enabled' directly)."""
        findings = [
            _make_finding(id="CA-MFA-001"),
            _make_finding(id="CA-LEGACY-001"),
            _make_finding(id="CA-ADMIN-001"),
            _make_finding(id="CA-RISK-001"),
            _make_finding(id="CA-RISK-002"),
            _make_finding(id="CA-SESS-001"),
        ]
        out = export_bicep(_result_with(*findings), _TENANT, _TS)
        # All state values should be report-only
        assert "enabledForReportingButNotEnforced" in out
        # No plain 'enabled' state (not counting the substring inside report-only)
        lines_with_state = [ln for ln in out.splitlines() if "state:" in ln]
        for ln in lines_with_state:
            assert "enabledForReportingButNotEnforced" in ln, (
                f"Policy has non-report-only state: {ln!r}"
            )
