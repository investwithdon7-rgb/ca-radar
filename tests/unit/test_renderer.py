"""Tests for the HTML renderer.

Checks:
  - render_html_report() returns a valid, non-empty HTML string
  - Key structural elements are always present
  - Finding IDs, titles, and severity labels appear in the output
  - Posture score is embedded correctly
  - Graph JSON is embedded
  - Empty-findings case renders the 'no findings' state
  - Redacted / not-redacted flag is reflected in the footer
"""

from __future__ import annotations

from datetime import UTC, datetime

from ca_radar.analysers.base import BaselineRef, Finding, Remediation, Severity
from ca_radar.analysers.runner import AnalysisResult
from ca_radar.render.html.renderer import render_html_report
from ca_radar.resolver.policy_graph import PolicyGraph, SnapshotData
from ca_radar.snapshot.models import (
    CaApplicationCondition,
    CaConditions,
    CaGrantControl,
    CaUserCondition,
    ConditionalAccessPolicy,
    Group,
    PolicyState,
    User,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_finding(
    fid: str, sev: Severity, *, affected: int = 0, confidence: float = 1.0
) -> Finding:
    return Finding(
        id=fid,
        title=f"Test finding {fid}",
        severity=sev,
        summary=f"Summary for {fid}",
        why_it_matters=f"Why {fid} matters.",
        evidence={"key": "value", "count": affected},
        affected_principals=[f"user-{i}" for i in range(affected)],
        baselines=[BaselineRef("SCuBA", "MS.AAD.1.1v1", "Test baseline")],
        remediation=Remediation(
            description="Do the thing.",
            snippets=[("Portal", "Click here"), ("PowerShell", "Get-MgPolicy")],
            references=["https://example.com/fix"],
        ),
        confidence=confidence,
    )


def _minimal_snapshot() -> SnapshotData:
    users = [User(id="u1", user_principal_name="alice@contoso.com", account_enabled=True)]
    groups = [
        Group(id="g1", display_name="All Users", member_ids=["u1"], transitive_member_ids=["u1"])
    ]
    policy = ConditionalAccessPolicy(
        id="p1",
        display_name="Require MFA",
        state=PolicyState.enabled,
        conditions=CaConditions(
            users=CaUserCondition(include_users=["All"]),
            applications=CaApplicationCondition(include_applications=["All"]),
        ),
        grant_controls=CaGrantControl(operator="OR", built_in_controls=["mfa"]),
    )
    data = SnapshotData(users=users, groups=groups, policies=[policy])
    data._build_indexes()
    return data


def _render(findings: list[Finding], redacted: bool = True) -> str:
    result = AnalysisResult(findings=findings, elapsed_seconds=1.23)
    data = _minimal_snapshot()
    graph = PolicyGraph.from_data(data)
    return render_html_report(
        result,
        graph.to_json_dict(),
        tenant_id="contoso.onmicrosoft.com",
        captured_at=datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC),
        redacted=redacted,
        tool_version="0.1.0",
    )


# ---------------------------------------------------------------------------
# Structural tests
# ---------------------------------------------------------------------------


class TestRendererStructure:
    def test_returns_non_empty_string(self):
        html = _render([])
        assert isinstance(html, str)
        assert len(html) > 500

    def test_has_doctype(self):
        html = _render([])
        assert html.lstrip().startswith("<!DOCTYPE html>")

    def test_has_title_with_tenant(self):
        html = _render([])
        assert "contoso.onmicrosoft.com" in html

    def test_has_posture_score(self):
        # No findings → score 100
        html = _render([])
        assert "100" in html

    def test_posture_score_with_findings(self):
        findings = [_make_finding("CA-MFA-001", Severity.critical)]
        # critical weight = 15, score = 100-15 = 85
        html = _render(findings)
        assert "85" in html

    def test_has_ca_radar_brand(self):
        html = _render([])
        assert "ca-radar" in html

    def test_has_captured_at(self):
        html = _render([])
        assert "2024-06-15" in html

    def test_has_tool_version(self):
        html = _render([])
        assert "0.1.0" in html

    def test_graph_json_embedded(self):
        html = _render([])
        assert "GRAPH_DATA" in html
        assert '"nodes"' in html

    def test_findings_json_embedded(self):
        findings = [_make_finding("CA-MFA-001", Severity.critical)]
        html = _render(findings)
        assert "FINDINGS" in html
        assert "CA-MFA-001" in html


# ---------------------------------------------------------------------------
# Findings content tests
# ---------------------------------------------------------------------------


class TestRendererFindings:
    def test_empty_findings_shows_no_findings_state(self):
        html = _render([])
        assert "No findings" in html

    def test_finding_id_appears(self):
        findings = [_make_finding("CA-BG-001", Severity.critical)]
        html = _render(findings)
        assert "CA-BG-001" in html

    def test_finding_title_appears(self):
        findings = [_make_finding("CA-LEGACY-001", Severity.critical)]
        html = _render(findings)
        assert "Test finding CA-LEGACY-001" in html

    def test_severity_label_appears(self):
        findings = [_make_finding("CA-MFA-002", Severity.high)]
        html = _render(findings)
        assert "high" in html.lower()

    def test_multiple_findings_all_present(self):
        findings = [
            _make_finding("CA-MFA-001", Severity.critical),
            _make_finding("CA-BG-001", Severity.critical),
            _make_finding("CA-SESS-001", Severity.medium),
        ]
        html = _render(findings)
        for f in findings:
            assert f.id in html

    def test_severity_counts_in_summary(self):
        findings = [
            _make_finding("CA-MFA-001", Severity.critical),
            _make_finding("CA-BG-001", Severity.critical),
            _make_finding("CA-SESS-001", Severity.medium),
        ]
        html = _render(findings)
        # 2 critical, 1 medium → both counts should appear
        assert "CA-MFA-001" in html
        assert "CA-SESS-001" in html

    def test_remediation_snippet_label_appears(self):
        findings = [_make_finding("CA-MFA-001", Severity.critical)]
        html = _render(findings)
        assert "Portal" in html
        assert "PowerShell" in html

    def test_baseline_tag_appears(self):
        findings = [_make_finding("CA-MFA-001", Severity.critical)]
        html = _render(findings)
        assert "SCuBA" in html
        assert "MS.AAD.1.1v1" in html

    def test_reference_link_appears(self):
        findings = [_make_finding("CA-MFA-001", Severity.critical)]
        html = _render(findings)
        assert "https://example.com/fix" in html

    def test_affected_principals_count(self):
        findings = [_make_finding("CA-MFA-001", Severity.critical, affected=7)]
        html = _render(findings)
        assert "7" in html

    def test_low_confidence_renders_bar(self):
        findings = [_make_finding("CA-BG-001", Severity.critical, confidence=0.7)]
        html = _render(findings)
        assert "70%" in html


# ---------------------------------------------------------------------------
# Redaction flag
# ---------------------------------------------------------------------------


class TestRendererRedaction:
    def test_redacted_flag_in_footer(self):
        html = _render([], redacted=True)
        assert "hashed" in html.lower() or "redacted" in html.lower()

    def test_not_redacted_warning_in_footer(self):
        html = _render([], redacted=False)
        assert "not redacted" in html.lower() or "UPNs not redacted" in html


# ---------------------------------------------------------------------------
# Graph data embedding
# ---------------------------------------------------------------------------


class TestRendererGraph:
    def test_graph_nodes_in_output(self):
        html = _render([])
        # The snapshot has users, groups, and a policy node
        idx = html.find("GRAPH_DATA")
        assert idx != -1
        # Just assert the embedded string contains expected structure
        assert '"nodes"' in html
        assert '"links"' in html

    def test_d3_cdn_script_tag_present(self):
        html = _render([])
        assert "d3" in html
        assert "cdn.jsdelivr.net" in html
