"""Tests for portfolio renderer and tenant YAML models."""

from __future__ import annotations

import textwrap
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ca_radar.render.html.portfolio_renderer import render_portfolio_report
from ca_radar.tenants.models import TenantConfig, TenantsFile
from ca_radar.trend.store import PortfolioSummaryRow

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(
    tenant_id: str = "contoso.onmicrosoft.com",
    score: int = 80,
    total: int = 2,
    critical: int = 0,
    high: int = 2,
    medium: int = 0,
    low: int = 0,
    info: int = 0,
    scan_count: int = 3,
    trend_scores: list[int] | None = None,
    report_path: str = "",
    captured_at: str = "2025-06-01T12:00:00+00:00",
) -> PortfolioSummaryRow:
    return PortfolioSummaryRow(
        tenant_id=tenant_id,
        latest_captured_at=captured_at,
        latest_posture_score=score,
        latest_total_findings=total,
        latest_critical=critical,
        latest_high=high,
        latest_medium=medium,
        latest_low=low,
        latest_info=info,
        scan_count=scan_count,
        trend_scores=trend_scores or [75, 78, 80],
        report_path=report_path,
    )


_TS = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)


# ===========================================================================
# Portfolio renderer
# ===========================================================================


class TestRenderPortfolioReport:
    def test_returns_string(self):
        html = render_portfolio_report([], captured_at=_TS)
        assert isinstance(html, str)

    def test_valid_html_structure(self):
        html = render_portfolio_report([], captured_at=_TS)
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html

    def test_empty_rows_shows_empty_state(self):
        html = render_portfolio_report([], captured_at=_TS)
        assert "No tenant scans recorded" in html

    def test_tenant_id_in_output(self):
        rows = [_row("fabrikam.onmicrosoft.com")]
        html = render_portfolio_report(rows, captured_at=_TS)
        assert "fabrikam.onmicrosoft.com" in html

    def test_posture_score_in_output(self):
        rows = [_row(score=73)]
        html = render_portfolio_report(rows, captured_at=_TS)
        assert "73" in html

    def test_total_tenants_count(self):
        rows = [_row("a"), _row("b"), _row("c")]
        html = render_portfolio_report(rows, captured_at=_TS)
        assert ">3<" in html  # stat card

    def test_avg_score_computed(self):
        rows = [_row(score=60), _row(score=80)]
        html = render_portfolio_report(rows, captured_at=_TS)
        assert "70.0" in html

    def test_tool_version_in_footer(self):
        html = render_portfolio_report([], captured_at=_TS, tool_version="0.1.0")
        assert "0.1.0" in html

    def test_captured_at_datetime_converted(self):
        html = render_portfolio_report([], captured_at=_TS)
        assert "2025-06-01" in html

    def test_captured_at_string_accepted(self):
        html = render_portfolio_report([], captured_at="2025-01-15")
        assert "2025-01-15" in html

    def test_captured_at_defaults_to_now(self):
        # Should not raise; just verify it renders
        html = render_portfolio_report([])
        assert "<!DOCTYPE html>" in html

    def test_report_link_rendered(self):
        rows = [_row(report_path="../contoso/20250601T120000Z/report.html")]
        html = render_portfolio_report(rows, captured_at=_TS)
        assert "report.html" in html
        assert "report ↗" in html

    def test_no_report_path_shows_dash(self):
        rows = [_row(report_path="")]
        html = render_portfolio_report(rows, captured_at=_TS)
        # Should not have a broken link
        assert 'href=""' not in html

    def test_sparkline_rendered_for_multiple_scores(self):
        rows = [_row(trend_scores=[70, 75, 80])]
        html = render_portfolio_report(rows, captured_at=_TS)
        assert "<polyline" in html

    def test_single_trend_score_no_polyline(self):
        rows = [_row(trend_scores=[80])]
        html = render_portfolio_report(rows, captured_at=_TS)
        assert "<polyline" not in html

    def test_critical_count_in_total_stat(self):
        rows = [_row(critical=3), _row(critical=2)]
        html = render_portfolio_report(rows, captured_at=_TS)
        # Sum should be 5
        assert ">5<" in html

    def test_multiple_tenants_all_present(self):
        rows = [_row("alpha"), _row("beta"), _row("gamma")]
        html = render_portfolio_report(rows, captured_at=_TS)
        for name in ["alpha", "beta", "gamma"]:
            assert name in html

    def test_sort_js_present(self):
        html = render_portfolio_report([_row()], captured_at=_TS)
        assert "sortTable" in html

    def test_score_ok_class_for_high_score(self):
        rows = [_row(score=90)]
        html = render_portfolio_report(rows, captured_at=_TS)
        assert "score-ok" in html

    def test_score_bad_class_for_low_score(self):
        rows = [_row(score=30)]
        html = render_portfolio_report(rows, captured_at=_TS)
        assert "score-bad" in html


# ===========================================================================
# TenantConfig
# ===========================================================================


class TestTenantConfig:
    def test_display_name_uses_name_field(self):
        tc = TenantConfig(id="contoso.onmicrosoft.com", name="Contoso Ltd")
        assert tc.display_name == "Contoso Ltd"

    def test_display_name_falls_back_to_id(self):
        tc = TenantConfig(id="contoso.onmicrosoft.com")
        assert tc.display_name == "contoso.onmicrosoft.com"

    def test_defaults(self):
        tc = TenantConfig(id="t")
        assert tc.auth_mode == "delegated"
        assert tc.client_id == ""
        assert tc.cert_path == ""
        assert tc.client_secret == ""


# ===========================================================================
# TenantsFile.from_yaml
# ===========================================================================


class TestTenantsFileFromYaml:
    def _write(self, tmp_path: Path, content: str) -> Path:
        p = tmp_path / "tenants.yaml"
        p.write_text(textwrap.dedent(content), encoding="utf-8")
        return p

    def test_parses_minimal_tenant(self, tmp_path):
        p = self._write(
            tmp_path,
            """\
            tenants:
              - id: contoso.onmicrosoft.com
        """,
        )
        tf = TenantsFile.from_yaml(p)
        assert len(tf.tenants) == 1
        assert tf.tenants[0].id == "contoso.onmicrosoft.com"

    def test_parses_all_fields(self, tmp_path):
        p = self._write(
            tmp_path,
            """\
            tenants:
              - id: contoso.onmicrosoft.com
                name: Contoso Ltd
                auth_mode: app
                client_id: "abc-123"
                cert_path: "/certs/c.pem"
                client_secret: "s3cr3t"
        """,
        )
        tf = TenantsFile.from_yaml(p)
        tc = tf.tenants[0]
        assert tc.name == "Contoso Ltd"
        assert tc.auth_mode == "app"
        assert tc.client_id == "abc-123"
        assert tc.cert_path == "/certs/c.pem"
        assert tc.client_secret == "s3cr3t"

    def test_parses_multiple_tenants(self, tmp_path):
        p = self._write(
            tmp_path,
            """\
            tenants:
              - id: alpha.onmicrosoft.com
              - id: beta.onmicrosoft.com
              - id: gamma.onmicrosoft.com
        """,
        )
        tf = TenantsFile.from_yaml(p)
        assert len(tf.tenants) == 3

    def test_auth_mode_defaults_to_delegated(self, tmp_path):
        p = self._write(
            tmp_path,
            """\
            tenants:
              - id: contoso.onmicrosoft.com
        """,
        )
        tf = TenantsFile.from_yaml(p)
        assert tf.tenants[0].auth_mode == "delegated"

    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            TenantsFile.from_yaml(tmp_path / "nonexistent.yaml")

    def test_missing_tenants_key_raises(self, tmp_path):
        p = self._write(tmp_path, "foo: bar\n")
        with pytest.raises(ValueError, match="'tenants'"):
            TenantsFile.from_yaml(p)

    def test_missing_id_raises(self, tmp_path):
        p = self._write(
            tmp_path,
            """\
            tenants:
              - name: Contoso Ltd
        """,
        )
        with pytest.raises(ValueError, match="'id'"):
            TenantsFile.from_yaml(p)

    def test_empty_tenants_list_ok(self, tmp_path):
        p = self._write(tmp_path, "tenants: []\n")
        tf = TenantsFile.from_yaml(p)
        assert tf.tenants == []

    def test_null_tenants_list_ok(self, tmp_path):
        p = self._write(tmp_path, "tenants:\n")
        tf = TenantsFile.from_yaml(p)
        assert tf.tenants == []

    def test_optional_fields_default_to_empty_string(self, tmp_path):
        p = self._write(
            tmp_path,
            """\
            tenants:
              - id: contoso.onmicrosoft.com
        """,
        )
        tc = TenantsFile.from_yaml(p).tenants[0]
        assert tc.name == ""
        assert tc.client_id == ""
        assert tc.cert_path == ""
        assert tc.client_secret == ""
