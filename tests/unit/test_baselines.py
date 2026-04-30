"""Tests for ca_radar.baselines — loader, enricher, alignment.

Covers:
  - YAML parsing via bundled data files
  - BaselineRegistry.refs_for()
  - BaselineRegistry.alignment()
  - enrich_findings() in-place mutation
  - enrich_findings() overwrite flag
  - compute_alignment() convenience wrapper
  - Edge cases: unknown finding ID, empty findings, all passing, all failing
"""

from __future__ import annotations

import textwrap

from ca_radar.analysers.base import BaselineRef, Finding, Severity
from ca_radar.baselines.enricher import compute_alignment, enrich_findings
from ca_radar.baselines.loader import (
    AlignmentResult,
    BaselineRegistry,
    ControlSpec,
    FrameworkSpec,
    load_registry,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    id: str,
    severity: Severity = Severity.high,
    baselines: list[BaselineRef] | None = None,
) -> Finding:
    return Finding(
        id=id,
        title=f"Title for {id}",
        severity=severity,
        summary="summary",
        why_it_matters="why",
        evidence={},
        affected_principals=[],
        baselines=baselines or [],
    )


def _make_registry(*specs: FrameworkSpec) -> BaselineRegistry:
    return BaselineRegistry(list(specs))


def _spec(
    framework: str = "TEST",
    version: str = "1.0",
    url: str = "https://example.com",
    controls: list[ControlSpec] | None = None,
) -> FrameworkSpec:
    return FrameworkSpec(
        framework=framework,
        version=version,
        url=url,
        controls=controls or [],
    )


def _ctrl(id: str, title: str = "", finding_ids: list[str] | None = None) -> ControlSpec:
    return ControlSpec(id=id, title=title, finding_ids=finding_ids or [])


# ===========================================================================
# load_registry — bundled YAML files
# ===========================================================================


class TestLoadRegistry:
    def test_loads_without_error(self):
        registry = load_registry()
        assert registry is not None

    def test_bundled_frameworks_include_scuba(self):
        registry = load_registry()
        assert "SCuBA" in registry.all_frameworks()

    def test_bundled_frameworks_include_cis(self):
        registry = load_registry()
        assert "CIS" in registry.all_frameworks()

    def test_scuba_has_controls(self):
        registry = load_registry()
        scuba = next(s for s in registry.frameworks if s.framework == "SCuBA")
        assert len(scuba.controls) >= 5

    def test_cis_has_controls(self):
        registry = load_registry()
        cis = next(s for s in registry.frameworks if s.framework == "CIS")
        assert len(cis.controls) >= 5

    def test_scuba_has_mfa_mapping(self):
        registry = load_registry()
        refs = registry.refs_for("CA-MFA-001")
        frameworks = [r.framework for r in refs]
        assert "SCuBA" in frameworks

    def test_cis_has_mfa_mapping(self):
        registry = load_registry()
        refs = registry.refs_for("CA-MFA-001")
        frameworks = [r.framework for r in refs]
        assert "CIS" in frameworks

    def test_legacy_mapped_in_both_frameworks(self):
        registry = load_registry()
        refs = registry.refs_for("CA-LEGACY-001")
        frameworks = {r.framework for r in refs}
        assert "SCuBA" in frameworks
        assert "CIS" in frameworks

    def test_loads_from_custom_dir(self, tmp_path):
        """load_registry respects an override data directory."""
        yaml_content = textwrap.dedent("""\
            framework: CUSTOM
            version: "9.9"
            url: "https://custom.example"
            controls:
              - id: CUSTOM-1
                title: "Test control"
                finding_ids:
                  - CA-MFA-001
        """)
        (tmp_path / "custom.yaml").write_text(yaml_content, encoding="utf-8")
        registry = load_registry(data_dir=tmp_path)
        assert "CUSTOM" in registry.all_frameworks()
        assert registry.refs_for("CA-MFA-001")[0].framework == "CUSTOM"

    def test_empty_dir_returns_empty_registry(self, tmp_path):
        registry = load_registry(data_dir=tmp_path)
        assert registry.all_frameworks() == []


# ===========================================================================
# BaselineRegistry.refs_for
# ===========================================================================


class TestRefsFor:
    def test_unknown_finding_id_returns_empty(self):
        registry = _make_registry(_spec())
        assert registry.refs_for("CA-NONEXISTENT-999") == []

    def test_single_framework_single_control(self):
        spec = _spec(
            framework="SCuBA",
            controls=[_ctrl("MS.AAD.2.1v1", "MFA required", ["CA-MFA-001"])],
        )
        registry = _make_registry(spec)
        refs = registry.refs_for("CA-MFA-001")
        assert len(refs) == 1
        assert refs[0].framework == "SCuBA"
        assert refs[0].control_id == "MS.AAD.2.1v1"
        assert refs[0].title == "MFA required"

    def test_finding_mapped_in_two_frameworks(self):
        spec_a = _spec("A", controls=[_ctrl("A-1", finding_ids=["CA-MFA-001"])])
        spec_b = _spec("B", controls=[_ctrl("B-1", finding_ids=["CA-MFA-001"])])
        registry = _make_registry(spec_a, spec_b)
        refs = registry.refs_for("CA-MFA-001")
        frameworks = {r.framework for r in refs}
        assert frameworks == {"A", "B"}

    def test_finding_mapped_to_multiple_controls_same_framework(self):
        spec = _spec(
            "SCuBA",
            controls=[
                _ctrl("MS.AAD.2.1v1", finding_ids=["CA-MFA-001"]),
                _ctrl("MS.AAD.2.3v1", finding_ids=["CA-MFA-001"]),
            ],
        )
        registry = _make_registry(spec)
        refs = registry.refs_for("CA-MFA-001")
        control_ids = {r.control_id for r in refs}
        assert control_ids == {"MS.AAD.2.1v1", "MS.AAD.2.3v1"}

    def test_control_with_no_finding_ids_not_indexed(self):
        spec = _spec(controls=[_ctrl("CTRL-1", finding_ids=[])])
        registry = _make_registry(spec)
        # CTRL-1 doesn't map to anything — querying returns empty
        assert registry.refs_for("CA-ANYTHING") == []

    def test_returns_base_line_ref_objects(self):
        spec = _spec(controls=[_ctrl("X-1", "title", ["CA-MFA-001"])])
        registry = _make_registry(spec)
        refs = registry.refs_for("CA-MFA-001")
        assert all(isinstance(r, BaselineRef) for r in refs)


# ===========================================================================
# BaselineRegistry.alignment
# ===========================================================================


class TestAlignment:
    def test_no_active_findings_all_pass(self):
        spec = _spec(
            "SCuBA",
            controls=[
                _ctrl("C1", finding_ids=["CA-MFA-001"]),
                _ctrl("C2", finding_ids=["CA-LEGACY-001"]),
            ],
        )
        registry = _make_registry(spec)
        result = registry.alignment(set())
        ar = result["SCuBA"]
        assert ar.passing == 2
        assert ar.failing == 0
        assert ar.pct == 100.0

    def test_all_active_findings_all_fail(self):
        spec = _spec(
            "SCuBA",
            controls=[
                _ctrl("C1", finding_ids=["CA-MFA-001"]),
                _ctrl("C2", finding_ids=["CA-LEGACY-001"]),
            ],
        )
        registry = _make_registry(spec)
        result = registry.alignment({"CA-MFA-001", "CA-LEGACY-001"})
        ar = result["SCuBA"]
        assert ar.failing == 2
        assert ar.passing == 0
        assert ar.pct == 0.0

    def test_partial_failure(self):
        spec = _spec(
            "SCuBA",
            controls=[
                _ctrl("C1", finding_ids=["CA-MFA-001"]),
                _ctrl("C2", finding_ids=["CA-LEGACY-001"]),
                _ctrl("C3", finding_ids=["CA-RISK-001"]),
                _ctrl("C4", finding_ids=["CA-RISK-002"]),
            ],
        )
        registry = _make_registry(spec)
        result = registry.alignment({"CA-MFA-001", "CA-RISK-001"})
        ar = result["SCuBA"]
        assert ar.failing == 2
        assert ar.passing == 2
        assert ar.pct == 50.0

    def test_control_with_multiple_finding_ids_fails_on_any(self):
        spec = _spec(
            "SCuBA",
            controls=[
                _ctrl("C1", finding_ids=["CA-LEGACY-001", "CA-LEGACY-002"]),
            ],
        )
        registry = _make_registry(spec)
        # Only one of the two finding IDs is active
        result = registry.alignment({"CA-LEGACY-001"})
        assert result["SCuBA"].failing == 1

    def test_control_with_no_finding_ids_always_passes(self):
        spec = _spec(
            "SCuBA",
            controls=[
                _ctrl("INFO-1", finding_ids=[]),  # always passes
                _ctrl("C1", finding_ids=["CA-MFA-001"]),
            ],
        )
        registry = _make_registry(spec)
        result = registry.alignment({"CA-MFA-001"})
        ar = result["SCuBA"]
        assert ar.total_controls == 2
        assert ar.passing == 1  # INFO-1 passes, C1 fails
        assert ar.failing == 1

    def test_pct_rounded_to_one_decimal(self):
        spec = _spec(
            "SCuBA",
            controls=[_ctrl(f"C{i}", finding_ids=[f"CA-F-{i:03d}"]) for i in range(3)],
        )
        registry = _make_registry(spec)
        # 1 of 3 active → 2/3 passing = 66.7%
        result = registry.alignment({"CA-F-000"})
        assert result["SCuBA"].pct == 66.7

    def test_empty_registry_returns_empty_dict(self):
        registry = _make_registry()
        result = registry.alignment({"CA-MFA-001"})
        assert result == {}

    def test_multiple_frameworks_independent(self):
        spec_a = _spec("A", controls=[_ctrl("A1", finding_ids=["CA-MFA-001"])])
        spec_b = _spec("B", controls=[_ctrl("B1", finding_ids=["CA-LEGACY-001"])])
        registry = _make_registry(spec_a, spec_b)
        result = registry.alignment({"CA-MFA-001"})  # only A1 fails
        assert result["A"].failing == 1
        assert result["B"].failing == 0

    def test_alignment_result_fields(self):
        spec = _spec(
            "SCuBA",
            version="1.0",
            url="https://cisa.gov",
            controls=[_ctrl("C1", finding_ids=["CA-MFA-001"])],
        )
        registry = _make_registry(spec)
        ar = registry.alignment(set())["SCuBA"]
        assert ar.framework == "SCuBA"
        assert ar.version == "1.0"
        assert ar.url == "https://cisa.gov"
        assert ar.total_controls == 1
        assert isinstance(ar, AlignmentResult)


# ===========================================================================
# enrich_findings
# ===========================================================================


class TestEnrichFindings:
    def _simple_registry(self) -> BaselineRegistry:
        spec = _spec(
            "SCuBA",
            controls=[
                _ctrl("MS.AAD.2.1v1", "MFA", ["CA-MFA-001"]),
                _ctrl("MS.AAD.1.1v1", "Legacy", ["CA-LEGACY-001"]),
            ],
        )
        return _make_registry(spec)

    def test_populates_baselines(self):
        findings = [_make_finding("CA-MFA-001")]
        enrich_findings(findings, self._simple_registry())
        assert len(findings[0].baselines) == 1
        assert findings[0].baselines[0].control_id == "MS.AAD.2.1v1"

    def test_unknown_finding_id_leaves_baselines_empty(self):
        findings = [_make_finding("CA-UNKNOWN-999")]
        enrich_findings(findings, self._simple_registry())
        assert findings[0].baselines == []

    def test_existing_baselines_not_overwritten_by_default(self):
        existing = [BaselineRef("CUSTOM", "X-1", "custom")]
        findings = [_make_finding("CA-MFA-001", baselines=existing)]
        enrich_findings(findings, self._simple_registry())
        # Should still have the original custom ref, not the SCuBA one
        assert findings[0].baselines[0].framework == "CUSTOM"

    def test_overwrite_flag_replaces_baselines(self):
        existing = [BaselineRef("CUSTOM", "X-1", "custom")]
        findings = [_make_finding("CA-MFA-001", baselines=existing)]
        enrich_findings(findings, self._simple_registry(), overwrite=True)
        assert findings[0].baselines[0].framework == "SCuBA"

    def test_multiple_findings_enriched(self):
        findings = [
            _make_finding("CA-MFA-001"),
            _make_finding("CA-LEGACY-001"),
        ]
        enrich_findings(findings, self._simple_registry())
        assert findings[0].baselines[0].control_id == "MS.AAD.2.1v1"
        assert findings[1].baselines[0].control_id == "MS.AAD.1.1v1"

    def test_empty_findings_list_no_error(self):
        enrich_findings([], self._simple_registry())  # should not raise

    def test_mutates_in_place(self):
        f = _make_finding("CA-MFA-001")
        original_id = id(f)
        findings = [f]
        enrich_findings(findings, self._simple_registry())
        assert id(findings[0]) == original_id  # same object
        assert findings[0].baselines  # mutated


# ===========================================================================
# compute_alignment
# ===========================================================================


class TestComputeAlignment:
    def test_returns_dict_keyed_by_framework(self):
        spec = _spec("SCuBA", controls=[_ctrl("C1", finding_ids=["CA-MFA-001"])])
        registry = _make_registry(spec)
        findings = [_make_finding("CA-MFA-001")]
        result = compute_alignment(findings, registry)
        assert "SCuBA" in result

    def test_active_finding_reduces_alignment(self):
        spec = _spec(
            "SCuBA",
            controls=[
                _ctrl("C1", finding_ids=["CA-MFA-001"]),
                _ctrl("C2", finding_ids=["CA-LEGACY-001"]),
            ],
        )
        registry = _make_registry(spec)
        findings = [_make_finding("CA-MFA-001")]
        result = compute_alignment(findings, registry)
        assert result["SCuBA"].failing == 1
        assert result["SCuBA"].pct == 50.0

    def test_no_findings_gives_100_pct(self):
        spec = _spec("SCuBA", controls=[_ctrl("C1", finding_ids=["CA-MFA-001"])])
        registry = _make_registry(spec)
        result = compute_alignment([], registry)
        assert result["SCuBA"].pct == 100.0

    def test_bundled_registry_works_end_to_end(self):
        """Smoke test: bundled YAML + real findings → valid AlignmentResult."""
        registry = load_registry()
        findings = [
            _make_finding("CA-MFA-001"),
            _make_finding("CA-LEGACY-001"),
        ]
        result = compute_alignment(findings, registry)
        for _fw, ar in result.items():
            assert 0.0 <= ar.pct <= 100.0
            assert ar.total_controls > 0
