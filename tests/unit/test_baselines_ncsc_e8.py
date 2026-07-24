"""Unit tests for NCSC and Essential Eight baseline mappings."""

from ca_radar.baselines.loader import load_registry


def test_load_all_four_baselines() -> None:
    registry = load_registry()
    framework_names = [f.framework for f in registry.frameworks]

    assert "SCuBA" in framework_names
    assert "CIS" in framework_names
    assert "NCSC" in framework_names
    assert "Essential Eight" in framework_names
    assert len(registry.frameworks) == 4


def test_ncsc_baseline_refs() -> None:
    registry = load_registry()
    refs = registry.refs_for("CA-MFA-001")
    ncsc_refs = [r for r in refs if r.framework == "NCSC"]

    assert len(ncsc_refs) > 0
    assert ncsc_refs[0].control_id == "NCSC.CA.2"


def test_essential_eight_baseline_refs() -> None:
    registry = load_registry()
    refs = registry.refs_for("CA-LEGACY-001")
    e8_refs = [r for r in refs if r.framework == "Essential Eight"]

    assert len(e8_refs) > 0
    assert e8_refs[0].control_id == "E8.MFA.3"


def test_alignment_computation_across_all_baselines() -> None:
    registry = load_registry()
    # If no findings are active, alignment should be 100% across all 4 frameworks
    alignment = registry.alignment(active_finding_ids=set())

    assert alignment["SCuBA"].pct == 100.0
    assert alignment["CIS"].pct == 100.0
    assert alignment["NCSC"].pct == 100.0
    assert alignment["Essential Eight"].pct == 100.0

    # If CA-MFA-001 is active, alignment should calculate passing and failing controls
    active_findings = {"CA-MFA-001"}
    alignment_with_finding = registry.alignment(active_finding_ids=active_findings)

    assert alignment_with_finding["NCSC"].failing >= 1
    assert alignment_with_finding["Essential Eight"].failing >= 1
    assert alignment_with_finding["NCSC"].pct < 100.0
    assert alignment_with_finding["Essential Eight"].pct < 100.0
