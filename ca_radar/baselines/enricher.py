"""Baseline enrichment — attaches BaselineRef objects to Findings.

This module bridges the baseline registry and the analysis pipeline.
Call :func:`enrich_findings` immediately after ``run_analysers()`` returns
to populate ``finding.baselines`` on every Finding before export or rendering.

Example::

    from ca_radar.baselines.enricher import enrich_findings
    from ca_radar.baselines.loader import load_registry

    registry = load_registry()
    enrich_findings(analysis.findings, registry)
    # findings now have .baselines populated
"""

from __future__ import annotations

from ca_radar.analysers.base import Finding
from ca_radar.baselines.loader import AlignmentResult, BaselineRegistry


def enrich_findings(
    findings: list[Finding],
    registry: BaselineRegistry,
    *,
    overwrite: bool = False,
) -> None:
    """Populate ``finding.baselines`` from *registry* for each finding in-place.

    Findings that already have baselines (populated by the analyser itself)
    are left untouched unless *overwrite* is ``True``.

    Args:
        findings:  List of :class:`~ca_radar.analysers.base.Finding` objects
                   to enrich (mutated in-place).
        registry:  Loaded :class:`~ca_radar.baselines.loader.BaselineRegistry`.
        overwrite: If ``True``, replace existing baselines.  Default ``False``.
    """
    for finding in findings:
        if finding.baselines and not overwrite:
            continue
        refs = registry.refs_for(finding.id)
        if refs:
            finding.baselines = refs


def compute_alignment(
    findings: list[Finding],
    registry: BaselineRegistry,
) -> dict[str, AlignmentResult]:
    """Compute per-framework alignment from a list of findings.

    Args:
        findings: Active findings (post-analysis, post-enrichment).
        registry: Loaded :class:`~ca_radar.baselines.loader.BaselineRegistry`.

    Returns:
        Dict mapping framework name → :class:`AlignmentResult`.
    """
    active_ids = {f.id for f in findings}
    return registry.alignment(active_ids)
