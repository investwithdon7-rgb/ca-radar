"""Analyser runner — executes all registered analysers and returns sorted findings.

Execution is parallel (asyncio.gather on a thread pool for CPU-bound analysers)
with stable deterministic ordering in the output regardless of completion order.

Usage:
    results = await run_analysers(data, resolver)
    for finding in results.findings:
        print(finding.id, finding.severity)
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ca_radar.analysers.base import Analyser, Finding, Severity
from ca_radar.resolver.effective_controls import PolicyResolver
from ca_radar.resolver.policy_graph import SnapshotData

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Registry: all built-in analysers
# ---------------------------------------------------------------------------


def _default_analysers() -> list[Analyser]:
    """Return one instance of every built-in analyser."""
    from ca_radar.analysers.packs.admin_roles.admin_roles import AdminRolesAnalyser
    from ca_radar.analysers.packs.break_glass.break_glass import BreakGlassAnalyser
    from ca_radar.analysers.packs.coverage.mfa_coverage import MfaCoverageAnalyser
    from ca_radar.analysers.packs.device_compliance.device_compliance import (
        DeviceComplianceAnalyser,
    )
    from ca_radar.analysers.packs.exclusions.exclusions import ExclusionAnalyser
    from ca_radar.analysers.packs.legacy_auth.legacy_protocols import LegacyAuthAnalyser
    from ca_radar.analysers.packs.risk_session.risk_session import RiskSessionAnalyser
    from ca_radar.analysers.packs.service_principals.service_principals import (
        ServicePrincipalAnalyser,
    )
    from ca_radar.analysers.packs.staging.staging import StagingHygieneAnalyser

    return [
        MfaCoverageAnalyser(),
        LegacyAuthAnalyser(),
        BreakGlassAnalyser(),
        ExclusionAnalyser(),
        AdminRolesAnalyser(),
        ServicePrincipalAnalyser(),
        RiskSessionAnalyser(),
        DeviceComplianceAnalyser(),
        StagingHygieneAnalyser(),
    ]


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    analyser_errors: dict[str, str] = field(default_factory=dict)  # analyser_repr → error msg
    elapsed_seconds: float = 0.0

    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    @property
    def posture_score(self) -> int:
        """0–100 score: 100 = perfect, each finding deducts weight × count."""
        score = 100
        for finding in self.findings:
            score -= finding.severity.weight
        return max(0, min(100, score))

    def summary_line(self) -> str:
        counts = self.by_severity
        parts = []
        for sev in (Severity.critical, Severity.high, Severity.medium, Severity.low):
            n = len(counts[sev])
            if n:
                parts.append(f"{sev.emoji} {n} {sev.value}")
        score = self.posture_score
        return f"Posture score: {score}/100  |  " + ("  ".join(parts) or "No findings")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


async def run_analysers(
    data: SnapshotData,
    resolver: PolicyResolver,
    analysers: list[Analyser] | None = None,
    max_workers: int = 4,
) -> AnalysisResult:
    """Run all analysers concurrently in a thread pool and return sorted findings.

    Analysers are CPU-bound (pure logic, no I/O), so we use a ThreadPoolExecutor
    rather than asyncio coroutines to avoid blocking the event loop.

    Args:
        data:        Snapshot data (pre-loaded, read-only during analysis).
        resolver:    PolicyResolver built from the same snapshot.
        analysers:   Override the default analyser list (useful for tests).
        max_workers: Thread pool size (default 4).
    """
    active = analysers if analysers is not None else _default_analysers()
    result = AnalysisResult()
    start = time.monotonic()

    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=max_workers)

    async def run_one(analyser: Analyser) -> list[Finding]:
        try:
            findings = await loop.run_in_executor(executor, analyser.analyse, data, resolver)
            log.debug("%s: %d finding(s)", repr(analyser), len(findings))
            return findings
        except Exception as exc:
            log.error("Analyser %s raised: %s", repr(analyser), exc, exc_info=True)
            result.analyser_errors[repr(analyser)] = str(exc)
            return []

    all_findings_nested = await asyncio.gather(*[run_one(a) for a in active])

    # Flatten, deduplicate by finding ID (first occurrence wins), sort stably
    seen: set[str] = set()
    flat: list[Finding] = []
    for findings in all_findings_nested:
        for f in findings:
            if f.id not in seen:
                seen.add(f.id)
                flat.append(f)

    # Stable sort: severity (critical first), then finding ID
    _sev_order = {s: i for i, s in enumerate(Severity)}
    flat.sort(key=lambda f: (_sev_order[f.severity], f.id))

    result.findings = flat
    result.elapsed_seconds = time.monotonic() - start
    executor.shutdown(wait=False)

    # ── Baseline enrichment ────────────────────────────────────────────────
    # Attach BaselineRef objects to every finding so JSON/CSV/HTML all have
    # framework mappings without each analyser needing to hard-code them.
    try:
        from ca_radar.baselines.enricher import enrich_findings
        from ca_radar.baselines.loader import load_registry

        enrich_findings(result.findings, load_registry())
    except Exception as exc:  # pragma: no cover
        log.warning("Baseline enrichment failed (non-fatal): %s", exc)

    return result
