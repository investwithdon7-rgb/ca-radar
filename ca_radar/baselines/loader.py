"""Baseline framework loader.

Reads YAML files from ``ca_radar/baselines/data/`` and exposes a
:class:`BaselineRegistry` that maps finding IDs to
:class:`~ca_radar.analysers.base.BaselineRef` objects and computes
per-framework alignment percentages.

Usage::

    from ca_radar.baselines.loader import load_registry

    registry = load_registry()              # loads all bundled YAML files
    refs = registry.refs_for("CA-MFA-001")  # → list[BaselineRef]
    align = registry.alignment({"CA-MFA-001", "CA-LEGACY-001"})
    print(align["SCuBA"].pct)               # e.g. 75.0
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ca_radar.analysers.base import BaselineRef

log = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"


# ---------------------------------------------------------------------------
# Internal data model for YAML deserialization
# ---------------------------------------------------------------------------


@dataclass
class ControlSpec:
    """One row from a YAML controls list."""

    id: str
    title: str
    description: str = ""
    finding_ids: list[str] = field(default_factory=list)


@dataclass
class FrameworkSpec:
    """Top-level YAML document."""

    framework: str
    version: str
    url: str
    controls: list[ControlSpec] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Alignment result
# ---------------------------------------------------------------------------


@dataclass
class AlignmentResult:
    """Alignment metrics for a single framework."""

    framework: str
    version: str
    url: str
    total_controls: int
    passing: int  # controls whose findings are all absent from active set
    failing: int  # controls with ≥1 active finding
    pct: float  # (passing / total) * 100, rounded to one decimal

    @property
    def failing_controls(self) -> int:
        """Alias kept for templates."""
        return self.failing


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class BaselineRegistry:
    """Holds all loaded framework specs and answers lookup queries.

    Attributes:
        frameworks: Ordered list of :class:`FrameworkSpec` objects (one per YAML).
    """

    def __init__(self, specs: list[FrameworkSpec]) -> None:
        self.frameworks = specs
        # Reverse index: finding_id → list of (FrameworkSpec, ControlSpec)
        self._idx: dict[str, list[tuple[FrameworkSpec, ControlSpec]]] = {}
        for spec in specs:
            for ctrl in spec.controls:
                for fid in ctrl.finding_ids:
                    self._idx.setdefault(fid, []).append((spec, ctrl))

    # ── Public API ────────────────────────────────────────────────────────

    def refs_for(self, finding_id: str) -> list[BaselineRef]:
        """Return all :class:`BaselineRef` objects for *finding_id*.

        Returns an empty list if the finding ID has no baseline mapping.
        """
        pairs = self._idx.get(finding_id, [])
        return [
            BaselineRef(
                framework=spec.framework,
                control_id=ctrl.id,
                title=ctrl.title,
            )
            for spec, ctrl in pairs
        ]

    def alignment(self, active_finding_ids: set[str]) -> dict[str, AlignmentResult]:
        """Compute per-framework alignment given the set of active finding IDs.

        A control is "passing" when *none* of its ``finding_ids`` appear in
        *active_finding_ids*.  A control with an empty ``finding_ids`` list
        is always passing.

        Args:
            active_finding_ids: Set of finding IDs raised in this scan.

        Returns:
            Dict mapping framework name → :class:`AlignmentResult`.
        """
        results: dict[str, AlignmentResult] = {}
        for spec in self.frameworks:
            total = len(spec.controls)
            failing = sum(
                1
                for ctrl in spec.controls
                if any(fid in active_finding_ids for fid in ctrl.finding_ids)
            )
            passing = total - failing
            pct = round((passing / total * 100), 1) if total else 100.0
            results[spec.framework] = AlignmentResult(
                framework=spec.framework,
                version=spec.version,
                url=spec.url,
                total_controls=total,
                passing=passing,
                failing=failing,
                pct=pct,
            )
        return results

    def all_frameworks(self) -> list[str]:
        """Return framework names in load order."""
        return [s.framework for s in self.frameworks]


# ---------------------------------------------------------------------------
# YAML parsing helpers
# ---------------------------------------------------------------------------


def _parse_yaml(path: Path) -> FrameworkSpec:
    """Parse a single YAML baseline file into a :class:`FrameworkSpec`."""
    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    controls = [
        ControlSpec(
            id=str(c["id"]),
            title=c.get("title", ""),
            description=c.get("description", ""),
            finding_ids=list(c.get("finding_ids") or []),
        )
        for c in (raw.get("controls") or [])
    ]

    return FrameworkSpec(
        framework=raw["framework"],
        version=str(raw.get("version", "")),
        url=str(raw.get("url", "")),
        controls=controls,
    )


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------


def load_registry(data_dir: Path | None = None) -> BaselineRegistry:
    """Load all YAML files from *data_dir* (default: bundled ``data/``).

    Files are loaded in alphabetical order so results are deterministic.

    Args:
        data_dir: Override the default data directory (useful for tests).

    Returns:
        A populated :class:`BaselineRegistry`.
    """
    directory = data_dir or _DATA_DIR
    yaml_files = sorted(directory.glob("*.yaml"))

    specs: list[FrameworkSpec] = []
    for path in yaml_files:
        try:
            spec = _parse_yaml(path)
            specs.append(spec)
            log.debug("Loaded baseline: %s (%d controls)", spec.framework, len(spec.controls))
        except Exception as exc:  # pragma: no cover
            log.warning("Failed to load baseline %s: %s", path, exc)

    return BaselineRegistry(specs)
