"""HTML report renderer.

Renders a self-contained HTML file from an AnalysisResult + PolicyGraph.
The output file embeds all CSS and finding data inline; only D3 (the graph
visualisation) is loaded from a CDN.  The graph gracefully degrades to a
static message when the CDN is unreachable.

Usage:
    html = render_html_report(analysis, graph.to_json_dict(), tenant_id, captured_at)
    Path("report.html").write_text(html, encoding="utf-8")
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ca_radar.analysers.base import Severity
from ca_radar.analysers.runner import AnalysisResult

log = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html_report(
    analysis: AnalysisResult,
    graph_data: dict[str, Any],
    tenant_id: str,
    captured_at: datetime | str,
    *,
    redacted: bool = True,
    tool_version: str = "",
) -> str:
    """Render the full HTML report and return it as a UTF-8 string.

    Args:
        analysis:     Completed AnalysisResult from run_analysers().
        graph_data:   PolicyGraph.to_json_dict() output {nodes, links}.
        tenant_id:    Tenant identifier (may be redacted domain).
        captured_at:  Snapshot timestamp (datetime or ISO string).
        redacted:     Whether UPNs were hashed in this snapshot.
        tool_version: ca-radar version string for the report footer.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    template = env.get_template("report.html.j2")

    sev_counts = {s.value: len(analysis.by_severity[s]) for s in Severity}

    captured_str = (
        captured_at.isoformat() if isinstance(captured_at, datetime) else str(captured_at)
    )

    # Baseline alignment — non-fatal if baseline data unavailable
    alignment: dict[str, Any] = {}
    try:
        from ca_radar.baselines.enricher import compute_alignment
        from ca_radar.baselines.loader import load_registry

        alignment = compute_alignment(analysis.findings, load_registry())
    except Exception as exc:  # pragma: no cover
        log.warning("Baseline alignment unavailable (non-fatal): %s", exc)

    return template.render(
        tenant_id=tenant_id,
        captured_at=captured_str,
        redacted=redacted,
        tool_version=tool_version,
        posture_score=analysis.posture_score,
        elapsed_seconds=round(analysis.elapsed_seconds, 1),
        sev_counts=sev_counts,
        findings=analysis.findings,
        findings_json=json.dumps([f.to_dict() for f in analysis.findings]),
        graph_json=json.dumps(graph_data),
        analyser_errors=analysis.analyser_errors,
        alignment=alignment,
        Severity=Severity,
    )
