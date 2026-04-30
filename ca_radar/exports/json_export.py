"""Versioned JSON findings export.

Produces a stable, machine-readable findings document with a schema version
field so consumers can detect breaking changes across tool versions.

Schema version history
----------------------
"1"  Initial release — findings array + summary block.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from ca_radar.analysers.base import Severity
from ca_radar.analysers.runner import AnalysisResult

FINDINGS_SCHEMA_VERSION = "1"


def export_json(
    analysis: AnalysisResult,
    tenant_id: str,
    captured_at: datetime | str,
    *,
    redacted: bool = True,
    tool_version: str = "",
    indent: int = 2,
) -> str:
    """Serialise an AnalysisResult to a versioned JSON string.

    Args:
        analysis:     Completed AnalysisResult from run_analysers().
        tenant_id:    Tenant identifier.
        captured_at:  Snapshot timestamp.
        redacted:     Whether UPNs were hashed in the snapshot.
        tool_version: ca-radar version string.
        indent:       JSON indentation (default 2; pass 0 for compact).

    Returns:
        UTF-8 JSON string.
    """
    captured_str = (
        captured_at.isoformat() if isinstance(captured_at, datetime) else str(captured_at)
    )

    by_sev: dict[str, int] = {s.value: len(analysis.by_severity[s]) for s in Severity}

    doc: dict[str, Any] = {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "tool_version": tool_version,
        "tenant_id": tenant_id,
        "captured_at": captured_str,
        "redacted": redacted,
        "summary": {
            "posture_score": analysis.posture_score,
            "total_findings": len(analysis.findings),
            "by_severity": by_sev,
            "elapsed_seconds": round(analysis.elapsed_seconds, 2),
            "analyser_errors": len(analysis.analyser_errors),
        },
        "findings": [f.to_dict() for f in analysis.findings],
        "analyser_errors": analysis.analyser_errors,
    }

    return json.dumps(doc, indent=indent or None, ensure_ascii=False)
