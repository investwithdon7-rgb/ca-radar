"""CSV findings export.

Produces a flat, Excel/Power BI-friendly CSV where each row is one finding.
Multi-value fields (baselines, affected principals) are pipe-delimited so the
file remains single-row-per-finding without quoting issues.

Columns
-------
finding_id       Stable ID, e.g. CA-MFA-001
severity         critical | high | medium | low | info
confidence       0.0–1.0 numeric
title            Short title string
affected_count   Number of affected principals (0 if not applicable)
baselines        Pipe-delimited "FRAMEWORK:control_id" pairs
summary          Single-sentence summary (quotes stripped to keep CSV clean)
tenant_id        Tenant identifier passed at export time
captured_at      ISO-8601 snapshot timestamp
owner            Pipe-delimited owner names resolved from optional owner mapping
owner_source     principal | finding | default | unknown
exception_status none | accepted_risk | expired | custom status
exception_expires ISO date for the matched exception, when present
priority_score   0-100 remediation priority score
priority_band    urgent | high | medium | low
"""

from __future__ import annotations

import csv
import io
from datetime import datetime

from ca_radar.analysers.runner import AnalysisResult

_FIELDS = [
    "finding_id",
    "severity",
    "confidence",
    "title",
    "affected_count",
    "baselines",
    "summary",
    "tenant_id",
    "captured_at",
    "owner",
    "owner_source",
    "exception_status",
    "exception_expires",
    "priority_score",
    "priority_band",
]


def export_csv(
    analysis: AnalysisResult,
    tenant_id: str,
    captured_at: datetime | str,
) -> str:
    """Serialise an AnalysisResult to a UTF-8 CSV string.

    Args:
        analysis:    Completed AnalysisResult from run_analysers().
        tenant_id:   Tenant identifier.
        captured_at: Snapshot timestamp.

    Returns:
        UTF-8 CSV string (with BOM so Excel auto-detects encoding).
    """
    captured_str = (
        captured_at.isoformat() if isinstance(captured_at, datetime) else str(captured_at)
    )

    buf = io.StringIO()
    # UTF-8 BOM so Excel opens without a wizard
    buf.write("﻿")

    writer = csv.DictWriter(
        buf,
        fieldnames=_FIELDS,
        quoting=csv.QUOTE_MINIMAL,
        lineterminator="\r\n",
    )
    writer.writeheader()

    for f in analysis.findings:
        baselines = (
            "|".join(f"{b.framework}:{b.control_id}" for b in f.baselines) if f.baselines else ""
        )
        owner = f.owner or {}
        exception = f.exception or {}
        priority = f.priority or {}

        writer.writerow(
            {
                "finding_id": f.id,
                "severity": f.severity.value,
                "confidence": f"{f.confidence:.2f}",
                "title": f.title,
                "affected_count": len(f.affected_principals),
                "baselines": baselines,
                "summary": f.summary.replace("\n", " "),
                "tenant_id": tenant_id,
                "captured_at": captured_str,
                "owner": _pipe_list(owner.get("names", [])),
                "owner_source": str(owner.get("source", "")),
                "exception_status": str(exception.get("status", "")),
                "exception_expires": str(exception.get("expires", "")),
                "priority_score": str(priority.get("score", "")),
                "priority_band": str(priority.get("band", "")),
            }
        )

    return buf.getvalue()


def _pipe_list(value: object) -> str:
    if isinstance(value, list):
        return "|".join(str(item) for item in value)
    return str(value or "")
