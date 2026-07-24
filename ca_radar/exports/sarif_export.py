"""SARIF (Static Analysis Results Interchange Format) export.

Produces a valid SARIF v2.1.0 JSON output compatible with GitHub Code Scanning,
GitLab CI, Azure DevOps, and other DevSecOps toolchains.
"""

from __future__ import annotations

import json
from typing import Any

from ca_radar.analysers.base import Severity
from ca_radar.analysers.runner import AnalysisResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _severity_to_sarif_level(sev: Severity) -> str:
    match sev:
        case Severity.critical | Severity.high:
            return "error"
        case Severity.medium:
            return "warning"
        case Severity.low:
            return "note"


def export_sarif(
    analysis: AnalysisResult,
    *,
    tool_version: str = "0.2.1",
    tenant_id: str = "",
    indent: int = 2,
) -> str:
    """Serialise an AnalysisResult to a SARIF v2.1.0 JSON string.

    Args:
        analysis:     Completed AnalysisResult from run_analysers().
        tool_version: ca-radar version string.
        tenant_id:    Tenant identifier.
        indent:       JSON indentation (default 2).

    Returns:
        UTF-8 SARIF JSON string.
    """
    rules_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in analysis.findings:
        if f.id not in rules_map:
            rules_map[f.id] = {
                "id": f.id,
                "name": f.id.replace("-", "_"),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.summary},
                "help": {"text": f"{f.why_it_matters}\n\nRemediation: {f.remediation.description}"},
                "properties": {
                    "tags": ["security", "entra-id", "conditional-access"],
                    "precision": "high",
                },
            }

        sarif_level = _severity_to_sarif_level(f.severity)

        result_obj: dict[str, Any] = {
            "ruleId": f.id,
            "level": sarif_level,
            "message": {"text": f"{f.title}: {f.summary}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"EntraID/{tenant_id or 'Tenant'}/ConditionalAccess"
                        }
                    }
                }
            ],
        }
        results.append(result_obj)

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ca-radar",
                        "version": tool_version,
                        "informationUri": "https://github.com/investwithdon7-rgb/ca-radar",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent, ensure_ascii=False)
