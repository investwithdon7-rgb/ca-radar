"""Unit tests for SARIF export module."""

import json

from ca_radar.analysers.base import Finding, Remediation, Severity
from ca_radar.analysers.runner import AnalysisResult
from ca_radar.exports.sarif_export import export_sarif


def test_export_sarif_valid_schema_and_content() -> None:
    finding = Finding(
        id="CA-MFA-001",
        title="Users not covered by MFA",
        severity=Severity.critical,
        summary="Summary test",
        why_it_matters="Why matters test",
        evidence={},
        affected_principals=[],
        remediation=Remediation(description="Remediation test"),
    )
    analysis = AnalysisResult(findings=[finding])

    sarif_str = export_sarif(analysis, tenant_id="contoso.com", tool_version="0.2.1")
    data = json.loads(sarif_str)

    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "ca-radar"
    assert run["tool"]["driver"]["version"] == "0.2.1"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "CA-MFA-001"

    results = run["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "CA-MFA-001"
    assert results[0]["level"] == "error"
