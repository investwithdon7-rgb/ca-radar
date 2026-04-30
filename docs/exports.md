# Exports

Every scan produces four output files in the snapshot directory.

---

## findings.json

Versioned, machine-readable findings document.

```json
{
  "schema_version": "1",
  "tool_version": "0.1.0",
  "tenant_id": "contoso.onmicrosoft.com",
  "captured_at": "2025-06-01T12:00:00+00:00",
  "redacted": true,
  "summary": {
    "posture_score": 72,
    "total_findings": 4,
    "by_severity": { "critical": 0, "high": 3, "medium": 1, "low": 0, "info": 0 },
    "elapsed_seconds": 1.23,
    "analyser_errors": 0
  },
  "findings": [
    {
      "id": "CA-MFA-001",
      "title": "No MFA policy covering all users",
      "severity": "high",
      "confidence": 1.0,
      "summary": "...",
      "why_it_matters": "...",
      "evidence": { "policy_count": 0 },
      "affected_principals": ["sha256:abc...", "sha256:def..."],
      "baselines": [
        { "framework": "SCuBA", "control_id": "MS.AAD.2.1v1", "title": "..." },
        { "framework": "CIS",   "control_id": "1.2.1",        "title": "..." }
      ],
      "remediation": {
        "description": "...",
        "snippets": [["PowerShell", "..."]],
        "references": ["https://aka.ms/..."]
      }
    }
  ],
  "analyser_errors": {}
}
```

`schema_version` is bumped on breaking changes. Consumers should check this field.

---

## findings.csv

Flat CSV suitable for Excel, Power BI, or SIEM ingestion.

```
finding_id,severity,confidence,title,affected_count,baselines,summary,tenant_id,captured_at
CA-MFA-001,high,1.00,No MFA policy covering all users,12,SCuBA:MS.AAD.2.1v1|CIS:1.2.1,...,contoso.onmicrosoft.com,2025-06-01T12:00:00+00:00
```

- UTF-8 with BOM (Excel auto-detects encoding)
- `baselines` column is pipe-delimited `FRAMEWORK:control_id` pairs
- `affected_count` is 0 when a finding is not user-specific

---

## remediation.bicep

Auto-generated [Microsoft Graph Bicep](https://learn.microsoft.com/en-us/graph/templates/overview)
file. Only produced when at least one finding has a Bicep template.

```bicep
extension microsoftGraph

// CA-MFA-001: Require MFA for all users
resource requireMfaAllUsers 'Microsoft.Graph/conditionalAccessPolicies@v1.0' = {
  displayName: 'CA-RADAR: Require MFA for all users'
  state: 'enabledForReportingButNotEnforced'
  conditions: {
    users: {
      includeUsers: ['All']
      excludeUsers: []  // <-- insert break-glass UPNs / object IDs
    }
    ...
  }
}
```

All policies are created in `enabledForReportingButNotEnforced` (report-only) mode.

Deploy with:

```bash
az deployment tenant create \
  --template-file remediation.bicep
```

!!! tip
    Review sign-in logs for 1–2 weeks in report-only mode before switching
    policies to `enabled`.

---

## report.html

See [HTML Report](html-report.md).
