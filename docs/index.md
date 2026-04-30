# ca-radar

**Conditional Access Gap Analyser & Visualiser for Microsoft 365 / Entra ID**

ca-radar is a free, read-only CLI tool that scans your Entra ID tenant, detects Conditional Access policy gaps, maps findings to CISA SCuBA and CIS benchmarks, and produces a self-contained HTML report — all without writing a single byte back to your tenant.

---

## What it does

```
ca-radar scan --tenant contoso.onmicrosoft.com
```

In under two minutes, ca-radar:

1. **Collects** a point-in-time snapshot of your CA policies, users, groups, roles, and sign-in risk configuration
2. **Analyses** the snapshot against 15+ detection rules across MFA coverage, legacy auth, break-glass, admin roles, exclusions, service principal coverage, and risk-based policies
3. **Maps** every finding to CISA SCuBA and CIS benchmark controls and computes an alignment percentage
4. **Exports** findings as `report.html`, `findings.json`, `findings.csv`, and `remediation.bicep`

---

## Key features

| Feature | Details |
|---|---|
| **Read-only** | Uses Microsoft Graph read scopes only — nothing is created or modified |
| **Privacy-first** | UPNs are SHA-256 hashed by default; use `--no-redact` to show real names |
| **Offline-capable** | Snapshots stored to disk; re-analyse without hitting Graph again |
| **Baseline alignment** | CISA SCuBA MS.AAD and CIS M365 Foundations controls, extensible via YAML |
| **Bicep remediation** | Auto-generated `remediation.bicep` in report-only mode for easy deployment |
| **MSP portfolio mode** | `scan-all` scans multiple tenants, produces a ranked portfolio report |
| **Trend tracking** | SQLite-backed posture score history with sparklines in portfolio view |

---

## Quickstart

```bash
# Install
pip install ca-radar

# Scan interactively (device code flow)
ca-radar scan --tenant contoso.onmicrosoft.com

# Open the report
open snapshot/contoso.onmicrosoft.com/*/report.html
```

See [Getting Started](getting-started.md) for full installation options including app registration auth.

---

## Findings covered

| ID | Severity | Description |
|---|---|---|
| CA-MFA-001 | 🟠 High | No MFA policy covering all users |
| CA-MFA-002 | 🟠 High | No phishing-resistant MFA for admin roles |
| CA-LEGACY-001 | 🟠 High | Legacy authentication not blocked |
| CA-LEGACY-002 | 🟠 High | Legacy auth not blocked (EAS path) |
| CA-ADMIN-001 | 🟠 High | No role-targeted CA policy for privileged roles |
| CA-ADMIN-002 | 🟠 High | PIM-eligible admins not covered by MFA |
| CA-EXCL-001 | 🟡 Medium | Ghost exclusions in CA policies |
| CA-EXCL-002 | 🟠 High | Oversized MFA exclusion groups |
| CA-RISK-001 | 🟠 High | No sign-in risk-based policy |
| CA-RISK-002 | 🟠 High | No user risk-based policy |
| CA-SESS-001 | 🟡 Medium | No sign-in frequency policy for admins |
| CA-SP-001 | 🟠 High | No workload identity CA policy |
| CA-SP-002 | 🟡 Medium | No app-specific CA policies |
| CA-BG-001 | 🟠 High | No break-glass account detected |
| CA-BG-002 | 🟡 Medium | Break-glass lacks phishing-resistant MFA |
| CA-BG-003 | 🔵 Low | Break-glass account subject to CA policies |

See the [Findings Reference](findings-reference.md) for full details, evidence fields, and remediation guidance.

---

## License

MIT — see [LICENSE](https://github.com/tekdruid/ca-radar/blob/main/LICENSE).
