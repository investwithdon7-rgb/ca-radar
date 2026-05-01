# Changelog

All notable changes to ca-radar are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.1.2] — 2026-05-01

### Fixed

- Removed unused `msgraph-sdk` runtime dependency to avoid Windows long-path
  installation failures during `pip install ca-radar`.

## [0.1.1] — 2026-04-30

### Fixed

- Made CLI help and setup output safe on Windows terminals using legacy code pages.
- Replaced decorative Unicode in CLI output with ASCII-safe text so `ca-radar --help`
  does not crash when stdout is encoded as `cp1252`.

## [0.1.0] — 2025-06-01

Initial public release.

### Added

**Core pipeline**
- `ca-radar scan` — collect Graph snapshot, analyse, export, render HTML report
- `ca-radar scan-all` — MSP portfolio mode; scan multiple tenants from a YAML file
- `ca-radar --version` — print version and exit

**Graph collection** (15 resource types)
- Conditional Access policies, named locations, authentication strength policies
- Authentication methods policy, users, groups, directory roles, role assignments
- PIM eligible role assignments, service principals, applications
- Device compliance policies, identity protection summary, risky users, sign-in logs

**Analysers** (16 finding IDs across 7 packs)
- `CA-MFA-001/002` — MFA coverage and phishing-resistant MFA for admins
- `CA-LEGACY-001/002` — Legacy authentication blocking
- `CA-ADMIN-001/002` — Privileged role CA policies and PIM-eligible admin coverage
- `CA-BG-001/002/003` — Break-glass account detection and quality checks
- `CA-EXCL-001/002` — Ghost exclusions and oversized MFA exclusion groups
- `CA-RISK-001/002` / `CA-SESS-001` — Risk-based and session frequency policies
- `CA-SP-001/002` — Workload identity CA coverage

**Exports**
- `findings.json` — versioned schema (v1), posture score, by-severity summary
- `findings.csv` — UTF-8 BOM, pipe-delimited baselines, Excel/Power BI ready
- `remediation.bicep` — Microsoft Graph Bicep extension, report-only mode
- `report.html` — self-contained, D3 policy graph, severity filter, baseline alignment

**Baseline alignment**
- CISA SCuBA MS.AAD v1.0 — 8 controls
- CIS Microsoft 365 Foundations Benchmark v3.1.0 — 7 controls
- Extensible via YAML drop-in (`ca_radar/baselines/data/`)

**Trend & portfolio**
- SQLite `trend.db` — posture score history per tenant
- `portfolio.html` — ranked table, sparklines, average score, critical/high totals

**Infrastructure**
- Multi-stage distroless container (`gcr.io/distroless/python3-debian12:nonroot`)
- GitHub Actions CI — lint, test (3.11 + 3.12), Docker smoke test
- GitHub Actions release — PyPI OIDC publishing, GHCR image push, GitHub release

**Documentation** (mkdocs-material)
- Getting started, first scan walkthrough, architecture, findings reference
- Baseline alignment YAML schema, MSP portfolio mode, CLI reference, exports

### Notes

- All CA policies created by `remediation.bicep` are in `enabledForReportingButNotEnforced` mode
- UPNs are SHA-256 hashed by default (`--no-redact` to disable)
- Sign-in risk features require Entra ID P2; workload identity CA requires Entra Workload ID Premium
- `scan-all` scans tenants sequentially to avoid Graph rate limiting

[0.1.2]: https://github.com/investwithdon7-rgb/ca-radar/releases/tag/v0.1.2
[0.1.1]: https://github.com/investwithdon7-rgb/ca-radar/releases/tag/v0.1.1
[0.1.0]: https://github.com/investwithdon7-rgb/ca-radar/releases/tag/v0.1.0
