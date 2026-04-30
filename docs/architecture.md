# Architecture

ca-radar is a single-process Python CLI tool with a clean pipeline architecture.
No server, no database (except an optional SQLite trend file), no data written back to the tenant.

## Pipeline

```
Microsoft Graph API
       │
       ▼
┌─────────────────┐
│  GraphClient    │  Authenticated, concurrent, paginated HTTP client
│  (graph/)       │  asyncio + httpx, semaphore-controlled concurrency
└────────┬────────┘
         │  raw JSON lists
         ▼
┌─────────────────┐
│  Snapshot       │  Point-in-time snapshot written to disk
│  Collector      │  UPNs optionally SHA-256 hashed (Redactor)
│  (snapshot/)    │  manifest.json + one file per resource type
└────────┬────────┘
         │  SnapshotStore (disk read)
         ▼
┌─────────────────┐
│  SnapshotData   │  In-memory indexed view of the snapshot
│  PolicyGraph    │  Pre-built: users_by_id, user_group_index,
│  (resolver/)    │  user_role_index, user_pim_role_index
└────────┬────────┘
         │  data + resolver
         ▼
┌─────────────────┐
│  Analysers      │  7 analyser packs run concurrently in a thread pool
│  (analysers/)   │  Each emits zero or more Finding objects
│                 │  BaselineEnricher attaches SCuBA/CIS refs
└────────┬────────┘
         │  AnalysisResult
         ▼
┌─────────────────┐
│  Exports        │  findings.json (versioned schema)
│  (exports/)     │  findings.csv  (UTF-8 BOM, Excel-friendly)
│                 │  remediation.bicep (Graph Bicep extension)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Renderer       │  Jinja2 → self-contained report.html
│  (render/)      │  D3 v7 force graph (CDN, graceful fallback)
│                 │  Baseline alignment bars, severity filter cards
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  TrendStore     │  SQLite posture score history
│  (trend/)       │  Portfolio sparklines, multi-tenant ranking
└─────────────────┘
```

## Key design decisions

### Read-only by design

ca-radar requests only read scopes from Microsoft Graph. The Graph client
never calls a `POST`, `PATCH`, or `DELETE` endpoint.

### Snapshot-first architecture

All analysis runs against the snapshot — not live Graph data. This means:

- Scans are reproducible (re-run analysis on the same snapshot)
- No repeated Graph calls during analysis (cheaper, faster)
- Snapshots can be archived and diffed across time

### Analyser plug-in system

Each detection is an `Analyser` subclass with a stable `finding_ids` list.
Adding a new detection never touches the renderer or the CLI — just add a
new file under `ca_radar/analysers/packs/` and register it in `runner.py`.

### Thread pool for analysers

Analysers are CPU-bound pure logic (no I/O). They run concurrently in a
`ThreadPoolExecutor` launched from the asyncio event loop, avoiding blocking.

### Baseline YAML extensibility

SCuBA and CIS mappings live in `ca_radar/baselines/data/*.yaml`. Custom
frameworks can be added without touching Python code — drop a YAML file in
the same directory and it's picked up automatically.

## Module layout

```
ca_radar/
├── __init__.py           __version__
├── cli.py                typer CLI entry point
├── auth/                 AppAuthProvider, DelegatedAuthProvider (MSAL)
├── graph/                GraphClient, paginated endpoint functions
├── snapshot/             SnapshotStore, collector, Pydantic models, Redactor
├── resolver/             SnapshotData, PolicyGraph, PolicyResolver
├── analysers/
│   ├── base.py           Finding, Severity, BaselineRef, Analyser ABC
│   ├── runner.py         run_analysers(), AnalysisResult
│   └── packs/
│       ├── coverage/     CA-MFA-001, CA-MFA-002
│       ├── legacy_auth/  CA-LEGACY-001, CA-LEGACY-002
│       ├── break_glass/  CA-BG-001, CA-BG-002, CA-BG-003
│       ├── exclusions/   CA-EXCL-001, CA-EXCL-002
│       ├── admin_roles/  CA-ADMIN-001, CA-ADMIN-002
│       ├── service_principals/ CA-SP-001, CA-SP-002
│       └── risk_session/ CA-RISK-001, CA-RISK-002, CA-SESS-001
├── baselines/            loader.py, enricher.py, data/scuba.yaml, data/cis.yaml
├── exports/              json_export, csv_export, bicep_export
├── render/html/          renderer.py, portfolio_renderer.py, templates/
├── tenants/              TenantConfig, TenantsFile (scan-all YAML)
└── trend/                TrendStore (SQLite posture history)
```

## Posture score

```
score = 100 − Σ(weight × count per finding)

Severity weights:
  critical = 15 pts
  high     =  7 pts
  medium   =  3 pts
  low      =  1 pt
  info     =  0 pts

Score is clamped to [0, 100].
```

A tenant with zero findings scores 100. Each additional high-severity finding
costs 7 points; a single critical finding costs 15.
