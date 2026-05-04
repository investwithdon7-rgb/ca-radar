# ca-radar — Developer Architecture Guide

This document is for developers who want to understand, extend, or contribute to ca-radar.
It covers the internal design, data flow, module responsibilities, and the logic behind every
major subsystem. Read this alongside the source code, not instead of it.

---

## Table of Contents

1. [Project Layout](#1-project-layout)
2. [End-to-End Data Flow](#2-end-to-end-data-flow)
3. [Module Reference](#3-module-reference)
   - [CLI (`ca_radar/cli.py`)](#31-cli)
   - [Config (`ca_radar/config.py`)](#32-config)
   - [Auth (`ca_radar/auth/`)](#33-auth)
   - [Graph Client (`ca_radar/graph/`)](#34-graph-client)
   - [Snapshot (`ca_radar/snapshot/`)](#35-snapshot)
   - [Resolver (`ca_radar/resolver/`)](#36-resolver)
   - [Analysers (`ca_radar/analysers/`)](#37-analysers)
   - [Baselines (`ca_radar/baselines/`)](#38-baselines)
   - [Enrichment (`ca_radar/enrichment.py`)](#39-enrichment)
   - [Exports (`ca_radar/exports/`)](#310-exports)
   - [Render (`ca_radar/render/`)](#311-render)
   - [Trend & Portfolio (`ca_radar/trend/`)](#312-trend--portfolio)
4. [Adding a New Analyser](#4-adding-a-new-analyser)
5. [Adding a New Baseline Framework](#5-adding-a-new-baseline-framework)
6. [Adding a New Export Format](#6-adding-a-new-export-format)
7. [Key Design Decisions](#7-key-design-decisions)
8. [Testing Strategy](#8-testing-strategy)

---

## 1. Project Layout

```
ca_radar/
├── __init__.py                   version, author metadata
├── __main__.py                   python -m ca_radar entry point (distroless Docker)
├── cli.py                        all CLI commands (setup, scan, scan-all)
├── config.py                     RadarConfig — persistent ~/.ca-radar/config.yaml
├── enrichment.py                 post-analysis enrichment: owners, exceptions, priority
│
├── analysers/
│   ├── base.py                   Analyser ABC, Finding, Severity, BaselineRef, Remediation
│   ├── runner.py                 run_analysers(), AnalysisResult
│   └── packs/
│       ├── admin_roles/          CA-ADMIN-001, CA-ADMIN-002
│       ├── break_glass/          CA-BG-001, CA-BG-002
│       ├── coverage/             CA-MFA-001, CA-MFA-002
│       ├── exclusions/           CA-EXCL-001, CA-EXCL-002
│       ├── legacy_auth/          CA-LEGACY-001 through CA-LEGACY-009
│       ├── risk_session/         CA-RISK-001, CA-RISK-002
│       └── service_principals/   CA-SP-001, CA-SP-002, CA-SP-003
│
├── auth/
│   ├── app_auth.py               AppAuthProvider (MSAL ConfidentialClientApplication)
│   └── delegated_auth.py         DelegatedAuthProvider (device-code flow)
│
├── baselines/
│   ├── loader.py                 BaselineRegistry — parse YAML, build reverse index
│   ├── enricher.py               enrich_findings(), compute_alignment()
│   └── data/                     SCuBA.yaml, CIS.yaml, NCSC.yaml, E8.yaml
│
├── exports/
│   ├── json_export.py            export_json()
│   ├── csv_export.py             export_csv()
│   └── bicep_export.py           export_bicep()
│
├── graph/
│   ├── client.py                 GraphClient, AuthProvider protocol
│   ├── endpoints.py              typed get_* wrappers for every Graph resource
│   └── pagination.py             extract_value(), extract_next_link()
│
├── render/html/
│   ├── renderer.py               render_html_report()
│   ├── portfolio_renderer.py     render_portfolio_report()
│   └── templates/                report.html.j2, portfolio.html.j2
│
├── resolver/
│   ├── policy_graph.py           SnapshotData (indexes), PolicyGraph (NetworkX)
│   ├── effective_controls.py     PolicyResolver, EffectiveAccess, EvaluationConditions
│   └── exclusion_walker.py       transitive group membership expansion
│
├── snapshot/
│   ├── models.py                 Pydantic models for all Graph resources
│   ├── collector.py              collect_snapshot() — concurrent Graph collection
│   └── store.py                  SnapshotStore — filesystem read/write
│
├── tenants/
│   └── models.py                 TenantsFile — multi-tenant YAML for portfolio mode
│
├── trend/
│   └── store.py                  TrendStore (SQLite), PortfolioSummaryRow
│
└── utils/
    └── redaction.py              Redactor — SHA-256 hash UPNs for privacy
```

---

## 2. End-to-End Data Flow

This is what happens when a user runs `ca-radar scan`:

```
┌─────────────────────────────────────────────────────────────┐
│  cli.py — scan()                                            │
│                                                             │
│  1. Load RadarConfig (saved config + CLI flag overrides)    │
│  2. Validate: tenant and client_id must be set              │
│  3. Call _run_scan(tenant, out, auth_mode, ...)             │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  AUTH                                                       │
│                                                             │
│  _build_auth(mode, ...)                                     │
│  ├─ "app"       → AppAuthProvider(tenant, client_id,        │
│  │                  cert_path | client_secret)              │
│  └─ "delegated" → DelegatedAuthProvider(tenant, client_id)  │
│                   (triggers device-code browser sign-in)    │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  COLLECTION — snapshot/collector.py                         │
│                                                             │
│  collect_snapshot(client, store, tenant_id, ...)            │
│  ├─ Opens GraphClient (async, throttle-aware, paginating)   │
│  ├─ Runs 15 Graph endpoint calls behind asyncio.Semaphore   │
│  │   get_ca_policies(), get_users(), get_groups(),          │
│  │   get_directory_roles(), get_role_assignments(),         │
│  │   get_pim_eligible_assignments(), get_sign_in_logs(),    │
│  │   get_service_principals(), get_applications(), ...      │
│  ├─ Optional: Redactor.hash_upn() all UPNs → SHA-256        │
│  └─ Writes JSON files to snapshot/<tenantId>/<timestamp>/   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  DATA LOADING — resolver/policy_graph.py                    │
│                                                             │
│  SnapshotData.from_store(snapshot_path, store)              │
│  ├─ Reads all JSON files back into typed Pydantic models    │
│  └─ _build_indexes():                                       │
│      user_role_index  (user_id → active role_definition_ids)│
│      user_group_index (user_id → transitive group_ids)      │
│      user_pim_role_index (user_id → PIM eligible role_ids)  │
│      users_by_id, groups_by_id, roles_by_id, ...            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  ANALYSIS — analysers/runner.py                             │
│                                                             │
│  run_analysers(data, resolver)                              │
│  ├─ PolicyResolver.from_data(data) — query engine           │
│  ├─ ThreadPoolExecutor: runs all 7 analyser packs           │
│  │   Each analyser returns list[Finding]                    │
│  ├─ Deduplicates findings by finding.id                     │
│  ├─ Sorts: severity (critical → info), then id              │
│  ├─ enrich_findings(findings, load_registry())              │
│  │   Attaches BaselineRef (SCuBA / CIS / NCSC / E8)        │
│  └─ Returns AnalysisResult                                  │
│      .posture_score = 100 - Σ(finding.severity.weight)      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  POST-ANALYSIS ENRICHMENT — enrichment.py                   │
│                                                             │
│  Optional: load owners.yaml + exceptions.yaml               │
│  enrich_findings(findings, config)                          │
│  Mutates each Finding in-place:                             │
│  ├─ .owner      — who is responsible for this finding       │
│  ├─ .exception  — accepted risk / waiver status             │
│  └─ .priority   — calculated priority score + band          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  EXPORTS                                                    │
│                                                             │
│  export_json()   → findings.json                           │
│  export_csv()    → findings.csv  (Excel-friendly, BOM)     │
│  export_bicep()  → remediation.bicep (if snippets exist)   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  RENDER — render/html/renderer.py                           │
│                                                             │
│  PolicyGraph.from_data(data)                                │
│  ├─ NetworkX DiGraph: users, groups, roles, policies,       │
│  │   apps, SPs as nodes; membership/assignment as edges     │
│  └─ to_json_dict() → {nodes, links} for D3 visualisation   │
│                                                             │
│  render_html_report(analysis, graph_dict, ...)              │
│  └─ Jinja2: embeds findings JSON + graph JSON + inline CSS  │
│     D3 loaded from CDN with graceful offline fallback       │
│     Baseline alignment table (SCuBA %, CIS %, ...)          │
│     → report.html                                           │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  TREND — trend/store.py                                     │
│                                                             │
│  TrendStore.save_scan(tenant_id, captured_at,               │
│    posture_score, by_severity, ...)                         │
│  └─ Appends one row to SQLite scans table                   │
│     Feeds portfolio sparklines on next scan-all             │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Module Reference

### 3.1 CLI

**File:** `ca_radar/cli.py`

The CLI is built with [Typer](https://typer.tiangolo.com/) and [Rich](https://rich.readthedocs.io/).
All heavy imports are deferred (inside functions) to keep startup fast.

**Commands:**

| Command | Function | What it does |
|---|---|---|
| `ca-radar setup` | `setup()` | 4-step interactive wizard: tenant → app registration guide → client ID + auth mode → options → save config |
| `ca-radar scan` | `scan()` | Single-tenant scan. Reads saved config, overlays any CLI flags, then calls `_run_scan()` |
| `ca-radar scan-all` | `scan_all()` | Portfolio mode. Reads a tenants YAML file, iterates tenants, calls `_run_scan()` for each, renders portfolio report |

**Key internals:**

```python
def _build_auth(mode, tenant, client_id, cert_path, client_secret) -> AuthProvider
```
Returns either `AppAuthProvider` or `DelegatedAuthProvider` based on `mode`.
Raises `typer.Exit(1)` if required fields are missing.

```python
async def _run_scan(tenant, out, auth_mode, client_id, ...) -> dict[str, Any]
```
Core orchestration coroutine. Returns a summary dict with `posture_score`, `total_findings`,
`by_severity`, `report_path`, `captured_at`, `elapsed_seconds`. Called directly for single scans
and via `asyncio.run()` in portfolio mode.

```python
def _run_scan_from_config(cfg: RadarConfig) -> None
```
Convenience wrapper used by the setup wizard's "run now?" prompt.

**stdio resilience:**
`_make_stdio_resilient()` is called at module import time. It reconfigures stdout/stderr
with `errors="replace"` on Windows so that Unicode characters in Rich output don't crash
in environments with restricted codepages (e.g. `chcp 437` terminals).

---

### 3.2 Config

**File:** `ca_radar/config.py`

```python
@dataclass
class RadarConfig:
    tenant: str = ""
    client_id: str = ""
    auth_mode: str = "delegated"   # "delegated" | "app"
    cert_path: str = ""
    client_secret: str = ""
    out: str = "./snapshot"
    redact: bool = True
    concurrency: int = 5
    _extra: dict[str, Any]         # unknown keys preserved on round-trip
```

**Persistence:**

- Saved to `~/.ca-radar/config.yaml` by default
- `load()` is safe when the file is missing (returns defaults)
- Empty strings are omitted when saving (clean YAML)
- Unknown keys from a newer config version are preserved in `_extra` and written back unchanged

**`merge_cli()` — non-destructive CLI overlay:**

```python
cfg = RadarConfig.load().merge_cli(tenant="contoso.com", client_id="...")
```

Only non-empty / non-None CLI values overwrite saved config.
This means `ca-radar scan` with no flags uses 100% saved config, and passing `--tenant` overrides
only that field. The saved config is never mutated — a new `RadarConfig` instance is returned.

---

### 3.3 Auth

**Files:** `ca_radar/auth/app_auth.py`, `ca_radar/auth/delegated_auth.py`

Both providers implement the `AuthProvider` protocol defined in `graph/client.py`:

```python
@runtime_checkable
class AuthProvider(Protocol):
    def get_auth_header(self) -> dict[str, str]: ...
```

**AppAuthProvider** — unattended / CI use

Uses MSAL's `ConfidentialClientApplication`. Supports both certificate (PEM) and client secret.

```python
AppAuthProvider(
    tenant_id="...",
    client_id="...",
    cert_path="/path/to/cert.pem",   # preferred
    client_secret="...",              # alternative
)
```

Tokens are cached in memory. `get_token()` acquires via `acquire_token_for_client()`
with scope `https://graph.microsoft.com/.default`.

**DelegatedAuthProvider** — interactive / device-code

Uses MSAL's `PublicClientApplication`. On first call, initiates the device-code flow and
calls `prompt_callback(message)` to surface the sign-in URL/code to the user.
Subsequent calls use MSAL's token cache (silent first, then prompt again if expired).

```python
DelegatedAuthProvider(
    tenant_id="...",
    client_id="...",
    prompt_callback=lambda msg: print(msg),
)
```

**Scope strategy for delegated:**
Requests a list of per-resource scopes on first authentication
(e.g. `Policy.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`).
If the admin didn't consent to a scope, the 403 from Graph is caught by `GraphClient`
as a `ScopeNotGrantedError` and recorded as a scope warning rather than a hard failure.
Findings that depend on that data are marked indeterminate.

---

### 3.4 Graph Client

**Files:** `ca_radar/graph/client.py`, `ca_radar/graph/endpoints.py`, `ca_radar/graph/pagination.py`

**GraphClient** is an async context manager wrapping `httpx.AsyncClient`:

```python
async with GraphClient(auth=auth) as client:
    policies = await client.get_all("identity/conditionalAccess/policies")
```

Features:
- **Pagination:** `get_all()` follows `@odata.nextLink` transparently until exhausted
- **Throttling:** Detects 429 / 503, honours `Retry-After` header, exponential backoff capped at 64 s
- **Scope detection:** 403 → raises `ScopeNotGrantedError`; caller records warning and returns empty/None
- **Request log:** Every request is recorded in `.request_log` for audit/debugging
- **Test injection:** `http_client` parameter accepts a pre-built `httpx.AsyncClient` for unit tests

**pagination.py helpers:**
- `extract_value(body) → list[Any]` — returns `body["value"]` or `[body]`
- `extract_next_link(body) → str | None` — returns `body.get("@odata.nextLink")`

**endpoints.py** provides typed wrappers. Every function:
- Takes a `GraphClient`
- Calls `client.get_all()` or `client.get_single()`
- Passes results through `_parse_list(items, model, resource_name)` to get Pydantic instances
- Returns a typed list (e.g. `list[ConditionalAccessPolicy]`)

Key endpoints:

| Function | Graph path | Returns |
|---|---|---|
| `get_ca_policies()` | `identity/conditionalAccess/policies` | `list[ConditionalAccessPolicy]` |
| `get_users()` | `users` | `list[User]` |
| `get_groups()` | `groups` | `list[Group]` |
| `get_directory_roles()` | `directoryRoles` | `list[DirectoryRole]` |
| `get_role_assignments()` | `roleManagement/directory/roleAssignments` | `list[RoleAssignment]` |
| `get_pim_eligible_assignments()` | `roleManagement/directory/roleEligibilityScheduleInstances` | `list[PimEligibleRoleAssignment]` |
| `get_service_principals()` | `servicePrincipals` | `list[ServicePrincipal]` |
| `get_sign_in_logs()` | `auditLogs/signIns` | `list[SignInLog]` |
| `get_named_locations()` | `identity/conditionalAccess/namedLocations` | `list[Any]` (raw — mixed subtypes) |
| `get_authentication_strength_policies()` | `policies/authenticationStrengthPolicies` | `list[AuthenticationStrengthPolicy]` |

---

### 3.5 Snapshot

**Files:** `ca_radar/snapshot/models.py`, `ca_radar/snapshot/collector.py`, `ca_radar/snapshot/store.py`

**models.py** — Pydantic models for every Graph resource

All models inherit from `_Base` which sets `alias_generator=to_camel` so that camelCase
JSON from Graph maps cleanly to snake_case Python fields:

```python
class ConditionalAccessPolicy(BaseModel):
    id: str
    display_name: str
    state: PolicyState          # "enabled" | "disabled" | "enabledForReportingButNotEnforced"
    conditions: CaConditions
    grant_controls: CaGrantControl | None
    session_controls: CaSessionControl | None
```

Key enums (`StrEnum` — value IS the string, hashable, comparable):
- `PolicyState`: `enabled`, `disabled`, `enabledForReportingButNotEnforced`
- `GrantControlOperator`: `OR`, `AND`
- `SignInRiskLevel`: `none`, `low`, `medium`, `high`

**collector.py** — concurrent Graph collection

```python
async def collect_snapshot(
    client: GraphClient,
    store: SnapshotStore,
    tenant_id: str,
    redact: bool = True,
    concurrency: int = 5,
    captured_at: datetime | None = None,
) -> CollectionResult
```

Runs all 15 resource fetches behind an `asyncio.Semaphore(concurrency)`.
Each resource is fetched, optionally redacted, then written to disk immediately.
Failed resources are recorded in `CollectionResult.resources_failed` but don't abort the scan.

**store.py** — filesystem read/write

Disk layout:
```
snapshot/
└── contoso.onmicrosoft.com/
    └── 2024-06-15T12-00-00Z/
        ├── manifest.json
        ├── conditional_access_policies.json
        ├── users.json
        ├── groups.json
        ├── directory_roles.json
        ├── role_assignments.json
        └── ...
```

`SnapshotManifest` records: `schema_version`, `tenant_id`, `captured_at`, `tool_version`,
`redacted`, `redaction_salt_hint`, `resources_captured`, `resources_failed`, `scope_warnings`.

---

### 3.6 Resolver

**Files:** `ca_radar/resolver/policy_graph.py`, `ca_radar/resolver/effective_controls.py`, `ca_radar/resolver/exclusion_walker.py`

**SnapshotData** — the central data container

Loads all resources from disk and pre-computes lookup tables once:

| Index | Type | Purpose |
|---|---|---|
| `users_by_id` | `dict[str, User]` | O(1) user lookup |
| `groups_by_id` | `dict[str, Group]` | O(1) group lookup |
| `roles_by_id` | `dict[str, DirectoryRole]` | O(1) role lookup |
| `user_role_index` | `dict[str, set[str]]` | Active role assignments per user |
| `user_group_index` | `dict[str, set[str]]` | Transitive group memberships per user |
| `user_pim_role_index` | `dict[str, set[str]]` | PIM-eligible (not yet activated) roles per user |

`user_group_index` is built by `exclusion_walker.build_user_group_index()` which
calls `expand_group_to_users()` for every group. It uses `transitive_member_ids` (Graph
pre-computed) as a fast path, falling back to recursive `member_ids` expansion with cycle detection.

**PolicyResolver** — the query engine

```python
resolver.effective_policies(user_id, app_id, conditions) -> list[ConditionalAccessPolicy]
```

For each non-disabled policy, `_policy_applies()` checks five conditions (all must be true):

1. `_user_included()` — user matches `ALL`, `GuestsOrExternalUsers`, direct ID, group membership, or role assignment
2. `not _user_excluded()` — user is not directly excluded, not in excluded group, not in excluded role
3. `_app_included()` — app matches `ALL`, `None` (no match), or direct app ID
4. `not _app_excluded()` — app not in exclusion list
5. `_client_app_matches()` — client app type matches policy restriction (or no restriction)

`_aggregate_controls()` then iterates the applicable policies and builds one `EffectiveAccess`
object capturing the net result: `mfa_required`, `block`, `compliant_device_required`,
`hybrid_joined_required`, `session_controls`.

Report-only policies (`enabledForReportingButNotEnforced`) are tracked separately in
`report_only_policies` and never contribute to `mfa_required` etc.

**PolicyGraph** — NetworkX visualisation

Builds a `nx.DiGraph` where each node has `node_type` and `label`.
Node types: `user`, `group`, `role`, `policy`, `app`, `service_principal`.
Edges represent relationships: `member_of`, `has_role`, `includes_user`, `excludes_user`,
`includes_group`, `excludes_group`, `targets_app`, `applies_to_role`.

`to_json_dict()` returns `{nodes: [...], links: [...]}` in D3 force-graph format.

---

### 3.7 Analysers

**Files:** `ca_radar/analysers/base.py`, `ca_radar/analysers/runner.py`, `ca_radar/analysers/packs/*/`

**Finding lifecycle:**

```
Analyser.analyse() creates Finding
       ↓
runner deduplicates + sorts
       ↓
enrich_findings() attaches BaselineRef
       ↓
enrichment.enrich_findings() attaches owner / exception / priority
       ↓
Finding.to_dict() for JSON/CSV export
```

**Severity weights** (used to calculate posture score):

| Severity | Weight |
|---|---|
| `critical` | 15 |
| `high` | 7 |
| `medium` | 3 |
| `low` | 1 |
| `info` | 0 |

`posture_score = max(0, 100 - Σ weights)` — floored at 0.

**Analyser packs:**

| Pack | Class | Finding IDs | What it detects |
|---|---|---|---|
| `coverage/` | `MfaCoverageAnalyser` | CA-MFA-001, CA-MFA-002 | Users or admins without MFA / phishing-resistant auth coverage |
| `admin_roles/` | `AdminRolesAnalyser` | CA-ADMIN-001, CA-ADMIN-002 | No role-targeted CA policy; PIM-eligible users without MFA |
| `break_glass/` | `BreakGlassAnalyser` | CA-BG-001, CA-BG-002 | Break-glass accounts excluded from all MFA policies or poorly protected |
| `exclusions/` | `ExclusionAnalyser` | CA-EXCL-001, CA-EXCL-002 | Ghost exclusions (deleted users/groups still listed); oversized group exclusions |
| `legacy_auth/` | `LegacyAuthAnalyser` | CA-LEGACY-001 to CA-LEGACY-009 | Legacy client types (IMAP, POP3, EAS, SMTP AUTH, etc.) not blocked |
| `service_principals/` | `ServicePrincipalAnalyser` | CA-SP-001, CA-SP-002, CA-SP-003 | SPs with excessive app role assignments; uncontrolled OAuth grants |
| `risk_session/` | `RiskSessionAnalyser` | CA-RISK-001, CA-RISK-002 | High-risk sign-in sessions not covered by a CA policy |

**runner.py — concurrent execution:**

```python
async def run_analysers(data, resolver, analysers=None, max_workers=4) -> AnalysisResult
```

Analysers are CPU-bound (pure computation, no I/O) so they run in a `ThreadPoolExecutor`.
Each analyser is submitted as `loop.run_in_executor(executor, analyser.analyse, data, resolver)`.
Failures in individual analysers are caught, logged, and stored in `AnalysisResult.analyser_errors`
so one broken pack never aborts the whole scan.

---

### 3.8 Baselines

**Files:** `ca_radar/baselines/loader.py`, `ca_radar/baselines/enricher.py`, `ca_radar/baselines/data/*.yaml`

**YAML format** (one file per framework):

```yaml
framework: "SCuBA"
version: "2.0"
url: "https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project"
controls:
  - id: "MS.AAD.3.1v1"
    title: "Phishing-resistant MFA for privileged roles"
    description: "All users with privileged roles must use phishing-resistant MFA."
    finding_ids:
      - CA-ADMIN-002
      - CA-MFA-002
```

`finding_ids` is the join key. One control can reference multiple findings;
one finding can appear in multiple controls across multiple frameworks.

**`BaselineRegistry`** builds a reverse index at load time:
`{finding_id → list[(FrameworkSpec, ControlSpec)]}`.

**`refs_for(finding_id)`** returns `list[BaselineRef]` — one per control that references this finding.

**`alignment(active_finding_ids)`** returns per-framework `AlignmentResult`:
- A control **passes** if none of its `finding_ids` are in `active_finding_ids`
- A control **fails** if any of its `finding_ids` are in `active_finding_ids`
- `pct = (passing / total) * 100`, rounded to 1 decimal place

**`load_registry(data_dir=None)`** reads all YAML files from `ca_radar/baselines/data/` by default.
Pass a custom directory to use your own baseline files.

---

### 3.9 Enrichment

**File:** `ca_radar/enrichment.py`

Optional post-analysis step that attaches operational context to findings.
None of this data comes from Graph — it comes from user-supplied YAML files.

**Owners** (`owners.yaml`):
```yaml
principals:
  "user-guid-123": "Alice Chen"
  "group-guid-456": "Security Team"
findings:
  "CA-MFA-001": "IAM Team"
default: "Security Operations"
```

**Exceptions** (`exceptions.yaml`):
```yaml
- finding_id: CA-LEGACY-003
  principal: "sp-guid-789"
  status: accepted_risk
  reason: "Legacy connector, migration planned Q3"
  owner: "Bob Smith"
  approved_by: "CISO"
  expires: "2025-12-31"
```

After enrichment, `finding.owner`, `finding.exception`, and `finding.priority` are populated
as dicts on each Finding object. These appear in the HTML report and CSV export.
Expired exceptions are flagged in the report.

---

### 3.10 Exports

**Files:** `ca_radar/exports/json_export.py`, `ca_radar/exports/csv_export.py`, `ca_radar/exports/bicep_export.py`

All three take `AnalysisResult` and return a `str` (file contents).

**JSON schema** (`findings.json`):
```json
{
  "schema_version": "1",
  "tool_version": "0.2.0",
  "tenant_id": "contoso.onmicrosoft.com",
  "captured_at": "2024-06-15T12:00:00+00:00",
  "redacted": true,
  "summary": {
    "posture_score": 72,
    "total_findings": 5,
    "by_severity": {"critical": 1, "high": 2, "medium": 2, "low": 0, "info": 0},
    "elapsed_seconds": 8.3
  },
  "findings": [...]
}
```

**CSV** — flat, pipe-delimited multi-values, UTF-8 BOM for Excel auto-detection.

**Bicep** — ARM template snippets extracted from `finding.remediation.snippets`
where the label is `"Bicep"`. Generated only if at least one such snippet exists.

---

### 3.11 Render

**Files:** `ca_radar/render/html/renderer.py`, `ca_radar/render/html/portfolio_renderer.py`

Both renderers use Jinja2 with `FileSystemLoader` pointing to `render/html/templates/`.

**`render_html_report()`** produces a fully self-contained single-file HTML report:
- Findings JSON embedded in a `<script>` tag as `window.FINDINGS`
- Graph JSON embedded as `window.GRAPH_DATA`
- CSS embedded inline — no external stylesheet
- D3.js loaded from `cdn.jsdelivr.net` with a graceful fallback message if offline
- Baseline alignment table computed via `compute_alignment(findings, load_registry())`
  — non-fatal if baseline data is unavailable
- Confidence bars for findings where `confidence < 1.0`
- Redaction notice in footer when `redacted=True`

**`render_portfolio_report()`** produces a multi-tenant overview:
- All tenants in a table ranked by posture score (worst first)
- Sparkline per tenant from `trend_scores` (list of historical posture scores)
- Aggregate stats: total tenants, average score, total critical, total high
- Each row links to that tenant's individual `report.html`

---

### 3.12 Trend & Portfolio

**File:** `ca_radar/trend/store.py`

**SQLite schema:**
```sql
CREATE TABLE scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL,
    captured_at     TEXT NOT NULL,
    posture_score   INTEGER NOT NULL,
    total_findings  INTEGER NOT NULL DEFAULT 0,
    critical_count  INTEGER NOT NULL DEFAULT 0,
    high_count      INTEGER NOT NULL DEFAULT 0,
    medium_count    INTEGER NOT NULL DEFAULT 0,
    low_count       INTEGER NOT NULL DEFAULT 0,
    info_count      INTEGER NOT NULL DEFAULT 0,
    tool_version    TEXT NOT NULL DEFAULT '',
    snapshot_path   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_tenant_time ON scans (tenant_id, captured_at DESC);
```

Database location: `<out>/trend.db` (same base dir as snapshots).

Every successful scan appends one row. The portfolio report reads the latest row per tenant
plus the last N `posture_score` values for the sparkline.

---

## 4. Adding a New Analyser

1. **Create the pack directory:**
   ```
   ca_radar/analysers/packs/my_feature/
   ├── __init__.py
   └── my_feature.py
   ```

2. **Implement the analyser class:**
   ```python
   # ca_radar/analysers/packs/my_feature/my_feature.py
   from __future__ import annotations
   from typing import TYPE_CHECKING
   from ca_radar.analysers.base import Analyser, Finding, Remediation, Severity

   if TYPE_CHECKING:
       from ca_radar.resolver.effective_controls import PolicyResolver
       from ca_radar.resolver.policy_graph import SnapshotData

   class MyFeatureAnalyser(Analyser):
       @property
       def finding_ids(self) -> list[str]:
           return ["CA-MYFEATURE-001"]

       def analyse(
           self,
           data: SnapshotData,
           resolver: PolicyResolver,
       ) -> list[Finding]:
           findings = []
           # Your detection logic using data.policies, data.users, resolver, etc.
           if something_is_wrong:
               findings.append(
                   Finding(
                       id="CA-MYFEATURE-001",
                       title="Short human-readable title",
                       severity=Severity.high,
                       summary="One sentence: what was found.",
                       why_it_matters="One paragraph: risk explanation.",
                       evidence={"count": len(affected), "sample": affected[:3]},
                       affected_principals=affected,
                       remediation=Remediation(
                           description="Steps to fix.",
                           snippets=[("Portal", "Go to..."), ("PowerShell", "Set-Mg...")],
                           references=["https://learn.microsoft.com/..."],
                       ),
                   )
               )
           return findings
   ```

3. **Register it in the runner:**
   ```python
   # ca_radar/analysers/runner.py
   def _default_analysers() -> list[Analyser]:
       from ca_radar.analysers.packs.my_feature.my_feature import MyFeatureAnalyser
       return [
           ...,
           MyFeatureAnalyser(),
       ]
   ```

4. **Add a baseline mapping** (optional — see next section).

5. **Add tests** in `tests/analysers/test_my_feature.py` using the fixtures pattern
   from existing analyser tests.

**Finding ID convention:** `CA-<CATEGORY>-<NNN>` — keep categories consistent with existing packs.

---

## 5. Adding a New Baseline Framework

1. **Create the YAML file** in `ca_radar/baselines/data/`:
   ```yaml
   framework: "MYFRAMEWORK"
   version: "1.0"
   url: "https://..."
   controls:
     - id: "MF-1.1"
       title: "Require MFA for all users"
       description: "All users must be required to use MFA."
       finding_ids:
         - CA-MFA-001
         - CA-MFA-002
   ```

2. **That's it.** `load_registry()` discovers all YAML files in the `data/` directory automatically.
   The new framework will appear in the HTML report's baseline alignment table and in
   `findings.json` under each finding's `baselines` array.

---

## 6. Adding a New Export Format

1. **Create `ca_radar/exports/myformat_export.py`:**
   ```python
   from ca_radar.analysers.runner import AnalysisResult

   def export_myformat(
       analysis: AnalysisResult,
       tenant_id: str,
       captured_at: str,
   ) -> str:
       # Return file contents as a string
       ...
   ```

2. **Call it in `cli.py`** inside `_run_scan()` alongside the existing exports:
   ```python
   from ca_radar.exports.myformat_export import export_myformat
   myformat_path = snapshot_path / "findings.xyz"
   myformat_path.write_text(
       export_myformat(result, tenant_id, captured_at_str),
       encoding="utf-8",
   )
   ```

---

## 7. Key Design Decisions

**Read-only by design.**
`GraphClient` only issues GET requests. There is no mutation of the tenant.
This is enforced at the HTTP client level, not just by convention.

**Snapshot-first architecture.**
Collection (Graph API calls) and analysis are completely decoupled.
The analyser packs read from `SnapshotData` (in-memory, loaded from disk).
This means you can re-run analysis without hitting Graph again, run analysis
in CI against a stored snapshot, and write analyser tests with no network calls.

**Conservative policy matching.**
When the resolver cannot determine group membership with certainty
(e.g. a dynamic group whose rule was not evaluated), it defaults to
including the policy as potentially applicable and marks `confidence < 1.0`.
False negatives (missed gaps) are treated as worse than false positives (extra findings).

**Findings are deduplicated by ID.**
If two analysers emit the same finding ID (which should not happen by convention
but could happen through misconfiguration), the first one wins.
Finding IDs are stable across versions — they are the join key for baselines,
exceptions, and trend data.

**Posture score is additive.**
Score = 100 − Σ(severity.weight) for all findings, clamped to [0, 100].
A tenant with zero findings scores 100. The score is intentionally simple —
it is not a compliance percentage, it is a rough indicator for trend tracking.

**ThreadPoolExecutor for analysers.**
Analysers are CPU-bound (in-memory computation). Running them in threads
avoids the GIL overhead of process-based parallelism for this use case
while still providing concurrency for multiple packs.

**HTML report is fully self-contained.**
The report file has no external dependencies except D3 from a CDN.
D3 has a graceful fallback if the CDN is unreachable (the graph section
shows a static message; the rest of the report works fine offline).
This makes reports easy to share — a single `.html` file, email attachment,
upload to SharePoint, or commit to a repo.

**Distroless Docker.**
The runtime image (`gcr.io/distroless/python3-debian12:nonroot`) contains no shell,
no package manager, and runs as a non-root user (uid 65532).
Only `site-packages` (not the venv's `bin/` scripts) are copied to the runtime
because the venv scripts have a shebang pointing to the builder Python path
(`/usr/local/bin/python3.11`) which does not exist in distroless.
`ca_radar/__main__.py` enables `python3 -m ca_radar` as the entry point instead.

---

## 8. Testing Strategy

Tests live in `tests/` and are split by concern:

```
tests/
├── analysers/          one file per analyser pack; uses SnapshotData fixtures
├── e2e/                live Graph calls; skipped unless AZURE_* env vars are set
├── fixtures/           shared resolver_fixtures.py
├── unit/               isolated unit tests for every other module
└── test_cli.py         CLI integration tests using Typer's CliRunner
```

**Analyser tests** construct minimal `SnapshotData` objects with only the fields
needed for the specific detection, then call `analyser.analyse(data, resolver)` directly.
No Graph calls, no disk I/O, no async needed.

**Resolver tests** build `SnapshotData` with known policies/users/groups and assert
that `effective_policies()` returns the expected set.

**CLI tests** use `typer.testing.CliRunner`. ANSI escape codes from Rich are stripped
before assertions using `re.sub(r"\x1b\[[0-9;]*[mK]", "", output)`.

**Coverage is tracked via `pytest-cov`** and uploaded to Codecov on every CI run.
E2E tests are excluded from the standard test run (`--ignore=tests/e2e`) and
require real Azure credentials to execute.
