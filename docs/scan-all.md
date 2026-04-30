# MSP Portfolio Mode

`ca-radar scan-all` scans multiple tenants from a YAML file and produces
a ranked portfolio report alongside the per-tenant reports.

---

## Tenants file format

```yaml
tenants:
  - id: contoso.onmicrosoft.com
    name: Contoso Ltd          # optional display name
    auth_mode: delegated       # delegated (default) | app

  - id: fabrikam.onmicrosoft.com
    name: Fabrikam Inc
    auth_mode: app
    client_id: "11111111-0000-0000-0000-000000000000"
    cert_path: "/path/to/fabrikam-cert.pem"

  - id: adventure-works.onmicrosoft.com
    name: Adventure Works
    auth_mode: app
    client_id: "22222222-0000-0000-0000-000000000000"
    client_secret: ""          # prefer cert_path; set via env var
```

### Field reference

| Field | Required | Default | Description |
|---|---|---|---|
| `id` | ✅ | — | Entra tenant ID or domain name |
| `name` | ❌ | `id` | Human-readable display name |
| `auth_mode` | ❌ | `delegated` | `delegated` or `app` |
| `client_id` | ❌ | Azure CLI ID | App registration client ID |
| `cert_path` | ❌ | — | Path to PEM certificate (app auth) |
| `client_secret` | ❌ | — | Client secret (app auth, less secure) |

---

## Running a portfolio scan

```bash
ca-radar scan-all --tenants tenants.yaml --out ./snapshot
```

Tenants are scanned **sequentially** to avoid rate-limiting issues.
For each tenant, ca-radar produces the full set of outputs
(`report.html`, `findings.json`, `findings.csv`, `remediation.bicep`).

After all tenants complete, a `portfolio.html` is written to the
snapshot base directory.

```
snapshot/
├── portfolio.html                 ← portfolio summary
├── contoso.onmicrosoft.com/
│   └── 20250601T120000Z/
│       ├── report.html
│       ├── findings.json
│       ├── findings.csv
│       └── remediation.bicep
├── fabrikam.onmicrosoft.com/
│   └── 20250601T120300Z/
│       └── report.html
└── trend.db                       ← posture score history
```

---

## Portfolio report features

The `portfolio.html` report shows:

- **Stat cards** — tenant count, average posture score, total critical/high findings
- **Ranked table** — tenants sorted worst-to-best by posture score
- **Sparklines** — inline SVG trend chart showing last 10 scans per tenant
- **Sortable columns** — click any column header to re-sort
- **Report links** — click "report ↗" to open the per-tenant HTML report

---

## Trend tracking

Every scan (single or portfolio) saves a row to `trend.db` in the snapshot
base directory. Run the scan weekly for posture trend data. Sparklines in
the portfolio view automatically show improvement or regression over time.

---

## Handling failures

If one tenant fails (auth error, insufficient permissions, etc.), ca-radar
prints the error, continues to the next tenant, and exits with code 1 after
all tenants have been attempted.

Successful results are still written to `portfolio.html`.

---

## Example: Unattended automation

```bash
#!/bin/bash
# Weekly MSP scan — run via cron or Azure DevOps pipeline

export CA_RADAR_CLIENT_ID="00000000-0000-0000-0000-000000000000"
export CA_RADAR_CERT_PATH="/secure/certs/ca-radar.pem"

ca-radar scan-all \
  --tenants /etc/ca-radar/tenants.yaml \
  --out /var/lib/ca-radar/snapshot \
  --auth app
```
