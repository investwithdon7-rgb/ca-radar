# ca-radar — Conditional Access Gap Analyser

[![CI](https://github.com/investwithdon7-rgb/ca-radar/actions/workflows/ci.yml/badge.svg)](https://github.com/investwithdon7-rgb/ca-radar/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ca-radar)](https://pypi.org/project/ca-radar/)
[![Python](https://img.shields.io/pypi/pyversions/ca-radar)](https://pypi.org/project/ca-radar/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> Created by **[Anjula Weeranayake](https://tekdruid.com)** · [TekDruid](https://tekdruid.com)

**ca-radar** is a free, read-only command-line tool that audits Microsoft 365 / Entra ID Conditional Access policies and produces an interactive HTML report.

- Detects **16 gap types** across MFA, legacy auth, admin protection, break-glass accounts, exclusion hygiene, risk policies, session controls, and workload identities
- Maps findings to **CISA SCuBA MS.AAD** and **CIS M365 Foundations** controls
- Renders a self-contained HTML report with a D3 policy graph, severity filters, and baseline alignment view
- Exports `findings.json`, `findings.csv`, and `remediation.bicep` for Power BI / ITSM / IaC workflows
- Tracks posture score over time via SQLite; supports MSP multi-tenant portfolio scanning
- Adds optional owner mapping, exception tracking, and priority scoring to findings
- **Never writes anything back to your tenant**

---

## Contents

- [Quick start](#quick-start)
- [Step 1 — Create an App Registration](#step-1--create-an-app-registration)
- [Step 2 — Run the setup wizard](#step-2--run-the-setup-wizard)
- [Step 3 — Run your first scan](#step-3--run-your-first-scan)
- [Installation](#installation)
- [Command reference](#command-reference)
- [Output files](#output-files)
- [Findings reference](#findings-reference)
- [MSP portfolio mode](#msp-portfolio-mode)
- [Docker](#docker)
- [Contributing](#contributing)

---

## Quick start

```bash
pip install ca-radar
ca-radar setup      # interactive wizard — guides you through app registration
ca-radar scan       # runs with saved config; open snapshot/<tenant>/report.html
```

---

## Step 1 — Create an App Registration

ca-radar needs a **read-only app registration** in your Entra ID tenant.
No write permissions are required at any point.

### 1.1 — Register the application

1. Sign in to the [Azure portal](https://portal.azure.com) as a **Global Administrator** or **Application Administrator**.
2. Go to **Azure Active Directory** → **App registrations** → **New registration**.
3. Fill in:
   - **Name:** `ca-radar` (or any name you prefer)
   - **Supported account types:** _Accounts in this organisational directory only_
   - **Redirect URI:** leave blank
4. Click **Register**.
5. On the **Overview** page, copy the **Application (client) ID** — you will need this in Step 2.

### 1.2 — Add API permissions

1. Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions**.
2. Search for and add **each** of the following permissions:

   | Permission | Purpose |
   |---|---|
   | `Policy.Read.All` | Read Conditional Access policies and named locations |
   | `Directory.Read.All` | Read users, groups, and directory roles |
   | `PrivilegedAccess.Read.AzureAD` | Read PIM eligible role assignments |
   | `DeviceManagementConfiguration.Read.All` | Read device compliance policies |
   | `IdentityRiskyUser.Read.All` | Read risky user list |
   | `AuditLog.Read.All` | Read sign-in logs |
   | `Application.Read.All` | Read service principals and applications |

3. Click **Grant admin consent for \<your organisation\>**.

> **Note:** Admin consent requires the Global Administrator role. If you don't have it, ask your tenant admin to grant consent after you create the app.

### 1.3 — Enable public client flows (delegated auth only)

Skip this if you are using app auth (certificate or secret).

1. Go to **Authentication** → scroll to **Advanced settings**.
2. Set **Allow public client flows** to **Yes**.
3. Click **Save**.

### 1.4 — (Optional) Certificate for unattended / app auth

For headless CI/CD use, generate a certificate and upload the `.cer` (public key) to your app registration under **Certificates & secrets** → **Certificates**. Pass the `.pem` (private key) path to ca-radar via `--cert-path`.

---

## Step 2 — Run the setup wizard

```bash
ca-radar setup
```

The wizard walks you through:

1. Entering your **tenant domain or ID** (e.g. `contoso.onmicrosoft.com`)
2. Optionally opening the Azure portal App Registration page in your browser
3. Pasting your **Client ID**
4. Choosing your **auth mode** (delegated device-code, app+certificate, or app+secret)
5. Setting output directory and UPN redaction preferences
6. Saving everything to **`~/.ca-radar/config.yaml`**
7. Optionally running your **first scan immediately**

After setup, `ca-radar scan` needs no arguments.

---

## Step 3 — Run your first scan

```bash
ca-radar scan
```

**Delegated auth** — a device-code URL is printed. Open it in your browser, sign in, and the scan proceeds automatically.

**App auth** — no interactive sign-in required.

The scan typically takes **30–90 seconds** depending on tenant size.

### What happens during a scan

1. **Collection** — ca-radar calls 15 Microsoft Graph endpoints in parallel and saves a JSON snapshot to disk
2. **Analysis** — 7 analyser packs evaluate the snapshot against 16 finding rules
3. **Export** — `findings.json`, `findings.csv`, and (if applicable) `remediation.bicep` are written
4. **Render** — A self-contained `report.html` is generated
5. **Trend** — The posture score is saved to `trend.db` for historical tracking

### Output location

```
./snapshot/
└── <tenant-id>/
    └── <YYYYMMDD-HHMMSS>/
        ├── report.html          ← open this in your browser
        ├── findings.json
        ├── findings.csv
        ├── remediation.bicep    ← only written when findings have remediation templates
        └── snapshot.json        ← raw Graph data (UPNs redacted by default)
```

Open `report.html` directly in any browser — it is fully self-contained with no external dependencies.

---

## Installation

### pip (recommended)

```bash
pip install ca-radar
```

Requires Python **3.11** or newer.

### pipx (isolated environment)

```bash
pipx install ca-radar
```

### uv

```bash
uv tool install ca-radar
```

### From source

```bash
git clone https://github.com/tekdruid/ca-radar.git
cd ca-radar
pip install -e ".[dev]"
```

---

## Command reference

### `ca-radar setup`

Interactive first-time setup wizard. Saves config to `~/.ca-radar/config.yaml`.

```bash
ca-radar setup
```

### `ca-radar scan`

Scan a single tenant. All options read from saved config if omitted.

```
Options:
  -t, --tenant TEXT        Tenant ID or domain name
  -o, --out TEXT           Base directory for snapshots  [default: ./snapshot]
  --auth TEXT              Auth mode: app or delegated  [default: delegated]
  --client-id TEXT         App registration client ID  [env: CA_RADAR_CLIENT_ID]
  --cert-path TEXT         Path to PEM certificate (app auth)  [env: CA_RADAR_CERT_PATH]
  --client-secret TEXT     Client secret (app auth)  [env: CA_RADAR_CLIENT_SECRET]
  --no-redact              Show real UPNs instead of hashes
  --concurrency INTEGER    Max parallel Graph requests  [default: 5]
  --owners PATH            Owner mapping YAML file
  --exceptions PATH        Exception tracking YAML file
```

**Examples:**

```bash
# Use saved config (recommended — run ca-radar setup first)
ca-radar scan

# Override tenant for this run only
ca-radar scan --tenant fabrikam.onmicrosoft.com

# App auth with a certificate (unattended / CI)
ca-radar scan --tenant contoso.com --auth app --cert-path /certs/ca-radar.pem

# Add owner mapping, exception status, and priority scoring
ca-radar scan --owners owners.yaml --exceptions exceptions.yaml

# Environment variables (CI/CD pipelines)
export CA_RADAR_CLIENT_ID=00000000-0000-0000-0000-000000000000
export CA_RADAR_CLIENT_SECRET=your-secret
ca-radar scan --tenant contoso.com --auth app
```

### Owner mapping, exceptions, and priority

Use `--owners` to attach accountable teams to findings. Principal keys can be user IDs, UPNs, group IDs, application IDs, or service principal IDs present in `affected_principals`; finding keys are stable finding IDs.

```yaml
owners:
  principals:
    guest.user_contoso.com#EXT#@tenant.onmicrosoft.com: "External Collaboration Owner"
    00000000-0000-0000-0000-000000000000: "IAM Team"
  findings:
    CA-SP-001: "Cloud Platform Team"
    CA-EXCL-001: "Identity Governance"
  default: "Unassigned"
```

Use `--exceptions` to mark approved risks, temporary suppressions, and expired exceptions. Exceptions do not hide findings; they add status and adjust priority so reviewers can see the risk decision.

```yaml
exceptions:
  - finding_id: CA-BG-001
    principal: breakglass@example.com
    status: accepted_risk
    reason: "Approved emergency access account"
    owner: "Security Operations"
    approved_by: "CISO"
    expires: "2026-12-31"
```

The HTML report, `findings.json`, and `findings.csv` include `owner`, `exception`, and `priority` fields.

### `ca-radar scan-all`

Scan multiple tenants from a YAML file and generate a portfolio report.

```bash
ca-radar scan-all --tenants tenants.yaml
```

**Example `tenants.yaml`:**

```yaml
tenants:
  - id: contoso.onmicrosoft.com
    name: Contoso Ltd
    auth_mode: delegated
    client_id: "00000000-0000-0000-0000-000000000000"

  - id: fabrikam.onmicrosoft.com
    name: Fabrikam Inc
    auth_mode: app
    client_id: "11111111-1111-1111-1111-111111111111"
    cert_path: "/certs/fabrikam.pem"
```

---

## Output files

| File | Description |
|---|---|
| `report.html` | Self-contained interactive report — open in any browser |
| `findings.json` | Versioned findings schema (v1) with posture score, owners, exceptions, and priority |
| `findings.csv` | UTF-8 BOM, pipe-delimited baselines plus owner, exception, and priority columns |
| `remediation.bicep` | Microsoft Graph Bicep templates for remediation-eligible findings |
| `snapshot.json` | Raw Graph data (UPNs SHA-256 hashed by default) |
| `trend.db` | SQLite database tracking posture score history per tenant |
| `portfolio.html` | MSP portfolio view with sparklines (scan-all only) |

---

## Findings reference

### MFA coverage

| ID | Severity | Title |
|---|---|---|
| `CA-MFA-001` | 🔴 Critical | No MFA policy covers all users |
| `CA-MFA-002` | 🟠 High | Privileged users not covered by phishing-resistant MFA |

### Legacy authentication

| ID | Severity | Title |
|---|---|---|
| `CA-LEGACY-001` | 🔴 Critical | No policy blocks legacy authentication protocols |
| `CA-LEGACY-002` | 🟠 High | Legacy auth not blocked for all platforms |

### Admin role protection

| ID | Severity | Title |
|---|---|---|
| `CA-ADMIN-001` | 🔴 Critical | No CA policy targets privileged directory roles |
| `CA-ADMIN-002` | 🟠 High | PIM-eligible admins not covered by CA policy |

### Break-glass accounts

| ID | Severity | Title |
|---|---|---|
| `CA-BG-001` | 🟠 High | No break-glass accounts detected |
| `CA-BG-002` | 🟡 Medium | Break-glass accounts not excluded from all CA policies |
| `CA-BG-003` | 🟡 Medium | Break-glass account quality issues |

### Exclusion hygiene

| ID | Severity | Title |
|---|---|---|
| `CA-EXCL-001` | 🟠 High | Ghost exclusions — excluded users/groups no longer exist |
| `CA-EXCL-002` | 🟡 Medium | Oversized MFA exclusion groups |

### Risk & session policies

| ID | Severity | Title |
|---|---|---|
| `CA-RISK-001` | 🟠 High | No sign-in risk policy configured |
| `CA-RISK-002` | 🟠 High | No user risk policy configured |
| `CA-SESS-001` | 🟡 Medium | No session frequency / persistent browser controls |

### Workload identity (service principals)

| ID | Severity | Title |
|---|---|---|
| `CA-SP-001` | 🟠 High | No CA policy targets workload identities |
| `CA-SP-002` | 🟡 Medium | High-privilege service principals not covered by CA |

---

## MSP portfolio mode

For MSPs managing multiple tenants, `scan-all` scans them sequentially and generates a ranked portfolio report.

```bash
ca-radar scan-all --tenants tenants.yaml --out ./snapshots
```

Open `./snapshots/portfolio.html` for:
- Ranked posture scores with trend sparklines
- Critical and high finding totals per tenant
- Links to each tenant's individual report

---

## Docker

```bash
# Pull and run (app auth)
docker run --rm \
  -e CA_RADAR_CLIENT_ID=your-client-id \
  -e CA_RADAR_CLIENT_SECRET=your-secret \
  -v "$(pwd)/snapshot:/snapshot" \
  ghcr.io/tekdruid/ca-radar:latest \
  scan --tenant contoso.onmicrosoft.com --auth app --out /snapshot

# Build locally
docker build -t ca-radar:local .
docker run --rm ca-radar:local --version
```

The image uses `gcr.io/distroless/python3-debian12:nonroot` — no shell, no package manager, minimal attack surface.

---

## Baseline alignment

ca-radar maps findings to two security frameworks:

- **CISA SCuBA MS.AAD v1.0** — 8 controls
- **CIS Microsoft 365 Foundations Benchmark v3.1.0** — 7 controls

The HTML report shows your alignment percentage for each framework. You can extend this by dropping YAML files into `ca_radar/baselines/data/`.

---

## Configuration file

`~/.ca-radar/config.yaml` (created by `ca-radar setup`):

```yaml
tenant: contoso.onmicrosoft.com
client_id: 00000000-0000-0000-0000-000000000000
auth_mode: delegated
out: ./snapshot
redact: true
concurrency: 5
```

CLI flags and environment variables always override saved config values.

---

## Troubleshooting

### `AADSTS65002` — Consent between application and resource

This error appears when admin consent has not been granted. In the Azure portal go to **API permissions** and click **Grant admin consent for your organisation**.

### `AADSTS700016` — Application not found

The client ID is incorrect or the app was created in a different tenant. Verify the **Application (client) ID** on the app registration Overview page.

### `AADSTS53003` — Access blocked by Conditional Access

The sign-in account is blocked by a CA policy. Try signing in with an emergency access (break-glass) account, or switch to app auth with a service principal.

### No connections in the policy graph

Floating user dots with no connecting lines means your tenant has **no Conditional Access policies** yet. All 16 findings will fire. The `remediation.bicep` file contains ready-to-deploy templates to fix each one.

### Scope warnings in the collection summary

Warnings such as _"IdentityProtection not available"_ mean that feature requires a higher licence tier (Entra ID P2 for risk policies, Entra Workload ID Premium for service principal policies). Affected findings show as **indeterminate** rather than falsely firing.

---

## Contributing

Contributions are welcome!

```bash
git clone https://github.com/investwithdon7-rgb/ca-radar.git
cd ca-radar
pip install -e ".[dev]"
pytest
```

Please read [CONTRIBUTING.md](docs/contributing.md) before submitting a pull request.

---

## Licence

[MIT](LICENSE) — free to use, modify, and redistribute.

---

> **ca-radar is strictly read-only.** It uses Microsoft Graph read permissions only.
> No data is ever written back to your tenant.
> Snapshots are stored locally; UPNs are SHA-256 hashed by default.

---

<p align="center">
  Built by <strong>Anjula Weeranayake</strong> &nbsp;·&nbsp;
  <a href="https://tekdruid.com">TekDruid</a> &nbsp;·&nbsp;
  <a href="https://tekdruid.com">tekdruid.com</a>
</p>
