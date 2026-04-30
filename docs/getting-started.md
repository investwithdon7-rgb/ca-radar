# Getting Started

## Requirements

- Python 3.11 or later
- An Entra ID tenant where you have at least one of:
  - **Global Reader** role (recommended for read-only operations)
  - **Security Reader** role
  - **Conditional Access Administrator** role (read access sufficient)

---

## Installation

=== "pip"

    ```bash
    pip install ca-radar
    ```

=== "uv"

    ```bash
    uv tool install ca-radar
    ```

=== "pipx"

    ```bash
    pipx install ca-radar
    ```

=== "Docker"

    ```bash
    docker pull ghcr.io/tekdruid/ca-radar:latest
    docker run --rm -v $(pwd)/snapshot:/snapshot \
      ghcr.io/tekdruid/ca-radar:latest \
      scan --tenant contoso.onmicrosoft.com
    ```

Verify the installation:

```bash
ca-radar --version
```

---

## Authentication modes

ca-radar supports two authentication modes:

### Delegated (device code) — recommended for first use

No app registration required. Uses the well-known Azure CLI app ID.

```bash
ca-radar scan --tenant contoso.onmicrosoft.com
# Prints a device code — open https://microsoft.com/devicelogin and enter it
```

!!! tip "Required permissions"
    The signed-in account needs at minimum: `Policy.Read.All`, `Directory.Read.All`,
    `IdentityRiskyUser.Read.All`, `AuditLog.Read.All`.

### App registration — recommended for automation

1. Create an app registration in Entra ID
2. Grant the following **application** permissions and admin-consent them:

    | Permission | Use |
    |---|---|
    | `Policy.Read.All` | Read CA policies |
    | `Directory.Read.All` | Read users, groups, roles |
    | `IdentityRiskyUser.Read.All` | Read risky users |
    | `AuditLog.Read.All` | Read sign-in logs |
    | `RoleManagement.Read.Directory` | Read PIM assignments |

3. Create a **certificate** (preferred) or client secret

```bash
# With certificate
ca-radar scan \
  --tenant contoso.onmicrosoft.com \
  --auth app \
  --client-id 00000000-0000-0000-0000-000000000000 \
  --cert-path /path/to/cert.pem

# With client secret (less secure)
ca-radar scan \
  --tenant contoso.onmicrosoft.com \
  --auth app \
  --client-id 00000000-0000-0000-0000-000000000000 \
  --client-secret "$CLIENT_SECRET"
```

Environment variables are also supported:

```bash
export CA_RADAR_CLIENT_ID="00000000-0000-0000-0000-000000000000"
export CA_RADAR_CERT_PATH="/path/to/cert.pem"
ca-radar scan --tenant contoso.onmicrosoft.com --auth app
```

---

## Your first scan

```bash
ca-radar scan --tenant contoso.onmicrosoft.com
```

ca-radar will:

1. Authenticate (prompt for device code if delegated)
2. Collect a snapshot from Microsoft Graph (~30–90 seconds depending on tenant size)
3. Run gap analysis
4. Write outputs to `./snapshot/contoso.onmicrosoft.com/<timestamp>/`

Output files:

| File | Description |
|---|---|
| `report.html` | Self-contained interactive HTML report |
| `findings.json` | Machine-readable findings with versioned schema |
| `findings.csv` | Flat CSV for Excel / Power BI |
| `remediation.bicep` | Auto-generated Bicep remediation (report-only mode) |
| `manifest.json` | Snapshot metadata (tenant, timestamp, tool version) |

Open the report:

```bash
# macOS / Linux
open snapshot/contoso.onmicrosoft.com/*/report.html

# Windows
start snapshot\contoso.onmicrosoft.com\*\report.html
```

---

## Privacy and redaction

By default, ca-radar **hashes all UPNs** (SHA-256) in the snapshot so no real
usernames are stored on disk. Finding outputs show hashed identifiers.

To store real usernames (e.g. for detailed investigation):

```bash
ca-radar scan --tenant contoso.onmicrosoft.com --no-redact
```

!!! warning
    `--no-redact` snapshots may contain PII. Store them accordingly.

---

## Next steps

- [First scan walkthrough](first-scan.md)
- [MSP Portfolio mode](scan-all.md) — scan multiple tenants at once
- [Findings Reference](findings-reference.md) — what each finding means
