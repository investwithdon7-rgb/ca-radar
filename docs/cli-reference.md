# CLI Reference

## ca-radar scan

Scan a single tenant and produce a snapshot + report.

```
ca-radar scan [OPTIONS]
```

| Option | Env var | Default | Description |
|---|---|---|---|
| `--tenant` / `-t` | — | required | Tenant ID or domain name |
| `--out` / `-o` | — | `./snapshot` | Base directory for snapshots |
| `--auth` | — | `delegated` | Auth mode: `app` or `delegated` |
| `--client-id` | `CA_RADAR_CLIENT_ID` | Azure CLI ID | App registration client ID |
| `--cert-path` | `CA_RADAR_CERT_PATH` | — | Path to PEM certificate |
| `--client-secret` | `CA_RADAR_CLIENT_SECRET` | — | Client secret |
| `--no-redact` | — | off | Disable UPN hashing |
| `--retain-signins` | — | off | Keep sign-in log samples |
| `--concurrency` | — | `5` | Max parallel Graph requests |

---

## ca-radar scan-all

Scan multiple tenants from a YAML file (MSP portfolio mode).

```
ca-radar scan-all [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--tenants` / `-t` | required | Path to tenants YAML file |
| `--out` / `-o` | `./snapshot` | Base directory for snapshots |
| `--no-redact` | off | Disable UPN hashing for all tenants |
| `--concurrency` | `5` | Max parallel Graph requests per tenant |

---

## ca-radar --version

```
ca-radar --version
# ca-radar version 0.1.0
```

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Scan failed or cancelled |

---

## Environment variables

| Variable | Used by |
|---|---|
| `CA_RADAR_CLIENT_ID` | `scan`, `scan-all` app auth |
| `CA_RADAR_CERT_PATH` | `scan`, `scan-all` app auth |
| `CA_RADAR_CLIENT_SECRET` | `scan`, `scan-all` app auth |
