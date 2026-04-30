# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: investwithdon7@gmail.com  
Subject: `[ca-radar SECURITY] <brief description>`

You can expect:
- Acknowledgement within **48 hours**
- A status update within **7 days**
- A patch release and public disclosure within **30 days** for confirmed issues

## Threat Model

ca-radar is a **read-only** tool. It requests only read permissions from Microsoft Graph and never writes to any tenant resource.

**In scope:**
- Vulnerabilities in ca-radar code that could expose tenant data from a snapshot
- Credential leakage via logs, reports, or temporary files
- Dependency vulnerabilities with known CVEs

**Out of scope:**
- Issues requiring physical access to the machine running ca-radar
- Issues in Microsoft Graph or Entra ID itself

## Safe Use Guidelines

- Store snapshots in a secure location; they contain tenant configuration data
- Use `--no-redact` only in trusted environments; default mode hashes all UPNs
- Rotate app registration certificates on a schedule recommended by your security policy
- Never commit `tenants.yaml` or certificate files to source control
