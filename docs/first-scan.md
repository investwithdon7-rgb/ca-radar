# First Scan Walkthrough

This page walks through a complete scan from installation to open report.

## 1. Install

```bash
pip install ca-radar
ca-radar --version   # ca-radar version 0.1.0
```

## 2. Run the scan

```bash
ca-radar scan --tenant contoso.onmicrosoft.com
```

You'll see:

```
╭─────────────────────────── Scan starting ─────────────────────────────╮
│ ca-radar v0.1.0                                                        │
│ Tenant      : contoso.onmicrosoft.com                                  │
│ Auth mode   : delegated                                                │
│ Output      : ./snapshot                                               │
│ Redact UPNs : yes                                                      │
╰────────────────────────────────────────────────────────────────────────╯

To sign in, use a web browser to open https://microsoft.com/devicelogin
and enter code ABCD-1234 to authenticate.
```

Sign in with an account that has at least **Global Reader** or **Security Reader**.

## 3. Watch the collection

```
Resource                          Status
──────────────────────────────────────────
conditional_access_policies       ✓ captured
named_locations                   ✓ captured
users                             ✓ captured
groups                            ✓ captured
...
sign_in_logs                      ✓ captured

╭──────────── Snapshot saved ────────────╮
│ Path     : snapshot/contoso/20250601T  │
│ Captured : 15 resources               │
│ Failed   : 0   Time : 42.3s           │
╰────────────────────────────────────────╯
```

## 4. Review findings

```
          Gap Analysis
┌──────────────┬──────────┬──────────────────────────┬──────────┐
│ ID           │ Severity │ Title                    │ Affected │
├──────────────┼──────────┼──────────────────────────┼──────────┤
│ CA-LEGACY-001│ 🟠 high  │ Legacy auth not blocked  │ —        │
│ CA-MFA-001   │ 🟠 high  │ No MFA for all users     │ 12       │
│ CA-BG-001    │ 🟠 high  │ No break-glass account   │ —        │
│ CA-SESS-001  │ 🟡 medium│ No sign-in frequency     │ —        │
└──────────────┴──────────┴──────────────────────────┴──────────╯

Posture score : 72/100
🟠 3 high  🟡 1 medium

✓ Report ready  snapshot/contoso.onmicrosoft.com/20250601T120000Z/report.html
```

## 5. Open the report

```bash
open snapshot/contoso.onmicrosoft.com/*/report.html
```

The report shows:

- **Posture score** in the sticky header (colour-coded green/amber/red)
- **Severity filter cards** — click to filter the findings table
- **Policy graph** — D3 force-directed graph showing user→group→policy relationships
- **Findings table** — click any row to expand full detail: why it matters, remediation steps, evidence JSON, affected principals
- **Baseline alignment** — SCuBA and CIS coverage bars

## 6. Deploy remediation

If `remediation.bicep` was generated:

```bash
# Preview changes (What-if)
az deployment tenant what-if \
  --template-file snapshot/contoso.onmicrosoft.com/*/remediation.bicep

# Deploy (creates policies in report-only mode)
az deployment tenant create \
  --template-file snapshot/contoso.onmicrosoft.com/*/remediation.bicep
```

All generated policies are in `enabledForReportingButNotEnforced` mode.
Review sign-in logs for 1–2 weeks before switching to `enabled`.
