# HTML Report

The `report.html` file is fully self-contained — it embeds all CSS, findings data,
and JavaScript inline. The only external dependency is D3 (loaded from jsDelivr CDN
for the policy graph; gracefully degrades offline).

---

## Sections

### Header (sticky)

- **Tenant name** (with `(redacted)` badge if UPNs are hashed)
- **Posture score** badge — colour-coded: green ≥80, amber ≥50, red <50
- Scan timestamp and ca-radar version

### Severity filter cards

Five clickable cards — All, Critical, High, Medium, Low — filter the findings
table in place. The active card is highlighted.

### Policy graph

D3 v7 force-directed graph showing the relationships between users, groups,
roles, applications, and CA policies.

- **Click a node** to highlight its direct connections (dims unrelated nodes)
- **Click background** to deselect
- **Drag nodes** to rearrange
- **Scroll / pinch** to zoom

Node shapes by type:

| Shape | Type |
|---|---|
| Circle | User, Service principal |
| Triangle | Group |
| Rectangle | Policy |

### Findings table

Expandable rows — click any finding to reveal:

- **Summary** and **Why it matters** paragraphs
- **Remediation** guidance with tabbed code snippets (Portal steps, PowerShell, Bicep)
- **Baseline references** — coloured tags showing SCuBA / CIS control IDs
- **Evidence** — raw JSON excerpt from the snapshot
- **Affected principals** — up to 30 shown (with "… and N more" overflow)

### Baseline alignment

One card per framework showing:

- Alignment percentage (colour-coded)
- Progress bar
- Passing / failing control counts
- Link to the benchmark source

### Analyser errors

If any analyser failed during analysis, errors are shown here with the analyser
name and error message.

---

## Offline use

The report works fully offline except for the policy graph. If D3 cannot be
loaded from the CDN, the graph section shows a friendly fallback message:

> Graph unavailable (D3 CDN unreachable)

All findings data, baseline alignment, and remediation guidance remain accessible.

---

## Sharing the report

Because `report.html` is self-contained, you can share it directly — email,
SharePoint, Slack — without any server.

!!! warning "Privacy"
    If `--no-redact` was used, the report contains real UPNs. Treat it as
    sensitive data and share only within your organisation.
