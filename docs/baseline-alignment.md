# Baseline Alignment

ca-radar maps every finding to external security framework controls and computes
an alignment percentage per framework. The mappings are stored as YAML files that
you can inspect, extend, or replace.

---

## Built-in frameworks

| Framework | Version | Controls |
|---|---|---|
| **CISA SCuBA** | 1.0 | 8 MS.AAD controls |
| **CIS M365** | 3.1.0 | 7 controls |

### SCuBA controls

| Control | Title | Covered by |
|---|---|---|
| MS.AAD.1.1v1 | Block legacy authentication | CA-LEGACY-001, CA-LEGACY-002 |
| MS.AAD.2.1v1 | Require MFA for all users | CA-MFA-001 |
| MS.AAD.2.3v1 | Phishing-resistant MFA for privileged roles | CA-MFA-002, CA-ADMIN-001 |
| MS.AAD.2.4v1 | No MFA exclusion groups | CA-EXCL-002 |
| MS.AAD.3.1v1 | Sign-in risk policy | CA-RISK-001 |
| MS.AAD.3.2v1 | User risk policy | CA-RISK-002 |
| MS.AAD.3.3v1 | Sign-in frequency for admins | CA-SESS-001 |
| MS.AAD.6.1v1 | Break-glass accounts | CA-BG-001, CA-BG-002 |

---

## YAML schema

Baseline files live in `ca_radar/baselines/data/`. Any `.yaml` file in that
directory is loaded automatically.

```yaml
framework: MyFramework          # required — display name
version: "1.0"                  # required — displayed in HTML report
url: "https://example.com"      # required — "benchmark ↗" link in report
controls:
  - id: CTRL-1.1                # required — stable control identifier
    title: "Block legacy auth"  # required — shown in finding detail cards
    description: >              # optional — additional context
      Policies MUST block all legacy authentication flows.
    finding_ids:                # optional — which ca-radar finding IDs
      - CA-LEGACY-001           # indicate this control is failing
      - CA-LEGACY-002
```

### Alignment calculation

A control is **passing** when none of its `finding_ids` appear in the current
scan's active findings. A control with an empty `finding_ids` list always passes.

```
alignment % = (passing controls / total controls) × 100
```

---

## Adding a custom framework

1. Create `ca_radar/baselines/data/myframework.yaml` using the schema above
2. Re-run a scan — the framework appears automatically in the HTML report

```yaml
framework: NCSC CAF
version: "3.2"
url: "https://www.ncsc.gov.uk/collection/caf"
controls:
  - id: B2.b
    title: "Identity and access management — MFA"
    finding_ids:
      - CA-MFA-001
      - CA-MFA-002
```

No Python changes required.

---

## Disabling a built-in framework

Remove or rename the YAML file:

```bash
mv ca_radar/baselines/data/cis.yaml ca_radar/baselines/data/cis.yaml.disabled
```

---

## JSON export

Baseline references appear in `findings.json` under each finding's `baselines` array:

```json
{
  "id": "CA-MFA-001",
  "baselines": [
    { "framework": "SCuBA", "control_id": "MS.AAD.2.1v1", "title": "MFA SHALL be required for all users" },
    { "framework": "CIS",   "control_id": "1.2.1",        "title": "Ensure MFA is required for all users" }
  ]
}
```
