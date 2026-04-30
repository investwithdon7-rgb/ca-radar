# Findings Reference

Every finding has a stable ID used across scans, exports, and dashboard tracking.

---

## MFA Coverage

### CA-MFA-001 — No MFA policy covering all users

| Field | Value |
|---|---|
| **Severity** | 🟠 High |
| **SCuBA** | MS.AAD.2.1v1 |
| **CIS** | 1.2.1 |

**Summary:** No enabled Conditional Access policy requires MFA for all users.

**Why it matters:** Without a blanket MFA policy, any user whose account is
compromised via phishing or password spray can authenticate with just a password,
giving an attacker persistent access to all cloud resources.

**Remediation:** Create a CA policy targeting All Users with a grant control of
`mfa`. Start in report-only mode, review the sign-in logs for 1–2 weeks, then
enable. Exclude break-glass accounts.

---

### CA-MFA-002 — No phishing-resistant MFA for privileged roles

| Field | Value |
|---|---|
| **Severity** | 🟠 High |
| **SCuBA** | MS.AAD.2.3v1 |
| **CIS** | 1.2.3 |

**Summary:** No enabled CA policy enforces phishing-resistant authentication
(FIDO2 / Windows Hello for Business / certificate-based) for privileged roles.

**Why it matters:** Standard MFA (TOTP, SMS) is vulnerable to real-time phishing
and adversary-in-the-middle attacks. Privileged accounts are primary targets.

---

## Legacy Authentication

### CA-LEGACY-001 / CA-LEGACY-002 — Legacy authentication not blocked

| Field | Value |
|---|---|
| **Severity** | 🟠 High |
| **SCuBA** | MS.AAD.1.1v1 |
| **CIS** | 1.1.1 |

**Summary:** Legacy authentication protocols (Exchange ActiveSync, IMAP, POP3,
SMTP AUTH, older Office clients) are not blocked by a CA policy.

**Why it matters:** Legacy protocols do not support modern authentication and
therefore bypass MFA entirely. Over 99% of password spray attacks use legacy auth.

**Remediation:** Create a CA policy targeting `clientAppTypes: [exchangeActiveSync, other]`
with `block` grant control.

---

## Break-Glass Accounts

### CA-BG-001 — No break-glass account detected

| Field | Value |
|---|---|
| **Severity** | 🟠 High |
| **SCuBA** | MS.AAD.6.1v1 |

**Summary:** No emergency access (break-glass) account was detected in the tenant.

**Why it matters:** If MFA is enforced via CA and your primary admin accounts
are locked out or their MFA methods are unavailable, you cannot administer the
tenant. Break-glass accounts provide a safety net.

---

### CA-BG-002 — Break-glass account lacks phishing-resistant MFA

| Field | Value |
|---|---|
| **Severity** | 🟡 Medium |
| **SCuBA** | MS.AAD.6.1v1 |

**Summary:** A break-glass account was detected, but it is not protected by a
phishing-resistant authentication method (FIDO2 hardware key or certificate).

---

### CA-BG-003 — Break-glass account subject to CA policies

| Field | Value |
|---|---|
| **Severity** | 🔵 Low |

**Summary:** A break-glass account exists but is not excluded from all CA policies.
In a lockout scenario, the policies may prevent emergency access.

---

## Admin Roles

### CA-ADMIN-001 — No role-targeted CA policy for privileged roles

| Field | Value |
|---|---|
| **Severity** | 🟠 High |
| **SCuBA** | MS.AAD.2.3v1 |
| **CIS** | 1.2.3 |

**Summary:** No enabled CA policy targets privileged Entra ID roles (Global
Administrator, Security Administrator, etc.) directly.

**Why it matters:** Admins require stronger authentication requirements than
regular users. A generic MFA policy is insufficient — privileged roles need
phishing-resistant MFA with shorter session lifetimes.

---

### CA-ADMIN-002 — PIM-eligible admins not covered by MFA

| Field | Value |
|---|---|
| **Severity** | 🟠 High |
| **SCuBA** | MS.AAD.2.3v1 |

**Summary:** Users with PIM-eligible privileged role assignments are not
covered by any MFA-enforcing CA policy. When they activate their roles,
they authenticate without MFA.

---

## Exclusions

### CA-EXCL-001 — Ghost exclusions in CA policies

| Field | Value |
|---|---|
| **Severity** | 🟡 Medium |

**Summary:** One or more CA policies exclude user or group IDs that no longer
exist in the directory (deleted accounts or groups).

**Why it matters:** Ghost exclusions are security hygiene issues. They may
indicate stale policy configurations and could mask larger problems.

---

### CA-EXCL-002 — Oversized MFA exclusion group

| Field | Value |
|---|---|
| **Severity** | 🟠 High |
| **SCuBA** | MS.AAD.2.4v1 |
| **CIS** | 1.2.4 |

**Summary:** An MFA Conditional Access policy has an exclusion group with more
than 10 members, effectively providing a large MFA bypass surface.

---

## Risk-Based Policies

### CA-RISK-001 — No sign-in risk policy

| Field | Value |
|---|---|
| **Severity** | 🟠 High |
| **SCuBA** | MS.AAD.3.1v1 |
| **CIS** | 1.3.1 |

**Summary:** No enabled CA policy responds to medium or high sign-in risk levels.
Requires Entra ID P2.

---

### CA-RISK-002 — No user risk policy

| Field | Value |
|---|---|
| **Severity** | 🟠 High |
| **SCuBA** | MS.AAD.3.2v1 |
| **CIS** | 1.3.2 |

**Summary:** No enabled CA policy requires a secure password change when a user's
risk level is high. Requires Entra ID P2.

---

### CA-SESS-001 — No sign-in frequency for privileged roles

| Field | Value |
|---|---|
| **Severity** | 🟡 Medium |
| **SCuBA** | MS.AAD.3.3v1 |
| **CIS** | 1.5.1 |

**Summary:** No CA session policy enforces sign-in frequency limits for
privileged administrator roles.

**Why it matters:** Long-lived sessions for admin accounts increase the blast
radius of token theft attacks.

---

## Service Principals

### CA-SP-001 — No workload identity CA policy

| Field | Value |
|---|---|
| **Severity** | 🟠 High |

**Summary:** No Conditional Access policy targets service principals / workload
identities (`clientApplications` condition). Requires Entra Workload ID Premium.

---

### CA-SP-002 — No app-specific CA policies

| Field | Value |
|---|---|
| **Severity** | 🟡 Medium |

**Summary:** Service principals are present in the tenant but no CA policy
restricts access to specific high-value applications (Microsoft Graph, Exchange
Online, Azure Management).

---

## Posture score weights

| Severity | Weight |
|---|---|
| 🔴 Critical | −15 pts |
| 🟠 High | −7 pts |
| 🟡 Medium | −3 pts |
| 🔵 Low | −1 pt |
| ⚪ Info | 0 pts |

Score is clamped to [0, 100]. A tenant with no findings scores 100.
