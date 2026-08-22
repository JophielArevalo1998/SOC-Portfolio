# Case 10 — SOC Account Compromise (Unfamiliar Sign-in / Impossible Travel)

**Incident:** 2355 | **Severity:** Medium → Critical | **Verdict:** True Positive — Active Account Compromise  
**Date:** 2026-07-07 | **Platform:** Microsoft XDR / Azure AD Identity Protection

---

## Alert

**Title:** Unfamiliar sign-in properties involving one user  
**Description:** All sign-in properties unfamiliar: ASN, Browser, Device, IP, Location, EASId, TenantIPsubnet  
**MITRE Tactic:** InitialAccess | **Techniques:** T1078, T1078.004  
**Detection Source:** Azure Active Directory Identity Protection  
**Correlated Alert:** Atypical travel (impossible travel between Canada and UK)  
**Activity:** 2026-07-07T21:12:00Z  

---

## Raw Alert (Key Fields)

```json
{
  "User Name": "SOC",
  "User Account": "soc@mahcyberdefense.com",
  "Client IP Address": "31.205.148.18",
  "Client Location": "Bath, Bath And North East Somerset, GB",
  "DetectorId": "UnfamiliarLocation",
  "PartnerAlgorithm": "Ests_FamiliarLocation",
  "User Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150.0.0.0 Edg/150.0.0.0",
  "Classification": null,
  "State": "Open"
}
```

---

## Queries Used

**SigninLogs — full sign-in timeline for SOC account:**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-07-07T20:00:00Z) .. datetime(2026-07-07T22:00:00Z))
| where UserPrincipalName has "soc@mahcyberdefense"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName, RiskLevelDuringSignIn, AuthenticationRequirement
| order by TimeGenerated asc
```

**CloudAppEvents — post-login activity from UK IP:**
```kql
CloudAppEvents
| where Timestamp between (datetime(2026-07-07T21:00:00Z) .. datetime(2026-07-07T22:30:00Z))
| where IPAddress == "31.205.148.18"
| project Timestamp, AccountUpn, ActionType, Application, ObjectName, IPAddress
| order by Timestamp asc
```

**MailItemsAccessed — email access detail:**
```kql
CloudAppEvents
| where Timestamp between (datetime(2026-07-07T21:10:00Z) .. datetime(2026-07-07T22:00:00Z))
| where IPAddress == "31.205.148.18"
| where ActionType == "MailItemsAccessed"
| project Timestamp, AccountUpn, ActionType, Application, IPAddress, RawEventData
| order by Timestamp asc
```

**AuditLogs — account modifications:**
```kql
AuditLogs
| where TimeGenerated between (datetime(2026-07-07T21:00:00Z) .. datetime(2026-07-07T23:00:00Z))
| where InitiatedBy has "soc" or TargetResources has "soc"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated asc
```

**Defender — all activity from UK IP across all tables:**
```kql
let ip = "31.205.148.18";
let selectedTimestamp = datetime(2026-07-07T21:12:00Z);
search in (IdentityLogonEvents,IdentityQueryEvents,IdentityDirectoryEvents,EmailEvents,CloudAppEvents)
Timestamp >= selectedTimestamp
and IPAddress == ip
| take 100
```

---

## Findings

**IOCs:**
- IP: `31[.]205[.]148[.]18` — Bath, England, UK — AbuseIPDB: 0 reports, 0% confidence; VT: 0/91 (clean residential/ISP)
- User: `soc[@]mahcyberdefense[.]com` — primary SOC account
- Application accessed: One Outlook Web (Microsoft Exchange Online)

**Sign-in timeline from UK IP:**

| Time (UTC) | ResultType | Risk Level | Event |
|---|---|---|---|
| 20:39 | 50126 | none | Failed — invalid credentials |
| 20:40 | 50126 | none | Failed — invalid credentials |
| 21:12 | 0 ✓ | — | **Successful login — alert fires** |
| 21:13 | 0 ✓ | medium | Successful |
| 21:13–21:19 | 0 ✓ | none/medium | 7 additional successful sessions |

**Post-login activity:**
- 4x `MailItemsAccessed` via Microsoft Exchange Online at 21:13–21:23 UTC
- SOC inbox emails read within 90 seconds of initial login
- No account modifications detected in AuditLogs

**Correlated alert:** Atypical travel — SOC account used from Canadian IP (`74[.]15[.]244[.]54`) and UK IP (`31[.]205[.]148[.]18`) simultaneously — impossible travel confirmed.

---

## Investigation Summary

On 2026-07-07, an attacker made two failed login attempts against `soc[@]mahcyberdefense[.]com` from a UK IP (`31[.]205[.]148[.]18`) at 20:39 and 20:40 UTC using incorrect credentials. At 21:12 UTC they succeeded and established a session. Within 90 seconds they accessed the SOC account's email inbox (4x `MailItemsAccessed`), maintaining an active session across 9 successful sign-ins until at least 21:19 UTC. Azure AD flagged all 7 sign-in properties as unfamiliar and simultaneously raised an Atypical Travel (impossible travel) alert correlating this UK login with a prior Canadian login. The compromised account is the primary SOC account — giving the attacker full visibility into active security investigations, incidents, and alerts.

**WHO:** Unknown threat actor; victim: `soc[@]mahcyberdefense[.]com` — primary SOC account  
**WHAT:** Successful account compromise — 9 authenticated sessions, SOC inbox emails accessed  
**WHEN:** 2026-07-07 20:39 UTC (first attempt) — 21:12 UTC (first success) — 21:19+ UTC (ongoing at detection); status at time of report: active  
**WHERE:** Microsoft 365 / Exchange Online — cloud; access via One Outlook Web from Bath, England  
**WHY:** Targeting the SOC account gives the attacker visibility into all security operations, active investigations, and potentially credentials or playbooks stored in email  
**HOW:** Credentials obtained via unknown means (no brute force — only 2 failed attempts before success suggesting prior credential exposure); authenticated via web browser from UK IP with no MFA challenge recorded  

---

## Recommendations

1. Revoke all active sessions for `soc[@]mahcyberdefense[.]com` immediately.
2. Reset the account password and enforce strong MFA (phishing-resistant where possible).
3. Audit all emails accessed during the compromise window — determine what content was read.
4. Check for email forwarding rules or inbox rules created by the attacker.
5. Block `31[.]205[.]148[.]18` at the tenant level.
6. Investigate how credentials were obtained — check for prior phishing, credential leaks, or password reuse.
7. Review all other accounts for similar unfamiliar sign-in or impossible travel alerts.
8. Consider whether active investigations were exposed and notify relevant parties.
