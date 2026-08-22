# Case 01 — Anonymous IP Address (SOC-174)

**Incident:** 2119 | **Severity:** Low | **Verdict:** True Positive  
**Date:** 2026-05-21 | **Platform:** Microsoft XDR / Azure AD Identity Protection

---

## Alert

**Title:** Anonymous IP address involving one user  
**Description:** Sign-in from an anonymous IP address (e.g. Tor browser, anonymizer VPNs)  
**MITRE Tactic:** InitialAccess  
**Detection Source:** Azure Active Directory Identity Protection  
**First Activity:** 2026-05-21T19:30:38Z  

---

## Raw Alert (Key Fields)

```json
{
  "User Name": "SOC-174",
  "User Account": "soc-174@mahcyberdefense.com",
  "Client IP Address": "92.118.63.112",
  "Client Location": "Reduta, Sofiya-Grad, BG",
  "PartnerAlgorithm": "Ests_Tor",
  "Classification": "truePositive",
  "User Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Firefox/150.0",
  "State": "Closed",
  "classificationComment": "Incident automatically resolved as all alerts in the incident were resolved."
}
```

---

## Queries Used

**SigninLogs — full activity for SOC-174:**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-05-21T19:00:00Z) .. datetime(2026-05-22T02:00:00Z))
| where UserPrincipalName has "soc-174"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription, AppDisplayName, RiskLevelDuringSignIn, AuthenticationRequirement
| order by TimeGenerated asc
```

**Activity log filtered on IP (Microsoft Defender for Cloud Apps):**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-05-21T19:00:00Z) .. datetime(2026-05-22T02:00:00Z))
| where IPAddress == "92.118.63.112"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName, Location, RiskLevelDuringSignIn
| order by TimeGenerated asc
```

**AuditLogs — post-login account changes:**
```kql
AuditLogs
| where TimeGenerated between (datetime(2026-05-21T19:00:00Z) .. datetime(2026-05-22T02:00:00Z))
| where InitiatedBy has "soc-174" or TargetResources has "soc-174"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated asc
```

---

## Findings

**IOCs:**
- IP: `92[.]118[.]63[.]112`
- User: `soc-174[@]mahcyberdefense[.]com`
- Location: Bulgaria (BG)
- Detection Algorithm: `Ests_Tor` (confirmed Tor exit node)

**Activity Log Results:**
- 5 events from same IP — multiple successful logins (ResultType 0)
- `ResultType 50140` — "Keep me signed in" interrupted — MFA challenged and passed
- Auto-closed by system, no prior analyst review

---

## Investigation Summary

On 2026-05-21 at 19:30:38 UTC, user SOC-174 signed into Microsoft 365 from a confirmed Tor exit node (`92[.]118[.]63[.]112`) located in Bulgaria. Microsoft's `Ests_Tor` algorithm confirmed the anonymous IP. The activity log showed MFA was challenged and passed, followed by multiple successful logins. The incident was auto-closed without analyst review. No malicious post-login activity was identified, but Tor-based authentication to a corporate tenant is abnormal regardless of IP reputation.

**WHO:** `soc-174[@]mahcyberdefense[.]com`  
**WHAT:** Successful sign-in from a confirmed Tor exit node with MFA challenge passed  
**WHEN:** 2026-05-21 19:30:38 UTC — single-point event, activity ended same day  
**WHERE:** Microsoft 365 / Azure AD — cloud authentication layer  
**WHY:** Unknown — no business justification for Tor usage identified  
**HOW:** User or threat actor authenticated via Tor browser/VPN, bypassed location-based controls, passed MFA  

---

## Recommendations

1. Contact SOC-174 to confirm whether Tor usage was intentional — if not, treat as account compromise and reset credentials immediately.
2. Review and enforce Conditional Access policies to block sign-ins from known Tor exit nodes and anonymous proxies.
3. Investigate why the auto-closure suppressed analyst review for a Microsoft-flagged `truePositive` event.
