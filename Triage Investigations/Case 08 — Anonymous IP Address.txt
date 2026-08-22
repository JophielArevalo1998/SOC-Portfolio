# Case 08 — Anonymous IP Address (SOC-186) — Log Retention Expired

**Incident:** 2199 | **Severity:** Medium | **Verdict:** True Positive — Limited Evidence  
**Date:** 2026-06-02 | **Platform:** Microsoft XDR / Azure AD Identity Protection

---

## Alert

**Title:** Anonymous IP address involving one user  
**Description:** Sign-in from an anonymous IP address (e.g. Tor browser, anonymizer VPNs)  
**MITRE Tactic:** InitialAccess  
**Detection Source:** Azure Active Directory Identity Protection  
**Activity:** 2026-06-02T22:03:51Z  
**Status:** Closed (auto-resolved by suppression rule — no analyst review)

---

## Raw Alert (Key Fields)

```json
{
  "User Name": "SOC-186",
  "User Account": "soc-186@mahcyberdefense.com",
  "Client IP Address": "217.216.105.108",
  "Client Location": "Ashburn, Virginia, US",
  "PartnerAlgorithm": "Ests_Tor",
  "Classification": "truePositive",
  "AssignedTo": "Suppression Rule",
  "State": "Closed"
}
```

---

## Queries Used

**SigninLogs — activity for SOC-186:**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-02T21:50:00Z) .. datetime(2026-06-02T23:00:00Z))
| where UserPrincipalName has "soc-186"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName, RiskLevelDuringSignIn
| order by TimeGenerated asc
```

**AADSignInEventsBeta — alternative table:**
```kql
AADSignInEventsBeta
| where Timestamp between (datetime(2026-06-02T21:50:00Z) .. datetime(2026-06-02T23:00:00Z))
| where AccountUpn has "soc-186"
| project Timestamp, AccountUpn, IPAddress, ErrorCode, City, Country, Application
| order by Timestamp asc
```

**AuditLogs — post-login account changes:**
```kql
AuditLogs
| where TimeGenerated between (datetime(2026-06-02T22:00:00Z) .. datetime(2026-06-02T23:59:00Z))
| where InitiatedBy has "soc-186" or TargetResources has "soc-186"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated asc
```

---

## Findings

**IOCs:**
- IP: `217[.]216[.]105[.]108`
- User: `soc-186[@]mahcyberdefense[.]com`
- Location: Ashburn, Virginia, US
- Detection: `Ests_Tor` — confirmed Tor exit node
- ISP: PacketHub S.A. (AS147049) — Data Center/Web Hosting/Transit
- AbuseIPDB: 1 report, 0% confidence — previously categorised as Bad Web Bot and Exploited Host (2 months prior)
- VT: 0/91 detections

**Query results:** All queries returned 0 results — alert is 35 days old, exceeding the ~30-day log retention window. Investigation relied solely on raw alert JSON data.

**Note:** Alert was handled by a suppression rule (`AssignedTo: Suppression Rule`) and closed without any analyst review.

---

## Investigation Summary

On 2026-06-02 at 22:03 UTC, `soc-186[@]mahcyberdefense[.]com` signed in from a confirmed Tor exit node (`217[.]216[.]105[.]108`) hosted on PacketHub S.A. infrastructure in Ashburn, Virginia. Microsoft internally classified this as `truePositive` using the `Ests_Tor` detection algorithm. The alert was automatically suppressed and closed without analyst review. At the time of investigation (35 days later), all sign-in and audit log data had aged out of the retention window — no further evidence could be gathered. The verdict relies entirely on the Identity Protection detection preserved in the raw alert JSON.

**WHO:** `soc-186[@]mahcyberdefense[.]com`  
**WHAT:** Sign-in from a confirmed Tor exit node to Microsoft 365  
**WHEN:** 2026-06-02 22:03:51 UTC — single event; activity status at time of login unknown  
**WHERE:** Azure AD / Microsoft 365 cloud authentication layer  
**WHY:** Unknown — no business justification for Tor-based access identified  
**HOW:** Authentication via Tor network, suppression rule prevented timely analyst review  

---

## Recommendations

1. Review the suppression rule that auto-dismissed this alert — it is preventing analyst review of Microsoft-confirmed true positives.
2. Implement a policy requiring analyst sign-off before closing Identity Protection alerts classified as `truePositive`.
3. Consider reducing alert backlog response time — alerts older than 30 days cannot be fully investigated due to log retention limits.
4. Contact SOC-186 to determine whether Tor usage was intentional.
