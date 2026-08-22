

Case 03 credential stuffing mts 2120 · MD
# Case 03 — Credential Stuffing / SMB Exposure (MTS-ContractorPC1)
 
**Incident:** 2120 | **Severity:** Low | **Verdict:** True Positive — Attack Unsuccessful  
**Date:** 2026-05-21 | **Platform:** Microsoft Sentinel / Azure (SecurityEvent)
 
---
 
## Alert
 
**Title:** Identity - Potential Credential Stuffing  
**Description:** Single source IP attempting logins against 5+ distinct accounts within a 10-minute window  
**MITRE Tactic:** CredentialAccess | **Technique:** T1110  
**Detection Source:** Azure Sentinel scheduled analytics rule  
**Activity Window:** 2026-05-21T19:50:00Z – 2026-05-21T20:10:00Z  
 
---
 
## Raw Alert (Key Fields)
 
```json
{
  "Analytic Rule Name": "Identity - Potential Credential Stuffing",
  "Query": "SecurityEvent | where EventID == '4625' | summarize Accounts = make_set(TargetAccount) by Computer, IpAddress, bin(TimeGenerated, 10m) | extend DistinctAccounts_Count = array_length(Accounts) | where DistinctAccounts_Count >= 5",
  "Search Query Results Overall Count": "3",
  "IncidentId": "2120"
}
```
 
---
 
## Queries Used
 
**Reproduce detection — find triggering IP and accounts:**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-05-21T19:50:00Z) .. datetime(2026-05-21T20:15:00Z))
| where EventID == "4625"
| summarize
    Accounts = make_set(TargetAccount),
    AttemptCount = count(),
    DistinctAccounts = dcount(TargetAccount)
    by Computer, IpAddress, bin(TimeGenerated, 10m)
| where DistinctAccounts >= 5
| order by AttemptCount desc
```
 
**Check for successful logins from attacking IPs:**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-05-21T19:45:00Z) .. datetime(2026-05-21T20:30:00Z))
| where EventID == "4624"
| where IpAddress in ("98.101.161.166", "62.164.177.28")
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| order by TimeGenerated asc
```
 
**Identify all attacking IPs and logon types:**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-05-21T19:50:00Z) .. datetime(2026-05-21T20:15:00Z))
| where EventID == "4625"
| summarize count() by LogonType, IpAddress, Computer
| order by count_ desc
```
 
---
 
## Findings
 
**IOCs:**
- Host: `MTS-ContractorPC1`
- IP: `98[.]101[.]161[.]166` (US, Charter Communications — Suspicious per GreyNoise/SOCRadar)
- IP: `62[.]164[.]177[.]28` (NL, Data Campus Limited — Phishing/Suspicious per SOCRadar) — 904 failed attempts
- Logon Type: 3 (SMB/Network) — SMB port 445 internet-exposed
- Accounts targeted: 73+ distinct accounts including `\ADMINGDL`, `\ALAN.PEREIRA-ADMIN`, `\ADMINISTRADOR`
- SuccessCount: 0 for both IPs
---
 
## Investigation Summary
 
On 2026-05-21 between 19:50–20:10 UTC, two external IPs targeted `MTS-ContractorPC1` via SMB (LogonType 3), attempting authentication against 73+ distinct accounts using what appeared to be a leaked credential list (Portuguese/Spanish account names consistent with a specific organisation). IP `62[.]164[.]177[.]28` made 904 attempts, `98[.]101[.]161[.]166` made 89 attempts. Neither IP achieved a successful login. The root cause is SMB port 445 being exposed to the internet on this host — a critical misconfiguration that will continue generating similar alerts until resolved.
 
**WHO:** Two external threat actors; victim host: `MTS-ContractorPC1`  
**WHAT:** Distributed credential stuffing via SMB using a leaked credential list  
**WHEN:** 2026-05-21 19:50–20:10 UTC — contained within the window, no ongoing compromise  
**WHERE:** `MTS-ContractorPC1` — contractor PC with SMB port 445 publicly accessible  
**WHY:** Opportunistic credential stuffing against an exposed SMB service  
**HOW:** External IPs sent authentication requests directly to SMB port 445 using lists of username/password pairs  
 
---
 
## Recommendations
 
1. Immediately close SMB port 445 from internet access on `MTS-ContractorPC1` — this is the root cause.
2. Block `98[.]101[.]161[.]166` and `62[.]164[.]177[.]28` at the perimeter firewall.
3. Audit all contractor PCs for similar internet-facing service exposure.
4. Implement network segmentation to prevent direct internet access to workstation SMB ports.
 
