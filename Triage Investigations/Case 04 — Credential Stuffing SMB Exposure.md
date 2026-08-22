# Case 04 — Credential Stuffing / SMB Exposure (MTS-ContractorPC1) — Repeat

**Incident:** 2121 | **Severity:** Low | **Verdict:** True Positive — Attack Unsuccessful  
**Date:** 2026-05-22 | **Platform:** Microsoft Sentinel / Azure (SecurityEvent)

---

## Alert

**Title:** Identity - Potential Credential Stuffing  
**Description:** Single source IP attempting logins against 5+ distinct accounts within a 10-minute window  
**MITRE Tactic:** CredentialAccess | **Technique:** T1110  
**Detection Source:** Azure Sentinel scheduled analytics rule  
**Activity Window:** 2026-05-22T07:50:00Z (single 10-minute window)  

---

## Raw Alert (Key Fields)

```json
{
  "Analytic Rule Name": "Identity - Potential Credential Stuffing",
  "Search Query Results Overall Count": "1",
  "IncidentId": "2121"
}
```

---

## Queries Used

**Reproduce detection:**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-05-22T07:40:00Z) .. datetime(2026-05-22T08:10:00Z))
| where EventID == "4625"
| summarize
    Accounts = make_set(TargetAccount),
    AttemptCount = count(),
    DistinctAccounts = dcount(TargetAccount)
    by Computer, IpAddress, bin(TimeGenerated, 10m)
| where DistinctAccounts >= 5
| order by AttemptCount desc
```

**Check for successful logins:**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-05-22T07:40:00Z) .. datetime(2026-05-22T08:10:00Z))
| where EventID == "4624"
| where Computer == "MTS-ContractorPC1"
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| order by TimeGenerated asc
```

---

## Findings

**IOCs:**
- Host: `MTS-ContractorPC1`
- IP: `124[.]156[.]231[.]67` (Japan, Tokyo — Tencent Cloud AS132203 — AbuseIPDB: 32% confidence, 11 reports; Defender entity reputation: Suspicious 74/100)
- Accounts targeted: `\WINSERVICES`, `\NICOSOFT`, `\ADMINXY`, `\GUEST`, `\HOSTS`, `\ADMINISTRATOR`, `\ADMIN` — generic wordlist
- Logon Type: 3 (SMB)
- SuccessCount: 0

---

## Investigation Summary

On 2026-05-22 at 07:50 UTC, IP `124[.]156[.]231[.]67` (Tencent Cloud, Tokyo) targeted `MTS-ContractorPC1` via SMB with 7 attempts against 7 generic wordlist accounts in a single 10-minute window. No successful authentication occurred. This is the second credential stuffing alert against this host within 24 hours (see Incident 2120). The root cause — SMB port 445 exposed to the internet — remains unremediated.

**WHO:** External threat actor using Tencent Cloud infrastructure; victim: `MTS-ContractorPC1`  
**WHAT:** Automated SMB credential stuffing using a generic wordlist  
**WHEN:** 2026-05-22 07:50 UTC — single 10-minute window, no ongoing compromise  
**WHERE:** `MTS-ContractorPC1` — SMB port 445 internet-exposed  
**WHY:** Opportunistic automated scanning — this is the second attack in 24 hours against the same exposed host  
**HOW:** Automated tool sent SMB authentication requests from a cloud-hosted scanning node  

---

## Recommendations

1. SMB port 445 on `MTS-ContractorPC1` remains exposed — this is an urgent unresolved misconfiguration generating repeated alerts.
2. Block `124[.]156[.]231[.]67` at the perimeter.
3. Prioritise closing port 445 from internet access — this host will continue to be targeted.
4. Consider implementing account lockout policies for repeated failed SMB authentication.
