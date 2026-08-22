# Case 07 — RDP Login to KCD-Web (Benign)

**Severity:** Medium | **Verdict:** True Positive — Benign  
**Date:** 2026-05-27 | **Platform:** Splunk (Endpoint)

---

## Alert

**Title:** KCD - Identity - Potential RDP Login Detected  
**Description:** External RDP login detected (LogonType 10) to KCD-Web server  
**MITRE Tactic:** InitialAccess  
**Detection Source:** Splunk scheduled search  

**Alert Details:**
```
ComputerName: KCD-Web.kerningcitydental.ca
user:         administrator
src_ip:       199.119.235.155
Logon_Type:   10
Logon_Process: User32
Event time:   2026-05-27T15:47:01Z
```

---

## Raw Alert

```json
{
  "search_name": "KCD - Identity - Potential RDP Login Detected",
  "severity": "medium",
  "result": {
    "src_ip": "199.119.235.155",
    "user": "administrator",
    "Logon_Type": "10",
    "ComputerName": "KCD-Web.kerningcitydental.ca",
    "Logon_Process": "User32"
  }
}
```

---

## Queries Used

**All events from this IP on KCD-Web:**
```
index=* host="KCD-Web" src_ip="199.119.235.155"
| table _time, EventCode, user, Logon_Type, src_ip
| sort _time
```

**Post-login activity:**
```
index=* host="KCD-Web" earliest="2026-05-27T15:46:00" latest="2026-05-27T16:30:00"
NOT Image="*svchost.exe"
(EventCode=1 OR EventCode=13 OR EventCode=10 OR EventCode=11)
| table _time, EventCode, user, Image, CommandLine, TargetObject
| sort _time
```

**tsclient activity check:**
```
index=* host="KCD-Web" "tsclient" earliest="2026-05-27T15:00:00" latest="2026-05-27T17:00:00"
| table _time, EventCode, user, Image, CommandLine
| sort _time
```

---

## Findings

**IOCs:**
- Host: `KCD-Web[.]kerningcitydental[.]ca`
- IP: `199[.]119[.]235[.]155` — Freedom Mobile Inc., Vancouver BC, Canada (Mobile ISP, AS20365) — AbuseIPDB: 4 reports, 0% confidence; VT: 0/91
- User: `administrator`
- Session duration: 28 seconds (15:47:01 – 15:47:18 UTC, EventCode 4779 = disconnected)
- Post-login activity: Normal Windows session initialisation only (csrss, spoolsv, services.exe)
- tsclient: 0 results

---

## Investigation Summary

On 2026-05-27 at 15:47 UTC, the local administrator account on `KCD-Web.kerningcitydental.ca` authenticated via RDP from a Freedom Mobile cellular IP in Vancouver, Canada. The session lasted 28 seconds before disconnecting. Post-login activity showed only normal Windows session initialisation — no suspicious processes, no registry modifications, no tsclient file delivery. The short duration and clean activity suggest a connection test or brief reconnection. IP reputation was clean across all OSINT sources. Assessed as a true positive detection of a benign event, though the exposure of RDP to the internet on this server remains a risk.

**WHO:** Unknown — administrator account; IP consistent with a Canadian mobile/VPN user  
**WHAT:** 28-second RDP session with no observable post-login activity  
**WHEN:** 2026-05-27 15:47:01–15:47:18 UTC — session ended, not ongoing  
**WHERE:** `KCD-Web[.]kerningcitydental[.]ca` — dental clinic web server; RDP port internet-exposed  
**WHY:** Unknown — possibly a connection test or legitimate brief access  
**HOW:** Direct RDP to internet-exposed port 3389 using administrator credentials  

---

## Recommendations

1. Restrict RDP access on `KCD-Web` to known IPs or require VPN — port 3389 should not be internet-facing.
2. Rename or disable the local administrator account for RDP access.
3. Monitor for follow-up activity from `199[.]119[.]235[.]155`.
