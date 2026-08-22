# Case 09 — RDP Login to KCD Workstation (Contractor — Benign)

**Severity:** Medium | **Verdict:** True Positive — Benign (Authorized Contractor)  
**Date:** 2026-07-06 | **Platform:** Splunk (Endpoint)

---

## Alert

**Title:** KCD - Identity - Potential RDP Login Detected  
**Description:** External RDP login detected (LogonType 10) to contractor workstation  
**MITRE Tactic:** InitialAccess  
**Detection Source:** Splunk scheduled search  

**Alert Details:**
```
ComputerName: DESKTOP-Q1HN49.kerningcitydental.ca
user:         KCD-Contractor
src_ip:       74.15.244.54
Logon_Type:   10
Logon_Process: User32
Event time:   2026-07-06T00:17:01Z
```

---

## Raw Alert

```json
{
  "search_name": "KCD - Identity - Potential RDP Login Detected",
  "severity": "medium",
  "result": {
    "src_ip": "74.15.244.54",
    "user": "KCD-Contractor",
    "Logon_Type": "10",
    "ComputerName": "DESKTOP-Q1HN49.kerningcitydental.ca",
    "Logon_Process": "User32"
  }
}
```

---

## Queries Used

**Historical logins from this IP:**
```
index=* host="DESKTOP-Q1HN49" src_ip="74.15.244.54"
| table _time, EventCode, user, Logon_Type, src_ip
| sort _time
```

**Post-login activity:**
```
index=* host="DESKTOP-Q1HN49" earliest="2026-07-06T00:15:00" latest="2026-07-06T02:00:00"
NOT Image="*svchost.exe"
(EventCode=1 OR EventCode=13 OR EventCode=10 OR EventCode=11 OR EventCode=4624 OR EventCode=4634)
| table _time, EventCode, user, Image, CommandLine, TargetObject
| sort _time
```

**tsclient check:**
```
index=* host="DESKTOP-Q1HN49" "tsclient" earliest="2026-07-06T00:00:00" latest="2026-07-06T03:00:00"
| table _time, EventCode, user, Image, CommandLine
| sort _time
```

---

## Findings

**IOCs:**
- Host: `DESKTOP-Q1HN49[.]kerningcitydental[.]ca`
- IP: `74[.]15[.]244[.]54` — Bell Canada Fixed Line DSL, Ottawa, Ontario (AS577) — AbuseIPDB: 0 reports, 0% confidence; VT: 0/91
- User: `KCD-Contractor`

**Historical login pattern from same IP:**
- 2026-07-02 17:56 UTC — successful RDP
- 2026-07-03 00:07 UTC — successful logon
- 2026-07-05 23:43 UTC — 2 failed attempts (lowercase username typo) then successful RDP
- 2026-07-06 00:17 UTC — successful RDP (this alert)

**Post-login activity:** 1,241 events reviewed — all normal Windows 11 session initialisation (Azure Guest Agent, winlogon, conhost, Microsoft Edge, Windows Widgets, Notepad). No suspicious processes, no registry persistence.  
**tsclient:** 0 results — no tools delivered via RDP drive share.  

---

## Investigation Summary

On 2026-07-06 at 00:17 UTC, `KCD-Contractor` connected via RDP to `DESKTOP-Q1HN49.kerningcitydental.ca` from a Bell Canada residential DSL IP in Ottawa, Ontario. The same IP has successfully authenticated to this host on three prior occasions across multiple days. Login times (00:17–17:56 UTC) are consistent with Canadian Eastern Time evening hours (~20:17–13:56 ET) — typical contractor remote work hours. Post-login activity showed only normal Windows 11 session behaviour. No tools were delivered via RDP drive share. Two failed attempts on July 5 (lowercase username) before success are consistent with a typing error. Assessed as authorised contractor remote access.

**WHO:** `KCD-Contractor` — recurring authorised user; IP: Bell Canada residential Ottawa  
**WHAT:** Routine contractor RDP session — normal Windows activity, no suspicious behaviour  
**WHEN:** 2026-07-06 00:17 UTC — session completed; recurring pattern since 2026-07-02, likely ongoing legitimate access  
**WHERE:** `DESKTOP-Q1HN49[.]kerningcitydental[.]ca` — contractor workstation; RDP internet-exposed  
**WHY:** Legitimate remote work by contractor from Ottawa home/office  
**HOW:** Direct RDP to internet-exposed port 3389 using valid contractor credentials  

---

## Recommendations

1. RDP on `DESKTOP-Q1HN49` remains internet-exposed — restrict access to known contractor IPs or require VPN.
2. Consider adding `74[.]15[.]244[.]54` to an approved IP allowlist to reduce alert noise from recurring legitimate access.
3. Enforce MFA for RDP sessions to mitigate risk if contractor credentials are ever compromised.
