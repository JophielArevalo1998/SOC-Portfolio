# Case 02 — ValleyRAT Multi-Stage Compromise (KCD-Web)

**Severity:** Medium → Escalated Critical | **Verdict:** True Positive — Active Intrusion  
**Date:** 2026-05-17 | **Platform:** Splunk (Sysmon / Endpoint)

---

## Alert

**Title:** KCD - Endpoint - Registry Modification  
**Description:** Suspicious registry modification — wmiprvse.exe writing a Run key pointing to a tsclient executable  
**MITRE Tactics:** InitialAccess, Persistence, CredentialAccess, Discovery  
**Detection Source:** Splunk scheduled search  

**Alert Details:**
```
ComputerName: KCD-Web.kerningcitydental.ca
User:         NT AUTHORITY\LOCAL SERVICE
Image:        C:\Windows\system32\wbem\wmiprvse.exe
TargetObject: HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftEdgeUpdate
Details:      "\\tsclient\SERVER\eeczbxfqse.exe"
```

---

## Raw Alert

```json
{
  "search_name": "KCD - Endpoint - Registry Modification",
  "severity": "medium",
  "result": {
    "User": "NT AUTHORITY\\LOCAL SERVICE",
    "Image": "C:\\Windows\\system32\\wbem\\wmiprvse.exe",
    "TargetObject": "HKU\\S-1-5-21-3772984715-3855048566-1297946058-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftEdgeUpdate",
    "Details": "\"\\\\tsclient\\SERVER\\eeczbxfqse.exe\"",
    "Computer": "KCD-Web.kerningcitydental.ca"
  }
}
```

---

## Queries Used

**Confirm execution of eeczbxfqse.exe (Sysmon EventID 1):**
```
index=* host="KCD-Web" Image="*eeczbxfqse.exe" EventCode=1
| table _time, User, Image, CommandLine, ParentImage, Hashes
| sort _time
```

**All tsclient activity on KCD-Web:**
```
index=* host="KCD-Web" "tsclient"
| table _time, EventCode, User, Image, CommandLine, ParentImage
| sort _time
```

**RDP login source IP:**
```
index=* host="KCD-Web" EventCode=4624 LogonType=10
| table _time, User, src_ip, WorkstationName, LogonType
| sort _time
```

**LSASS memory access (credential dumping):**
```
index=* host="KCD-Web" TargetImage="*lsass.exe"
| table _time, User, SourceImage, GrantedAccess, CallTrace
| sort _time
```

**Full host timeline May 17:**
```
index=* host="KCD-Web" earliest="2026-05-17T11:00:00" latest="2026-05-17T17:00:00"
NOT Image="*svchost.exe"
(EventCode=1 OR EventCode=4624 OR EventCode=13 OR EventCode=10 OR EventCode=11)
| table _time, EventCode, User, Image, CommandLine, TargetObject
| sort _time
```

---

## Findings

**IOCs:**
- Host: `KCD-Web[.]kerningcitydental[.]ca`
- IP (Attacker RDP): `155[.]117[.]189[.]111`
- File: `eeczbxfqse[.]exe` (ValleyRAT — renamed from `HardwareDiagnosticsTool.exe`)
- File: `\\tsclient\SERVER\rundll32[.]exe` (Mimikatz credential dumper)
- File: `Advanced_IP_Scanner_2[.]5[.]4594[.]1[.]exe`
- SHA256: `a9cc794cb09b1c328e0e88439068343f0c8edd7345f702f837580ec80cf0af8c`
- Run Key: `MicrosoftEdgeUpdate`
- Threat Family: ValleyRAT (xkcp/valley) — 48/65 VT detections

---

## Investigation Summary

On 2026-05-17 at 11:57 UTC, an attacker brute-forced RDP into `KCD-Web.kerningcitydental.ca` as the local `administrator` account from IP `155[.]117[.]189[.]111` (flagged for brute force on OSINT). They delivered tools via RDP drive redirection (`\\tsclient\SERVER\`) to avoid writing to local disk. At 15:52 UTC they executed ValleyRAT (`eeczbxfqse.exe`) which established a full remote access backdoor. Persistence was set via a WMI-written Run key disguised as `MicrosoftEdgeUpdate`. At 15:53 UTC, Advanced IP Scanner was run for network reconnaissance. At 16:15 UTC, a renamed Mimikatz (`rundll32.exe`) accessed `lsass.exe` with `GrantedAccess 0x1010`, dumping domain credentials. ValleyRAT made DNS queries consistent with C2 communication throughout. The attacker had at minimum 5 days of undetected access to a dental clinic web server containing patient health information (PHI).

**WHO:** External threat actor (Silver Fox APT — ValleyRAT campaign); victim: `KCD-Web.kerningcitydental.ca` local administrator  
**WHAT:** RDP brute force → ValleyRAT RAT deployment → persistence via Run key → network recon → credential dumping via lsass  
**WHEN:** 2026-05-17 11:57 UTC (initial access) through 2026-05-22+ (persistence active until remediation) — ongoing at time of detection  
**WHERE:** `KCD-Web.kerningcitydental.ca` — dental clinic internet-facing web server; RDP exposed publicly  
**WHY:** Targeted credential theft and persistent access to a healthcare environment; possible ransomware staging  
**HOW:** RDP brute force → admin credentials compromised → tools delivered via RDP drive share → WMI used for persistence and evasion → lsass dumped for lateral movement credentials  

---

## Recommendations

1. Isolate `KCD-Web.kerningcitydental.ca` immediately and preserve a forensic image before remediation.
2. Disable or reset the local administrator account and revoke all active sessions.
3. Restrict RDP access to known IPs only or require VPN before RDP.
4. Block attacker IP `155[.]117[.]189[.]111` and all ValleyRAT C2 IPs at the firewall.
5. Scan the entire environment for the SHA256 hash and tsclient-originated processes.
6. Assess PIPEDA breach notification obligations given PHI exposure on a dental clinic server.
7. Audit all domain accounts — credentials from lsass should be considered compromised.
