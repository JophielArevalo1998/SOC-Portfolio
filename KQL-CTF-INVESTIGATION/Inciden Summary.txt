# 📄 Incident Summary — Apex Talent Partners

**Date:** January 15, 2026  
**Severity:** Critical  
**Status:** Contained (post-investigation)  
**Analyst:** Jophiel Arevalo Enriquez

---

## Executive Summary

On January 15, 2026, a threat actor gained initial access to Apex Talent Partners' network via a spear-phishing email containing a malicious executable disguised as a recruitment CV. The attacker progressed from a standard workstation to the file server in a single day, deployed persistent access mechanisms, and staged all client contract and pricing data for exfiltration. Eight client folders were accessed. Evidence log clearing was performed at the end of the operation.

---

## Affected Systems

| System | Role | Compromise Level |
|--------|------|-----------------|
| `as-pc1` | Workstation (Patient Zero) | Full compromise — dropper executed, RMM deployed, backdoor account |
| `as-pc2` | Workstation | Lateral movement stepping stone — credentials brute-forced |
| `as-srv` | File Server | Full compromise — dropper deployed, persistence, data staged |

---

## Compromised Accounts

| Account | Action Required |
|---------|----------------|
| `a.stewart` | Disable, reset password, audit all access |
| `j.harris` | Disable, reset password — brute-forced |
| `svc_backup` | Disable, reset password — used to access file server |
| `helpdesk` | **Delete** — attacker-created backdoor account |

---

## Key IOCs

### Files
| IOC | Value |
|-----|-------|
| Original dropper | `Daniel_Richardson_CV.pdf.exe` |
| Dropper SHA256 | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` |
| Masqueraded dropper | `C:\ProgramData\Microsoft\RuntimeBroker.exe` |
| RMM tool | `C:\ProgramData\AnyDesk\AnyDesk.exe` |
| Staging archive | `C:\Shares\Clients\Shares.7z` |

### Network
| IOC | Value |
|-----|-------|
| Staging domain | `filestorage-cdn.net` |

### Persistence
| IOC | Value |
|-----|-------|
| Scheduled task | `WindowsUpdateService` (runs daily 03:00, as SYSTEM) |
| Backdoor account | `helpdesk` (local Administrators member) |
| RMM password | `Sup3rS3cur3RMM!` |

---

## Data at Risk

**Location:** `C:\Shares\Clients\` on `as-srv`  
**Files accessed:** `Contract.pdf` and `Pricing.xlsx` from **8 client folders**  
**Archive created:** `Shares.7z` — positioned at `C:\Shares\Clients\Shares.7z`  
**Exfiltration confirmed:** Staging confirmed. External transfer not verified — requires proxy/firewall egress log review.

---

## Immediate Containment Actions

1. **Isolate** `as-pc1`, `as-pc2`, and `as-srv` from the network
2. **Disable** accounts: `a.stewart`, `j.harris`, `svc_backup`
3. **Delete** backdoor account: `helpdesk`
4. **Block** domain `filestorage-cdn.net` at DNS and proxy
5. **Remove** scheduled task `WindowsUpdateService` from `as-srv`
6. **Remove** `C:\ProgramData\Microsoft\RuntimeBroker.exe` from `as-srv`
7. **Remove** `C:\ProgramData\AnyDesk\AnyDesk.exe` from `as-pc1`
8. **Preserve** `C:\Shares\Clients\Shares.7z` as evidence before removal
9. **Block** SHA256 `48b97fd91...` in EDR across all endpoints

---

## MITRE ATT&CK Summary

| Phase | Technique | ID |
|-------|-----------|-----|
| Initial Access | Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Discovery | Local Groups Discovery | T1069.001 |
| C2 | Remote Access Software (AnyDesk) | T1219 |
| Persistence | Create Local Account | T1136.001 |
| Persistence | Scheduled Task | T1053.005 |
| Lateral Movement | Remote Desktop Protocol | T1021.001 |
| Defence Evasion | Masquerading | T1036.005 |
| Defence Evasion | Clear Windows Event Logs | T1070.001 |
| Collection | Archive via Utility (7-Zip) | T1560.001 |
