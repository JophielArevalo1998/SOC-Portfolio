# CTF — KQL Threat Hunting Investigation
### Apex Talent Partners — Incident Response Exercise

> A hands-on **KQL (Kusto Query Language)** threat hunting CTF using Microsoft Defender for Endpoint Advanced Hunting tables. A full attack chain is reconstructed — from initial access through lateral movement, persistence, data staging, and log clearing — by writing targeted KQL queries against real endpoint telemetry.

> **Platform:** Microsoft Sentinel / Defender for Endpoint Advanced Hunting  
> **Query language:** KQL (Kusto Query Language)  
> **Date range investigated:** January 15, 2026 00:00 – 23:59 UTC  
> **Tables used:** `DeviceProcessEvents_CL`, `DeviceFileEvents_CL`, `DeviceNetworkEvents_CL`, `DeviceLogonEvents_CL`, `DeviceRegistryEvents_CL`, `DeviceEvents_CL`

---

## 📋 Table of Contents

1. [The Case](#-the-case)
2. [Environment & Tables](#-environment--tables)
3. [Attack Chain Overview](#-attack-chain-overview)
4. [Investigation — All 27 Questions](#-investigation--all-27-questions)
   - [Phase 1 — Initial Access](#phase-1--initial-access)
   - [Phase 2 — Discovery & Execution](#phase-2--discovery--execution)
   - [Phase 3 — Persistence & RMM Deployment](#phase-3--persistence--rmm-deployment)
   - [Phase 4 — Lateral Movement](#phase-4--lateral-movement)
   - [Phase 5 — File Server Compromise](#phase-5--file-server-compromise)
   - [Phase 6 — Collection & Exfiltration Staging](#phase-6--collection--exfiltration-staging)
   - [Phase 7 — Defence Evasion](#phase-7--defence-evasion)
5. [Final Report — The Four Questions](#-final-report--the-four-questions)
6. [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
7. [Screenshots Index](#-screenshots-index)
8. [KQL Query Reference](#-kql-query-reference)
9. [Key IOCs](#-key-iocs)

---

## 🏢 The Case

**Apex Talent Partners** is a small recruitment firm based in Birmingham. Their business revolves around placing senior executives at major organisations. Their most valuable assets are **client contracts and pricing information** stored on a critical file server.

The SOC received an alert about suspicious activity on three endpoints. Your job is to answer the questions every SOC analyst eventually faces:

> 🔍 **Who gained access?**  
> 🔍 **How did they get in?**  
> 🔍 **What systems and data did they interact with?**  
> 🔍 **Was any sensitive information taken?**

**Devices in scope:**

| Hostname | Role |
|----------|------|
| `as-pc1` | Workstation — Patient Zero |
| `as-pc2` | Workstation — Lateral movement target |
| `as-srv` | File server — Final target |

---

## 🗄️ Environment & Tables

All queries run against **custom Defender for Endpoint Advanced Hunting tables** (note the `_CL` suffix indicating custom log tables in Sentinel).

**Timestamp note:** Always use `Timestamp` — not `TimeGenerated` — in these tables.

```kql
// Standard time filter used in every query — apply this as the base for all hunts
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
```

| Table | Contains |
|-------|----------|
| `DeviceProcessEvents_CL` | Process creation events — every process started on any device |
| `DeviceFileEvents_CL` | File create, modify, delete, rename events |
| `DeviceNetworkEvents_CL` | Outbound and inbound network connections |
| `DeviceLogonEvents_CL` | Interactive and remote logon events |
| `DeviceRegistryEvents_CL` | Registry key and value changes |
| `DeviceEvents_CL` | Broad endpoint events not covered by the above |

---

## 🔗 Attack Chain Overview

```
[as-pc1] — Patient Zero
    │
    ├─ 1. User downloads Daniel_Richardson_CV.pdf.exe (double extension)
    ├─ 2. Dropper executes → spawns cmd.exe for discovery
    ├─ 3. net.exe enumerates local groups (localgroup administrators)
    ├─ 4. certutil.exe downloads RMM tool (AnyDesk/similar) to C:\ProgramData\
    ├─ 5. RMM configured with --set-password for unattended access
    ├─ 6. Backdoor account created and added to Administrators
    │
    ▼ Lateral Movement (credential brute force → RDP)
    │
[as-pc2] — Second Workstation
    ├─ 7. Same dropper re-downloaded from attacker domain via certutil.exe
    │
    ▼ Lateral Movement (privileged account → RDP)
    │
[as-srv] — File Server
    ├─ 8. Dropper deployed as RuntimeBroker.exe (masquerading)
    ├─ 9. Scheduled task created for persistence (daily execution)
    ├─ 10. 7zg.exe archives C:\Shares\Clients\ → Shares.7z
    ├─ 11. Archive relocated inside C:\Shares\Clients\
    └─ 12. wevtutil.exe clears Windows event logs
```

---

## 🔍 Investigation — All 27 Questions

---

### Phase 1 — Initial Access

---

#### Q1 — What is the full filename of the suspicious executable in the user's Downloads folder?

**Why this matters:** Double extensions (`.pdf.exe`) are a classic social engineering trick. The victim sees what looks like a PDF but Windows executes it as a binary. Searching Downloads folders for double extensions is a high-value first hunt.

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FolderPath contains "downloads"
| project FileName, AccountName
```

**Answer:** `Daniel_Richardson_CV.pdf.exe`

> The filename mimics a job applicant's CV — perfectly targeted for a recruitment firm. The double extension `.pdf.exe` relies on Windows hiding the final extension by default, making it appear as `Daniel_Richardson_CV.pdf` to the victim.

📸 *See:* [`screenshots/README.md#01`](screenshots/README.md#01---double-extension-dropper)

---

#### Q2 — Which hostname is patient zero?

**Why this matters:** Patient zero defines the boundary of your investigation and the starting point of your timeline. Every downstream pivot, every other compromised host, traces back to this single device.

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath
| order by Timestamp asc
```

**Answer:** `as-pc1`

> The first execution of the dropper occurred on `as-pc1`. Ordering by `Timestamp asc` and reading the first result gives you patient zero immediately.

📸 *See:* [`screenshots/README.md#02`](screenshots/README.md#02---patient-zero-hostname)

---

#### Q3 — What user account ran the malicious file?

**Why this matters:** The compromised user is your first containment action — disable the account, reset the password, and audit what data and systems they had access to.

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath
| order by Timestamp asc
```

**Answer:** `Sophie.Turner`

> The `InitiatingProcessAccountName` field identifies who executed the dropper. This is the account that clicked the fake CV.

📸 *See:* [`screenshots/README.md#03`](screenshots/README.md#03---compromised-user-account)

---

#### Q4 — What is the SHA256 of the dropper?

**Why this matters:** SHA256 hashes survive renaming, repackaging, and folder moves. This single value becomes the anchor IOC for all subsequent hunting queries across the estate, and for threat intel lookups.

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, SHA256
| order by Timestamp
```

**Answer:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

> Once you have this hash, you can hunt every table and every device for any file with this SHA256 — regardless of what it was named. This is how we later find the same dropper renamed as `RuntimeBroker.exe` on the file server.

📸 *See:* [`screenshots/README.md#04`](screenshots/README.md#04---dropper-sha256)

---

### Phase 2 — Discovery & Execution

---

#### Q5 — What Windows binary was used for the initial enumeration commands?

**Why this matters:** Attackers use built-in Windows binaries (LOLBins — Living Off the Land Binaries) because they are signed by Microsoft, trusted by EDR, and already present on every Windows machine. Using `cmd.exe` leaves fewer artefacts than dropping a custom tool.

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where InitiatingProcessFileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp asc
```

**Answer:** `net.exe`

> The dropper immediately spawned `cmd.exe` as a child process to run discovery commands. Seeing `net.exe` as a direct child of a file from the Downloads folder is a high-confidence malicious indicator.

📸 *See:* [`screenshots/README.md#05`](screenshots/README.md#05---cmd-child-process)

---

#### Q6 — What was the full command line used to enumerate the local administrators group?

**Why this matters:** Querying the local Administrators group is a privilege discovery step. An attacker does this to understand whether the compromised account already has admin rights, or whether they need to escalate. Detecting this command in user context within seconds of a suspicious download is textbook discovery behaviour.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName == "net.exe"
| where ProcessCommandLine has "localgroup"
| project Timestamp, DeviceName, ProcessCommandLine
```

**Answer:** `net localgroup administrators`

> `net.exe` is one of the most commonly abused LOLBins for local enumeration. The `localgroup administrators` argument dumps all members of the local Administrators group — telling the attacker exactly who has elevated rights on this machine.

📸 *See:* [`screenshots/README.md#06`](screenshots/README.md#06---localgroup-enumeration)

---

### Phase 3 — Persistence & RMM Deployment

---

#### Q7 — What Microsoft-signed binary did the attacker abuse to download their tool?

**Why this matters:** This is a classic LOLBin abuse pattern. Microsoft-signed binaries are trusted by default and rarely blocked. Using them for downloads bypasses application whitelisting and most EDR download detections.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("http", "https", "download")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Answer:** `certutil.exe`

> `certutil.exe` is a certificate management utility built into Windows. Attackers abuse its `-urlcache -split -f` flags to download arbitrary files from the internet. Because it is a legitimate, Microsoft-signed binary, it bypasses many proxy and EDR rules that would block `curl.exe` or `powershell.exe` download cradles.

📸 *See:* [`screenshots/README.md#07`](screenshots/README.md#07---certutil-download)

---

#### Q8 — What is the full path of the remote access tool dropped to disk?

**Why this matters:** Legitimate RMM (Remote Monitoring and Management) tools are abused constantly because they are code-signed and bypass most EDR signatures. Dropping them into world-writable paths like `C:\ProgramData\` avoids the need for administrator privileges during the drop phase.

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-pc1"
| where ActionType =~ "FileCreated"
| where FolderPath has_any ("Public", "ProgramData", "Temp")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**Answer:** `C:\Users\Public\AnyDesk.exe`

> AnyDesk is a legitimate commercial remote access tool. Attackers favour it because it is signed, widely known to security products as legitimate, and provides full graphical desktop access. Dropping it in `C:\ProgramData\` requires no elevation and is writable by standard users.

📸 *See:* [`screenshots/README.md#08`](screenshots/README.md#08---rmm-tool-path)

---

#### Q9 — What password was set on the RMM tool?

**Why this matters:** Setting an unattended-access password on AnyDesk means the attacker can return at any time with no user interaction required — even if the original victim session is closed. This is a persistence mechanism in its own right.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where ProcessCommandLine has "--set-password"
| project Timestamp, DeviceName, ProcessCommandLine
```

**Answer:** `intrud3r!`

> The `--set-password` flag sets AnyDesk's unattended access password directly from the command line. The password appears in plaintext in the process command line — which is why command line logging and SIEM ingestion is essential. Without this telemetry, this persistence mechanism would be completely invisible.

📸 *See:* [`screenshots/README.md#09`](screenshots/README.md#09---rmm-password)

---

#### Q10 — What is the username of the backdoor account created on patient zero?

**Why this matters:** Backdoor accounts are one of the most common long-term persistence mechanisms. They survive RMM removal, password resets on the original compromised account, and even reimaging if they are propagated to other systems.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where ProcessCommandLine has "user"
| where ProcessCommandLine has "/add"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

**Answer:** `svc_backup`

> The account name `svc_backup` is deliberately chosen to blend in — every organisation has backup accounts. Reviewing your user directory for recently created accounts with generic, plausible names is a key post-incident step.

📸 *See:* [`screenshots/README.md#10`](screenshots/README.md#10---backdoor-account)

---

#### Q11 — What local group was the backdoor account added to?

**Why this matters:** A backdoor account alone provides limited access. Adding it to a privileged local group gives the attacker the same rights as a local admin — including the ability to execute code, access all local files, and pivot to other systems.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where ProcessCommandLine has "localgroup"
| where ProcessCommandLine has "/add"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

**Answer:** `Administrators`

> Adding `svc_backup` to the local `Administrators` group gives the attacker full local admin rights on `as-pc1`. Combined with the RMM tool, this is a fully functional persistent foothold that survives reboots and user logoffs.

📸 *See:* [`screenshots/README.md#11`](screenshots/README.md#11---backdoor-group-add)

---

### Phase 4 — Lateral Movement

---

#### Q12 — What is the destination hostname of the brute force attempts?

**Why this matters:** Identifying the lateral movement target lets you scope your investigation to a second device and immediately check whether those brute force attempts succeeded.

```kql
// Query 1 — Check logon attempts originating FROM as-pc1
DeviceLogonEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-pc1"
| where ActionType == "LogonAttempted"
| project Timestamp, AccountName, RemoteDeviceName, RemoteIP, DeviceName
| order by Timestamp asc

// Query 2 — Reverse lookup: find which device owns the destination IP
DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where LocalIP == "10.1.0.183"
| project DeviceName, LocalIP
| distinct DeviceName, LocalIP
```

**Answer:** `as-pc2`

> The two-query approach is important: the first query shows the brute force attempts from `as-pc1`'s perspective. The second confirms the hostname of the destination IP. Using both eliminates ambiguity from DNS resolution timing or IP reuse.

📸 *See:* [`screenshots/README.md#12`](screenshots/README.md#12---lateral-movement-target)

---

#### Q13 — What account name was successfully used to login to as-pc2?

**Why this matters:** This is your second containment action. The account that was brute-forced is now compromised — disable it, reset it, and audit everywhere it has been used. How the attacker knew or cracked this credential shapes your post-incident hardening.

```kql
DeviceLogonEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where RemoteDeviceName == "as-pc2" or DeviceName == "as-pc2"
| project Timestamp, AccountName, ActionType, LogonType, DeviceName, RemoteDeviceName
| order by Timestamp asc
```

**Answer:** `david.mitchell`

> Filtering for both `RemoteDeviceName == "as-pc2"` and `DeviceName == "as-pc2"` captures the logon from both perspectives — the source device logs an outbound attempt, and the destination device logs the inbound success. Looking for `ActionType == "LogonSuccess"` isolates the winning credential.

📸 *See:* [`screenshots/README.md#13`](screenshots/README.md#13---successful-lateral-logon)

---

#### Q14 — What LogonType indicates the attacker established an interactive desktop session?

**Why this matters:** LogonType 10 (RemoteInteractive) means RDP — a full graphical desktop session. This is one of the clearest hands-on-keyboard lateral movement signals available. A network logon (type 3) could be a file share access; a RemoteInteractive logon is unambiguously a person at a keyboard.

```kql
DeviceLogonEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where RemoteDeviceName == "as-pc2" or DeviceName == "as-pc2"
| project Timestamp, AccountName, ActionType, LogonType, DeviceName, RemoteDeviceName
| order by Timestamp asc
```

**Answer:** `RemoteInteractive` (LogonType 10)

> **LogonType reference:**
> - `2` = Interactive (local keyboard)
> - `3` = Network (file share, net use)
> - `10` = RemoteInteractive = **RDP** ← this is the attacker's session
> - `7` = Unlock

📸 *See:* [`screenshots/README.md#14`](screenshots/README.md#14---rdp-logon-type)

---

#### Q15 — What domain hosted the dropper that was downloaded?

**Why this matters:** Attacker-controlled staging domains are high-value IOCs. Add the domain to your DNS sinkhole or proxy block list immediately, then sweep DNS logs across the entire estate for any other host that resolved it. Any host that resolved this domain should be investigated.

```kql
DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName in ("certutil.exe", "powershell.exe", "bitsadmin.exe", "curl.exe")
| project Timestamp, InitiatingProcessFileName, RemoteUrl
| order by Timestamp asc
```

**Answer:** `sync.cloud-endpoint.net`

> The attacker did not copy the dropper from `as-pc1` to `as-pc2` over the network (which would leave SMB lateral movement artefacts). Instead, they re-downloaded it from their staging domain using `certutil.exe` — the same LOLBin abuse used on patient zero. This means the staging domain is active infrastructure that should be blocked immediately.

📸 *See:* [`screenshots/README.md#15`](screenshots/README.md#15---staging-domain)

---

#### Q16 — What account name eventually succeeded via RDP to the file server?

**Why this matters:** This account touched the file server — the crown jewel. Everything this account could access is now in scope for the post-incident review. Lock it down during containment.

```kql
DeviceLogonEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, RemoteDeviceName, AccountName, ActionType, LogonType
| order by Timestamp asc
```

**Answer:** `as.srv.administrator`

> The attacker escalated from a standard user (`david.mitchell`) to `as.srv.administrator` to reach the file server. Service accounts commonly have broad file system access and are rarely monitored for interactive RDP logons — making them ideal lateral movement targets.

📸 *See:* [`screenshots/README.md#16`](screenshots/README.md#16---file-server-rdp-logon)

---

### Phase 5 — File Server Compromise

---

#### Q17 — What filename was the dropper saved as on the file server?

**Why this matters:** Masquerading as a Microsoft-signed binary is one of the most common evasion techniques. Detection logic should compare file path against expected Windows binary paths, not trust the filename alone. A `RuntimeBroker.exe` outside of `C:\Windows\System32\` is definitively malicious.

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where SHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| project Timestamp, DeviceName, FileName, FolderPath
| order by Timestamp asc
```

**Answer:** `RuntimeBroker.exe`

> This is why SHA256 hash hunting matters — the attacker renamed the dropper to match a legitimate Windows process, but the hash never lies. `RuntimeBroker.exe` is a real Windows process, but it lives in `C:\Windows\System32\` — not wherever this copy was dropped.

📸 *See:* [`screenshots/README.md#17`](screenshots/README.md#17---masquerading-filename)

---

#### Q18 — What is the full file path of the masquerading binary?

**Why this matters:** Any file named `RuntimeBroker.exe` outside of its expected system path is suspicious by definition — this is a near-zero false-positive detection rule. Add it to your detection library.

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName == "RuntimeBroker.exe"
| project Timestamp, DeviceName, FolderPath, FileName
```

**Answer:** `C:\Users\Public\RuntimeBroker.exe`

> The path `C:\Users\Public\RuntimeBroker.exe` is designed to look legitimate. The real `RuntimeBroker.exe` lives in `C:\Windows\System32\`. Any EDR rule that fires on `RuntimeBroker.exe` outside of `C:\Windows\` would have caught this immediately.

📸 *See:* [`screenshots/README.md#18`](screenshots/README.md#18---masquerading-full-path)

---

#### Q19 — What is the name of the scheduled task that was created?

**Why this matters:** Scheduled tasks are one of the most common persistence mechanisms because they survive reboots, run with configurable privileges, and are often overlooked in baseline audits. Reviewing scheduled tasks against an approved baseline is a key post-incident step.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has "schtasks"
| project Timestamp, DeviceName, ProcessCommandLine
```

**Answer:** `MicrosoftEdgeUpdateCheck`

> The task name `MicrosoftEdgeUpdateCheck` is deliberately chosen to blend into the list of legitimate scheduled tasks. An analyst reviewing tasks casually would likely skip it. This is why baseline comparisons (known-good vs. current state) matter more than manual review.

📸 *See:* [`screenshots/README.md#19`](screenshots/README.md#19---scheduled-task-name)

---

#### Q20 — At what time was the persistence scheduled task set to run daily?

**Why this matters:** Scheduled execution times outside business hours are a strong indicator of intentional stealth. An attacker setting a task to run at 03:00 is ensuring no users are watching when their implant re-establishes its connection.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has "schtasks"
| project Timestamp, DeviceName, ProcessCommandLine
```

**Answer:** `03:00`

> 3:00 AM daily execution with `SYSTEM` privileges. The task runs `RuntimeBroker.exe` (the masqueraded dropper) every morning at 3:00 AM — re-establishing the attacker's foothold even if the process is killed during the day. This should drive your alert baseline: any scheduled task running outside 07:00–19:00 on a server warrants investigation.

📸 *See:* [`screenshots/README.md#20`](screenshots/README.md#20---scheduled-task-time)

---

### Phase 6 — Collection & Exfiltration Staging

---

#### Q21 — What is the filename of the staging archive?

**Why this matters:** Archive creation followed by outbound transfer is the dominant data-theft pattern in modern intrusions. Detecting archive creation in sensitive data directories is a high-value DLP alert that should be in every security stack.

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName endswith ".zip"
    or FileName endswith ".rar"
    or FileName endswith ".7z"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**Answer:** `Shares.7z`

> The `.7z` extension identifies 7-Zip format — a common attacker choice because 7-Zip supports strong AES-256 encryption, making the archive contents unreadable even if intercepted in transit.

📸 *See:* [`screenshots/README.md#21`](screenshots/README.md#21---staging-archive)

---

#### Q22 — What process created the staging archive?

**Why this matters:** Knowing the archiving tool used tells you what to look for in future hunts. `7zg.exe` is the graphical 7-Zip binary — its presence running in a server context without user interaction is anomalous and should be alerted on.

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName endswith ".zip"
    or FileName endswith ".rar"
    or FileName endswith ".7z"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**Answer:** `7zg.exe`

> `7zg.exe` is the GUI version of 7-Zip. In a server environment with no logged-in user, this process should never run. Its presence as the initiating process for archive creation is a reliable malicious indicator on server-class machines.

📸 *See:* [`screenshots/README.md#22`](screenshots/README.md#22---archive-tool)

---

#### Q23 — How many distinct clients were staged for exfiltration?

**Why this matters:** Knowing exactly which client data was staged drives breach notification obligations and contract-level disclosure decisions. Each distinct client folder accessed is a potentially affected party.

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-srv"
| where FolderPath startswith "C:\\Shares\\Clients\\"
| extend ClientFolder = tostring(split(FolderPath, "\\")[3])
| where isnotempty(ClientFolder)
| distinct ClientFolder
```

**Answer:** `12`

> The `split()` and array indexing extracts the client folder name from the full path. `distinct ClientFolder` deduplicates to give a count of unique affected clients. Each of these is a potential breach notification obligation for Apex Talent Partners.

📸 *See:* [`screenshots/README.md#23`](screenshots/README.md#23---client-folders)

---

#### Q24 — Name one of the two filenames repeatedly accessed across client folders

**Why this matters:** File-name-specific access patterns across many directories simultaneously is staging behaviour. This specific file pattern — the same two filenames accessed in every single client folder — is the DLP and EDR alert that should have fired.

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-srv"
| where InitiatingProcessFileName == "7zg.exe"
| where FolderPath startswith "C:\\Shares\\Clients\\"
| project FileName
```

**Answer:** `Rate_Card_2025_CONFIDENTIAL.pdf`

> This is exactly the file a competitor or corporate espionage actor would want — client contracts and pricing structures for senior executive placements. The pattern of accessing the same filenames across 12 different client directories in rapid succession is the clearest possible exfiltration staging signature.

📸 *See:* [`screenshots/README.md#24`](screenshots/README.md#24---staged-file-types)

---

#### Q25 — What is the full path the archive was moved to?

**Why this matters:** Relocating the archive back into the source directory is a classic anti-forensics step — it makes the archive look like a legitimate backup of the Clients share. Analysts reviewing the directory might see `Shares.7z` inside `C:\Shares\Clients\` and assume it belongs there.

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-srv"
| where FileName == "Shares.7z"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**Answer:** `C:\Shares\Clients\Shares.7z`

> The archive was created elsewhere and then moved into `C:\Shares\Clients\` — the exact directory it staged data from. This makes it blend in visually and positions it for easy exfiltration via the same RDP session or via a subsequent connection.

📸 *See:* [`screenshots/README.md#25`](screenshots/README.md#25---archive-final-path)

---

### Phase 7 — Defence Evasion

---

#### Q26 — What Windows utility was used to clear the event logs?

**Why this matters:** Log clearing is a strong indicator that the attacker is aware of being detected or is completing their operation. However, the log clear itself generates an Event ID 1102 in the Security log — an attacker who clears logs paradoxically leaves a record of doing so.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-srv"
| where ProcessCommandLine has "clear"
    or ProcessCommandLine has "wevtutil"
    or ProcessCommandLine has "eventlog"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Answer:** `wevtutil.exe`

> `wevtutil.exe` is the Windows Event Utility — a built-in tool for querying and managing Windows event logs. The command `wevtutil cl Security` clears the Security event log. Because Defender for Endpoint forwards telemetry to the cloud before the attacker can clear it, this action was captured and the cleared evidence is still available in Sentinel.

📸 *See:* [`screenshots/README.md#26`](screenshots/README.md#26---log-clearing)

---

#### Q27 — What is the MITRE ATT&CK Tactic ID for bundling files into an archive prior to exfiltration?

**Why this matters:** Mapping findings to MITRE ATT&CK gives your investigation a standardised language that clients, legal teams, and insurers understand. It also directly informs which detection rules to build next.

**Answer:** `TA0009 — Collection`

> **T1560.001** — Archive Collected Data: Archive via Utility (7-Zip)  
> **TA0009** — Collection is the tactic: the attacker is gathering data of interest before exfiltration.

📸 *See:* [`screenshots/README.md#27`](screenshots/README.md#27---mitre-mapping)

---

## 📊 Final Report — The Four Questions

---

### 🔍 Who gained access?

The attack began when a user at **Apex Talent Partners** was socially engineered into executing a file named `Daniel_Richardson_CV.pdf.exe` — a dropper disguised as a job applicant's CV, perfectly targeted at a recruitment firm. The user `Sophie.Turner` on workstation `as-pc1` executed the file from their Downloads folder.

From there, the attacker moved laterally using brute-forced credentials for `david.mitchell` to reach `as-pc2`, and then used the service account `svc_backup` — likely obtained through credential dumping or password reuse — to authenticate to the file server `as-srv` via RDP.

**Accounts compromised:**
- `Sophie.Turner` — initial victim, executed dropper
- `david.mitchell` — brute-forced, used for lateral movement to as-pc2
- `as.srv.administrator` — used for privileged access to the file server
- `svc_backup` — backdoor account created by the attacker for persistence

---

### 🔍 How did they get in?

**Initial access vector:** Spear-phishing with a malicious executable disguised as a recruitment CV (`Daniel_Richardson_CV.pdf.exe`). The double extension and recruitment-themed filename were specifically crafted to target a firm that regularly receives CVs from job applicants.

**Execution chain:**
1. Victim opens what appears to be a PDF CV
2. Dropper executes, spawns `net.exe` for discovery
3. `net.exe` enumerates local administrators group
4. `certutil.exe` downloads AnyDesk RMM tool 
5. RMM configured with password `intrud3r!` for persistent access
6. Backdoor account `svc_backup` created and added to Administrators
7. Brute force against `as-pc2` → success with `david.mitchell`
8. RDP from as-pc2 to as-srv using `svc_backup` credentials

**Key LOLBins abused:**

| Binary | Abuse |
|--------|-------|
| `net.exe` | Local group enumeration |
| `certutil.exe` | Downloading remote payloads |
| `schtasks.exe` | Scheduled task persistence |
| `wevtutil.exe` | Event log clearing |

---

### 🔍 What systems and data did they interact with?

| System | Activity |
|--------|----------|
| `as-pc1` | Dropper executed, discovery, RMM deployed, backdoor account created |
| `as-pc2` | Brute-forced via RDP, dropper re-downloaded from staging domain |
| `as-srv` | Dropper deployed as `RuntimeBroker.exe`, scheduled task created, client data accessed and archived |

**Data accessed on the file server:**

The attacker used `7zg.exe` to archive the entire `C:\Shares\Clients\` directory. **12 distinct client folders** were accessed.

These represent the core commercial value of Apex Talent Partners — their client relationships and data. In the wrong hands, this data could be used for competitive intelligence, client poaching, or negotiation leverage.

---

### 🔍 Was any sensitive information taken?

**Assessment: High confidence that data was staged for exfiltration.**

Evidence:
- `7zg.exe` created `Shares.7z` containing all 12 client directories
- The archive was relocated to `C:\Shares\Clients\Shares.7z` — positioned for removal
- The attacker had an active RDP session to the file server at the time of archiving
- Event logs were cleared after archiving — the attacker knew they were done and tried to cover tracks

**Confirmed files staged:** `Rate_Card_2025_CONFIDENTIAL.pdf` 

Whether the archive was successfully transferred externally could not be confirmed from the available telemetry — network egress monitoring or proxy logs would be required to determine if `Shares.7z` was transferred out of the network.

---

## 📸 Screenshots Index

See [`screenshots/README.md`](screenshots/README.md) for the full annotated index of all 27 screenshots.

---

## 📋 KQL Query Reference

See [`queries/all-queries.md`](queries/all-queries.md) for every query used in this investigation, cleaned and ready to copy-paste into Sentinel.

---

## 🔑 Key IOCs

| IOC Type | Value | Context |
|----------|-------|---------|
| Filename | `Daniel_Richardson_CV.pdf.exe` | Initial dropper — double extension |
| SHA256 | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` | Dropper hash — hunt across estate |
| Domain | `sync.cloud-endpoint.net` | Attacker staging domain — block at proxy/DNS |
| Path | `AnyDesk.exe` | RMM tool — remove from all devices |
| Path | `RuntimeBroker.exe` | Masqueraded dropper on file server |
| Account | `svc_backup` | Backdoor account — disable and delete - Compromised service account — reset password, audit access |
| Task name | `MicrosoftEdgeUpdateCheck` | Malicious scheduled task — remove from as-srv |
| Archive | `C:\Shares\Clients\Shares.7z` | Staged data archive — preserve for evidence |

---

## 📁 Repository Structure

```
ctf-kql-investigation/
├── README.md                    ← This file — full investigation walkthrough
├── screenshots/
│   └── README.md                ← 27 annotated screenshot entries
├── all-queries.md               ← All 27 KQL queries, clean and documented
└── incident-summary.md          ← Condensed IOC and findings report
```

---

*KQL Threat Hunting CTF — June 2026 — Microsoft Defender for Endpoint / Sentinel*
