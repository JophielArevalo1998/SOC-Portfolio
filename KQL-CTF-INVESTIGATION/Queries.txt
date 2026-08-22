# 📋 KQL Query Reference — All 27 Questions

> Every query used in this investigation, cleaned and documented.
> Copy directly into Microsoft Sentinel or Defender for Endpoint Advanced Hunting.
> All queries use the date range: **January 15, 2026 00:00 – 23:59 UTC**

---

## Base Time Filter

```kql
// Apply this to every query — replace the table name as needed
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
```

> **Important:** Use `Timestamp`, NOT `TimeGenerated` in these custom `_CL` tables.

---

## Phase 1 — Initial Access

### Q1 — Find the double-extension dropper in Downloads

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FolderPath contains "downloads"
| project FileName, AccountName
```

**Returns:** `Daniel_Richardson_CV.pdf.exe` / `a.stewart`

---

### Q2 & Q3 — Identify patient zero and the executing user

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath
| order by Timestamp asc
```

**Returns:** First row = `as-pc1` / `a.stewart` — patient zero and compromised user

---

### Q4 — Get the dropper SHA256 hash

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, SHA256
| order by Timestamp asc
```

**Returns:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

> **Hunt tip:** Once you have this hash, use it across all tables and all devices:
> ```kql
> DeviceFileEvents_CL
> | where SHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
> | project Timestamp, DeviceName, FileName, FolderPath
> ```

---

## Phase 2 — Discovery

### Q5 — Find child processes spawned by the dropper

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where InitiatingProcessFileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp asc
```

**Returns:** `cmd.exe` as the first child process

---

### Q6 — Find local administrator group enumeration

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName == "net.exe"
| where ProcessCommandLine has "localgroup"
| project Timestamp, DeviceName, ProcessCommandLine
```

**Returns:** `net localgroup administrators`

---

## Phase 3 — Persistence & RMM

### Q7 — Find LOLBin used to download the RMM tool

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("http", "https", "download")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Returns:** `certutil.exe` with a download command

---

### Q8 — Find where the RMM tool was dropped

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-pc1"
| where ActionType =~ "FileCreated"
| where FolderPath has_any ("Public", "ProgramData", "Temp")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**Returns:** `C:\ProgramData\AnyDesk\AnyDesk.exe`

---

### Q9 — Find the RMM unattended access password

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where ProcessCommandLine has "--set-password"
| project Timestamp, DeviceName, ProcessCommandLine
```

**Returns:** `Sup3rS3cur3RMM!`

---

### Q10 — Find the backdoor account creation

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where ProcessCommandLine has "user"
| where ProcessCommandLine has "/add"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

**Returns:** `net user helpdesk [password] /add`

---

### Q11 — Find backdoor account privilege escalation

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where ProcessCommandLine has "localgroup"
| where ProcessCommandLine has "/add"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

**Returns:** `net localgroup Administrators helpdesk /add`

---

## Phase 4 — Lateral Movement

### Q12 — Identify lateral movement target (two-query approach)

```kql
// Query 1 — Logon attempts FROM as-pc1
DeviceLogonEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-pc1"
| where ActionType == "LogonAttempted"
| project Timestamp, AccountName, RemoteDeviceName, RemoteIP, DeviceName
| order by Timestamp asc
```

```kql
// Query 2 — Reverse lookup: which device owns the destination IP?
DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where LocalIP == "10.1.0.183"
| project DeviceName, LocalIP
| distinct DeviceName, LocalIP
```

**Returns:** `as-pc2`

---

### Q13 & Q14 — Find successful lateral logon and logon type

```kql
DeviceLogonEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where RemoteDeviceName == "as-pc2" or DeviceName == "as-pc2"
| project Timestamp, AccountName, ActionType, LogonType, DeviceName, RemoteDeviceName
| order by Timestamp asc
```

**Returns:** `j.harris` with `LogonType = RemoteInteractive` (RDP)

---

### Q15 — Find attacker staging domain on as-pc2

```kql
DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName in ("certutil.exe", "powershell.exe", "bitsadmin.exe", "curl.exe")
| project Timestamp, InitiatingProcessFileName, RemoteUrl
| order by Timestamp asc
```

**Returns:** `filestorage-cdn.net`

---

### Q16 — Find privileged RDP account used to reach file server

```kql
DeviceLogonEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, RemoteDeviceName, AccountName, ActionType, LogonType
| order by Timestamp asc
```

**Returns:** `svc_backup` → `as-srv`

---

## Phase 5 — File Server Compromise

### Q17 — Hunt dropper by SHA256 across all devices

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where SHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| project Timestamp, DeviceName, FileName, FolderPath
| order by Timestamp asc
```

**Returns:** `RuntimeBroker.exe` on `as-srv`

---

### Q18 — Find the masquerading binary path

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName == "RuntimeBroker.exe"
| project Timestamp, DeviceName, FolderPath, FileName
```

**Returns:** `C:\ProgramData\Microsoft\RuntimeBroker.exe`

> **Detection rule:** Any `RuntimeBroker.exe` outside `C:\Windows\System32\` is malicious.

---

### Q19 & Q20 — Find the scheduled task name and execution time

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has "schtasks"
| project Timestamp, DeviceName, ProcessCommandLine
```

**Returns:** Task name `WindowsUpdateService`, scheduled time `03:00`, runs as `SYSTEM`

---

## Phase 6 — Collection & Staging

### Q21 & Q22 — Find staging archive and the tool that created it

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName endswith ".zip"
    or FileName endswith ".rar"
    or FileName endswith ".7z"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**Returns:** `Shares.7z` created by `7zg.exe`

---

### Q23 — Count distinct client folders accessed

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-srv"
| where FolderPath startswith "C:\\Shares\\Clients\\"
| extend ClientFolder = tostring(split(FolderPath, "\\")[3])
| where isnotempty(ClientFolder)
| distinct ClientFolder
```

**Returns:** 8 distinct client folders

> **KQL breakdown:**
> - `split(FolderPath, "\\")[3]` — splits the path by backslash and takes the 4th element (index 3)
> - For `C:\Shares\Clients\Acme\Contract.pdf` → splits to `["C:", "Shares", "Clients", "Acme", "Contract.pdf"]` → index 3 = `"Acme"`
> - `isnotempty()` filters out any rows where the split returned nothing

---

### Q24 — Find filenames targeted across client folders

```kql
DeviceEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-srv"
| where InitiatingProcessFileName == "7zg.exe"
| where FolderPath startswith "C:\\Shares\\Clients\\"
| project FileName
```

**Returns:** `Contract.pdf` and `Pricing.xlsx`

---

### Q25 — Track archive relocation

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-srv"
| where FileName == "Shares.7z"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**Returns:** Archive moved to `C:\Shares\Clients\Shares.7z`

---

## Phase 7 — Defence Evasion

### Q26 — Find event log clearing activity

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

**Returns:** `wevtutil.exe cl Security`

---

## Bonus Hunting Queries

### Hunt all three devices for the dropper hash

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where SHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
| order by Timestamp asc
```

### Hunt all LOLBin download activity across the estate

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where FileName in ("certutil.exe", "bitsadmin.exe", "powershell.exe", "curl.exe", "wget.exe")
| where ProcessCommandLine has_any ("http://", "https://", "-urlcache", "DownloadFile", "WebClient")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

### Hunt all RDP logons across the estate

```kql
DeviceLogonEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, RemoteDeviceName, AccountName
| order by Timestamp asc
```

### Reconstruct the full attack timeline on as-srv

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where DeviceName == "as-srv"
| project Timestamp, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```

### Hunt for all accounts added to Administrators across estate

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-01-15 00:00) .. datetime(2026-01-15 23:59))
| where ProcessCommandLine has "localgroup"
| where ProcessCommandLine has "Administrators"
| where ProcessCommandLine has "/add"
| project Timestamp, DeviceName, ProcessCommandLine
```

---

## KQL Operators Quick Reference

| Operator | Use | Example |
|----------|-----|---------|
| `==` | Exact match (case-sensitive) | `FileName == "cmd.exe"` |
| `=~` | Exact match (case-insensitive) | `ActionType =~ "FileCreated"` |
| `has` | Contains whole word | `ProcessCommandLine has "localgroup"` |
| `contains` | Contains substring | `FolderPath contains "downloads"` |
| `has_any()` | Contains any of the values | `FileName has_any ("http", "https")` |
| `in` | Value is in a list | `FileName in ("cmd.exe", "net.exe")` |
| `startswith` | Starts with prefix | `FolderPath startswith "C:\\Shares\\"` |
| `endswith` | Ends with suffix | `FileName endswith ".exe"` |
| `between` | Range filter | `Timestamp between (t1 .. t2)` |
| `split()` | Split string into array | `split(FolderPath, "\\")[3]` |
| `tostring()` | Cast to string | `tostring(split(...)[3])` |
| `isnotempty()` | Filter out null/blank | `\| where isnotempty(ClientFolder)` |
| `distinct` | Unique values | `\| distinct DeviceName, LocalIP` |
| `extend` | Add computed column | `\| extend ClientFolder = ...` |
| `project` | Select columns | `\| project Timestamp, FileName` |
| `order by` | Sort results | `\| order by Timestamp asc` |
