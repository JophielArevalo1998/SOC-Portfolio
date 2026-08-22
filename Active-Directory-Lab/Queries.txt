# 📋 Splunk SPL Query Reference

> All Splunk Search Processing Language (SPL) queries used in this lab, organised by use case.
> Copy these directly into the Splunk search bar.

---

## 🔵 Basic Index Verification

### Confirm data is flowing from both hosts
```spl
index="endpoint"
| stats count by host
```

### Check the most recent events from any host
```spl
index="endpoint"
| sort -_time
| head 50
```

### Check which Windows Event IDs are being collected
```spl
index="endpoint"
| stats count by EventCode
| sort -count
```

---

## 🔵 Logon Monitoring (Event ID 4624 & 4625)

### All successful logons
```spl
index="endpoint" EventCode=4624
| table _time, ComputerName, Account_Name, Logon_Type, Source_Network_Address
| sort -_time
```

### All failed logons
```spl
index="endpoint" EventCode=4625
| table _time, ComputerName, Account_Name, Source_Network_Address
| sort -_time
```

### Failed logons grouped by source IP — identify brute force sources
```spl
index="endpoint" EventCode=4625
| stats count by Source_Network_Address, Account_Name
| sort -count
```

### Successful logons grouped by source IP
```spl
index="endpoint" EventCode=4624
| stats count by Source_Network_Address, Account_Name, ComputerName
| sort -count
```

---

## 🔵 Brute Force Investigation

### Find all logon attempts (failed and successful) from a specific IP
```spl
index="endpoint" (EventCode=4624 OR EventCode=4625)
  Source_Network_Address="REPLACE_WITH_SUSPICIOUS_IP"
| table _time, EventCode, Account_Name, Logon_Type, ComputerName
| sort _time
```

> Change `EventCode=4624` results appearing after a string of `4625` events is the moment the brute force succeeded.

### Detect brute force pattern — high failure count per source IP
```spl
index="endpoint" EventCode=4625
| stats count by Source_Network_Address
| where count > 10
| sort -count
```

### Timeline view of attack — see the volume spike
```spl
index="endpoint" EventCode=4625
| timechart count by Source_Network_Address
```

---

## 🔔 Alert Rule — RDP Remote Logon Detection

### Full alert query (paste this when creating the alert)
```spl
index="endpoint" EventCode=4624
  (Logon_Type=7 OR Logon_Type=10)
  Source_Network_Address=*
  Source_Network_Address!="-"
  Source_Network_Address!=40.*
| stats count by _time, ComputerName, Source_Network_Address, Account_Name, Logon_Type
```

**Field breakdown:**

| Field / Filter | What it means |
|----------------|---------------|
| `EventCode=4624` | Successful logon only |
| `Logon_Type=7` | Unlock — workstation unlock, often seen with RDP reconnects |
| `Logon_Type=10` | RemoteInteractive — this is the primary RDP logon type |
| `Source_Network_Address=*` | Must have a source IP (excludes local/service logons with no IP) |
| `Source_Network_Address!="-"` | Excludes events where the field is a literal dash (blank) |
| `Source_Network_Address!=40.*` | Exclude your internal subnet — tune to your lab's IP range |

> **Tuning tip:** Replace `40.*` with your actual internal subnet (e.g., `192.168.1.*` or `10.0.0.*`) to avoid false positives from internal logons.

---

## 🔵 Sysmon Queries

### All Sysmon process creation events (Event ID 1)
```spl
index="endpoint" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time, ComputerName, Image, CommandLine, ParentImage, User
| sort -_time
```

### Sysmon network connections (Event ID 3) — outbound only
```spl
index="endpoint" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
  Initiated=true
| table _time, ComputerName, Image, DestinationIp, DestinationPort, User
| sort -_time
```

### Sysmon — find connections to a specific destination IP
```spl
index="endpoint" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
  DestinationIp="REPLACE_WITH_SUSPICIOUS_IP"
| table _time, ComputerName, Image, DestinationPort
```

---

## 🔴 Atomic Red Team / MITRE ATT&CK Detection

### Detect new local account creation (T1136 — Create Account)
```spl
index="endpoint" EventCode=4720
| table _time, ComputerName, Account_Name, Subject_Account_Name
| sort -_time
```

> Event ID `4720` fires every time a new local or domain account is created. This is the primary detection for Atomic technique T1136.001.

### Detect privilege escalation — user added to admin group (T1078)
```spl
index="endpoint" EventCode=4732
| table _time, ComputerName, Account_Name, Group_Name
| sort -_time
```

> Event ID `4732` = a member was added to a security-enabled local group. If `Group_Name` is "Administrators", this is a critical signal.

### Detect PowerShell execution (T1059.001)
```spl
index="endpoint" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*powershell*"
| table _time, ComputerName, CommandLine, ParentImage, User
| sort -_time
```

### Detect scheduled task creation (T1053)
```spl
index="endpoint" EventCode=4698
| table _time, ComputerName, Account_Name, Task_Name
| sort -_time
```

---

## 📊 Dashboard Queries

### Logon activity over time — for a time chart panel
```spl
index="endpoint" (EventCode=4624 OR EventCode=4625)
| timechart count by EventCode
```

### Top targeted accounts — for a bar chart panel
```spl
index="endpoint" EventCode=4625
| stats count by Account_Name
| sort -count
| head 10
```

### Top source IPs — for a table panel
```spl
index="endpoint" EventCode=4625
| stats count by Source_Network_Address
| sort -count
| head 10
```

### All Sysmon event types — for a pie chart panel
```spl
index="endpoint" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
| sort -count
```

---

## 📝 Event ID Quick Reference

| Event ID | Description | Why it matters |
|----------|-------------|----------------|
| `4624` | Successful logon | Confirms access — watch LogonType |
| `4625` | Failed logon | Brute force indicator |
| `4648` | Logon with explicit credentials | Pass-the-hash or runas attacks |
| `4672` | Special privileges assigned | Admin logon |
| `4688` | Process creation (native Windows) | Less detail than Sysmon ID 1 |
| `4698` | Scheduled task created | Persistence mechanism |
| `4720` | User account created | T1136 — Create Account |
| `4732` | User added to local group | Privilege escalation |
| `4776` | NTLM authentication attempt | Credential attacks |
| Sysmon `1` | Process creation (rich) | Full command line + parent |
| Sysmon `3` | Network connection | C2 beaconing detection |
| Sysmon `7` | Image loaded | DLL injection detection |
| Sysmon `11` | File created | Dropper/payload detection |

---

## Logon Type Reference

| Logon Type | Name | Description |
|------------|------|-------------|
| 2 | Interactive | Local keyboard logon |
| 3 | Network | File share, net use |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Windows services |
| 7 | Unlock | Screen unlock (often RDP reconnect) |
| 8 | NetworkCleartext | IIS basic auth |
| 10 | RemoteInteractive | **RDP session** — primary alert trigger |
| 11 | CachedInteractive | Cached domain creds (no DC contact) |
