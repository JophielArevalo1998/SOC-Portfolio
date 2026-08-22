# 📋 KQL Detection Queries Reference

> All Kibana Query Language (KQL) queries used in this lab, organized by use case.
> Copy these directly into Kibana's search bar in **Discover**, **Alerts**, or **Security Rules**.

---

## 🔵 Blue Team — SSH Monitoring (Linux)

### Detect all failed SSH login attempts
```kql
system.auth.ssh.event: "Failed"
```

### Failed SSH attempts on a specific agent
```kql
system.auth.ssh.event: "Failed"
  and agent.name: "SOC-Linux-Jop"
```

### Failed SSH with username and country context
```kql
system.auth.ssh.event: "Failed"
  and agent.name: "SOC-Linux-Jop"
  and user.name: *
  and source.geo.country_name: *
```

### Check if any suspicious IP ever authenticated successfully
```kql
system.auth.ssh.event: "Accepted"
  and source.ip: "REPLACE_WITH_SUSPICIOUS_IP"
```

### Full SSH brute force investigation query (used for the alert rule)
```kql
system.auth.ssh.event: *
  and agent.name: "SOC-Linux-Jop"
  and system.auth.ssh.event: "Failed"
```

---

## 🔵 Blue Team — RDP Monitoring (Windows)

### Detect failed RDP logon attempts (Event ID 4625)
```kql
event.code: "4625"
  and agent.name: "SOC-WIN-JOP"
```

### Detect successful RDP logons — Remote Interactive sessions only
```kql
event.code: "4624"
  and agent.name: "SOC-WIN-JOP"
  and (
    winlog.event_data.LogonType: "10"
    or winlog.event_data.LogonType: "7"
  )
```
> **Note:** LogonType 10 = RemoteInteractive (RDP). LogonType 7 = Unlock. Filtering prevents noise from local service logons (type 5) and batch jobs (type 4).

### RDP failed attempts from a specific IP
```kql
event.code: "4625"
  and source.ip: "REPLACE_WITH_ATTACKER_IP"
  and agent.name: "SOC-WIN-JOP"
```

### Count failed RDP attempts grouped by attacker IP
```kql
event.code: "4625"
  and agent.name: "SOC-WIN-JOP"
```
> In Discover, use the **Field Statistics** or build a **Lens** visualization with `source.ip` as the top values to see the count breakdown.

---

## 🔵 Blue Team — Sysmon Process Monitoring

### All process creation events (Sysmon Event ID 1)
```kql
event.code: "1"
  and event.provider: "Microsoft-Windows-Sysmon"
```

### Suspicious process execution — PowerShell, CMD, or rundll32
```kql
event.code: "1"
  and event.provider: "Microsoft-Windows-Sysmon"
  and (
    winlog.event_data.Image: *powershell*
    or winlog.event_data.Image: *cmd.exe*
    or winlog.event_data.Image: *rundll32*
  )
```

### Find process creation by a specific executable name
```kql
event.code: "1"
  and event.provider: "Microsoft-Windows-Sysmon"
  and winlog.event_data.Image: *svchost-jop*
```

### Track all child processes spawned by a specific parent
```kql
event.code: "1"
  and event.provider: "Microsoft-Windows-Sysmon"
  and winlog.event_data.ParentImage: *svchost-jop*
```

---

## 🔵 Blue Team — Sysmon Network Monitoring

### All outbound network connections (Sysmon Event ID 3)
```kql
event.code: "3"
  and event.provider: "Microsoft-Windows-Sysmon"
  and winlog.event_data.Initiated: "true"
```
> Event ID 3 logs every outbound connection. `Initiated: true` filters for connections the host initiated (not inbound).

### Network connections to a specific destination IP
```kql
event.code: "3"
  and event.provider: "Microsoft-Windows-Sysmon"
  and winlog.event_data.DestinationIp: "REPLACE_WITH_C2_IP"
```

### C2 beaconing detection — connections on suspicious ports
```kql
event.code: "3"
  and event.provider: "Microsoft-Windows-Sysmon"
  and winlog.event_data.Initiated: "true"
  and (
    winlog.event_data.DestinationPort: "80"
    or winlog.event_data.DestinationPort: "443"
    or winlog.event_data.DestinationPort: "9999"
  )
```

---

## 🔴 Threat Hunting — Mythic C2 / Apollo Implant

### Detect Apollo C2 implant by original filename + hash
```kql
event.code: "1"
  and winlog.event_data.OriginalFileName: "Apollo.exe"
  and winlog.event_data.Hashes: *B922E4A7C639E697D4AA06196E4DDE56CAF49CC4837F253228237EF46A285F90*
```
> **Why this works:** Sysmon reads the `OriginalFileName` field from the PE (Portable Executable) header. Even if the attacker renames the file to `svchost.exe`, the original name embedded in the binary remains `Apollo.exe`. Attackers would need to recompile to evade this.

### Hunt for the payload file by known filename
```kql
event.code: "1"
  and winlog.event_data.Image: *svchost-jop*
```

### Full C2 dashboard query — process creation with interpreter context
```kql
event.code: "1"
  and event.provider: "Microsoft-Windows-Sysmon"
  and (powershell or cmd or rundll32)
```

### Sysmon network connections (C2 callback traffic)
```kql
event.code: "3"
  and event.provider: "Microsoft-Windows-Sysmon"
  and winlog.event_data.Initiated: "true"
```

---

## 🛡️ Defender & EDR Events

### Windows Defender — malware detected (Event ID 1116)
```kql
event.code: "1116"
  and event.provider: "Microsoft-Windows-Windows Defender"
```

### Windows Defender — malware action taken (Event ID 1117)
```kql
event.code: "1117"
  and event.provider: "Microsoft-Windows-Windows Defender"
```

### Windows Defender — real-time protection disabled (Event ID 5001)
```kql
event.code: "5001"
  and event.provider: "Microsoft-Windows-Windows Defender"
```

### Elastic EDR — prevention events
```kql
event.action: "prevention"
  and agent.name: "SOC-WIN-JOP"
```

---

## 📊 Dashboard Queries (copy into Kibana Dashboards)

### SSH Brute Force Map — layer filter
```kql
system.auth.ssh.event: "Failed"
  and agent.name: "SOC-Linux-Jop"
```
> Join field: `source.geo.country_iso_code` → World Countries layer

### RDP Failed Logons table
```kql
event.code: "4625"
  and agent.name: "SOC-WIN-JOP"
```
> Fields: `source.ip`, `winlog.event_data.TargetUserName`, `@timestamp`

### RDP Successful Logons table
```kql
event.code: "4624"
  and agent.name: "SOC-WIN-JOP"
  and (winlog.event_data.LogonType: 10 or winlog.event_data.LogonType: 7)
```

### Sysmon Process Creation — C2 dashboard panel 1
```kql
event.code: "1"
  and event.provider: "Microsoft-Windows-Sysmon"
  and (powershell or cmd or rundll32)
```

### Sysmon Network Connections — C2 dashboard panel 2
```kql
event.code: "3"
  and event.provider: "Microsoft-Windows-Sysmon"
  and winlog.event_data.Initiated: "true"
```

### Defender Disabled — C2 dashboard panel 3
```kql
event.code: "5001"
  and event.provider: "Microsoft-Windows-Windows Defender"
```

---

## 🔔 Detection Rule Configurations

### Rule: SSH Brute Force Threshold
| Setting | Value |
|---------|-------|
| Rule type | Threshold |
| Index pattern | `logs-system.auth-*` |
| KQL filter | `system.auth.ssh.event: "Failed"` |
| Threshold | 5 |
| Group by | `source.ip`, `user.name` |
| Time window | 5 minutes |
| Severity | Medium |

### Rule: RDP Brute Force Threshold
| Setting | Value |
|---------|-------|
| Rule type | Threshold |
| Index pattern | `logs-windows.*` |
| KQL filter | `event.code: "4625" and agent.name: "SOC-WIN-JOP"` |
| Threshold | 5 |
| Group by | `source.ip`, `winlog.event_data.TargetUserName` |
| Time window | 5 minutes |
| Severity | Medium |

### Rule: Apollo C2 Implant Detection
| Setting | Value |
|---------|-------|
| Rule type | Custom query |
| Index pattern | `logs-endpoint*`, `logs-windows.*` |
| KQL filter | See Apollo query above |
| Severity | Critical |
| Required fields | `winlog.event_data.Hashes`, `winlog.event_data.OriginalFileName`, `process.parent.name` |

---

## 📝 Field Reference Cheat Sheet

| Field | Description | Example Value |
|-------|-------------|---------------|
| `event.code` | Windows Event ID | `4625`, `4624`, `1`, `3` |
| `agent.name` | Elastic Agent hostname | `SOC-WIN-JOP` |
| `event.provider` | Windows log source | `Microsoft-Windows-Sysmon` |
| `winlog.event_data.LogonType` | RDP session type | `10` = RDP, `7` = Unlock |
| `winlog.event_data.TargetUserName` | Account being logged into | `Administrator` |
| `winlog.event_data.OriginalFileName` | PE original filename (survives renaming) | `Apollo.exe` |
| `winlog.event_data.Hashes` | File hash (MD5, SHA1, SHA256) | `SHA256=B922E4A7...` |
| `winlog.event_data.Initiated` | Direction of network connection | `true` = outbound |
| `winlog.event_data.DestinationIp` | Target IP of network connection | `207.148.87.34` |
| `winlog.event_data.DestinationPort` | Target port of network connection | `80`, `443` |
| `winlog.event_data.Image` | Full path of process image | `C:\Users\Public\Downloads\svchost-jop.exe` |
| `winlog.event_data.ParentImage` | Parent process path | `C:\Windows\System32\cmd.exe` |
| `system.auth.ssh.event` | SSH auth outcome | `Failed`, `Accepted` |
| `source.ip` | Attacker source IP address | `192.0.2.10` |
| `source.geo.country_iso_code` | 2-letter country code | `RO`, `CN`, `US` |
| `source.geo.country_name` | Full country name | `Romania` |
