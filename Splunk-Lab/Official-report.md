# Splunk SOC Investigation — FRONTDESK-PC1 Compromise

##  Scenario
Ryan Adams, a local administrator at a dental clinic, reported suspicious activity on his workstation on October 15, 2025, around 13:00 UTC. The user observed abnormal mouse movements, indicating potential compromise.

##  Objective
Investigate the incident using Splunk logs to:
- Identify the root cause
- Determine attacker behavior
- Extract Indicators of Compromise (IOCs)
- Reconstruct the full attack chain

---

##  Investigation Summary

The investigation revealed a **complete endpoint compromise** involving:

- **Initial Access:** Password spraying attack from `172.16.0.184`
- **Compromised Account:** `Ryan.Adams`
- **Execution:** Malicious `python.exe` executed from user directory
- **Command & Control:** Communication with `157.245.46.190`
- **Persistence:** Scheduled task `PythonUpdate` created with SYSTEM privileges

---

##  Attack Timeline

| Time (UTC) | Event |
|-----------|------|
| 12:51–12:55 | Password spraying (multiple 4625 events) |
| 12:55:17 | Successful login (Ryan.Adams) |
| 13:00:33 | python.exe executed |
| 13:00:34 | C2 communication initiated |
| 13:04:59 | Persistence established via scheduled task |

---

##  Indicators of Compromise (IOCs)

### IP Addresses
- `172.16.0.184` (attacker)
- `157.245.46.190` (C2 server)

### File
- `C:\Users\Ryan.Adams\Music\python.exe`

### Persistence Mechanism
- Task Name: `PythonUpdate`

### Network
- Port: `9999` (primary C2 channel)

---

##  MITRE ATT&CK Mapping

| Tactic | Technique |
|------|----------|
| Initial Access | T1110 – Brute Force |
| Execution | T1059 – Command Execution |
| Persistence | T1053.005 – Scheduled Task |
| Command & Control | T1071 – Application Layer Protocol |

---

##  Tools Used
- Splunk (SIEM)
- Sysmon Logs
- Windows Event Logs
- Suricata / Zeek
- VirusTotal (Threat Intelligence)

---

##  Files Included
- `capstone_report.pdf` → Full SOC report
- `spl_queries.txt` → SPL queries used
- `screenshots/` → Evidence from Splunk dashboards

---

##  Outcome

The system was fully compromised via credential attack and remote access malware. Immediate remediation actions should include account resets, host isolation, and IOC blocking.

---

## 👨‍💻 Author
Jophiel Arevalo Enriquez
