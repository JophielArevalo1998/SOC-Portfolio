# 🔔 Alert Configurations

> All Splunk alert rules used in this lab with their full configuration details.

---

## Alert 1 — RDP Remote Logon Detected

**Purpose:** Fires whenever a successful remote desktop or network logon occurs from an external IP address. This catches both legitimate admin RDP sessions and attacker access after a successful brute force.

### SPL Query
```spl
index="endpoint" EventCode=4624
  (Logon_Type=7 OR Logon_Type=10)
  Source_Network_Address=*
  Source_Network_Address!="-"
  Source_Network_Address!=40.*
| stats count by _time, ComputerName, Source_Network_Address, Account_Name, Logon_Type
```

### Splunk Alert Settings
| Setting | Value |
|---------|-------|
| Title | RDP Remote Logon Detected |
| Alert type | Real-time |
| Trigger condition | Number of results is greater than 0 |
| Trigger once | For each result |
| Action | Add to Triggered Alerts |
| Severity | High |

### How to create it in Splunk
1. Paste the query into the Splunk search bar
2. Set the time range to **All time** or **Last 15 minutes**
3. Click **Save As → Alert**
4. Fill in the settings above
5. Click **Save**

### Testing the alert
From Kali Linux, initiate an RDP session:
```bash
xfreerdp /v:TARGET_VM_IP /u:DOMAIN\\username /p:password
```
Within 30–60 seconds, the alert should appear under **Activity → Triggered Alerts** in Splunk.

---

## Alert 2 — New Local User Account Created

**Purpose:** Detects when a new user account is created on any monitored endpoint — a common attacker persistence technique (MITRE T1136).

### SPL Query
```spl
index="endpoint" EventCode=4720
| table _time, ComputerName, Account_Name, Subject_Account_Name
```

### Splunk Alert Settings
| Setting | Value |
|---------|-------|
| Title | New Local Account Created (T1136) |
| Alert type | Real-time |
| Trigger condition | Number of results is greater than 0 |
| Severity | Medium |

---

## Alert 3 — Brute Force Threshold

**Purpose:** Fires when more than 10 failed logon attempts come from the same IP within 5 minutes — a clear brute force signal.

### SPL Query
```spl
index="endpoint" EventCode=4625
  Source_Network_Address!="-"
  Source_Network_Address!=40.*
| stats count by Source_Network_Address, Account_Name, ComputerName
| where count > 10
```

### Splunk Alert Settings
| Setting | Value |
|---------|-------|
| Title | Brute Force Threshold Exceeded |
| Alert type | Scheduled |
| Schedule | Every 5 minutes |
| Trigger condition | Number of results is greater than 0 |
| Severity | High |

> **Note:** Tune the `count > 10` threshold based on your environment. In a lab with no legitimate failed logons, even 5 could be appropriate. In production, typical thresholds are 10–20 within 5 minutes.
