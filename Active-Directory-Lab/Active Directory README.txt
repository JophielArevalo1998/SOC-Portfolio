# Active Directory SOC Lab — Splunk + Atomic Red Team

> A hands-on home lab that builds a fully functional **Active Directory** environment, integrates it with **Splunk** as a SIEM, simulates real-world attacks using **Hydra** and **Atomic Red Team**, and detects them through custom Splunk alerts — all mapped to the **MITRE ATT&CK** framework.

---

## 📋 Table of Contents

1. [Lab Overview](#-lab-overview)
2. [Architecture](#-architecture)
3. [Prerequisites](#-prerequisites)
4. [Phase 1 — Splunk SIEM Setup](#phase-1--splunk-siem-setup)
   - [Splunk Server Installation](#11-splunk-server-installation)
   - [Index & Receiving Configuration](#12-index--receiving-configuration)
5. [Phase 2 — Windows Agent Deployment](#phase-2--windows-agent-deployment)
   - [Splunk Universal Forwarder](#21-splunk-universal-forwarder)
   - [Sysmon Installation](#22-sysmon-installation)
   - [inputs.conf Configuration](#23-inputsconf-configuration)
6. [Phase 3 — Active Directory Setup](#phase-3--active-directory-setup)
   - [Installing AD Domain Services](#31-installing-ad-domain-services)
   - [Promoting to Domain Controller](#32-promoting-to-domain-controller)
   - [Creating Users & Groups](#33-creating-users--groups)
   - [Joining the Target Machine to the Domain](#34-joining-the-target-machine-to-the-domain)
7. [Phase 4 — Attack Simulation](#phase-4--attack-simulation)
   - [RDP Brute Force with Hydra](#41-rdp-brute-force-with-hydra)
   - [Atomic Red Team](#42-atomic-red-team)
8. [Phase 5 — Detection & Alerting in Splunk](#phase-5--detection--alerting-in-splunk)
   - [Investigating Brute Force Logs](#51-investigating-brute-force-logs)
   - [RDP Logon Alert Rule](#52-rdp-logon-alert-rule)
9. [Screenshots Index](#-screenshots-index)
10. [Splunk Query Reference](#-splunk-query-reference)
11. [Lessons Learned](#-lessons-learned)

---

## 🔭 Lab Overview

This lab simulates a small enterprise environment where a domain controller manages users and a target Windows machine is joined to the domain. A Splunk SIEM collects logs from all Windows machines via Universal Forwarder and Sysmon. Attacks are launched from Kali Linux using both credential brute-forcing and MITRE ATT&CK-mapped techniques via Atomic Red Team. All activity is detected and alerted in Splunk.

| Role | Tooling |
|------|---------|
| SIEM | Splunk Enterprise |
| Log Agent | Splunk Universal Forwarder + Sysmon |
| Active Directory | Windows Server (ADDC01) |
| Target Machine | Windows (domain-joined) |
| Attacker | Kali Linux, Hydra, Atomic Red Team |

---

## 🏗️ Architecture

<img width="1228" height="1208" alt="Screenshot 2026-06-05 141910" src="https://github.com/user-attachments/assets/9684fde5-c3d4-463a-910d-7fa86697f620" />


**Machines used in this lab:**

| Instance | OS | Role | Key Port(s) |
|----------|----|------|-------------|
| Splunk Server | Ubuntu/Linux | SIEM — receives and indexes logs | 8000 (UI), 9997 (receiving) |
| ADDC01 | Windows Server | Active Directory Domain Controller | 53 (DNS), 389 (LDAP), 3389 (RDP) |
| Target VM | Windows | Domain-joined endpoint (victim) | 3389 (RDP) |
| Kali Linux | Kali | Attacker machine | — |

---

## ✅ Prerequisites

- A hypervisor (VMware, VirtualBox, or cloud VMs)
- Basic Windows Server and Linux CLI knowledge
- Splunk Enterprise free trial account (splunk.com)
- Kali Linux VM

---

## Phase 1 — Splunk SIEM Setup

### 1.1 Splunk Server Installation

Splunk is the SIEM at the centre of this lab. It collects, indexes, and searches log data from all machines. The web UI runs on port **8000**, and it listens for incoming data from Universal Forwarders on port **9997**.

**Step 1 — Download and install Splunk on the Ubuntu server:**

```bash
# Download the Splunk .deb package from splunk.com
wget -O splunk.deb "https://download.splunk.com/products/splunk/releases/9.x.x/linux/splunk-9.x.x-linux-2.6-amd64.deb"

# Install the package
sudo dpkg -i splunk.deb
```

**Step 2 — Switch to the Splunk user and start Splunk:**

```bash
# Splunk runs under its own dedicated system user for security isolation
# This prevents Splunk processes from running as root
sudo su - splunk

# Start Splunk for the first time — this also sets up the initial config
/opt/splunk/bin/splunk start
```

> 💡 On first start, Splunk will prompt you to accept the license agreement and create an admin account. Choose a strong password and save it somewhere safe.

**Step 3 — Create the admin account:**

During first start you will be prompted:

```
Create credentials for the administrator account.
Username: admin
Password: [choose a strong password]
```

**Step 4 — Enable Splunk to start on boot:**

```bash
# This registers Splunk as a system service so it survives reboots
/opt/splunk/bin/splunk enable boot-start
```

**Step 5 — Allow port 8000 through the firewall:**

```bash
# Open port 8000 so you can access the Splunk web UI from your browser
# Replace YOUR_IP with your own IP to restrict access, or use 0.0.0.0/0 for lab-only testing
sudo ufw allow from YOUR_IP to any port 8000
```

> ⚠️ In a production environment, never expose port 8000 to the public internet without authentication and TLS.

Navigate to `http://YOUR_SPLUNK_SERVER_IP:8000` to access the Splunk UI.

📸 *See:* [`screenshots/01-splunk-install.png`](screenshots/README.md#01---splunk-installation)
📸 *See:* [`screenshots/02-splunk-login.png`](screenshots/README.md#02---splunk-login-page)

---

### 1.2 Index & Receiving Configuration

Before Splunk can receive data, you need to:
1. Create an **index** — a dedicated storage bucket for your endpoint logs
2. Enable a **receiving port** — so forwarders know where to send data

**Step 1 — Create the `endpoint` index:**

- Splunk UI → **Settings → Indexes → New Index**
- **Index name:** `endpoint`
- Leave all other settings as default
- Click **Save**

> An index in Splunk is like a database table — it's where your logs are stored and searched. Separating endpoint logs into their own index keeps searches fast and organised.

**Step 2 — Enable the receiving port (9997):**

- Splunk UI → **Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port**
- **Port:** `9997`
- Click **Save**

> Port 9997 is the standard Splunk-to-Splunk communication port. All Universal Forwarders installed on your Windows machines will ship their logs here.

📸 *See:* [`screenshots/03-splunk-index.png`](screenshots/README.md#03---splunk-index-creation)
📸 *See:* [`screenshots/04-splunk-receiving.png`](screenshots/README.md#04---splunk-receiving-port)

---

## Phase 2 — Windows Agent Deployment

Both the Windows Target VM and the Windows Server (ADDC01) need two components installed:
- **Splunk Universal Forwarder** — ships logs to Splunk
- **Sysmon** — enriches Windows event logs with detailed process and network telemetry

---

### 2.1 Splunk Universal Forwarder

The **Universal Forwarder** is a lightweight Splunk agent. It runs silently in the background, monitors Windows Event Log channels, and forwards the data to the Splunk indexer. It consumes minimal resources and has no search/UI capability — it only forwards.

**Step 1 — Download the Universal Forwarder:**

```powershell
# Download the Universal Forwarder MSI installer for Windows x64
# You can also download manually from: https://www.splunk.com/en_us/download/universal-forwarder.html
wget -O splunkforwarder.msi "https://download.splunk.com/products/universalforwarder/releases/10.4.0/windows/splunkforwarder-10.4.0-f798d4d49089-windows-x64.msi"
```

**Step 2 — Install the Universal Forwarder:**

Run the downloaded `.msi` installer and follow the wizard with these key settings:

| Setting | Value |
|---------|-------|
| Username | `admin` |
| Password | your chosen password |
| Receiving Indexer | `YOUR_SPLUNK_SERVER_IP` |
| Receiving Port | `9997` |

> Leave all other options as default. The installer registers Splunk Forwarder as a Windows service that starts automatically.

📸 *See:* [`screenshots/05-forwarder-install.png`](screenshots/README.md#05---universal-forwarder-installation)

---

### 2.2 Sysmon Installation

**Sysmon** (System Monitor) is a free Microsoft tool that dramatically improves the quality of Windows event logging. By default, Windows logs are sparse — Sysmon adds rich detail about process creation (who launched what, from where), network connections (which process connected to which IP), and file operations.

**Step 1 — Download Sysmon from Microsoft Sysinternals:**

```
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
```

**Step 2 — Download the Olaf Hartong Sysmon config:**

This community-maintained config filters out noisy, low-value events and focuses Sysmon on what matters for threat detection.

```
https://github.com/olafhartong/sysmon-modular
```

> Save the raw `.xml` config file in the **same folder** as `Sysmon.exe` — the installer reads it from the local path.

**Step 3 — Install Sysmon via PowerShell (run as Administrator):**

```powershell
# Navigate to the folder where you saved Sysmon.exe and sysmonconfig.xml
cd C:\Users\Administrator\Downloads\Sysmon

# Install Sysmon as a Windows service with the Olaf config
# -i         : install (first-time setup)
# -accepteula: auto-accept the end user licence agreement
# .\ prefix  : use the config from the current directory
.\Sysmon.exe -accepteula -i .\sysmonconfig.xml
```

**Step 4 — Verify Sysmon is running:**

```powershell
# Check the Sysmon service status — should show "Running"
Get-Service Sysmon

# Or check Event Viewer:
# Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

📸 *See:* [`screenshots/06-sysmon-install.png`](screenshots/README.md#06---sysmon-installation)
📸 *See:* [`screenshots/07-sysmon-events.png`](screenshots/README.md#07---sysmon-events-in-event-viewer)

---

### 2.3 inputs.conf Configuration

The `inputs.conf` file tells the Universal Forwarder **which Windows Event Log channels to monitor** and **which Splunk index to send them to**. Without this file, the forwarder has nothing to forward.

**Step 1 — Navigate to the local config directory:**

```powershell
cd "C:\Program Files\SplunkUniversalForwarder\etc\system\local"
```

> The `local` folder is where user-defined overrides live. Never edit files in the `default` folder — those are Splunk's own defaults and get overwritten on upgrade.

**Step 2 — Create `inputs.conf` with the following content:**

```ini
# Application event log — captures software installs, crashes, and application errors
[WinEventLog://Application]
index = endpoint
disabled = false

# Security event log — captures logon events, privilege use, account changes
# This is the most critical channel for detecting attacks (Event IDs 4624, 4625, 4648, etc.)
[WinEventLog://Security]
index = endpoint
disabled = false

# System event log — captures Windows service start/stop, driver loads, hardware events
[WinEventLog://System]
index = endpoint
disabled = false

# Sysmon operational log — enriched process, network, and file events from Sysmon
# renderXml=true preserves the full XML structure so all Sysmon fields parse correctly in Splunk
# source override ensures Splunk recognises this as a Sysmon-specific source
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = endpoint
disabled = false
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

**Step 3 — Restart the Splunk Forwarder service to apply the new config:**

```powershell
# The forwarder must be restarted any time inputs.conf is changed
# Without a restart, the new channels won't be monitored
Restart-Service SplunkForwarder
```

> ✅ After restart, logs should begin flowing into Splunk within 1–2 minutes. Verify by searching `index=endpoint` in the Splunk UI — you should see events from the host.

📸 *See:* [`screenshots/08-inputs-conf.png`](screenshots/README.md#08---inputsconf-file)
📸 *See:* [`screenshots/09-splunk-both-hosts.png`](screenshots/README.md#09---both-hosts-visible-in-splunk)

---

## Phase 3 — Active Directory Setup

**Active Directory (AD)** is Microsoft's directory service used by virtually every enterprise to manage users, computers, and policies from a central server called a **Domain Controller (DC)**. Setting up AD lets us simulate a realistic corporate environment where multiple machines and users are centrally managed.

---

### 3.1 Installing AD Domain Services

**Step 1 — Open Server Manager on the Windows Server:**

```
Start → Server Manager → Manage → Add Roles and Features
```

**Step 2 — Select installation type:**

- Choose **Role-based or feature-based installation**
- Click **Next**

> Role-based means you are adding a Windows Server role (a major capability like DNS, DHCP, or Active Directory) rather than installing a feature or a remote desktop service.

**Step 3 — Select the server:**

- Your server should appear in the server pool — select it and click **Next**

**Step 4 — Select the `Active Directory Domain Services` role:**

- Tick **Active Directory Domain Services**
- A popup will appear asking to add required features — click **Add Features**
- Click **Next** through the remaining screens until **Install** appears
- Click **Install** and wait for the installation to complete

> Installing AD DS adds the binaries and management tools, but the server is not yet a domain controller — that happens in the next step.

📸 *See:* [`screenshots/10-ad-role-install.png`](screenshots/README.md#10---active-directory-role-installation)

---

### 3.2 Promoting to Domain Controller

After installing the AD DS role, you must **promote** the server to a Domain Controller. This is what actually creates the domain and enables the server to authenticate users and manage the directory.

**Step 1 — Click the flag notification in Server Manager:**

After installation completes, a yellow warning flag appears in Server Manager. Click it and select **Promote this server to a domain controller**.

**Step 2 — Choose deployment configuration:**

- Select **Add a new forest** (you are creating a brand new domain from scratch)
- **Root domain name:** choose something like `SOClab.local` or `mycompany.local`

> A "forest" is the top-level container in Active Directory. A "domain" lives inside the forest. For a lab, you'll have one forest with one domain.

**Step 3 — Set the Directory Services Restore Mode (DSRM) password:**

This is a recovery password used if the AD database becomes corrupted. Set a strong password and save it — you likely won't need it, but losing it means you can't recover the DC.

**Step 4 — Continue through all remaining screens with defaults and click Install:**

> The server will automatically restart after promoting. This is expected — after the reboot the login screen will show `YOURDOMAIN\` before the username, confirming the DC is active.

📸 *See:* [`screenshots/11-ad-promote.png`](screenshots/README.md#11---promoting-to-domain-controller)
📸 *See:* [`screenshots/12-ad-login-confirmation.png`](screenshots/README.md#12---domain-login-confirmation)

---

### 3.3 Creating Users & Groups

With Active Directory running, you can now create the users and groups that will populate the domain — and that the attacker will later target.

**Step 1 — Open Active Directory Users and Computers (ADUC):**

```
Server Manager → Tools → Active Directory Users and Computers
```

> ADUC is the primary GUI for managing everything in your domain — users, groups, computers, and organisational units (OUs).

**Step 2 — Explore the default structure:**

You will see your domain (e.g., `SOClab.local`) with several default containers:
- **Builtin** — built-in groups like Administrators, Users, Guests
- **Computers** — machine accounts auto-register here when joined to the domain
- **Users** — default location for user accounts and groups

**Step 3 — Create a new Organisational Unit (OU):**

Right-click your domain → **New → Organizational Unit**

> OUs are like folders within Active Directory. They help organise users and computers and allow Group Policy to be applied selectively.

**Step 4 — Create new users:**

Right-click your OU (or the Users container) → **New → User**

Fill in:
- First name, Last name
- User logon name (e.g., `jsmith`)
- Password — and for the lab, uncheck "User must change password at next logon"

> Create at least 2 users. These will be the accounts Hydra targets during the brute force attack.

**Step 5 — Create a new group:**

Right-click → **New → Group**

- **Group name:** e.g., `SOC_Analysts`
- **Group scope:** Global
- **Group type:** Security

> Security groups control access to resources. Distribution groups are for email only. For lab purposes, create a Security group and add your users to it.

📸 *See:* [`screenshots/13-aduc-overview.png`](screenshots/README.md#13---active-directory-users-and-computers)
📸 *See:* [`screenshots/14-new-user.png`](screenshots/README.md#14---creating-a-new-user)
📸 *See:* [`screenshots/15-new-group.png`](screenshots/README.md#15---creating-a-new-group)

---

### 3.4 Joining the Target Machine to the Domain

Now you need to connect the Windows Target VM to the domain. Once joined, the users you created in AD can log into this machine — and it becomes a realistic attack surface.

**Step 1 — Configure DNS on the Target VM to point to the DC:**

This is the most common mistake when joining a domain — if DNS isn't pointing at the domain controller, Windows can't find the domain.

```
Control Panel → Network and Sharing Centre → Change adapter settings
→ Right-click your NIC → Properties → IPv4 → Properties
→ Preferred DNS server: [IP address of your Windows Server / DC]
```

> The domain controller runs its own DNS server. All domain-joined machines must use the DC as their DNS — otherwise the domain name (e.g., `SOClab.local`) won't resolve and the join will fail.

**Step 2 — Join the domain:**

```
Right-click This PC → Properties → Advanced system settings
→ Computer Name tab → Change
→ Select "Domain" → Type your domain name (e.g., SOClab.local)
→ Click OK
```

Enter the credentials of a domain admin account when prompted.

**Step 3 — Confirm the join:**

A popup will say **"Welcome to the SOClab.local domain"** — click OK. The machine will restart automatically.

📸 *See:* [`screenshots/16-dns-config.png`](screenshots/README.md#16---dns-configuration-on-target)
📸 *See:* [`screenshots/17-domain-join.png`](screenshots/README.md#17---joining-the-domain)
📸 *See:* [`screenshots/18-domain-join-confirm.png`](screenshots/README.md#18---domain-join-confirmation)

**Step 4 — Log in with a domain user:**

After the restart, on the login screen select **Other user** and log in with one of the AD accounts you created (e.g., `SOClab\jsmith`).

📸 *See:* [`screenshots/19-domain-user-login.png`](screenshots/README.md#19---logging-in-as-a-domain-user)

**Step 5 — Enable Remote Desktop for domain users:**

```
Right-click This PC → Properties → Remote settings
→ Allow remote connections to this computer
→ Select Users → Add your domain users
```

> By default, only the local Administrator can RDP. Adding domain users here is what makes them valid RDP targets for the brute force attack.

---

## Phase 4 — Attack Simulation

> ⚠️ **Legal disclaimer:** All attacks are performed in a self-controlled lab environment. Never use these techniques against systems you do not own or have explicit written permission to test.

### 4.1 RDP Brute Force with Hydra

**Hydra** is a fast, parallelised login cracker. We use it to simulate an attacker trying to guess passwords for RDP accounts — a very common real-world attack vector.

**Step 1 — Prepare the password wordlist:**

Create a custom wordlist that contains the actual passwords of your lab users (so the attack succeeds for demonstration purposes):

```bash
# On Kali Linux — create a wordlist file
# Include common passwords AND the real passwords of your AD users
nano ~/passwords.txt

# Example contents:
# Password123
# Welcome1
# Summer2024
# [add your actual AD user passwords here]
```

**Step 2 — Run Hydra against the Target VM:**

```bash
# Hydra RDP brute force targeting multiple usernames
# -L        : file containing a list of usernames to try
# -P        : file containing the password wordlist
# rdp://    : protocol — Remote Desktop Protocol
# -t 1      : use only 1 thread (RDP is sensitive to concurrent connections)
# -V        : verbose — print every single attempt to the screen
hydra -L ~/usernames.txt -P ~/passwords.txt rdp://TARGET_VM_IP -t 1 -V
```

> The `-t 1` flag is important for RDP. Unlike HTTP or SSH, RDP connections are fragile under parallel load and Hydra will get inconsistent results or be blocked if you use multiple threads.

**Step 3 — Review what Splunk captured:**

Every failed and successful logon attempt generates Windows Event Log entries:
- **Event ID 4625** — failed logon (each Hydra attempt)
- **Event ID 4624** — successful logon (when Hydra finds the right password)

📸 *See:* [`screenshots/20-hydra-attack.png`](screenshots/README.md#20---hydra-brute-force-attack)
📸 *See:* [`screenshots/21-splunk-attack-logs.png`](screenshots/README.md#21---splunk-logs-during-attack)

---

### 4.2 Atomic Red Team

**Atomic Red Team** is an open-source library of small, focused attack tests — each one maps directly to a technique in the **MITRE ATT&CK** framework. Instead of writing your own attack scripts, you invoke pre-built tests that simulate what real adversaries do.

> **MITRE ATT&CK** is a globally recognised knowledge base of adversary tactics and techniques based on real-world observations. Each technique has an ID (e.g., `T1136` = Create Account).

**Step 1 — Bypass Windows Defender before installation:**

Atomic Red Team will be flagged as malicious by Defender because it contains attack code. Add an exclusion first:

```
Windows Security → Virus & Threat Protection
→ Manage Settings → Add or remove exclusions
→ Add exclusion → Folder → C:\
```

> We exclude the entire `C:\` drive to prevent Defender from blocking the Atomic tests. In a real environment you would never do this — but this is a lab, and the point is to see what the attacker does, not have it blocked.

**Step 2 — Install Atomic Red Team via PowerShell (run as Administrator):**

```powershell
# Set execution policy to allow running scripts in this session
Set-ExecutionPolicy Bypass CurrentUser

# Install the Invoke-AtomicRedTeam module from PowerShell Gallery
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser

# Import the module into the current session
Import-Module Invoke-AtomicRedTeam

# Install all Atomic test content (the actual technique files)
Invoke-AtomicRedTeam -getAtomics
```

**Step 3 — Explore available techniques:**

After installation, the techniques are saved under `C:\AtomicRedTeam\atomics\`. Each folder corresponds to a MITRE ATT&CK technique ID:

```
C:\AtomicRedTeam\atomics\
├── T1059\      ← Command and Scripting Interpreter
├── T1136\      ← Create Account
├── T1003\      ← OS Credential Dumping
└── ...
```

**Step 4 — Run a technique (example: Create a new local user — T1136.001):**

```powershell
# Invoke technique T1136.001 — Create Account: Local Account
# This simulates an attacker creating a backdoor account on the compromised machine
Invoke-AtomicTest T1136.001
```

> After running this, a new local user account will appear on the machine. Check Splunk for **Event ID 4720** (a user account was created) — that's the detection signal.

📸 *See:* [`screenshots/22-atomic-install.png`](screenshots/README.md#22---atomic-red-team-installation)
📸 *See:* [`screenshots/23-atomic-techniques.png`](screenshots/README.md#23---atomic-red-team-techniques-folder)
📸 *See:* [`screenshots/24-atomic-run.png`](screenshots/README.md#24---running-an-atomic-technique)
📸 *See:* [`screenshots/25-splunk-atomic-log.png`](screenshots/README.md#25---atomic-technique-log-in-splunk)

---

## Phase 5 — Detection & Alerting in Splunk

### 5.1 Investigating Brute Force Logs

After the Hydra attack, navigate to Splunk and search for the evidence.

**Query — See all logon events from the endpoint index:**

```spl
index="endpoint" EventCode=4624 OR EventCode=4625
```

**Query — Filter for only failed logons (4625) from external IPs:**

```spl
index="endpoint" EventCode=4625
| table _time, ComputerName, Source_Network_Address, Account_Name, Logon_Type
| sort -_time
```

**Query — Find the Kali machine's IP in the logs:**

```spl
index="endpoint" EventCode=4624
| stats count by Source_Network_Address, Account_Name, ComputerName
| sort -count
```

> When you see a single source IP appearing hundreds of times with 4625 events followed by a 4624, that is the brute force attack and the successful login. The source IP will be your Kali machine's IP address.

📸 *See:* [`screenshots/26-splunk-brute-force-logs.png`](screenshots/README.md#26---brute-force-logs-in-splunk)
📸 *See:* [`screenshots/27-splunk-kali-ip.png`](screenshots/README.md#27---kali-ip-identified-in-splunk)

---

### 5.2 RDP Logon Alert Rule

This alert fires whenever a successful remote logon (RDP or network) occurs from an external IP — which is exactly what happens during the brute force attack.

**Full SPL query used for the alert:**

```spl
index="endpoint" EventCode=4624
  (Logon_Type=7 OR Logon_Type=10)
  Source_Network_Address=*
  Source_Network_Address!="-"
  Source_Network_Address!=40.*
| stats count by _time, ComputerName, Source_Network_Address, Account_Name, Logon_Type
```

**Breaking down the query:**

| Part | Explanation |
|------|-------------|
| `index="endpoint"` | Search only the endpoint index where all your Windows logs live |
| `EventCode=4624` | Windows Event ID 4624 = successful logon |
| `Logon_Type=7` | Unlock (user unlocking a locked screen) — can indicate RDP reconnect |
| `Logon_Type=10` | RemoteInteractive = full RDP session. This is the primary RDP logon type |
| `Source_Network_Address=*` | Only include events that have a source IP (filters out local/service logons) |
| `Source_Network_Address!="-"` | Exclude events where the source IP field is a literal dash (blank/local) |
| `Source_Network_Address!=40.*` | Exclude your internal network range — tune this to your own lab subnet |
| `\| stats count by ...` | Aggregate results: show how many times each combination of fields appeared |

**Creating the alert in Splunk:**

1. Run the query in Splunk Search
2. Click **Save As → Alert**
3. Configure:
   - **Title:** RDP Remote Logon Detected
   - **Alert type:** Real-time
   - **Trigger condition:** Number of results is greater than 0
   - **Trigger actions:** Add to Triggered Alerts (or email)
4. Click **Save**

**Step — Test the alert by RDP-ing from Kali:**

```bash
# Use xfreerdp to initiate an RDP session from Kali to the Target VM
# This triggers the exact logon type (10) that the alert watches for
xfreerdp /v:TARGET_VM_IP /u:DOMAIN\\username /p:password
```

📸 *See:* [`screenshots/28-alert-config.png`](screenshots/README.md#28---splunk-alert-configuration)
📸 *See:* [`screenshots/29-alert-triggered.png`](screenshots/README.md#29---alert-triggered-in-splunk)

---

## 📸 Screenshots Index

All screenshots are stored in the [`/screenshots`](./screenshots/) folder. See [`screenshots/README.md`](./screenshots/README.md) for the full annotated index.

---

## 📋 Splunk Query Reference

All SPL queries are collected in [`queries/splunk-queries.md`](./queries/splunk-queries.md).

---

## 💡 Lessons Learned

1. **DNS is the most common domain join failure** — always point the target machine's DNS at the DC before attempting to join.
2. **`inputs.conf` requires a forwarder restart** — changes don't take effect until `SplunkForwarder` service is restarted.
3. **`renderXml = true` is critical for Sysmon** — without it, Sysmon events arrive as flat strings and lose their structured field data in Splunk.
4. **Logon Type matters** — filtering alerts on `LogonType=10` dramatically reduces noise by focusing only on interactive RDP sessions and ignoring background service logons.
5. **Atomic Red Team maps to MITRE** — each test gives you a real indicator of compromise to hunt for in Splunk, building muscle memory for threat hunting.
6. **Defender exclusions before Atomic** — skipping this step means most tests are blocked before they run and you won't see anything in the logs.
7. **Custom wordlists beat generic ones** — for a realistic lab, plant the real password somewhere in the wordlist so Hydra succeeds in a reasonable time.

---

## 📁 Repository Structure

```
active-directory-lab/
├── README.md                    ← This file
├── screenshots/
│   └── README.md                ← Annotated screenshots index
├── queries/
│   └── splunk-queries.md        ← All SPL queries in one place
├── alerts/
│   └── alert-configs.md         ← Alert rule configurations
└── dashboards/
    └── dashboard-guide.md       ← Dashboard setup guide
```

