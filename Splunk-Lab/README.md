# 🔴 SOC Investigation — KCD Contractor Account Compromise & RDP Backdoor

**Simulator:** MyDFIR SOC Simulator (mahcyberdefense.com)  
**Analyst:** Jophiel Arevalo Enriquez  
**Role:** Level 1 SOC Analyst  
**Verdict:** ✅ True Positive — Active Compromise  
**Severity:** Critical  

---

## 📋 Table of Contents

1. [Alert Details](#1-alert-details)
2. [Environment Context](#2-environment-context)
3. [OSINT Investigation](#3-osint-investigation)
4. [Query 1 — Baseline: Who has been authenticating as KCD-Contractor?](#4-query-1--baseline-who-has-been-authenticating-as-kcd-contractor)
5. [Query 2 — Scope: What else has this IP touched?](#5-query-2--scope-what-else-has-this-ip-touched)
6. [Query 3 — Brute Force Check](#6-query-3--brute-force-check)
7. [Query 4 — Filtered Session Timeline](#7-query-4--filtered-session-timeline)
8. [Query 5 — Post-Logon Process Execution](#8-query-5--post-logon-process-execution)
9. [Query 6 — KCD-Web Lateral Movement Check](#9-query-6--kcd-web-lateral-movement-check)
10. [Full Report](#10-full-report)
11. [Key Takeaways](#11-key-takeaways)
12. [MITRE ATT&CK Mapping](#12-mitre-attck-mapping)

---

## 1. Alert Details

| Field | Value |
|---|---|
| **Alert Raised** | 2026-07-13 21:00 UTC (2026-07-14 07:00 AEST) |
| **Event Time** | 2026-07-13 20:20 UTC (2026-07-14 06:20 AEST) |
| **Detection lag** | 40 minutes |
| **ComputerName** | `DESKTOP-Q1HN49.kerningcitydental.ca` |
| **User** | `KCD-Contractor` |
| **Source IP** | `42.1.67.220` |
| **Logon_Type** | `7` (Unlock) |
| **Logon_Process** | `User32` |<img width="2716" height="1654" alt="Screenshot 2026-07-14 200115" src="https://github.com/user-attachments/assets/5a4b19f0-bb5a-4e8d-aee6-75efcbc21f63" />


## 2. Environment Context

| Field | Detail |
|---|---|
| **Client** | Kerning City Dental (KCD) |
| **Host** | DESKTOP-Q1HN49 — Toronto Azure branch reception workstation, Windows 11 Pro |
| **Internal IP** | 172.16.1.4 |
| **Known risk** | RDP port 3389 publicly exposed — accepted risk on file |
| **Baselined contractor IP** | `74.15.244.54` (Bell Canada, Ottawa — previously verified as legitimate) |
| **SIEM** | Splunk (KCD on-prem + Azure branch) |

> ⚠️ The baselined legitimate contractor IP (`74.15.244.54`) **does not appear at all** in the last 5 days of logs. Every authentication as `KCD-Contractor` in that window is from an unrecognised foreign source.

---

## 3. OSINT Investigation

### AbuseIPDB — `42.1.67.220`

<img width="2716" height="1654" alt="Screenshot 2026-07-14 200115" src="https://github.com/user-attachments/assets/b91b65d4-5ef7-4a08-88f8-f7477b80f50f" />


**Findings:**
- **342 reports** from **72 distinct sources**
- **100% Confidence of Abuse**
- ISP: Mobifone Corporation
- ASN: AS131429
- Country: 🇻🇳 **Vietnam** — Ho Chi Minh City
- Usage Type: Fixed Line ISP
- Most recent report: **2 days ago** — actively abusive at time of investigation

---

### VirusTotal — `42.1.67.220`

<img width="3002" height="1632" alt="Screenshot 2026-07-14 200201" src="https://github.com/user-attachments/assets/931a7fc4-6ac8-4e3d-a670-211fd21817be" />


**Findings:**
- **9/91 security vendors flagged as malicious**
- Detections: ADMINUSLabs (Malicious), BitDefender (Phishing), Chong Lua Dao (Malicious), CRDF (Malicious), Cyble (Malicious), CyRadar (Malware), G-Data (Phishing), Lionic (Malicious), SOCRadar (Malicious)
- Additional suspicious flags: AlphaSOC, alphaMountain.ai, Gridinsoft
- Last analysis: **6 days ago**
- ASN confirmed: AS131429 / MOBIFONE Corporation
---

### Shodan — `42.1.67.220`
<img width="3042" height="1534" alt="Screenshot 2026-07-14 200327" src="https://github.com/user-attachments/assets/e3329d54-289c-4f83-822f-a48f77cc9440" />


**Findings — this is the most significant OSINT result:**

| Field | Value |
|---|---|
| Country | Vietnam |
| Organisation | Mobifone Corporation |
| Last seen | **2026-07-13** (day of incident) |
| **Open port: 445/TCP** | SMB — Authentication enabled, SMB Version 2 |
| **Open port: 5985/TCP** | WinRM — Microsoft HTTPAPI/2.0 |
| **OS** | Windows Server 2022 (build 10.0.20348) |
| **Hostname** | `TEST1111111111` |
| **CVE** | **CVE-2020-0796 (SMBGhost)** — Critical RCE via SMBv3 |

<img width="2252" height="1000" alt="Screenshot 2026-07-14 200948" src="https://github.com/user-attachments/assets/e6228f50-5fe6-43b8-af30-971fa7a0e6cb" />
This IP is **not a legitimate user's device**. A throwaway-named Windows Server 2022 box with SMB and WinRM exposed, sitting on a Vietnamese consumer ISP and vulnerable to SMBGhost, is **attacker-controlled jump infrastructure** — almost certainly a previously compromised host being used as a hop point. A dental clinic contractor in Ottawa has no reason to route through it.

---

## 4. Query 1 — Baseline: Who has been authenticating as KCD-Contractor?

**Tool:** Splunk  
**Purpose:** Establish all source IPs for this account over the last 5 days and check whether the baselined legitimate IP is present

```spl
index=endpoint user="KCD-Contractor" (EventCode=4624 OR EventCode=4625 OR EventCode=4778)
earliest=-5d
| stats count, values(Logon_Type) as logon_types, min(_time) as first_seen, max(_time) as last_seen by src_ip
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```
<img width="2614" height="1322" alt="Screenshot 2026-07-14 201006" src="https://github.com/user-attachments/assets/e71d8012-c6f4-4215-9eb3-f90710313541" />


**Key findings:**
- The legitimate contractor IP **`74.15.244.54` is absent** — the credential is fully in attacker hands
- **Two IPs produced Type 7 Unlock events** — two separate interactive sessions on the same account
- `172.16.1.4` (the host itself) generating a Type 3 10 minutes after the unlock suggests post-exploitation local tooling

---

## 5. Query 2 — Scope: What else has this IP touched?

**Tool:** Splunk  
**Purpose:** Determine whether `42.1.67.220` touched any other hosts in the environment

```spl
index=* ("42.1.67.220")
earliest=-30d
| stats count, values(host) as hosts, values(user) as users, values(EventCode) as events,
        min(_time) as first, max(_time) as last by index, sourcetype
| convert ctime(first) ctime(last)
```

<img width="2882" height="1044" alt="Screenshot 2026-07-14 201123" src="https://github.com/user-attachments/assets/2e89c536-895f-41b6-8939-b54e69f23ca0" />


**Critical finding:**
- This IP first appeared in logs **19 June 2026** — **24 days before the alert**
- Sysmon EventCode 3 (Network Connection) records show this IP connected to **both DESKTOP-Q1HN49 and KCD-Web** — a **second host is implicated**
- The 19 June connection is the true start of attacker presence, not the alert date

---

## 6. Query 3 — Brute Force Check

**Tool:** Splunk  
**Purpose:** Confirm whether failed logon 4625 events preceded the successful access (brute force pattern)

```spl
index=endpoint host="DESKTOP-Q1HN49*" EventCode=4625 earliest=-7d
| stats count by src_ip, user, Failure_Reason
| sort - count
```
<img width="2862" height="1566" alt="Screenshot 2026-07-14 201311" src="https://github.com/user-attachments/assets/2bd671ff-4ef5-40b1-9b3d-924ab6d7c473" />

1,465,113 events — **DESKTOP-Q1HN49 is absorbing over 1.4 million failed logon attempts in 7 days** against the `Administrator` account from a large distributed IP set (primarily targeting `Administrator`, not `KCD-Contractor`). This is the background noise of an internet-exposed RDP server. The successful KCD-Contractor credential access is concealed within this volume.

---

## 7. Query 4 — Filtered Session Timeline

**Tool:** Splunk  
**Purpose:** Build a precise timeline of authentication events for the two attacker IPs, excluding system noise

```spl
index=endpoint host="DESKTOP-Q1HN49*" (src_ip="42.1.67.220" OR src_ip="162.192.142.215")
earliest=-7d
| table _time, EventCode, Logon_Type, Logon_Process, Authentication_Package, user, src_ip, src, Logon_ID
| sort _time
```

<img width="2862" height="1580" alt="Screenshot 2026-07-14 202347" src="https://github.com/user-attachments/assets/f390429a-54b5-47b4-bd34-25340a19c8aa" />


**Results — full attack narrative reconstructed:**

### Session 1 — `162.192.142.215` (hostname: `DTBWIN2025SRV1`)

| Time (UTC) | EventCode | Type | Detail |
|---|---|---|---|
| 13 Jul 18:27:35 | 4625 | 3 | Failed — NTLM spray begins |
| 13 Jul 18:34:23 | 4625 | 3 | Failed — second attempt burst |
| 13 Jul 18:42:58 | 4625 | 3 | Failed — third attempt burst |
| 13 Jul 19:01:17 | **4624** | **3** | ✅ **Successful Network logon — NTLM** |
| 13 Jul 19:01:20 | **4624** | **7** | ✅ **Unlock via User32 — interactive desktop accessed** |
| 13 Jul 19:01:20 | **4648** | — | ⚠️ **Explicit credential reuse** |

33 minutes from first failure to first successful interactive session.

### Session 2 — `42.1.67.220` (hostname: `TEST1111111111`)

| Time (UTC) | EventCode | Type | Detail |
|---|---|---|---|
| 11 Jul 19:55:41 | 4625 | 3 | Failed — first probe (2 days earlier) |
| 11 Jul 19:56:05 | 4625 | 3 | Failed |
| 11 Jul 19:56:30 | 4625 | 3 | Failed |
| 13 Jul 20:20:24 | **4624** | **3** | ✅ **Successful Network logon — NTLM** |
| 13 Jul 20:20:30 | **4624** | **7** | ✅ **Unlock via User32 — THIS IS THE ALERTED EVENT** |
| 13 Jul 20:20:30 | **4648** | — | ⚠️ **Explicit credential reuse** |
| 13 Jul 20:37:49 | 4634 | — | Session closes — 17 minutes of network access |

**Pattern:** Both attacks use identical tooling — NTLM spray via NtLmSsp → Type 3 success → immediate Type 7 unlock → 4648 credential reuse. The `src` field on the 4624 events confirms the attacker hostnames directly (`TEST1111111111` and `DTBWIN2025SRV1`), matching the Shodan data.

---

## 8. Query 5 — Post-Logon Process Execution

**Tool:** Splunk  
**Purpose:** Identify what ran on the host during and after the attacker sessions

```spl
index=endpoint host="DESKTOP-Q1HN49*" (EventCode=1 OR EventCode=4688)
earliest="07/13/2026:19:00:00" latest="07/14/2026:04:00:00"
| table _time, user, ParentImage, Image, CommandLine
| sort _time
```
<img width="2908" height="1466" alt="Screenshot 2026-07-14 202538" src="https://github.com/user-attachments/assets/a69f4f3d-edcd-4362-90f7-ce37ba35a5e8" />


**`sethc.exe` spawned by `AtBroker.exe` under SYSTEM — 2 seconds after the first interactive unlock — is the [Accessibility Feature Backdoor (T1546.008)](https://attack.mitre.org/techniques/T1546/008/).**

This technique replaces or hooks Sticky Keys (`sethc.exe`) so that pressing **Shift 5 times at the RDP login screen** drops a **SYSTEM-level command shell before any credentials are entered**. The backdoor:
- Survives reboots
- Requires no credentials to trigger
- Operates at SYSTEM privilege
- Means account lockout alone **does not close the attacker's access path**

Additionally, Sysmon EventCode 25 (Process Tampering — image replaced/hollowed) fired **10 times between 20:20:41 and 20:25:15 UTC** immediately after the second session's unlock, indicating active process injection or masquerading (T1055 / T1036).

---

## 9. Query 6 — KCD-Web Lateral Movement Check

**Tool:** Splunk  
**Purpose:** Confirm what the attacker did from DESKTOP-Q1HN49 toward KCD-Web on 19 June

```spl
index=* ("42.1.67.220") host="KCD-Web*" earliest=-30d
| table _time, sourcetype, EventCode, Image, DestinationIp, DestinationPort, SourceIp
| sort _time
```

<img width="2858" height="724" alt="Screenshot 2026-07-14 202633" src="https://github.com/user-attachments/assets/64c4519e-8413-4540-96a1-ab8a7a0d6aee" />


**`42.1.67.220` initiated an RDP connection from DESKTOP-Q1HN49 to KCD-Web (172.16.1.7) on 19 June 2026 — 24 days before the alert fired.** Whether this connection succeeded in compromising KCD-Web requires investigation of KCD-Web's own IIS and auth logs.

---

## 10. Full Report

### Verdict
```
TRUE POSITIVE — ACTIVE COMPROMISE
```

---

### Findings

| Field | Value |
|---|---|
| Alert Time | 2026-07-13 21:00 UTC / 2026-07-14 07:00 AEST |
| Event Time | 2026-07-13 20:20:30 UTC / 2026-07-14 06:20 AEST |
| Host | `DESKTOP-Q1HN49.kerningcitydental.ca` (172.16.1.4) |
| Compromised Account | `KCD-Contractor` |
| Attacker IP #1 | `42.1.67.220` — Mobifone / Vietnam / AS131429. AbuseIPDB: 342 reports, 100% confidence. VT: 9/91 malicious. Shodan: Windows Server 2022, hostname TEST1111111111, SMB/445 + WinRM/5985 exposed, CVE-2020-0796. |
| Attacker IP #2 | `162.192.142.215` — hostname DTBWIN2025SRV1 |
| Auth Method | NTLM via NtLmSsp |
| Earliest Attacker Presence | **2026-06-19 03:43 UTC — estimated dwell: 24 days** |
| Second Host at Risk | `KCD-Web` (172.16.1.7) — RDP connection from compromised host on 2026-06-19 |
| Suspected Persistence | `sethc.exe` spawned by `AtBroker.exe` under SYSTEM — T1546.008 Accessibility Feature Backdoor |
| Post-Exploitation | 10× Sysmon EventCode 25 (Process Tampering) |

---

### Investigation Summary

On 2026-07-11 19:55 UTC, `42.1.67.220` — a Windows Server 2022 jump box (Shodan hostname: `TEST1111111111`) hosted on Mobifone in Vietnam — began NTLM credential spraying against the `KCD-Contractor` account on `DESKTOP-Q1HN49` via its internet-exposed RDP port (3389). Three failures were recorded. The attack did not succeed that day.

On 2026-07-13, a second attacker IP, `162.192.142.215` (hostname: `DTBWIN2025SRV1`), began spraying the same account at 18:27 UTC. Three failure bursts occurred at 18:27, 18:34, and 18:42 UTC. At 19:01:17 UTC the credential was broken — a successful Type 3 Network logon was recorded. Three seconds later at 19:01:20 UTC the attacker unlocked the interactive desktop session (Type 7, User32), gaining visual control of the workstation. A 4648 (explicit credential reuse) event fired immediately. Two seconds into the session — at 19:01:22 UTC — `sethc.exe` was spawned by `AtBroker.exe` under SYSTEM, the hallmark of an Accessibility Feature Backdoor installation. This provides the attacker with a persistent SYSTEM shell from the RDP login screen, requiring no credentials and surviving reboots.

At 20:20:24 UTC, `42.1.67.220` returned and achieved its own successful Type 3 Network logon. At 20:20:30 UTC it unlocked the desktop session (Type 7) — this is the event that triggered the alert. Another 4648 fired, followed by 10 Sysmon EventCode 25 (Process Tampering) events between 20:20:41 and 20:25:15 UTC, indicating active process injection or hollowing. The attacker's network session remained open until 20:37:49 UTC — 17 minutes of access. The alert was raised 40 minutes after the event at 21:00 UTC.

Sysmon records establish that `42.1.67.220` was first present on DESKTOP-Q1HN49 on **2026-06-19 03:43 UTC**, 24 days before detection, and used that access to pivot toward KCD-Web (172.16.1.7) on RDP/3389. The legitimate contractor baseline IP (`74.15.244.54`, Bell Canada, Ottawa) has not appeared for 5 days.

---

### Who, What, When, Where, Why, How

**WHO**  
Account `KCD-Contractor` on `DESKTOP-Q1HN49.kerningcitydental.ca`. Two attacker jump boxes: `42.1.67.220` (TEST1111111111 / Vietnam) and `162.192.142.215` (DTBWIN2025SRV1). Legitimate contractor has not been seen from their known IP in 5 days — credentials are confirmed compromised.

**WHAT**  
Successful NTLM brute-force of the KCD-Contractor credential via internet-exposed RDP, leading to two separate interactive sessions with post-exploitation activity: explicit credential reuse (4648), suspected Accessibility Feature Backdoor installation (sethc.exe / SYSTEM), process tampering (Sysmon 25), and lateral movement attempt toward KCD-Web.

**WHEN**  
- Earliest attacker presence: **2026-06-19 03:43 UTC** (~24 days dwell)
- Brute force begins: **2026-07-11 19:55 UTC** (`42.1.67.220`)
- First successful compromise: **2026-07-13 19:01:20 UTC** (`162.192.142.215`) — AEST: 2026-07-14 05:01
- Backdoor installed: **2026-07-13 19:01:22 UTC**
- Second successful access: **2026-07-13 20:20:30 UTC** (`42.1.67.220`) — AEST: 2026-07-14 06:20
- Alert raised: 2026-07-13 21:00 UTC (40-minute lag)
- **Activity likely ongoing** — the sethc backdoor persists across reboots and does not require credentials

**WHERE**  
`DESKTOP-Q1HN49.kerningcitydental.ca` (172.16.1.4), Toronto Azure branch, entry via internet-facing RDP/3389. Secondary host at risk: `KCD-Web` (172.16.1.7). Ottawa estate not confirmed compromised from available data but should be verified.

**WHY**  
Motive not confirmed from available evidence. Given the dental clinic context (patient records, billing, insurance data), the likely objective is data exfiltration or ransomware staging. A 24-day dwell time suggests deliberate pre-positioning rather than opportunistic access.

**HOW**  
Internet-exposed RDP on a Windows 11 workstation with a weak or reused contractor credential. Attackers used NTLM credential spraying via dedicated jump-box infrastructure (both source IPs resolve to named Windows servers, indicating a tooled, multi-hop approach). On successful Type 3 Network auth, tooling automatically unlocked the RDP desktop (Type 7) and executed post-exploitation steps within seconds.

---

### Recommendations

1. **Immediately isolate DESKTOP-Q1HN49.** Do not rely on account lockout alone — if the sethc backdoor is installed, the attacker retains SYSTEM-level shell access from the RDP login screen with no credentials required.

2. **Forensically examine DESKTOP-Q1HN49** for: confirmed sethc.exe replacement (hash vs known-good); LSASS access (Sysmon EventCode 10); staged malware, credential dumps, exfiltrated data; new scheduled tasks, services, or registry Run keys created after 2026-06-19.

3. **Investigate KCD-Web (172.16.1.7) immediately.** The 2026-06-19 Sysmon record places the attacker's IP initiating RDP toward KCD-Web. Pull IIS and auth logs for connections from `42.1.67.220` and from `172.16.1.4` around that date.

4. **Reset the KCD-Contractor credential** across all systems. Also query `SigninLogs` in Defender/Sentinel for any cloud identity activity from `42.1.67.220` or `162.192.142.215` against the mahcyberdefense tenant.

5. **Remove internet-facing RDP from DESKTOP-Q1HN49.** This was an accepted risk — it has now materialised as a confirmed compromise vector. Gate access behind Azure Bastion or a VPN, or disable RDP entirely and manage the host through a jump server.

6. **Threat hunt the attacker IPs across the full estate.** Query all indexes for `42.1.67.220` and `162.192.142.215` across all KCD hosts (Toronto and Ottawa) to establish the true blast radius.

---

### IOCs

| Type | Value | Source |
|---|---|---|
| Attacker IP | `42[.]1[.]67[.]220` | AbuseIPDB / VirusTotal / Splunk |
| Attacker IP | `162[.]192[.]142[.]215` | Splunk 4624/4625 |
| Attacker hostname | `TEST1111111111` | Splunk src field / Shodan |
| Attacker hostname | `DTBWIN2025SRV1` | Splunk src field |
| Compromised account | `KCD-Contractor` | Splunk 4624 |
| Compromised host | `DESKTOP-Q1HN49[.]kerningcitydental[.]ca` (172.16.1.4) | Alert / Splunk |
| Lateral movement target | `172[.]16[.]1[.]7` (KCD-Web) / port 3389 | Sysmon EventCode 3 |
| Suspected persistence | `sethc[.]exe` (spawned by `AtBroker[.]exe` / SYSTEM) | Splunk EventCode 1 |
| Earliest dwell date | 2026-06-19 03:43:35 UTC | Sysmon EventCode 3 |

---

## 11. Key Takeaways

> These are the transferable lessons from this investigation.

**1. Logon Type 7 with a remote source IP is a detection gap, not a low-priority alert.**  
RDP reconnects generate Type 7, not Type 10. Any detection rule keyed only on Type 10 for RDP will miss an attacker reconnecting to an already-established session — or, as in this case, unlocking one they just created via Type 3.

**2. The src field carries the attacker's hostname — use it.**  
Both attacker IPs had named hostnames in the Splunk `src` field (`TEST1111111111`, `DTBWIN2025SRV1`). Cross-referencing these with Shodan confirmed they were not end-user machines but dedicated attack infrastructure. This is often overlooked.

**3. Start the investigation with scope before narrowing to the alerted event.**  
The alert fired on one unlock event. The true picture — a 24-day dwell, two attacker IPs, a probable backdoor, and a second host at risk — only emerged by stepping back to look at the full 30-day history for the source IP across all indexes.

**4. Account lockout does not close all access paths.**  
The Accessibility Feature Backdoor (T1546.008 / Sticky Keys) installed during the first session provides SYSTEM-level shell access via the RDP login screen before credentials are entered. Resetting the password or locking the account does not remove it.

**5. Internet-exposed RDP absorbs so much noise it buries signals.**  
1.46 million failed logon attempts in 7 days against `Administrator` on this one host. The KCD-Contractor compromise was hiding in that. When investigating credential-based alerts on exposed RDP hosts, filter to the specific account and source IP immediately rather than trying to work through the full 4625 dataset.

---

## 12. MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|---|---|---|
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Multiple 4625 failures from two IPs before success |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Internet-exposed RDP entry point, Type 3 + Type 7 logons |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | KCD-Contractor credentials used post-compromise |
| [T1546.008](https://attack.mitre.org/techniques/T1546/008/) | Accessibility Features | `sethc.exe` spawned by `AtBroker.exe` under SYSTEM |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | 10× Sysmon EventCode 25 (Process Tampering) |
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Local Accounts | KCD-Contractor is a local workstation account |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services (lateral movement) | RDP from DESKTOP-Q1HN49 → KCD-Web on 2026-06-19 |

