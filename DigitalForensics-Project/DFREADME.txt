Link: https://github.com/JophielArevalo/SOC-Portfolio/tree/main/digital_forensic

# 🔍 Digital Forensics Investigation — Alex Marshall Case

> A full end-to-end **Digital Forensics and Incident Response (DFIR)** investigation conducted as part of a Master of Cybersecurity major assignment. Four pieces of evidence are analysed — a **disk image**, a **network packet capture**, a **memory dump**, and a **mobile phone image** — to reconstruct the events surrounding the suspicious death of a university student, Alex Marshall.

> **Tools used:** The Sleuth Kit, RegRipper, Volatility, Wireshark, fcrackzip, SQLite, Bless Hex Editor, GHex, md5sum

---

## 📋 Table of Contents

1. [Case Overview](#-case-overview)
2. [Evidence Summary](#-evidence-summary)
3. [Evidence A — Disk Image (Desktop Computer)](#evidence-a--disk-image-desktop-computer)
   - [Setup & Integrity Verification](#setup--integrity-verification)
   - [Q1 — Who owns the computer?](#q1--who-owns-the-computer)
   - [Q2 — Installed and recently run programs](#q2--installed-and-recently-run-programs)
   - [Q3 — Recycle Bin recovery](#q3--recycle-bin-recovery)
   - [Q4 — State of mind indicators](#q4--state-of-mind-indicators)
4. [Evidence B — Network Capture (PCAP)](#evidence-b--network-capture-pcap)
   - [Q5 — Communicating parties & timestamps](#q5--communicating-parties--timestamps)
   - [Q6 — Browsers, OS, and IP addresses](#q6--browsers-os-and-ip-addresses)
   - [Q7 — Files transmitted on the network](#q7--files-transmitted-on-the-network)
   - [Q8 — Relationships of parties to victim](#q8--relationships-of-parties-to-victim)
5. [Evidence C — Memory Dump (Personal Laptop)](#evidence-c--memory-dump-personal-laptop)
   - [Q9 — Running applications](#q9--running-applications)
   - [Q10 — Recently visited web pages](#q10--recently-visited-web-pages)
   - [Q11 — Owner identity and connection to case](#q11--owner-identity-and-connection-to-case)
   - [Q12 — Computer password](#q12--computer-password)
6. [Evidence D — Mobile Phone Image (Android)](#evidence-d--mobile-phone-image-android)
   - [Q13 — Non-stock applications](#q13--non-stock-applications)
   - [Q14 — Contacts, messages, and calls](#q14--contacts-messages-and-calls)
   - [Q15 — Internet search history](#q15--internet-search-history)
   - [Q16 — Additional evidence linking owner to case](#q16--additional-evidence-linking-owner-to-case)
7. [Timeline Analysis](#-timeline-analysis)
8. [Final Conclusions](#-final-conclusions)
9. [Screenshots Index](#-screenshots-index)
10. [Command Reference](#-command-reference)

---

## 🗂️ Case Overview

**Subject:** Alex Marshall — university student, suspicious death  
**Investigation type:** Multi-evidence DFIR  
**Assignment:** Griffith University — Master of Cybersecurity — Digital Forensics Major Assignment  
**Date:** October 2024

The investigation examines four pieces of digital evidence collected from Alex Marshall's dorm room and apartment. The goal is to reconstruct Alex's life circumstances, identify persons of interest, and establish a timeline of events leading up to his death.

**Key persons identified:**

| Person | Alias / Handle | Relationship to Alex |
|--------|----------------|----------------------|
| Alex Marshall | AlexM21 | Victim |
| Lily Parker | LilyLaw | Girlfriend |
| Sophia Bennett | ArtLover99 / vb9945311@gmail.com | Secret romantic interest |
| DormKing | DormKing | Classmate / exam buyer |
| PartyDude | PartyDude | Classmate / exam buyer |
| BookWorm | BookWorm | Classmate |
| Oliver Marshall | — | Alex's father |
| Unknown | +61458230941 | Debt collector / loan shark |

---

## 📦 Evidence Summary

| Evidence | Type | Hash (MD5) | Description |
|----------|------|------------|-------------|
| Evidence A | Disk image (.dd) | `e2163d35fb453047af7534d12de89055` | Desktop computer from Alex's dorm room |
| Evidence B | Network capture (.pcap) | `b383bb9ae1dce23a4e72a0c192aafe80` | Network traffic from dormitory network |
| Evidence C | Memory dump (.vmem) | `610278c68947d89a587ea64987af5b85` | Laptop memory from Alex's bedroom |
| Evidence D | Mobile phone image (Android) | `cbf84de09de09b0143ebddefcdae2e3d9a7c` | Damaged Android phone |

> **Chain of custody:** All evidence hashes were verified using `md5sum` before analysis began. Analysis was performed on copies — never on the original evidence files.

---

## Evidence A — Disk Image (Desktop Computer)

### Setup & Integrity Verification

Before any analysis, a structured folder system is created to maintain chain of custody and evidence organisation:

```bash
# Create the working directory for Evidence A
# Good practice: one folder per evidence item, all under a /cases parent
mkdir -p /cases/EvidenceA/
```

**Extract the multi-part disk image:**

```bash
# Evidence A arrives as 11 split parts (.001 to .011)
# 'unzip' extracts compressed archives while preserving directory structure and permissions
unzip EvidenceA.zip -d /cases/EvidenceA/
```

**Reassemble the split parts into a single .dd image:**

```bash
# 'cat' concatenates multiple files sequentially into a single output file
# This joins all 11 parts into one complete raw disk image (.dd format)
cat EvidenceA.001 EvidenceA.002 EvidenceA.003 EvidenceA.004 \
    EvidenceA.005 EvidenceA.006 EvidenceA.007 EvidenceA.008 \
    EvidenceA.009 EvidenceA.010 EvidenceA.011 > EvidenceA.dd
```

**Verify integrity with MD5 hash:**

```bash
# md5sum generates a 128-bit hash fingerprint of the file
# Running this BEFORE and AFTER analysis confirms the evidence was not modified
md5sum EvidenceA.dd
# Expected output: e2163d35fb453047af7534d12de89055  EvidenceA.dd
```

> ⚖️ **Why hashing matters:** In a court of law, the ability to prove that evidence was not tampered with is essential. The MD5 hash acts as a fingerprint — if even one bit changes, the hash changes completely.

**Inspect the image structure:**

```bash
# img_stat shows image type, total size in bytes, and sector size
# This tells us what we're working with before we try to mount it
img_stat EvidenceA.dd
# Result: Image Type: raw | Size: 21474836480 bytes | Sector size: 512
```

**List disk partitions:**

```bash
# mmls shows the partition table of the disk image
# We look for the largest partition — typically the "Basic data partition" — as that's where user files live
mmls EvidenceA.dd
# The Basic data partition starts at sector 673792
```

**Calculate the mount offset and mount the partition:**

```bash
# The offset (in bytes) = partition start sector × sector size
# 673792 sectors × 512 bytes/sector = 344981504 bytes
# -o ro        : mount read-only (CRITICAL — never mount evidence read-write)
# -o loop      : treat the file as a block device
# -o offset=   : start reading from this byte position (skips the partition table)
sudo mount -o ro,loop,offset=344981504 EvidenceA.dd /mnt/windows_mount
```

📸 *See:* [`screenshots/README.md#01`](screenshots/README.md#01---evidence-a-disk-image-info)

---

### Q1 — Who owns the computer?

**Method 1 — Check Windows version and registered owner via RegRipper:**

```bash
# rip.pl is RegRipper's main script — it extracts data from Windows registry hive files
# -l lists all available plugins; grep filters for ones containing 'win'
rip.pl -l | grep win
# Result: 'winver' plugin found — reads Windows version and registered owner

# Run winver plugin against the SOFTWARE hive
# The SOFTWARE hive contains application settings, installed programs, and Windows metadata
rip.pl -r /mnt/windows_mount/Windows/System32/config/SOFTWARE -p winver
# Result: RegisteredOwner = "Windows User" (generic name set at install)
```

📸 *See:* [`screenshots/README.md#02`](screenshots/README.md#02---registered-owner-winver)

**Method 2 — Get the computer hostname:**

```bash
# The SYSTEM hive contains hardware config, services, and the computer name
# compname plugin extracts ComputerName and TCP/IP hostname values
rip.pl -r /mnt/windows_mount/Windows/System32/config/SYSTEM -p compname
# Result: ComputerName = DESKTOP-0N2DC4F
```

📸 *See:* [`screenshots/README.md#03`](screenshots/README.md#03---hostname-compname)

**Method 3 — List all user accounts from the SAM database:**

```bash
# The SAM (Security Account Manager) hive stores local user account information
# samparse parses all user accounts, including username, RID, last login, and account flags
# grep Username filters to show just the account names
rip.pl -r /mnt/windows_mount/Windows/System32/config/SAM -p samparse | grep Username
# Result: 5 accounts found — Administrator, Guest, DefaultAccount, WDAGUtilityAccount, Alex Marshall
```

> **Finding:** Alex Marshall (RID 1000) is the only non-system account and the only account with login activity, confirming he is the owner and primary user of this machine.

```bash
# Run samparse without grep to see full account details including last login timestamps
rip.pl -r /mnt/windows_mount/Windows/System32/config/SAM -p samparse
# Alex Marshall:
#   Account Created : 2024-08-27 13:02:28Z
#   Last Login Date : 2024-08-27 13:05:43Z
#   Login Count     : 2
```

📸 *See:* [`screenshots/README.md#04`](screenshots/README.md#04---sam-usernames)
📸 *See:* [`screenshots/README.md#05`](screenshots/README.md#05---alex-user-activity)

---

### Q2 — Installed and recently run programs

```bash
# Navigate directly into the mounted Windows filesystem to browse installed programs
# Program Files contains 64-bit applications
cd /mnt/windows_mount/Program\ Files/
ls
# Found: 7-Zip, Internet Explorer, ModifiableWindowsApps, VMware, Windows Defender,
#        Windows Mail, Windows NT, Windows Photo Viewer, WindowsPowerShell, Windows Security, Windows Sidebar

# Program Files (x86) contains 32-bit applications
cd /mnt/windows_mount/Program\ Files\ \(x86\)/
ls
# Found: Common Files, Internet Explorer, Microsoft, Microsoft.NET, Mozilla Firefox,
#        VideoLAN (VLC), Windows Defender, Windows Mail, Windows Photo Viewer, WindowsPowerShell

# Check Alex's Downloads folder for recently acquired installers
cd "/mnt/windows_mount/Documents and Settings/Alex Marshall/Downloads"
ls
# Found: 7z2408-x64.exe, Firefox Installer.exe, vlc-3.0.21-win32.exe, winzip76-downwz.exe
```

> **Finding:** Alex was actively installing software — 7-Zip, Firefox, VLC, and WinZip installers are in his Downloads folder, suggesting he was setting up a newly installed system.

📸 *See:* [`screenshots/README.md#06`](screenshots/README.md#06---program-files)
📸 *See:* [`screenshots/README.md#07`](screenshots/README.md#07---program-files-x86)
📸 *See:* [`screenshots/README.md#08`](screenshots/README.md#08---downloads-folder)

---

### Q3 — Recycle Bin recovery

```bash
# recbin.pl parses the $I metadata files in the Windows Recycle Bin
# $I files store: original filename, original path, file size, and deletion timestamp
# $R files store: the actual deleted file content
rip.pl -r /mnt/windows_mount/\$Recycle.Bin/ -p recbin
```

**Files recovered from Recycle Bin:**

| Filename | Original Path | Size | Deleted |
|----------|---------------|------|---------|
| privatenotes.txt | `C:\Alex Marshall\Documents\privatenotes.txt` | 14,336 bytes | 2024-08-27 13:15:35Z |
| rubbish.zip | `C:\Alex Marshall\Documents\rubbish.zip` | 63,400 bytes | 2024-08-27 13:15:35Z |

**Crack the password-protected zip file:**

```bash
# fcrackzip is a fast password cracker for zip archives
# -u  : use the unzip binary to verify cracked passwords (avoids false positives)
# -v  : verbose — show each attempt
# -D  : dictionary mode (use a wordlist, not brute force)
# -p  : path to the wordlist (rockyou.txt is a classic credential list)
fcrackzip -u -v -D -p /cases/EvidenceD/Sms/rockyou.txt "$RLY0J7N.zip"
# Result: PASSWORD FOUND: football
```

```bash
# Unzip the cracked archive to see its contents
unzip -P football "$RLY0J7N.zip"
# Extracted: UniversityWarning_Letter.pdf
```

> **Finding:** The zip contained a **university warning letter** addressed to Alex Marshall, dated March 15, 2024. The letter states he had failed courses, missed assignments, was on academic probation, and faced scholarship revocation. Additionally, allegations of unauthorized access to university systems are mentioned.

**Recover the disguised Word document (notes.jpg):**

```bash
# Alex saved a .docx file with a .jpg extension to disguise its true nature
# The 'file' command checks the actual file type by reading magic bytes (not the extension)
file notes.jpg
# Result: notes.jpg: Microsoft Word 2007+

# Open notes.jpg in Bless Hex Editor to find the DOCX magic number
# DOCX magic bytes: 50 4B 03 04 (this is a ZIP header — DOCX files are ZIP archives)
# Remove all bytes BEFORE 50 4B 03 04 to strip the fake JPEG header
# Save and open as a .docx file
```

> **Finding:** The disguised file was Alex Marshall's **Last Will and Testament** — a deeply personal document in which he apologises to his parents, Lily, and Sophia, distributes his belongings to family, and says goodbye. This strongly indicates Alex anticipated something fatal happening to him.

📸 *See:* [`screenshots/README.md#09`](screenshots/README.md#09---university-warning-letter)
📸 *See:* [`screenshots/README.md#10`](screenshots/README.md#10---last-will-and-testament)

---

### Q4 — State of mind indicators

Browsing Alex's personal documents folder reveals a picture of a young man under severe pressure:

```bash
# Navigate to Alex's personal documents
cd "/mnt/windows_mount/Users/Alex Marshall/My Documents"
ls
# Found: Dad_Email_March.pdf, Debt_Tracker.csv, Expenses_March.csv,
#        InternshipOffer_Reynolds.pdf, journal1.txt, journal2.txt, Mum_Email_April.jpg
```

**Key documents and what they reveal:**

| Document | Date | Content |
|----------|------|---------|
| `Dad_Email_March.pdf` | March 10, 2024 | Father warns Alex that his grades are unacceptable and threatens to cut financial support |
| `Debt_Tracker.csv` | April 2024 | Lists $7,450 in total debts — credit cards maxed, private loan of $5,000 marked urgent |
| `journal1.txt` | February 28, 2024 | Alex confesses he began selling exam answers to cover debts; describes guilt and fear of being caught |
| `journal2.txt` | April 5, 2024 | Alex describes drowning in debt, his father's pressure, and contemplating dropping out |
| `Mum_Email_April.jpg` | April 5, 2024 | Alex's mother expresses support and encourages him to seek help |
| `InternshipOffer_Reynolds.pdf` | April 2024 | TechVision internship offer from Professor Mark Reynolds, deadline April 10 |

**Debt breakdown from `Debt_Tracker.csv`:**

| Creditor | Amount | Status |
|----------|--------|--------|
| Credit Card 1 | $1,200 | Maxed out |
| Credit Card 2 | $800 | Maxed out |
| Lily Parker | $300 | Personal loan, urgent |
| Private Loan | $5,000 | Unknown source, urgent |
| Friends | $150 | Various small loans |
| **Total** | **$7,450** | |

> **Conclusion:** Alex was experiencing severe financial, academic, and emotional stress simultaneously. The combination of mounting debt, academic misconduct, parental pressure, and a hidden romantic relationship — plus a Last Will and Testament — strongly suggests Alex was aware his situation was dangerous and potentially fatal.

📸 *See:* [`screenshots/README.md#11`](screenshots/README.md#11---alex-personal-documents)
📸 *See:* [`screenshots/README.md#12`](screenshots/README.md#12---debt-tracker)
📸 *See:* [`screenshots/README.md#13`](screenshots/README.md#13---journal-1)
📸 *See:* [`screenshots/README.md#14`](screenshots/README.md#14---journal-2)

---

## Evidence B — Network Capture (PCAP)

```bash
# Create a dedicated folder and verify integrity before analysis
mkdir -p /cases/EvidenceB/
md5sum EvidenceB.pcap
# Expected: b383bb9ae1dce23a4e72a0c192aafe80

# Open the .pcap file in Wireshark for analysis
wireshark EvidenceB.pcap
```

> A `.pcap` file is a **packet capture** — a recording of all network traffic on a network interface during a specific time period. Wireshark can replay, filter, and decode this traffic to reconstruct conversations and file transfers.

---

### Q5 — Communicating parties & timestamps

**Method — Follow TCP streams in Wireshark:**

```
Wireshark → Statistics → Conversations → TCP tab
Sort by Duration or Bytes to find the most significant exchanges
Right-click any conversation → Follow TCP Stream
```

> Following TCP streams reassembles the raw bytes of a TCP session back into readable text — this is how chat messages and file transfers become visible.

**Communications found:**

**1. CheatChat group (Packet 272 — Alex's endpoint)**

| Handle | Message | Timestamp |
|--------|---------|-----------|
| AlexM21 | "Alright, the files are ready. Bio101 answers, top tier. Who's in?" | 2024-09-01 07:57:11Z |
| DormKing | "I'm in. How much are we talking?" | 2024-09-01 07:57:51Z |
| DormKing | "$200 for the full set. Same as last time." | 2024-09-01 07:58:26Z |
| PartyDude | "Dude you're saving my life. Finals are killing me." | 2024-09-01 07:59:02Z |
| AlexM21 | "Done. Won't get the answers better anywhere else." | 2024-09-01 08:01:38Z |
| AlexM21 | "Yep I'll leave it on the ftp server. Make sure you delete everything after." | 2024-09-01 08:02:32Z |
| BookWorm | "Careful guys. Heard the faculty is cracking down." | 2024-09-01 08:03:22Z |
| AlexM21 | "Relax, they'll never trace it back. Just keep it quiet." | 2024-09-01 08:03:59Z |

**First transmission:** `2024-09-01 07:57:11Z`  
**Last transmission (all captures):** `2024-09-01 08:46:20Z`

**2. Private chat — Alex and Sophia (ArtLover99): 08:09:28 – 08:12:26Z**

Sophia pressures Alex to make a decision between her and Lily. Alex asks for more time.

**3. Private chat — Alex and Lily (LilyLaw): 08:20:53 – 08:23:51Z**

Lily confronts Alex about seeing someone else. Alex denies it. They agree to talk in person.

**4. Private chat — DormKing and PartyDude (Packet TCP stream 3): 08:16:09 – 08:46:20Z**

DormKing instructs PartyDude to break into Alex's room while he's away and steal the FTP session key. The plan fails — PartyDude enters DormKing's room by mistake.

📸 *See:* [`screenshots/README.md#15`](screenshots/README.md#15---cheatchat-stream)
📸 *See:* [`screenshots/README.md#16`](screenshots/README.md#16---dormking-partydude-stream)

---

### Q6 — Browsers, OS, and IP addresses

```
Wireshark → Filter bar → type: http → Enter
Select any HTTP packet → Inspect the "User-Agent" field in the HTTP headers
Cross-reference User-Agent strings at useragents.net
```

> The **User-Agent** string is sent by browsers with every HTTP request. It reveals the browser name, version, and operating system of the device making the request.

| IP Address | Browser | Operating System |
|------------|---------|-----------------|
| `10.10.10.33` | Chrome 47 | Windows 7 (WOW64) |
| `10.10.10.1` | Chrome 47 | Windows 7 (WOW64) |
| `10.10.10.56` | Safari 9.0.2 | Mac OS X 10.11.2 |
| `10.10.10.22` | Safari 9.0.2 | Mac OS X 10.11.2 |
| `10.10.10.44` | Firefox 15.0.1 | Ubuntu Linux x86_64 |
| `10.10.10.254` | Firefox 129.0 | Ubuntu Linux x86_64 (server) |

> All devices communicated with the local server at `10.10.10.254` — likely the dormitory's shared server hosting the CheatChat application and FTP service.

📸 *See:* [`screenshots/README.md#17`](screenshots/README.md#17---http-user-agents)

---

### Q7 — Files transmitted on the network

```
Wireshark → Filter bar → type: ftp → Enter
Follow each FTP TCP stream to see the commands and responses
```

> **FTP (File Transfer Protocol)** is an unencrypted protocol for transferring files. Because it's unencrypted, Wireshark can read every command, filename, and file content in the clear.

**FTP stream 694 — key findings:**

```
USER anonymous          ← FTP logged in as anonymous (no credentials required)
SYST                    ← Queried server OS type: Unix L8
TYPE A                  ← ASCII mode (for text files)
CWD pub                 ← Changed to the 'pub' (public) directory
LIST                    ← Listed directory contents
TYPE I                  ← Switched to Binary mode (for binary files)
STOR sslkeyfile         ← Uploaded a file named 'sslkeyfile'
553 Could not create file  ← Upload failed (permissions issue)
STOR sslkeyfile         ← Attempted again
226 Transfer complete   ← Second upload succeeded
QUIT / 221 Goodbye
```

> **Finding:** DormKing's plan (via PartyDude) was to steal Alex's TLS/SSL session key and upload it to the FTP server — allowing them to decrypt Alex's encrypted traffic and steal the exam answers without paying. The upload eventually succeeded.

**Files found in the FTP `pub` directory:**

- `test.txt` (5 Aug 31 2021)
- `upload.txt` (5 Aug 31 2021)

📸 *See:* [`screenshots/README.md#18`](screenshots/README.md#18---ftp-stream-694)
📸 *See:* [`screenshots/README.md#19`](screenshots/README.md#19---pub-directory)

---

### Q8 — Relationships of parties to victim

| Person | Role | Connection to Alex |
|--------|------|--------------------|
| DormKing | Classmate, exam buyer | Bought exam answers; plotted to steal them via FTP session key theft |
| PartyDude | Classmate, exam buyer | Carried out (unsuccessfully) DormKing's break-in plan |
| BookWorm | Classmate | Aware of the scheme; warned about faculty crackdown |
| Sophia (ArtLover99) | Secret girlfriend | Romantically involved with Alex; pressure him to leave Lily |
| Lily (LilyLaw) | Girlfriend | Official partner; suspects Alex is seeing someone else; issued ultimatum |

---

## Evidence C — Memory Dump (Personal Laptop)

```bash
# Create a folder and verify integrity
mkdir -p /cases/EvidenceC/
md5sum EvidenceC.vmem
# Expected: 610278c68947d89a587ea64987af5b85
```

> A `.vmem` file is a **virtual memory dump** — a snapshot of a computer's RAM at a specific moment. Unlike disk forensics (which deals with stored files), memory forensics captures what was actively running: open applications, network connections, passwords in memory, and running processes.

**Determine the memory image profile:**

```bash
# volatility's imageinfo plugin analyses the memory dump and suggests the correct OS profile
# The profile tells Volatility which Windows version's data structures to use for parsing
vol.py -f EvidenceC.vmem imageinfo
# Suggested Profile: Win7SP1x64 (Windows 7 Service Pack 1, 64-bit)
```

**Identify the machine owner via registry hives:**

```bash
# hivelist shows all registry hives loaded in memory
# We look for user-specific hives (NTUSER.DAT) which reveal the logged-in username
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 hivelist
# Found: C:\Users\Sophia Bennett\ntuser.dat
# Finding: This laptop belongs to Sophia Bennett — NOT Alex Marshall
```

📸 *See:* [`screenshots/README.md#20`](screenshots/README.md#20---evidence-c-image-type)
📸 *See:* [`screenshots/README.md#21`](screenshots/README.md#21---registry-hives)

---

### Q9 — Running applications

```bash
# pslist lists all processes that were running when the memory dump was taken
# Shows process name, PID (process ID), parent PID, and start time
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 pslist
```

**Active processes at time of memory capture:**

| Process | Category |
|---------|----------|
| Firefox | Web browser (key — network connections) |
| Thunderbird | Email client (key — email evidence) |
| Mynotepad++ | Text editor (key — note contents in memory) |
| Explorer | Windows shell |
| Taskhost | Windows task host |
| Dwm | Desktop Window Manager |
| Vmtoolsd | VMware tools (confirms this is a VM) |
| Csrss, Winlogon, Dllhost | System processes |

📸 *See:* [`screenshots/README.md#22`](screenshots/README.md#22---pslist-processes)

---

### Q10 — Recently visited web pages

```bash
# netscan identifies all active TCP/UDP network connections in the memory dump
# Shows local IP:port, remote IP:port, connection state, and the process that owns the connection
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 netscan
```

**Active connections at time of memory capture:**

| Process | Remote IP | Port | State |
|---------|-----------|------|-------|
| firefox.exe | 142.250.66.195 | 443 | ESTABLISHED |
| firefox.exe | 18.155.212.56 | 443 | ESTABLISHED |
| firefox.exe | 172.217.167.100 | 443 | ESTABLISHED |
| thunderbird.exe | 74.125.130.109 | 993 | ESTABLISHED |
| svchost.exe | 18.155.212.56 | 443 | ESTABLISHED |

> **Finding:** Firefox was actively connected to multiple HTTPS endpoints (Google services at 142.250.x and 172.217.x), and Thunderbird was connected to an IMAP mail server (port 993). This confirms active browsing and email activity at the time of the dump.

📸 *See:* [`screenshots/README.md#23`](screenshots/README.md#23---netscan-connections)

---

### Q11 — Owner identity and connection to case

**Extract email address from memory strings:**

```bash
# 'strings' extracts all printable character sequences from the binary memory dump
# Piping through grep narrows results to email addresses
strings EvidenceC.vmem | grep "gmail.com"
# Result: Vb9945311@gmail.com  Sophia Bennet
```

> **Finding:** The laptop belongs to **Sophia Bennett** — the same person Alex was secretly romantically involved with, as seen in the network capture evidence.

**Extract Sophia's Notepad++ journal entries from memory:**

```bash
# memdump extracts all memory pages belonging to a specific process
# -p 4360 : the PID of the Mynotepad++ process (from pslist)
# -D Notepad/ : output directory for the dump
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 memdump -p 4360 -D Notepad/

# Open the output file in GHex and search for the string 'Alex' to find her journal entries
```

**Key extracts from Sophia's journals:**

> *"It's getting harder to control my thoughts about Alex. I've started keeping track of where he goes, who he talks to, what he does when he's not with me."*

> *"I saw them together again today, Lily and Alex, and it was like a knife in my heart. I wanted to scream, to grab him and make him understand that she doesn't deserve him."*

> *"I'll do whatever it takes to make sure he realizes that we're meant to be together."*

**Professor Kane / Victor Ivanov email found in memory:**

An email to Sophia from someone identifying as "Victor Ivanov" (via `vb9945311@gmail.com` — the same address as Sophia) offers to protect her work and warns that "your enemies are closing in." This suggests Sophia may be connected to a larger criminal network.

> **Conclusion:** Sophia Bennett was obsessively fixated on Alex, tracked his movements, and expressed inability to accept his relationship with Lily. Her journals reveal escalating emotional instability. The cryptic email from "Victor Ivanov" adds an additional layer of criminal connection.

📸 *See:* [`screenshots/README.md#24`](screenshots/README.md#24---sophia-email-strings)
📸 *See:* [`screenshots/README.md#25`](screenshots/README.md#25---sophia-journal-notepad)

---

### Q12 — Computer password

```bash
# lsadump extracts LSA (Local Security Authority) secrets from memory
# These can include: autologin passwords, service account credentials, DPAPI keys
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 lsadump
# Result: Alexisbeautifull
```

> **Finding:** Sophia's laptop password was `Alexisbeautifull` — further evidence of her obsessive fixation on Alex Marshall.

📸 *See:* [`screenshots/README.md#26`](screenshots/README.md#26---lsadump-password)

---

## Evidence D — Mobile Phone Image (Android)

```bash
# Evidence D is a 7-zip archive (not a standard zip)
# Use 7zip to extract the Android disk image
7z x EvidenceD.7z -o/cases/EvidenceD/

# The most significant file is dm-1 (the main data partition of the Android device)
md5sum dm-1
# Expected: cbf84de09de09b0143ebddefcdae2e3d9a7c

# Mount the Android partition read-only for analysis
sudo mount -o loop dm-1 /mnt/e01/
```

> Android stores almost all user data in SQLite databases — contacts, call logs, SMS messages, browser history. The `find` command is the primary tool for locating these databases within the mounted image.

---

### Q13 — Non-stock applications

```bash
# APK files are Android application packages — the equivalent of Windows .exe files
# 'find' recursively searches the filesystem for files matching the pattern *.apk
# Non-stock apps are those not part of the base Android OS
find /mnt/e01 -name "*.apk"
```

**Non-stock applications found:**

| App | Category |
|-----|----------|
| Facebook | Social media |
| Angry Birds | Game |
| Tencent | Messaging / Gaming |
| Twitter | Social media |
| Bubble Shooter | Game |

📸 *See:* [`screenshots/README.md#27`](screenshots/README.md#27---non-stock-apks)

---

### Q14 — Contacts, messages, and calls

**Call log analysis:**

```bash
# Android stores call history in a SQLite database
# 'find' locates it; then we copy it out and open with SQLite browser
find /mnt/e01 -name "*call*"
# Target: /mnt/e01/data/com.android.providers.contacts/databases/calllog.db

# Copy the database out (need to change permissions to view as normal user)
sudo cp /mnt/e01/data/com.android.providers.contacts/databases/calllog.db /cases/EvidenceD/
sudo chmod 644 /cases/EvidenceD/calllog.db

# Open with SQLite browser to read the call records
```

**Call history — September 14, 2024:**

| # | Number | Contact | Time | Duration | Outcome |
|---|--------|---------|------|----------|---------|
| 1 | +61449857236 | Lily Parker | 10:58:53 AM UTC | 0s | No answer |
| 2 | +61449857236 | Lily Parker | 10:58:56 AM UTC | 0s | No answer |
| 3 | +61449857236 | Lily Parker | 10:58:59 AM UTC | 0s | No answer |
| 4 | +61449857236 | Lily Parker | 10:59:02 AM UTC | 0s | No answer |
| 5 | +61417692485 | Sophia Bennett | 10:59:22 AM UTC | 1:10 | Connected |

> **Finding:** Alex tried to reach Lily four times with no answer, then immediately called Sophia and spoke for 70 seconds. This was his last recorded phone activity.

**Contact list — with deleted contact recovery:**

```bash
# Primary contacts database
find /mnt/e01 -name "*contact*"
# Target: /mnt/e01/data/com.android.providers.contacts/databases/contacts2.db

# Open in SQLite — 4 contacts visible, but 3 were deleted
# Contacts2.db shows: Lily Parker, Sophie Bennett, Mum, Dad

# Recover deleted contacts from the WAL (Write-Ahead Log) file
# WAL files contain recent changes not yet committed to the main database — older versions of deleted records
# Open icing_contacts.db-wal in Bless Hex Editor and search for readable strings
```

**Recovered deleted contacts (from WAL backup):**

The hex editor reveals names and phone numbers of contacts Alex deleted before his death — suggesting a deliberate attempt to erase connections to certain people.

📸 *See:* [`screenshots/README.md#28`](screenshots/README.md#28---call-history)
📸 *See:* [`screenshots/README.md#29`](screenshots/README.md#29---contact-list)
📸 *See:* [`screenshots/README.md#30`](screenshots/README.md#30---deleted-contacts-hex)

**SMS messages:**

```bash
# Android SMS messages are stored in the mmssms.db database
find /mnt/e01 -name "*sms*"
# Target: /mnt/e01/user_de/0/com.android.providers.telephony/databases/mmssms.db
```

**SMS conversations — September 14, 2024:**

| Contact | Time Window | Key Content |
|---------|-------------|-------------|
| Lily Parker | 12:51:36 – 12:53:03 PM UTC | Lily demands Alex end things with "her". Alex deflects. Lily threatens consequences. |
| Sophia Bennett | 12:53:34 – 12:55:07 PM UTC | Sophia demands Alex choose her. Alex asks for more time. |
| Sophia Bennett | 12:58:08 – 12:59:21 PM UTC | Sophia says she can't take it anymore. Alex says "It's either me or her." |
| Unknown (+61458230941) | 12:55:30 – 12:56:42 PM UTC | Debt threats — payment overdue ultimatums ("Time's up. You don't want to see what happens if you keep stalling.") |

> **Critical finding:** The unknown number `+61458230941` is not in Alex's contact list and was not among the contacts he deleted — suggesting this person was someone he never saved, likely a loan shark or debt collector. The messages contain explicit threats.

📸 *See:* [`screenshots/README.md#31`](screenshots/README.md#31---sms-messages)

---

### Q15 — Internet search history

```bash
# Android browser history is stored in a SQLite database
find /mnt/e01 -name "*History*"
# Open the History database in SQLite browser
```

**Alex's recent searches — revealing a person preparing to disappear or protect himself:**

| Search Query | Implication |
|--------------|-------------|
| `nearest campus security office` | Considering reporting something or seeking protection |
| `how to delete messages permanently on Android` | Attempting to cover tracks |
| `how to block calls from a specific number` | Trying to cut off the unknown threatening number |
| `emergency loan options for students` | Desperately seeking money to repay debt |
| `cheap burner phones near me` | Planning to use an untraceable device |
| `Android Archive or delete messages, calls` | Further evidence scrubbing |
| `California Community Colleges Chancellor's Office` | Possibly researching appeals or transfer |

📸 *See:* [`screenshots/README.md#32`](screenshots/README.md#32---browser-search-history)

---

### Q16 — Additional evidence linking owner to case

**Partial emails recovered from `bigTopDataDB.1204881091-wal`:**

```bash
# This WAL file from a Google services database contains fragments of Gmail messages
# Open in a text editor to extract readable email content
```

| From | Subject | Key Content |
|------|---------|-------------|
| Oliver Marshall (father) | Final Warning | Threatens to cut off Alex's bank account if he doesn't show responsibility |
| Alex to Lily | I'm Sorry | Apologises for hurting her; asks her not to give up on him |
| Alex to Sophia (vb9945311@gmail.com) | We Need to Talk | Tells Sophia things have gotten too complicated; wants to end the relationship |
| Saul Reynolds (university) | Urgent: Academic Integrity | Informs Alex of formal allegations regarding exam answer sales |

**Encrypted audio file:**

```bash
# An encrypted file 'recording.aes' was found in Alex's Downloads folder
# AES encryption requires both a key and an initialization vector (IV) to decrypt
# The key was not found in any of the four evidence pieces — Alex may have distributed it intentionally
file recording.aes
# Result: data (encrypted binary)
```

> **Finding:** The encrypted recording may contain critical audio evidence. Alex appears to have intentionally distributed the decryption key across multiple locations or people — suggesting he wanted it found only under specific circumstances.

📸 *See:* [`screenshots/README.md#33`](screenshots/README.md#33---alex-sophia-photos)
📸 *See:* [`screenshots/README.md#34`](screenshots/README.md#34---encrypted-recording)

---

## 📅 Timeline Analysis

| Date | Time | Event | Source |
|------|------|-------|--------|
| Feb 28, 2024 | — | Alex's journal 1: begins selling exam answers due to financial pressure | Evidence A |
| Mar 10, 2024 | — | Father's email: threatens to cut financial support over poor grades | Evidence A |
| Mar 15, 2024 | — | University warning letter: academic probation, exam sale allegations | Evidence A |
| Mar 31, 2024 | — | Expenses spreadsheet created | Evidence A |
| Apr 1, 2024 | — | Internship offer from TechVision (Prof. Reynolds), deadline Apr 10 | Evidence A |
| Apr 5, 2024 | — | Journal 2: drowning in debt, considering dropping out | Evidence A |
| Apr 5, 2024 | — | Mother's supportive email | Evidence A |
| Apr 2024 | Various | Debt tracker: Credit cards maxed, $5,000 private loan urgent | Evidence A |
| Aug 27, 2024 | 13:02:28Z | Windows installation date — new computer setup | Evidence A |
| Aug 27, 2024 | 13:05:43Z | Alex's last login to the Windows machine | Evidence A |
| Aug 27, 2024 | 13:15:35Z | `privatenotes.txt` and `rubbish.zip` deleted from Documents | Evidence A |
| Sep 1, 2024 | 07:57:11Z | CheatChat group: Alex offers Bio101 exam answers for $200 | Evidence B |
| Sep 1, 2024 | 08:02:32Z | Alex instructs buyers to use FTP server for the drop | Evidence B |
| Sep 1, 2024 | 08:09:28Z | Private chat: Sophia pressures Alex to choose her over Lily | Evidence B |
| Sep 1, 2024 | 08:16:09Z | DormKing instructs PartyDude to steal Alex's FTP session key | Evidence B |
| Sep 1, 2024 | 08:20:53Z | Lily confronts Alex about seeing someone else | Evidence B |
| Sep 1, 2024 | 08:42:54Z | FTP session key successfully uploaded to server | Evidence B |
| Sep 14, 2024 | 10:58:53Z | Alex calls Lily 4 times — no answer | Evidence D |
| Sep 14, 2024 | 10:59:22Z | Alex calls Sophia — 1 min 10 sec conversation | Evidence D |
| Sep 14, 2024 | 12:51:36Z | SMS: Lily threatens to expose Alex if he doesn't end it with "her" | Evidence D |
| Sep 14, 2024 | 12:53:34Z | SMS: Sophia demands Alex make a final decision | Evidence D |
| Sep 14, 2024 | 12:55:30Z | SMS: Unknown number (+61458230941) threatens Alex over unpaid debt | Evidence D |
| Sep 14, 2024 | 12:59:21Z | Last recorded SMS message | Evidence D |

---

## 🧾 Final Conclusions

This investigation identified multiple persons of interest and risk factors contributing to Alex Marshall's death:

**Primary persons of interest:**

**Lily Parker** — Alex's official girlfriend who issued threats and was aware of his infidelity. The four unanswered calls on September 14 and her threatening SMS messages place her in a confrontational position on what appears to be the day of Alex's death.

**Sophia Bennett** — Evidence from her laptop (memory dump) reveals an obsessive, controlling fixation on Alex. Her journal entries describe surveillance of Alex's movements and an inability to accept his relationship with Lily. Her password (`Alexisbeautifull`) and the cryptic email from "Victor Ivanov" suggest she may have connections to organised criminal elements.

**Unknown (+61458230941)** — The debt collector's threatening messages on September 14 represent the most immediate physical danger. A $5,000 private loan from an unknown source with an urgent status — and explicit payment ultimatums — suggests this may be a loan shark or organised crime connection.

**Key forensic findings:**

- Alex wrote and hid a **Last Will and Testament** on his computer — he anticipated his death
- Alex was **actively deleting evidence** (contacts, messages, files) in the hours before his death — he was trying to protect someone or cover his tracks
- Alex was **searching for ways to disappear** (burner phones, blocking numbers, deleting messages)
- The **encrypted `recording.aes`** file may contain critical evidence — its decryption key was never found
- Alex's email to Sophia saying "We Need to Talk" on Sep 14 suggests he was ending the relationship — which could have triggered a violent response

> Multiple converging factors — debt threats, relationship conflicts, academic exposure, and family pressure — created a perfect storm around Alex Marshall in the final days of his life.

---

## 📸 Screenshots Index

See [`screenshots/README.md`](screenshots/README.md) for the full annotated index of all 34 screenshots with descriptions of what each one shows and what to look for.

---

## 📋 Command Reference

See [`evidence-a/commands.md`](embeds) for a full reference of every command used across all four evidence items, with flags explained.

---

## 📁 Repository Structure

```
digital-forensics-lab/
├── README.md                    ← This file — full investigation walkthrough
├── screenshots/
│   └── README.md                ← Annotated screenshot index (34 entries)
├── evidence-a/
│   └── commands.md              ← All disk forensics commands
├── evidence-b/
│   └── commands.md              ← Wireshark filters and FTP analysis
├── evidence-c/
│   └── commands.md              ← Volatility memory forensics commands
├── evidence-d/
│   └── commands.md              ← Android forensics commands
└── reports/
    └── final-report-summary.md  ← Condensed findings and conclusions
```

---

*Griffith University — Master of Cybersecurity — Digital Forensics Major Assignment — October 2024*
