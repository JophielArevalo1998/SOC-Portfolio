# 🧠 Evidence C — Memory Forensics Command Reference

> All Volatility commands used to analyse the RAM dump from the personal laptop found in Alex's bedroom.

---

## Setup & Integrity Verification

```bash
# Create dedicated folder for Evidence C
mkdir -p /cases/EvidenceC/

# Extract the memory dump
unzip EvidenceC.zip -d /cases/EvidenceC/
cd /cases/EvidenceC/

# Verify integrity before analysis
# A .vmem file is a VMware Virtual Machine memory dump — a snapshot of RAM
md5sum EvidenceC.vmem
# Expected: 610278c68947d89a587ea64987af5b85
```

> **What is a .vmem file?** VMware saves the complete contents of a virtual machine's RAM to a `.vmem` file when the VM is suspended or snapshotted. This file contains everything that was in memory at that moment: running processes, open files, network connections, passwords, and fragments of documents.

---

## Determining the Memory Profile

```bash
# Before running any analysis, Volatility needs to know which OS version produced the dump
# imageinfo analyses the memory structure and suggests matching OS profiles
# Different Windows versions store data in different memory locations and formats
vol.py -f EvidenceC.vmem imageinfo

# Output (abbreviated):
# Suggested Profile(s): Win7SP1x64, Win7SP0x64, Win2008R2SP0x64
# AS Layer1: FileAddressSpace
# PAE type: No PAE
# DTB: 0x187000L
# Image date and time: 2024-09-08 22:26:34 UTC
# Image local date and time: 2024-09-09 08:26:34

# Use Win7SP1x64 for all subsequent commands (first suggestion = best match)
# Add --profile=Win7SP1x64 to every volatility command
```

---

## Identifying the Machine Owner

```bash
# hivelist shows all Windows registry hive files that are loaded in memory
# Registry hives are the binary files that make up the Windows Registry
# The NTUSER.DAT hive is user-specific — its path reveals the username
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 hivelist

# Critical output line:
# 0xfffff8a0013d4010  0x000000009514801  ??\C:\Users\Sophia Bennett\AppData\Local\Microsoft\Windows\UsrClass.dat
# 0xfffff8a0001ea010  0x000000000a971010  ??\C:\Users\Sophia Bennett\ntuser.dat
#                                                  ^^^^^^^^^^^^^^
#                                   This path reveals the logged-in user: Sophia Bennett
```

---

## Q9 — Listing Running Processes

```bash
# pslist walks the doubly-linked list of EPROCESS structures in kernel memory
# This is the same list Windows uses internally to track processes
# Shows: process name, PID, parent PID (PPID), number of threads, start time
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 pslist

# Key processes to note:
# firefox.exe     PID 3512  — web browser (network connections, browsing history)
# thunderbird.exe PID 1892  — email client (emails in memory)
# Mynotepad++.exe PID 4360  — text editor (open documents in memory)
# explorer.exe    PID 2200  — Windows shell (open folder windows)
# vmtoolsd.exe    PID 992   — VMware tools (confirms this is a virtual machine)

# Alternative: pstree shows parent/child relationships between processes
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 pstree
```

---

## Q10 — Network Connections

```bash
# netscan scans memory for network socket structures
# Unlike netstat (which requires a live system), netscan works on offline memory dumps
# Shows: protocol, local address:port, remote address:port, state, PID, process name
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 netscan

# Key connections found:
# firefox.exe → 142.250.66.195:443  ESTABLISHED  (Google services — HTTPS)
# firefox.exe → 18.155.212.56:443   ESTABLISHED  (Amazon/AWS CDN — HTTPS)
# firefox.exe → 172.217.167.100:443 ESTABLISHED  (Google services — HTTPS)
# thunderbird.exe → 74.125.130.109:993 ESTABLISHED (Google Gmail IMAP — encrypted mail)
# svchost.exe → 18.155.212.56:443  ESTABLISHED  (Windows Update or cloud service)

# Port reference:
# 443  = HTTPS (encrypted web traffic)
# 993  = IMAPS (encrypted email retrieval)
# 3587 = LISTENING (local service waiting for connections)
```

---

## Q11 — Identifying the Owner and Extracting Journals

```bash
# strings extracts all printable ASCII and Unicode character sequences from the binary dump
# The minimum length filter (default 4 chars) reduces noise
# Piping to grep narrows results to email-related strings
strings EvidenceC.vmem | grep "gmail.com"
# Result: Vb9945311@gmail.com  Sophia Bennet

# Cross-reference: this email matches "ArtLover99" from Evidence B network capture
# Sophia Bennett is confirmed as both the laptop owner and Alex's secret girlfriend

# ---- EXTRACTING NOTEPAD++ JOURNAL CONTENT ----

# memdump extracts ALL memory pages belonging to a specific process into a file
# This captures everything the process had loaded in RAM — including open documents
# -p 4360 : PID of Mynotepad++ (from pslist)
# -D Notepad/ : output directory (will be created)
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 memdump -p 4360 -D /cases/EvidenceC/Notepad/

# The output file will be: /cases/EvidenceC/Notepad/4360.dmp
# This binary file contains the raw memory of Notepad++ including all open documents

# Open in GHex hex editor:
ghex /cases/EvidenceC/Notepad/4360.dmp

# In GHex: Edit → Find (Ctrl+F) → search for the string "Alex"
# Readable text will appear in the right pane of the hex editor
# Navigate through all occurrences to find Sophia's journal entries
```

---

## Q11 — Extracting Emails from Thunderbird Memory

```bash
# memdump for Thunderbird to extract email content from memory
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 memdump -p 1892 -D /cases/EvidenceC/Thunderbird/

# strings + grep to find email addresses and subjects in the Thunderbird dump
strings /cases/EvidenceC/Thunderbird/1892.dmp | grep -i "@gmail.com"
strings /cases/EvidenceC/Thunderbird/1892.dmp | grep -i "Subject:"
strings /cases/EvidenceC/Thunderbird/1892.dmp | grep -i "From:"
```

---

## Q12 — Extracting the Password

```bash
# lsadump extracts LSA (Local Security Authority) secrets from memory
# LSA secrets can contain:
# - Default passwords (for systems configured with autologin)
# - Service account credentials
# - Cached domain credentials
# - DPAPI master keys
# - RDP certificate private keys
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 lsadump

# Result: DefaultPassword = Alexisbeautifull
# This is Sophia's Windows autologin password
# The content of the password is direct evidence of obsessive fixation on Alex Marshall
```

---

## Additional Volatility Commands (Optional Investigation)

```bash
# dlllist shows all DLLs loaded by a specific process
# Useful for detecting injected malicious DLLs
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 dlllist -p 3512

# handles shows all open file handles for a process
# Can reveal which files were open in Firefox at the time of the dump
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 handles -p 3512 -t File

# cmdline shows the command line used to launch each process
# Useful for detecting processes launched with suspicious arguments
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 cmdline

# filescan scans memory for FILE_OBJECT structures (open file references)
# Can find files that were open even if they have since been deleted
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 filescan | grep -i "Sophia"

# hashdump extracts NTLM password hashes from the SAM and SYSTEM hives in memory
# These can be cracked offline or used in pass-the-hash attacks
vol.py -f EvidenceC.vmem --profile=Win7SP1x64 hashdump
```

---

## Volatility Plugin Quick Reference

| Plugin | Purpose | Key Output Fields |
|--------|---------|-------------------|
| `imageinfo` | Identify OS profile | Suggested profiles, image datetime |
| `hivelist` | List registry hives | Virtual address, physical address, hive path |
| `pslist` | List running processes | PID, PPID, process name, threads, start time |
| `pstree` | Process tree (parent/child) | Hierarchical view of process relationships |
| `netscan` | Network connections | Protocol, local/remote IP:port, state, PID |
| `memdump` | Dump process memory | Binary file of all process memory pages |
| `lsadump` | Extract LSA secrets | Passwords, service credentials, DPAPI keys |
| `hashdump` | Extract password hashes | NTLM hashes for all local accounts |
| `dlllist` | Loaded DLLs per process | DLL name, base address, size, path |
| `handles` | Open handles per process | File, registry key, thread, process handles |
| `cmdline` | Process command lines | Full command used to launch each process |
| `filescan` | Open file references | All FILE_OBJECT structs in memory |
| `strings` | Extract readable strings | Printable character sequences from raw memory |
