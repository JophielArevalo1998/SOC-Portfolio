# 🌐 Evidence B — Network Capture Command Reference

> All Wireshark filters and analysis steps used to investigate the dormitory network packet capture.

---

## Setup & Integrity Verification

```bash
# Create dedicated folder for Evidence B
mkdir -p /cases/EvidenceB/

# Extract the pcap file
unzip EvidenceB.zip -d /cases/EvidenceB/
cd /cases/EvidenceB/

# Verify integrity before analysis
md5sum EvidenceB.pcap
# Expected: b383bb9ae1dce23a4e72a0c192aafe80

# Open the capture in Wireshark
wireshark EvidenceB.pcap &
```

> A `.pcap` (Packet Capture) file is a binary recording of all network traffic seen on a network interface during a specific time period. Wireshark can decode, filter, and reconstruct the original conversations from these raw packets.

---

## Finding Conversations (Q5 — Who is communicating?)

### Method 1 — Statistics → Conversations

```
Wireshark menu → Statistics → Conversations
Click the TCP tab
Sort by "Bytes" or "Duration" (descending) to find the most significant exchanges
These are the conversations with the most data — likely the chat messages
```

> The Conversations view shows every unique pair of IP:port combinations that exchanged packets. Sorting by bytes or duration surfaces the meaningful conversations over background noise.

### Method 2 — Follow TCP Stream

```
In the main packet list, right-click any TCP packet
→ Follow → TCP Stream

This reassembles all packets in that TCP session into a readable conversation.
Text from the client appears in one colour; text from the server in another.
```

> TCP streams reassemble fragmented packets back into the original data. Chat messages that were split across dozens of packets become readable in a single view.

### Wireshark Display Filters Used

```
# Show only TCP traffic
tcp

# Show only FTP traffic (for file transfer analysis)
ftp

# Show only HTTP traffic (for user agent and IP analysis)
http

# Show traffic between two specific hosts
ip.addr == 10.10.10.33 && ip.addr == 10.10.10.254

# Show traffic from a specific source IP
ip.src == 10.10.10.33

# Follow specific TCP stream by stream index
tcp.stream eq 3
```

---

## Identifying Browsers and Operating Systems (Q6)

```
Wireshark filter: http
Select any HTTP GET request in the packet list
In the packet detail panel, expand: Hypertext Transfer Protocol
Look for the "User-Agent:" field

The User-Agent string format is:
Mozilla/5.0 (OS; Architecture) AppleWebKit/... Chrome/VERSION Safari/...
                ↑                                                ↑
        Operating System info                          Browser name + version

Cross-reference at: https://useragents.net
```

**User-Agent to OS/Browser mapping:**

```
# Windows 7 + Chrome 47
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36
# NT 6.1 = Windows 7 | WOW64 = 32-bit app on 64-bit Windows

# Mac OS X + Safari 9
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9
# OS X 10_11_2 = El Capitan

# Ubuntu Linux + Firefox 15
Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1
# X11 = Linux display system | Ubuntu = distro | x86_64 = 64-bit
```

---

## FTP File Transfer Analysis (Q7)

```
Wireshark filter: ftp

# This shows all FTP control channel commands
# FTP uses port 21 for commands and a negotiated port for data transfer

# To see what files were transferred, follow each FTP stream:
Right-click any FTP packet → Follow → TCP Stream

# FTP command reference:
# USER anonymous  → Login as anonymous user (no password required)
# SYST            → Query server operating system type
# TYPE A          → Set transfer mode to ASCII (for text files)
# TYPE I          → Set transfer mode to Binary/Image (for binary files)
# CWD pub         → Change directory to 'pub'
# LIST            → List files in current directory
# STOR filename   → Upload (store) a file on the server
# RETR filename   → Download (retrieve) a file from the server
# QUIT            → End the FTP session

# Response codes:
# 200 = Command OK
# 220 = Service ready
# 226 = Transfer complete ← confirms file was successfully transferred
# 553 = Could not create file ← upload failed (permissions)
```

### Extracting Transferred Files from PCAP

```
Wireshark menu → File → Export Objects → FTP-DATA
This extracts the actual binary content of any FTP data transfers captured in the pcap
Save all extracted objects for further analysis
```

---

## Reconstructing the SSL/TLS Key Theft

The FTP stream 694 shows the stolen SSL session key being uploaded. To understand what this enables:

```
# The sslkeyfile contains TLS session secrets in NSS Key Log format
# Format: CLIENT_RANDOM <hex_value> <master_secret_hex>

# If an attacker has this file, they can decrypt TLS traffic in Wireshark:
Wireshark → Edit → Preferences → Protocols → TLS
→ (Pre)-Master-Secret log filename → browse to sslkeyfile
→ Apply → all previously unreadable HTTPS traffic becomes decrypted

# This means DormKing's plan was to:
# 1. Steal Alex's TLS session key from his computer
# 2. Upload it to the FTP server
# 3. Use it to decrypt Alex's HTTPS traffic to the exam answer server
# 4. Download the exam answers without paying the $200
```

---

## Timeline Reconstruction

```
# To see ALL packets in chronological order with timestamps:
Wireshark → View → Time Display Format → Date and Time of Day

# To find the first and last packet:
# First packet: top of the packet list after clearing all filters
# Last packet: Ctrl+End to jump to bottom of packet list

# To filter packets within a specific time window:
frame.time >= "2024-09-01 07:57:00" && frame.time <= "2024-09-01 08:47:00"
```

**Key timestamps from Evidence B:**

| Event | Timestamp |
|-------|-----------|
| First CheatChat message (AlexM21) | 2024-09-01 07:57:11Z |
| DormKing theft plan begins | 2024-09-01 08:16:09Z |
| FTP sslkeyfile upload completes | 2024-09-01 08:42:54Z |
| Last recorded message (DormKing/PartyDude) | 2024-09-01 08:46:20Z |
