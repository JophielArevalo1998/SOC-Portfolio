# 📄 Final Report Summary — Alex Marshall Investigation

> Condensed findings from all four evidence items for quick reference.

---

## Case Summary

**Subject:** Alex Marshall, university student  
**Investigation type:** Multi-evidence Digital Forensics  
**Evidence items:** 4 (disk image, network capture, memory dump, mobile phone)  
**Tools:** The Sleuth Kit, RegRipper, Volatility 2.6, Wireshark, fcrackzip, SQLite Browser, Bless Hex Editor, GHex

---

## Key Findings Per Evidence

### Evidence A — Disk Image (Alex's Desktop)

| Finding | Detail |
|---------|--------|
| Computer owner | Alex Marshall (confirmed via SAM, only active user account) |
| Hostname | DESKTOP-0N2DC4F |
| Windows installed | 2024-08-27 — brand new machine |
| Last login | 2024-08-27 13:05:43Z |
| Files deleted | privatenotes.txt, rubbish.zip — both deleted 13:15:35Z same day |
| Recovered from zip | UniversityWarning_Letter.pdf — academic probation, exam sale allegations |
| Disguised file | notes.jpg → Last Will and Testament (DOCX disguised as JPEG) |
| Financial status | $7,450 in debt across 5 creditors; $5,000 from unknown source |
| Journals | Admits selling exam answers since Feb 2024; describes debt and guilt |

### Evidence B — Network Capture (Dormitory Network)

| Finding | Detail |
|---------|--------|
| Chat platform | CheatChat — custom application running on local server 10.10.10.254 |
| Alex's handle | AlexM21 |
| Criminal activity | Sold Bio101 exam answers for $200 per set |
| Delivery method | FTP server drop |
| Persons involved | DormKing, PartyDude, BookWorm (buyers/aware parties) |
| Theft attempt | DormKing instructed PartyDude to steal Alex's FTP session key — partly succeeded |
| Relationships | Sophia pressures Alex to choose her; Lily suspects infidelity |
| First/last timestamp | 2024-09-01 07:57:11Z – 08:46:20Z |
| FTP transfer | sslkeyfile uploaded by PartyDude — captured in stream 694 |

### Evidence C — Memory Dump (Sophia's Laptop)

| Finding | Detail |
|---------|--------|
| Machine owner | Sophia Bennett (revealed via NTUSER.DAT path in hivelist) |
| Email address | vb9945311@gmail.com — matches ArtLover99 from network capture |
| Active applications | Firefox, Thunderbird, Mynotepad++, VMware Tools |
| Network connections | Google services (HTTPS), Gmail IMAP (port 993) |
| Password | `Alexisbeautifull` — autologin password revealing obsessive fixation |
| Journal content | Describes surveillance of Alex; expresses rage about Lily; states "I'll do whatever it takes" |
| External connection | Email from "Victor Ivanov" offering protection and warning of enemies closing in |

### Evidence D — Mobile Phone (Alex's Android)

| Finding | Detail |
|---------|--------|
| Non-stock apps | Facebook, Angry Birds, Tencent, Twitter, Bubble Shooter |
| Call activity (Sep 14) | 4 calls to Lily (no answer), 1 call to Sophia (70 seconds, connected) |
| Deleted contacts | 3 contacts deleted before death; partially recovered from WAL file |
| SMS (Sep 14) | Lily threatens consequences; Sophia demands decision; unknown number threatens over unpaid debt |
| Unknown number | +61458230941 — explicit payment threats, not in contact list, not among deleted contacts |
| Search history | Burner phones, deleting messages, blocking numbers, emergency loans — evidence of fear |
| Email fragments | Father's final warning; Alex apologising to Lily; Alex ending things with Sophia; formal academic misconduct notice |
| Encrypted file | recording.aes — AES encrypted, key not found in any evidence item |

---

## Persons of Interest

### 1. Sophia Bennett — HIGH PRIORITY
- Obsessive surveillance of Alex documented in her own journals
- Password `Alexisbeautifull` demonstrates fixation
- Connected to "Victor Ivanov" — possible organised crime link
- Was present at Alex's dorm on the day of his calls (she answered his last call — 70 seconds)
- Journal states: "I'll do whatever it takes to make sure he realizes we're meant to be together"

### 2. Unknown (+61458230941) — HIGH PRIORITY
- Explicit death threats via SMS on September 14 — the day of Alex's death
- Connected to the $5,000 private loan (unknown source, urgent status)
- Not in Alex's contact list and not among contacts he deleted — deliberately kept off the record
- Alex was searching "how to block calls from a specific number" — likely this number

### 3. Lily Parker — MEDIUM PRIORITY
- Threatened Alex via SMS: "I'm not going to do anything rash. I'll figure it out, Alex. I promise."
- Did not answer four calls from Alex on the morning of his death
- Warned she would expose him if he didn't end things with the other person
- Aware of a third party in the relationship

### 4. DormKing — LOW PRIORITY (separate criminal matter)
- Directed a theft operation against Alex
- Planned to steal exam answers without payment
- This is a separate criminal matter but establishes that Alex had active adversaries

---

## Timeline Summary

| Date | Event |
|------|-------|
| Feb 28, 2024 | Alex begins selling exam answers — documented in journal |
| Mar 10, 2024 | Father threatens to cut financial support |
| Mar 15, 2024 | University issues formal warning — academic probation |
| Apr 2024 | Debts reach $7,450 across five creditors |
| Aug 27, 2024 | New computer set up; Last Will and Testament created and hidden; files deleted |
| Sep 1, 2024 | Exam sale network active; DormKing theft attempt; relationship confrontations with Sophia and Lily |
| Sep 14, 2024 | Alex's last day: 4 unanswered calls to Lily, call to Sophia, threatening SMS from unknown number, relationship ultimatums from both women |

---

## Unresolved Evidence

| Item | Status | Significance |
|------|--------|--------------|
| `recording.aes` | Encrypted — key not found | Potentially critical audio evidence; Alex may have recorded something intentionally |
| Unknown number +61458230941 | Not identified | Likely connected to the $5,000 private loan; possible primary suspect |
| "Victor Ivanov" / vb9945311@gmail.com | Sophia's email address | Dual identity suggests Sophia may have been operating under an alias |
| Deleted contacts (1, 2, 3) | Partially recovered from WAL | Full identities of deleted contacts not fully retrieved |

---

## Forensic Methodology Notes

- All evidence hashes verified with `md5sum` before and after analysis
- Evidence mounted read-only (`-o ro`) at all times — original files never modified  
- Working copies made for all databases before querying
- SQLite WAL files examined for deleted record recovery
- Multi-tool corroboration used throughout (no single-source conclusions)
- Chain of custody maintained: dedicated folder per evidence item, hashes logged

---

*Griffith University — Master of Cybersecurity — Digital Forensics Major Assignment — Grade: High Distinction*
