# 📱 Evidence D — Mobile Phone (Android) Command Reference

> All commands used to analyse the Android disk image from the damaged mobile phone found in Alex's apartment.

---

## Setup & Integrity Verification

```bash
# Create dedicated folder for Evidence D
mkdir -p /cases/EvidenceD/

# Evidence D is a 7-Zip archive (not a standard .zip)
# 7z is the command-line tool for 7-Zip archives
# x = extract with full paths
# -o = output directory
7z x EvidenceD.7z -o/cases/EvidenceD/

cd /cases/EvidenceD/

# After extraction, several Android partition image files will appear
# Analyse the sizes of each to find the main data partition
ls -lh
# The largest file is dm-1 — this is the main Android data partition

# Verify integrity before analysis
md5sum dm-1
# Expected: cbf84de09de09b0143ebddefcdae2e3d9a7c

# Create the mount point for the Android partition
sudo mkdir -p /mnt/e01/

# Mount the Android partition read-only
# Android typically uses ext4 filesystem for its data partition
# -o loop : treat dm-1 as a block device
sudo mount -o loop dm-1 /mnt/e01/

# Verify mount by listing the top-level directory
ls /mnt/e01/
# Should show: data, system, misc, etc.
```

> **Android filesystem structure:** Unlike Windows, Android stores app data in `/data/data/com.packagename/` directories. Each app gets its own sandboxed folder. Databases are SQLite files stored within these directories.

---

## Q13 — Finding Non-Stock Applications

```bash
# APK files are Android Package files — the equivalent of Windows .exe installers
# Stock (pre-installed) apps live in /system/app/ and /system/priv-app/
# User-installed (non-stock) apps live in /data/app/

# find searches the entire filesystem recursively for files matching a pattern
# -name "*.apk" matches any file ending in .apk
find /mnt/e01 -name "*.apk"

# To see only user-installed apps (not system apps):
find /mnt/e01/data/app -name "*.apk"
# Found:
#   /mnt/e01/data/app/com.facebook.katana-1/base.apk      (Facebook)
#   /mnt/e01/data/app/com.rovio.baba-1/base.apk           (Angry Birds)
#   /mnt/e01/data/app/com.tencent.mm-1/base.apk           (WeChat/Tencent)
#   /mnt/e01/data/app/com.twitter.android-1/base.apk      (Twitter)
#   /mnt/e01/data/app/com.bbbandgames.bubbleshooter-1/base.apk (Bubble Shooter)
```

---

## Q14 — Call History

```bash
# Find the call log database
# Android stores call history in a SQLite database managed by the contacts provider
find /mnt/e01 -name "*call*"
# Target: /mnt/e01/data/com.android.providers.contacts/databases/calllog.db

# IMPORTANT: Access to /data/ requires root/superuser permissions
# Copy the database to the working directory and adjust permissions so a normal user can read it
sudo cp /mnt/e01/data/com.android.providers.contacts/databases/calllog.db /cases/EvidenceD/
sudo chmod 644 /cases/EvidenceD/calllog.db

# Open with SQLite command-line tool
sqlite3 /cases/EvidenceD/calllog.db

# Within SQLite, query the calls table:
.tables                     -- list all tables in the database
.schema calls               -- show the structure of the calls table
SELECT * FROM calls;        -- show all call records
.quit                       -- exit SQLite

# Or open with DB Browser for SQLite (GUI) for easier viewing:
sqlitebrowser /cases/EvidenceD/calllog.db &

# Key columns in the calls table:
# number    : phone number called or received from
# date      : Unix timestamp (milliseconds since epoch) — convert to human-readable
# duration  : call duration in seconds (0 = no answer or missed)
# type      : 1=incoming, 2=outgoing, 3=missed
# name      : contact name if saved in address book
```

**Converting Unix timestamps to readable dates:**
```bash
# Android stores dates as milliseconds since Jan 1 1970 (Unix epoch × 1000)
# Convert using date command:
date -d @$((1726311533266 / 1000))
# Output: Sat 14 Sep 2024 10:58:53 AM UTC
```

---

## Q14 — Contact List

```bash
# Find the contacts database
find /mnt/e01 -name "*contact*"
# Two relevant databases:
# /mnt/e01/data/com.android.providers.contacts/databases/contacts2.db  (primary)
# /mnt/e01/data/com.google.android.gms/databases/icing_contacts.db      (Google backup)

# Copy both out for analysis
sudo cp /mnt/e01/data/com.android.providers.contacts/databases/contacts2.db /cases/EvidenceD/
sudo cp /mnt/e01/data/com.google.android.gms/databases/icing_contacts.db /cases/EvidenceD/
sudo chmod 644 /cases/EvidenceD/contacts2.db /cases/EvidenceD/icing_contacts.db

# Query contacts2.db in SQLite
sqlite3 /cases/EvidenceD/contacts2.db
.tables
SELECT contact_id, display_name, given_names, phone_numbers FROM contacts;
# Note the contact_id values — gaps in sequence indicate deleted contacts
# IDs 4,5,6,7 visible but IDs 1,2,3 are missing → 3 contacts were deleted

# Recovering deleted contacts from the WAL (Write-Ahead Log) file
# WAL files contain recent uncommitted changes — they preserve old data before writes were applied
# icing_contacts.db-wal contains the pre-deletion state of the contacts database

# Method: Open icing_contacts.db-wal in Bless Hex Editor
bless /cases/EvidenceD/icing_contacts.db-wal

# In Bless: Search → Find → switch to Text mode
# Search for names or partial phone numbers to find deleted contact data
# The WAL file preserves the data in binary form with surrounding structure bytes
```

---

## Q14 — SMS Messages

```bash
# Find the SMS/MMS database
find /mnt/e01 -name "*sms*"
# Target: /mnt/e01/user_de/0/com.android.providers.telephony/databases/mmssms.db

# Copy and adjust permissions
sudo cp /mnt/e01/user_de/0/com.android.providers.telephony/databases/mmssms.db /cases/EvidenceD/
sudo chmod 644 /cases/EvidenceD/mmssms.db

# Query in SQLite
sqlite3 /cases/EvidenceD/mmssms.db

# List all tables
.tables
# Key tables: sms, threads, canonical_addresses

# Read all SMS messages with sender/recipient and body
SELECT _id, address, date, date_sent, type, body FROM sms ORDER BY date;
# type: 1=received, 2=sent

# Convert timestamps (same Unix millisecond format as call log)

# Key conversations found:
# +61449857236 (Lily Parker)    12:51:36 – 12:53:03 PM UTC Sep 14
# +61417692485 (Sophia Bennett) 12:53:34 – 12:55:07 PM UTC Sep 14
# +61417692485 (Sophia Bennett) 12:58:08 – 12:59:21 PM UTC Sep 14
# +61458230941 (Unknown)        12:55:30 – 12:56:42 PM UTC Sep 14  ← THREAT MESSAGES
```

---

## Q15 — Browser Search History

```bash
# Find browser history databases
find /mnt/e01 -name "*History*"
# Two results — the main one is the standard Android browser or Chrome history

# For Chrome/Chromium-based browsers on Android:
find /mnt/e01 -name "History" -path "*/Chrome/*"
# Target: /mnt/e01/data/com.android.chrome/app_chrome/Default/History

sudo cp /mnt/e01/data/com.android.chrome/app_chrome/Default/History /cases/EvidenceD/ChromeHistory
sudo chmod 644 /cases/EvidenceD/ChromeHistory

# Query in SQLite
sqlite3 /cases/EvidenceD/ChromeHistory
.tables
# Key tables: urls, visits, keyword_search_terms

# Show all visited URLs
SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC;

# Show only search queries
SELECT term, url FROM keyword_search_terms ORDER BY url_id DESC;
```

---

## Q16 — Recovering Email Fragments from WAL Files

```bash
# bigTopDataDB is a Google services database that caches email data locally
find /mnt/e01 -name "bigTopDataDB*"
# Found: bigTopDataDB.1204881091
#        bigTopDataDB.1204881091-wal   ← this WAL contains email fragments

# Copy the WAL file
sudo cp /mnt/e01/data/com.google.android.gms/databases/bigTopDataDB.1204881091-wal /cases/EvidenceD/

# Method 1: strings to extract readable text
strings /cases/EvidenceD/bigTopDataDB.1204881091-wal | grep -A 5 "Subject:"
strings /cases/EvidenceD/bigTopDataDB.1204881091-wal | grep -A 10 "From:"

# Method 2: Open in a text editor and search for readable fragments
# Look for thread-f: and msg-f: identifiers which are Gmail message thread IDs
grep -a "thread" /cases/EvidenceD/bigTopDataDB.1204881091-wal

# Found email thread fragments:
# Oliver Marshall → Alex: "Final Warning" (threatening to cut bank account)
# Alex → Lily: "I'm Sorry" (apologising, asking her not to give up)
# Alex → Sophia: "We Need to Talk" (trying to end the relationship)
# Saul Reynolds → Alex: "Urgent: Academic Integrity" (formal misconduct allegations)
```

---

## Q16 — Investigating the Encrypted File

```bash
# Find the encrypted recording
find /mnt/e01 -name "recording.aes"
# Found: /mnt/e01/data/.../downloads/recording.aes

# Check the file type
file /cases/EvidenceD/recording.aes
# Output: data
# No recognisable magic bytes — properly encrypted binary data

# Inspect the first bytes in hex (no readable structure)
xxd /cases/EvidenceD/recording.aes | head -20

# Attempt to find the AES key and IV in other evidence items:
# Search Evidence A (disk image) for hex strings that could be a key
strings /cases/EvidenceA/EvidenceA.dd | grep -i "key\|iv\|aes"

# Search Evidence C (memory dump) for the key
strings /cases/EvidenceC/EvidenceC.vmem | grep -i "aes\|decrypt"

# The key was NOT found in any evidence piece
# Alex likely distributed the key to a trusted person or stored it externally
# recording.aes remains undecrypted — the most significant unresolved piece of evidence
```

---

## Android Forensics Quick Reference

| Database Path | Contents | Key Tables |
|---------------|----------|------------|
| `.../contacts/databases/calllog.db` | Call history | calls |
| `.../contacts/databases/contacts2.db` | Contact list | contacts, raw_contacts, phone_lookup |
| `.../telephony/databases/mmssms.db` | SMS/MMS messages | sms, threads, canonical_addresses |
| `.../chrome/.../History` | Browser history | urls, visits, keyword_search_terms |
| `.../chrome/.../Cookies` | Browser cookies | cookies |
| `.../gms/databases/bigTopDataDB.*` | Google services cache | Email fragments, account data |
| `.../app/` directory | Installed APKs | — (filesystem, not SQLite) |

**Key Android forensic concepts:**

| Concept | Explanation |
|---------|-------------|
| WAL file | Write-Ahead Log — contains uncommitted database changes; used to recover deleted records |
| Unix timestamp | Seconds (or milliseconds) since Jan 1 1970; Android uses milliseconds |
| APK | Android Package — zip archive containing app code, resources, and manifest |
| `find` command | Essential tool for locating databases and files by name pattern |
| SQLite | Database format used by virtually all Android apps for structured data storage |
| Root access | Required to read `/data/` directory contents — must copy files to accessible location |
# 📱 Evidence D — Mobile Phone (Android) Command Reference

> All commands used to analyse the Android disk image from the damaged mobile phone found in Alex's apartment.

---

## Setup & Integrity Verification

```bash
# Create dedicated folder for Evidence D
mkdir -p /cases/EvidenceD/

# Evidence D is a 7-Zip archive (not a standard .zip)
# 7z is the command-line tool for 7-Zip archives
# x = extract with full paths
# -o = output directory
7z x EvidenceD.7z -o/cases/EvidenceD/

cd /cases/EvidenceD/

# After extraction, several Android partition image files will appear
# Analyse the sizes of each to find the main data partition
ls -lh
# The largest file is dm-1 — this is the main Android data partition

# Verify integrity before analysis
md5sum dm-1
# Expected: cbf84de09de09b0143ebddefcdae2e3d9a7c

# Create the mount point for the Android partition
sudo mkdir -p /mnt/e01/

# Mount the Android partition read-only
# Android typically uses ext4 filesystem for its data partition
# -o loop : treat dm-1 as a block device
sudo mount -o loop dm-1 /mnt/e01/

# Verify mount by listing the top-level directory
ls /mnt/e01/
# Should show: data, system, misc, etc.
```

> **Android filesystem structure:** Unlike Windows, Android stores app data in `/data/data/com.packagename/` directories. Each app gets its own sandboxed folder. Databases are SQLite files stored within these directories.

---

## Q13 — Finding Non-Stock Applications

```bash
# APK files are Android Package files — the equivalent of Windows .exe installers
# Stock (pre-installed) apps live in /system/app/ and /system/priv-app/
# User-installed (non-stock) apps live in /data/app/

# find searches the entire filesystem recursively for files matching a pattern
# -name "*.apk" matches any file ending in .apk
find /mnt/e01 -name "*.apk"

# To see only user-installed apps (not system apps):
find /mnt/e01/data/app -name "*.apk"
# Found:
#   /mnt/e01/data/app/com.facebook.katana-1/base.apk      (Facebook)
#   /mnt/e01/data/app/com.rovio.baba-1/base.apk           (Angry Birds)
#   /mnt/e01/data/app/com.tencent.mm-1/base.apk           (WeChat/Tencent)
#   /mnt/e01/data/app/com.twitter.android-1/base.apk      (Twitter)
#   /mnt/e01/data/app/com.bbbandgames.bubbleshooter-1/base.apk (Bubble Shooter)
```

---

## Q14 — Call History

```bash
# Find the call log database
# Android stores call history in a SQLite database managed by the contacts provider
find /mnt/e01 -name "*call*"
# Target: /mnt/e01/data/com.android.providers.contacts/databases/calllog.db

# IMPORTANT: Access to /data/ requires root/superuser permissions
# Copy the database to the working directory and adjust permissions so a normal user can read it
sudo cp /mnt/e01/data/com.android.providers.contacts/databases/calllog.db /cases/EvidenceD/
sudo chmod 644 /cases/EvidenceD/calllog.db

# Open with SQLite command-line tool
sqlite3 /cases/EvidenceD/calllog.db

# Within SQLite, query the calls table:
.tables                     -- list all tables in the database
.schema calls               -- show the structure of the calls table
SELECT * FROM calls;        -- show all call records
.quit                       -- exit SQLite

# Or open with DB Browser for SQLite (GUI) for easier viewing:
sqlitebrowser /cases/EvidenceD/calllog.db &

# Key columns in the calls table:
# number    : phone number called or received from
# date      : Unix timestamp (milliseconds since epoch) — convert to human-readable
# duration  : call duration in seconds (0 = no answer or missed)
# type      : 1=incoming, 2=outgoing, 3=missed
# name      : contact name if saved in address book
```

**Converting Unix timestamps to readable dates:**
```bash
# Android stores dates as milliseconds since Jan 1 1970 (Unix epoch × 1000)
# Convert using date command:
date -d @$((1726311533266 / 1000))
# Output: Sat 14 Sep 2024 10:58:53 AM UTC
```

---

## Q14 — Contact List

```bash
# Find the contacts database
find /mnt/e01 -name "*contact*"
# Two relevant databases:
# /mnt/e01/data/com.android.providers.contacts/databases/contacts2.db  (primary)
# /mnt/e01/data/com.google.android.gms/databases/icing_contacts.db      (Google backup)

# Copy both out for analysis
sudo cp /mnt/e01/data/com.android.providers.contacts/databases/contacts2.db /cases/EvidenceD/
sudo cp /mnt/e01/data/com.google.android.gms/databases/icing_contacts.db /cases/EvidenceD/
sudo chmod 644 /cases/EvidenceD/contacts2.db /cases/EvidenceD/icing_contacts.db

# Query contacts2.db in SQLite
sqlite3 /cases/EvidenceD/contacts2.db
.tables
SELECT contact_id, display_name, given_names, phone_numbers FROM contacts;
# Note the contact_id values — gaps in sequence indicate deleted contacts
# IDs 4,5,6,7 visible but IDs 1,2,3 are missing → 3 contacts were deleted

# Recovering deleted contacts from the WAL (Write-Ahead Log) file
# WAL files contain recent uncommitted changes — they preserve old data before writes were applied
# icing_contacts.db-wal contains the pre-deletion state of the contacts database

# Method: Open icing_contacts.db-wal in Bless Hex Editor
bless /cases/EvidenceD/icing_contacts.db-wal

# In Bless: Search → Find → switch to Text mode
# Search for names or partial phone numbers to find deleted contact data
# The WAL file preserves the data in binary form with surrounding structure bytes
```

---

## Q14 — SMS Messages

```bash
# Find the SMS/MMS database
find /mnt/e01 -name "*sms*"
# Target: /mnt/e01/user_de/0/com.android.providers.telephony/databases/mmssms.db

# Copy and adjust permissions
sudo cp /mnt/e01/user_de/0/com.android.providers.telephony/databases/mmssms.db /cases/EvidenceD/
sudo chmod 644 /cases/EvidenceD/mmssms.db

# Query in SQLite
sqlite3 /cases/EvidenceD/mmssms.db

# List all tables
.tables
# Key tables: sms, threads, canonical_addresses

# Read all SMS messages with sender/recipient and body
SELECT _id, address, date, date_sent, type, body FROM sms ORDER BY date;
# type: 1=received, 2=sent

# Convert timestamps (same Unix millisecond format as call log)

# Key conversations found:
# +61449857236 (Lily Parker)    12:51:36 – 12:53:03 PM UTC Sep 14
# +61417692485 (Sophia Bennett) 12:53:34 – 12:55:07 PM UTC Sep 14
# +61417692485 (Sophia Bennett) 12:58:08 – 12:59:21 PM UTC Sep 14
# +61458230941 (Unknown)        12:55:30 – 12:56:42 PM UTC Sep 14  ← THREAT MESSAGES
```

---

## Q15 — Browser Search History

```bash
# Find browser history databases
find /mnt/e01 -name "*History*"
# Two results — the main one is the standard Android browser or Chrome history

# For Chrome/Chromium-based browsers on Android:
find /mnt/e01 -name "History" -path "*/Chrome/*"
# Target: /mnt/e01/data/com.android.chrome/app_chrome/Default/History

sudo cp /mnt/e01/data/com.android.chrome/app_chrome/Default/History /cases/EvidenceD/ChromeHistory
sudo chmod 644 /cases/EvidenceD/ChromeHistory

# Query in SQLite
sqlite3 /cases/EvidenceD/ChromeHistory
.tables
# Key tables: urls, visits, keyword_search_terms

# Show all visited URLs
SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC;

# Show only search queries
SELECT term, url FROM keyword_search_terms ORDER BY url_id DESC;
```

---

## Q16 — Recovering Email Fragments from WAL Files

```bash
# bigTopDataDB is a Google services database that caches email data locally
find /mnt/e01 -name "bigTopDataDB*"
# Found: bigTopDataDB.1204881091
#        bigTopDataDB.1204881091-wal   ← this WAL contains email fragments

# Copy the WAL file
sudo cp /mnt/e01/data/com.google.android.gms/databases/bigTopDataDB.1204881091-wal /cases/EvidenceD/

# Method 1: strings to extract readable text
strings /cases/EvidenceD/bigTopDataDB.1204881091-wal | grep -A 5 "Subject:"
strings /cases/EvidenceD/bigTopDataDB.1204881091-wal | grep -A 10 "From:"

# Method 2: Open in a text editor and search for readable fragments
# Look for thread-f: and msg-f: identifiers which are Gmail message thread IDs
grep -a "thread" /cases/EvidenceD/bigTopDataDB.1204881091-wal

# Found email thread fragments:
# Oliver Marshall → Alex: "Final Warning" (threatening to cut bank account)
# Alex → Lily: "I'm Sorry" (apologising, asking her not to give up)
# Alex → Sophia: "We Need to Talk" (trying to end the relationship)
# Saul Reynolds → Alex: "Urgent: Academic Integrity" (formal misconduct allegations)
```

---

## Q16 — Investigating the Encrypted File

```bash
# Find the encrypted recording
find /mnt/e01 -name "recording.aes"
# Found: /mnt/e01/data/.../downloads/recording.aes

# Check the file type
file /cases/EvidenceD/recording.aes
# Output: data
# No recognisable magic bytes — properly encrypted binary data

# Inspect the first bytes in hex (no readable structure)
xxd /cases/EvidenceD/recording.aes | head -20

# Attempt to find the AES key and IV in other evidence items:
# Search Evidence A (disk image) for hex strings that could be a key
strings /cases/EvidenceA/EvidenceA.dd | grep -i "key\|iv\|aes"

# Search Evidence C (memory dump) for the key
strings /cases/EvidenceC/EvidenceC.vmem | grep -i "aes\|decrypt"

# The key was NOT found in any evidence piece
# Alex likely distributed the key to a trusted person or stored it externally
# recording.aes remains undecrypted — the most significant unresolved piece of evidence
```

---

## Android Forensics Quick Reference

| Database Path | Contents | Key Tables |
|---------------|----------|------------|
| `.../contacts/databases/calllog.db` | Call history | calls |
| `.../contacts/databases/contacts2.db` | Contact list | contacts, raw_contacts, phone_lookup |
| `.../telephony/databases/mmssms.db` | SMS/MMS messages | sms, threads, canonical_addresses |
| `.../chrome/.../History` | Browser history | urls, visits, keyword_search_terms |
| `.../chrome/.../Cookies` | Browser cookies | cookies |
| `.../gms/databases/bigTopDataDB.*` | Google services cache | Email fragments, account data |
| `.../app/` directory | Installed APKs | — (filesystem, not SQLite) |

**Key Android forensic concepts:**

| Concept | Explanation |
|---------|-------------|
| WAL file | Write-Ahead Log — contains uncommitted database changes; used to recover deleted records |
| Unix timestamp | Seconds (or milliseconds) since Jan 1 1970; Android uses milliseconds |
| APK | Android Package — zip archive containing app code, resources, and manifest |
| `find` command | Essential tool for locating databases and files by name pattern |
| SQLite | Database format used by virtually all Android apps for structured data storage |
| Root access | Required to read `/data/` directory contents — must copy files to accessible location |
