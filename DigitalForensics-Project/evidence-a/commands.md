# 🖥️ Evidence A — Disk Forensics Command Reference

> All commands used to analyse the disk image from Alex Marshall's desktop computer.
> Every flag and option is explained so the methodology is fully reproducible.

---

## Setup & Organisation

```bash
# Create a dedicated folder for Evidence A
# Good forensic practice: one folder per evidence item under a /cases parent
# This maintains chain of custody and prevents cross-contamination between evidence items
mkdir -p /cases/EvidenceA/

# Navigate into the working directory
cd /cases/EvidenceA/
```

---

## Extracting the Multi-Part Archive

```bash
# Evidence A arrives as a zip containing 11 split parts (.001 to .011)
# unzip extracts all contents, preserving directory structure and file permissions
unzip EvidenceA.zip -d /cases/EvidenceA/
```

---

## Reassembling the Disk Image

```bash
# The 11 split parts must be joined into a single .dd (raw disk image) file
# cat reads files sequentially and writes them to a new file
# The wildcard EvidenceA.0* matches all 11 parts in order
cat EvidenceA.0* > EvidenceA.dd

# Verify the output file was created and check its size
ls -lh EvidenceA.dd
# Expected: approximately 20 GB
```

---

## Integrity Verification (Chain of Custody)

```bash
# Generate the MD5 hash of the assembled disk image
# md5sum creates a 128-bit fingerprint of the file
# If even one byte changes, the hash will be completely different
# Run this BEFORE analysis and AFTER to prove the evidence was not modified
md5sum EvidenceA.dd
# Expected: e2163d35fb453047af7534d12de89055  EvidenceA.dd

# Save the hash to a file for the chain of custody record
md5sum EvidenceA.dd > EvidenceA.md5
```

---

## Inspecting the Disk Image

```bash
# img_stat examines the disk image and reports:
# - Image type (raw, E01, AFF, etc.)
# - Total size in bytes
# - Sector size (almost always 512 bytes for standard hard drives)
img_stat EvidenceA.dd
# Output:
#   IMAGE FILE INFORMATION
#   Image Type: raw
#   Size in bytes: 21474836480
#   Sector size: 512
```

---

## Partition Analysis

```bash
# mmls reads the partition table of the disk image and lists all partitions
# Shows: partition type, start sector, end sector, length, and description
# We look for the largest partition — typically "Basic data partition" — where user files live
mmls EvidenceA.dd

# Example output:
# DOS Partition Table
# Offset Sector: 0
# Units are in 512-byte sectors
#      Slot    Start       End         Length      Description
# 000: Meta    0000000000  0000000000  0000000001  Primary Table (#0)
# 001: -------  0000000001  0000002047  0000002047  Unallocated
# 002: 000:000  0000002048  0000673791  0000671744  Microsoft Reserved Partition (NTFS)
# 003: 000:001  0000673792  0041943039  0041269248  Basic Data Partition (NTFS)  ← THIS ONE

# The Basic Data Partition starts at sector 673792
# This is the Windows system and user data partition
```

---

## Mounting the Partition

```bash
# Calculate the byte offset for mounting
# offset = start_sector × sector_size
# offset = 673792 × 512 = 344981504 bytes
echo $((673792 * 512))
# Output: 344981504

# Create the mount point
sudo mkdir -p /mnt/windows_mount

# Mount the partition from the disk image
# -o ro       : READ-ONLY — never mount evidence read-write (would modify timestamps)
# -o loop     : treats the file as a block device (loop device)
# -o offset=  : start reading from byte 344981504 (skips the partition table and reserved partition)
sudo mount -o ro,loop,offset=344981504 EvidenceA.dd /mnt/windows_mount

# Verify the mount succeeded
ls /mnt/windows_mount
# Should show: Windows, Users, Program Files, etc.
```

---

## Registry Analysis with RegRipper

```bash
# List all available RegRipper plugins and filter for Windows-related ones
# rip.pl -l lists all plugins; grep narrows results
rip.pl -l | grep win
# Relevant result: winver — reads Windows version and registered owner

# ---- Q1: WHO OWNS THE COMPUTER? ----

# Method 1: Windows version and registered owner from SOFTWARE hive
# The SOFTWARE hive stores application settings, installed software, and OS metadata
# winver plugin reads: ProductName, RegisteredOwner, InstallDate, BuildLab
rip.pl -r /mnt/windows_mount/Windows/System32/config/SOFTWARE -p winver

# Method 2: Computer hostname from SYSTEM hive
# The SYSTEM hive stores hardware configuration, services, and network settings
# compname plugin reads: ComputerName and TCP/IP Hostname
rip.pl -r /mnt/windows_mount/Windows/System32/config/SYSTEM -p compname

# Method 3: User accounts from SAM hive
# The SAM (Security Account Manager) hive stores local user account database
# samparse plugin lists all accounts with: username, RID, account type, creation date, last login
# grep Username filters to show just the account names quickly
rip.pl -r /mnt/windows_mount/Windows/System32/config/SAM -p samparse | grep Username

# Method 4: Full account details including login timestamps
# Remove the grep to see complete account information for all users
rip.pl -r /mnt/windows_mount/Windows/System32/config/SAM -p samparse
```

---

## Browsing Installed Programs

```bash
# ---- Q2: WHAT PROGRAMS WERE INSTALLED? ----

# 64-bit applications (native Windows programs)
ls "/mnt/windows_mount/Program Files/"

# 32-bit applications (legacy or cross-platform programs)
ls "/mnt/windows_mount/Program Files (x86)/"

# Recently downloaded installers — reveals what the user was setting up
ls "/mnt/windows_mount/Users/Alex Marshall/Downloads/"
```

---

## Recycle Bin Analysis

```bash
# ---- Q3: RECOVER RECYCLE BIN CONTENTS ----

# List the contents of the Recycle Bin folder
# $Recycle.Bin contains $I files (metadata) and $R files (actual deleted content)
ls "/mnt/windows_mount/\$Recycle.Bin/"

# recbin.pl parses $I metadata files from the Windows Recycle Bin
# For each deleted file it extracts: original filename, full original path, size, deletion timestamp
rip.pl -r "/mnt/windows_mount/\$Recycle.Bin/" -p recbin
# Recovered:
#   privatenotes.txt  → C:\Alex Marshall\Documents\privatenotes.txt  [14336 bytes]  deleted 2024-08-27 13:15:35Z
#   rubbish.zip       → C:\Alex Marshall\Documents\rubbish.zip       [63400 bytes]  deleted 2024-08-27 13:15:35Z

# Copy the $R files (actual deleted file content) to the working directory for analysis
sudo cp "/mnt/windows_mount/\$Recycle.Bin/S-1-5-21-*/\$R*" /cases/EvidenceA/
```

---

## Password Cracking the Deleted Zip

```bash
# fcrackzip is a fast password cracker for zip archives
# -u : use the unzip binary to verify candidate passwords (prevents false positives)
# -v : verbose — shows each password attempt in real time
# -D : dictionary attack mode (uses a wordlist, not brute force character combinations)
# -p : path to the wordlist file (rockyou.txt is a standard credential dictionary)
fcrackzip -u -v -D -p /cases/EvidenceD/Sms/rockyou.txt "$RLY0J7N.zip"
# Password found: football

# Unzip the archive using the discovered password
# -P : specify the password
unzip -P football "$RLY0J7N.zip"
# Extracted: UniversityWarning_Letter.pdf
```

---

## File Type Identification (Magic Number Analysis)

```bash
# ---- IDENTIFY THE DISGUISED DOCUMENT ----

# Alex saved a Word document with a .jpg extension to hide it
# The 'file' command reads the first few bytes (magic bytes) to determine the true file type
# It ignores the filename extension entirely
file notes.jpg
# Output: notes.jpg: Microsoft Word 2007+ (ZIP format)
# Confirmed: this is a .docx file disguised as an image

# DOCX magic bytes: 50 4B 03 04 (hex) = PK.. (ASCII)
# This is actually a ZIP header — all .docx, .xlsx, .pptx files are ZIP archives internally

# Use Bless Hex Editor to:
# 1. Open notes.jpg
# 2. Search for the hex sequence: 50 4B 03 04
# 3. Select and delete all bytes BEFORE that sequence (the fake JPEG header)
# 4. Save the file with a .docx extension
# 5. Open in LibreOffice Writer to read the content
```

---

## Browsing Personal Documents

```bash
# ---- Q4: STATE OF MIND EVIDENCE ----

# Navigate to Alex's personal documents
cd "/mnt/windows_mount/Users/Alex Marshall/My Documents"
ls -la

# Read Alex's journals (plain text files)
cat journal1.txt
cat journal2.txt

# Open the debt tracker (CSV — readable as plain text)
cat Debt_Tracker.csv

# List the contents of the pictures folder
ls "/mnt/windows_mount/Users/Alex Marshall/My Pictures"
```

---

## Unmounting After Analysis

```bash
# Always unmount the evidence image when analysis is complete
sudo umount /mnt/windows_mount

# Verify unmount was successful (command should show nothing)
mount | grep windows_mount

# Re-verify hash to confirm evidence integrity was maintained throughout
md5sum EvidenceA.dd
# Must match: e2163d35fb453047af7534d12de89055
```
