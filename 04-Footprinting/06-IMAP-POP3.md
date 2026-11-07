# IMAP / POP3 — Footprinting
**Port(s):** 110 (POP3), 143 (IMAP), 993 (IMAPS), 995 (POP3S)
**Protocol:** TCP
**CPTS Module:** Footprinting | **Date:** March 2026

## What IMAP and POP3 Are and Why Pentesters Care

IMAP and POP3 are the two email retrieval protocols. POP3 downloads emails
to the client and deletes them from the server. IMAP keeps emails on the
server and supports folders and mailboxes — which means if you get access
to an IMAP account you can read the entire email history still sitting on
the server, not just what has been recently downloaded.

From a pentesting perspective these services are valuable for three reasons.
First, the SSL certificates on ports 993 and 995 leak the organisation name
and FQDN before you even connect. Second, the POP3 banner on port 110 reveals
the server software and version string without authentication. Third, if you
obtain credentials through password spraying or reuse from other services,
IMAP gives you direct access to someone's entire mailbox — emails containing
credentials, internal information, and lateral movement paths.

Dovecot is the most common open-source IMAP/POP3 server on Linux systems.

## Enumeration — Step by Step

### Step 1 — Initial Nmap Scan
```bash
sudo nmap -p110,143,993,995 -sC -sV 10.129.14.128
```
**What each flag does:**
- `-sC` — runs default NSE scripts including SSL cert reading and banner grabbing
- `-sV` — detects exact service version on each port
- All four ports together — covers both plain and encrypted variants

**What to look for in output:**
- `ssl-cert` block — reveals `organizationName` and `commonName` (FQDN)
- Service version string — Dovecot version, custom banners
- Supported capabilities — AUTH mechanisms, STARTTLS, IDLE

### Step 2 — Banner Grab Port 110 (POP3 Plain)
```bash
telnet 10.129.14.128 110
```
POP3 sends a `+OK` banner immediately on connection before any authentication.
This reveals custom version strings and server branding not visible in Nmap.

```
+OK InFreight POP3 v9.188
```

### Step 3 — Connect to Encrypted Ports via OpenSSL
```bash
# IMAPS port 993
openssl s_client -connect 10.129.14.128:993

# POP3S port 995
openssl s_client -connect 10.129.14.128:995
```

After the TLS handshake the server sends its welcome banner and capability
list. Misconfigured servers sometimes leak flags, internal notes, or version
strings directly in the banner without requiring login.

### Step 4 — IMAP Manual Enumeration (Authenticated)
Every IMAP command requires a tag prefix — without it the server ignores the command.

```bash
openssl s_client -connect 10.129.14.128:993
```

```imap
# Login
tag0 LOGIN robin robin

# List all mailboxes
tag1 LIST "" "*"

# Open a specific mailbox
tag2 SELECT "DEV.DEPARTMENT.INT"

# Fetch full email (headers + body)
tag3 FETCH 1 (BODY[])

# Fetch body only
tag3 FETCH 1 (BODY[TEXT])

# Logout
tag4 LOGOUT
```

**Understanding the LIST output:**
```
* LIST (\Noselect \HasChildren) "." DEV
* LIST (\Noselect \HasChildren) "." DEV.DEPARTMENT
* LIST (\HasNoChildren) "." DEV.DEPARTMENT.INT
* LIST (\HasNoChildren) "." INBOX
```
The dot `.` is the hierarchy separator. `DEV.DEPARTMENT.INT` means folder
`INT` inside `DEPARTMENT` inside `DEV`. Always `LIST` before `SELECT` —
you need the exact folder name first.

### Step 5 — POP3 Manual Enumeration (Authenticated)
```bash
telnet 10.129.14.128 110
```

```pop3
USER robin
PASS robin
LIST              # list all messages with sizes
STAT              # count messages in mailbox
RETR 1            # read message number 1 full content
QUIT
```

### Step 6 — Automated Credential Testing
```bash
# Hydra against IMAP
hydra -l robin -P /usr/share/wordlists/rockyou.txt imap://10.129.14.128

# Hydra against POP3
hydra -l robin -P /usr/share/wordlists/rockyou.txt pop3://10.129.14.128

# Nmap auth brute
nmap --script imap-brute -p143 10.129.14.128
```

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| Plain text ports 110/143 open | Credentials travel unencrypted | Sniff USER/PASS on the wire with Wireshark |
| Weak or reused credentials | Easy brute force | Hydra password spray against IMAP/POP3 |
| Server banner reveals version | CVE research possible | Target specific Dovecot/Courier exploit |
| SSL cert contains internal FQDN | Infrastructure mapping | Reveals internal hostnames before any auth |
| Emails contain credentials | Lateral movement | Search inbox for passwords sent via email |
| No rate limiting on auth | Brute force unrestricted | Rapid credential stuffing without lockout |

## Real Lab Output
```
HackerpatelOO7_1@htb[/htb]$ sudo nmap -p110,143,993,995 -sC -sV 10.129.14.128

PORT    STATE SERVICE  VERSION
110/tcp open  pop3     Dovecot pop3d
143/tcp open  imap     Dovecot imapd
993/tcp open  ssl/imap Dovecot imapd
| ssl-cert: Subject: commonName=dev.inlanefreight.htb
|           organizationName=InlaneFreight Ltd
|           stateOrProvinceName=London
|           countryName=UK
995/tcp open  ssl/pop3 Dovecot pop3d

HackerpatelOO7_1@htb[/htb]$ telnet 10.129.14.128 110
+OK InFreight POP3 v9.188

openssl s_client -connect 10.129.14.128:993
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+
  AUTH=PLAIN] HTB{...flag_redacted...}

tag0 LOGIN robin robin
tag0 OK Logged in

tag1 LIST "" "*"
* LIST (\HasNoChildren) "." DEV.DEPARTMENT.INT
* LIST (\HasNoChildren) "." INBOX

tag2 SELECT "DEV.DEPARTMENT.INT"
* 1 EXISTS

tag3 FETCH 1 (BODY[])
Subject: Flag
To: Robin <robin@inlanefreight.htb>
From: CTO <devadmin@inlanefreight.htb>
HTB{...flag_redacted...}
```

## What I Learned / What Surprised Me

The SSL certificate leaking the organisation name and internal FQDN before
you even authenticate was something I did not expect. You get free
infrastructure recon just from scanning — no login, no interaction with the
service beyond the TLS handshake. The IMAP command tag requirement also
caught me initially — the server completely ignores commands without a tag
prefix which looks like the connection is broken when it is not. The most
interesting finding was the flag embedded directly in the IMAP capability
banner on port 993 — that is a real class of misconfiguration where admins
leave test strings or internal notes in service banners that go public.
The FETCH command returning the From header revealing devadmin's email
shows how a single compromised low-privilege mailbox can expose higher
privilege account details for further attacks.

## IMAP Command Reference

| Command | Purpose |
|---|---|
| `tag0 LOGIN user pass` | Authenticate |
| `tag1 LIST "" "*"` | List all mailboxes |
| `tag2 SELECT "INBOX"` | Open a mailbox |
| `tag3 FETCH 1 (BODY[])` | Fetch full email including headers |
| `tag3 FETCH 1 (BODY[TEXT])` | Fetch body only |
| `tag3 FETCH 1 (FLAGS)` | Check read/unread status |
| `tag4 LOGOUT` | Disconnect |

## POP3 Command Reference

| Command | Purpose |
|---|---|
| `USER username` | Identify user |
| `PASS password` | Authenticate |
| `LIST` | List all messages with sizes |
| `RETR 1` | Read message number 1 |
| `STAT` | Count messages in mailbox |
| `QUIT` | Disconnect |

## Key Pentest Takeaways

- Always scan all four ports 110, 143, 993, 995 together
- SSL certs on 993/995 leak org name and FQDN for free
- Banner grab port 110 with telnet — version strings before any auth
- Use `openssl s_client` for encrypted ports — telnet will not work with TLS
- Every IMAP command needs a tag prefix — `tag0`, `a1`, etc.
- Always `LIST` before `SELECT` — you need exact folder names first
- Emails containing credentials are the highest value finding from IMAP access
