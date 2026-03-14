# SMTP — Footprinting
**Port(s):** 25 (SMTP), 587 (submission), 465 (SMTPS)
**Protocol:** TCP
**CPTS Module:** Footprinting | **Date:** March 2026

## What SMTP Is and Why Pentesters Care

SMTP handles outgoing email and from a pentesting perspective it reveals
two valuable things: user enumeration and mail relay misconfiguration.
The VRFY and EXPN commands, if enabled on the server, confirm whether
a username exists on the system — this turns SMTP into a user enumeration
tool without needing any credentials. An open relay (a server that forwards
email from any source to any destination) can be abused for phishing,
spam, and bypassing email security filters.

The SMTP banner alone often reveals the mail server software and version,
which feeds directly into CVE research. On internal networks, SMTP
enumeration via Telnet or Netcat is a fast way to confirm user accounts
before attempting password spraying against other services.

## Enumeration — Step by Step

### Step 1 — Initial Nmap Scan
```bash
sudo nmap 10.129.14.128 -sC -sV -p25,587,465
```

**Run SMTP NSE scripts:**
```bash
sudo nmap 10.129.14.128 -p25 --script smtp-*
```

**What to look for:**
- Banner — software version (Postfix, Sendmail, Exim, Microsoft Exchange)
- ESMTP extensions supported (AUTH mechanisms, STARTTLS, SIZE limits)
- Whether VRFY or EXPN commands are available

### Step 2 — Manual Interaction Via Telnet
```bash
telnet 10.129.14.128 25
# or
nc -nv 10.129.14.128 25
```

**SMTP conversation:**
```
220 inlanefreight.htb ESMTP Postfix (Ubuntu)

EHLO hacktheplanet          # Introduce ourselves, lists supported extensions
VRFY root                   # Does this user exist?
VRFY admin
VRFY john.smith
EXPN support                # Expand mailing list — reveals all members
MAIL FROM:<test@test.com>   # Test open relay — set sender
RCPT TO:<victim@company.com> # Test open relay — set recipient
DATA                        # Begin message body (for relay test)
QUIT
```

**VRFY response codes:**
- `252 2.0.0` — user probably exists
- `550 5.1.1` — user does not exist

### Step 3 — Automated User Enumeration
```bash
# smtp-user-enum tool
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
               -t 10.129.14.128

# Specify method: VRFY, EXPN, or RCPT
smtp-user-enum -M RCPT -U users.txt -t 10.129.14.128 -p 25
```

### Step 4 — Test For Open Relay
```bash
# Using Nmap
nmap --script smtp-open-relay -p25 10.129.14.128

# Manual test via Telnet
telnet 10.129.14.128 25
EHLO test
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@otherdomain.com>
# If server accepts this — it is an open relay
```

### Step 5 — DNS MX Lookup (Find SMTP Servers First)
```bash
dig mx inlanefreight.com         # Find MX records
dig a mail.inlanefreight.com     # Resolve MX hostname to IP
```

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| VRFY command enabled | Username enumeration without credentials | Confirm valid users for password spraying |
| EXPN command enabled | Mailing list member disclosure | Reveal all users in distribution lists |
| Open relay configured | Forward email on behalf of anyone | Phishing, spam, bypass email filters |
| No STARTTLS | Credentials travel in cleartext | Sniff authentication on the wire |
| Weak AUTH mechanisms | Brute force possible | Hydra against SMTP AUTH |
| Banner reveals software version | CVE research | Target specific exploit for Postfix/Exim version |

## Real Lab Output
```
Hackerpatel007_1@htb[/htb]$ telnet 10.129.14.128 25
Trying 10.129.14.128...
Connected to 10.129.14.128.
220 inlanefreight.htb ESMTP Postfix (Ubuntu)

EHLO hacktheplanet
250-inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN

VRFY root
252 2.0.0 root

VRFY john
550 5.1.1 john: Recipient address rejected: User unknown
```

## What I Learned / What Surprised Me

SMTP as a user enumeration vector was something I completely overlooked before
this module. The VRFY command feels like a debug feature left enabled in
production — and yet it directly confirms whether a username exists on the
system, which feeds straight into a credential stuffing or password spraying
attack. The open relay test was also surprising in its simplicity — just
providing an external RCPT TO and seeing the server accept it is an instant
critical finding in any pentest. I also did not realise that EXPN on mailing
lists can expose an entire department's user list in one command.

## Detection Layer

| Log Source | What Is Logged | Detection Signal |
|---|---|---|
| Mail server logs `/var/log/mail.log` | VRFY/EXPN commands | Sequential VRFY commands from single IP |
| Mail server logs | Rejected relay attempts | External IP attempting to relay to external domain |
| Network logs | SMTP connections on port 25 | External source connecting to internal SMTP |
| SIEM | Auth failures | Multiple failed SMTP AUTH attempts |

**SPL Query to detect SMTP user enumeration:**
```spl
index=mail sourcetype=smtp_logs
(command="VRFY" OR command="EXPN")
| stats count by src_ip, command, recipient
| where count > 10
| sort -count
```

**KQL Query (Sentinel):**
```kql
CommonSecurityLog
| where DestinationPort == 25
| where Message contains "VRFY" or Message contains "EXPN"
| summarize Count=count() by SourceIP, Message
| where Count > 10
| sort by Count desc
```

**MITRE Technique:** T1589.002 — Gather Victim Identity Information: Email Addresses
**Also relevant:** T1595 — Active Scanning, T1566 — Phishing (open relay abuse)

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap --script smtp-* -p25 <IP>` | Full SMTP NSE enumeration |
| `telnet <IP> 25` | Manual SMTP interaction |
| `EHLO <hostname>` | List supported extensions |
| `VRFY <username>` | Check if user exists |
| `EXPN <list>` | Expand mailing list |
| `smtp-user-enum -M VRFY -U <wordlist> -t <IP>` | Automated user enumeration |
| `nmap --script smtp-open-relay -p25 <IP>` | Test for open relay |
| `dig mx <domain>` | Find SMTP servers via DNS |
