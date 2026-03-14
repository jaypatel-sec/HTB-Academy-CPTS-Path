# FTP — Footprinting
**Port(s):** 21 (control), 20 (data)
**Protocol:** TCP
**CPTS Module:** Footprinting | **Date:** March 2026

## What FTP Is and Why Pentesters Care

FTP is one of the oldest protocols on the internet and runs at the application
layer of the TCP/IP stack. What makes it interesting from a pentesting perspective
is that it operates in cleartext — credentials and data both travel unencrypted
unless TLS is explicitly configured. Even more useful is that many administrators
leave anonymous login enabled, meaning you can browse and sometimes download files
without any credentials at all.

FTP opens two channels: a control channel on TCP port 21 for commands and a data
channel on TCP port 20 for actual file transfers. The distinction between active
and passive mode matters when firewalls are involved — passive mode is almost
always used in modern environments because the client initiates both connections,
bypassing firewall restrictions on inbound connections.

## Enumeration — Step by Step

### Step 1 — Initial Nmap Scan
```bash
sudo nmap -sV -p21 -sC -A 10.129.14.136
```
**What each flag does:**
- `-sV` — version detection, tells us exactly what FTP software is running
- `-p21` — target only port 21
- `-sC` — run default NSE scripts including ftp-anon and ftp-syst
- `-A` — aggressive scan combining OS detection, version, scripts, traceroute

**What to look for in output:**
- FTP banner — often reveals software version (vsFTPd, ProFTPD, FileZilla)
- `ftp-anon` script result — if anonymous login is allowed it lists directory contents
- `ftp-syst` result — reveals server status and version string

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rwxrwxrwx    1 ftp   ftp   8138592 Sep 14 16:54 Calendar.pptx
| drwxrwxrwx    4 ftp   ftp      4096 Sep 16 17:57 Clients
```

### Step 2 — Anonymous Login Attempt
```bash
ftp 10.129.14.136
# Username: anonymous
# Password: (press Enter or use anonymous@anonymous.com)
```

Once connected:
```bash
ftp> ls          # list directory contents
ftp> ls -R       # recursive listing — shows entire folder structure at once
ftp> status      # shows connection mode, transfer type, settings
ftp> debug       # enables verbose output showing raw FTP commands
ftp> trace       # packet-level tracing
```

### Step 3 — Downloading Files
```bash
ftp> get "Important Notes.txt"    # download single file
```

```bash
# Download everything at once (causes alarms — use carefully)
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

### Step 4 — NSE Script Enumeration
```bash
# Update NSE database first
sudo nmap --script-updatedb

# Run all FTP-specific scripts
sudo nmap -sV -p21 --script ftp-* 10.129.14.136

# Trace NSE script activity at network level
sudo nmap -sV -p21 -sC -A 10.129.14.136 --script-trace
```

### Step 5 — TLS/SSL FTP Interaction
```bash
openssl s_client -connect 10.129.14.136:21 -starttls ftp
# Reveals SSL certificate — hostname, organisation, email, location
```

### Step 6 — NetCat / Telnet Direct Interaction
```bash
nc -nv 10.129.14.136 21
telnet 10.129.14.136 21
```

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| `anonymous_enable=YES` | Anyone can browse files without credentials | List, download sensitive files, pivot to other attacks |
| `anon_upload_enable=YES` | Anonymous users can upload files | Upload webshell if FTP root is in web directory |
| `write_enable=YES` | Authenticated users can upload and delete | Upload malicious files, overwrite configs |
| `hide_ids=YES` | UID/GID replaced with "ftp" | Harder to enumerate but still accessible |
| `ls_recurse_enable=YES` | Full recursive directory listing | Map entire file structure in one command |
| SSL disabled | Credentials travel in cleartext | Sniff credentials on the network with Wireshark |

## vsFTPd Key Config File
```bash
cat /etc/vsftpd.conf | grep -v "#"
cat /etc/ftpusers    # users denied FTP access even if they exist on the system
```

## Real Lab Output
```
Hackerpatel007_1@htb[/htb]$ ftp 10.129.14.136
Connected to 10.129.14.136.
220 "Welcome to the HTB Academy vsFTP service."
Name: anonymous
230 Login successful.
ftp> ls
-rw-rw-r--  1 1002  1002  8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x  2 1002  1002     4096 Sep 14 16:50 Clients
drwxrwxr-x  2 1002  1002     4096 Sep 14 16:50 Documents
-rw-rw-r--  1 1002  1002       41 Sep 14 16:45 Important Notes.txt
```

## What I Learned / What Surprised Me

The thing that stood out to me was how much information leaks just from the
banner and anonymous login before any exploitation happens. The SSL certificate
revealing the internal hostname and organisation email was something I did not
expect — that information feeds directly into phishing or further enumeration.
The recursive listing with `ls -R` feels almost too easy when anonymous login
is enabled — you get the entire file structure in seconds. I also did not
realise FTP logs on the server side can lead to RCE through log poisoning
combined with LFI vulnerabilities.

## Detection Layer

**What this enumeration looks like to a defender:**

| Log Source | What Is Logged | Detection Signal |
|---|---|---|
| FTP server logs `/var/log/vsftpd.log` | Anonymous login events, file access | Multiple anonymous logins from same IP |
| Network traffic | Cleartext FTP commands and credentials | FTP traffic on port 21 with USER/PASS visible |
| Firewall logs | Connection to port 21 | External IP connecting to FTP |
| SIEM | Auth events | Anonymous login followed by recursive directory listing |

**SPL Query to detect anonymous FTP login:**
```spl
index=network sourcetype=ftp_logs
(user="anonymous" OR user="ftp")
| stats count by src_ip, dest_ip, action
| where count > 5
| sort -count
```

**KQL Query to detect anonymous FTP (Sentinel):**
```kql
CommonSecurityLog
| where DestinationPort == 21
| where SourceUserName contains "anonymous" or SourceUserName contains "ftp"
| summarize Count=count() by SourceIP, DestinationIP, SourceUserName
| where Count > 5
| sort by Count desc
```

**MITRE Technique:** T1190 — Exploit Public-Facing Application
**Also relevant:** T1083 — File and Directory Discovery

## Commands Reference

| Command | Purpose |
|---|---|
| `ftp <IP>` | Connect to FTP server |
| `ftp> ls -R` | Recursive directory listing |
| `ftp> get <file>` | Download a file |
| `ftp> put <file>` | Upload a file |
| `ftp> status` | Show connection settings |
| `ftp> debug` | Enable verbose command output |
| `wget -m --no-passive ftp://anonymous:anonymous@<IP>` | Download all files |
| `nmap -sV -p21 -sC -A <IP>` | Full FTP enumeration with NSE scripts |
| `openssl s_client -connect <IP>:21 -starttls ftp` | Connect to FTP over TLS |
