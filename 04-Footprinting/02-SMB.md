# SMB — Footprinting
**Port(s):** 139 (NetBIOS), 445 (direct TCP)
**Protocol:** TCP
**CPTS Module:** Footprinting | **Date:** March 2026

## What SMB Is and Why Pentesters Care

SMB is the backbone of Windows file sharing and one of the most valuable
protocols to enumerate during a pentest. It controls access to files,
directories, printers, and other network resources. What makes it particularly
dangerous is that misconfigurations are extremely common — anonymous access,
overly permissive shares, and outdated SMB versions (SMB1/CIFS) are still
found regularly in enterprise environments.

Samba is the Linux/Unix implementation of SMB, which means you will encounter
this protocol on both Windows and Linux targets. The RPC interface exposed
through SMB is especially valuable — it lets you enumerate domain users, groups,
shares, and policies without ever needing valid credentials if null sessions are
permitted.

## Enumeration — Step by Step

### Step 1 — Initial Nmap Scan
```bash
sudo nmap 10.129.14.128 -sV -sC -p139,445
```
**What to look for:**
- SMB version (SMB1 = very dangerous, still exploitable via EternalBlue)
- Message signing enabled or not — if disabled, SMB relay attacks are possible
- NetBIOS name and domain information

### Step 2 — Null Session Share Enumeration
```bash
smbclient -N -L //10.129.14.128
# -N = null session (no credentials)
# -L = list available shares
```

**Connect to a specific share:**
```bash
smbclient //10.129.14.128/notes
# Press Enter for blank password — tests anonymous/guest access
```

**Once inside a share:**
```bash
smb: \> ls           # list files
smb: \> get prep-prod.txt    # download file
smb: \> !ls          # run local command without leaving session
smb: \> !cat prep-prod.txt   # read downloaded file
```

### Step 3 — RPC Enumeration
```bash
rpcclient -U "" 10.129.14.128
# Press Enter for blank password
```

**Key RPC queries:**
```bash
rpcclient $> srvinfo           # server information and OS version
rpcclient $> enumdomains       # list all domains
rpcclient $> querydominfo      # domain, server, user counts
rpcclient $> netshareenumall   # list all shares with paths
rpcclient $> netsharegetinfo notes   # detailed info on specific share
rpcclient $> enumdomusers      # list all domain users with RIDs
rpcclient $> queryuser 0x3e9   # detailed info on specific user by RID
rpcclient $> querygroup 0x201  # group information
```

**Brute force user RIDs to enumerate all accounts:**
```bash
for i in $(seq 500 1100); do
  rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" \
  | grep "User Name\|user_rid\|group_rid" && echo ""
done
```

### Step 4 — Automated Enumeration Tools
```bash
# SMBmap — shows share permissions clearly
smbmap -H 10.129.14.128

# CrackMapExec — fast share enum with READ/WRITE permissions
crackmapexec smb 10.129.14.128 --shares -u '' -p ''

# Impacket samrdump — user enumeration via SAM
samrdump.py 10.129.14.128

# enum4linux-ng — comprehensive automated enumeration
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng && pip3 install -r requirements.txt
./enum4linux-ng.py 10.129.14.128 -A
```

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| `guest ok = yes` | No password required to connect to share | Browse and download files without credentials |
| `browseable = yes` | Share visible in share listing | Attacker can see all available shares |
| `writable = yes` + `create mask = 0777` | Anyone can write files | Upload malicious files, achieve code execution |
| SMB signing disabled | Relay attacks possible | Capture NTLM hash and relay to other hosts |
| SMB1 enabled | Vulnerable to EternalBlue (MS17-010) | Remote code execution without credentials |
| Null session allowed | RPC enumeration without credentials | User, group, policy enumeration |

## Samba Config File
```bash
cat /etc/samba/smb.conf | grep -v "#\|\;"
# Key dangerous settings to look for:
# guest ok = yes
# writable = yes
# browseable = yes
# create mask = 0777
```

## Real Lab Output
```
Hackerpatel007_1@htb[/htb]$ smbclient -N -L //10.129.14.128
        Sharename     Type    Comment
        ---------     ----    -------
        print$        Disk    Printer Drivers
        home          Disk    INFREIGHT Samba
        dev           Disk    DEVenv
        notes         Disk    CheckIT
        IPC$          IPC     IPC Service (DEVSM)

rpcclient $> enumdomusers
user:[mrb3n] rid:[0x3e8]
user:[cry0l1t3] rid:[0x3e9]
```

## What I Learned / What Surprised Me

RPC through SMB was completely new to me — I did not realise you could enumerate
domain users, groups and password policies through what looks like a file sharing
protocol. The RID brute forcing technique to pull every user account is something
I will use in every AD engagement. What also stood out was enum4linux-ng — it runs
in 0.61 seconds and returns OS version, users, groups, shares, policies and
password complexity settings all in one shot. The password policy output showing
`min_pw_length: 5` and no complexity requirements is exactly the kind of finding
that goes straight into a pentest report as a critical misconfiguration.

## Commands Reference

| Command | Purpose |
|---|---|
| `smbclient -N -L //<IP>` | List shares anonymously |
| `smbclient //<IP>/<share>` | Connect to share |
| `smbmap -H <IP>` | Show share permissions |
| `crackmapexec smb <IP> --shares -u '' -p ''` | Fast share enum with permissions |
| `rpcclient -U "" <IP>` | RPC null session |
| `rpcclient $> enumdomusers` | List all domain users |
| `enum4linux-ng.py <IP> -A` | Full automated enumeration |
| `samrdump.py <IP>` | User enumeration via SAM |
