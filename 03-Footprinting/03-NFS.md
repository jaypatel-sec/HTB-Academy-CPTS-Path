# NFS — Footprinting
**Port(s):** 111 (rpcbind), 2049 (NFS)
**Protocol:** TCP/UDP
**CPTS Module:** Footprinting | **Date:** March 2026

## What NFS Is and Why Pentesters Care

Network File System is a distributed file system protocol that allows a system
to share directories over a network. It is heavily used in Unix/Linux
environments for centralised file storage. What makes NFS dangerous for
pentesters is that older versions (NFSv2, NFSv3) have no authentication
mechanism — access control is based purely on IP addresses and Unix UIDs.
If you can reach the NFS port and your IP is in the allowed range, you can
mount the share and read everything on it. Even NFSv4 with Kerberos auth
is often misconfigured in practice.

## Enumeration — Step by Step

### Step 1 — Initial Nmap Scan
```bash
sudo nmap 10.129.14.128 -p111,2049 -sV -sC
```

**Run NFS-specific NSE scripts:**
```bash
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

**What to look for:**
- Which NFS shares are exported
- Which IP ranges are allowed to mount
- NFS version running (v2/v3 = no auth, v4 = potentially Kerberos)

### Step 2 — List Available NFS Exports
```bash
showmount -e 10.129.14.128
# Shows all exported shares and which IPs are allowed to mount them
```

Example output showing world-readable export:
```
Export list for 10.129.14.128:
/mnt/nfs  10.129.14.0/24
/var/nfs  *           # * means anyone can mount this
```

### Step 3 — Mount the Share
```bash
mkdir /tmp/nfs-mount
sudo mount -t nfs 10.129.14.128:/mnt/nfs /tmp/nfs-mount/ -o nolock
# -o nolock disables file locking — useful when NFS server doesn't support it

ls -la /tmp/nfs-mount/
```

### Step 4 — UID Manipulation (Critical Technique)
NFSv3 trusts the UID provided by the client. If a file is owned by UID 1000
on the server, create a user with UID 1000 on your Kali machine to read it:

```bash
# Check file ownership on mounted share
ls -n /tmp/nfs-mount/
# Shows numeric UIDs — e.g. 1000, 48 (apache)

# Create matching user on attacker machine
sudo useradd -u 1000 nfs-user
sudo su nfs-user
cat /tmp/nfs-mount/sensitive-file.txt
```

This is a trivial privilege bypass — no exploitation needed, just UID matching.

### Step 5 — Unmount When Done
```bash
sudo umount /tmp/nfs-mount
```

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| `*(rw,sync,no_root_squash)` | Anyone can mount with read/write, root keeps root | Mount and read/write all files as root |
| `no_root_squash` | Root on client = root on server | Write SSH keys into /root/.ssh/authorized_keys |
| World-readable exports `*` | Any IP can mount | Mount from attacker machine, read all data |
| Sensitive paths exported | Direct access to `/etc`, `/home`, `/var` | Extract credentials, SSH keys, configs |
| NFSv3 with no auth | UID-based access only | UID manipulation to read any user's files |

## NFS Exports Config
```bash
# On the NFS server
cat /etc/exports
# Example dangerous entry:
# /var/nfs *(rw,sync,no_root_squash,no_subtree_check)
```

## Real Lab Output
```
Hackerpatel007_1@htb[/htb]$ showmount -e 10.129.14.128
Export list for 10.129.14.128:
/mnt/nfs  10.129.14.0/24

Hackerpatel007_1@htb[/htb]$ sudo mount -t nfs 10.129.14.128:/mnt/nfs /tmp/nfs-mount -o nolock
Hackerpatel007_1@htb[/htb]$ ls -la /tmp/nfs-mount/
total 16
drwxr-xr-x  3 1000 1000 4096 Sep 22 16:15 .
drwxrwxrwt 10 root root 4096 Sep 22 18:30 ..
-rw-r--r--  1 1000 1000  220 Sep 22 16:15 .bash_logout
drwx------  2 1000 1000 4096 Sep 22 16:15 .ssh
```

## What I Learned / What Surprised Me

The UID manipulation technique surprised me the most. I expected NFS to have
some kind of authentication but NFSv3 literally just trusts whatever UID the
client claims to be. Creating a local user with a matching UID to read another
user's files feels almost too trivial. The `no_root_squash` option is the most
dangerous setting I came across — it means if you mount the share as root on
your machine, you are root on the server's filesystem too. Finding that in an
`/etc/exports` file is an immediate critical finding.

## Detection Layer

| Log Source | What Is Logged | Detection Signal |
|---|---|---|
| System logs `/var/log/syslog` | NFS mount events | External IP mounting NFS share |
| Firewall logs | Connection to port 2049 | Unexpected source IP connecting to NFS |
| NFS server logs | File access events | Bulk file reads from mounted share |

**SPL Query to detect NFS enumeration:**
```spl
index=network dest_port=2049 OR dest_port=111
| stats count by src_ip, dest_ip, dest_port
| where count > 10
| sort -count
```

**KQL Query (Sentinel):**
```kql
CommonSecurityLog
| where DestinationPort == 2049 or DestinationPort == 111
| summarize Count=count() by SourceIP, DestinationIP, DestinationPort
| where Count > 10
| sort by Count desc
```

**MITRE Technique:** T1135 — Network Share Discovery
**Also relevant:** T1005 — Data from Local System

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap --script nfs* <IP> -p111,2049` | NFS NSE enumeration |
| `showmount -e <IP>` | List exported NFS shares |
| `sudo mount -t nfs <IP>:/share /tmp/mount -o nolock` | Mount NFS share |
| `ls -n /tmp/mount` | Show numeric UIDs of files |
| `sudo useradd -u <UID> nfs-user` | Create UID-matching user |
| `sudo umount /tmp/mount` | Unmount share |
