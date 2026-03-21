# SNMP — Footprinting
**Port(s):** 161 UDP (queries), 162 UDP (traps)
**Protocol:** UDP — standard TCP scans miss this entirely
**CPTS Module:** Footprinting | **Date:** March 2026

## What SNMP Is and Why Pentesters Care

SNMP is used to monitor and manage network devices — routers, switches, servers, printers. From a pentesting perspective it is a goldmine because it can expose the entire system configuration, running processes, installed software, user accounts, and network information — often with zero authentication. The critical thing to understand is that SNMP runs on UDP 161, which means standard Nmap TCP scans miss it completely. You must explicitly scan UDP or it will never show up in your results.

SNMPv1 and v2c use community strings for authentication — essentially a plaintext password sent over the wire with no encryption. The default community strings are `public` for read-only and `private` for read-write, and many devices ship with these defaults never changed.

## SNMP Versions

| Version | Auth Method | Encryption | Risk |
|---|---|---|---|
| v1 | Community string plaintext | None | Critical |
| v2c | Community string plaintext | None | Critical |
| v3 | Username + password | Yes | Lower but brute force still possible |

v2c is the most common version found in real environments. The `c` stands for community-based — still sending credentials in plaintext over the wire.

## OIDs and MIBs

**OID (Object Identifier)** — A unique number identifying a specific piece of information on a device. Looks like: `1.3.6.1.2.1.1.4.0`

**MIB (Management Information Base)** — A dictionary that translates numeric OIDs into human-readable names. Without MIBs installed you see raw numbers. With MIBs you see names like `sysContact`.

**Key OIDs to memorise:**

| OID | Name | Contains |
|---|---|---|
| `1.3.6.1.2.1.1.1.0` | sysDescr | OS type, kernel version, architecture |
| `1.3.6.1.2.1.1.4.0` | sysContact | Admin email/contact info |
| `1.3.6.1.2.1.1.5.0` | sysName | Hostname |
| `1.3.6.1.2.1.1.6.0` | sysLocation | Location or custom string |
| `1.3.6.1.2.1.25.1.7` | hrSWRunParameters | Running scripts and their output |
| `1.3.6.1.2.1.25.4.2.1.2` | hrSWRunName | Running process names |
| `1.3.6.1.2.1.25.6.3.1.2` | hrSWInstalledName | Installed software list |
| `1.3.6.1.4.1.77.1.2.25` | — | Windows local user accounts |

## Enumeration — Step by Step

### Step 1 — Nmap UDP Scan
```bash
# Must use -sU for UDP — TCP scan misses SNMP entirely
sudo nmap -sU -p161 -sV 10.129.14.128

# With default NSE scripts
sudo nmap -sU -p161 -sV -sC 10.129.14.128

# SNMP-specific NSE script
sudo nmap -sU -p161 --script snmp-info 10.129.14.128
```
**What to look for:** SNMP version, community string hints, device type in banner

### Step 2 — Full snmpwalk Dump
```bash
# Always save output to file — snmpwalk returns hundreds of lines
snmpwalk -v2c -c public 10.129.14.128 | tee SNMPWalk.txt
```
**Flag breakdown:**
- `-v2c` — use SNMPv2c, most common in real environments
- `-c public` — default read-only community string
- `| tee SNMPWalk.txt` — print to terminal AND save to file simultaneously

`tee` is essential here. The output can be thousands of lines. Saving to a file lets you grep it repeatedly without re-running the scan.

### Step 3 — Walk Specific OID Subtrees
```bash
snmpwalk -v2c -c public 10.129.14.128 system           # System info only
snmpwalk -v2c -c public 10.129.14.128 interfaces       # Network interfaces
snmpwalk -v2c -c public 10.129.14.128 hrSWRunTable     # Running processes
snmpwalk -v2c -c public 10.129.14.128 hrStorageTable   # Disk and memory
snmpwalk -v2c -c public 10.129.14.128 hrSWInstalledTable # Installed software

# Query a single specific OID
snmpget -v2c -c public 10.129.14.128 1.3.6.1.2.1.1.4.0  # Just sysContact
```

### Step 4 — grep Filtering on Saved Output
```bash
grep "@"                SNMPWalk.txt   # Email addresses
grep "STRING"           SNMPWalk.txt   # All text values
grep "password\|pass"   SNMPWalk.txt   # Potential credentials
grep -m 1 -B 8 "HTB{"  SNMPWalk.txt   # Flag with 8 lines of context before it
```

`-m 1` stops after first match. `-B 8` shows 8 lines before the match — critical because those lines reveal which script or process produced the output.

### Step 5 — Community String Brute Force
```bash
# onesixtyone — fast SNMP community string bruteforcer
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.129.14.128

# Then use the found string with snmpwalk
snmpwalk -v2c -c <found_string> 10.129.14.128 | tee output.txt
```

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| Default community string `public` left enabled | Anyone can read full device config | snmpwalk dumps entire system info |
| `private` community string left enabled | Read-write access to device config | Modify device settings remotely |
| SNMPv1 or v2c in use | Community strings travel in plaintext | Wireshark capture reveals credentials instantly |
| hrSWRunParameters exposed | Running script output is readable | Scripts may output flags, passwords, sensitive data |
| sysContact field populated | Admin email exposed | Targeted phishing using real admin email |
| sysLocation misused | Version strings or internal notes exposed | Internal system information for free |

## Real Lab Output
```
Hackerpatel007_1@htb[/htb]$ snmpwalk -v2c -c public 10.129.14.128 | tee SNMPWalk.txt

iso.3.6.1.2.1.1.1.0 = STRING: "Linux NIX02 5.4.0-90-generic #101-Ubuntu SMP x86_64"
iso.3.6.1.2.1.1.4.0 = STRING: "devadmin <devadmin@inlanefreight.htb>"
iso.3.6.1.2.1.1.5.0 = STRING: "NIX02"
iso.3.6.1.2.1.1.6.0 = STRING: "InFreight SNMP v0.91"

Hackerpatel007_1@htb[/htb]$ grep -m 1 -B 8 "HTB{" SNMPWalk.txt
iso.3.6.1.2.1.25.1.7.1.2.1.2.4.70.76.65.71 = STRING: "/usr/share/flag.sh"
iso.3.6.1.2.1.25.1.7.1.3.1.1.4.70.76.65.71 = STRING: "HTB{5nMp_fl4g_uidhfljnsldiuhbfsdij44738b2u763g}"
```

## What I Learned / What Surprised Me

The thing that surprised me most was how much SNMP exposes before any exploitation — OS version, kernel, hostname, admin email, running processes, installed software, and even script output, all from a single `snmpwalk` with the default `public` community string. The `hrSWRunParameters` MIB was completely unexpected — the idea that a running script's output is stored in an SNMP OID and readable by anyone who knows the community string is a serious misconfiguration that I would not have thought to look for. The `.70.76.65.71` OID suffix being ASCII decimal encoding of `FLAG` was also something I had not encountered before — understanding how SNMP indexes named entries in tables is genuinely useful for parsing output in real engagements.



## Commands Reference

| Command | Purpose |
|---|---|
| `sudo nmap -sU -p161 -sV <IP>` | SNMP UDP scan with version detection |
| `snmpwalk -v2c -c public <IP> \| tee output.txt` | Full walk saving to file |
| `snmpget -v2c -c public <IP> 1.3.6.1.2.1.1.4.0` | Query single OID |
| `onesixtyone -c <wordlist> <IP>` | Community string brute force |
| `grep "@" output.txt` | Filter for email addresses |
| `grep -m 1 -B 8 "HTB{" output.txt` | Find flag with context |
