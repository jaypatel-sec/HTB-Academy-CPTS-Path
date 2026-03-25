# HTB Academy — Module 03: Network Enumeration with Nmap

| Field | Details |
|---|---|
| Platform | Hack The Box Academy |
| Module | 03 — Network Enumeration with Nmap |
| Difficulty | Easy |
| Type | Offensive — Hands-on with Skills Assessments |
| Date | March 2026 |

---

## Module Overview

Nmap is the most widely used network scanning and host discovery tool in offensive security. This module covers every major Nmap capability from first principles — host discovery, port scanning techniques, service and version enumeration, OS detection, the Nmap Scripting Engine, output formats, and firewall/IDS/IPS evasion. The module ends with three skills assessment labs — Easy, Medium, and Hard — each simulating a progressively more hardened target environment.

---

## What Nmap Does and Why It Matters

Before any exploitation attempt, a pentester needs answers to three questions: what hosts are alive, what ports are open on those hosts, and what services are running on those ports. Nmap answers all three in a structured, scriptable way that produces output suitable for both manual analysis and automated processing.

Core Nmap capabilities:

| Capability | What It Finds |
|---|---|
| Host Discovery | Which IP addresses have live hosts responding |
| Port Scanning | Which TCP/UDP ports are open, closed, or filtered |
| Service Enumeration | Exact software and version running on each open port |
| OS Detection | Operating system and version based on TCP/IP stack fingerprinting |
| NSE Scripts | Protocol-specific enumeration, vulnerability checks, banner grab |
| Firewall/IDS Evasion | Techniques to bypass packet filters and intrusion detection |

---

## Section 1 — Host Discovery

Host discovery is the first phase — establishing which IP addresses in a range are actually alive before spending time scanning ports on dead hosts.

### Default Host Discovery

By default Nmap sends an ICMP echo request, a TCP SYN to port 443, a TCP ACK to port 80, and an ICMP timestamp request. In a local network it also uses ARP requests.

```bash
sudo nmap 10.129.2.0/24 -sn -oA hosts
```

| Flag | Purpose |
|---|---|
| `-sn` | Ping scan only — no port scan, just host discovery |
| `-oA` | Save output in all formats (normal, XML, greppable) |

### ICMP Echo Request with Packet Trace

```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
```

| Flag | Purpose |
|---|---|
| `-PE` | ICMP Echo Request — send ping packet |
| `--packet-trace` | Show every packet sent and received |
| `--disable-arp-ping` | Skip ARP on local subnets — force ICMP |

### Reading TTL values to identify OS

When a host responds to an ICMP echo, the TTL (Time to Live) value in the response identifies the operating system:

| TTL Value | Operating System |
|---|---|
| 64 | Linux / Unix |
| 128 | Windows |
| 255 | Cisco / Network Device |

A TTL of 128 in the response = Windows. A TTL of 64 = Linux. This is passive OS identification from a single ping response — no intrusive scan required.

---

## Section 2 — Host and Port Scanning

### Port States

Nmap classifies every scanned port into one of six states:

| State | Meaning |
|---|---|
| open | Connection established — service is actively listening |
| closed | Port is reachable but no service is listening (RST received) |
| filtered | Firewall or filter is blocking — no response received |
| unfiltered | Port reachable but state undetermined (ACK scan result) |
| open/filtered | Cannot determine if open or filtered — no response |
| closed/filtered | Cannot determine state — IP ID idle scan only |

### Scan Types

| Scan Type | Flag | Mechanism | Use Case |
|---|---|---|---|
| SYN Scan (Stealth) | `-sS` | Sends SYN, waits for SYN-ACK, sends RST — never completes handshake | Default root scan — fast, stealthy |
| Connect Scan | `-sT` | Full TCP three-way handshake | Non-root scan — slower, logged by target |
| UDP Scan | `-sU` | Sends UDP packet — no response = open/filtered, ICMP unreachable = closed | SNMP, DNS, DHCP discovery |
| ACK Scan | `-sA` | Sends ACK only — bypasses stateless firewalls | Firewall rule mapping |
| Version Scan | `-sV` | Probes services with protocol-specific payloads | Exact software version identification |
| OS Detection | `-O` | Analyses TCP/IP stack behaviour | OS fingerprinting |
| Aggressive | `-A` | Combines `-sV -O -sC --traceroute` | Maximum information, maximum noise |

### Full Port Scan

```bash
sudo nmap -sS -p- 10.129.2.28 --open -T4
```

| Flag | Purpose |
|---|---|
| `-p-` | Scan all 65535 ports — never skip this on CTF/CPTS labs |
| `--open` | Show only open ports — reduces noise |
| `-T4` | Aggressive timing — faster on stable lab networks |

Count open ports from output:

```bash
sudo nmap --open -p- 10.129.2.28 -T5 | grep "/tcp" | wc -l
```

### Specific Port Targeting

```bash
sudo nmap 10.129.2.28 -p 22,80,445 -sV
```

### Hostname Enumeration via SMB

Running `-sV` or `-sC` against port 445 reveals the hostname through the SMB service banner:

```bash
sudo nmap -p445 10.129.2.28 -sV
```

**Output (relevant section):**

```
PORT    STATE SERVICE     VERSION
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: NIX-NMAP-DEFAULT
```

The `Host:` field in the SMB service info directly gives the NetBIOS hostname. Extract cleanly with grep:

```bash
sudo nmap -p445 10.129.2.28 -sV | grep "Host:" | cut -d " " -f3,4
```

---

## Section 3 — Saving the Results

Nmap supports multiple simultaneous output formats. Always save results — never run a scan without capturing the output.

```bash
sudo nmap -p- 10.129.2.28 --open -oA scan_results
```

| Flag | Output Format | File Extension |
|---|---|---|
| `-oN` | Normal — human-readable text | .nmap |
| `-oX` | XML — machine-parseable, convertible | .xml |
| `-oG` | Greppable — single-line format | .gnmap |
| `-oA` | All three simultaneously | All extensions |

### Convert XML to HTML report

```bash
xsltproc scan_results.xml -o scan_results.html
firefox scan_results.html
```

The HTML report provides a clean, formatted view of all findings that can be included in client-facing deliverables or shared with a team.

---

## Section 4 — Service Enumeration

Version detection goes beyond identifying a port is open — it determines exactly what software and version is listening, which is what drives vulnerability identification.

```bash
sudo nmap -sV -p- 10.129.2.28 --stats-every=5s
```

| Flag | Purpose |
|---|---|
| `-sV` | Service/version detection |
| `--stats-every=5s` | Print progress every 5 seconds — useful for long scans |

### Banner Grabbing with Netcat

When Nmap identifies an unusual or high port, Netcat can grab the banner directly:

```bash
nc -nv 10.129.2.49 31337
```

**Output:**

```
(UNKNOWN) [10.129.2.49] 31337 (?) open
220 HTB{...flag_redacted...}
```

Services on non-standard ports often expose banners that contain version strings, internal hostnames, or even flags. Always connect manually to anything unusual before moving on.

---

## Section 5 — Nmap Scripting Engine (NSE)

NSE extends Nmap's capabilities with Lua scripts that perform specific enumeration tasks against services. There are 14 script categories:

| Category | Purpose |
|---|---|
| auth | Authentication — credential checking and bypass |
| broadcast | Host discovery via broadcast — finds hosts not responding to ping |
| brute | Credential brute force against services |
| default | Safe, fast scripts run with `-sC` |
| discovery | Service enumeration, protocol information gathering |
| dos | Denial of service testing — use carefully |
| exploit | Active exploitation of known vulnerabilities |
| external | Queries external databases (Shodan, etc.) |
| fuzzer | Sends unexpected inputs to identify crashes |
| intrusive | High-risk scripts — may cause crashes or lock accounts |
| malware | Detects backdoors and malware indicators |
| safe | Low-risk scripts that are unlikely to cause problems |
| version | More advanced service/version detection |
| vuln | Checks services against known CVEs |

### Common NSE Usage

```bash
# Run default scripts (safe, fast — equivalent to -sC)
sudo nmap -sC -p80,443 10.129.2.28

# Run specific script
sudo nmap -p80 --script http-enum 10.129.2.28

# Run all discovery scripts
sudo nmap -p80 --script discovery 10.129.2.28

# Run all scripts in a category
sudo nmap -p445 --script "smb-*" 10.129.2.28

# Trace script activity
sudo nmap -p80 --script http-enum --script-trace 10.129.2.28
```

### Finding Hidden Files with NSE

The `http-enum` and `discovery` scripts find paths not visible through manual browsing. A common finding is `robots.txt`:

```bash
sudo nmap -p80 10.129.2.28 --script discovery
```

**Relevant output:**

```
| http-enum:
|_  /robots.txt: Robots file
```

```bash
curl http://10.129.2.28/robots.txt
```

**Output:**

```
User-agent: *
Allow: /

HTB{...flag_redacted...}
```

`robots.txt` disallows specific paths from being indexed by search engines — which often means those paths contain something the administrator does not want publicly visible. Always fetch it.

---

## Section 6 — OS Detection

Nmap fingerprints the operating system by analysing how the target's TCP/IP stack responds to crafted packets. Different operating systems implement the TCP/IP specification slightly differently — those differences form a fingerprint.

```bash
sudo nmap -O 10.129.2.28
```

**Output (relevant section):**

```
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
```

OS detection works best when there is at least one open and one closed port — it needs both types of response to build a complete fingerprint.

---

## Section 7 — Firewall and IDS/IPS Evasion

This is the most advanced section of the module. Network defenses — firewalls, IDS (Intrusion Detection Systems), and IPS (Intrusion Prevention Systems) — are designed to detect and block port scanning activity. Understanding how to work around them is essential for real engagement scenarios where targets are hardened.

### Understanding What Gets Detected

A standard Nmap SYN scan sends a high volume of SYN packets from a single source IP. This pattern is trivially detected by:
- Firewalls with rate limiting rules
- IDS signatures matching rapid port scanning behaviour
- IPS systems that automatically block the source IP after N events

The goal of evasion is not to be invisible — it is to make the scan traffic look normal enough to pass through filters.

---

### Evasion Technique 1 — Decoys (`-D`)

Decoys flood the target with scan packets appearing to come from multiple source IPs simultaneously. The IDS cannot determine which IP is the real attacker.

```bash
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

| Flag | Purpose |
|---|---|
| `-D RND:5` | Generate 5 random decoy IP addresses mixed with real scan traffic |
| `-D RND:15` | More decoys = harder to identify real source = slower scan |

**Named decoys:**

```bash
sudo nmap 10.129.2.28 -p 80 -D 203.0.113.1,198.51.100.5,ME
```

`ME` represents the real attacker's position in the decoy list. Placing `ME` sixth or later in the list means most IDS tools will not show the real IP at all.

Decoys work with: SYN scans, ACK scans, ICMP scans, OS detection scans. Decoys do NOT work with: Version detection (`-sV`) or NSE scripts (rely on full TCP stack).

---

### Evasion Technique 2 — Source Port Spoofing (`--source-port` / `-g`)

Many firewalls and IDS systems trust traffic appearing to come from well-known service ports. DNS (53), HTTP (80), and HTTPS (443) are commonly whitelisted. Spoofing the source port to 53 makes scan packets appear to originate from a DNS server.

```bash
sudo nmap 10.129.2.28 -p 50000 -sS -Pn -n --disable-arp-ping --source-port 53
```

| Flag | Purpose |
|---|---|
| `--source-port 53` | Set outgoing packet source port to 53 (DNS) |
| `-g 53` | Identical to `--source-port 53` — shorter alias |

When source port 53 bypasses a filtered port, direct connection via ncat with the same source port can retrieve the service banner:

```bash
sudo ncat -nv --source-port 53 10.129.2.47 50000
```

**Output:**

```
Ncat: Connected to 10.129.2.47:50000.
220 HTB{...flag_redacted...}
```

---

### Evasion Technique 3 — Packet Fragmentation (`-f`)

Breaks scan packets into small fragments. Some firewalls and older IDS systems process individual fragments rather than reassembling them — the signature matching logic fails because no single fragment matches the attack pattern.

```bash
sudo nmap -f 10.129.2.28 -p 80 -sS
```

| Flag | Purpose |
|---|---|
| `-f` | Fragment packets into 8-byte chunks |
| `-ff` | Fragment into 16-byte chunks |
| `--mtu <n>` | Custom fragment size — must be a multiple of 8 |

Note: Fragmentation does not work with version detection (`-sV`) or NSE scripts.

---

### Evasion Technique 4 — Source IP Spoofing (`-S`)

Makes scan traffic appear to originate from a different IP address. Useful for testing whether firewall rules are IP-specific and for evading IP-based detection rules.

```bash
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

| Flag | Purpose |
|---|---|
| `-S <IP>` | Spoof source IP address |
| `-e tun0` | Specify which network interface to use |

**Limitation:** Replies are sent to the spoofed IP, not to the attacker. No response data is received — useful only for one-way evasion testing.

---

### Evasion Technique 5 — Timing Adjustments (`-T`)

Slow scans evade time-based IDS detection rules that look for high packet rates from a single source.

| Template | Name | Speed | IDS Detection Risk |
|---|---|---|---|
| `-T0` | Paranoid | Slowest | Minimal |
| `-T1` | Sneaky | Slow | Very Low |
| `-T2` | Polite | Medium | Low |
| `-T3` | Normal | Default | Moderate |
| `-T4` | Aggressive | Fast | High |
| `-T5` | Insane | Fastest | Very High |

For evasion in hardened environments: `-T1` or `-T2`. For lab/CPTS environments: `-T4` is generally fine.

---

### Disabling Unnecessary Probes

Every unnecessary probe is another packet that could trigger detection:

```bash
sudo nmap 10.129.2.28 -p 53 -sU -sC -Pn -n --disable-arp-ping
```

| Flag | Purpose |
|---|---|
| `-Pn` | Skip host discovery — treat all hosts as up |
| `-n` | Disable DNS resolution — faster, no DNS logs created |
| `--disable-arp-ping` | Skip ARP requests on local subnets |

---

### Combining Evasion Techniques

Real hardened environments require combining multiple techniques simultaneously:

```bash
sudo nmap 10.129.2.47 -p 22,80,50000 -sV -sS -Pn -n \
--disable-arp-ping --packet-trace --source-port 53 -e tun0 -D RND:10
```

This command: uses source port 53 to bypass firewall rules, adds 10 random decoys to confuse IDS, disables ARP and host discovery to reduce noise, and traces every packet for verification.

---

## Skills Assessment Labs

### Lab 1 — Easy: OS Identification

**Objective:** Identify the operating system of the target.

**Approach:** Use version detection with disabled ARP ping to bypass local network filters.

```bash
sudo nmap -sV --top-ports 10 --disable-arp-ping 10.129.2.80
```

**Relevant output:**

```
PORT     STATE    SERVICE       VERSION
22/tcp   open     ssh           OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http          Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The SSH banner `Ubuntu 4ubuntu2.10` and Apache banner `(Ubuntu)` directly identify the OS. `Service Info: OS: Linux` confirms. The OS is Ubuntu.

**Answer:** Ubuntu

---

### Lab 2 — Medium: DNS Server Version via UDP Evasion

**Objective:** Identify the DNS server version running on the target. The port is filtered — standard TCP scans return nothing.

**Key insight:** DNS runs on UDP port 53. Standard TCP scans miss it. Use `-sU` for UDP scanning combined with `-Pn` and `--disable-arp-ping` to bypass host discovery blocks.

```bash
sudo nmap -Pn --disable-arp-ping -p53 -sU -sC 10.129.2.48
```

| Flag | Purpose |
|---|---|
| `-sU` | UDP scan — required for DNS on port 53 |
| `-sC` | Run default scripts — dns-nsid script reveals bind version |
| `-Pn` | Skip host discovery — host may not respond to ping |

**Output:**

```
PORT   STATE SERVICE
53/udp open  domain
| dns-nsid:
|_  bind.version: HTB{...flag_redacted...}
```

The `dns-nsid` NSE script queries the DNS server for its version string via the NSID (Name Server Identifier) extension. The version string returned here is the flag.

**Answer:** HTB{...flag_redacted...}

---

### Lab 3 — Hard: Service Version Behind IDS/IPS via Source Port Evasion

**Objective:** Identify the version of a service running on the target. A firewall and IDS are active — standard scans return filtered ports.

**Phase 1 — Full port scan with source port evasion to find all open ports:**

```bash
sudo nmap -sS -p- -Pn -n --disable-arp-ping --source-port 53 10.129.2.47
```

**Output:**

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
50000/tcp open  ibm-db2
```

Port 50000 only appears when scanning with source port 53 — the firewall is configured to allow traffic from port 53 (DNS) but blocks everything else.

**Phase 2 — Version detection with source port 53:**

```bash
sudo nmap -sV -p50000 --source-port 53 10.129.2.47
```

**Output:**

```
PORT      STATE SERVICE VERSION
50000/tcp open  ibm-db2 IBM Db2 (version string shows in banner)
```

**Phase 3 — Direct banner grab with ncat using source port 53:**

If Nmap version detection is still blocked, use ncat to connect directly with the same source port:

```bash
sudo ncat -nv --source-port 53 10.129.2.47 50000
```

**Output:**

```
Ncat: Connected to 10.129.2.47:50000.
220 HTB{...flag_redacted...}
```

The service banner on port 50000 contains the flag directly. Source port 53 was the key — the IDS was configured to allow DNS traffic and source port 53 spoofing bypassed the rule entirely.

**Answer:** HTB{...flag_redacted...}

---

## Key Takeaways

The TTL-based OS identification in the host discovery section was something I had read about but never consciously applied before this module. A single ping response with TTL 128 tells you it is Windows, TTL 64 tells you it is Linux — before running a single port scan. Reading what the target is already telling you before sending more packets is always the right approach.

The NSE `dns-nsid` script finding a bind version string embedded in a DNS response was unexpected. I assumed DNS was a low-value service that only mattered for zone transfers and subdomain enumeration. The fact that a default NSE script can pull a flag from a DNS version response made me realise that running `-sC` on every open port — not just web and SSH — is mandatory.

The firewall evasion labs were the most practically valuable part of the module. The Hard lab's core lesson — that a firewall rule whitelisting source port 53 can be abused by anyone to bypass the filter — is not theoretical. Real enterprise firewall rules frequently whitelist DNS, NTP, and other infrastructure service ports. Source port 53 is one of the most reliable bypass techniques in real engagements and it is worth memorising as a first-attempt evasion method when a port shows as filtered.

The combination of techniques in the Hard lab — `-sS`, `-Pn`, `-n`, `--disable-arp-ping`, `--source-port 53` all together — also reinforced that individual techniques rarely work alone in hardened environments. Each flag removes one noise source. Combining them removes enough noise that the signal gets through.

---

## Full Commands Reference

| Command | Purpose |
|---|---|
| `sudo nmap 10.129.2.0/24 -sn -oA hosts` | Host discovery sweep across a /24 subnet |
| `sudo nmap 10.129.2.18 -sn -PE --packet-trace --disable-arp-ping` | ICMP ping with full packet trace — TTL reveals OS |
| `sudo nmap -sS -p- 10.129.2.28 --open -T4` | Full TCP SYN scan — all ports, show only open |
| `sudo nmap --open -p- 10.129.2.28 \| grep "/tcp" \| wc -l` | Count open TCP ports |
| `sudo nmap -p445 10.129.2.28 -sV \| grep "Host:"` | Extract hostname from SMB banner |
| `sudo nmap -sV -p- 10.129.2.28 --stats-every=5s` | Full version scan with progress updates |
| `nc -nv 10.129.2.49 31337` | Manual banner grab via Netcat |
| `sudo nmap -p- 10.129.2.28 --open -oA results` | Save all output formats simultaneously |
| `xsltproc results.xml -o results.html` | Convert XML output to HTML report |
| `sudo nmap -p80 --script discovery 10.129.2.28` | Run all discovery scripts against port 80 |
| `curl http://10.129.2.28/robots.txt` | Fetch robots.txt found by NSE http-enum |
| `sudo nmap -O 10.129.2.28` | OS fingerprinting |
| `sudo nmap -A 10.129.2.28` | Aggressive — OS + version + scripts + traceroute |
| `sudo nmap -D RND:5 10.129.2.28 -p80 -sS -Pn -n --disable-arp-ping` | Decoy scan — 5 random fake source IPs |
| `sudo nmap --source-port 53 10.129.2.47 -p50000 -sS -Pn -n --disable-arp-ping` | Source port 53 evasion — bypass DNS-trusting firewall rules |
| `sudo ncat -nv --source-port 53 10.129.2.47 50000` | Direct banner grab via ncat with spoofed source port |
| `sudo nmap -Pn --disable-arp-ping -p53 -sU -sC 10.129.2.48` | UDP scan on DNS port with default scripts |
| `sudo nmap -f 10.129.2.28 -p80 -sS` | Fragment packets to evade stateless firewall inspection |
| `sudo nmap -sV --top-ports 10 --disable-arp-ping 10.129.2.80` | Top 10 ports version scan with ARP disabled |
| `sudo nmap 10.129.2.47 -p 22,80,50000 -sV -sS -Pn -n --disable-arp-ping --source-port 53 -e tun0 -D RND:10` | Combined evasion — source port + decoys + no ARP + no ping |

---

Main portfolio: [Offensive-Security-Portfolio](https://github.com/jaypatel-sec/Offensive-Security-Portfolio)
