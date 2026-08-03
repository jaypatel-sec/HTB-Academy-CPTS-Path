# HTB Academy — CPTS Path

**Author:** Jay Patel | **Path:** Certified Penetration Testing Specialist (CPTS)
**Started:** March 2026 | **Status:** In Progress (17/28 modules complete)

---

## What This Repository Is

Personal documentation of progress through the HTB Academy CPTS path. Written in my own words —
not copied from HTB, not a tutorial summary. Every module is documented with real lab output,
exact commands, and notes on what each technique actually means in practice.

---

## Prerequisites (Completed Before CPTS Path)

| Module | Status | Date |
|---|---|---|
| Linux Fundamentals | ✅ Complete | March 2026 |
| Bash Scripting | ✅ Complete | March 2026 |

---

## CPTS Path — Module Progress

| # | Module | Difficulty | Status | Date |
|---|---|---|---|---|
| 01 | Penetration Testing Process | Fundamental | ✅ Complete | March 2026 |
| 02 | Getting Started | Fundamental | ✅ Complete | March 2026 |
| 03 | Network Enumeration with Nmap | Easy | ✅ Complete | March 2026 |
| 04 | Footprinting | Medium | ✅ Complete | March 2026 |
| 05 | Information Gathering - Web Edition | Easy | ✅ Complete | April 2026 |
| 06 | Vulnerability Assessment | Easy | ✅ Complete | April 2026 |
| 07 | File Transfers | Medium | ✅ Complete | April 2026 |
| 08 | Shells and Payloads | Medium | ✅ Complete | April 2026 |
| 09 | Using the Metasploit Framework | Medium | ✅ Complete | April 2026 |
| 10 | Password Attacks | Medium | ✅ Complete | July 2026 |
| 11 | Attacking Common Services | Medium | ✅ Complete | April 2026 |
| 12 | Pivoting, Tunneling and Port Forwarding | Medium | ✅ Complete | July 2026 |
| 13 | Active Directory Enumeration and Attacks | Medium | ⏳ Pending | — |
| 14 | Using Web Proxies | Easy | ✅ Complete | July 2026 |
| 15 | Attacking Web Applications with Ffuf | Easy | ✅ Complete | July 2026 |
| 16 | Login Brute Forcing | Easy | ✅ Complete | August 2026 |
| 17 | SQL Injection Fundamentals | Medium | ⏳ Pending | — |
| 18 | SQLMap Essentials | Easy | ⏳ Pending | — |
| 19 | Cross-Site Scripting (XSS) | Easy | ⏳ Pending | — |
| 20 | File Inclusion | Medium | ⏳ Pending | — |
| 21 | File Upload Attacks | Medium | ⏳ Pending | — |
| 22 | Command Injections | Medium | ⏳ Pending | — |
| 23 | Web Attacks | Medium | ⏳ Pending | — |
| 24 | Attacking Common Applications | Medium | ⏳ Pending | — |
| 25 | Linux Privilege Escalation | Medium | ✅ Complete | May 2026 |
| 26 | Windows Privilege Escalation | Medium | ✅ Complete | July 2026 |
| 27 | Documentation and Reporting | Easy | ⏳ Pending | — |
| 28 | Attacking Enterprise Networks | Medium | ⏳ Pending | — |

### Module 10 — Password Attacks
- [Module Notes](10-Password-Attacks/Password-Attacks.md)
- [Skills Assessment](10-Password-Attacks/Skills-Assessment.md) — DMZ foothold → ligolo-ng pivot → Snaffler share hunting → Password Safe 3 cracking → LSASS hash extraction → NTDS Administrator hash

### Module 12 — Pivoting, Tunneling and Port Forwarding
- [Module Notes](12-Pivoting-Tunneling-and-Port-Forwarding/Pivoting-Tunneling-and-Port-Forwarding.md) — SSH local/dynamic/remote forwarding, Meterpreter AutoRoute, Socat redirectors, sshuttle, Chisel, ligolo-ng, rpivot, dnscat2, ptunnel-ng, Netsh, double pivots
- [Skills Assessment](12-Pivoting-Tunneling-and-Port-Forwarding/Skills-Assessment.md) — Web shell → SSH key → Ubuntu pivot → Meterpreter AutoRoute + SOCKS → RDP mlefay (Flag 1) → LSASS dump + Mimikatz → vfrank cleartext → RDP workstation (Flag 2) → Z: mapped share → DC (Flag 3)

### Module 14 — Using Web Proxies
- [Module Notes](14-Using-Web-Proxies/Using-Web-Proxies.md) — Burp Suite vs ZAP, FoxyProxy setup, CA certificates, request/response interception, Match and Replace, Repeater, Decoder/Inspector, proxychains, Metasploit proxying, Intruder (Sniper/Battering Ram/Pitchfork/Cluster Bomb), ZAP Fuzzer, Burp Scanner, ZAP Active Scanner, BApp Store, ZAP Marketplace
- [Skills Assessment](14-Using-Web-Proxies/Skills-Assessment.md) — ZAP Replacer strip `disabled>` (Flag 1) → ZAP Encoder ASCII Hex → Base64 decode 31-char MD5 cookie → Burp Intruder 3-rule encoding chain fuzz last MD5 char (Flag 2) → Metasploit `coldfusion_locale_traversal` proxied → CFIDE directory

### Module 15 — Attacking Web Applications with Ffuf
- [Module Notes](15-Attacking-Web-Applications-with-Ffuf/Attacking-Web-Applications-with-Ffuf.md) — Directory fuzzing, extension fuzzing, page fuzzing, recursive scanning, DNS /etc/hosts, sub-domain fuzzing, VHost fuzzing with Host header, response size filtering (`-fs`), GET parameter fuzzing, POST parameter fuzzing, value fuzzing with custom wordlists
- [Skills Assessment](15-Attacking-Web-Applications-with-Ffuf/Skills-Assessment.md) — VHost fuzzing → 3 sub-domains → extension fuzzing → recursive fuzzing with `-mr` regex match → POST parameter fuzzing → value fuzzing → `HTB{flag_redacted}`

### Module 16 — Login Brute Forcing
- [Module Notes](16-Login-Brute-Forcing/Login-Brute-Forcing.md) — Brute force types (simple/dictionary/hybrid/credential stuffing/password spraying), password security fundamentals, default credentials, Hydra (http-get/http-post-form/ssh/ftp/rdp), Basic HTTP Auth brute force, login form inspection + params string construction, Medusa (SSH/FTP modules), SSH pivot → internal FTP discovery, Username Anarchy, CUPP password profiling, grep-based wordlist policy filtering

### Module 26 — Windows Privilege Escalation
- [Module Notes](26-Windows-Privilege-Escalation/Windows-Privilege-Escalation.md)
- [Skills Assessment Part I](26-Windows-Privilege-Escalation/Skills-Assessment-Part-I.md) — Command injection → PrintNightmare → LaZagne
- [Skills Assessment Part II](26-Windows-Privilege-Escalation/Skills-Assessment-Part-II.md) — unattend.xml → AlwaysInstallElevated → PwDump8 + Hashcat

---

## Certification Roadmap

| Certification | Provider | Status |
|---|---|---|
| INE ICCA (Certified Cloud Associate) | INE | ✅ Completed |
| eJPT (eLearnSecurity Junior Penetration Tester) | INE / eLearnSecurity | ✅ Completed |
| HTB CPTS (Certified Penetration Testing Specialist) | HackTheBox | 🔄 In Progress |
| OSCP (Offensive Security Certified Professional) | OffSec | ⏳ Upcoming |
| eWPTX (Web Application Penetration Tester eXtreme) | INE / eLearnSecurity | ⏳ Upcoming |
| CPSA (CREST Practitioner Security Analyst) | CREST | ⏳ Upcoming |
| CRT (CREST Registered Tester) | CREST | ⏳ Upcoming |
| AZ-900 (Azure Fundamentals) | Microsoft | ⏳ Upcoming |

---

→ [Main Portfolio](https://github.com/jaypatel-sec/Offensive-Security-Portfolio)
