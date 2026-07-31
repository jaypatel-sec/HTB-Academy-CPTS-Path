# Attacking Web Applications with Ffuf

**Platform:** Hack The Box Academy  
**Module:** Attacking Web Applications with Ffuf  
**Sections:** 13  
**Difficulty:** Easy  
**Category:** Offensive Security / Web Application Penetration Testing  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [Web Fuzzing](#web-fuzzing)
3. [Directory Fuzzing](#directory-fuzzing)
4. [Page and Extension Fuzzing](#page-and-extension-fuzzing)
5. [Recursive Fuzzing](#recursive-fuzzing)
6. [DNS Records and /etc/hosts](#dns-records-and-etchosts)
7. [Sub-domain Fuzzing](#sub-domain-fuzzing)
8. [Vhost Fuzzing](#vhost-fuzzing)
9. [Filtering Results](#filtering-results)
10. [Parameter Fuzzing — GET](#parameter-fuzzing--get)
11. [Parameter Fuzzing — POST](#parameter-fuzzing--post)
12. [Value Fuzzing](#value-fuzzing)
13. [Key Flags Reference](#key-flags-reference)
14. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

Ffuf (Fuzz Faster U Fool) is one of the fastest and most versatile web fuzzing tools available. It sends hundreds of requests per second, studies HTTP response codes and sizes, and determines which resources exist on a target web server — replacing slow manual enumeration with automated, structured discovery.

This module covers five core use cases:

| Use Case | Ffuf Technique |
|----------|---------------|
| Find hidden directories | Directory fuzzing with FUZZ keyword in path |
| Find hidden files and their extensions | Extension fuzzing + page fuzzing under discovered directories |
| Find internal virtual hosts | VHost fuzzing via `-H 'Host: FUZZ.domain'` |
| Find undocumented GET parameters | GET parameter fuzzing via `?FUZZ=key` |
| Find undocumented POST parameters | POST parameter fuzzing via `-d 'FUZZ=key'` |
| Find valid parameter values | Value fuzzing with custom wordlist |

---

## Web Fuzzing

Fuzzing sends many different inputs to an interface to study how it reacts. For web fuzzing specifically:

- Send wordlist entries as path components, parameters, or header values
- Server returns HTTP 200 → resource exists
- Server returns HTTP 404 → resource does not exist
- Server returns HTTP 403 → resource exists but access is denied
- Server returns HTTP 301/302 → redirect, resource exists at another path

**Wordlists — SecLists:**

SecLists (`/opt/useful/seclists/`) is the standard wordlist repository used throughout web fuzzing:

| Wordlist | Path | Use Case |
|---------|------|----------|
| directory-list-2.3-small.txt | `/opt/useful/seclists/Discovery/Web-Content/` | Directory and page fuzzing |
| web-extensions.txt | `/opt/useful/seclists/Discovery/Web-Content/` | Extension fuzzing |
| subdomains-top1million-5000.txt | `/opt/useful/seclists/Discovery/DNS/` | Sub-domain and VHost fuzzing |
| burp-parameter-names.txt | `/opt/useful/seclists/Discovery/Web-Content/` | GET and POST parameter fuzzing |

> **Tip:** Use `-ic` to ignore comment lines at the top of wordlists (e.g., copyright headers in directory-list-2.3).

---

## Directory Fuzzing

The two required flags for every ffuf command are `-w` (wordlist) and `-u` (URL). The `FUZZ` keyword marks the injection point — ffuf substitutes each wordlist entry there.

**Basic syntax:**

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://SERVER_IP:PORT/FUZZ
```

**Example output:**

```
blog                    [Status: 301, Size: 326, Words: 20, Lines: 10]
:: Progress: [87651/87651] :: Job [1/1] :: 9739 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

Ffuf tests ~90k URLs in under 10 seconds with the default 40 threads.

**Thread tuning:**

| Flag | Value | Notes |
|------|-------|-------|
| `-t` | 40 | Default — safe for most targets |
| `-t` | 200 | Fast — may disrupt fragile servers or saturate home connections |

> **Never use high thread counts against production systems** — it constitutes a DoS risk.

**Default matched status codes:** `200, 204, 301, 302, 307, 401, 403`

---

## Page and Extension Fuzzing

### Extension Fuzzing

When a directory is found but returns an empty page, fuzz for the server's file extension before fuzzing for pages. Place `FUZZ` where the extension would appear:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
     -u http://SERVER_IP:PORT/blog/indexFUZZ
```

```
.php                    [Status: 200, Size: 0, Words: 1, Lines: 1]
.phps                   [Status: 403, Size: 283, Words: 20, Lines: 10]
```

> **Note:** The web-extensions.txt wordlist already includes the leading dot — do not add an extra dot in the URL.

### Page Fuzzing

Once the extension is known (e.g., `.php`), fuzz for filenames under the discovered directory:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://SERVER_IP:PORT/blog/FUZZ.php
```

```
index                   [Status: 200, Size: 0, Words: 1, Lines: 1]
admin                   [Status: 200, Size: 465, Words: 42, Lines: 15]
```

A non-zero `Size` value indicates the page has content worth visiting.

---

## Recursive Fuzzing

Recursive scanning automatically spawns new scans under every newly discovered directory, eliminating the need to manually re-run ffuf at each level.

**Flags:**

| Flag | Purpose |
|------|--------|
| `-recursion` | Enable recursive scanning |
| `-recursion-depth 1` | Only fuzz direct sub-directories (depth 1 = main dir + one level) |
| `-e .php` | Append this extension to every wordlist entry in recursive scans |
| `-v` | Output full URLs (required to distinguish which file is under which directory) |

**Command:**

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://SERVER_IP:PORT/FUZZ \
     -recursion -recursion-depth 1 -e .php -v
```

**Example output:**

```
[Status: 301] | URL | http://SERVER_IP:PORT/blog
[INFO] Adding a new job to the queue: http://SERVER_IP:PORT/blog/FUZZ
[Status: 200] | URL | http://SERVER_IP:PORT/blog/index.php
[Status: 200] | URL | http://SERVER_IP:PORT/forum/admin.php
```

> **Note:** Recursive scans double the request count (each entry tested once bare, once with the extension). Limit depth to avoid exponential scan growth on deeply nested sites.

---

## DNS Records and /etc/hosts

When a page redirects to a hostname (e.g., `academy.htb`) that is not publicly registered, the browser cannot resolve it. The hostname must be manually added to `/etc/hosts` to make it reachable.

**Add a hostname:**

```bash
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

After adding the entry, the browser resolves `academy.htb` to `SERVER_IP` directly — bypassing public DNS — and the site becomes accessible.

> **Key point:** Adding `academy.htb` to `/etc/hosts` does not automatically resolve sub-domains like `admin.academy.htb`. Each sub-domain found via VHost fuzzing must be added separately before it can be browsed.

---

## Sub-domain Fuzzing

Sub-domain fuzzing checks whether publicly resolvable sub-domains exist by placing `FUZZ` in the sub-domain position of the URL:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u https://FUZZ.inlanefreight.com/
```

**Limitation:** This only finds sub-domains with **public DNS records**. Internal or private sub-domains (like those under `academy.htb`) will not be found this way — every request returns an error because the public DNS has no record of them.

```
:: Progress: [4997/4997] :: Job [1/1] :: 131 req/sec :: Errors: 4997 ::
```

All 4997 errors = no public DNS records found. Use VHost fuzzing instead for internal targets.

---

## Vhost Fuzzing

VHost fuzzing tests for virtual hosts (sub-domains hosted on the same IP) by fuzzing the `Host:` HTTP header rather than the URL path. This discovers both public and non-public VHosts without requiring `/etc/hosts` entries.

**Key difference from sub-domain fuzzing:**

| Method | Technique | Finds |
|--------|-----------|-------|
| Sub-domain fuzzing | URL: `FUZZ.domain.com` | Public DNS sub-domains only |
| VHost fuzzing | Header: `Host: FUZZ.domain.com` | Public and private VHosts |

**Command:**

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://academy.htb:PORT/ \
     -H 'Host: FUZZ.academy.htb'
```

Without filtering, every entry returns 200 OK (the same default page regardless of the Host header). The useful signal is a **different response size** — a valid VHost will serve a different page, producing a different byte count.

---

## Filtering Results

Ffuf supports both matching (keep only responses that meet a condition) and filtering (exclude responses that meet a condition).

**Matcher flags:**

| Flag | Matches on |
|------|------------|
| `-mc` | HTTP status code(s) |
| `-ms` | Response size |
| `-ml` | Number of lines |
| `-mw` | Number of words |
| `-mr` | Regex pattern |

**Filter flags:**

| Flag | Filters out |
|------|-------------|
| `-fc` | HTTP status code(s) |
| `-fs` | Response size |
| `-fl` | Number of lines |
| `-fw` | Number of words |
| `-fr` | Regex pattern |

**VHost fuzzing with size filter:**

First run without filter to identify the baseline response size (e.g., 900 bytes for all invalid VHosts). Then filter it out:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://academy.htb:PORT/ \
     -H 'Host: FUZZ.academy.htb' \
     -fs 900
```

```
admin                   [Status: 200, Size: 0, Words: 1, Lines: 1]
```

The `admin` VHost produces a different response size — confirming it is a real, distinct VHost. Add it to `/etc/hosts` and browse to verify:

```bash
sudo sh -c 'echo "SERVER_IP  admin.academy.htb" >> /etc/hosts'
```

---

## Parameter Fuzzing — GET

GET parameters are appended to the URL after `?`. Fuzz by placing `FUZZ` in the parameter name position:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key \
     -fs <baseline_size>
```

The `-fs` value is determined by running without the filter first to see the default response size for unknown parameters.

**Why fuzz GET parameters:**
- Pages may accept undocumented parameters not visible in the UI
- Unpublished parameters are often less tested and less secured
- Can expose functionality gated behind a simple key/value pair

**Example hit:**

```
user                    [Status: 200, Size: 783, Words: 63, Lines: 26]
```

Visit `?user=key` — if it returns a message like "This method is deprecated", the parameter exists but may point to legacy functionality. Continue to POST fuzzing.

---

## Parameter Fuzzing — POST

POST parameters are passed in the request body, not the URL. Required flags:

| Flag | Purpose |
|------|--------|
| `-X POST` | Send POST requests instead of GET |
| `-d 'FUZZ=key'` | POST body — FUZZ marks the parameter name position |
| `-H 'Content-Type: application/x-www-form-urlencoded'` | Required for PHP POST data |

**Command:**

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u http://admin.academy.htb:PORT/admin/admin.php \
     -X POST \
     -d 'FUZZ=key' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -fs <baseline_size>
```

**Example hit:**

```
id                      [Status: 200, Size: 768, Words: 57, Lines: 24]
```

Verify with curl:

```bash
curl http://admin.academy.htb:PORT/admin/admin.php \
     -X POST \
     -d 'id=key' \
     -H 'Content-Type: application/x-www-form-urlencoded'
```

```
<div class='center'><p>Invalid id!</p></div>
```

`Invalid id!` confirms the parameter is real — the server is validating the value. Now fuzz for the correct value.

---

## Value Fuzzing

When no pre-made wordlist fits the expected parameter type, generate a custom one. For a numeric `id` parameter, create a sequential ID list:

**Generate wordlist (1–1000):**

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

**Fuzz with custom wordlist:**

```bash
ffuf -w ids.txt:FUZZ \
     -u http://admin.academy.htb:PORT/admin/admin.php \
     -X POST \
     -d 'id=FUZZ' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -fs <baseline_size>
```

**Example hit:**

```
73                      [Status: 200, Size: 792, Words: 61, Lines: 25]
```

Retrieve the flag with curl:

```bash
curl http://admin.academy.htb:PORT/admin/admin.php \
     -X POST \
     -d 'id=73' \
     -H 'Content-Type: application/x-www-form-urlencoded'
```

**Wordlist generation strategies:**

| Parameter Type | Wordlist Approach |
|---------------|------------------|
| Numeric ID | `seq 1 1000` bash loop |
| Username | SecLists `/Usernames/` |
| Common values | SecLists `/Fuzzing/` |
| Application-specific | Manual creation based on enumeration |

---

## Key Flags Reference

| Flag | Purpose | Example |
|------|---------|--------|
| `-w wordlist:KEYWORD` | Assign wordlist to a keyword | `-w list.txt:FUZZ` |
| `-u` | Target URL with FUZZ keyword | `-u http://IP/FUZZ` |
| `-H` | Add HTTP header | `-H 'Host: FUZZ.domain.com'` |
| `-X` | HTTP method | `-X POST` |
| `-d` | POST data | `-d 'param=FUZZ'` |
| `-t` | Thread count (default 40) | `-t 200` |
| `-e` | File extension(s) for recursive scans | `-e .php` |
| `-recursion` | Enable recursive scanning | |
| `-recursion-depth` | Max recursion depth | `-recursion-depth 1` |
| `-v` | Verbose — print full URLs | |
| `-ic` | Ignore wordlist comment lines | |
| `-mc` | Match status code(s) | `-mc 200,301` |
| `-ms` | Match response size | `-ms 500` |
| `-fc` | Filter status code(s) | `-fc 404` |
| `-fs` | Filter response size | `-fs 900` |
| `-fw` | Filter by word count | `-fw 20` |
| `-o` | Write output to file | `-o results.txt` |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1595 | T1595.003 | Active Scanning: Wordlist Scanning — directory, page, and extension fuzzing |
| T1083 | — | File and Directory Discovery — recursive ffuf scan revealing hidden paths |
| T1046 | — | Network Service Discovery — VHost fuzzing identifying internal virtual hosts |
| T1190 | — | Exploit Public-Facing Application — parameter fuzzing exposing unpublished POST endpoints |
| T1592 | T1592.002 | Gather Victim Host Information: Software — extension fuzzing revealing PHP stack |
| T1589 | T1589.001 | Gather Victim Identity Information — sub-domain enumeration mapping attack surface |
| T1071 | T1071.001 | Application Layer Protocol: Web — all fuzzing conducted over HTTP/HTTPS |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
