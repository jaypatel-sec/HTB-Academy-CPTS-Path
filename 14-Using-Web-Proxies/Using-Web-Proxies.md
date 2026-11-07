# Using Web Proxies

**Platform:** Hack The Box Academy  
**Module:** Using Web Proxies  
**Sections:** 15  
**Difficulty:** Easy  
**Category:** Offensive Security / Web Application Penetration Testing  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [Burp Suite vs ZAP — Tool Comparison](#burp-suite-vs-zap--tool-comparison)
3. [Setup and Configuration](#setup-and-configuration)
   - [Proxy Setup with FoxyProxy](#proxy-setup-with-foxyproxy)
   - [Installing CA Certificates](#installing-ca-certificates)
4. [Intercepting Web Requests](#intercepting-web-requests)
   - [Intercepting Requests — Burp](#intercepting-requests--burp)
   - [Intercepting Requests — ZAP and HUD](#intercepting-requests--zap-and-hud)
   - [Intercepting Responses](#intercepting-responses)
5. [Automatic Modification](#automatic-modification)
   - [Match and Replace — Burp](#match-and-replace--burp)
   - [Replacer — ZAP](#replacer--zap)
6. [Repeating Requests](#repeating-requests)
   - [Burp Repeater](#burp-repeater)
   - [ZAP Request Editor](#zap-request-editor)
7. [Encoding and Decoding](#encoding-and-decoding)
   - [Burp Decoder and Inspector](#burp-decoder-and-inspector)
   - [ZAP Encoder/Decoder/Hash](#zap-encoderdecoderhash)
8. [Proxying CLI Tools](#proxying-cli-tools)
   - [Proxychains](#proxychains)
   - [Metasploit](#metasploit)
9. [Web Fuzzing](#web-fuzzing)
   - [Burp Intruder](#burp-intruder)
   - [ZAP Fuzzer](#zap-fuzzer)
10. [Web Scanning](#web-scanning)
    - [Burp Scanner](#burp-scanner)
    - [ZAP Active Scanner](#zap-active-scanner)
11. [Extensions](#extensions)
    - [Burp BApp Store](#burp-bapp-store)
    - [ZAP Marketplace](#zap-marketplace)
12. [Key Shortcuts Reference](#key-shortcuts-reference)
13. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

Web proxies sit between the browser and the back-end server, acting as a transparent man-in-the-middle. Every HTTP/HTTPS request and response passes through them, giving the penetration tester complete visibility and control over all web traffic. They are the single most essential tool in web application penetration testing — enabling request interception, modification, replay, fuzzing, scanning, and encoding without requiring external tools for most tasks.

This module covers **Burp Suite** (industry-standard, partly commercial) and **OWASP ZAP** (free, open-source) side by side across every feature, so a tester can choose the right tool for each situation.

### Use Cases for Web Proxies

| Use Case | Burp Feature | ZAP Feature |
|----------|-------------|-------------|
| Capture and inspect HTTP traffic | Proxy → HTTP History | History pane / HUD |
| Modify and replay requests | Repeater | Request Editor / HUD Replay |
| Auto-modify all requests or responses | Match and Replace | Replacer |
| Fuzz parameters, directories, credentials | Intruder | Fuzzer |
| Automated vulnerability scanning | Scanner (Pro) | Active Scanner |
| Encode/decode/hash values | Decoder + Inspector | Encoder/Decoder/Hash |
| Proxy CLI tools (curl, msfconsole) | HTTP proxy on 8080 | HTTP proxy on 8080 |
| Extend functionality | BApp Store | ZAP Marketplace |

---

## Burp Suite vs ZAP — Tool Comparison

| Feature | Burp Community | Burp Pro | ZAP |
|---------|---------------|----------|-----|
| Price | Free | Paid | Free (open-source) |
| Active Web Scanner | ✗ | ✓ | ✓ |
| Intruder speed | Throttled (1 req/sec) | Unlimited | N/A |
| Fuzzer speed | N/A | N/A | Unlimited |
| Extensions | Most available | All available | ZAP Marketplace |
| Built-in browser | ✓ (Chromium) | ✓ (Chromium) | ✓ (Firefox) |
| HUD (in-browser overlay) | ✗ | ✗ | ✓ |
| Save projects | ✗ | ✓ | ✓ |
| Best for | Manual testing, repeating, learning | Full professional web engagements | Scanning, fuzzing, open-source workflows |

> **Practical decision:** Use Burp for manual interception, repeating, and request manipulation. Use ZAP for scanning and unlimited-speed fuzzing when the Pro version of Burp is not available.

---

## Setup and Configuration

### Proxy Setup with FoxyProxy

Both Burp and ZAP listen on `127.0.0.1:8080` by default. FoxyProxy is a Firefox extension that lets you switch between proxy profiles in one click without changing Firefox settings manually.

**Configure FoxyProxy:**

```
FoxyProxy → Options → Add
  Title: Burp (or ZAP)
  Proxy Type: HTTP
  IP Address: 127.0.0.1
  Port: 8080
  → Save
```

**Activate proxy:**
```
Click FoxyProxy icon in toolbar → Select Burp/ZAP
```

To change the default proxy port:
- **Burp:** `Proxy → Proxy settings → Proxy listeners`
- **ZAP:** `Tools → Options → Network → Local Servers/Proxies`

> **Tip:** Both tools include a pre-configured browser that requires no setup — use it for quick testing. For production testing that requires your actual Firefox profile, configure FoxyProxy.

---

### Installing CA Certificates

HTTPS traffic must be decrypted by the proxy to be inspected. Both tools act as a CA and re-sign all certificates on the fly. Without installing their CA certificate, Firefox will throw SSL errors on every HTTPS site.

**Burp CA Certificate:**

```
1. Activate Burp as proxy in FoxyProxy
2. Navigate to http://burp in browser
3. Click "CA Certificate" → download cacert.der
4. Firefox → about:preferences#privacy → View Certificates
5. Authorities tab → Import → select cacert.der
6. Check: "Trust this CA to identify websites" → OK
```

**ZAP CA Certificate:**

```
1. ZAP → Tools → Options → Network → Server Certificates → Save
2. Firefox → about:preferences#privacy → View Certificates
3. Authorities tab → Import → select ZAP certificate
4. Check: "Trust this CA to identify websites" → OK
```

Once installed, all HTTPS traffic is decrypted, inspected, and re-encrypted transparently — no browser warnings.

---

## Intercepting Web Requests

### Intercepting Requests — Burp

Burp's intercept captures each request and holds it until the tester takes action.

```
Proxy tab → Intercept sub-tab → "Intercept is on" (toggle)
```

**Workflow:**

```
Turn Intercept ON
    ↓
Browser sends request (e.g. click Ping)
    ↓
Burp holds the request in the Proxy → Intercept pane
    ↓
Inspect / modify the raw HTTP request
    ↓
Click "Forward" to send it to the server
    ↓
Click "Drop" to discard the request entirely
```

**Example — intercepted POST request:**

```http
POST /ping HTTP/1.1
Host: 94.237.62.138:32306
Content-Type: application/x-www-form-urlencoded
Content-Length: 4

ip=1
```

Modify `ip=1` to `ip=;ls;` — the back-end executes the injected command, proving command injection. This is the core workflow for testing SQL injection, command injection, upload bypass, authentication bypass, and similar vulnerabilities.

> **Note:** All Firefox traffic is intercepted — not just the target. If unrelated requests appear first, keep clicking Forward until the target request appears.

---

### Intercepting Requests — ZAP and HUD

ZAP interception is **off by default** (green button = requests flow freely, red = intercepted).

**Toggle interception:**
```
Click the green/red break button in the top bar
OR press CTRL+B
```

**ZAP HUD (Heads Up Display):**

ZAP's HUD overlays directly onto the pre-configured browser, surfacing proxy controls without switching windows:

```
Enable HUD: Click the HUD button at the end of the top menu bar
```

HUD intercept controls:
- **Step** — Forward current request and intercept the response
- **Continue** — Forward all remaining requests without intercepting
- **Drop** — Discard the current request

**ZAP-specific advantage:** The HUD's **Show/Enable** button (light bulb icon) can instantly enable disabled HTML form fields or reveal hidden fields without intercepting and modifying the response — saving time when you just need to unlock an input.

```
HUD left pane → Light bulb icon → Enables all disabled/hidden fields on the page
```

**Comments button** reveals HTML comment positions directly in the browser, flagging potential information disclosure without needing to view page source.

---

### Intercepting Responses

By default, only requests are intercepted. Intercepting the server's response before it reaches the browser lets us modify the rendered HTML — for example, removing JavaScript input validation or enabling disabled form fields.

**Burp — Enable response interception:**

```
Proxy → Proxy settings → Response interception rules
→ Enable "Intercept responses based on the following rules" → check "Or request was intercepted"
```

**Practical example — remove client-side input validation:**

Original response from server:
```html
<input type="number" id="ip" name="ip" min="1" max="255" maxlength="3" required>
```

Modified in Burp before forwarding to browser:
```html
<input type="text" id="ip" name="ip" min="1" max="255" maxlength="100" required>
```

Result: The browser now accepts any character in the IP field — not just numbers. The input restriction was only enforced by the front end; the back end performs no validation, confirming the command injection vulnerability.

**ZAP** — When a request is intercepted, clicking **Step** automatically intercepts the response before it reaches the browser, presenting both the request and response for modification in the same workflow.

---

## Automatic Modification

Intercepting and manually modifying every request is impractical for ongoing testing. Automatic modification rules apply changes to every matching request or response without requiring manual intervention.

### Match and Replace — Burp

```
Proxy → Proxy settings → HTTP match and replace rules → Add
```

**Example 1 — Replace User-Agent in all requests:**

| Field | Value |
|-------|-------|
| Type | Request header |
| Match | `^User-Agent.*$` |
| Replace | `User-Agent: HackTheBox Agent 1.0` |
| Regex match | True |

Result: Every outgoing request automatically carries the custom User-Agent — useful for bypassing User-Agent-based WAF filters.

**Example 2 — Permanently unlock input fields in all responses:**

| Field | Value |
|-------|-------|
| Type | Response body |
| Match | `type="number"` |
| Replace | `type="text"` |
| Regex match | False |

Add a second rule:

| Field | Value |
|-------|-------|
| Type | Response body |
| Match | `maxlength="3"` |
| Replace | `maxlength="100"` |

Result: Every time the page loads, the IP input field accepts any text and up to 100 characters — no need to intercept the response on every page refresh.

---

### Replacer — ZAP

```
ZAP → Tools → Options → Replacer (or CTRL+R) → Add
```

**Example — Replace User-Agent:**

| Field | Value |
|-------|-------|
| Description | HTB User-Agent |
| Match Type | Request Header (will add if not present) |
| Match String | User-Agent |
| Replacement String | HackTheBox Agent 1.0 |
| Enable | True |

ZAP Replacer also supports the **Initiators** tab to restrict which types of traffic the rule applies to (e.g., only manual browser requests, not scanner or fuzzer traffic).

---

## Repeating Requests

Repeating allows resending previously captured requests with modifications — without intercepting fresh requests each time. Essential for iterating through payloads during manual testing.

### Burp Repeater

```
Proxy → HTTP History → Right-click request → Send to Repeater
OR press CTRL+R on the intercepted request

Navigate to Repeater tab: CTRL+SHIFT+R
```

```
Repeater workflow:
  Select text to modify → change payload → click "Send" → view response immediately
```

**Key shortcuts in Repeater:**
- `CTRL+R` — Send request to Repeater from Proxy History
- `CTRL+SHIFT+R` — Jump directly to Repeater tab
- Right-click → **Change Request Method** — Toggle between GET/POST without rewriting the request

**Example — Command injection iteration:**

```
Original: ip=1
Modified: ip=;whoami;        → returns www-data
Modified: ip=;cat /etc/passwd; → returns all users
Modified: ip=;ls /home/;     → returns home directories
```

Each modification is sent with a single click — response appears immediately in the right pane.

---

### ZAP Request Editor

```
Proxy History → Right-click request → Open/Resend with Request Editor
```

**ZAP HUD equivalent:**

```
History pane (bottom) → Click request → HTTP Message dialog
→ "Replay in Console" (view response in HUD)
→ "Replay in Browser" (render response in browser)
```

> **Tip:** ZAP's Request Editor shows only the final sent request. Burp Repeater shows both the **Original Request** and the **Edited Request** — useful for comparing changes and debugging modifications.

---

## Encoding and Decoding

HTTP requires specific characters to be URL-encoded to prevent misinterpretation. Additionally, web applications frequently encode data (base64, HTML entities, hex) — all of which must be decoded to understand and test effectively.

**Characters that must be URL-encoded in HTTP:**

| Character | Meaning if unencoded | Encoded Form |
|-----------|---------------------|-------------|
| Space | Ends request data | `%20` or `+` |
| `&` | Parameter delimiter | `%26` |
| `#` | Fragment identifier | `%23` |
| `=` | Key-value separator | `%3D` |

### Burp Decoder and Inspector

**Burp Decoder tab:**

```
Decoder tab → Paste value → Select "Decode as" or "Encode as"
Supported: URL, HTML, Base64, ASCII Hex, Hex, Octal, Binary, Gzip
```

**Burp Inspector** (inline, available in Proxy and Repeater):

```
Select text in request/response → Inspector panel on the right
→ Automatically shows URL-decoded, Base64-decoded, and other representations
```

**Practical example — Privilege escalation via cookie tampering:**

Base64 encoded cookie found in traffic:
```
eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=
```

Decode in Burp Decoder → Base64:
```json
{"username":"guest", "is_admin":false}
```

Modify and re-encode:
```json
{"username":"admin", "is_admin":true}
```

Re-encoded Base64:
```
eyJ1c2VybmFtZSI6ImFkbWluIiwgImlzX2FkbWluIjp0cnVlfQ==
```

Replace the cookie value in Burp Repeater and send — if the application trusts the cookie without server-side validation, admin access is achieved.

**Burp Repeater URL-encoding shortcut:**

```
Select text in request body → Right-click → Convert Selection → URL → URL-encode key characters
OR press CTRL+U
```

---

### ZAP Encoder/Decoder/Hash

```
CTRL+E → Encoder/Decoder/Hash window
```

ZAP's tool automatically shows the selected text decoded across multiple formats simultaneously in the **Decode** tab. Custom tabs can be created with the **Add New Tab** button, combining any encoders/decoders/hash functions into a single view.

Supported operations:
- Base64 Encode/Decode
- URL Encode/Decode
- HTML Encode/Decode
- Unicode Encode/Decode
- MD5 / SHA-1 / SHA-256 / SHA-512 Hash
- ASCII Hex

ZAP also automatically URL-encodes request data in the background before sending — this is handled transparently, unlike Burp where manual encoding is sometimes needed.

---

## Proxying CLI Tools

Web proxies are not limited to browser traffic. Any CLI tool or thick client that makes HTTP requests can be routed through Burp/ZAP for inspection and manipulation.

### Proxychains

The fastest way to proxy any Linux CLI tool — no per-tool configuration needed.

**Configure `/etc/proxychains.conf`:**

```bash
# Comment out the default SOCKS line
#socks4  127.0.0.1 9050

# Add the Burp/ZAP HTTP proxy
http 127.0.0.1 8080
```

**Usage:**

```shell-session
# Route curl through Burp/ZAP — suppress connection info with -q
Hackerpatel007_1@htb[/htb]$ proxychains -q curl http://SERVER_IP:PORT

# Route any other tool the same way
Hackerpatel007_1@htb[/htb]$ proxychains -q nmap -sT -p80,443 SERVER_IP
Hackerpatel007_1@htb[/htb]$ proxychains -q sqlmap -u "http://SERVER_IP:PORT/?id=1"
```

All requests appear in Burp's Proxy → HTTP History or ZAP's History pane, allowing full inspection and modification of CLI tool traffic.

> **Note:** Proxying slows down tools significantly. Only proxy when actively inspecting traffic — run normal scans without proxychains.

---

### Metasploit

Route Metasploit module web traffic through the proxy with the `PROXIES` option:

```shell-session
Hackerpatel007_1@htb[/htb]$ msfconsole -q

msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080
msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP
msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT
msf6 auxiliary(scanner/http/robots_txt) > run

[*] Scanned 1 of 1 hosts (100% complete)
```

The module's HTTP requests appear in the proxy history — useful for debugging scanner behaviour, modifying requests mid-scan, or understanding exactly what Metasploit is sending to the server.

---

## Web Fuzzing

Web fuzzing automates the process of sending many different payloads to web endpoints to discover vulnerabilities, hidden directories, valid parameters, or brute-force credentials.

### Burp Intruder

Burp Intruder is powerful but throttled to 1 request/second in the Community version. Use it for short, targeted attacks; for larger wordlists use ZAP Fuzzer or CLI tools like `ffuf`.

**Workflow — Directory Fuzzing:**

```
Proxy History → Right-click target request → Send to Intruder (CTRL+I)
Navigate to Intruder: CTRL+SHIFT+I
```

**Step 1 — Positions (Payload Placement):**

Wrap the fuzzing target with `§` markers, or select the word and click **Add §**:

```http
GET /§DIRECTORY§/ HTTP/1.1
Host: SERVER_IP:PORT
```

**Step 2 — Payloads (Wordlist Configuration):**

| Option | Setting |
|--------|--------|
| Payload Type | Simple List |
| Load | `/opt/useful/seclists/Discovery/Web-Content/common.txt` |
| Payload Processing | Skip if matches regex `^\..*$` (skip lines starting with `.`) |
| Payload Encoding | URL-encode key characters (enabled) |

> For very large wordlists, use **Runtime file** instead of Simple List to avoid loading the entire wordlist into memory at once.

**Step 3 — Settings (Grep-Match):**

Configure **Grep - Match** to flag responses containing `200 OK`:

```
Settings → Grep - Match → Clear → Type "200 OK" → Add
Disable "Exclude HTTP Headers"
```

**Step 4 — Attack:**

Click **Start Attack** → Sort results by the `200 OK` column → Identified `/admin/` returns 200.

**Intruder Attack Types:**

| Type | Description | Use Case |
|------|-------------|----------|
| Sniper | Single payload list, one position at a time | Directory fuzzing, parameter testing |
| Battering Ram | Same payload in all positions simultaneously | Username = Password brute force |
| Pitchfork | Different payload lists per position, matched by index | Credential spraying (user:pass pairs) |
| Cluster Bomb | All combinations across multiple positions | Full credential brute force |

---

### ZAP Fuzzer

ZAP Fuzzer has **no rate throttling** — significantly faster than Burp Community Intruder for large wordlists.

**Workflow — Directory Fuzzing:**

```
Proxy History → Right-click target request → Attack → Fuzz
```

**Step 1 — Fuzz Location:**

Select the directory name in the request (e.g., `test` in `GET /test/`) → Click **Add**.

**Step 2 — Payloads:**

| Type | Option | Details |
|------|--------|---------|
| File | Custom path | Load external wordlist from disk |
| File Fuzzers | Built-in databases | DirBuster, FuzzDB wordlists (no file needed) |
| Numberzz | Numeric sequences | Parameter enumeration, ID fuzzing |

Select `File Fuzzers → dirbuster → directory-list-1.0.txt` for directory fuzzing.

**Step 3 — Processors:**

Add a **URL Encode** processor to ensure all payload characters are properly encoded before sending. Click **Generate Preview** to verify encoding.

**Step 4 — Options:**

| Option | Recommended Value |
|--------|------------------|
| Concurrent Threads | 20 (adjust to server tolerance) |
| Strategy | Depth First (all payloads per position) or Breadth First (all positions per payload) |
| Follow Redirects | Depends on application |

**Start Fuzzer** → Sort results by **Response Code** → Filter for `200` responses.

---

## Web Scanning

Automated vulnerability scanning tests all discovered endpoints and parameters for common web vulnerabilities — SQLi, XSS, command injection, path traversal, and more.

### Burp Scanner

Burp Scanner is available in **Pro/Enterprise only**. It runs both passive scanning (analysing existing traffic) and active scanning (sending crafted payloads to test for vulnerabilities).

**Passive Scan** — runs automatically in the background on all proxied traffic, flagging potential issues without sending additional requests.

**Active Scan:**

```
Proxy History → Right-click target request → Scan
OR
Dashboard → New Scan → select scope and crawl/audit options
```

The scanner crawls the application, builds a site map, then actively sends payloads to all discovered parameters. Results appear in the **Dashboard** and **Target → Issues** tabs, categorised by severity: High, Medium, Low, Informational.

**Issue Severity Triage:**

| Severity | Action |
|----------|--------|
| High | Always investigate first — potential direct compromise |
| Medium | Investigate after Highs — significant risk |
| Low | Include in report — may chain with other issues |
| Informational | Log for context — headers, version disclosure |

---

### ZAP Active Scanner

ZAP's Active Scanner is available in the **free version** with no limitations.

**From ZAP main UI:**

```
Right-click target in Sites tree → Attack → Active Scan
→ Configure scope → Start Scan
```

**From ZAP HUD:**

```
HUD left pane → Active Scan button → Select scan policy → Start
```

Monitor progress in the Active Scan tab — the scanner shows percentage completion and requests per second:

```
Active scan at 42% on http://46.101.23.188:30873
```

**Viewing Results:**

```
Alerts tab → filter by Risk level
High Alerts → Remote OS Command Injection detected

Attack example: 127.0.0.1&cat /etc/passwd&
Evidence: root:x:0:0
```

Click any alert to view:
- The full request ZAP used to trigger the vulnerability
- The response containing the evidence
- Option to replay in Console or Browser for manual verification

**Generating Reports:**

```
ZAP → Report → Generate HTML Report → Select save path
```

Report includes all alerts categorised by risk level with request/response evidence — ready for inclusion in a penetration test deliverable.

---

## Extensions

### Burp BApp Store

```
Extensions tab → BApp Store sub-tab → Sort by Popularity
```

**Notable extensions:**

| Extension | Purpose |
|-----------|---------|
| **Active Scan++** | Additional active scan checks — host header injection, edge-side includes, XML input |
| **Autorize** | Automatically tests for authorisation bypass on every request |
| **CSRF Scanner** | Detects CSRF vulnerabilities across all forms |
| **Decoder Improved** | Extended encoding/decoding/hashing with hex editor and Unicode support |
| **JS Link Finder** | Extracts endpoints from JavaScript files |
| **Retire.JS** | Identifies vulnerable JavaScript libraries |
| **Software Version Reporter** | Identifies software versions from HTTP headers and responses |
| **Backslash Powered Scanner** | Detects server-side injection via backslash probing |
| **HTTP Request Smuggler** | Tests for HTTP request smuggling vulnerabilities |
| **Java Deserialization Scanner** | Detects Java deserialization vulnerabilities |
| **PHP Object Injection Check** | Detects PHP object injection vulnerabilities |
| **CSP Auditor** | Analyses and flags weak Content Security Policy headers |
| **Random IP Address Header** | Randomises `X-Forwarded-For` and similar headers to bypass IP-based rate limiting |

> **Note:** Some extensions require Jython (Python runtime) or additional dependencies. Some are Pro-only. Check BApp Store listing for requirements before installing.

---

### ZAP Marketplace

```
Manage Add-ons button → Marketplace tab
```

Add-ons are categorised by stability: **Release** (stable), **Beta**, **Alpha**.

**Notable add-ons:**

| Add-on | Purpose |
|--------|---------|
| **FuzzDB Files** | Adds FuzzDB wordlist collection to ZAP Fuzzer |
| **FuzzDB Offensive** | Adds FuzzDB attack payloads (command injection, SQLi, XSS, etc.) |
| **Ajax Spider** | Crawls JavaScript-heavy (SPA) applications that the standard spider misses |
| **OpenAPI Support** | Imports and scans OpenAPI/Swagger/GraphQL definitions |
| **Access Control Testing** | Tests for horizontal and vertical privilege escalation |

**Example — Command injection fuzzing with FuzzDB:**

After installing FuzzDB Offensive, the ZAP Fuzzer payload selection includes:

```
File Fuzzers → fuzzdb → attack → os-cmd-execution → command_execution-unix.txt
```

Payloads include:
```
;id
;id;
|id
|id|
`id`
$(id)
/usr/bin/id
```

Running the fuzzer with this list against the `/ping` endpoint identifies command injection in multiple payloads, useful when a WAF is blocking obvious patterns.

---

## Key Shortcuts Reference

### Burp Suite

| Shortcut | Action |
|----------|--------|
| `CTRL+I` | Send request to Intruder |
| `CTRL+R` | Send request to Repeater |
| `CTRL+SHIFT+I` | Navigate to Intruder tab |
| `CTRL+SHIFT+R` | Navigate to Repeater tab |
| `CTRL+U` | URL-encode selected text in Repeater |
| `CTRL+SHIFT+R` (browser) | Force full page refresh (bypasses cache) |
| `Forward` | Forward intercepted request to server |
| `Drop` | Discard intercepted request |

### ZAP

| Shortcut | Action |
|----------|--------|
| `CTRL+B` | Toggle request interception on/off |
| `CTRL+R` | Open Replacer options |
| `CTRL+E` | Open Encoder/Decoder/Hash tool |
| `Step` (HUD) | Forward request and intercept response |
| `Continue` (HUD) | Forward all requests without intercepting |
| `Drop` (HUD) | Discard current intercepted request |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application — proxy enables manual testing of command injection, SQLi, auth bypass |
| T1059 | T1059.007 | Command and Scripting Interpreter: JavaScript (XSS testing via proxy) |
| T1110 | T1110.001 | Brute Force: Password Guessing (Intruder / Fuzzer credential brute force) |
| T1110 | T1110.003 | Brute Force: Password Spraying (Intruder cluster bomb against login forms) |
| T1552 | T1552.004 | Unsecured Credentials: Private Keys (identifying private keys in HTTP responses) |
| T1565 | T1565.002 | Data Manipulation: Transmitted Data Manipulation (intercepting and modifying HTTP requests/responses) |
| T1134 | T1134.001 | Token Impersonation — cookie tampering via Decoder to escalate privileges |
| T1583 | — | Acquire Infrastructure (identifying endpoints and parameters through scanning and crawling) |
| T1595 | T1595.002 | Active Scanning: Vulnerability Scanning (Burp Scanner / ZAP Active Scanner) |
| T1592 | T1592.002 | Gather Victim Host Information: Software — identifying server software versions via response headers |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
