# Using Web Proxies — Skills Assessment

**Platform:** Hack The Box Academy  
**Module:** Using Web Proxies  
**Assessment:** Skills Assessment  
**Difficulty:** Easy  
**Target IP:** 10.129.58.24  
**Target Port:** 30851  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | ZAP Replacer — strip `disabled>` from response body | Button enabled on `/lucky.php` |
| 2 | Click enabled button ~8 times in browser | Flag 1 captured |
| 3 | ZAP Encoder — ASCII Hex decode → Base64 decode on `/admin.php` cookie | 31-char partial MD5 hash recovered |
| 4 | Burp Intruder — fuzz last MD5 character with alphanum-case.txt + 3-rule payload processing chain | Complete MD5 cookie candidate identified |
| 5 | Sort Intruder results by Length — outlier 1248-byte response | Flag 2 captured |
| 6 | Metasploit `coldfusion_locale_traversal` + `set PROXIES HTTP:127.0.0.1:8080` → proxy intercept | Hidden directory `CFIDE` identified |

---

## Question 1 — Enable a Disabled Button and Capture the Flag

**Question:** "The /lucky.php page has a button that appears to be disabled. Try to enable the button, and then click it to get the flag."

### Step 1 — Navigate to /lucky.php and Identify the Disabled Attribute

With ZAP running and FoxyProxy set to `Burp (8080)` in Firefox, navigate to `/lucky.php`. The page presents a "Click for a chance to win a flag!" button that is greyed out and non-functional. Viewing the GET response in ZAP confirms the button has a `disabled` attribute hardcoded in the HTML:

```html
<button disabled>Click for a chance to win a flag!</button>
```

---

### Step 2 — Create a ZAP Replacer Rule to Strip the Disabled Attribute

Open ZAP Replacer: `CTRL+R` → click **Add...**

Configure the rule:

| Field | Value |
|-------|-------|
| Match Type | Response Body String |
| Match String | `disabled>` |
| Replacement String | `>` |
| Enable | ✓ Checked |

Click **Save**. The rule is now globally active — every response body containing `disabled>` will have it stripped before reaching the browser.

---

### Step 3 — Resend the GET Request and Verify the Fix

In ZAP's History pane, select the `GET /lucky.php` request → right-click → **Open/Resend with Request Editor**.

For a cleaner view:
- Request tab → `Combined display for header and body`
- Response tab → `Combined display for header and body`

Click **Send**. Inspect the response body — `disabled` is no longer present. The Replacer has stripped it in transit.

---

### Step 4 — Open in Browser and Click the Button

Right-click on the response in the Request Editor → **Open URL in System Browser**.

The button is now active and clickable. Click it approximately 8 times to trigger the flag:

> **Note:** If the button still appears disabled after opening the browser, press `CTRL+SHIFT+R` to force a full cache-bypassing page refresh.

> **Answer:** `HTB{flag_redacted}`

---

## Question 2 — Decode a Multi-Encoded Cookie to Recover 31 Characters

**Question:** "The /admin.php page uses a cookie that has been encoded multiple times. Try to decode the cookie until you get a value with 31-characters. Submit the value as the answer."

### Step 1 — Capture the Cookie from /admin.php

With ZAP intercepting, navigate to `/admin.php`. The intercepted request in ZAP's History pane shows a `Cookie` header with an encoded value:

```http
GET /admin.php HTTP/1.1
Host: 10.129.58.24:30851
Cookie: cookie=<hex_encoded_value>
```

---

### Step 2 — Decode the Cookie Using ZAP Encoder

Select the encoded value after `cookie=` → right-click → **Encode/Decode/Hash...**

In the Encoder window, click the **Decode** tab. Two decode operations are needed:

**Layer 1 — ASCII Hex Decode:**  
The raw cookie value decodes from hex to a Base64-looking string.

**Layer 2 — Copy the ASCII Hex result → paste into the input → Base64 Decode:**  
The Base64 layer decodes to a 31-character value:

```
3dac93b8cd250aa8c1a36fffc79a17a
```

The cookie was double-encoded: **Base64 → ASCII Hex** on the way out, **ASCII Hex → Base64** on decode. The 31-character result is a partial MD5 hash missing its final character.

> **Answer:** `3dac93b8cd250aa8c1a36fffc79a17a`

---

## Question 3 — Fuzz the Missing MD5 Character and Retrieve the Flag

**Question:** "Once you decode the cookie, you will notice that it is only 31 characters long, which appears to be an MD5 hash missing its last character. So, try to fuzz the last character of the decoded MD5 cookie with all alpha-numeric characters, while encoding each request with the encoding methods you identified above. (You may use the 'alphanum-case.txt' wordlist from SecLists for the payload)"

### Step 1 — Capture /admin.php in Burp Suite and Send to Intruder

Switch to Burp Suite (ZAP lacks a built-in ASCII Hex payload processor, making this significantly more complex there). With Burp intercepting, navigate to `/admin.php`.

In Proxy → HTTP History: right-click the request → **Send to Intruder** (`CTRL+I`).

---

### Step 2 — Set Up Intruder Positions

Navigate to Intruder (`CTRL+SHIFT+I`) → **Positions** tab:

1. Click **Clear §** to remove all auto-detected positions
2. Replace the existing cookie value entirely with the 31-character hash: `3dac93b8cd250aa8c1a36fffc79a17a`
3. Select the entire hash → click **Add §**

The position marker now wraps the full hash:

```
Cookie: cookie=§3dac93b8cd250aa8c1a36fffc79a17a§
```

Each payload character will be appended to the hash via the Add Prefix processor in Step 4.

---

### Step 3 — Load the Alphanumeric Payload Wordlist

Navigate to the **Payloads** tab:

| Setting | Value |
|---------|-------|
| Payload Type | Simple list |
| Load file | `/opt/useful/SecLists/Fuzzing/alphanum-case.txt` |

This wordlist contains all 62 single alphanumeric characters (a-z, A-Z, 0-9) — every valid hex character needed to complete the MD5 hash.

---

### Step 4 — Configure Payload Processing Chain

Under **Payload Processing**, add three rules in this exact order:

| # | Rule Type | Value |
|---|-----------|-------|
| 1 | Add prefix | `3dac93b8cd250aa8c1a36fffc79a17a` |
| 2 | Base64-encode | *(no additional value)* |
| 3 | Encode as ASCII hex | *(no additional value)* |

**What this chain does for each payload character (e.g., `f`):**
1. Prefix prepended: `3dac93b8cd250aa8c1a36fffc79a17af` (32-char MD5 candidate)
2. Base64-encoded: `M2RhYzkzYjhjZDI1MGFhOGMxYTM2ZmZmYzc5YTE3YWY=`
3. ASCII-hex-encoded: `4d3364614...` (final value sent as cookie)

This mirrors the exact double-encoding format the server expects, identified in Question 2.

---

### Step 5 — Start the Attack and Identify the Flag

Click **Start attack**.

When fuzzing completes, click the **Length** column to sort results by response size. All invalid responses share a consistent baseline length. The correct MD5 character produces a distinct response of size **1248** — containing the flag in the response body.

> **Answer:** `HTB{flag_redacted}`

---

## Question 4 — Identify the Hidden Directory in the ColdFusion Module Request

**Question:** "You are using the 'auxiliary/scanner/http/coldfusion_locale_traversal' tool within Metasploit, but it is not working properly for you. You decide to capture the request sent by Metasploit so you can manually verify it and repeat it. Once you capture the request, what is the 'XXXXX' directory being called in '/XXXXX/administrator/..'?"

### Step 1 — Launch Metasploit

```bash
$ msfconsole -q
```

### Step 2 — Load the ColdFusion Locale Traversal Module

```bash
msf6 > use auxiliary/scanner/http/coldfusion_locale_traversal
```

### Step 3 — Configure the Module and Route Traffic Through the Proxy

```bash
msf6 auxiliary(scanner/http/coldfusion_locale_traversal) > set PROXIES HTTP:127.0.0.1:8080
msf6 auxiliary(scanner/http/coldfusion_locale_traversal) > set RHOSTS 159.65.63.151
msf6 auxiliary(scanner/http/coldfusion_locale_traversal) > set RPORT 31845
```

```
PROXIES => HTTP:127.0.0.1:8080
RHOSTS  => 159.65.63.151
RPORT   => 31845
```

### Step 4 — Enable Interception and Run

Enable interception in **Burp Suite** (`Proxy → Intercept → Intercept is on`) or **ZAP** (`CTRL+B`), then execute:

```bash
msf6 auxiliary(scanner/http/coldfusion_locale_traversal) > run
```

### Step 5 — Analyse the Intercepted Request

The proxy holds the raw HTTP request sent by the module:

```http
GET /CFIDE/administrator/.. HTTP/1.1
Host: 159.65.63.151:31845
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Connection: close
```

The path `/CFIDE/administrator/..` reveals the target directory: `CFIDE` — Adobe ColdFusion's default administrative directory used as the traversal origin.

> **Answer:** `CFIDE`

---

## Flags

| Question | Description | Answer |
|----------|-------------|--------|
| Q1 — /lucky.php disabled button | Flag after clicking re-enabled button | `HTB{flag_redacted}` |
| Q2 — /admin.php cookie decode | 31-char value after ASCII Hex → Base64 decode | `3dac93b8cd250aa8c1a36fffc79a17a` |
| Q3 — MD5 character fuzzing | Flag from Intruder outlier response (length 1248) | `HTB{flag_redacted}` |
| Q4 — ColdFusion traversal directory | Directory name in `/XXXXX/administrator/..` | `CFIDE` |

---

## Lessons Learned

- **ZAP Replacer eliminates the need to intercept every response manually.** A single rule targeting `disabled>` in the response body removes the attribute permanently for all subsequent page loads — far more efficient than intercepting each response one at a time when iterating on the same page.

- **Multi-layer encoding is a common anti-analysis technique for web cookies.** Always attempt to decode cookies through multiple encoding schemes when the value is not immediately human-readable. The pattern here — ASCII Hex wrapping Base64 wrapping an MD5 — is a common obfuscation stack in web applications. ZAP's Encode/Decode/Hash tool handles each layer individually, making the iterative decoding process straightforward.

- **Burp Intruder's Payload Processing chain must mirror the target's expected encoding exactly.** When the server expects a re-encoded value, every payload sent by Intruder must go through the same transformation pipeline before being inserted into the request. Getting the order wrong (e.g., Base64 after hex instead of before) results in all responses being identical — an easy mistake that wastes a full attack run.

- **Response Length is the primary triage column in Intruder.** After an attack completes, sorting by Length immediately surfaces outliers. A consistent baseline length across all responses with a single exception is a definitive indicator of a successful payload — before even reading the response body.

- **The `PROXIES` option in Metasploit is the single most important debug tool for HTTP-based modules.** Setting `HTTP:127.0.0.1:8080` exposes exactly what request the module constructs and sends, enabling manual verification, replay in Repeater, and targeted modification — turning a black-box module into a fully transparent, controllable HTTP client.

- **CFIDE is an immediate ColdFusion fingerprint.** Any web server exposing `/CFIDE/` should be investigated for ColdFusion-specific vulnerabilities — the Administrator panel at `/CFIDE/administrator/` has been exploited via multiple unauthenticated access CVEs and directory traversal chains across ColdFusion 8 through 2021.

---

## Full Attack Chain Reference

```
/lucky.php → button has disabled attribute
        ↓
ZAP Replacer: Response Body String "disabled>" → ">"
        ↓
Resend GET /lucky.php → response stripped of disabled attribute
        ↓
Open URL in System Browser → button clickable → click ~8 times
        ↓
Flag 1 captured [HTB{flag_redacted}]

/admin.php → Cookie header contains double-encoded value
        ↓
ZAP Encoder → ASCII Hex Decode → Base64 Decode → 31-char MD5
        ↓
Answer: 3dac93b8cd250aa8c1a36fffc79a17a

Burp Intruder → Positions: cookie=§3dac93b8cd250aa8c1a36fffc79a17a§
        ↓
Payloads: alphanum-case.txt (a-z, A-Z, 0-9)
Processing: Add prefix (31-char hash) → Base64-encode → ASCII-hex-encode
        ↓
Start Attack → sort by Length → 1248-byte response
        ↓
Flag 2 captured [HTB{flag_redacted}]

msfconsole -q → use auxiliary/scanner/http/coldfusion_locale_traversal
        ↓
set PROXIES HTTP:127.0.0.1:8080 → enable intercept → run
        ↓
Intercepted: GET /CFIDE/administrator/..
        ↓
Directory: CFIDE
```

---

## Commands Reference

| Command | Purpose |
|---------|----------|
| `CTRL+R` (ZAP) | Open Replacer |
| `CTRL+SHIFT+R` (Browser) | Force full cache-bypassing page refresh |
| Right-click response → Open URL in System Browser | Render proxy-modified response in browser |
| `CTRL+E` (ZAP) | Open Encode/Decode/Hash tool |
| `CTRL+I` (Burp) | Send request to Intruder |
| `CTRL+SHIFT+I` (Burp) | Navigate to Intruder tab |
| Clear § → select hash → Add § | Set single fuzzing position in Intruder |
| Add prefix → Base64-encode → ASCII-hex | Three-rule payload processing chain in Intruder |
| Sort by Length (Intruder results) | Identify outlier (successful) responses |
| `msfconsole -q` | Launch Metasploit suppressing banner |
| `use auxiliary/scanner/http/coldfusion_locale_traversal` | Load ColdFusion traversal scanner module |
| `set PROXIES HTTP:127.0.0.1:8080` | Route all module HTTP traffic through Burp/ZAP |
| `CTRL+B` (ZAP) | Toggle request interception on/off |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1565 | T1565.002 | Transmitted Data Manipulation — ZAP Replacer stripping `disabled` attribute from server response |
| T1539 | — | Steal Web Session Cookie — decoding and analysing multi-encoded `/admin.php` session cookie |
| T1110 | T1110.001 | Brute Force: Password Guessing — Intruder fuzzing last MD5 character with alphanum-case.txt |
| T1190 | — | Exploit Public-Facing Application — ColdFusion locale traversal via Metasploit auxiliary module |
| T1595 | T1595.002 | Active Scanning: Vulnerability Scanning — Metasploit ColdFusion scanner proxied through Burp/ZAP |
| T1592 | T1592.002 | Gather Victim Host Information: Software — identifying ColdFusion via CFIDE directory in intercepted path |
| T1071 | T1071.001 | Application Layer Protocol: Web Protocols — HTTP traffic intercepted, modified, and replayed via proxy |

---

*Part of the HTB Academy CPTS path — Using Web Proxies module.*  
*Penetration Tester role in India | Target: January 2027*
