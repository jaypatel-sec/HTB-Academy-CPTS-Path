# Using Web Proxies — Skills Assessment

**Platform:** Hack The Box Academy  
**Module:** Using Web Proxies  
**Difficulty:** Easy  
**Target IP:** 10.129.58.24  
**Target Port:** 30851  

---

## Overview

This assessment covers the full proxy workflow from both Burp and ZAP angles. Four questions, each testing a different skill: response manipulation, multi-layer cookie decoding, Intruder payload processing, and proxying a Metasploit module to inspect its raw traffic. I worked through them in order since each one builds on what you learn from the previous.

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | ZAP Replacer — strip `disabled>` from response body | Button enabled on `/lucky.php` |
| 2 | Click enabled button ~8 times in browser | Flag 1 captured |
| 3 | ZAP Encoder — ASCII Hex decode → Base64 decode on `/admin.php` cookie | 31-char partial MD5 hash recovered |
| 4 | Burp Intruder — fuzz last MD5 character with alphanum-case.txt + 3-rule payload processing chain | Complete MD5 cookie candidate identified |
| 5 | Sort Intruder results by Length — outlier 1248-byte response | Flag 2 captured |
| 6 | Metasploit `coldfusion_locale_traversal` + `set PROXIES HTTP:127.0.0.1:8080` | Hidden directory `CFIDE` identified |

---

## Question 1 — Enable a Disabled Button and Capture the Flag

**"The /lucky.php page has a button that appears to be disabled. Try to enable the button, and then click it to get the flag."**

### Identifying the Problem

With ZAP running and FoxyProxy pointing to port 8080, I navigated to `http://10.129.58.24:30851/lucky.php`. The page had a "Click for a chance to win a flag!" button that was completely greyed out and non-functional. Checked the raw response in ZAP's History pane and saw the `disabled` attribute hardcoded directly on the button element:

```html
<button disabled>Click for a chance to win a flag!</button>
```

Rather than intercept and modify every single request manually, I used ZAP Replacer to strip the attribute automatically from every response going forward.

### Creating the ZAP Replacer Rule

`CTRL+R` to open Replacer → click **Add...**

| Field | Value |
|-------|-------|
| Match Type | Response Body String |
| Match String | `disabled>` |
| Replacement String | `>` |
| Enable | ✓ Checked |

Saved the rule. From this point on, any response containing `disabled>` gets it stripped before the browser ever sees it.

### Resending the Request and Getting the Flag

In ZAP's History pane, found the `GET /lucky.php` entry → right-clicked → **Open/Resend with Request Editor** → hit **Send**. Confirmed the response body no longer contained `disabled`.

Right-clicked the response → **Open URL in System Browser**. The button rendered as active and clickable. Clicked it about 8 times and the flag appeared on screen.

> **Note:** If the button still looks disabled after the browser opens, `CTRL+SHIFT+R` forces a full cache-bypassing reload.

**Flag 1:** `HTB{...}` *(captured and submitted)*

---

## Question 2 — Decode a Multi-Encoded Cookie to Recover 31 Characters

**"The /admin.php page uses a cookie that has been encoded multiple times. Try to decode the cookie until you get a value with 31-characters. Submit the value as the answer."**

### Capturing the Cookie

Navigated to `http://10.129.58.24:30851/admin.php` with ZAP intercepting. The request in ZAP's History showed a `Cookie` header with a long hex-encoded value:

```http
GET /admin.php HTTP/1.1
Host: 10.129.58.24:30851
Cookie: cookie=4d325268597a6b7a596a686a5a4449314d47466854... [truncated]
```

### Decoding with ZAP Encoder

Selected the encoded value after `cookie=` → right-clicked → **Encode/Decode/Hash...**

The value was double-encoded. I worked through it layer by layer:

**Layer 1 — ASCII Hex Decode:**

Pasted the raw cookie value into the Decode tab and ran ASCII Hex Decode. The output was a Base64 string.

**Layer 2 — Base64 Decode:**

Copied that result, pasted it back in, ran Base64 Decode. Out came a 31-character string:

```
3dac93b8cd250aa8c1a36fffc79a17a
```

The encoding stack was: Base64 → ASCII Hex on the way out (server side), so ASCII Hex → Base64 to reverse it. The 31-character result is clearly an MD5 hash missing its final character — that's what Question 3 is about.

**Answer:** `3dac93b8cd250aa8c1a36fffc79a17a`

---

## Question 3 — Fuzz the Missing MD5 Character and Retrieve the Flag

**"Once you decode the cookie, you will notice that it is only 31 characters long, which appears to be an MD5 hash missing its last character. So, try to fuzz the last character of the decoded MD5 cookie with all alpha-numeric characters, while encoding each request with the encoding methods you identified above."**

### Why Burp Instead of ZAP Here

I switched to Burp for this one. ZAP's fuzzer doesn't have a built-in ASCII Hex payload encoder, so replicating the 3-step processing chain would need external scripting. Burp Intruder handles it natively with Payload Processing rules.

### Capturing the Request in Burp

Switched FoxyProxy to Burp (port 8080), navigated to `http://10.129.58.24:30851/admin.php`, found the request in Proxy → HTTP History, right-clicked → **Send to Intruder** (`CTRL+I`).

### Setting the Position

In Intruder → **Positions** tab:

1. Clicked **Clear §** to remove all auto-detected positions
2. Replaced the encoded cookie value with the 31-character hash: `3dac93b8cd250aa8c1a36fffc79a17a`
3. Selected the entire hash → clicked **Add §**

The position looked like:

```
Cookie: cookie=§3dac93b8cd250aa8c1a36fffc79a17a§
```

The Add Prefix rule in the processing chain will prepend the 31-char hash to each payload character, giving a complete 32-char MD5 candidate before re-encoding.

### Loading the Wordlist

**Payloads** tab:

| Setting | Value |
|---------|-------|
| Payload Type | Simple list |
| Load | `/opt/useful/SecLists/Fuzzing/alphanum-case.txt` |

62 entries: a–z, A–Z, 0–9. Every valid hex character is covered.

### Payload Processing Chain

Under **Payload Processing**, added three rules in this exact order:

| # | Rule Type | Value |
|---|-----------|-------|
| 1 | Add prefix | `3dac93b8cd250aa8c1a36fffc79a17a` |
| 2 | Base64-encode | |
| 3 | Encode as ASCII hex | |

What this does for each payload character (e.g. `f`):
1. Prefix prepended → `3dac93b8cd250aa8c1a36fffc79a17af` (32-char complete MD5 candidate)
2. Base64-encoded → `M2RhYzkzYjhjZDI1MGFhOGMxYTM2ZmZmYzc5YTE3YWY=`
3. ASCII-hex-encoded → final cookie value sent in the request

This mirrors the exact double-encoding the server expects, based on what I reversed in Question 2.

### Running the Attack

Clicked **Start attack**. Once all 62 payloads completed, sorted results by the **Length** column. Every wrong character produced the same baseline response length. One character came back at **1248 bytes** — visibly different from everything else. Opened that response and found the flag in the body.

**Flag 2:** `HTB{...}` *(captured and submitted)*

---

## Question 4 — Identify the Hidden Directory in the ColdFusion Module Request

**"You are using the 'auxiliary/scanner/http/coldfusion_locale_traversal' tool within Metasploit, but it is not working properly for you. You decide to capture the request sent by Metasploit so you can manually verify it and repeat it. Once you capture the request, what is the 'XXXXX' directory being called in '/XXXXX/administrator/..'?"**

### Why Proxy a Metasploit Module?

The module wasn't returning useful results. The fastest way to see exactly what it's sending is to route it through Burp with `set PROXIES` — this forces all HTTP traffic from the module through the proxy so I can read the raw request.

### Setup and Execution

```
┌─[jay@htb-academy]─[~]
└──╼ $ msfconsole -q
```

```
msf6 > use auxiliary/scanner/http/coldfusion_locale_traversal
msf6 auxiliary(scanner/http/coldfusion_locale_traversal) > set RHOSTS 10.129.58.24
RHOSTS => 10.129.58.24
msf6 auxiliary(scanner/http/coldfusion_locale_traversal) > set RPORT 30851
RPORT => 30851
msf6 auxiliary(scanner/http/coldfusion_locale_traversal) > set PROXIES HTTP:127.0.0.1:8080
PROXIES => HTTP:127.0.0.1:8080
```

Enabled interception in Burp (`Proxy → Intercept → Intercept is on`), then:

```
msf6 auxiliary(scanner/http/coldfusion_locale_traversal) > run
```

### Intercepted Request

Burp caught the request immediately:

```http
GET /CFIDE/administrator/.. HTTP/1.1
Host: 10.129.58.24:30851
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Connection: close
```

The path is `/CFIDE/administrator/..` — `CFIDE` is Adobe ColdFusion's default administrative directory. The module was trying to traverse out of it. Just needed to read the intercepted request to get the answer.

**Answer:** `CFIDE`

---

## Answers Summary

| Question | Answer |
|----------|--------|
| Q1 — /lucky.php disabled button | Flag obtained after clicking re-enabled button |
| Q2 — /admin.php cookie decode | `3dac93b8cd250aa8c1a36fffc79a17a` |
| Q3 — MD5 character fuzzing | Flag from Intruder outlier response (length 1248) |
| Q4 — ColdFusion traversal directory | `CFIDE` |

---

## Lessons Learned

- **ZAP Replacer is far more efficient than manual interception for persistent response modifications.** One rule targeting `disabled>` handles the attribute permanently across all subsequent requests — no need to intercept and edit each response individually.

- **Multi-layer cookie encoding always unravels if you decode from the outside in.** The pattern here was ASCII Hex wrapping Base64 wrapping an MD5. ZAP Encoder handles each layer independently — decode one, copy the result, decode the next. Let the output tell you what the next layer is rather than guessing.

- **Burp Intruder's Payload Processing chain order is critical.** The server expects a specific encoding pipeline. If the order is wrong, every response comes back identical and you won't catch it until the entire attack run is wasted. Always verify the chain matches how the server encodes before starting.

- **Sort by Length is always the first move after an Intruder attack.** A consistent baseline with a single outlier is a definitive hit before even opening the response body.

- **`set PROXIES` in Metasploit turns any HTTP module into a transparent client.** The module sent exactly one request and Burp caught it. This is the fastest way to debug a non-working Metasploit module or confirm what path it's actually hitting.

- **CFIDE is an immediate ColdFusion fingerprint.** Any server exposing `/CFIDE/` should be treated as a ColdFusion instance and tested for unauthenticated access — the Administrator panel has been exploited across multiple ColdFusion versions via directory traversal and authentication bypass.

---

## Key Commands Reference

| Command | What It Does |
|---------|----------|
| `CTRL+R` (ZAP) | Open Replacer |
| `CTRL+SHIFT+R` (Browser) | Force full cache-bypassing page refresh |
| Right-click response → Open URL in System Browser | Render the proxy-modified response in browser |
| `CTRL+E` (ZAP) | Open Encode/Decode/Hash tool |
| `CTRL+I` (Burp) | Send request to Intruder |
| `CTRL+SHIFT+I` (Burp) | Navigate to Intruder tab |
| Clear § → select value → Add § | Set single fuzzing position in Intruder |
| Add prefix → Base64-encode → ASCII-hex | Three-rule payload processing chain |
| Sort by Length (Intruder results) | Identify the outlier (successful) response |
| `set PROXIES HTTP:127.0.0.1:8080` | Route Metasploit HTTP traffic through Burp/ZAP |
| `CTRL+B` (ZAP) | Toggle request interception on/off |

---

## MITRE ATT&CK Mapping

| Technique | ID | What I Was Doing |
|---|---|---|
| Transmitted Data Manipulation | T1565.002 | ZAP Replacer stripping `disabled` attribute from server response |
| Steal Web Session Cookie | T1539 | Decoding and analysing the multi-encoded `/admin.php` session cookie |
| Brute Force: Password Guessing | T1110.001 | Intruder fuzzing last MD5 character with alphanum-case.txt |
| Exploit Public-Facing Application | T1190 | ColdFusion locale traversal via Metasploit auxiliary module |
| Active Scanning: Vulnerability Scanning | T1595.002 | Metasploit ColdFusion scanner proxied through Burp |
| Gather Victim Host Information: Software | T1592.002 | Identifying ColdFusion via CFIDE directory in intercepted path |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTP traffic intercepted, modified, and replayed via proxy |
