# MSSQL — Footprinting
**Port(s):** 1433 TCP (main), 1434 UDP/TCP (DAC)
**Protocol:** TCP
**CPTS Module:** Footprinting | **Date:** March 2026

## What MSSQL Is and Why Pentesters Care

Microsoft SQL Server is Microsoft's enterprise relational database, deeply integrated into Windows and Active Directory environments. Unlike MySQL, MSSQL supports two authentication modes — SQL Server auth (native SQL accounts) and Windows auth (domain accounts) — and has built-in OS-level capabilities like `xp_cmdshell` that can turn database access into full OS command execution. Modern MSSQL enforces TLS so raw netcat connections fail — impacket-mssqlclient handles the TLS handshake automatically.

The most powerful enumeration technique against MSSQL requires zero credentials — the `ms-sql-ntlm-info` NSE script extracts the hostname and domain name through the NTLM handshake before any authentication is exchanged.

## Authentication Modes

| Mode | How It Works | Flag Required |
|---|---|---|
| SQL Server Auth | Username + password stored inside SQL Server | None (default) |
| Windows Auth | Domain or local Windows account credentials | `-windows-auth` in impacket |

## Enumeration — Step by Step

### Step 1 — Nmap NSE Script Battery
```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes \
--script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER \
-sV -p1433 10.129.14.128
```

**What each NSE script does:**

| Script | Purpose |
|---|---|
| `ms-sql-ntlm-info` | Leaks hostname and domain with zero credentials via NTLM handshake |
| `ms-sql-info` | Server version, instance name, named pipe, clustering status |
| `ms-sql-empty-password` | Tests if `sa` has a blank password |
| `ms-sql-config` | Reads server configuration settings |
| `ms-sql-tables` | Lists accessible tables |
| `ms-sql-hasdbaccess` | Lists databases the current user can access |
| `ms-sql-dac` | Tests Dedicated Admin Connection on port 1434 |
| `ms-sql-dump-hashes` | Dumps SQL Server password hashes (requires sysadmin) |
| `ms-sql-xp-cmdshell` | Attempts OS command execution via xp_cmdshell |

### Step 2 — Connect With impacket-mssqlclient

**Windows auth (domain account):**
```bash
impacket-mssqlclient backdoor@10.129.14.128 -windows-auth
# Prompted for password: Password1
```

**SQL auth (native SQL account):**
```bash
impacket-mssqlclient sa@10.129.14.128
```

Without `-windows-auth`, impacket defaults to SQL Server auth. If the account is a Windows/domain account and you omit this flag, the login silently fails with no useful error.

### Step 3 — Database Enumeration (T-SQL Syntax)
```sql
-- Server information
SELECT @@version;                          -- Full version string
SELECT @@servername;                       -- Hostname
SELECT DB_NAME();                          -- Currently selected database

-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');       -- 1 = yes, 0 = no

-- List all databases (modern syntax)
SELECT name FROM sys.databases;

-- List all databases (legacy syntax — use if sys.databases restricted)
SELECT name FROM master.dbo.sysdatabases;

-- Switch database
USE Employees;

-- List tables in current database
SELECT table_name FROM information_schema.tables
WHERE table_type = 'BASE TABLE';

-- Preview data — MSSQL uses TOP not LIMIT
SELECT TOP 10 * FROM <table>;

-- Column structure
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'target_table';
```

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| `sa` account with blank or weak password | Full sysadmin access | Connect with SQL auth, access all databases |
| Windows auth using domain account | Credential reuse from other services | Discovered domain creds work directly on MSSQL |
| `xp_cmdshell` enabled | OS command execution from SQL | `EXEC xp_cmdshell 'whoami'` runs OS commands |
| Unpatched RTM install | Known CVEs unaddressed | Check version against exploit database |
| `msdb` job scripts with hardcoded credentials | Creds stored in SQL Agent jobs | Query msdb for job definitions containing passwords |
| Named pipe exposed | Alternative SMB-based connection method | Connect via named pipe if TCP filtered |

## Real Lab Output
```
Hackerpatel007_1@htb[/htb]$ sudo nmap --script ms-sql-ntlm-info -p1433 10.129.14.128

| ms-sql-ntlm-info:
|   Target_Name: ILF-SQL-01
|   NetBIOS_Computer_Name: ILF-SQL-01
|   DNS_Computer_Name: ILF-SQL-01
|   Product_Version: 10.0.17763

Hackerpatel007_1@htb[/htb]$ impacket-mssqlclient backdoor@10.129.14.128 -windows-auth
Password: Password1
[*] Encryption required, switching to TLS
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
SQL> SELECT name FROM sys.databases;

name
-------------------------------
master
tempdb
model
msdb
Employees
```

## What I Learned / What Surprised Me

The `ms-sql-ntlm-info` script was the biggest revelation in this module — extracting the hostname and domain name before any credentials are exchanged, purely through the NTLM handshake, is something I did not realise was possible. You get free reconnaissance on every MSSQL server you touch just by running that one script. The `RTM` with `Post-SP patches applied: false` combination is also a significant finding pattern — an unpatched base release in production is an immediate flag to check against known CVEs. The silent failure when omitting `-windows-auth` for a domain account also caught me — there is no error message, the connection just fails, and without knowing the flag you would assume the credentials are wrong.

## Detection Layer

| Log Source | What Is Logged | Detection Signal |
|---|---|---|
| SQL Server logs | Authentication events | Multiple failed logins from same IP |
| SQL Server logs | Schema enumeration queries | `sys.databases`, `information_schema` queries |
| Windows Security Log | Event ID 4624/4625 | Windows auth login success or failure to SQL |
| Network logs | Connection to port 1433 | External IP connecting to database port |

**SPL Query to detect MSSQL enumeration:**
```spl
index=windows EventCode=4624 LogonType=3
(ProcessName="*sqlservr*" OR TargetUserName="sa")
| stats count by SourceNetworkAddress, TargetUserName
| where count > 5
| sort -count
```

**KQL Query (Sentinel):**
```kql
SecurityEvent
| where EventID in (4624, 4625)
| where ProcessName contains "sqlservr"
| summarize Count=count() by IpAddress, TargetUserName, EventID
| where Count > 5
| sort by Count desc
```

**MITRE Technique:** T1190 — Exploit Public-Facing Application
**Also relevant:** T1213 — Data from Information Repositories, T1059 — Command and Scripting Interpreter (xp_cmdshell)

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap --script ms-sql-ntlm-info -p1433 <IP>` | Hostname leak with zero credentials |
| `nmap --script ms-sql-info -p1433 <IP>` | Full version and instance info |
| `impacket-mssqlclient <user>@<IP> -windows-auth` | Connect with Windows/domain account |
| `impacket-mssqlclient sa@<IP>` | Connect with SQL native account |
| `SELECT name FROM sys.databases;` | List all databases |
| `SELECT IS_SRVROLEMEMBER('sysadmin');` | Check sysadmin privilege |
| `SELECT TOP 10 * FROM <table>;` | Preview data (MSSQL uses TOP not LIMIT) |
