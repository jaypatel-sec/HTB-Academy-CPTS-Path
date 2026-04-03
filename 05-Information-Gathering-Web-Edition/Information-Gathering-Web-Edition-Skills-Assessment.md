# HTB Academy — Module 05: Information Gathering Web Edition — Skills Assessment

| Field | Details |
|---|---|
| Platform | Hack The Box Academy |
| Module | 05 — Information Gathering - Web Edition |
| Lab | Skills Assessment |
| Difficulty | Easy |
| Target IP | 154.57.164.74 |
| Target Port | 32127 |
| Date | April 2026 |

---

## Assessment Overview

Five questions requiring the full breadth of web reconnaissance techniques covered in the module — WHOIS lookup, HTTP header fingerprinting, virtual host enumeration, robots.txt analysis, web crawling, and HTML comment extraction. Each question builds on the previous, with newly discovered virtual hosts needing to be added to `/etc/hosts` before proceeding.

---

## Assessment Chain Summary

1. `whois inlanefreight.com` → Registrar IANA ID
2. `curl -I inlanefreight.htb` → Server: nginx confirmed
3. `gobuster vhost` on inlanefreight.htb → web1337.inlanefreight.htb
4. Add web1337 to `/etc/hosts` → `curl /robots.txt` → Disallow: /admin_h1dd3n
5. `curl /admin_h1dd3n/` → API key in HTML
6. `gobuster vhost` on web1337.inlanefreight.htb → dev.web1337.inlanefreight.htb
7. Add dev.web1337 to `/etc/hosts` → `python3 ReconSpider.py` → results.json
8. `cat results.json | jq '.emails'` → email address
9. `cat results.json | jq '.comments'` → new API key in comment

---

## Question 1 — Registrar IANA ID

**Question:** What is the IANA ID of the registrar of the inlanefreight.com domain?

**Approach:** WHOIS lookup on the domain, filtered with grep to isolate the IANA ID field.

```bash
Hackerpatel007_1@htb[/htb]$ whois inlanefreight.com | grep IANA
```

**Output:**

```
   Registrar IANA ID: 468
Registrar IANA ID: 468
```

Every domain registrar is assigned a unique IANA ID. This confirms which company manages the domain registration — useful for identifying the hosting ecosystem and any associated services under the same registrar.

> **Answer:** <details><summary>Click to reveal</summary>468</details>

---

## Question 2 — HTTP Server Software

**Question:** What HTTP server software is powering the inlanefreight.htb site on the target system?

**Step 1 — Add the target to /etc/hosts:**

```bash
Hackerpatel007_1@htb[/htb]$ sudo sh -c "echo '154.57.164.74 inlanefreight.htb' >> /etc/hosts"
```

**Step 2 — Fetch only the response headers using -I:**

```bash
Hackerpatel007_1@htb[/htb]$ curl -I http://inlanefreight.htb:32127
```

**Output:**

```
HTTP/1.1 200 OK
Server: nginx/1.26.1
Date: Fri, 21 Jun 2024 21:14:55 GMT
Content-Type: text/html
Content-Length: 120
Last-Modified: Fri, 07 Jun 2024 14:56:31 GMT
Connection: keep-alive
ETag: "66631f9f-78"
Accept-Ranges: bytes
```

The `Server` response header directly identifies the web server software. `nginx/1.26.1` — the question asks for the software name only, not the version.

> **Answer:** <details><summary>Click to reveal</summary>nginx</details>

---

## Question 3 — API Key in Hidden Admin Directory

**Question:** What is the API key in the hidden admin directory discovered on the target system?

**Step 1 — VHost enumeration against inlanefreight.htb:**

```bash
Hackerpatel007_1@htb[/htb]$ gobuster vhost -u http://inlanefreight.htb:32127 \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
-t 60 --append-domain
```

**Output:**

```
===============================================================
Gobuster v3.6
===============================================================
[+] Url:             http://inlanefreight.htb:32127
[+] Threads:         60
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] Append Domain:   true
===============================================================
Found: web1337.inlanefreight.htb:32127 (Status: 200) [Size: 104]
===============================================================
```

New virtual host found: `web1337.inlanefreight.htb`

**Step 2 — Add to /etc/hosts:**

```bash
Hackerpatel007_1@htb[/htb]$ sudo sh -c "echo '154.57.164.74 web1337.inlanefreight.htb' >> /etc/hosts"
```

**Step 3 — Check robots.txt on the new vhost:**

```bash
Hackerpatel007_1@htb[/htb]$ curl http://web1337.inlanefreight.htb:32127/robots.txt
```

**Output:**

```
User-agent: *
Allow: /index.html
Allow: /index-2.html
Allow: /index-3.html
Disallow: /admin_h1dd3n
```

A `Disallow` directive is not a security control — it is a breadcrumb. `/admin_h1dd3n` is the hidden admin directory.

**Step 4 — Check headers on the admin path:**

```bash
Hackerpatel007_1@htb[/htb]$ curl -I http://web1337.inlanefreight.htb:32127/admin_h1dd3n
```

**Output:**

```
HTTP/1.1 301 Moved Permanently
Server: nginx/1.26.1
Location: http://web1337.inlanefreight.htb/admin_h1dd3n/
Connection: keep-alive
```

301 Moved Permanently with a trailing slash in Location — the directory requires the trailing slash.

**Step 5 — Fetch the admin directory:**

```bash
Hackerpatel007_1@htb[/htb]$ curl http://web1337.inlanefreight.htb:32127/admin_h1dd3n/
```

**Output:**

```html
<!DOCTYPE html>
<html>
<head><title>web1337 admin</title></head>
<body>
<h1>Welcome to web1337 admin site</h1>
<h2>The admin panel is currently under maintenance, but the API is still accessible with the key e963d863ee0e82ba7080fbf558ca0d3f</h2>
</body>
</html>
```

The API key is embedded directly in the page content.

> **Answer:** <details><summary>Click to reveal</summary>e963d863ee0e82ba7080fbf558ca0d3f</details>

---

## Question 4 — Email Address from Crawl

**Question:** After crawling the inlanefreight.htb domain on the target system, what is the email address found?

**Step 1 — VHost enumeration against web1337.inlanefreight.htb:**

```bash
Hackerpatel007_1@htb[/htb]$ gobuster vhost -u http://web1337.inlanefreight.htb:32127 \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
-t 60 --append-domain
```

**Output:**

```
===============================================================
Found: dev.web1337.inlanefreight.htb:32127 (Status: 200) [Size: 123]
===============================================================
```

A development subdomain found on the second-level vhost.

**Step 2 — Add to /etc/hosts:**

```bash
Hackerpatel007_1@htb[/htb]$ sudo sh -c "echo '154.57.164.74 dev.web1337.inlanefreight.htb' >> /etc/hosts"
```

**Step 3 — Install Scrapy and set up ReconSpider:**

```bash
Hackerpatel007_1@htb[/htb]$ pip3 install scrapy --break-system-packages
Hackerpatel007_1@htb[/htb]$ wget https://academy.hackthebox.com/storage/modules/279/ReconSpider.zip
Hackerpatel007_1@htb[/htb]$ unzip ReconSpider.zip
```

**Step 4 — Crawl dev.web1337.inlanefreight.htb:**

```bash
Hackerpatel007_1@htb[/htb]$ python3 ReconSpider.py http://dev.web1337.inlanefreight.htb:32127
```

**Output (truncated):**

```
2024-06-24 04:48:53 [scrapy.utils.log] INFO: Scrapy 2.11.2 started
...
2024-06-24 04:49:11 [scrapy.core.engine] INFO: Spider closed (finished)
```

**Step 5 — Extract emails from results:**

```bash
Hackerpatel007_1@htb[/htb]$ cat results.json | jq '.emails'
```

**Output:**

```json
[
  "1337testing@inlanefreight.htb"
]
```

ReconSpider crawled all linked pages under the vhost and extracted every email address found in the HTML source. Development environments frequently contain staff emails, contact addresses, and internal notification addresses.

> **Answer:** <details><summary>Click to reveal</summary>1337testing@inlanefreight.htb</details>

---

## Question 5 — New API Key from HTML Comment

**Question:** What is the API key the inlanefreight.htb developers will be changing to?

**Approach:** The `results.json` file generated by ReconSpider in Question 4 is already available. Parse the `comments` field — developer comments in HTML source often contain sensitive information including upcoming configuration changes.

```bash
Hackerpatel007_1@htb[/htb]$ cat results.json | jq '.comments'
```

**Output:**

```json
[
  "<!-- Remember to change the API key to ba988b835be4aa97d068941dc852ff33 -->"
]
```

A developer left a note in an HTML comment on the development site referencing the upcoming API key rotation. The development subdomain is not linked from the main site and has no public DNS record — but VHost enumeration found it. HTML comments are never visible to normal users but are fully readable in source code and by any crawler.

The current API key (`e963d863ee0e82ba7080fbf558ca0d3f` — found in Question 3) is being replaced. This comment reveals the replacement key before the rotation occurs.

> **Answer:** <details><summary>Click to reveal</summary>ba988b835be4aa97d068941dc852ff33</details>

---

## Key Takeaways

VHost enumeration was the pivotal technique in this assessment. The entire chain from Question 3 onward depended on finding `web1337.inlanefreight.htb` — a virtual host that has no public DNS record and would never appear in standard subdomain enumeration. Running `gobuster vhost` against each newly discovered vhost is the correct methodology: enumerate the root domain, add what you find, then enumerate each discovered vhost in turn. Skipping the second-level gobuster on web1337 would have meant missing dev.web1337 and never finding the email or the comment.

The `robots.txt` finding is one of those things that seems obvious once seen but is easy to deprioritise when there are other attack surfaces visible. The `Disallow: /admin_h1dd3n` line was the entire path to the first API key. Checking `robots.txt` and `sitemap.xml` immediately after adding a new vhost to `/etc/hosts` is now a fixed step in my methodology — before running any directory buster.

The HTML comment with the upcoming API key rotation was the most interesting finding. A developer left a note on a development site about a planned configuration change. That development site was only discoverable through VHost enumeration. The comment itself is invisible to a normal user but completely readable by any crawler. The lesson is that development environments are almost always less carefully maintained than production and more likely to leak sensitive information — they should be prioritised when found.

---

## Full Assessment Chain Reference

```
1.  whois inlanefreight.com | grep IANA
    → Registrar IANA ID: [hidden]

2.  sudo sh -c "echo '154.57.164.74 inlanefreight.htb' >> /etc/hosts"
    curl -I http://inlanefreight.htb:32127
    → Server: nginx/[version]

3.  gobuster vhost -u http://inlanefreight.htb:32127 -w subdomains-top1million-110000.txt -t 60 --append-domain
    → Found: web1337.inlanefreight.htb

4.  sudo sh -c "echo '154.57.164.74 web1337.inlanefreight.htb' >> /etc/hosts"
    curl http://web1337.inlanefreight.htb:32127/robots.txt
    → Disallow: /admin_h1dd3n

5.  curl -I http://web1337.inlanefreight.htb:32127/admin_h1dd3n
    → 301 → /admin_h1dd3n/

6.  curl http://web1337.inlanefreight.htb:32127/admin_h1dd3n/
    → API key: [hidden] ✅

7.  gobuster vhost -u http://web1337.inlanefreight.htb:32127 -w subdomains-top1million-110000.txt -t 60 --append-domain
    → Found: dev.web1337.inlanefreight.htb

8.  sudo sh -c "echo '154.57.164.74 dev.web1337.inlanefreight.htb' >> /etc/hosts"

9.  pip3 install scrapy --break-system-packages
    wget ReconSpider.zip && unzip ReconSpider.zip
    python3 ReconSpider.py http://dev.web1337.inlanefreight.htb:32127

10. cat results.json | jq '.emails'
    → [hidden] ✅

11. cat results.json | jq '.comments'
    → API key rotation comment: [hidden] ✅
```

---

## Commands Reference

| Command | Purpose |
|---|---|
| `whois <domain> \| grep IANA` | Extract registrar IANA ID |
| `sudo sh -c "echo '<IP> <hostname>' >> /etc/hosts"` | Add vhost to hosts file |
| `curl -I http://<target>:<port>` | Fetch HTTP headers only — server fingerprinting |
| `gobuster vhost -u http://<target>:<port> -w <wordlist> -t 60 --append-domain` | VHost enumeration |
| `curl http://<vhost>:<port>/robots.txt` | Check for disallowed paths |
| `curl -I http://<vhost>:<port>/<path>` | Check redirect before fetching |
| `curl http://<vhost>:<port>/<path>/` | Fetch directory with trailing slash |
| `pip3 install scrapy --break-system-packages` | Install Scrapy for ReconSpider |
| `wget https://academy.hackthebox.com/storage/modules/279/ReconSpider.zip` | Download ReconSpider |
| `unzip ReconSpider.zip` | Extract ReconSpider |
| `python3 ReconSpider.py http://<target>:<port>` | Crawl target — outputs results.json |
| `cat results.json \| jq '.emails'` | Extract emails from crawl |
| `cat results.json \| jq '.comments'` | Extract HTML comments from crawl |
| `cat results.json \| jq '.links'` | Extract all discovered links |
