# HTB Academy — Module 05: Information Gathering - Web Edition

| Field | Details |
|---|---|
| Platform | Hack The Box Academy |
| Module | 05 — Information Gathering - Web Edition |
| Difficulty | Easy |
| Type | Offensive — Passive and Active Web Reconnaissance |
| Date | April 2026 |

---

## Module Overview

Web reconnaissance is the systematic process of gathering information about a target's web presence before any exploitation attempt. This module covers both passive techniques — gathering information without directly interacting with the target — and active techniques that touch the target's infrastructure directly. The goal is to map the attack surface, identify technologies, discover hidden assets, and gather intelligence that informs every subsequent phase of an engagement.

**Seven core areas covered:**

| Area | Type | Purpose |
|---|---|---|
| WHOIS | Passive | Domain registration, ownership, contact data |
| DNS Enumeration | Active | DNS records, zone transfers, subdomain discovery |
| Subdomain Enumeration | Active | Brute force and passive discovery of subdomains |
| Web Crawling | Active | Automated site mapping, link and email extraction |
| Web Archives | Passive | Historical snapshots via Wayback Machine |
| Search Engine Discovery | Passive | Google dorking and OSINT via search engines |
| Fingerprinting | Active | Technology stack, versions, server software |

---

## Section 1 — WHOIS

WHOIS is a query protocol that retrieves registration information about a domain. Every registered domain has a WHOIS record maintained by the domain's registrar.

### What WHOIS Reveals

| Field | Information |
|---|---|
| Registrar | Company where the domain was registered + IANA ID |
| Registrant Contact | Organisation name, address, phone, email |
| Admin / Tech Contact | Operational contacts — often contain email addresses |
| Name Servers | Authoritative DNS servers for the domain |
| Creation / Expiry Date | Age of domain, renewal timeline |
| Registration Status | Active, expired, pending delete |

### Commands

```bash
# Basic WHOIS lookup
Hackerpatel007_1@htb[/htb]$ whois inlanefreight.com

# Filter for specific field
Hackerpatel007_1@htb[/htb]$ whois inlanefreight.com | grep IANA
Hackerpatel007_1@htb[/htb]$ whois tesla.com | grep -i admin

# Reverse WHOIS — find domains registered by same entity
Hackerpatel007_1@htb[/htb]$ whois -h whois.radb.net -- '-i origin AS8560'
```

### What to Look For

- **IANA ID** — unique identifier for the registrar
- **Admin email** — often personal or corporate email, useful for phishing simulation
- **Name servers** — identify hosting provider and potential zone transfer targets
- **Historical registrant data** — older WHOIS records may show real contact details before privacy protection was added
- **Domain age** — very new domains associated with a target may be typosquatting or phishing infrastructure

---

## Section 2 — DNS Enumeration

DNS is the backbone of the internet. Every web asset has DNS records — A, AAAA, CNAME, MX, TXT, NS, SOA, PTR. Enumerating DNS reveals IP addresses, mail servers, subdomains, internal hostnames, and infrastructure details.

### DNS Record Types

| Record | Purpose | Pentest Value |
|---|---|---|
| A | Hostname → IPv4 address | IP of main site and subdomains |
| AAAA | Hostname → IPv6 address | IPv6 infrastructure |
| CNAME | Alias → canonical name | Cloud services, CDN providers |
| MX | Mail exchange server | Email infrastructure, phishing targets |
| TXT | Arbitrary text | SPF, DKIM, verification tokens, internal notes |
| NS | Authoritative name servers | Zone transfer targets |
| SOA | Start of Authority — zone admin details | Admin email, serial number |
| PTR | IPv4/IPv6 → hostname (reverse DNS) | Identify hostname from IP |

### Core Commands

```bash
# Query specific record types
Hackerpatel007_1@htb[/htb]$ dig inlanefreight.com A
Hackerpatel007_1@htb[/htb]$ dig inlanefreight.com MX
Hackerpatel007_1@htb[/htb]$ dig inlanefreight.com TXT
Hackerpatel007_1@htb[/htb]$ dig inlanefreight.com NS
Hackerpatel007_1@htb[/htb]$ dig inlanefreight.com SOA

# Reverse DNS lookup (IP → hostname)
Hackerpatel007_1@htb[/htb]$ dig -x 134.209.24.248
Hackerpatel007_1@htb[/htb]$ nslookup 134.209.24.248

# Query mail servers
Hackerpatel007_1@htb[/htb]$ nslookup -query=mx facebook.com

# Query specific name server
Hackerpatel007_1@htb[/htb]$ dig @8.8.8.8 inlanefreight.com A

# Zone transfer attempt
Hackerpatel007_1@htb[/htb]$ dig axfr inlanefreight.htb @inlanefreight.htb
```

### Zone Transfers

A DNS zone transfer (AXFR) replicates the entire DNS zone database from one name server to another. When misconfigured, any host can request a full transfer — exposing every DNS record in the zone.

```bash
Hackerpatel007_1@htb[/htb]$ dig axfr inlanefreight.htb @<nameserver-IP>
```

**Output (successful transfer):**

```
inlanefreight.htb.      604800  IN  SOA   inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN  NS    inlanefreight.htb.
inlanefreight.htb.      604800  IN  A     10.129.x.x
admin.inlanefreight.htb. 604800 IN  A     10.129.x.x
ftp.admin.inlanefreight.htb. 604800 IN A 10.129.x.x
...
```

A successful zone transfer exposes the entire internal DNS structure — every hostname, every internal IP, every service — in a single query. This is one of the highest-value findings in passive reconnaissance.

---

## Section 3 — Subdomain Enumeration

Subdomains represent separate services, environments, and applications under a root domain. Development servers, admin panels, API endpoints, and staging environments all live on subdomains — and they are often less hardened than the main site.

### Passive Subdomain Discovery

Does not touch the target — uses third-party data sources.

```bash
# Certificate Transparency logs — fastest passive method
Hackerpatel007_1@htb[/htb]$ curl -s "https://crt.sh/?q=%25.inlanefreight.com&output=json" | jq '.[].name_value' | sort -u

# Sublist3r — aggregates multiple passive sources
Hackerpatel007_1@htb[/htb]$ sublist3r -d inlanefreight.com

# theHarvester — OSINT aggregator
Hackerpatel007_1@htb[/htb]$ theHarvester -d inlanefreight.com -b google,bing,crtsh
```

### Active Subdomain Brute Force

Directly queries DNS servers with wordlist-generated names.

```bash
# dnsenum — comprehensive subdomain enumeration
Hackerpatel007_1@htb[/htb]$ dnsenum --enum inlanefreight.com \
-f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# gobuster DNS mode
Hackerpatel007_1@htb[/htb]$ gobuster dns -d inlanefreight.com \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
-t 50

# dnsrecon
Hackerpatel007_1@htb[/htb]$ dnsrecon -d inlanefreight.com -D \
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t brt
```

### Virtual Host (VHost) Enumeration

VHosts are multiple websites served from the same IP address, distinguished by the Host header. VHost enumeration finds subdomains that do not appear in public DNS — only in the server's virtual host configuration.

```bash
# gobuster vhost — brute force virtual hosts
Hackerpatel007_1@htb[/htb]$ gobuster vhost -u http://inlanefreight.htb:<PORT> \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
-t 60 --append-domain

# ffuf vhost enumeration
Hackerpatel007_1@htb[/htb]$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
-u http://inlanefreight.htb:<PORT> -H "Host: FUZZ.inlanefreight.htb" \
-fs <baseline_size>
```

**Key difference:** DNS subdomain enumeration finds publicly resolvable subdomains. VHost enumeration finds internal virtual hosts that are only accessible if you know to request them in the Host header — even if they have no public DNS record.

After finding a new vhost — always add to `/etc/hosts`:

```bash
Hackerpatel007_1@htb[/htb]$ sudo sh -c "echo '<TARGET_IP> web1337.inlanefreight.htb' >> /etc/hosts"
```

---

## Section 4 — Web Crawling

Web crawling is the automated traversal of a website — following links, collecting URLs, extracting emails, identifying comments, and mapping the full structure of a site.

### What Crawlers Find

| Artifact | Pentest Value |
|---|---|
| URLs | Hidden paths, admin panels, API endpoints, parameter names |
| Emails | Staff emails for phishing, contacts for OSINT |
| Comments | Developer notes, TODO items, hardcoded credentials, API keys |
| Forms | Input fields, hidden fields, authentication endpoints |
| External links | Third-party integrations, data flows |
| robots.txt | Explicitly blocked paths — always check, often reveals sensitive directories |
| sitemap.xml | Complete site structure provided by the site itself |

### ReconSpider

HTB Academy's custom Scrapy-based crawler that outputs structured JSON.

```bash
# Install Scrapy
Hackerpatel007_1@htb[/htb]$ pip3 install scrapy --break-system-packages

# Download and extract ReconSpider
Hackerpatel007_1@htb[/htb]$ wget https://academy.hackthebox.com/storage/modules/279/ReconSpider.zip
Hackerpatel007_1@htb[/htb]$ unzip ReconSpider.zip

# Run crawler against target
Hackerpatel007_1@htb[/htb]$ python3 ReconSpider.py http://inlanefreight.htb:<PORT>

# Parse results
Hackerpatel007_1@htb[/htb]$ cat results.json | jq '.emails'
Hackerpatel007_1@htb[/htb]$ cat results.json | jq '.comments'
Hackerpatel007_1@htb[/htb]$ cat results.json | jq '.links'
```

### robots.txt and sitemap.xml

These two files are always the first manual checks before any automated crawling:

```bash
Hackerpatel007_1@htb[/htb]$ curl http://inlanefreight.htb:<PORT>/robots.txt
Hackerpatel007_1@htb[/htb]$ curl http://inlanefreight.htb:<PORT>/sitemap.xml
```

`robots.txt` Disallow directives are not a security control — they are a courtesy directive to search engine bots. Any path listed under `Disallow` is still fully accessible to a browser or curl. `Disallow: /admin_h1dd3n` tells an attacker exactly where the admin panel is.

---

## Section 5 — Web Archives

The Wayback Machine (web.archive.org) stores historical snapshots of websites. Old versions of a site frequently contain:

- Exposed credentials in configuration files that were later removed
- Old API endpoints that still work but are no longer linked
- Developer contact information and internal documentation
- Previous versions of pages showing how the application structure changed
- Subdomains and paths that were removed from the current site

```bash
# Query Wayback Machine CDX API for all URLs ever crawled
Hackerpatel007_1@htb[/htb]$ curl -s "http://web.archive.org/cdx/search/cdx?url=inlanefreight.com/*&output=text&fl=original&collapse=urlkey" | head -50

# Check if a specific URL has archived versions
Hackerpatel007_1@htb[/htb]$ curl -s "https://archive.org/wayback/available?url=inlanefreight.com"
```

The CDX API returns every URL the Wayback Machine ever crawled for a domain — including old admin paths, backup files, and API endpoints that no longer exist on the live site but may still be accessible on the server.

---

## Section 6 — Search Engine Discovery (Google Dorking)

Google and other search engines index far more about a target than the homepage. Specific search operators — called Google dorks — filter results to find sensitive information that is publicly accessible but not intentionally published.

### Core Google Dork Operators

| Operator | Usage | What It Finds |
|---|---|---|
| `site:` | `site:inlanefreight.com` | All indexed pages under the domain |
| `inurl:` | `inurl:admin site:target.com` | Pages with specific string in the URL |
| `intitle:` | `intitle:"index of" site:target.com` | Directory listings |
| `filetype:` | `filetype:pdf site:target.com` | Specific file types — PDFs, DOCs, config files |
| `ext:` | `ext:env site:target.com` | Environment files, config files |
| `cache:` | `cache:target.com` | Google's cached version of a page |
| `-` | `site:target.com -www` | Exclude results matching a string |

### High-Value Dork Examples

```bash
# Find exposed config files
site:inlanefreight.com filetype:env OR filetype:config OR filetype:yaml

# Find admin panels
site:inlanefreight.com inurl:admin OR inurl:login OR inurl:dashboard

# Find exposed directories
site:inlanefreight.com intitle:"index of"

# Find PDFs and documents
site:inlanefreight.com filetype:pdf OR filetype:docx OR filetype:xlsx

# Find subdomains not visible via DNS
site:*.inlanefreight.com -www

# Find exposed credentials
site:github.com inlanefreight password OR api_key OR secret
```

---

## Section 7 — Fingerprinting

Fingerprinting identifies the technology stack powering a web application — the web server software, CMS, programming language, framework, CDN, and version numbers. Every identified technology is a potential attack surface with its own CVE history.

### What to Fingerprint

| Layer | Examples | Tool |
|---|---|---|
| Web server | Apache 2.4.18, Nginx 1.26.1, IIS 10.0 | `curl -I`, Nmap |
| OS | Ubuntu, CentOS, Windows Server | HTTP headers, Nmap |
| CMS | WordPress 6.x, Joomla, Drupal | WhatWeb, Wappalyzer |
| Framework | Laravel, Django, Rails, ASP.NET | WhatWeb, cookie names |
| JavaScript | React, Vue, jQuery version | Browser devtools |
| CDN | Cloudflare, Akamai, Fastly | DNS, headers |

### Fingerprinting Commands

```bash
# HTTP response headers — first and fastest fingerprinting step
Hackerpatel007_1@htb[/htb]$ curl -I http://inlanefreight.htb:<PORT>

# Specific header inspection
Hackerpatel007_1@htb[/htb]$ curl -s -I http://inlanefreight.htb:<PORT> | grep -i "server\|x-powered-by\|x-generator"

# WhatWeb — automated technology fingerprinting
Hackerpatel007_1@htb[/htb]$ whatweb http://inlanefreight.htb:<PORT>
Hackerpatel007_1@htb[/htb]$ whatweb -a 3 http://inlanefreight.htb:<PORT>  # aggressive mode

# Nmap with HTTP scripts
Hackerpatel007_1@htb[/htb]$ nmap -p 80,443 --script http-headers,http-server-header inlanefreight.htb

# Nikto — web server scanner
Hackerpatel007_1@htb[/htb]$ nikto -h http://inlanefreight.htb:<PORT>
```

**Example header output:**

```
HTTP/1.1 200 OK
Server: nginx/1.26.1
X-Powered-By: PHP/8.1.2
X-Generator: WordPress 6.4.1
Content-Type: text/html; charset=UTF-8
```

Every value in the response headers is a fingerprint — `Server` gives the web server name and version, `X-Powered-By` gives the language/framework, `X-Generator` can reveal the CMS. Cross-reference each version against known CVEs immediately.

---

## Passive vs Active Reconnaissance — Decision Framework

| Situation | Technique | Risk |
|---|---|---|
| Scope not yet confirmed | WHOIS, crt.sh, Wayback, Google dorking | None |
| Early recon on external domain | Passive subdomain enum, theHarvester | Very Low |
| Active scope confirmed | DNS zone transfer, gobuster vhost, crawling | Low |
| Need full technology stack | WhatWeb, curl headers, Nikto | Medium |

Always exhaust passive techniques before touching the target. Passive recon generates zero alerts and can reveal more information than active scanning in many cases — certificates, old source code, and cached pages are all freely available without ever sending a packet to the target.

---

## Key Takeaways

WHOIS and certificate transparency logs are the fastest way to build an initial asset inventory before any active enumeration begins. `crt.sh` in particular returns every subdomain that has ever had a TLS certificate issued — which is frequently more comprehensive than brute-force subdomain enumeration.

The distinction between DNS subdomain enumeration and VHost enumeration was the most important concept in this module. DNS enumeration finds publicly resolvable names. VHost enumeration finds internal virtual hosts configured on the same server that have no public DNS record. A target can have a dozen internal applications that only appear in VHost enumeration — none of which would be found by DNS brute force. Both techniques are required.

The `robots.txt` file being a recon goldmine rather than a security control is something that seems obvious in retrospect but is easy to overlook. A `Disallow` directive is an explicit invitation to look at that path — it is telling every attacker exactly which directories the administrator wanted to hide from search engines.

The ReconSpider JSON output structure — separating emails, comments, links, and forms — makes manual analysis fast. The `comments` key is the most valuable field because developer comments routinely contain API keys, TODO items referencing vulnerabilities, and internal system names.

---

## Commands Reference

| Command | Purpose |
|---|---|
| `whois <domain>` | Full WHOIS lookup |
| `whois <domain> \| grep IANA` | Extract registrar IANA ID |
| `whois <domain> \| grep -i admin` | Extract admin contact email |
| `dig <domain> A` | Query A records |
| `dig <domain> MX` | Query mail exchange records |
| `dig <domain> NS` | Query name servers |
| `dig <domain> TXT` | Query TXT records (SPF, DKIM, tokens) |
| `dig -x <IP>` | Reverse DNS lookup |
| `dig axfr <domain> @<nameserver>` | Attempt zone transfer |
| `nslookup -query=mx <domain>` | Query MX records via nslookup |
| `dnsenum --enum <domain> -f <wordlist>` | Subdomain brute force + zone transfer |
| `gobuster dns -d <domain> -w <wordlist> -t 50` | DNS subdomain brute force |
| `gobuster vhost -u http://<domain>:<port> -w <wordlist> --append-domain -t 60` | VHost enumeration |
| `sudo sh -c "echo '<IP> <vhost>' >> /etc/hosts"` | Add discovered vhost to hosts file |
| `curl -I http://<target>` | HTTP response headers — fingerprint server |
| `curl http://<target>/robots.txt` | Check robots.txt for disallowed paths |
| `curl http://<target>/sitemap.xml` | Check sitemap for full site structure |
| `whatweb http://<target>` | Automated technology fingerprinting |
| `whatweb -a 3 http://<target>` | Aggressive fingerprinting mode |
| `nikto -h http://<target>` | Web server vulnerability scanner |
| `python3 ReconSpider.py http://<target>` | Crawl target and extract links, emails, comments |
| `cat results.json \| jq '.emails'` | Extract emails from crawl results |
| `cat results.json \| jq '.comments'` | Extract HTML comments from crawl results |
| `curl -s "http://web.archive.org/cdx/search/cdx?url=<domain>/*&output=text&fl=original&collapse=urlkey"` | Query Wayback Machine for all archived URLs |
