# DNS — Footprinting
**Port(s):** 53
**Protocol:** UDP (queries), TCP (zone transfers, large responses)
**CPTS Module:** Footprinting | **Date:** March 2026

## What DNS Is and Why Pentesters Care

DNS translates domain names to IP addresses but from a pentesting perspective
it is a goldmine of infrastructure information. A misconfigured DNS server
will hand over its entire zone file — every hostname, IP address, mail server,
and subdomain — to anyone who asks via a zone transfer. Even without zone
transfer access, DNS enumeration reveals internal hostnames, naming conventions,
mail infrastructure, and sometimes internal IP addresses that should never
be public.

Key record types a pentester cares about: A (hostname to IP), AAAA (IPv6),
MX (mail servers), NS (nameservers), TXT (SPF, DKIM, sometimes credentials
or config info left by mistake), CNAME (aliases), PTR (reverse lookup),
SOA (zone authority info).

## Enumeration — Step by Step

### Step 1 — Initial Query
```bash
# Query default DNS for basic records
nslookup inlanefreight.com
dig inlanefreight.com

# Query specific DNS server
dig inlanefreight.com @10.129.14.128

# Get all available record types
dig any inlanefreight.com @10.129.14.128
```

### Step 2 — Individual Record Type Queries
```bash
dig a inlanefreight.com @10.129.14.128       # A records
dig aaaa inlanefreight.com @10.129.14.128    # IPv6 records
dig mx inlanefreight.com @10.129.14.128      # Mail servers
dig ns inlanefreight.com @10.129.14.128      # Nameservers
dig txt inlanefreight.com @10.129.14.128     # TXT records (SPF, DKIM, etc)
dig soa inlanefreight.com @10.129.14.128     # Start of Authority
```

### Step 3 — Zone Transfer Attempt (Critical)
```bash
dig axfr inlanefreight.com @10.129.14.128
# axfr = Asynchronous Full Transfer
# If misconfigured, returns EVERY record in the zone
# This is the equivalent of getting the entire network map for free
```

**Internal zone transfer:**
```bash
dig axfr internal.inlanefreight.com @10.129.14.128
# Internal zones often contain private IP ranges and sensitive hostnames
```

### Step 4 — Subdomain Brute Forcing
```bash
# Using dnsenum
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt \
        -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
        inlanefreight.com

# Using fierce
fierce --domain inlanefreight.com --dns-servers 10.129.14.128

# Using subfinder (passive)
subfinder -d inlanefreight.com -v
```

### Step 5 — Reverse Lookup
```bash
# Reverse lookup — IP to hostname
dig -x 10.129.14.128 @10.129.14.128

# Reverse lookup across entire subnet
for ip in $(seq 1 254); do
  host 10.129.14.$ip 10.129.14.128 | grep "domain name"
done
```

## Common Misconfigurations

| Misconfiguration | Why It Is Dangerous | Attack Path |
|---|---|---|
| Zone transfer allowed from any IP | Entire zone file exposed | `dig axfr` returns all hostnames and IPs |
| Internal hostnames in public DNS | Infrastructure mapping | Reveals naming conventions and internal IPs |
| TXT records with sensitive data | Config info exposed | SPF records reveal all mail infrastructure |
| Wildcard DNS `*.domain.com` | Subdomain takeover potential | Unregistered CNAMEs can be hijacked |
| Recursive queries allowed externally | DNS amplification DDoS possible | Use server as amplifier in DDoS attacks |

## Real Lab Output
```
Hackerpatel007_1@htb[/htb]$ dig axfr inlanefreight.com @10.129.14.128

; <<>> DiG 9.16.1 <<>> axfr inlanefreight.com @10.129.14.128
;; global options: +cmd
inlanefreight.com.    3600  IN  SOA   ns1.inlanefreight.com. ...
inlanefreight.com.    3600  IN  TXT   "v=spf1 include:mailgun.org ..."
inlanefreight.com.    3600  IN  MX    10 mail.inlanefreight.com.
app.inlanefreight.com. 3600 IN  A     10.129.14.130
internal.inlanefreight.com. 3600 IN A 192.168.1.5
mail.inlanefreight.com. 3600 IN  A    10.129.14.131
dev.inlanefreight.com.  3600 IN  A    10.129.14.132
```

## What I Learned / What Surprised Me

Zone transfers genuinely surprised me — the idea that a misconfigured DNS
server just hands over its entire database in one query feels almost absurd.
But it happens in real environments constantly because internal DNS servers
are often configured permissively for legitimate replication between DNS
servers and nobody locks it down externally. The TXT record enumeration was
also new to me — I had no idea SPF records indirectly reveal every third-party
email service a company uses, which is valuable OSINT for phishing campaigns.


## Commands Reference

| Command | Purpose |
|---|---|
| `dig any <domain> @<DNS-IP>` | Query all record types |
| `dig axfr <domain> @<DNS-IP>` | Zone transfer attempt |
| `dig axfr internal.<domain> @<DNS-IP>` | Internal zone transfer |
| `dig -x <IP> @<DNS-IP>` | Reverse lookup |
| `dnsenum --dnsserver <IP> --enum -f <wordlist> <domain>` | Subdomain brute force |
| `fierce --domain <domain>` | Subdomain enumeration |
| `subfinder -d <domain> -v` | Passive subdomain discovery |
