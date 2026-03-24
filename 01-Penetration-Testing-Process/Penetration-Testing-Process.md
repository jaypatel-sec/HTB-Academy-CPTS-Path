# HTB Academy — Module 01: Penetration Testing Process

| Field | Details |
|---|---|
| Platform | Hack The Box Academy |
| Module | 01 — Penetration Testing Process |
| Difficulty | Fundamental |
| Type | Conceptual — No lab |
| Date | March 2026 |

---

## Module Overview

This module introduces the full penetration testing process from first contact with a client through to final report delivery. No hands-on lab — entirely conceptual and methodology focused. It covers the legal framework, engagement structure, all eight phases of a pentest, and how each phase feeds into the next. It is the foundation that every practical module in the CPTS path is built on.

---

## What Penetration Testing Actually Is

Penetration testing is the authorised simulation of real-world attacks against a client's infrastructure to identify security weaknesses before malicious actors do. The key word is authorised — without a signed contract and documented scope, every action a pentester takes is illegal regardless of intent.

A penetration test is not a vulnerability scan. A scanner identifies what might be vulnerable. A penetration test proves what is actually exploitable, demonstrates the real-world impact, and chains findings together to show how far an attacker could actually get. That chain — from initial access to full domain compromise — is what justifies the cost of an engagement and what clients actually need to understand their risk.

The three types of pentest engagements by knowledge level:

| Type | What the Tester Knows | What It Simulates |
|---|---|---|
| Black Box | Only the target IP/domain | External attacker with no prior knowledge |
| Grey Box | Some internal info (user creds, architecture) | Insider threat or post-phishing attacker |
| White Box | Full source code, network diagrams, creds | Most thorough — finds the deepest issues |

---

## The Eight Phases of a Penetration Test

Every engagement follows the same process regardless of scope size. Skipping or rushing any phase creates gaps that reduce the quality and defensibility of findings.

### Phase 1 — Pre-Engagement

Everything that happens before any testing begins. This phase produces the legal and contractual foundation that protects both the tester and the client.

Three essential components:
- **Scoping questionnaire** — client answers questions about what they want tested, timeline, constraints, and objectives
- **Pre-engagement meeting** — both parties review the questionnaire output, clarify scope, agree on rules
- **Kick-off meeting** — final alignment before testing starts, confirm emergency contacts and escalation procedures

Documents produced:

| Document | Purpose |
|---|---|
| Non-Disclosure Agreement (NDA) | Confidentiality — signed before any details are discussed |
| Scope of Work (SoW) / Contract | Legal agreement — defines deliverables, timeline, payment |
| Rules of Engagement (RoE) | Technical boundaries — what is allowed, what is off-limits |
| Penetration Testing Proposal | Detailed description of methodology, team, tools, timeline |
| Emergency Contact Sheet | Who to call if something breaks during testing |

NDA types:

| Type | Who Must Keep Confidential | When Used |
|---|---|---|
| Unilateral | Only the tester | Rare — client wants freedom to discuss findings |
| Bilateral | Both parties | Most common — mutual confidentiality |
| Multilateral | Three or more parties | Large engagements with subcontractors |

The NDA must be signed before the kick-off meeting or at the very latest at the start of it — before any confidential client details are shared.

Scope definition is the most important document in the engagement. It lists exactly what is in scope — IP ranges, domains, specific systems, excluded hosts — and is the legal boundary for every action taken. Going outside scope, even to follow a promising lead, is a legal violation. If something interesting is discovered outside scope, stop and contact the client before proceeding.

---

### Phase 2 — Information Gathering

The first active phase. The goal is to collect as much information as possible about the target before attempting any exploitation. Better reconnaissance produces better attacks — every piece of information reduces guesswork and increases the precision of later phases.

Two categories:

| Category | Description |
|---|---|
| OSINT (Passive) | Information collected from public sources — no direct interaction with target infrastructure |
| Active Recon | Direct interaction with target systems — DNS queries, port scans, banner grabbing |

What to collect:

| Target Area | Information Sought |
|---|---|
| Network | IP ranges, open ports, services, protocols, firewall rules |
| Web | Technologies, frameworks, login portals, subdomains, APIs |
| People | Email addresses, employee names, job titles, LinkedIn data |
| Infrastructure | Cloud providers, CDN usage, internal naming conventions |
| Credentials | Leaked credentials in public breach databases, Pastebin, GitHub |

The more specific and accurate the information gathered here, the more targeted and effective the exploitation phase becomes.

---

### Phase 3 — Vulnerability Assessment

Taking the information gathered and systematically identifying potential weaknesses. This is where raw recon data is analysed and converted into a prioritised list of attack vectors.

Two approaches:

| Approach | Description |
|---|---|
| Automated | Tools like Nessus, OpenVAS — fast, broad coverage, high false positive rate |
| Manual | Tester-driven analysis — slower, more accurate, catches logic flaws |

Analysis types:
- **Descriptive** — what happened (characterise what was found)
- **Diagnostic** — why it happened (root cause of the vulnerability)
- **Predictive** — what will likely happen (likelihood of exploitation)
- **Prescriptive** — what to do about it (specific remediation action)

Vulnerabilities are rated by severity to guide prioritisation. A critical RCE with no authentication required ranks above a medium-severity misconfiguration that requires prior access.

---

### Phase 4 — Exploitation

Taking identified vulnerabilities and attempting to confirm they are actually exploitable in this specific environment. The goal is not just to run a PoC — it is to demonstrate real-world impact.

Key principle: exploit the minimum necessary to prove access. Destroying data, crashing services, or causing business disruption is never the goal and should always be avoided. If an exploit is destructive by nature, it must be discussed with the client before execution.

What exploitation produces:
- Confirmed vulnerabilities (not just theoretical)
- Initial foothold on at least one system
- Proof-of-concept evidence for the report
- Starting point for post-exploitation phases

---

### Phase 5 — Post-Exploitation

Once a foothold is established, post-exploitation determines the actual impact of that access. This phase answers the question: what could a real attacker do from here?

Objectives:

| Action | Purpose |
|---|---|
| Local enumeration | OS version, installed software, local users, scheduled tasks |
| Credential dumping | SAM database, LSASS, credential files, browser-stored passwords |
| Sensitive data search | PII, financial data, source code, internal documentation |
| Persistence | Demonstrate that an attacker could maintain long-term access |
| Situational awareness | Network shares, internal hosts, trust relationships |

This phase documents the blast radius — if an attacker reached this point, what would they have access to?

---

### Phase 6 — Lateral Movement

Using the initial foothold to move through the network and access additional systems. The goal is to demonstrate how far an attacker with one compromised machine could propagate.

Common techniques:

| Technique | Description |
|---|---|
| Pass-the-Hash | Reuse NTLM hash without cracking the password |
| Pass-the-Ticket | Reuse Kerberos tickets for authentication |
| Credential reuse | Test recovered passwords against other services and systems |
| Pivoting | Route traffic through compromised hosts to reach isolated segments |
| Exploitation of trust | Abuse AD trust relationships between domains |

Lateral movement only applies to systems explicitly within the defined scope. Discovering an interesting host outside scope requires stopping and consulting the client.

---

### Phase 7 — Proof of Concept

Documenting and demonstrating that identified vulnerabilities are real and reproducible. A proof of concept (PoC) is the evidence that converts a finding from theoretical to confirmed.

What a good PoC includes:
- Step-by-step reproduction instructions
- Specific tool commands and parameters used
- Actual output — screenshots, terminal captures, file contents
- Impact statement — what an attacker could do with this access
- Remediation recommendation

The PoC is what the client's technical team uses to reproduce and then verify the fix. Vague descriptions without reproduction steps are not useful findings.

---

### Phase 8 — Post-Engagement

The administrative phase after all testing is complete. Testing without proper documentation and communication leaves the client without the information they paid for.

Activities:

| Activity | Description |
|---|---|
| Data analysis | Correlate all findings, identify chains and dependencies |
| Report writing | Produce formal deliverable — executive summary + technical detail |
| Risk rating | Assign severity to each finding — Critical/High/Medium/Low/Info |
| Report delivery | Deliver to client through secure channel |
| Report walkthrough meeting | Explain findings, answer technical questions, confirm understanding |
| Remediation support | Assist client in understanding and implementing fixes |
| Evidence cleanup | Remove all tools, shells, persistence, and created accounts from target |

The report is a legal document. It must be accurate, professional, and deliverable to both technical staff and senior management. The executive summary explains business risk in plain language. The technical sections provide everything a developer or sysadmin needs to reproduce and fix the finding.

Evidence cleanup is non-negotiable. Every created user account, uploaded file, installed tool, and persistence mechanism must be removed. A backdoor left on a client's network after a pentest is a security liability — and potentially a legal one.

---

## The Legal Boundary — Never Cross This Line

A penetration test without a signed, in-scope contract is a criminal act. The tools and techniques used in a pentest — Nmap, Metasploit, Hydra, Burp Suite — are identical to what malicious attackers use. The only thing that separates a penetration tester from a criminal is documented, explicit authorisation.

Rules that must never be broken:
- Never test systems not listed in the scope document
- Never store or retain client data beyond what is necessary for the report
- Never perform destructive actions (data deletion, service disruption) without explicit prior approval
- Always have a signed contract before touching anything
- If in doubt about scope, stop and ask — do not proceed

The authorisation chain: **NDA → SoW/Contract → RoE → Start of Testing**. If any link in that chain is missing, there is no legal basis for any action taken.

---

## How This Module Connects to the Rest of CPTS

Every subsequent module in the CPTS path corresponds to one or more phases of this process:

| Phase | Relevant CPTS Modules |
|---|---|
| Information Gathering | Footprinting, Information Gathering Web Edition, Network Enumeration with Nmap |
| Vulnerability Assessment | Vulnerability Assessment |
| Exploitation | Shells and Payloads, Metasploit, Attacking Common Services, Web modules |
| Post-Exploitation | Password Attacks, File Transfers |
| Lateral Movement | Pivoting, Active Directory Enumeration and Attacks |
| Privilege Escalation | Linux PrivEsc, Windows PrivEsc |
| Post-Engagement | Documentation and Reporting |

This module is the map. Every other module is a location on it.

---

## Key Takeaways

The thing that stood out most from this module is how much of a pentest happens before and after the actual hacking. The technical phases — exploitation, lateral movement, post-exploitation — are probably 30–40% of the total engagement work. The rest is pre-engagement documentation, information gathering, report writing, and post-engagement communication.

Understanding the phases also changes how I think about tools. Nmap is an information gathering tool. Gobuster is an information gathering tool. Neither of them means anything without the broader question: what phase am I in, what am I trying to answer, and what comes next? Running Nmap without knowing why you're running it or what you're going to do with the output is just noise.

The legal section was more important than I expected. The specific point that doing any active scanning without written authorisation is illegal — regardless of good intentions — is not something every aspiring pentester fully internalises. The contract is not bureaucracy. It is the thing that makes the entire engagement legitimate.

---

## Commands Reference

This module is conceptual — no lab commands. The commands relevant to each phase are covered in their corresponding modules:

| Phase | Module Where Commands Are Covered |
|---|---|
| Information Gathering | Footprinting, Network Enumeration with Nmap |
| Vulnerability Assessment | Vulnerability Assessment |
| Exploitation | Shells and Payloads, Metasploit |
| Post-Exploitation | Password Attacks, File Transfers |
| Lateral Movement | Pivoting, Active Directory Attacks |
| Privilege Escalation | Linux PrivEsc, Windows PrivEsc |
| Reporting | Documentation and Reporting |

---

Main portfolio: [Offensive-Security-Portfolio](https://github.com/jaypatel-sec/Offensive-Security-Portfolio)
