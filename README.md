# Web Application Security — Vulnerable App Testing & Defensive Hardening

## Overview

This project is a full-cycle web application security engagement performed in an isolated home lab against **OWASP DVWA (Damn Vulnerable Web Application)**. It covers the complete lifecycle a security practitioner works through in a real engagement:

**Reconnaissance → Exploitation → Root-Cause Analysis → Remediation → Detection Engineering → Formal Reporting**

Unlike a typical "ran a scanner" writeup, this project ties offensive testing directly back into defensive infrastructure: every exploited vulnerability was traced to its exact line of vulnerable source code, a corrected version was written, and a custom Wazuh detection rule was built and *proven to fire* against the same attack pattern used to exploit it.

This project is part of a broader SOC/blue-team portfolio, alongside related work in:
- SOC automation (Wazuh, Shuffle, TheHive)
- MITRE ATT&CK-mapped detection engineering + MISP threat intel
- DFIR — memory forensics and timeline reconstruction
- Network security monitoring and threat hunting (Suricata, Zeek)

## What's in this repo

| Path | Contents |
|---|---|
| [`docs/ASSESSMENT_REPORT.md`](docs/ASSESSMENT_REPORT.md) | Full formal security assessment report (Finding → Risk → Evidence → Remediation), pentest-report format |
| [`docs/LAB_ARCHITECTURE.md`](docs/LAB_ARCHITECTURE.md) | Lab topology, design decisions, and honest trade-off notes |
| [`detection-rules/local_rules.xml`](detection-rules/local_rules.xml) | Three custom Wazuh detection rules (SQLi, XSS, Brute Force), each MITRE ATT&CK-mapped and confirmed firing against live attack traffic |
| [`remediation-code/`](remediation-code/) | Before/after PHP and JavaScript code for every vulnerability fixed, with inline explanations |
| [`screenshots/`](screenshots/) | Evidence captures, referenced throughout the report |

## Lab Environment

- **Attacker:** Kali Linux (native/bare-metal host)
- **Target:** Debian 12 VM — Apache 2.4 / MariaDB / PHP 8.2, hosting DVWA
- **Detection:** Wazuh manager + dashboard (co-located on the target VM — see [Lab Architecture](docs/LAB_ARCHITECTURE.md) for the reasoning and trade-offs)
- **Network:** VirtualBox host-only adapter, `192.168.56.0/24`

## Vulnerability Classes Covered

| # | Class | Result | OWASP 2021 Category |
|---|---|---|---|
| 1 | SQL Injection (UNION-based) | ✅ Exploited — full credential extraction | A03: Injection |
| 2 | Reflected XSS | ✅ Exploited | A03: Injection |
| 3 | Stored XSS | ✅ Exploited | A03: Injection |
| 4 | DOM-based XSS | ✅ Exploited | A03: Injection |
| 5 | Broken Authentication (no rate limiting) | ✅ Exploited via Burp Intruder | A07: Auth Failures |
| 6 | Predictable Session IDs | ✅ Confirmed sequential | A07: Auth Failures |
| 7 | Local File Inclusion (LFI) | ✅ Exploited — read `/etc/passwd` | A03: Injection |
| 8 | Remote File Inclusion (RFI) | ❌ Not exploitable — PHP 8.2 hardening (documented negative result) | A03: Injection |
| 9 | Security Misconfiguration | ✅ Multiple findings (directory indexing, `.git` exposure, missing headers) | A05: Security Misconfiguration |
| 10 | Weak Cryptography (MD5 password hashing) | ✅ Observed during SQLi extraction | A02: Cryptographic Failures |

Full details, evidence, and remediation for each are in the [assessment report](docs/ASSESSMENT_REPORT.md).

## Detection Engineering

Three custom Wazuh rules were written and validated by re-running the exact attacks used during exploitation:

| Rule ID | Detects | Technique | MITRE ATT&CK |
|---|---|---|---|
| 100014 | SQL Injection payloads in URL parameters | Content matching | T1190 |
| 100015 | XSS payloads in URL parameters | Content matching | T1059.007 |
| 100016 | Brute-force login attempts | Frequency/correlation (5 events / 60s) | T1110 |

See [`detection-rules/local_rules.xml`](detection-rules/local_rules.xml) for the full rule definitions.

## Tools Used

- **OWASP DVWA** — vulnerable target application
- **Burp Suite Community Edition** — intercepting proxy, manual testing, Intruder (brute force)
- **Nikto** — automated web server misconfiguration scanning
- **Gobuster** — directory/content discovery
- **curl** — precise, scriptable request crafting and session control
- **Wazuh** — SIEM manager, custom detection rule engine
- **MariaDB / Apache / PHP 8.2** — target application stack

## Skills Demonstrated

- Manual web application penetration testing methodology (recon → exploitation → reporting)
- Root-cause vulnerability analysis at the source-code level
- Secure coding remediation (parameterized queries, output encoding, whitelisting, secure randomness)
- SIEM detection rule authoring (content-based and frequency/correlation-based)
- MITRE ATT&CK technique mapping
- Professional security assessment report writing
