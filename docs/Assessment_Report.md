# Web Application Security Assessment Report

**Target:** OWASP DVWA (Damn Vulnerable Web Application), deployed at `http://192.168.56.101`
**Assessment Type:** Manual penetration testing + automated reconnaissance
**Assessment Level:** DVWA Security Level — Low

**Tester:** Khalil ullah

**Date:** August 2026

---

## 1. Executive Summary

This assessment evaluated a deliberately vulnerable web application (OWASP DVWA) deployed in an isolated lab environment, using a methodology modeled on real-world penetration testing engagements: reconnaissance, manual and tool-assisted exploitation, root-cause source code analysis, remediation, and re-validation. It additionally extended beyond typical exploitation testing to include **detection engineering** — building and validating SIEM detection rules against the exact attacks performed.

**Nine distinct security findings** were confirmed across four major vulnerability classes (SQL Injection, Cross-Site Scripting, Broken Authentication, and File Inclusion), plus multiple security misconfiguration issues identified during reconnaissance. The most severe finding, SQL Injection, allowed complete extraction of the application's user credential store — usernames and password hashes for all registered users — using nothing but a manipulated URL parameter.

Every exploited vulnerability was traced to its exact vulnerable source code, and a corrected implementation was written demonstrating the appropriate remediation technique (parameterized queries, output encoding, secure randomness, and allow-listing, depending on the vulnerability class). Three of these attack patterns were additionally instrumented with custom SIEM detection rules, which were tested and confirmed to generate alerts when the same attacks were replayed — closing the loop from "vulnerability found" to "vulnerability detectable."

Overall risk posture of the target, as configured, is **Critical**, driven primarily by the SQL Injection and Broken Authentication findings, both of which permit an unauthenticated or low-privilege attacker to obtain full user credential data with minimal effort.

---

## 2. Scope & Methodology

### 2.1 Scope

- **In scope:** OWASP DVWA application, running at DVWA Security Level "Low," including all core modules (SQL Injection, XSS — Reflected/Stored/DOM, Brute Force, Weak Session IDs, File Inclusion) plus the underlying Apache web server configuration.
- **Out of scope:** The underlying host operating system's general hardening (beyond what directly affects the web application), the Wazuh SIEM installation itself (used only as the detection target, not as a test subject), and DVWA modules not listed above (e.g., CSRF, File Upload, Command Injection, Insecure CAPTCHA) — reserved for potential future work.

### 2.2 Methodology

Testing followed a structured sequence:

1. **Reconnaissance** — technology fingerprinting, automated scanning (Nikto, Gobuster), manual review of server responses and headers.
2. **Manual exploitation** — hands-on testing of each vulnerability class, escalated from simple proof-of-concept to demonstrated real-world impact (e.g., SQLi escalated from a true/false injection to full credential extraction).
3. **Tool-assisted testing** — Burp Suite Community Edition used for request interception, manual parameter tampering, and automated brute-force testing (Intruder).
4. **Root-cause analysis** — direct review of DVWA's PHP/JavaScript source code for each exploited module to identify the exact flawed logic.
5. **Remediation** — secure code rewritten for each vulnerability, following established secure coding patterns.
6. **Detection engineering** — custom Wazuh SIEM rules authored and validated against replayed attack traffic.

See [`LAB_ARCHITECTURE.md`](LAB_ARCHITECTURE.md) for full lab topology and an honest discussion of design trade-offs made for this assessment.

### 2.3 Risk Rating Methodology

Severity ratings follow an approach consistent with the OWASP Risk Rating Methodology, considering both **Likelihood** (ease of discovery and exploitation, given the vulnerability requires no special access) and **Impact** (confidentiality, integrity, and availability consequences of successful exploitation). Given DVWA's Low security level has no mitigating controls, likelihood is uniformly high across all confirmed findings; ratings below are therefore primarily impact-driven.

| Rating | Criteria |
|---|---|
| **Critical** | Full compromise of confidentiality/integrity of sensitive data (e.g., all user credentials) with trivial exploitation |
| **High** | Significant data exposure or account compromise, exploitation requires minimal skill |
| **Medium** | Meaningful security weakness, but limited direct impact or requires additional conditions |
| **Low** | Defense-in-depth gap; not independently exploitable to significant effect |
| **Informational** | No direct security impact; noted for completeness or as a validated negative result |

---

## 3. Findings Summary

| # | Finding | Category (OWASP 2021) | Severity |
|---|---|---|---|
| 1 | SQL Injection — credential extraction via UNION-based injection | A03: Injection | **Critical** |
| 2 | Weak password hashing (MD5) | A02: Cryptographic Failures | Medium |
| 3 | Reflected Cross-Site Scripting | A03: Injection | High |
| 4 | Stored Cross-Site Scripting (asymmetric field protection) | A03: Injection | High |
| 5 | DOM-based Cross-Site Scripting | A03: Injection | High |
| 6 | No brute-force protection / weak default credentials | A07: Identification and Authentication Failures | High |
| 7 | Predictable session identifiers | A07: Identification and Authentication Failures | Medium |
| 8 | Local File Inclusion (LFI) | A03: Injection | High |
| 9 | Remote File Inclusion — tested, not exploitable (negative result) | A03: Injection | Informational |
| 10 | Security misconfiguration: directory indexing | A05: Security Misconfiguration | Low–Medium |
| 11 | Security misconfiguration: `.git` metadata exposure | A05: Security Misconfiguration | Medium |
| 12 | Security misconfiguration: missing HTTP security headers | A05: Security Misconfiguration | Low |
| 13 | Positive control: sensitive files (`.htaccess`, `.htpasswd`, `server-status`) correctly blocked | N/A | N/A (control validated) |

---

## 4. Detailed Findings

### Finding 1: SQL Injection — Credential Extraction (Critical)

**Description**
The SQL Injection module's User ID parameter is concatenated directly into a SQL query string with no input sanitization or parameterization, allowing an attacker to alter the query's logic and structure.

**Risk / Impact**
An attacker with no prior access can extract arbitrary data from any table in the database, including full user credentials. This is a complete confidentiality failure for the user store.

**Evidence**
- `screenshots/phase3_sqli_credential_extraction.png` — UNION-based injection returning usernames and password hashes for all registered users (admin, gordonb, 1337, pablo, smithy).

**Steps to Reproduce**
1. Navigate to the SQL Injection module, User ID field.
2. Submit: `1' UNION SELECT user, password FROM users-- -`
3. Observe the response returns all rows from the `users` table instead of a single user record.

**Root Cause**
```php
$id = $_REQUEST[ 'id' ];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```
User input is directly interpolated into the SQL query string. No boundary exists between "data" and "code" from the database engine's perspective.

**Remediation**
Use parameterized queries (prepared statements), which separate query structure from data at the protocol level:
```php
$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name FROM users WHERE user_id = ?");
mysqli_stmt_bind_param($stmt, "s", $id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```
See [`remediation-code/sqli_fix.php`](../remediation-code/sqli_fix.php) for the full corrected file.

---

### Finding 2: Weak Password Hashing — MD5 (Medium)

**Description**
Password values extracted during Finding 1 are 32-character hexadecimal strings consistent with unsalted MD5 hashes.

**Risk / Impact**
MD5 is cryptographically broken for password storage — it is fast to compute, making brute-force and precomputed rainbow-table attacks practical. Combined with Finding 1, an attacker who extracts the hash store can feasibly recover plaintext passwords for reuse elsewhere (credential stuffing).

**Evidence**
Observed directly in the extracted data from Finding 1; no separate exploitation was required.

**Remediation**
Passwords should be hashed with a slow, salted, purpose-built algorithm such as `bcrypt`, `Argon2`, or PHP's built-in `password_hash()` (which defaults to bcrypt and handles salting automatically):
```php
$hashed = password_hash($password, PASSWORD_DEFAULT);
// verification:
password_verify($input_password, $hashed);
```

---

### Finding 3: Reflected Cross-Site Scripting (High)

**Description**
The `name` parameter on the Reflected XSS module is echoed directly into the page's HTML with no output encoding.

**Risk / Impact**
An attacker can craft a malicious link that, when clicked by a victim, executes arbitrary JavaScript in the victim's browser session — enabling session hijacking, credential theft, or defacement.

**Evidence**
`screenshots/phase3_xss_reflected_alert.png` — `<script>alert('XSS-Reflected-Test')</script>` executes on page load.

**Root Cause**
```php
echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
```

**Remediation**
```php
echo '<pre>Hello ' . htmlspecialchars( $_GET[ 'name' ], ENT_QUOTES, 'UTF-8' ) . '</pre>';
```
`htmlspecialchars()` converts HTML-significant characters to their entity equivalents, ensuring injected markup is rendered as visible text rather than parsed as executable HTML/JS. See [`remediation-code/xss_reflected_fix.php`](../remediation-code/xss_reflected_fix.php).

---

### Finding 4: Stored Cross-Site Scripting (High)

**Description**
The Stored XSS module's guestbook **Name** field persists attacker-supplied input to the database with only SQL-injection-oriented escaping (`mysqli_real_escape_string`) applied — no HTML/XSS-specific output encoding. Notably, the **Message** field on the same form *does* correctly encode output, demonstrating inconsistent protection within a single form.

**Risk / Impact**
Higher severity than reflected XSS: the payload persists and executes for **every** visitor to the guestbook page, including potentially privileged users (e.g., an administrator reviewing submissions), without requiring a victim to click a crafted link.

**Evidence**
`screenshots/phase3_xss_stored_alert.png` — payload injected via the Name field executes on initial submission and again on page reload, confirming persistence.

**Root Cause**
```php
$name = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $name );
// Message field escaped the same way, but is additionally output-encoded elsewhere;
// Name field's stored value is later echoed without htmlspecialchars().
```

**Remediation**
Apply `htmlspecialchars()` to both fields specifically at **output/render time** (not just SQL-escaping at input time — these solve different problems):
```php
echo htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8') . ': ' . htmlspecialchars($row['comment'], ENT_QUOTES, 'UTF-8');
```
**Key takeaway:** SQL-injection sanitization and XSS output encoding are separate concerns; applying one does not provide protection against the other. See [`remediation-code/xss_stored_fix.php`](../remediation-code/xss_stored_fix.php).

---

### Finding 5: DOM-based Cross-Site Scripting (High)

**Description**
The DOM XSS module's language-selector JavaScript reads the `default` URL parameter and inserts it directly into the page via `document.write()`, with no encoding. Unlike Findings 3–4, this vulnerability exists entirely in client-side code — the server response itself is never "poisoned."

**Risk / Impact**
Identical impact to other XSS variants (arbitrary JS execution in the victim's browser), but the vulnerable logic and the required fix live in a different layer of the application (client-side JS vs. server-side PHP), and this vulnerability class is not visible to server-side defenses such as input validation or a WAF that only inspects requests, not client-side rendering behavior.

**Evidence**
`screenshots/phase3_xss_dom_alert.png` — navigating directly to `?default=<script>alert('XSS-DOM-Test')</script>` executes the payload with zero form submission.

**Root Cause**
```javascript
var lang = document.location.href.substring(document.location.href.indexOf("default=") + 8);
document.write("<option value='" + lang + "'>" + lang + "</option>");
```

**Remediation**
Avoid inserting untrusted data as raw HTML; build DOM elements programmatically and use `textContent`, which never interprets its value as markup:
```javascript
var option = document.createElement("option");
option.value = lang;
option.textContent = lang;
document.getElementById("langSelect").appendChild(option);
```
See [`remediation-code/xss_dom_fix.js`](../remediation-code/xss_dom_fix.js).

---

### Finding 6: No Brute-Force Protection (High)

**Description**
The Brute Force login module has no mechanism to detect, rate-limit, or lock out repeated failed login attempts. Additionally, the same query is separately vulnerable to SQL Injection via unparameterized concatenation.

**Risk / Impact**
An attacker can attempt unlimited password guesses against any username with no penalty, making credential-guessing attacks fully practical. Demonstrated in this assessment using Burp Suite Intruder against a small, realistic password list, successfully recovering the valid credential `admin`/`password` in ten attempts with zero resistance from the application.

**Evidence**
`screenshots/phase3_bruteforce_success.png` — Intruder attack results showing the successful attempt returning distinct response content ("Welcome to the password protected area") versus uniform failure responses for all other attempts.

**Root Cause**
```php
$query = "SELECT * FROM users WHERE user = '$user' AND password = '$pass';";
// No attempt counter, no lockout, no delay — every request is evaluated independently.
```

**Remediation**
Implement session-based attempt tracking with a temporary lockout after a defined threshold, in addition to fixing the co-located SQL Injection issue with parameterized queries:
```php
if( $_SESSION['login_attempts'] >= 3 && time() < $_SESSION['lockout_time'] ) {
    echo "<pre>Too many failed attempts. Try again later.</pre>";
    exit;
}
// ... on failed attempt:
$_SESSION['login_attempts']++;
if( $_SESSION['login_attempts'] >= 3 ) {
    $_SESSION['lockout_time'] = time() + 30;
}
```
See [`remediation-code/bruteforce_fix.php`](../remediation-code/bruteforce_fix.php) for the full implementation, including the parameterized-query fix applied to the same file.

**Note:** A production system would typically combine this with IP-based tracking, exponential backoff, and CAPTCHA — the fix above demonstrates the core mechanism (state tracking across requests) rather than a fully production-hardened implementation.

---

### Finding 7: Predictable Session Identifiers (Medium)

**Description**
The Weak Session IDs module generates its `dvwaSession` token as a simple incrementing integer (observed sequence: `1`, `3`, `4`) rather than a cryptographically random value.

**Risk / Impact**
Session tokens generated this way are trivially enumerable. An attacker does not need to steal a token — they can simply guess adjacent values, potentially hijacking another user's active session. For contrast, DVWA's own `PHPSESSID` (the actual authentication session cookie) is correctly implemented as a long, random alphanumeric string, demonstrating both the vulnerable and correct pattern exist side-by-side in the same application.

**Evidence**
`screenshots/phase3_weak_sessionid.png` — sequential `dvwaSession` values captured across repeated page loads.

**Root Cause**
```php
$cookie_value = $last_session_id + 1;
setcookie('dvwaSession', $cookie_value);
```

**Remediation**
Generate tokens using a cryptographically secure random source:
```php
$cookie_value = bin2hex(random_bytes(16));
setcookie('dvwaSession', $cookie_value);
```
`random_bytes()` draws from the OS's cryptographically secure entropy source, producing 2^128 possible values — computationally infeasible to guess or enumerate. See [`remediation-code/weak_sessionid_fix.php`](../remediation-code/weak_sessionid_fix.php).

---

### Finding 8: Local File Inclusion (High)

**Description**
The File Inclusion module's `page` parameter is passed directly to a file-inclusion function with no validation, allowing directory traversal to read arbitrary files on the server's filesystem.

**Risk / Impact**
An attacker can read any file the web server process has permission to access, including system configuration files. In this assessment, this was used to read `/etc/passwd`, which — due to this lab's co-located target/SIEM architecture (see [`LAB_ARCHITECTURE.md`](LAB_ARCHITECTURE.md)) — additionally revealed the existence and naming of Wazuh SIEM service accounts (`wazuh`, `wazuh-indexer`, `wazuh-dashboard`) and Wazuh's install path. This is a direct demonstration of why target/SIEM segmentation matters in production: this specific information leak would not occur in a properly segmented deployment.

**Evidence**
`screenshots/phase3_lfi_etcpasswd.png` — full contents of `/etc/passwd` returned via `?page=../../../../../../etc/passwd`.

**Root Cause**
```php
$file = $_GET[ 'page' ];
// passed directly to include(), with no validation
```

**Remediation**
Use an allow-list of explicitly permitted values rather than attempting to filter out malicious patterns:
```php
$allowed_pages = array( 'include.php', 'file1.php', 'file2.php', 'file3.php' );
$file = $_GET[ 'page' ];
if( !in_array( $file, $allowed_pages ) ) {
    $file = 'include.php';
}
```
Allow-listing is preferred over blacklisting because it does not require anticipating every possible bypass technique (encoded traversal sequences, absolute paths, null-byte injection, etc.). See [`remediation-code/file_inclusion_fix.php`](../remediation-code/file_inclusion_fix.php).

---

### Finding 9: Remote File Inclusion — Negative Result (Informational)

**Description**
RFI was tested using the same `page` parameter, attempting to fetch and execute a PHP payload hosted on the attacker machine.

**Result**
**Not exploitable.** PHP 8.2 (the version in use on the target) has removed support for remote stream wrappers in `include()`/`require()` as of PHP 7.4, superseding the legacy `allow_url_include` configuration directive even when explicitly enabled. DVWA's own interface surfaces this exact deprecation notice.

**Evidence**
`screenshots/phase3_rfi_blocked_php_version.png`

**Significance**
This is documented as a validated negative result rather than omitted, consistent with thorough assessment practice. It also demonstrates that platform-level hardening (PHP version) can neutralize an entire vulnerability class independent of application-level code changes.

---

### Finding 10: Security Misconfiguration — Directory Indexing (Low–Medium)

**Description**
Apache's directory indexing (`Options +Indexes`) is enabled globally, causing any directory without an index file to render a browsable file listing. Confirmed on `/config/`, `/database/`, `/docs/`, `/tests/`, and `/external/`.

**Risk / Impact**
Exposes application structure and filenames to unauthenticated visitors, aiding reconnaissance for further attacks. No direct data exposure was observed beyond directory/file names and one bundled third-party library (reCAPTCHA).

**Evidence**
Confirmed via Nikto scan and manual browser verification of each directory.

**Remediation**
Disable directory indexing in the Apache virtual host configuration:
```apache
<Directory /var/www/html>
    Options -Indexes
</Directory>
```
This single change remediates all five instances of this finding simultaneously, as they share one root cause.

---

### Finding 11: Security Misconfiguration — `.git` Metadata Exposure (Medium)

**Description**
The application's `.git` directory (version control metadata) is publicly web-accessible (`.git/HEAD`, `.git/config`, `.git/index` all returned HTTP 200).

**Risk / Impact**
In a real deployment, an exposed `.git` directory can allow reconstruction of source code history, potentially including old code, comments, or accidentally committed credentials. Expected in this lab (deployed via direct `git clone` into the web root) but represents a genuine, common real-world misconfiguration.

**Evidence**
Confirmed via Nikto and Gobuster scans.

**Remediation**
Never deploy directly from a `git clone` into a web-servable directory. Either deploy from a build artifact that excludes `.git`, or explicitly block access:
```apache
<DirectoryMatch "\.git">
    Require all denied
</DirectoryMatch>
```

---

### Finding 12: Security Misconfiguration — Missing HTTP Security Headers (Low)

**Description**
The application does not set `Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`, or `Permissions-Policy` headers.

**Risk / Impact**
These headers provide defense-in-depth against several attack classes (notably reducing the impact of XSS via CSP). Their absence does not itself constitute an exploitable vulnerability but weakens the application's overall security posture.

**Evidence**
Confirmed via Nikto scan and manual header inspection (`curl -I`).

**Remediation**
Add security headers at the Apache configuration level:
```apache
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
```

**Positive note:** The `Server` response header discloses the Apache version but *not* the PHP version — better than the common default configuration, and worth noting as a partial positive control.

---

### Finding 13: Positive Control — Sensitive Files Correctly Blocked

**Description**
`.htaccess`, `.htpasswd`, and `/server-status` all correctly return HTTP 403 Forbidden, confirming these sensitive paths are appropriately access-restricted.

**Significance**
Included to demonstrate methodical testing (verifying protections work, not only reporting failures) and to give the assessment balanced coverage rather than reading as exclusively negative.

---

## 5. Detection & Monitoring

Beyond identifying and remediating vulnerabilities, this assessment builds detection capability for the exploited attack patterns, integrating with an existing Wazuh SIEM deployment (see Projects 1–2 of this portfolio).

### 5.1 Log Pipeline

Apache's access log (`/var/log/apache2/access.log`) was configured as a monitored local file source in Wazuh (`ossec.conf`), using Wazuh's built-in `apache` log format decoder, which structures raw log lines into queryable fields (`data.url`, `data.srcip`, `data.protocol`, etc.) without custom parsing logic.

### 5.2 Custom Detection Rules

Three custom rules were authored in `local_rules.xml`, each validated by replaying the exact attack traffic used during exploitation and confirming a corresponding alert was generated.

| Rule ID | Detects | Detection Technique | MITRE ATT&CK |
|---|---|---|---|
| 100014 | SQL Injection payloads in request URLs | Content matching against `data.url` | T1190 — Exploit Public-Facing Application |
| 100015 | XSS payloads in request URLs | Content matching against `data.url` | T1059.007 — JavaScript |
| 100016 | Brute-force login attempts | Frequency/correlation (≥5 matching events within 60 seconds) | T1110 — Brute Force |

Full rule definitions are in [`detection-rules/local_rules.xml`](../detection-rules/local_rules.xml).

**Methodological note:** Rules 100014 and 100015 use content-based matching, appropriate for attacks visible within a single request. Rule 100016 uses frequency-based correlation instead, because brute force is only identifiable as a *pattern over time* — a single failed login is normal behavior; five in sixty seconds is not. This distinction — matching single-event content versus correlating event frequency — reflects a broader detection engineering principle: the correct technique depends on how the attack manifests in log data, not a one-size-fits-all approach.

### 5.3 Validation

Each rule was tested by re-executing the corresponding attack (or, for brute force, a scripted sequence of failed logins) and confirming the expected alert appeared in the Wazuh dashboard, including correct `rule.description`, `rule.level`, and `rule.mitre.id` fields. Screenshots of each firing alert are included in `screenshots/`.

### 5.4 Supplementary Findings from Existing Wazuh Coverage

Independent of the custom rules above, the existing Wazuh deployment's default modules surfaced additional relevant data during this assessment:

- **CIS Debian 12 Benchmark (SCA) scan:** scored 37/100, including a failed check for "Ensure web server services are not in use" — corroborating the target/SIEM co-location trade-off discussed in `LAB_ARCHITECTURE.md`.
- **Rootcheck module** flagged several DVWA/Kali system binaries (`/usr/bin/passwd`, `/bin/chsh`, `/bin/chfn`) as "Trojaned version of file detected." These were reviewed and assessed as **false positives** — generic signature matching against binaries compiled differently than Wazuh's reference signatures expect, not evidence of actual compromise. Documented here to demonstrate alert triage rather than blind alert reporting.

---

## 6. Conclusion & Recommendations

The assessed application, as configured at DVWA's "Low" security level, exhibits critical-severity vulnerabilities across multiple OWASP Top 10 (2021) categories. While DVWA is intentionally vulnerable by design, the specific flaws examined — string-concatenated SQL queries, unencoded output, absent rate-limiting, predictable randomness, and unvalidated file paths — are all commonly found in real production applications, and the remediation patterns demonstrated here are directly transferable.

**Priority recommendations, in order:**

1. **Adopt parameterized queries as a non-negotiable coding standard** for all database access — this single practice would have fully remediated Findings 1 and half of Finding 6.
2. **Enforce output encoding at every point untrusted data is rendered**, distinct from input sanitization — Finding 4 specifically demonstrates that SQL-oriented escaping provides no XSS protection.
3. **Implement authentication rate-limiting** (attempt counting, lockout, and ideally IP-based tracking) on all login endpoints.
4. **Use cryptographically secure randomness** (`random_bytes()` or equivalent) for any security-relevant token generation.
5. **Adopt allow-listing over blacklisting** for any user-controlled value that maps to file paths, includes, or redirects.
6. **Apply baseline server hardening** — disable directory indexing, block `.git` exposure, and set standard security headers — as part of a deployment checklist rather than ad hoc configuration.
7. **Extend detection coverage** to the remaining untested DVWA modules (CSRF, Command Injection, File Upload) as a natural next phase of this work.

This assessment demonstrates that meaningful security testing extends beyond vulnerability discovery: understanding root cause, writing correct fixes, and building detection capability for the same attack patterns together form a complete, defensible security engineering workflow.
