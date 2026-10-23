# NoSQLi Hunter — Testing Guide

Two things live here: the PortSwigger lab regression list (T3) and the
repeatable manual checklist (T4). Run both after any detection-logic change.

## T3 — Lab regression list

All labs are free with a PortSwigger account. Record: winning payload,
expected finding (technique + severity), and the log lines that must appear.

| # | Lab | What it covers | Expected result |
|---|-----|----------------|-----------------|
| 1 | Exploiting NoSQL operator injection to bypass authentication | JSON auth bypass, exactly-one-record apps (500 on multi-match), re-baselining on a valid-creds capture | `AUTH-BYPASS` CRITICAL on `$regex admin.*` / `$in` / `administrator+$ne`; broad `$ne`/`$gt` payloads → MEDIUM `OPERATOR-ERROR` lead, never CRITICAL; log shows `Baseline looks already logged-in ... re-baselining` |
| 2 | Detecting NoSQL injection | Error-based via the trackingId cookie (Pro: active scan; Community: manual error strings via Repeater) | ERROR-BASED detection concept — signature appears only after injection |
| 3 | Exploiting NoSQL operator injection to extract unknown fields | `$regex` prefix extraction | Extract Field Data → `DATA-EXTRACT` HIGH with the administrator password |
| 4 | Exploiting NoSQL injection to extract data ($where) | Manual technique reference (cookie-based, tool documents it in cheatsheet) | Informational |

Negative controls (must produce ZERO findings):
- `httpbin.org/post` / `/get` echo endpoints — reflects payloads, not a Mongo app.
- Any non-NoSQL login (e.g. the SQL injection authentication labs) via Auth Bypass.

## T4.5 — v2.1.1 regression checks

Each item below guards a bug fixed in v2.1.1; run them after any change to
`ScanState`, the context-menu scan lifecycle, or the extraction builder.

1. **Full Scan actually runs** — right-click → Full Scan on the
   `/login-url` request from `test-target`. The log must show attempt
   lines from EVERY technique (`[AUTH BYPASS] Attempt 1/10`, `[OPERATOR
   SCAN] Testing parameter`, `[TIME-BASED] Baseline avg`, ...) and NOT a
   single "A scan is already running" line.
2. **Cancel releases the host** — start any scan, click Cancel Scan, then
   immediately start the same scan again: it must begin (no 15-minute
   lockout message).
3. **Cancel stops the whole Full Scan** — cancel during the AUTH BYPASS
   stage; the log must show `[AUTH BYPASS] Cancelled.`, `[FULL SCAN]
   Cancelled — skipping the remaining techniques.` and NO later technique
   starting up again.
4. **$regex extraction on urlencoded** — run Extract Field Data on the
   `/login-url` request (`administrator` / `s3cur3P@ss!` seeded): progress
   lines must appear per character and end with
   `DONE: password = s3cur3P@ss!`. (v2.1.0 sent the ORIGINAL request for
   every probe on urlencoded bodies — oracle failed instantly.)
5. **JS scan negative control** — run JavaScript Injection against
   `httpbin.org/post`: zero findings (reflective echo only). Transient
   diffs must log `diff not reproducible — skipped`.
6. **CT confusion keeps CSRF** — run Content-Type Confusion on
   `/login-json` (CSRF-protected): the sent requests must still carry the
   original `csrf` field; a bare 403 must NOT be reported as a finding.

## T4 — Manual checklist

Per body type (urlencoded / JSON / GET / GraphQL), run each attack from the
right-click menu on the matching request from `test-target` (see its README)
or a lab:

1. **Body Type line** in the menu shows the detected type.
2. **Authentication Bypass** — verify in Logger that ONLY the user/pass fields
   changed; every other body field (CSRF!) is byte-identical.
3. **Operator Injection Scan** — confirming pairs log `DIFFERENT (…)` AND a
   `diff not reproducible` never precedes a finding; 2+ pairs required.
4. **Extract Field Data** — progress lines appear per matched char; cancel
   button stops it mid-run.
5. **Time-Based / CT Confusion / Aggregation** — CT/Agg findings are MEDIUM
   unless a DB error signature appeared.
6. **Findings table** — sort by any column, double-click a row: the shown
   request must belong to THAT finding (row-mapping check).
7. **Send to Repeater** — the Repeater tab opens with the exact stored request.
8. **Export Findings** — save as .json, .csv, .html; open each and verify
   content; re-run a scan → duplicates are suppressed (`Duplicate suppressed`
   log line).
9. **Cancel Scan** — click during a Full Scan; loops stop at the next request;
   the host guard releases.
10. **Theme** — repeat 1-2 in Burp light and dark: everything readable, no
    custom colors except severity text.
11. **Logging** — no emoji anywhere; no HTML markup rendered as text in dialogs.

## Failure triage

- Finding on a non-vulnerable target → capture the Logger request pair and
  check `DiffEngine.normalize` coverage (new dynamic field? add it + a test).
- Missing finding on a known-vulnerable target → check the log for
  `not reproducible` / `blocked response` / oracle lines; then the payload set.
