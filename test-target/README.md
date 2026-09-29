# NoSQLi Hunter — Local Test Target

Deliberately vulnerable Node.js + MongoDB app for regression-testing the
extension without touching any real target. **Local/authorized use only.**

## Run

```bash
cd test-target
docker compose up --build
# App:    http://localhost:3000
# Users:  administrator / s3cur3P@ss!   and   wiener / peter
```

## Endpoints and what they exercise

| Endpoint | Body type | What it tests |
|---|---|---|
| `GET /csrf` | — | Issues a reusable CSRF token (plain text) |
| `POST /login-json` | JSON | Lab-style strict login: requires a valid `csrf` field (403 without one) and **exactly one** matching record (500 "unexpected number of records" on multi-match). Exercises per-field rewriting + CSRF preservation + single-account payloads (`$regex admin.*`) |
| `POST /login-url` | urlencoded | Lenient `findOne` login, no CSRF. Exercises the urlencoded operator path (`extended=true` so `username[$ne]` parses as an object) |
| `GET /search?filter=x` | GET params | Query-string operator injection, response reflects the filter (DiffEngine normalization test) |
| `GET /my-account?id=x` | — | Success page containing welcome/logout keywords (auth-path detection) |

## Expected NoSQLi Hunter results (regression matrix)

Capture these requests through Burp, then right-click → NoSQLi Hunter:

| Request | Attack | Expected |
|---|---|---|
| `POST /login-json` (with csrf) | Authentication Bypass → JSON Operator Bypass | CRITICAL `AUTH-BYPASS` on single-account payloads (`$regex admin.*`, `$in`, `administrator+$ne`); broad `$ne`/`$gt` payloads → MEDIUM `OPERATOR-ERROR` lead (500 multi-record); **no 403s** — the csrf field must survive |
| `POST /login-json` | Operator Injection Scan | HIGH `OPERATOR-INJECTION` (2+ reproducible pairs) |
| `POST /login-url` | Authentication Bypass → URL-Encoded | CRITICAL `AUTH-BYPASS` |
| `GET /search?filter=x` | Operator Injection Scan | findable differential on `filter` |
| `POST /login-json` | Extract Field Data ($regex) | HIGH `DATA-EXTRACT` with `s3cur3P@ss!` |
| `httpbin.org/post` (or any echo) | Operator Injection Scan | **zero findings** — reflected-payload FP must stay dead |

## Cleanup

```bash
docker compose down -v
```
