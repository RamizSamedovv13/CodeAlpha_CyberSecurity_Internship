# Secure Coding Review — SCR Tool & Case Studies

**Author:** _<your name>_ · **Date:** 11 Nov 2026 · **CodeAlpha Cyber Security Internship — Task 3**

## 1. Objective
Task 3 asks to *select a language/application, review its code for vulnerabilities (static analyzers or manual inspection), recommend secure-coding practices and document remediation.*
Instead of reviewing a single app by hand, I built **SCR**, a reusable review tool, and used it to audit **four code bases** (one written by me, three third-party open-source projects).

## 2. Tool design
- **Language of the tool:** Python 3 (stdlib only, ~650 lines). **Languages it can review:** Python (deep analysis), JavaScript/TypeScript, PHP, Java, C/C++ (pattern rules), secrets in any text file.
- **Python engine:** `ast` parser + intra-procedural **taint analysis**.
  `source → propagation → sink`, e.g. `request.args["host"]` → `host` → `"ping " + host` → `os.popen()` ⇒ *Critical OS command injection*.
  Severity depends on taint: user-controlled data → Critical/High; dynamic but not proven user-controlled → High/Medium.
- **Sanitizer awareness** reduces false positives (`int()`, `secure_filename()`, `escape()`, `shlex.quote()`…).
- **Logic heuristic:** IDOR detection — a route taking an id that queries the DB without referencing `session`/`current_user`.
- **Output:** each finding has rule ID, severity, CWE, OWASP 2021 category, file:line, code, explanation, confidence and a concrete **fix**. Formats: console, HTML, JSON, Markdown, **SARIF** (importable by GitHub Code Scanning). `--fail-on` makes it usable in CI/CD.
- **Rules (40):** SQLi, command injection, eval/exec, insecure deserialization (pickle/yaml/marshal), SSTI/XSS, path traversal, SSRF, open redirect, weak hashes, TLS verification off, JWT unverified, debug mode, 0.0.0.0 bind, CSRF exempt, insecure cookies, hard-coded secrets/keys, IDOR, temp files, file permissions + JS/PHP/Java/C rules.

## 3. Methodology
1. Run SCR on the target; 2. manually triage every finding (true/false positive); 3. compare with **Bandit** (industry-standard Python SAST); 4. fix and re-scan (demo app); 5. prove exploitability with PoC tests (demo app); 6. unit-test the tool itself.

## 4. Results
| Target | Type | Files / LOC | Critical | High | Medium | Total |
|---|---|---|---|---|---|---|
| `samples/vulnerable` | own demo (Flask) | 2 / 83 | 3 | 7 | 2 | **12** |
| `samples/secure` | fixed version | 2 / 123 | 0 | 0 | 0 | **0** |
| Vulnerable-Flask-App (we45) | 3rd-party Flask | 15 / 878 | 2 | 12 | 3 | **17** |
| pygoat (OWASP-style, Django/Flask labs) | 3rd-party | 330 / 25,091 | 4 | 66 | 94 | **164** |
| dvpwa | 3rd-party aiohttp | 27 / 10,809 | 0 | 1 | 4 | **5** |

Scan speed: 25k lines in ≈0.3 s.

### 4.1 Real vulnerabilities found in third-party code (Vulnerable-Flask-App)
| Finding | Location | Rule |
|---|---|---|
| SQL injection (`db.engine.execute(str_query)`) | `app/app.py:265` | PY-SQLI — Critical |
| Template injection (`render_template_string(template,…)`) | `app.py:114, 281` | PY-SSTI — Critical/High |
| JWT decoded with `verify=False` | `app.py:97` | PY-JWT — High |
| MD5 for passwords | `app.py:141` | PY-HASH — High |
| Hard-coded `secret_key`, HMAC keys, default admin password | `app.py:26-28, 63` | PY-SECRET — High |
| Unsafe `yaml.load()` | `app.py:329` | PY-YAML — Medium |
| IDOR on `get_customer(cust_id)` | `app.py:222` | PY-IDOR — Medium (heuristic) |
| TLS verification disabled in test client | `tests/e2e_zap.py` | PY-TLS — High |

### 4.2 SCR vs Bandit (same target, Vulnerable-Flask-App)
| Class | SCR | Bandit |
|---|---|---|
| SQL injection, MD5, yaml.load, hard-coded passwords, TLS off | ✅ | ✅ |
| **SSTI / XSS via `render_template_string`** | ✅ | ❌ |
| **JWT signature verification disabled** | ✅ | ❌ |
| **IDOR / broken access control (heuristic)** | ✅ | ❌ |
| Missing request timeouts (B113), weak `random` (B311) | ❌ | ✅ |

On the own demo app Bandit missed IDOR, SSTI/XSS and path traversal; SCR found them. **Conclusion:** the tools are complementary — best practice is to run both plus manual review.

### 4.3 Fix verification (demo app)
`samples/secure/app.py` applies: parameterized queries, scrypt password hashing, `session.clear()` + ownership checks, auto-escaped templates, `subprocess` list + allow-list, `send_from_directory`, JSON instead of pickle, `safe_load`, secret from env, debug off, security headers. SCR: 12 → **0** findings; PoC attacks (`samples/evidence/exploit_tests.py`): 7/7 exploitable → 7/7 blocked.

## 5. Limitations (honest assessment)
- Taint tracking is **intra-procedural**: data passed through helper functions or class attributes is not followed → false negatives.
- IDOR and weak-hash-in-password-context are **heuristics** (confidence flagged LOW/MEDIUM) and need human triage.
- Pattern rules for JS/PHP/Java/C are regex-based (no parsing) → noisier; intentionally-vulnerable training apps (pygoat) naturally produce many findings, including debug/bind issues that are by design.
- No dependency (CVE) scanning — use `pip-audit` / `npm audit` alongside.
- Static analysis cannot prove exploitability; findings must be validated.

## 6. Secure coding recommendations
1. Treat all external input as hostile; validate with allow-lists, encode output for its context.
2. Parameterize SQL; never build SQL/commands/templates by concatenation.
3. Enforce authentication **and** object-level authorization server-side on every request.
4. Store passwords with scrypt/bcrypt/argon2; never MD5/SHA-1/plaintext.
5. Keep secrets out of source control (env vars / vault); rotate leaked ones; add secret scanning to CI.
6. Avoid dangerous APIs: `pickle`, `eval/exec`, `yaml.load`, `os.system`, `shell=True`.
7. Secure defaults: debug off, minimal exposure, HTTPS, secure cookies, security headers, CSRF protection.
8. Automate: run SCR/Bandit/Semgrep + dependency audit in CI (`--fail-on HIGH`, SARIF upload) and keep human code review.

## 7. Future work
Inter-procedural taint, Django/ORM-specific sinks, dependency CVE check, auto-fix suggestions as diffs, baseline file to ignore accepted findings.
