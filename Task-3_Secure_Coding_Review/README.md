# CodeAlpha_Secure_Coding_Review

**CodeAlpha Cyber Security Internship — Task 3: Secure Coding Review**

**SCR** is a command-line *secure code review tool* written in Python (standard library only).
It scans a file or a whole project, finds security vulnerabilities, maps each to **CWE + OWASP Top 10**, shows the
exact line, and gives a **remediation** for every finding. Reports: console, **HTML**, JSON, Markdown, **SARIF**.

## How it works
| Layer | What it does |
|---|---|
| **Python AST + taint tracking** | Parses code into a syntax tree, marks user input as *tainted* (`request.*`, `input()`, `sys.argv`, route params), follows it through assignments, and reports when it reaches a dangerous *sink* (SQL, shell, `eval`, `pickle`, template, file, URL…). Sanitizers (`int()`, `secure_filename()`, `escape()`…) clear the taint. |
| **Heuristic checks** | IDOR (route loads an object by id without checking the session user), weak password hashing, debug mode, TLS off, JWT without verification, CSRF exempt… |
| **Secret scanner** | AWS/GitHub/Slack/Google/Stripe keys, private keys, JWTs, hard-coded passwords (values are redacted in reports). |
| **Regex rules** | JavaScript, PHP, Java, C/C++ (eval, innerHTML, SQL concat, `unserialize`, `strcpy`…). |

## Install & run
```bash
python3 -m venv venv && source venv/bin/activate        # Kali/Debian need a venv
python scr.py <path>                                    # scan a folder or file
python scr.py <path> -f html,json,md,sarif -o report    # write reports (open report/report.html)
python scr.py <path> --min-severity MEDIUM --fail-on HIGH   # CI mode: exit code 1 if HIGH+ found
python scr.py <path> --exclude tests --exclude docs     # skip paths
```
Suppress a reviewed false positive with `# scr:ignore` at the end of the line.

## Tests
```bash
python -m unittest tests.test_scr -v      # 14 tests: each rule fires on bad code, silent on good code
```

## Demo / evidence
| Target | Files | Lines | Findings (SCR) |
|---|---|---|---|
| `samples/vulnerable` (own demo app) | 2 | 83 | 12 (3 Critical, 7 High, 2 Medium) |
| `samples/secure` (fixed version) | 2 | 123 | **0** |
| we45/Vulnerable-Flask-App (3rd party) | 15 | 878 | 17 |
| adeyosemanputra/pygoat (3rd party, Django) | 330 | 25,091 | 164 |
| anxolerd/dvpwa (3rd party, aiohttp) | 27 | 10,809 | 5 |

Full reports for each target are in `evidence/case_*/` (HTML, JSON, Markdown, SARIF).
Detailed write-up: **`SECURE_CODING_REVIEW.md`**.

## Layout
```
scr.py              CLI entry point
scr/                core.py (rules catalog) · pyast.py (AST+taint) · regex_rules.py · scanner.py · report.py
tests/              unit tests
samples/            vulnerable + fixed demo app, exploit PoC tests
evidence/           generated reports for every scanned target
```
> ⚠️ Only scan code you own or have permission to review. `samples/vulnerable` is deliberately insecure — never deploy it.
