# CodeAlpha Cyber Security Internship

Projects completed during my **Cyber Security Internship at [CodeAlpha](https://www.codealpha.tech)**.

| # | Task | Folder | Status |
|---|------|--------|--------|
| 1 | Basic Network Sniffer | [`Task-1_Basic-Network-Sniffer`](./Task-1_Basic-Network-Sniffer) | ✅ Done |
| 2 | Phishing Awareness Training | [`Task-2_Phishing-Awareness`](./Task-2_Phishing-Awareness) | ✅ Done |
| 3 | Secure Coding Review | [`Task-3_Secure_Coding_Review`](./Task-3_Secure_Coding_Review) | ✅ Done |
| 4 | Network Intrusion Detection System | [`Task-4_Network-IDS`](./Task-4_Network-IDS) | ✅ Done |

---

## Task 1 — Basic Network Sniffer
A Python program that captures network traffic and shows the structure of each packet.

- Captures packets and displays source/destination IPs, protocols and payloads
- Helps understand how data flows through a network and how common protocols work
- Built with: `Python`, `scapy` / `socket` <!-- TODO: keep only what you actually used -->

**Run:** see the README inside [`Task-1_Basic-Network-Sniffer`](./Task-1_Basic-Network-Sniffer). <!-- TODO: add the run command, e.g. sudo python3 sniffer.py -->

---

## Task 2 — Phishing Awareness Training
Training material that teaches how to recognize and avoid phishing attacks.

- How to spot phishing emails and fake websites
- Social-engineering tactics used by attackers
- Best practices to avoid becoming a victim
- <!-- TODO: mention real examples / quiz if you included them -->

**Content:** see [`Task-2_Phishing-Awareness`](./Task-2_Phishing-Awareness).

---

## Task 3 — Secure Coding Review: the **SCR** tool
Instead of reviewing one app by hand, I built **SCR**, a command-line tool that audits source code for security vulnerabilities. It is written in Python and uses **only the standard library**.

**How it works**
- **AST + taint analysis (Python):** marks user input (`request.*`, `input()`, `sys.argv`) as tainted, follows it through the code and reports when it reaches a dangerous function (SQL, shell, `eval`, `pickle`, templates, files, URLs)
- **Heuristic checks:** IDOR, weak password hashing, debug mode, disabled TLS verification, unverified JWT
- **Secret scanner:** API keys, private keys, hardcoded passwords (values are masked in reports)
- **Pattern rules:** JavaScript, PHP, Java, C/C++
- Every finding includes **CWE + OWASP Top 10 mapping, exact line, and a fix**
- Reports: console, **HTML**, JSON, Markdown, **SARIF**; CI mode with `--fail-on`

---

## Task 4 — Network Intrusion Detection System 
Set up a network-based intrusion detection system (NIDS) to detect suspicious and malicious activity.

**Planned scope**
1. Set up a network-based IDS using tools like **Snort** or **Suricata**
2. Configure rules and alerts to detect suspicious or malicious activity
3. Monitor network traffic continuously for potential threats
4. Implement response mechanisms for detected intrusions
5. *(Optional)* Visualize detected attacks using dashboards or graphs

**Status:** not started yet. Code, rules and documentation will be added to [`Task-4_Network-IDS`](./Task-4_Network-IDS) when completed.

**Results**

| Target | Findings |
|---|---|
| Own demo app (vulnerable version) | 12 |
| Same app after remediation | **0** |
| we45/Vulnerable-Flask-App | 17 |
| pygoat (25,000+ lines) | 164 |
| dvpwa | 5 |

- Exploit tests on the demo app: **7/7 attacks succeed before the fix, 7/7 are blocked after**
- Compared with Bandit: SCR also found template injection, JWT with `verify=False` and IDOR; Bandit found missing request timeouts and weak `random`. The tools complement each other.
- 14 unit tests; known limitations are documented in the report

**Quick start**
```bash
cd Task-3_Secure_Coding_Review
python3 -m venv venv && source venv/bin/activate
python scr.py samples/vulnerable                      # scan the demo app
python scr.py <path> -f html,json,md -o report        # generate reports
python -m unittest tests.test_scr -v                  # run tests
```

Full write-up: [`SECURE_CODING_REVIEW.md`](./Task-3_Secure_Coding_Review/SECURE_CODING_REVIEW.md)

> ⚠️ `samples/vulnerable` is deliberately insecure and for learning only. Scan only code you own or have permission to review.

---

## Tech & Skills
`Python` · `Network analysis` · `Static analysis (AST)` · `OWASP Top 10` · `CWE` · `Secure coding` · `Social engineering awareness` · `Git/GitHub`

## Author
**Ramiz Samedov**
GitHub: [@RamizSamedovv13](https://github.com/RamizSamedovv13)
LinkedIn: https://linkedin.com/in/ramiz-samedov-b0a182375

*Internship: [CodeAlpha](https://www.codealpha.tech) — Cyber Security*
