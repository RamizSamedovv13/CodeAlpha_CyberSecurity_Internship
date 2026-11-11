"""Regex rules for non-Python languages + secret detection for every text file."""
import re
from .core import make

# (rule_id, severity, regex, extensions or None for all)
SECRET_PATTERNS = [
    ("SEC-KEY", "CRITICAL", r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    ("SEC-KEY", "CRITICAL", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "Private key"),
    ("SEC-KEY", "HIGH", r"gh[pousr]_[A-Za-z0-9]{36,}", "GitHub token"),
    ("SEC-KEY", "HIGH", r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    ("SEC-KEY", "HIGH", r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    ("SEC-KEY", "HIGH", r"sk_live_[0-9a-zA-Z]{20,}", "Stripe live key"),
    ("SEC-KEY", "MEDIUM", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JSON Web Token"),
]
GENERIC_SECRET = re.compile(r"""(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"]([^'"\s]{6,})['"]""")
PLACEHOLDER = re.compile(r"^(<.*>|\$\{.*\}|\{\{.*\}\}|x+|\*+|your.*|example.*|changeme|process\.env.*|os\.environ.*)$", re.I)

LANG_RULES = [
    ("JS-EVAL", "HIGH", r"\beval\s*\(", {".js", ".jsx", ".ts", ".tsx", ".mjs"}),
    ("JS-XSS", "MEDIUM", r"\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML", {".js", ".jsx", ".ts", ".tsx", ".html", ".mjs"}),
    ("JS-CMDI", "HIGH", r"\b(?:exec|execSync)\s*\([^)]*(?:\+|\$\{)", {".js", ".ts", ".mjs"}),
    ("JS-SQLI", "HIGH", r"(?i)(?:query|execute)\s*\(\s*[\"'`][^\"'`]*\b(?:select|insert|update|delete)\b[^\"'`]*(?:[\"'`]\s*\+|\$\{)", {".js", ".ts", ".mjs"}),
    ("JS-TLS", "HIGH", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", {".js", ".ts", ".mjs"}),
    ("PHP-EXEC", "CRITICAL", r"\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)", {".php"}),
    ("PHP-INCL", "CRITICAL", r"\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)", {".php"}),
    ("PHP-DESER", "HIGH", r"\bunserialize\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)", {".php"}),
    ("PHP-SQLI", "CRITICAL", r"(?i)(?:mysqli?_query|->query|pg_query)\s*\([^;]*\$_(?:GET|POST|REQUEST)", {".php"}),
    ("PHP-XSS", "HIGH", r"\b(?:echo|print)\b[^;]*\$_(?:GET|POST|REQUEST)", {".php"}),
    ("JAVA-EXEC", "HIGH", r"Runtime\.getRuntime\(\)\.exec\s*\(", {".java"}),
    ("JAVA-HASH", "MEDIUM", r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"", {".java"}),
    ("JAVA-SQLI", "HIGH", r"(?i)(?:createStatement|executeQuery|executeUpdate|prepareStatement)\s*\([^)]*\"\s*\+", {".java"}),
    ("JAVA-DESER", "HIGH", r"new\s+ObjectInputStream\s*\(", {".java"}),
    ("C-UNSAFE", "HIGH", r"\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(", {".c", ".cpp", ".h", ".cc"}),
    ("C-SYSTEM", "MEDIUM", r"\bsystem\s*\(", {".c", ".cpp", ".cc"}),
]
COMPILED = [(r, s, re.compile(rx), exts) for r, s, rx, exts in LANG_RULES]
SECRET_COMPILED = [(r, s, re.compile(rx), d) for r, s, rx, d in SECRET_PATTERNS]
COMMENT = re.compile(r"^\s*(//|#|\*|/\*|<!--)")


def redact(text):
    return re.sub(r"([A-Za-z0-9_\-/+=]{4})[A-Za-z0-9_\-/+=]{6,}", r"\1****", text)


def scan_text(path, ext, source):
    out = []
    for i, line in enumerate(source.splitlines(), 1):
        if "scr:ignore" in line or len(line) > 400:   # skip minified / generated lines
            continue
        for rule, sev, rx, desc in SECRET_COMPILED:
            if rx.search(line):
                out.append(make(rule, sev, path, i, redact(line.strip())[:200], desc + " found in source", "regex", "HIGH"))
        if ext != ".py":
            m = GENERIC_SECRET.search(line)
            if m and not PLACEHOLDER.match(m.group(2)) and not COMMENT.match(line):
                out.append(make("SEC-KEY", "MEDIUM", path, i, redact(line.strip())[:200], f"Hardcoded value for '{m.group(1)}'", "regex", "MEDIUM"))
            if COMMENT.match(line):
                continue
            for rule, sev, rx, exts in COMPILED:
                if ext in exts and rx.search(line):
                    out.append(make(rule, sev, path, i, line.strip()[:200], "", "regex", "MEDIUM"))
    return out
