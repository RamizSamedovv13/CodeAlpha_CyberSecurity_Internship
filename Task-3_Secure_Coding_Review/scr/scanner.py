"""File walking + orchestration."""
import os
import time
from . import pyast, regex_rules
from .core import SEV_ORDER

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", ".tox", ".idea", ".mypy_cache", "site-packages", "migrations"}
TEXT_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".php", ".java", ".c", ".cpp", ".cc", ".h", ".html", ".htm", ".yml", ".yaml",
            ".json", ".env", ".cfg", ".ini", ".conf", ".toml", ".properties", ".sh", ".rb", ".go", ".txt", ".xml"}
MAX_BYTES = 1_000_000


def iter_files(target, excludes):
    if os.path.isfile(target):
        yield target
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not any(x in os.path.join(root, d) for x in excludes)]
        for fn in files:
            p = os.path.join(root, fn)
            ext = os.path.splitext(fn)[1].lower()
            if ".min." in fn:
                continue
            if (ext in TEXT_EXT or fn in (".env", "Dockerfile")) and not any(x in p for x in excludes):
                yield p


def scan(target, min_severity="LOW", excludes=()):
    t0 = time.time()
    base = target if os.path.isdir(target) else os.path.dirname(target)
    findings, files, lines, errors = [], 0, 0, []
    for p in iter_files(target, excludes):
        try:
            if os.path.getsize(p) > MAX_BYTES:
                continue
            src = open(p, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        rel = os.path.relpath(p, base) if os.path.isdir(target) else os.path.basename(p)
        ext = os.path.splitext(p)[1].lower()
        files += 1
        lines += src.count("\n") + 1
        if ext == ".py":
            try:
                findings += pyast.analyze(rel, src)
            except SyntaxError as e:
                errors.append(f"{rel}: syntax error line {e.lineno}")
        findings += regex_rules.scan_text(rel, ext, src)
    seen, uniq = set(), []
    for f in findings:
        k = (f.file, f.line, f.rule_id)
        if k not in seen and SEV_ORDER[f.severity] >= SEV_ORDER[min_severity]:
            seen.add(k)
            uniq.append(f)
    uniq.sort(key=lambda f: (-SEV_ORDER[f.severity], f.file, f.line))
    return uniq, {"files": files, "lines": lines, "seconds": time.time() - t0, "errors": errors}
