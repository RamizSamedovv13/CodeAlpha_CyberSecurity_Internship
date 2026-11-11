#!/usr/bin/env python3
"""SCR - Secure Code Review tool (CodeAlpha Internship, Task 3)

Usage:
  python scr.py PATH                              # scan a file or directory
  python scr.py PATH -f html,json,md,sarif -o out # also write reports
  python scr.py PATH --min-severity MEDIUM --fail-on HIGH   # CI mode (exit code 1)
"""
import argparse
import os
import sys
from scr import __version__, report
from scr.core import SEV_ORDER
from scr.scanner import scan

BANNER = r"""
  ___  ___ ___     Secure Code Review tool v%s
 / __|/ __| _ \    AST taint analysis + secret detection
 \__ \ (__|   /    CWE / OWASP Top 10 mapping
 |___/\___|_|_\
"""


def main():
    ap = argparse.ArgumentParser(description="Static secure-code-review scanner")
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("-f", "--formats", default="", help="comma list: html,json,md,sarif")
    ap.add_argument("-o", "--out", default="scr_report", help="output directory for reports")
    ap.add_argument("--min-severity", default="LOW", choices=list(SEV_ORDER))
    ap.add_argument("--fail-on", default=None, choices=list(SEV_ORDER), help="exit 1 if a finding >= this severity exists")
    ap.add_argument("--exclude", action="append", default=[], help="substring of paths to skip (repeatable)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print the summary line")
    a = ap.parse_args()
    if not os.path.exists(a.path):
        sys.exit(f"error: {a.path} not found")
    color = sys.stdout.isatty() and not a.no_color
    if not a.quiet:
        print(BANNER % __version__)
    findings, stats = scan(a.path, a.min_severity, a.exclude)
    text = report.console(findings, stats, color)
    print(text.splitlines()[-1] if a.quiet else text)
    for e in stats["errors"]:
        print("warning:", e, file=sys.stderr)
    fmts = [x.strip() for x in a.formats.split(",") if x.strip()]
    if fmts:
        os.makedirs(a.out, exist_ok=True)
        writers = {"json": ("report.json", lambda: report.to_json(findings, stats, a.path)),
                   "md": ("report.md", lambda: report.to_markdown(findings, stats, a.path)),
                   "html": ("report.html", lambda: report.to_html(findings, stats, a.path)),
                   "sarif": ("report.sarif", lambda: report.to_sarif(findings, a.path))}
        for f in fmts:
            if f in writers:
                name, fn = writers[f]
                open(os.path.join(a.out, name), "w", encoding="utf-8").write(fn())
                print(f"wrote {os.path.join(a.out, name)}")
    if a.fail_on and any(SEV_ORDER[f.severity] >= SEV_ORDER[a.fail_on] for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
