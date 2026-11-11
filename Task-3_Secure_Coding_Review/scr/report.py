"""Report writers: console, JSON, Markdown, HTML, SARIF."""
import html
import json
import sys
from collections import Counter
from . import __version__
from .core import SEV_ORDER

COLORS = {"CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[33m", "LOW": "\033[36m", "INFO": "\033[37m"}
HTML_COLORS = {"CRITICAL": "#b00020", "HIGH": "#e53935", "MEDIUM": "#f9a825", "LOW": "#1e88e5", "INFO": "#757575"}


def summary(findings):
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}


def console(findings, stats, color=True):
    out = []
    paint = (lambda s, t: f"{COLORS[s]}{t}\033[0m") if color else (lambda s, t: t)
    for f in findings:
        out.append(f"{paint(f.severity, f'[{f.severity}]'):<18} {f.rule_id:<10} {f.file}:{f.line}")
        out.append(f"    {f.title} ({f.cwe}, {f.owasp})")
        if f.message and f.message != f.title:
            out.append(f"    -> {f.message}")
        out.append(f"    code: {f.snippet}")
        out.append(f"    fix : {f.fix}\n")
    s = summary(findings)
    out.append("=" * 70)
    out.append(f"Scanned {stats['files']} files / {stats['lines']} lines in {stats['seconds']:.2f}s  |  "
               + "  ".join(f"{k}: {v}" for k, v in s.items()) + f"  |  TOTAL: {len(findings)}")
    return "\n".join(out)


def to_json(findings, stats, target):
    return json.dumps({"tool": "scr", "version": __version__, "target": target, "stats": stats,
                       "summary": summary(findings), "findings": [f.to_dict() for f in findings]}, indent=2)


def to_markdown(findings, stats, target):
    s = summary(findings)
    L = [f"# Secure Code Review Report", "", f"**Target:** `{target}`  ", f"**Tool:** SCR v{__version__}  ",
         f"**Files scanned:** {stats['files']} ({stats['lines']} lines)", "", "## Summary", "",
         "| Severity | Count |", "|---|---|"] + [f"| {k} | {v} |" for k, v in s.items()] + ["", f"**Total findings: {len(findings)}**", "",
         "## Findings overview", "", "| # | Severity | Rule | CWE | Location |", "|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        L.append(f"| {i} | {f.severity} | {f.rule_id} | {f.cwe} | `{f.file}:{f.line}` |")
    L += ["", "## Details", ""]
    for i, f in enumerate(findings, 1):
        L += [f"### {i}. {f.title} — {f.severity}", f"- **Location:** `{f.file}:{f.line}`", f"- **CWE / OWASP:** {f.cwe} / {f.owasp}",
              f"- **Detail:** {f.message}", f"- **Confidence:** {f.confidence}", "- **Code:**", "```", f.snippet, "```", f"- **Remediation:** {f.fix}", ""]
    return "\n".join(L)


def to_html(findings, stats, target):
    s = summary(findings)
    e = html.escape
    cards = []
    for f in findings:
        cards.append(f"""<details class="card"><summary><span class="sev" style="background:{HTML_COLORS[f.severity]}">{f.severity}</span>
<b>{e(f.title)}</b> <code>{e(f.file)}:{f.line}</code> <span class="tag">{f.rule_id}</span></summary>
<p>{e(f.message)}</p><p class="meta">{e(f.cwe)} &middot; {e(f.owasp)} &middot; confidence {f.confidence} &middot; source {f.source}</p>
<pre>{e(f.snippet)}</pre><p class="fix"><b>Fix:</b> {e(f.fix)}</p></details>""")
    badges = "".join(f'<div class="b" style="border-color:{HTML_COLORS[k]}"><span style="color:{HTML_COLORS[k]}">{v}</span>{k}</div>' for k, v in s.items())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SCR Report</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>
:root{{--bg:#fff;--fg:#1b1f23;--card:#f6f8fa;--bd:#d0d7de}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--fg:#e6edf3;--card:#161b22;--bd:#30363d}}}}
body{{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:960px;margin:2rem auto;padding:0 1rem}}
.row{{display:flex;gap:.8rem;flex-wrap:wrap;margin:1rem 0}}.b{{border:2px solid;border-radius:10px;padding:.6rem 1rem;text-align:center;min-width:90px;font-size:.8rem}}
.b span{{display:block;font-size:1.6rem;font-weight:700}}.card{{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:.6rem 1rem;margin:.5rem 0}}
summary{{cursor:pointer}}.sev{{color:#fff;border-radius:4px;padding:1px 7px;font-size:.75rem;margin-right:.4rem}}.tag{{opacity:.6;font-size:.75rem}}
pre{{background:var(--bg);border:1px solid var(--bd);padding:.5rem;border-radius:6px;overflow-x:auto}}.meta{{opacity:.7;font-size:.85rem}}.fix{{border-left:3px solid #2da44e;padding-left:.6rem}}
</style></head><body><h1>Secure Code Review Report</h1>
<p>Target <code>{e(target)}</code> &middot; {stats['files']} files &middot; {stats['lines']} lines &middot; SCR v{__version__}</p>
<div class="row">{badges}</div><h2>{len(findings)} findings</h2>{''.join(cards) or '<p>No findings.</p>'}</body></html>"""


def to_sarif(findings, target):
    rules, seen = [], set()
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            rules.append({"id": f.rule_id, "name": f.title, "shortDescription": {"text": f.title},
                          "help": {"text": f.fix}, "properties": {"tags": [f.cwe, f.owasp]}})
    lvl = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    res = [{"ruleId": f.rule_id, "level": lvl[f.severity], "message": {"text": f.message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": f.line}}}]} for f in findings]
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "SCR", "version": __version__, "rules": rules}}, "results": res}]}, indent=2)
