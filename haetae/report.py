"""Turn a ScanResult into text, JSON, Markdown or a standalone HTML page."""

from __future__ import annotations

import html
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .models import ScanResult, Severity

COLORS = {
    Severity.CRITICAL: "\033[1;41;97m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def render_text(result: ScanResult, stream=sys.stdout) -> str:
    color = _use_color(stream)
    c = (lambda code, s: f"{code}{s}{RESET}") if color else (lambda code, s: s)

    out = [c(BOLD, f"haetae {__version__}") + f" · scanned {result.files_scanned} files in {result.root}", ""]
    findings = result.sorted_findings()
    if not findings:
        out.append(c(BOLD, "✓ No findings."))
    for f in findings:
        tag = f" {f.severity.label().upper()} "
        out.append(f"{c(COLORS[f.severity], tag)} {f.check} {c(BOLD, f.rule)} — {f.location()}")
        out.append(f"    {f.message}")
        if f.extra.get("introduced_in"):
            out.append(f"    introduced in commit {f.extra['introduced_in'][:7]}")
        out.append(c(DIM, f"    why: {f.why}"))
        out.append(f"    fix: {f.fix}")
        out.append("")

    counts = ", ".join(f"{n} {sev}" for sev, n in result.counts().items() if n)
    out.append(c(BOLD, "Summary: ") + (counts or "clean"))
    for note in result.skipped:
        out.append(c(DIM, f"Note: {note}"))
    return "\n".join(out)


def render_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": "haetae",
        "version": __version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
        "summary": result.counts(),
        "skipped": result.skipped,
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }, indent=2, ensure_ascii=False)


def render_markdown(result: ScanResult) -> str:
    out = [f"# haetae security report", "",
           f"Scanned **{result.files_scanned}** files in `{result.root}` with haetae {__version__}.", ""]
    counts = result.counts()
    out += ["| Severity | Count |", "|---|---|"] + [f"| {s} | {n} |" for s, n in counts.items()] + [""]
    findings = result.sorted_findings()
    if not findings:
        out.append("✅ No findings.")
    for f in findings:
        out += [f"### {f.severity.label().upper()} · {f.rule}", "",
                f"- **Where:** `{f.location()}`",
                f"- **What:** {f.message}",
                f"- **Why it matters:** {f.why}",
                f"- **Fix:** {f.fix}", ""]
    if result.skipped:
        out += ["## Skipped", ""] + [f"- {n}" for n in result.skipped]
    return "\n".join(out)


# ---------------------------------------------------------------- HTML
# One self-contained file: no external fonts, scripts or images, so the report
# works offline and opening it never phones home. Every value is HTML-escaped,
# because file paths and messages come from the scanned repo and can't be trusted.

_HTML_STYLE = """
:root{--bg:#06080d;--panel:#0d1322;--panel2:#131b30;--ink:#efe9dc;--muted:#8d93a5;--line:rgba(255,255,255,.08);
--gold:#d4a84b;--red:#c62a3a;--crit:#ff4d5e;--high:#ff8a4c;--med:#e8c25a;--low:#6fb7ff;--info:#8d93a5;
--mono:ui-monospace,"Cascadia Code","JetBrains Mono",Consolas,monospace;--sans:system-ui,-apple-system,"Segoe UI",sans-serif}
@media (prefers-color-scheme:light){:root{--bg:#f3efe6;--panel:#fffdf8;--panel2:#f2ece0;--ink:#0b1020;--muted:#5b6479;
--line:rgba(11,16,32,.12);--gold:#9a7020;--crit:#c0182b;--high:#c2521b;--med:#8a6a00;--low:#1d5fb3}}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font:15px/1.55 var(--sans);padding:32px 16px 64px}
main{max-width:980px;margin:0 auto}
header{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:12px;border-bottom:2px solid var(--gold);padding-bottom:14px}
h1{font-size:1.6rem;letter-spacing:-.01em}h1 span{color:var(--gold);font-weight:900}
.meta{font:12px/1.6 var(--mono);color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:22px 0}
.card{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--c);border-radius:12px;padding:12px 14px;cursor:pointer;text-align:left;color:inherit;font:inherit}
.card b{display:block;font:700 1.7rem var(--mono);color:var(--c)}.card span{font:12px var(--mono);color:var(--muted);text-transform:uppercase}
.card[aria-pressed=false]{opacity:.4}
.verdict{padding:14px 16px;border-radius:12px;background:var(--panel2);border-left:4px solid var(--v);font-weight:600;margin-bottom:22px}
.f{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:12px;padding:14px 16px;margin-bottom:10px}
.f h2{font-size:1rem;display:flex;flex-wrap:wrap;gap:8px;align-items:baseline}
.sev{font:700 11px var(--mono);text-transform:uppercase;color:var(--c);border:1px solid var(--c);border-radius:999px;padding:1px 8px}
.loc{font:13px var(--mono);color:var(--gold);margin-top:4px;word-break:break-all}
.f dl{display:grid;grid-template-columns:70px 1fr;gap:4px 12px;margin-top:10px;font-size:14px}
.f dt{font:12px/1.9 var(--mono);color:var(--muted)}.f dd code{font-family:var(--mono);font-size:13px}
.notes{margin-top:26px;font:13px/1.7 var(--mono);color:var(--muted)}.notes li{list-style:none}.notes li::before{content:"# "}
.crit{--c:var(--crit)}.high{--c:var(--high)}.medium{--c:var(--med)}.low{--c:var(--low)}.info{--c:var(--info)}
footer{margin-top:32px;font:12px var(--mono);color:var(--muted)}
@media (max-width:640px){.cards{grid-template-columns:repeat(3,1fr)}.f dl{grid-template-columns:1fr}}
@media print{body{background:#fff;color:#000}.card,.f,.verdict{break-inside:avoid}}
"""

_HTML_SCRIPT = """
document.querySelectorAll('.card').forEach(c=>c.addEventListener('click',()=>{
  const on=c.getAttribute('aria-pressed')!=='true';c.setAttribute('aria-pressed',on);
  document.querySelectorAll('.f[data-sev="'+c.dataset.sev+'"]').forEach(f=>f.hidden=!on);
}));
"""

_SEV_CLASS = {Severity.CRITICAL: "crit", Severity.HIGH: "high", Severity.MEDIUM: "medium",
              Severity.LOW: "low", Severity.INFO: "info"}


def render_html(result: ScanResult) -> str:
    e = html.escape
    counts = result.counts()
    worst = result.worst()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    cards = "".join(
        f'<button class="card {_SEV_CLASS[Severity.parse(sev)]}" data-sev="{sev}" aria-pressed="true" '
        f'title="Show or hide {sev} findings"><b>{n}</b><span>{sev}</span></button>'
        for sev, n in counts.items()
    )
    if worst is None:
        verdict = ('<div class="verdict" style="--v:#3fcf6e">✓ No findings in the checks that ran. '
                   'See the notes below for anything that was skipped.</div>')
    else:
        total = len(result.findings)
        verdict = (f'<div class="verdict" style="--v:var(--{"crit" if worst >= Severity.HIGH else "med"})">'
                   f'{total} finding{"s" if total != 1 else ""}; the most serious is '
                   f'<strong>{e(worst.label())}</strong>. Start at the top.</div>')

    items = []
    for f in result.sorted_findings():
        cls = _SEV_CLASS[f.severity]
        introduced = f.extra.get("introduced_in")
        rows = [("what", e(f.message))]
        if introduced:
            rows.append(("history", f"introduced in commit <code>{e(introduced[:7])}</code>"))
        rows += [("why", e(f.why)), ("fix", e(f.fix))]
        dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
        items.append(
            f'<article class="f {cls}" data-sev="{f.severity.label()}">'
            f'<h2><span class="sev">{f.severity.label()}</span>{e(f.check)} · {e(f.rule)}</h2>'
            f'<p class="loc">{e(f.location())}</p><dl>{dl}</dl></article>'
        )

    notes = "".join(f"<li>{e(n)}</li>" for n in result.skipped)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>haetae report · {e(os.path.basename(result.root) or result.root)}</title>
<style>{_HTML_STYLE}</style>
</head>
<body>
<main>
<header>
  <div><h1><span>haetae</span> security report</h1>
  <p class="meta">{e(result.root)}</p></div>
  <p class="meta">{result.files_scanned} files scanned · {stamp} · haetae {e(__version__)}</p>
</header>
<section class="cards" aria-label="Findings by severity (click to filter)">{cards}</section>
{verdict}
<section aria-label="Findings">{"".join(items)}</section>
<ul class="notes">{notes}</ul>
<footer>Secrets are redacted in this report. Generated by haetae (해태).</footer>
</main>
<script>{_HTML_SCRIPT}</script>
</body>
</html>
"""


# ---------------------------------------------------------------- SARIF
# SARIF 2.1.0, the format GitHub code scanning reads: findings appear in the
# Security tab and as annotations on pull requests.

_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
                Severity.LOW: "note", Severity.INFO: "note"}
# GitHub maps this number to its own critical / high / medium / low labels.
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                      Severity.LOW: "2.0", Severity.INFO: "0.0"}


def _rule_id(check: str, rule: str) -> str:
    slug = "".join(c if c.isalnum() else "-" for c in rule.lower()).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return f"{check}/{slug}"


def render_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    worst: dict[str, Severity] = {}
    results = []
    for f in result.sorted_findings():
        rid = _rule_id(f.check, f.rule)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.rule,
                "shortDescription": {"text": f.rule},
                "fullDescription": {"text": f.why},
                "help": {"text": f.fix, "markdown": f"**Why it matters:** {f.why}\n\n**Fix:** {f.fix}"},
                "properties": {"tags": ["security", f.check]},
            }
        worst[rid] = max(worst.get(rid, f.severity), f.severity)
        region = {"startLine": f.line} if f.line else {"startLine": 1}
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.message}. Fix: {f.fix}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                "region": region,
            }}],
            "partialFingerprints": {"haetae/v1": f.id()},
            "properties": {"severity": f.severity.label(),
                           **({"commit": f.commit} if f.commit else {})},
        })
    for rid, sev in worst.items():
        rules[rid]["properties"]["security-severity"] = _SECURITY_SEVERITY[sev]
        rules[rid]["defaultConfiguration"] = {"level": _SARIF_LEVEL[sev]}

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "haetae",
                "version": __version__,
                "informationUri": "https://github.com/jankykohh-boop/haetae-scanner",
                "rules": list(rules.values()),
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": [{"level": "note", "message": {"text": n}} for n in result.skipped],
            }],
        }],
    }, indent=2, ensure_ascii=False)
