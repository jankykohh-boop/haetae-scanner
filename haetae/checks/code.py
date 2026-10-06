"""C4 — dangerous code patterns, and C5 — insecure defaults.

Line-based rules for JavaScript/TypeScript (including inline scripts in HTML)
and Python. They look for the *shape* of a risky call, so they are hints for a
reviewer, not proof of a vulnerability; every finding says what to check.

Noise controls: comment lines are skipped, test files report one level lower,
and a line containing `haetae: ignore` is silenced on purpose.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from ..files import read_lines
from ..models import Finding, Severity
from .secrets import SUPPRESS, is_test_path

JS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue", ".svelte"}
PY = {".py"}
COMMENT = re.compile(r"^\s*(//|#|\*|/\*|<!--)")
SQL = r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b"


@dataclass(frozen=True)
class LineRule:
    check: str
    name: str
    langs: frozenset
    pattern: re.Pattern
    severity: Severity
    why: str
    fix: str


def _rule(check, name, langs, regex, severity, why, fix, flags=0) -> LineRule:
    return LineRule(check, name, frozenset(langs), re.compile(regex, flags), severity, why, fix)


RULES: list[LineRule] = [
    # ---------------------------------------------------------------- C4
    _rule("C4", "eval()", JS, r"(?<![\w.$])eval\s*\(", Severity.HIGH,
          "eval runs any string as code; if any part of it comes from a user, they can run code in your app.",
          "Replace it: JSON.parse for data, a lookup table for dynamic behaviour."),
    _rule("C4", "new Function()", JS, r"\bnew\s+Function\s*\(", Severity.HIGH,
          "new Function compiles a string into code, with the same risk as eval.",
          "Replace it with a normal function or a lookup table."),
    _rule("C4", "eval()/exec()", PY, r"(?<![\w.])(?:eval|exec)\s*\(", Severity.HIGH,
          "eval/exec run any string as Python; user-controlled input means remote code execution.",
          "Use ast.literal_eval for data, or explicit code paths instead of generated code."),
    _rule("C4", "Shell command built from variables", JS,
          r"\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)", Severity.HIGH,
          "A shell command assembled from variables lets crafted input run extra commands (command injection).",
          "Use execFile/spawn with an argument array and no shell, and validate every argument."),
    _rule("C4", "Shell command built from variables", PY,
          r"\bos\.(?:system|popen)\s*\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\+|\.format))", Severity.HIGH,
          "A shell command assembled from variables lets crafted input run extra commands (command injection).",
          "Use subprocess.run([...]) with an argument list and shell=False."),
    _rule("C4", "subprocess with shell=True", PY, r"\bsubprocess\.\w+\s*\(.*\bshell\s*=\s*True", Severity.MEDIUM,
          "shell=True hands the whole string to a shell, so any variable in it can inject commands.",
          "Pass an argument list and drop shell=True."),
    _rule("C4", "SQL built from strings", JS,
          r"\b(?:query|execute|raw|run|all|get|prepare)\s*\(\s*(?:`\s*" + SQL + r"[^`]*\$\{|['\"]\s*" + SQL + r"[^'\"]*['\"]\s*\+)",
          Severity.HIGH,
          "SQL assembled from variables is the classic SQL injection: input can read or change any data.",
          "Use parameterised queries ($1 / ? placeholders with a values array).", re.IGNORECASE),
    _rule("C4", "SQL built from strings", PY,
          r"\.(?:execute|executemany|raw)\s*\(\s*(?:f['\"]\s*" + SQL + r"|['\"]\s*" + SQL + r"[^'\"]*['\"]\s*(?:%|\+|\.format))",
          Severity.HIGH,
          "SQL assembled from variables is the classic SQL injection: input can read or change any data.",
          "Pass parameters separately: cursor.execute(\"... WHERE id = %s\", (id,)).", re.IGNORECASE),
    _rule("C4", "Unsafe deserialization", PY, r"\b(?:pickle|cPickle|marshal)\.loads?\s*\(", Severity.MEDIUM,
          "Unpickling data from an untrusted source can execute arbitrary code.",
          "Use JSON for data from outside; only unpickle data you created and stored yourself."),
    _rule("C4", "yaml.load without SafeLoader", PY, r"\byaml\.load\s*\((?!.*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)", Severity.MEDIUM,
          "yaml.load with the default loader can construct arbitrary Python objects from a document.",
          "Use yaml.safe_load(...)."),

    # ---------------------------------------------------------------- C5
    _rule("C5", "Debug mode on", PY, r"^\s*DEBUG\s*=\s*True\b|\.run\s*\(.*\bdebug\s*=\s*True", Severity.MEDIUM,
          "Debug mode shows stack traces, settings and sometimes an interactive console to anyone who triggers an error.",
          "Read it from the environment and default to off: DEBUG = os.getenv('DEBUG') == '1'."),
    _rule("C5", "CORS open to any origin", JS,
          r"\bcors\s*\(\s*\)|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]|\borigin\s*:\s*(?:['\"]\*['\"]|true)\b",
          Severity.MEDIUM,
          "Any website can call this API from a visitor's browser; with credentials allowed, it can act as them.",
          "List the exact origins you trust: cors({ origin: ['https://app.example.com'] })."),
    _rule("C5", "CORS open to any origin", PY,
          r"\bCORS\s*\(\s*app\s*\)|CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True|allow_origins\s*=\s*\[\s*['\"]\*['\"]",
          Severity.MEDIUM,
          "Any website can call this API from a visitor's browser; with credentials allowed, it can act as them.",
          "List the exact origins you trust instead of allowing all."),
    _rule("C5", "TLS verification disabled", PY, r"\bverify\s*=\s*False\b", Severity.MEDIUM,
          "Without certificate checks, anyone on the network path can read and alter the traffic.",
          "Remove verify=False; if you use a private CA, pass its bundle: verify='/path/to/ca.pem'."),
    _rule("C5", "TLS verification disabled", JS,
          r"\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*\]?\s*=\s*['\"]?0", Severity.MEDIUM,
          "Without certificate checks, anyone on the network path can read and alter the traffic.",
          "Remove it; for a private CA, pass the CA certificate via the `ca` option."),
    _rule("C5", "Weak default password", JS | PY,
          r"""(?i)\b[\w\-]*(?:password|passwd|pwd|pass)\b["']?\s*[:=]\s*["'](password|passw0rd|admin|root|toor|123456|12345678|qwerty|letmein|secret|default|changeme|pass|test123)["']""",
          Severity.HIGH,
          "A well-known default password is the first thing attackers try, and it often survives into production.",
          "Require the password from the environment and refuse to start without one."),
]


def _lang(rel: str) -> frozenset:
    ext = Path(rel).suffix.lower()
    return frozenset(JS) if ext in JS else frozenset(PY) if ext in PY else frozenset()


def check(files: list[tuple[str, Path]]) -> list[Finding]:
    findings: list[Finding] = []
    for rel, path in files:
        lang = _lang(rel)
        if not lang:
            continue
        rules = [r for r in RULES if r.langs & lang]
        in_test = is_test_path(rel)
        for no, line in enumerate(read_lines(path), start=1):
            if SUPPRESS in line or COMMENT.match(line) or len(line) > 2000:   # long lines: minified code
                continue
            for rule in rules:
                m = rule.pattern.search(line)
                if not m:
                    continue
                if rule.name not in MATCHES_STRINGS and _in_string(line, m.start()):
                    continue   # text that mentions the call, e.g. an error message or a rule definition
                name, severity, why, fix = rule.name, rule.severity, rule.why, rule.fix
                if rule.name == "Weak default password" and _is_label(m):
                    continue
                if rule.name == "SQL built from strings" and PARAMETERISED.search(line):
                    name, severity, why, fix = DYNAMIC_IDENTIFIERS
                if in_test:
                    # no user input reaches a test harness: a hint, never a CI failure
                    severity = Severity.LOW
                    why += " (In a test file, so ranked low.)"
                findings.append(Finding(
                    check=rule.check, rule=name, severity=severity, path=rel, line=no,
                    message=f"{name}: `{line.strip()[:120]}`",
                    why=why, fix=fix + f" If this line is safe and reviewed, add a `{SUPPRESS}` comment to it.",
                    extra={"content": hashlib.sha256(line.strip().encode()).hexdigest()[:16]},
                ))
    return findings


# Values are already bound as parameters ($1, $${i}, ?): only identifiers such as
# column names are spliced in. Safe when those come from an allowlist, so this is a
# review prompt, not an injection alarm (seen on a real codebase, 2026-10-06).
# Python's %s counts only when the values follow as a separate argument
# ("... %s", (uid,)); "... %s" % uid is string formatting, i.e. the injection itself.
PARAMETERISED = re.compile(r"\$\d|\$\$\{|\$'\s*\+|=\s*\?|%s['\"]\s*,")
DYNAMIC_IDENTIFIERS = (
    "SQL with dynamic column names", Severity.MEDIUM,
    "The values are parameterised, but column or table names are spliced into the SQL; "
    "if any of those names can come from a request, it's injection.",
    "Check that every spliced name comes from a fixed allowlist in code, never from request fields.",
)


# Rules whose pattern is itself about a string's contents; every other rule matches a
# call or assignment, so a hit inside a string literal is only text that mentions it.
MATCHES_STRINGS = {"Weak default password", "CORS open to any origin"}


def _in_string(line: str, pos: int) -> bool:
    """True if line[pos] sits inside a '...', "..." or `...` literal on this line."""
    quote, i = None, 0
    while i < pos:
        ch = line[i]
        if ch == "\\":
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        i += 1
    return quote is not None


UI_KEY = re.compile(r"(?i)label|placeholder|text|title|hint|caption|message|msg|tooltip")


def _is_label(m: re.Match) -> bool:
    """A UI string, not a credential.

    `accPassword: 'Password'` is display text: capitalised like a label and repeating
    the key's own name. `pwdLabel: 'pass'` says so in its key. Real weak defaults are
    lowercase, like a database password set to the literal word itself, and stay flagged.
    """
    value = m.group(1)
    key = m.string[m.start(0):m.start(1)]
    if UI_KEY.search(key):
        return True
    return value[:1].isupper() and value[1:].islower() and value.lower() in key.lower()
