"""C1 — secrets in files and in git history.

Every match is redacted before it leaves this module; the raw value is only
kept as a hash so history matches can be tied back to working-tree matches.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from ..files import git, read_lines
from ..models import Finding, Severity

CHECK = "C1"


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    severity: Severity
    group: int = 0          # regex group holding the secret itself


def _r(name: str, regex: str, severity: Severity, group: int = 0, flags: int = 0) -> Rule:
    return Rule(name, re.compile(regex, flags), severity, group)


RULES: list[Rule] = [
    _r("Private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", Severity.CRITICAL),
    _r("AWS access key ID", r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])", Severity.CRITICAL),
    _r("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b", Severity.CRITICAL),
    _r("Stripe live key", r"\b[sr]k_live_[0-9A-Za-z]{20,}\b", Severity.CRITICAL),
    _r("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", Severity.CRITICAL),
    _r("OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}|\bsk-proj-[A-Za-z0-9_\-]{40,}", Severity.CRITICAL),
    _r("Slack token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", Severity.HIGH),
    _r("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", Severity.HIGH),
    _r("Database URL with password", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:([^\s@/]{3,})@", Severity.HIGH, group=1),
    _r("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", Severity.MEDIUM),
    _r("Hardcoded secret", r"""(?i)\b[\w\-]*?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']""", Severity.HIGH, group=1),
]

# Values that are obviously not real secrets.
PLACEHOLDER = re.compile(
    r"(?i)example|changeme|change_me|your[_-]|placeholder|dummy|sample|redacted|xxxx|\*\*\*|"
    r"^<.*>$|^\{.*\}$|%\(\w+\)s|^\$[A-Z_]|\$\{|\{\{|process\.env|os\.environ|getenv|^test|^fake|^mock|^stub"
)

# Values that are a form field's own vocabulary, not a secret: HTML autocomplete
# tokens and the words used to label a password box.
FIELD_WORDS = {
    "password", "new-password", "current-password", "one-time-code", "username",
    "passwort", "contraseña", "mot-de-passe",
}

# The generic rules guess from a variable name. In a test file they almost always
# find a fixture, so there they report LOW, not HIGH. Rules that recognise a real
# provider's key format (AWS, GitHub, Stripe, Anthropic…) keep their severity in
# tests: a real key pasted into a test has leaked just the same.
GENERIC_RULES = {"Hardcoded secret", "JSON Web Token"}
TEST_PATH = re.compile(
    r"(?i)(^|/)(tests?|__tests__|spec|specs|fixtures?|testdata)(/|$)"
    r"|(^|/)[^/]*[._-](test|spec)\.[a-z0-9]+$"
    r"|(^|/)test_[^/]*\.py$|(^|/)[^/]*_test\.(py|go)$"
)


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH.search(path or ""))


WHY = {
    Severity.CRITICAL: "Anyone with read access to this repo, or any copy or fork of it, can use this credential.",
    Severity.HIGH: "A credential in source code is easy to leak and hard to rotate safely.",
    Severity.MEDIUM: "Tokens in source code can expose sessions or user data if still valid.",
}
FIX = (
    "Revoke and rotate the credential now (deleting it from the code is not enough), "
    "then load it from an environment variable or a secrets manager."
)


def redact(value: str) -> str:
    value = value.strip()
    shown = value[:4] if len(value) > 8 else value[:1]
    return f"{shown}…({len(value)} chars)"


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def scan_line(line: str):
    """Yield (rule, secret) for each secret on a single line."""
    for rule in RULES:
        for m in rule.pattern.finditer(line):
            secret = m.group(rule.group)
            if rule.group and PLACEHOLDER.search(secret):
                continue
            if rule.group and _is_label(m, rule, secret):
                continue
            yield rule, secret


def _is_label(m: re.Match, rule: Rule, secret: str) -> bool:
    """True when the "secret" is a field's label or autocomplete token, not a value.

    `accPassword: 'Password'` (a UI string) and `autocomplete="new-password"` were
    reported as hardcoded passwords. The value repeating the variable's own name,
    or being a form-field word, is the tell.
    """
    value = secret.strip().lower()
    if value in FIELD_WORDS:
        return True
    key = m.string[m.start(0):m.start(rule.group)].lower()
    return len(value) >= 4 and value in key


def _finding(rule: Rule, secret: str, path: str, line: int | None, commit: str | None = None) -> Finding:
    msg = f"{rule.name}: {redact(secret)}"
    severity, why = rule.severity, WHY.get(rule.severity, WHY[Severity.HIGH])
    if rule.name in GENERIC_RULES and is_test_path(path):
        severity = Severity.LOW
        msg += " (in a test file; probably a fixture)"
        why = ("Usually a made-up value for a test. Check it is not a real credential; "
               "if it is, it has leaked like any other.")
    if commit:
        msg += " — removed from the code but still in git history"
    return Finding(
        check=CHECK, rule=rule.name, severity=severity, path=path, line=line,
        message=msg, why=why, fix=FIX, commit=commit,
        extra={"fingerprint": fingerprint(secret)},
    )


SUPPRESS = "haetae: ignore"   # a line carrying this comment is skipped by every check


def scan_files(files: list[tuple[str, Path]]) -> list[Finding]:
    findings = []
    for rel, path in files:
        for no, line in enumerate(read_lines(path), start=1):
            if SUPPRESS in line:
                continue
            for rule, secret in scan_line(line):
                findings.append(_finding(rule, secret, rel, no))
    return findings


def scan_history(root: Path, current: list[Finding]) -> tuple[list[Finding], str | None]:
    """Walk every commit oldest-first and report the commit where each secret first appeared.

    Secrets still in the working tree get their existing finding annotated with that commit;
    secrets that only survive in history get a new finding.
    Returns (new_findings, skipped_note).
    """
    log = git(root, "log", "--all", "--reverse", "-p", "-U0", "--no-color", "--format=commit %H")
    if log is None:
        return [], "C1 history: skipped (not a git repository, or git is not installed)"

    by_print = {f.extra["fingerprint"]: f for f in current}
    seen: set[str] = set()
    new: list[Finding] = []
    commit, path = None, None
    for line in log.splitlines():
        if line.startswith("commit "):
            commit = line[7:].strip()
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("+") and path and commit and SUPPRESS not in line:
            for rule, secret in scan_line(line[1:]):
                fp = fingerprint(secret)
                if fp in seen:
                    continue
                seen.add(fp)
                if fp in by_print:
                    by_print[fp].extra["introduced_in"] = commit
                else:
                    new.append(_finding(rule, secret, path, None, commit=commit))
    return new, None
