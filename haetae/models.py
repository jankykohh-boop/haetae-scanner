"""Core data types shared by every check and report format."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so that a higher value means more serious."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.upper()]
        except KeyError:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity '{name}' (choose from: {choices})") from None

    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    check: str          # check id, e.g. "C1"
    rule: str           # short rule name, e.g. "AWS access key"
    severity: Severity
    path: str           # repo-relative path, POSIX separators
    line: int | None    # 1-based line number, None when not line-specific
    message: str        # what was found, safe to print (never a raw secret)
    why: str            # why it matters
    fix: str            # what to do about it
    commit: str | None = None   # where it was introduced, for history findings
    extra: dict = field(default_factory=dict)

    def location(self) -> str:
        loc = self.path
        if self.line is not None:
            loc += f":{self.line}"
        if self.commit:
            loc += f" (commit {self.commit[:7]})"
        return loc

    def id(self) -> str:
        """Stable identity for baselines and SARIF.

        Built from *what* was found, never the line number, so a finding keeps its id
        when unrelated code above it moves: the secret's hash, the flagged line's
        content, or the package and version.
        """
        what = (self.extra.get("fingerprint") or self.extra.get("content")
                or (f"{self.extra['package']}@{self.extra['version']}" if "package" in self.extra else ""))
        raw = "|".join((self.check, self.rule, self.path, what))
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label()
        data["id"] = self.id()
        return data


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)   # human-readable notes on what didn't run
    files_scanned: int = 0

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, f.path, f.line or 0, f.rule))

    def counts(self) -> dict[str, int]:
        out = {s.label(): 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.label()] += 1
        return out

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)
