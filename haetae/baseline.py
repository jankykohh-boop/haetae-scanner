"""Baselines: accept today's findings once, then fail only on new ones.

The file lists finding ids with enough context (check, rule, path, severity) for a
reviewer to read it in a pull request. It never contains secrets or code: ids are
one-way hashes. Commit it, and treat every addition to it as a security decision.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import ScanResult


def write(result: ScanResult, path: str) -> int:
    entries = sorted(
        ({"id": f.id(), "check": f.check, "rule": f.rule, "path": f.path, "severity": f.severity.label()}
         for f in result.findings),
        key=lambda e: (e["path"], e["check"], e["rule"], e["id"]),
    )
    # a finding can repeat (same secret on two lines of one file): keep one entry per id
    unique = list({e["id"]: e for e in entries}.values())
    doc = {
        "tool": "haetae",
        "version": __version__,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "note": "Accepted findings. haetae hides these and fails only on new ones. "
                "Every entry added here is a decision to live with a known issue; review it like code.",
        "findings": unique,
    }
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(unique)


def load(path: str) -> set[str]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("tool") != "haetae" or not isinstance(doc.get("findings"), list):
        raise ValueError(f"{path} is not a haetae baseline file")
    return {e["id"] for e in doc["findings"] if isinstance(e, dict) and "id" in e}


def apply(result: ScanResult, path: str) -> None:
    """Drop baselined findings from the result and explain what happened in the notes."""
    accepted = load(path)
    kept, hidden, seen = [], 0, set()
    for f in result.findings:
        fid = f.id()
        if fid in accepted:
            hidden += 1
            seen.add(fid)
        else:
            kept.append(f)
    result.findings = kept
    if hidden:
        result.skipped.append(f"{hidden} finding(s) hidden by the baseline {path}: accepted earlier, not re-reported")
    stale = len(accepted - seen)
    if stale:
        result.skipped.append(f"{stale} baseline entr{'y' if stale == 1 else 'ies'} no longer found (fixed?): "
                              f"run --write-baseline {path} to drop them")
