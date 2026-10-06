"""Runs every check against a repository and collects the results."""

from __future__ import annotations

import re
from pathlib import Path

from .checks import code, deps, envfiles, hygiene, secrets
from .files import git_ignored, iter_text_files, load_ignore_patterns
from .models import ScanResult


def scan(root: str | Path, *, history: bool = False, exclude: list[str] | None = None,
         offline: bool = False, osv_client=None, include_ignored: bool = False) -> ScanResult:
    root = Path(root).resolve()
    result = ScanResult(root=str(root))
    patterns = load_ignore_patterns(root, exclude)
    ignored = None if include_ignored else git_ignored(root)
    stats: dict = {}
    files = list(iter_text_files(root, patterns, ignored, stats))
    result.files_scanned = len(files)
    # Say what was left out, so a clean report is never mistaken for a full one.
    if stats.get("ignored"):
        result.skipped.append(f"{stats['ignored']} git-ignored path(s) not scanned: not committed, "
                              "so nothing in them has leaked through the repo (--include-ignored to scan them)")
    if stats.get("nested"):
        result.skipped.append(f"{stats['nested']} nested repositor(ies) or worktree(s) skipped: "
                              "scan each one on its own")

    # C1 — secrets in the working tree, then (optionally) in history
    found = secrets.scan_files(files)
    result.findings += found
    if history:
        extra, note = secrets.scan_history(root, found)
        result.findings += extra
        if note:
            result.skipped.append(note)
    else:
        result.skipped.append("C1 history: not scanned (run with --history to check past commits)")

    # C3 — committed .env / key files and .gitignore gaps
    env_findings, note = envfiles.check(root)
    result.findings += env_findings
    if note:
        result.skipped.append(note)

    # C2 — known-vulnerable dependencies (osv.dev)
    dep_findings, notes = deps.check(files, offline=offline, client=osv_client)
    result.findings += dep_findings
    result.skipped += notes

    # C4 code patterns + C5 insecure defaults (one pass over the source), C6 hygiene
    result.findings += code.check(files)
    result.findings += hygiene.check(root, files)

    # A local .env that git ignores is the right setup; say so, so nobody wonders why it was not scanned.
    if ignored and any(re.search(r"(^|/)\.env(\.[^/]+)?$", p) and not p.endswith((".example", ".sample")) for p in ignored):
        result.skipped.append("local .env file(s) present but git-ignored, not committed: good (not scanned)")
    return result
