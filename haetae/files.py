"""Walking a repository: which files to read, and which to leave alone."""

from __future__ import annotations

import fnmatch
import os
import subprocess
from pathlib import Path

# Directories that are never worth scanning: VCS internals, installed deps, build output.
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__",
    "dist", "build", ".next", ".tox", ".mypy_cache", ".pytest_cache",
}
MAX_BYTES = 2 * 1024 * 1024
IGNORE_FILE = ".haetaeignore"


def load_ignore_patterns(root: Path, extra: list[str] | None = None) -> list[str]:
    patterns = list(extra or [])
    ignore = root / IGNORE_FILE
    if ignore.is_file():
        for raw in ignore.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def is_excluded(rel: str, patterns: list[str]) -> bool:
    for pat in patterns:
        pat = pat.rstrip("/")
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*"):
            return True
        # a bare name ("fixtures") matches that file or directory anywhere
        if "/" not in pat and any(fnmatch.fnmatch(part, pat) for part in rel.split("/")):
            return True
    return False


def git_ignored(root: Path) -> set[str] | None:
    """Paths git ignores (files, and directories with a trailing "/"), or None if not a repo.

    Ignored files are not committed, so a secret in one has not leaked through the
    repository: a local .env, build output, an editor's scratch folder. Scanning them
    turned a clean repo's report into a wall of false alarms (found on a real repo,
    2026-10-06). --include-ignored scans them anyway.
    """
    out = git(root, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z")
    if out is None:
        return None
    return {p for p in out.split("\0") if p}


def looks_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(8192)
    except OSError:
        return True


def iter_text_files(root: Path, patterns: list[str], ignored: set[str] | None = None,
                    stats: dict | None = None):
    """Yield (relative_posix_path, absolute_path) for every scannable text file.

    ignored: paths from git_ignored(), skipped. stats, if given, counts what was
    skipped and why ("ignored", "nested") so the report can say so.
    """
    ignored = ignored or set()
    stats = stats if stats is not None else {}
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            rel_d = (base / d).relative_to(root).as_posix()
            if d in SKIP_DIRS or is_excluded(rel_d, patterns):
                continue
            if rel_d + "/" in ignored:
                stats["ignored"] = stats.get("ignored", 0) + 1
                continue
            # Another repository or a git worktree checked out inside this one: it
            # has its own history and its own report. Scanning it here mixed an old
            # copy of the code into this repo's findings.
            if (base / d / ".git").exists():
                stats["nested"] = stats.get("nested", 0) + 1
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            path = base / name
            rel = path.relative_to(root).as_posix()
            if is_excluded(rel, patterns):
                continue
            if rel in ignored:
                stats["ignored"] = stats.get("ignored", 0) + 1
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            if looks_binary(path):
                continue
            yield rel, path


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def git(root: Path, *args: str) -> str | None:
    """Run a git command in root; None if git is missing or this isn't a repo."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
        )
    except FileNotFoundError:
        return None
    return proc.stdout if proc.returncode == 0 else None


def is_git_repo(root: Path) -> bool:
    out = git(root, "rev-parse", "--is-inside-work-tree")
    return out is not None and out.strip() == "true"
