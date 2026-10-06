"""C3 — committed .env / key files and .gitignore gaps."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from ..files import git, is_git_repo
from ..models import Finding, Severity

CHECK = "C3"

ENV_FILE = re.compile(r"(^|/)\.env(\.[^/]+)?$")
ENV_TEMPLATE = re.compile(r"\.(example|sample|template|dist|defaults)$")
KEY_FILE_GLOBS = ["*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519", "id_ecdsa", "*.keystore", "*.jks"]
# Patterns that would cover a plain ".env" if present in .gitignore.
ENV_IGNORE_PATTERNS = {".env", ".env*", "*.env", ".env.*", "/.env", "**/.env", ".env.local"}


def _is_env(rel: str) -> bool:
    return bool(ENV_FILE.search(rel)) and not ENV_TEMPLATE.search(rel)


def _is_key_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, g) for g in KEY_FILE_GLOBS)


def _gitignore_covers_env(root: Path) -> bool:
    gi = root / ".gitignore"
    if not gi.is_file():
        return False
    lines = {l.strip() for l in gi.read_text(encoding="utf-8", errors="replace").splitlines()}
    return bool(lines & ENV_IGNORE_PATTERNS)


def check(root: Path) -> tuple[list[Finding], str | None]:
    findings: list[Finding] = []
    if not is_git_repo(root):
        return findings, "C3: skipped (not a git repository, so tracked files can't be checked)"

    tracked = (git(root, "ls-files") or "").splitlines()
    for rel in tracked:
        if _is_env(rel):
            findings.append(Finding(
                check=CHECK, rule="Committed .env file", severity=Severity.HIGH, path=rel, line=None,
                message=f"{rel} is tracked by git",
                why=".env files usually hold real credentials, and once committed they live in history for good.",
                fix=f"Run `git rm --cached {rel}`, add it to .gitignore, rotate any secrets it held, "
                    "and commit a .env.example with placeholder values instead.",
            ))
        elif _is_key_file(rel):
            findings.append(Finding(
                check=CHECK, rule="Committed key file", severity=Severity.HIGH, path=rel, line=None,
                message=f"{rel} looks like a private key or certificate store",
                why="Private keys in a repository can be copied by anyone with read access.",
                fix=f"Run `git rm --cached {rel}`, add the pattern to .gitignore and replace the key.",
            ))

    if not _gitignore_covers_env(root):
        findings.append(Finding(
            check=CHECK, rule=".gitignore missing .env", severity=Severity.MEDIUM, path=".gitignore", line=None,
            message=".gitignore does not ignore .env files" if (root / ".gitignore").is_file()
                    else "repository has no .gitignore",
            why="Without an ignore rule, the next `git add .` can commit local secrets.",
            fix="Add a line `.env*` to .gitignore, followed by `!.env.example` if you keep a template.",
        ))
    return findings, None
