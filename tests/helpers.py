"""Builds throwaway repositories for tests.

Fake credentials are assembled from pieces at runtime so this repo never
contains a string that looks like a real secret (and haetae can scan itself cleanly).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

FAKE_AWS_KEY = "AK" + "IA" + "QWERTYUIOPASDFGH"
FAKE_GITHUB_TOKEN = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
FAKE_PASSWORD = "Hunter" + "2-" + "correct-horse-battery"
PRIVATE_KEY_HEADER = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"


class TempRepo:
    def __init__(self, git_init: bool = True):
        self.root = Path(tempfile.mkdtemp(prefix="haetae-test-"))
        self.is_git = git_init
        if git_init:
            self.git("init", "-q")
            # every test repo has a security policy, so C6 stays quiet unless a test removes it
            self.write("SECURITY.md", "Report issues to security@example.com\n")

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-c", "user.name=test", "-c", "user.email=test@example.com",
             "-c", "commit.gpgsign=false", "-C", str(self.root), *args],
            capture_output=True, text=True, check=True,
        ).stdout

    def write(self, rel: str, text: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def delete(self, rel: str) -> None:
        (self.root / rel).unlink()

    def commit(self, message: str = "commit") -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
