"""v0.2.1: what the first real-repo run reported that it should not have.

Every one of 27 findings on a real app was a false alarm. These pin the fixes,
and pin what must NOT be relaxed: a recognised provider key is reported at full
severity wherever it is, including test files.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from haetae.cli import main
from haetae.models import Severity
from haetae.scanner import scan

from .helpers import FAKE_AWS_KEY, FAKE_PASSWORD, TempRepo


def run_cli(*args: str) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


class NoiseTestCase(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()

    def tearDown(self):
        self.repo.cleanup()

    def findings(self, result, rule=None):
        return [f for f in result.findings if rule is None or f.rule == rule]


class TestIgnoredFiles(NoiseTestCase):
    def test_git_ignored_files_are_not_scanned_and_the_report_says_so(self):
        self.repo.write(".gitignore", "local/\n.env\n")
        self.repo.write("local/notes.js", "const k = '" + FAKE_AWS_KEY + "';\n")
        self.repo.write(".env", "DB_PASSWORD='" + FAKE_PASSWORD + "'\n")
        self.repo.write("app.js", "console.log('ok');\n")
        self.repo.commit()
        result = scan(self.repo.root, offline=True)
        self.assertEqual(self.findings(result), [], [f.location() for f in result.findings])
        self.assertTrue(any("git-ignored" in s for s in result.skipped), result.skipped)

    def test_include_ignored_scans_them(self):
        self.repo.write(".gitignore", "local/\n")
        self.repo.write("local/notes.js", "const k = '" + FAKE_AWS_KEY + "';\n")
        self.repo.commit()
        result = scan(self.repo.root, offline=True, include_ignored=True)
        self.assertEqual(len(self.findings(result, "AWS access key ID")), 1)
        code, _ = run_cli(str(self.repo.root), "--offline", "--include-ignored")
        self.assertEqual(code, 1)

    def test_a_committed_file_is_still_scanned_even_if_ignored_later(self):
        self.repo.write("config.js", "const k = '" + FAKE_AWS_KEY + "';\n")
        self.repo.commit()
        self.repo.write(".gitignore", "config.js\n")   # tracked files are not "ignored"
        result = scan(self.repo.root, offline=True)
        self.assertEqual(len(self.findings(result, "AWS access key ID")), 1)


class TestNestedRepositories(NoiseTestCase):
    def test_a_repository_inside_the_repository_is_skipped(self):
        inner = TempRepo()
        try:
            self.repo.write("README.md", "hello\n")
            self.repo.commit()
            nested = self.repo.root / "vendor-copy"
            nested.mkdir()
            (nested / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")   # how a worktree looks
            (nested / "old.js").write_text("const k = '" + FAKE_AWS_KEY + "';\n", encoding="utf-8")
            result = scan(self.repo.root, offline=True)
            self.assertEqual(self.findings(result, "AWS access key ID"), [])
            self.assertTrue(any("nested" in s for s in result.skipped), result.skipped)
        finally:
            inner.cleanup()


class TestFieldWords(NoiseTestCase):
    def test_labels_and_autocomplete_tokens_are_not_passwords(self):
        self.repo.write("ui.js", "const STR = {\n  accPassword:      'Password',\n};\n")
        self.repo.write("form.html",
                        '<input type="password" autocomplete="${signin ? \'current-password\' : \'new-password\'}">\n')
        self.repo.commit()
        result = scan(self.repo.root, offline=True)
        self.assertEqual(self.findings(result, "Hardcoded secret"), [], [f.location() for f in result.findings])

    def test_mock_and_stub_values_are_not_secrets(self):
        self.repo.write("harness.js", "accessToken = 'mock-token';\nconst apiKey = 'stub-key-123';\n")
        self.repo.commit()
        result = scan(self.repo.root, offline=True)
        self.assertEqual(self.findings(result, "Hardcoded secret"), [], [f.location() for f in result.findings])

    def test_a_real_looking_password_is_still_reported(self):
        self.repo.write("config.yml", 'db_password: "' + FAKE_PASSWORD + '"\n')
        self.repo.commit()
        result = scan(self.repo.root, offline=True)
        hits = self.findings(result, "Hardcoded secret")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, Severity.HIGH)


class TestTestFiles(NoiseTestCase):
    def test_name_based_guesses_in_tests_are_low(self):
        self.repo.write("tests/login.test.js", "const password = '" + FAKE_PASSWORD + "';\n")
        self.repo.write("test_auth.py", 'API_KEY = "' + FAKE_PASSWORD + '"\n')
        self.repo.commit()
        result = scan(self.repo.root, offline=True)
        hits = self.findings(result, "Hardcoded secret")
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(f.severity == Severity.LOW for f in hits), [(f.path, f.severity) for f in hits])
        code, _ = run_cli(str(self.repo.root), "--offline")
        self.assertEqual(code, 0, "low findings must not fail the default --fail-on high")

    def test_a_provider_key_in_a_test_keeps_full_severity(self):
        self.repo.write("tests/upload.test.js", "const key = '" + FAKE_AWS_KEY + "';\n")
        self.repo.commit()
        result = scan(self.repo.root, offline=True)
        hits = self.findings(result, "AWS access key ID")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, Severity.CRITICAL)

    def test_the_downgrade_does_not_leak_the_secret(self):
        self.repo.write("tests/a.test.js", "const password = '" + FAKE_PASSWORD + "';\n")
        self.repo.commit()
        for fmt in ("text", "json", "md", "html"):
            _, out = run_cli(str(self.repo.root), "--offline", "--format", fmt)
            self.assertNotIn(FAKE_PASSWORD, out, f"raw secret in {fmt} output")


if __name__ == "__main__":
    unittest.main()
