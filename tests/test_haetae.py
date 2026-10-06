"""Acceptance tests for M1, mirroring SPEC.md section 7."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

from haetae.checks.secrets import redact
from haetae.cli import main
from haetae.models import Severity
from haetae.scanner import scan

from .helpers import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, FAKE_PASSWORD, PRIVATE_KEY_HEADER, TempRepo


def run_cli(*args: str) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


class RepoTestCase(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()
        self.repo.write(".gitignore", ".env*\n!.env.example\n")

    def tearDown(self):
        self.repo.cleanup()

    def rules(self, result):
        return {f.rule for f in result.findings}


class TestSecrets(RepoTestCase):
    def test_leaked_secret_is_caught_and_redacted(self):
        self.repo.write("config.js", "const a = 1;\nconst key = '" + FAKE_AWS_KEY + "';\n")
        self.repo.commit()
        result = scan(self.repo.root)
        hits = [f for f in result.findings if f.rule == "AWS access key ID"]
        self.assertEqual(len(hits), 1)
        self.assertEqual((hits[0].path, hits[0].line, hits[0].severity), ("config.js", 2, Severity.CRITICAL))

        for fmt in ("text", "json", "md"):
            _, out = run_cli(str(self.repo.root), "--format", fmt)
            self.assertNotIn(FAKE_AWS_KEY, out, f"raw secret leaked in {fmt} output")
            self.assertIn(redact(FAKE_AWS_KEY), out)

    def test_common_token_types(self):
        self.repo.write("a.py", f'TOKEN = "{FAKE_GITHUB_TOKEN}"\n')
        self.repo.write("b.yml", f'db_password: "{FAKE_PASSWORD}"\n')
        self.repo.write("deploy.txt", PRIVATE_KEY_HEADER + "\nMIIE...\n")
        self.repo.write("c.env.example", "DATABASE_URL=postgres://app:" + "s3cretpass" + "@db:5432/app\n")
        result = scan(self.repo.root)
        self.assertLessEqual(
            {"GitHub token", "Hardcoded secret", "Private key", "Database URL with password"}, self.rules(result)
        )

    def test_placeholders_are_ignored(self):
        self.repo.write("settings.py", 'API_KEY = "your-api-key-here"\npassword = "${DB_PASSWORD}"\n'
                                       'secret = process.env.SECRET\n'
                                       'db_password: "{DB_PASSWORD}"\n'
                                       "pwd = '%(password)s'\n"
                                       'auth_token = "$AUTH_TOKEN"\n')
        result = scan(self.repo.root)
        self.assertNotIn("Hardcoded secret", self.rules(result))

    def test_secret_removed_from_code_is_found_in_history(self):
        self.repo.write("config.js", f"const key = '{FAKE_AWS_KEY}';\n")
        self.repo.commit("add key")
        introduced = self.repo.git("rev-parse", "HEAD").strip()
        self.repo.write("config.js", "const key = process.env.AWS_KEY;\n")
        self.repo.commit("remove key")

        self.assertNotIn("AWS access key ID", self.rules(scan(self.repo.root)))

        result = scan(self.repo.root, history=True)
        hits = [f for f in result.findings if f.rule == "AWS access key ID"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].commit, introduced)
        self.assertEqual(hits[0].path, "config.js")

    def test_secret_still_present_is_annotated_not_duplicated(self):
        self.repo.write("config.js", f"const key = '{FAKE_AWS_KEY}';\n")
        self.repo.commit()
        result = scan(self.repo.root, history=True)
        hits = [f for f in result.findings if f.rule == "AWS access key ID"]
        self.assertEqual(len(hits), 1)
        self.assertIn("introduced_in", hits[0].extra)

    def test_exclude_and_ignore_file(self):
        self.repo.write("fixtures/keys.js", f"k = '{FAKE_AWS_KEY}'\n")
        self.assertIn("AWS access key ID", self.rules(scan(self.repo.root)))
        self.assertNotIn("AWS access key ID", self.rules(scan(self.repo.root, exclude=["fixtures"])))
        self.repo.write(".haetaeignore", "# test data\nfixtures/\n")
        self.assertNotIn("AWS access key ID", self.rules(scan(self.repo.root)))


class TestEnvFiles(RepoTestCase):
    def test_committed_env_file(self):
        self.repo.write(".gitignore", "node_modules\n")
        self.repo.write(".env", "DEBUG=true\n")
        self.repo.write(".env.example", "API_KEY=\n")
        self.repo.commit()
        result = scan(self.repo.root)
        env = [f for f in result.findings if f.rule == "Committed .env file"]
        self.assertEqual([f.path for f in env], [".env"])
        self.assertIn(".gitignore missing .env", self.rules(result))

    def test_committed_key_file(self):
        self.repo.write("certs/server.pem", "not really a cert\n")
        self.repo.commit()
        self.assertIn("Committed key file", self.rules(scan(self.repo.root)))

    def test_gitignore_present_and_correct(self):
        self.repo.commit()
        self.assertEqual(scan(self.repo.root).findings, [])

    def test_not_a_git_repo_is_reported_as_skipped(self):
        plain = TempRepo(git_init=False)
        try:
            result = scan(plain.root, history=True)
            self.assertTrue(any(n.startswith("C3: skipped") for n in result.skipped))
            self.assertTrue(any(n.startswith("C1 history: skipped") for n in result.skipped))
        finally:
            plain.cleanup()


class TestCli(RepoTestCase):
    def test_clean_repo_exits_zero(self):
        self.repo.write("app.py", "print('hello')\n")
        self.repo.commit()
        code, out = run_cli(str(self.repo.root))
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)

    def test_fail_on_threshold(self):
        self.repo.write(".gitignore", "build/\n")   # only a MEDIUM finding
        self.repo.commit()
        self.assertEqual(run_cli(str(self.repo.root), "--fail-on", "high")[0], 0)
        self.assertEqual(run_cli(str(self.repo.root), "--fail-on", "medium")[0], 1)

    def test_bad_severity_is_an_error(self):
        self.assertEqual(run_cli(str(self.repo.root), "--fail-on", "urgent")[0], 2)

    def test_html_report_is_redacted_and_escaped(self):
        # a hostile file name must not be able to inject markup into the report
        hostile = "<img src=x onerror=alert(1)>.js"
        try:
            self.repo.write(hostile, f"k = '{FAKE_AWS_KEY}'\n")
        except OSError:  # Windows forbids < > in file names
            hostile = "evil&quot;onload.js"
            self.repo.write(hostile, f"k = '{FAKE_AWS_KEY}'\n")
        self.repo.commit()
        out_file = self.repo.root.parent / (self.repo.root.name + "-report.html")
        try:
            code, _ = run_cli(str(self.repo.root), "--format", "html", "--output", str(out_file))
            page = out_file.read_text(encoding="utf-8")
        finally:
            out_file.unlink(missing_ok=True)
        self.assertEqual(code, 1)
        self.assertTrue(page.startswith("<!DOCTYPE html>"))
        self.assertNotIn(FAKE_AWS_KEY, page)
        self.assertIn("AKIA…(20 chars)", page)
        self.assertNotIn(hostile, page)          # only the escaped form may appear
        self.assertNotIn("<img src=x", page)
        for external in ('src="http', "src='http", 'href="http', "url(http", "@import"):
            self.assertNotIn(external, page)        # self-contained: nothing loaded from the network

    def test_output_file_for_text(self):
        out_file = self.repo.root.parent / (self.repo.root.name + "-report.txt")
        try:
            run_cli(str(self.repo.root), "--output", str(out_file))
            text = out_file.read_text(encoding="utf-8")
        finally:
            out_file.unlink(missing_ok=True)
        self.assertNotIn("\033[", text)   # no colour codes in files
        self.assertIn("Summary:", text)

    def test_json_is_ranked(self):
        self.repo.write(".gitignore", "build/\n")
        self.repo.write("config.js", f"k = '{FAKE_AWS_KEY}'\n")
        self.repo.commit()
        _, out = run_cli(str(self.repo.root), "--format", "json")
        data = json.loads(out)
        sev = [f["severity"] for f in data["findings"]]
        self.assertEqual(sev, sorted(sev, key=lambda s: -Severity.parse(s)))
        self.assertEqual(sev[0], "critical")


if __name__ == "__main__":
    unittest.main()
