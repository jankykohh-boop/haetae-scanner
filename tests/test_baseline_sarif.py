"""--baseline / --write-baseline, and SARIF output."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from haetae.cli import main

from .helpers import FAKE_AWS_KEY, TempRepo


def run_cli(*args: str) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()
        self.repo.write(".gitignore", ".env*\n")
        self.base = str(self.repo.root / "haetae-baseline.json")

    def tearDown(self):
        self.repo.cleanup()

    def scan_json(self, *extra):
        code, out = run_cli(str(self.repo.root), "--offline", "--format", "json", *extra)
        return code, json.loads(out)


class TestBaseline(Base):
    def test_accept_then_fail_only_on_new(self):
        self.repo.write("app.js", "eval(input);\n")
        self.repo.commit()
        self.assertEqual(run_cli(str(self.repo.root), "--offline")[0], 1)

        code, _ = run_cli(str(self.repo.root), "--offline", "--write-baseline", self.base)
        self.assertEqual(code, 0)
        code, data = self.scan_json("--baseline", self.base)
        self.assertEqual((code, data["findings"]), (0, []))
        self.assertTrue(any("hidden by the baseline" in n for n in data["skipped"]))

        self.repo.write("other.js", "new Function(src);\n")
        code, data = self.scan_json("--baseline", self.base)
        self.assertEqual(code, 1)
        self.assertEqual([f["path"] for f in data["findings"]], ["other.js"])

    def test_ids_survive_line_moves(self):
        self.repo.write("app.js", "eval(input);\n")
        run_cli(str(self.repo.root), "--offline", "--write-baseline", self.base)
        self.repo.write("app.js", "// header\nconst a = 1;\n\neval(input);\n")
        code, data = self.scan_json("--baseline", self.base)
        self.assertEqual((code, data["findings"]), (0, []))

    def test_fixed_findings_are_reported_stale(self):
        self.repo.write("app.js", "eval(input);\n")
        run_cli(str(self.repo.root), "--offline", "--write-baseline", self.base)
        self.repo.write("app.js", "JSON.parse(input);\n")
        _, data = self.scan_json("--baseline", self.base)
        self.assertTrue(any("no longer found" in n for n in data["skipped"]))

    def test_baseline_file_never_contains_the_secret(self):
        self.repo.write("config.js", f"const k = '{FAKE_AWS_KEY}';\n")
        run_cli(str(self.repo.root), "--offline", "--write-baseline", self.base)
        text = open(self.base, encoding="utf-8").read()
        self.assertNotIn(FAKE_AWS_KEY, text)
        self.assertNotIn(FAKE_AWS_KEY[:12], text)
        self.assertIn("AWS access key ID", text)

    def test_bad_baseline_is_an_error(self):
        with open(self.base, "w", encoding="utf-8") as fh:
            fh.write('{"not": "a baseline"}')
        self.assertEqual(run_cli(str(self.repo.root), "--offline", "--baseline", self.base)[0], 2)


class TestSarif(Base):
    def test_sarif_shape_and_redaction(self):
        self.repo.write("config.js", f"const k = '{FAKE_AWS_KEY}';\n")
        self.repo.write("app.js", "eval(input);\n")
        code, out = run_cli(str(self.repo.root), "--offline", "--format", "sarif")
        self.assertEqual(code, 1)
        self.assertNotIn(FAKE_AWS_KEY, out)
        doc = json.loads(out)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertIn("C1/aws-access-key-id", rule_ids)
        self.assertIn("C4/eval", rule_ids)
        for res in run["results"]:
            self.assertIn(res["ruleId"], rule_ids)
            loc = res["locations"][0]["physicalLocation"]
            self.assertGreaterEqual(loc["region"]["startLine"], 1)
            self.assertTrue(res["partialFingerprints"]["haetae/v1"])
        aws = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "C1/aws-access-key-id")
        self.assertEqual(aws["properties"]["security-severity"], "9.5")
        levels = {r["ruleId"]: r["level"] for r in run["results"]}
        self.assertEqual(levels["C1/aws-access-key-id"], "error")

    def test_clean_repo_is_valid_empty_sarif(self):
        self.repo.write("app.js", "console.log('ok');\n")
        code, out = run_cli(str(self.repo.root), "--offline", "--format", "sarif")
        doc = json.loads(out)
        self.assertEqual((code, doc["runs"][0]["results"]), (0, []))


if __name__ == "__main__":
    unittest.main()
