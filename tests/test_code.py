"""C4 code patterns, C5 insecure defaults and C6 repo hygiene."""

from __future__ import annotations

import unittest

from haetae.models import Severity
from haetae.scanner import scan

from .helpers import TempRepo

# Each snippet must trigger exactly the named rule.
VULNERABLE = {
    "app.js": [
        ("eval(req.query.expr);", "eval()"),
        ("const f = new Function('a', body);", "new Function()"),
        ("exec(`git log ${branch}`, cb);", "Shell command built from variables"),
        ("execSync('convert ' + file + ' out.png');", "Shell command built from variables"),
        ("db.query(`SELECT * FROM users WHERE id = ${id}`);", "SQL built from strings"),
        ("pool.query('DELETE FROM t WHERE id = ' + id);", "SQL built from strings"),
        ("app.use(cors());", "CORS open to any origin"),
        ("res.setHeader('Access-Control-Allow-Origin', '*');", "CORS open to any origin"),
        ("https.get(url, { rejectUnauthorized: false });", "TLS verification disabled"),
        ("const adminPassword = 'admin';", "Weak default password"),
    ],
    "server.py": [
        ("result = eval(user_input)", "eval()/exec()"),
        ("os.system(f'ping {host}')", "Shell command built from variables"),
        ("subprocess.run(cmd, shell=True)", "subprocess with shell=True"),
        ("cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")", "SQL built from strings"),
        ("cur.execute(\"SELECT * FROM t WHERE id = %s\" % uid)", "SQL built from strings"),
        ("obj = pickle.loads(blob)", "Unsafe deserialization"),
        ("cfg = yaml.load(text)", "yaml.load without SafeLoader"),
        ("DEBUG = True", "Debug mode on"),
        ("app.run(host='0.0.0.0', debug=True)", "Debug mode on"),
        ("CORS(app)", "CORS open to any origin"),
        ("requests.get(url, verify=False)", "TLS verification disabled"),
        ("DB_PASSWORD = 'password'", "Weak default password"),
    ],
}

SAFE = {
    "safe.js": [
        "const data = JSON.parse(body);",
        "execFile('git', ['log', branch], cb);",
        "db.query('SELECT * FROM users WHERE id = $1', [id]);",
        "app.use(cors({ origin: ['https://app.example.com'] }));",
        "// eval(x) is mentioned in a comment",
        "const evaluation = evaluate(x);",
        "element.retrieval(x)",
        "throw new Error('never call eval(input) here');",
        "const help = `avoid new Function(src) in handlers`;",
    ],
    "safe.py": [
        "value = ast.literal_eval(text)",
        "subprocess.run(['ping', host])",
        "cur.execute('SELECT * FROM t WHERE id = %s', (uid,))",
        "cfg = yaml.safe_load(text)",
        "cfg = yaml.load(text, Loader=yaml.SafeLoader)",
        "DEBUG = os.getenv('DEBUG') == '1'",
        "# DEBUG = True",
        "requests.get(url, timeout=5)",
        "re.compile(pattern).exec_module",
    ],
}


class CodeRepo(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()
        self.repo.write(".gitignore", ".env*\n")

    def tearDown(self):
        self.repo.cleanup()

    def found(self, result, checks=("C4", "C5")):
        return [f for f in result.findings if f.check in checks]


class TestCodePatterns(CodeRepo):
    def test_each_vulnerable_pattern_is_caught(self):
        for path, cases in VULNERABLE.items():
            self.repo.write(path, "\n".join(line for line, _ in cases) + "\n")
        result = scan(self.repo.root, offline=True)
        by_loc = {(f.path, f.line): f.rule for f in self.found(result)}
        for path, cases in VULNERABLE.items():
            for no, (line, rule) in enumerate(cases, start=1):
                self.assertEqual(by_loc.get((path, no)), rule, f"{path}:{no} `{line}`")
        self.assertEqual(len(by_loc), sum(len(c) for c in VULNERABLE.values()))

    def test_safe_code_is_quiet(self):
        for path, lines in SAFE.items():
            self.repo.write(path, "\n".join(lines) + "\n")
        found = self.found(scan(self.repo.root, offline=True))
        self.assertEqual(found, [], [f"{f.location()} {f.rule}" for f in found])

    def test_parameterised_sql_with_dynamic_columns_is_medium(self):
        self.repo.write("db.js",
            "await pool.query(`UPDATE firms SET ${updates.join(',')} WHERE id=$${i}`, values);\n"
            "await pool.query('UPDATE users SET ' + fields.join(',') + ' WHERE id=$' + i, values);\n")
        found = self.found(scan(self.repo.root, offline=True))
        self.assertEqual([(f.rule, f.severity) for f in found],
                         [("SQL with dynamic column names", Severity.MEDIUM)] * 2)

    def test_password_label_is_not_a_password(self):
        self.repo.write("ui.js", "const t = { accPassword: 'Password', pwdLabel: 'pass' };\n")
        self.assertEqual(self.found(scan(self.repo.root, offline=True)), [])

    def test_suppression_comment(self):
        self.repo.write("a.js", "eval(trusted); // haetae: ignore (reviewed 2026-10-06)\neval(other);\n")
        found = self.found(scan(self.repo.root, offline=True))
        self.assertEqual([f.line for f in found], [2])

    def test_test_files_rank_lower(self):
        self.repo.write("tests/fixture_test.py", "subprocess.run(cmd, shell=True)\nDB_PASSWORD = 'password'\n")
        found = {f.rule: f.severity for f in self.found(scan(self.repo.root, offline=True))}
        self.assertEqual(found["subprocess with shell=True"], Severity.LOW)
        self.assertEqual(found["Weak default password"], Severity.LOW)

    def test_minified_lines_are_skipped(self):
        self.repo.write("vendor.min.js", "var a=1;" * 400 + "eval(x);\n")
        self.assertEqual(self.found(scan(self.repo.root, offline=True)), [])

    def test_other_languages_are_ignored(self):
        self.repo.write("notes.md", "Never call eval(input) or use DEBUG = True.\n")
        self.assertEqual(self.found(scan(self.repo.root, offline=True)), [])


class TestHygiene(CodeRepo):
    def test_missing_security_policy(self):
        self.repo.delete("SECURITY.md")
        rules = {f.rule for f in self.found(scan(self.repo.root, offline=True), ("C6",))}
        self.assertIn("No security policy", rules)

    def test_package_json_without_lockfile_and_no_ci_scanning(self):
        self.repo.write("package.json", '{"dependencies": {}}')
        rules = {f.rule for f in self.found(scan(self.repo.root, offline=True), ("C6",))}
        self.assertEqual(rules, {"No lockfile", "No dependency scanning in CI"})

    def test_lockfile_and_ci_scanner_satisfy_hygiene(self):
        self.repo.write("package.json", '{"dependencies": {}}')
        self.repo.write("package-lock.json", '{"lockfileVersion": 3, "packages": {}}')
        self.repo.write(".github/workflows/security.yml", "jobs:\n  scan:\n    steps:\n      - run: haetae . --history\n")
        self.assertEqual(self.found(scan(self.repo.root, offline=True), ("C6",)), [])

    def test_hygiene_is_low_and_never_fails_ci_by_default(self):
        self.repo.delete("SECURITY.md")
        self.repo.write("package.json", '{"dependencies": {}}')
        found = self.found(scan(self.repo.root, offline=True), ("C6",))
        self.assertTrue(found)
        self.assertTrue(all(f.severity == Severity.LOW for f in found))


class TestLocalEnvNote(CodeRepo):
    def test_ignored_local_env_gets_a_reassuring_note(self):
        self.repo.write(".env", "X=1\n")
        self.repo.commit()
        result = scan(self.repo.root, offline=True)
        self.assertTrue(any("local .env" in n for n in result.skipped), result.skipped)


if __name__ == "__main__":
    unittest.main()
