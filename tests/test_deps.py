"""C2 dependency check, with OSV replaced by an in-memory fake (no network in tests)."""

from __future__ import annotations

import json
import unittest
import urllib.error

from haetae.checks.deps import cvss3_score, vuln_severity
from haetae.models import Severity
from haetae.scanner import scan

from .helpers import TempRepo


class FakeOSV:
    """Advisories keyed by (ecosystem, name, version)."""

    def __init__(self, vulns: dict[tuple, list[dict]] | None = None, fail: bool = False):
        self.vulns = vulns or {}
        self.fail = fail
        self.queried: list[tuple] = []

    def query(self, packages):
        if self.fail:
            raise urllib.error.URLError("no network")
        self.queried = [p.key() for p in packages]
        return [[v["id"] for v in self.vulns.get(p.key(), [])] for p in packages]

    def details(self, ids):
        docs = {v["id"]: v for vs in self.vulns.values() for v in vs}
        return {i: docs[i] for i in ids}


def advisory(vid, eco, name, fixed, severity=None, cvss=None):
    doc = {"id": vid, "affected": [{"package": {"ecosystem": eco, "name": name},
                                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}
    if severity:
        doc["database_specific"] = {"severity": severity}
    if cvss:
        doc["severity"] = [{"type": "CVSS_V3", "score": cvss}]
    return doc


PACKAGE_LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"express": "^4.17.0"}, "devDependencies": {"mocha": "^10.0.0"}},
        "node_modules/express": {"version": "4.17.1"},
        "node_modules/qs": {"version": "6.7.0"},
        "node_modules/mocha": {"version": "10.0.0", "dev": True},
    },
}


class TestDeps(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()
        self.repo.write(".gitignore", ".env*\n")

    def tearDown(self):
        self.repo.cleanup()

    def dep_findings(self, result):
        return [f for f in result.findings if f.check == "C2"]

    def test_vulnerable_dependency_is_ranked_with_fix(self):
        self.repo.write("package-lock.json", json.dumps(PACKAGE_LOCK))
        self.repo.write("requirements.txt", "django==3.2.0\nrequests>=2.0\n")
        osv = FakeOSV({
            ("npm", "qs", "6.7.0"): [dict(advisory("GHSA-qs-1", "npm", "qs", "6.7.3", severity="HIGH"),
                                          aliases=["CVE-2022-24999"])],
            ("npm", "mocha", "10.0.0"): [advisory("GHSA-mo-1", "npm", "mocha", "10.1.0", severity="HIGH")],
            ("PyPI", "django", "3.2.0"): [
                advisory("PYSEC-dj-1", "PyPI", "Django", "3.2.4", severity="MODERATE"),
                advisory("PYSEC-dj-2", "PyPI", "Django", "3.2.19",
                         cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            ],
        })
        found = {f.extra["package"]: f for f in self.dep_findings(scan(self.repo.root, osv_client=osv))}

        self.assertEqual(found["django"].severity, Severity.CRITICAL)    # worst advisory wins (CVSS 9.8)
        self.assertIn("3.2.19", found["django"].fix)                     # highest fixed version
        self.assertIn("2 known vulnerabilities", found["django"].message)
        self.assertEqual(found["qs"].severity, Severity.HIGH)
        self.assertIn("transitive", found["qs"].message)
        self.assertIn("CVE-2022-24999 (GHSA-qs-1)", found["qs"].message)   # CVE first, advisory as source
        self.assertEqual(found["qs"].extra["cves"], ["CVE-2022-24999"])
        self.assertEqual(found["mocha"].severity, Severity.MEDIUM)       # dev-only: one step lower
        self.assertNotIn("express", found)
        self.assertTrue(any("not pinned" in n for n in scan(self.repo.root, osv_client=FakeOSV()).skipped))

    def test_offline_skips_and_says_so(self):
        self.repo.write("requirements.txt", "flask==2.0.0\n")
        result = scan(self.repo.root, offline=True)
        self.assertEqual(self.dep_findings(result), [])
        self.assertTrue(any("--offline" in n for n in result.skipped))

    def test_network_failure_is_reported_not_hidden(self):
        self.repo.write("requirements.txt", "flask==2.0.0\n")
        result = scan(self.repo.root, osv_client=FakeOSV(fail=True))
        self.assertTrue(any("NOT checked" in n for n in result.skipped))

    def test_package_json_without_lockfile(self):
        self.repo.write("package.json", json.dumps({"dependencies": {"lodash": "4.17.15", "react": "^18.0.0"}}))
        osv = FakeOSV()
        result = scan(self.repo.root, osv_client=osv)
        self.assertEqual(osv.queried, [("npm", "lodash", "4.17.15")])   # exact pins only
        self.assertTrue(any("version ranges" in n for n in result.skipped))

    def test_lockfile_takes_precedence_over_package_json(self):
        self.repo.write("package.json", json.dumps({"dependencies": {"express": "^4.17.0"}}))
        self.repo.write("package-lock.json", json.dumps(PACKAGE_LOCK))
        result = scan(self.repo.root, osv_client=FakeOSV())
        self.assertFalse(any("version ranges" in n for n in result.skipped))

    def test_broken_manifest_is_reported(self):
        self.repo.write("package-lock.json", "{ not json")
        result = scan(self.repo.root, osv_client=FakeOSV())
        self.assertTrue(any("could not read package-lock.json" in n for n in result.skipped))


class TestFixAdvice(unittest.TestCase):
    def test_prefers_patch_on_same_line_over_major_jump(self):
        from haetae.checks.deps import Package, fixed_version
        doc = {"affected": [{"package": {"ecosystem": "PyPI", "name": "Django"}, "ranges": [{"events": [
            {"introduced": "3.2"}, {"fixed": "3.2.19"}, {"introduced": "4.0"}, {"fixed": "4.1.9"},
            {"introduced": "5.0"}, {"fixed": "6.1.1"}]}]}]}
        pkg = Package("PyPI", "django", "3.2.0", "requirements.txt")
        self.assertEqual(fixed_version(doc, pkg), "3.2.19")


class TestSeverity(unittest.TestCase):
    def test_cvss3_reference_scores(self):
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(cvss3_score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5)
        self.assertIsNone(cvss3_score("not a vector"))

    def test_unknown_severity_defaults_to_medium(self):
        self.assertEqual(vuln_severity({"id": "X"}), Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()
