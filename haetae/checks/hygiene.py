"""C6 — repository hygiene: the basics that make security problems get found and fixed."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding, Severity

CHECK = "C6"
SCANNERS = ("dependabot", "renovate", "haetae", "osv-scanner", "npm audit", "pip-audit",
            "snyk", "trivy", "safety check", "dependency-review", "grype")


def check(root: Path, files: list[tuple[str, Path]]) -> list[Finding]:
    names = {rel for rel, _ in files}
    findings: list[Finding] = []

    if not any(p in names for p in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")):
        findings.append(Finding(
            check=CHECK, rule="No security policy", severity=Severity.LOW, path="SECURITY.md", line=None,
            message="the repository has no SECURITY.md",
            why="Without one, someone who finds a vulnerability doesn't know how to tell you privately, "
                "so it may end up in a public issue instead.",
            fix="Add SECURITY.md saying how to report a vulnerability (an email address is enough) "
                "and how fast you'll respond.",
        ))

    # lockfiles: only meaningful where there is a manifest
    for rel in sorted(names):
        d, _, name = rel.rpartition("/")
        prefix = f"{d}/" if d else ""
        if name == "package.json" and not any(
            f"{prefix}{lock}" in names for lock in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
        ):
            findings.append(Finding(
                check=CHECK, rule="No lockfile", severity=Severity.LOW, path=rel, line=None,
                message=f"{rel} has no lockfile next to it",
                why="Without a lockfile every install can pull different versions, so a compromised or vulnerable "
                    "release can slip in unnoticed, and C2 can't check what you actually run.",
                fix="Run `npm install` and commit package-lock.json (or your package manager's lockfile).",
            ))

    has_deps = any(rel.rpartition("/")[2] in ("package.json", "requirements.txt", "pyproject.toml", "Pipfile")
                   for rel in names)
    if has_deps:
        dependabot = any(p in names for p in (".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json"))
        workflows = [p for rel, p in files if rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml"))]
        in_ci = any(any(s in p.read_text(encoding="utf-8", errors="replace").lower() for s in SCANNERS)
                    for p in workflows)
        if not (dependabot or in_ci):
            findings.append(Finding(
                check=CHECK, rule="No dependency scanning in CI", severity=Severity.LOW,
                path=".github/workflows", line=None,
                message="nothing checks dependencies for new vulnerabilities automatically",
                why="New advisories land against code that hasn't changed; without a scheduled check you only "
                    "find out when someone runs a scan by hand.",
                fix="Enable Dependabot (.github/dependabot.yml) or run haetae in CI on a weekly schedule.",
            ))
    return findings
