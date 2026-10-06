# Changelog

All notable changes to haetae. Versions follow [semantic versioning](https://semver.org).

## 0.4.0 · 2026-10-06
- **Baselines:** `--write-baseline` accepts today's findings; `--baseline` then fails only on new ones. Ids come from what was found, not line numbers, and the file never holds secrets or code.
- **SARIF output** (`--format sarif`) for GitHub code scanning.
- **GitHub Action** (`uses: jankykohh-boop/haetae-scanner@v0.4.0`), run on this repo in CI.
- Dependency findings lead with CVE ids, e.g. `CVE-2022-24999 (GHSA-…)`.

## 0.3.0 · 2026-10-06
- **C4 dangerous code patterns** (JS/TS/HTML, Python): eval, `new Function`, exec, shell commands and SQL built from variables, unsafe deserialization.
- **C5 insecure defaults:** debug mode, CORS open to any origin, TLS verification off, well-known default passwords.
- **C6 repo hygiene** (always low): no `SECURITY.md`, no lockfile, no dependency scanning in CI.
- `haetae: ignore` comment silences a reviewed line for every check.
- Noise fixes from a real codebase: parameterised SQL with dynamic column names is its own medium rule; UI labels aren't passwords; text inside string literals, comments and minified lines is skipped; test files rank low.

## 0.2.1 · 2026-10-06
- Skips git-ignored files and nested repositories or worktrees, and says so (`--include-ignored` to scan them).
- Name-based secret guesses in test files rank low; provider keys keep full severity everywhere.
- Form-field words and `mock`/`stub` values are not reported as secrets.

## 0.2.0 · 2026-10-06
- **C2 dependency vulnerabilities** via osv.dev for npm and Python lockfiles: one finding per package, ranked by the worst advisory, dev-only one step lower, smallest safe upgrade suggested. `--offline` skips it.
- **HTML report** (`--format html`) and `-o/--output`.

## 0.1.0 · 2026-10-06
- **C1 secrets** in files and git history (`--history`), always redacted.
- **C3** committed `.env` and key files, `.gitignore` gaps.
- Text, JSON and Markdown reports; `--fail-on` and exit codes for CI.
