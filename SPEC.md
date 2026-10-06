# haetae (해태) — Product Spec

**Owner:** Joshua Lee
**Status:** v0.5.0 · M1–M6 done
**One-liner:** Point it at a repo; get a ranked list of security problems, with how to fix each one.

---

## 1. Problem

Small teams and solo builders ship code without a security reviewer. The common mistakes (a leaked API key, a vulnerable package, a committed `.env`) are easy to catch but rarely checked, because the tools that catch them are separate, noisy, and each needs its own setup.

## 2. Goal

One command that runs a practical security checklist against any repo and answers three questions:

1. **What's wrong?** Every finding names the file and line.
2. **What matters most?** Findings are ranked by severity, not dumped in file order.
3. **What do I do about it?** Every finding includes a specific fix.

## 3. Users

- **Primary:** a developer or product owner checking their own repo before a release.
- **Secondary:** a CI pipeline that should fail a build when something serious is found.

## 4. Non-goals (v1)

- Not a replacement for a full SAST/DAST product or a penetration test.
- No automatic fixing of code. haetae reports; a human decides.
- No hosted service or dashboard. It's a local command-line tool.
- v1 covered JavaScript/TypeScript and Python; M6 added Shell, Terraform and Java (GitHub's Octoverse 2025 top ten guided the order).

## 5. Checks

| # | Check | Examples of what it catches | Default severity |
|---|---|---|---|
| C1 | **Secrets** in files and git history | API keys, tokens, private keys, passwords in config | Critical |
| C2 | **Dependency vulnerabilities**, ranked by risk | Packages with known CVEs in `package.json` / `requirements.txt`, using the public OSV database | From advisory (Critical–Low) |
| C3 | **Committed `.env` files and `.gitignore` gaps** | `.env` tracked by git; `.gitignore` missing `.env`, keys or build output | High |
| C4 | **Dangerous code patterns** | `eval`, shell commands built from input, SQL built by string concatenation | High |
| C5 | **Insecure defaults** | Debug mode on, CORS open to `*`, hardcoded admin credentials | Medium |
| C6 | **Repo hygiene** | No `SECURITY.md`, no lockfile, no dependency scanning in CI | Low |

## 6. Output

- **Terminal report** (default): findings grouped by severity, each with file:line, what it is, why it matters, and the fix.
- **JSON** (`--format json`): for CI and other tools.
- **Markdown** (`--format md`): a report you can attach to a ticket or pull request.
- **HTML** (`--format html`): a standalone report page with clickable severity filters; self-contained (no network requests) and HTML-escaped, since paths and messages come from the scanned repo.
- **`-o FILE`**: write any format to a file instead of the terminal.
- **Exit code:** `0` if nothing at or above the threshold, `1` if there are findings, `2` on errors. Threshold set with `--fail-on high` (default: `high`).

## 7. Acceptance criteria

```gherkin
Feature: Scan a repository

  Scenario: Leaked secret is caught and redacted
    Given a repo with an API key committed in config.js
    When I run haetae on the repo
    Then the report lists a Critical finding at config.js with its line number
    And the key itself is shown redacted, never in full

  Scenario: Secret removed from code but still in history
    Given a key that was committed and later deleted
    When I run haetae with --history
    Then the report lists the commit where the key was introduced

  Scenario: Vulnerable dependency is ranked
    Given package.json pins a package version with a known Critical CVE
    When I run haetae
    Then the finding shows the package, version, CVE ID and the first fixed version
    And it appears above all lower-severity findings

  Scenario: Clean repo passes
    Given a repo with no findings at or above the threshold
    When I run haetae
    Then it prints a clean summary and exits with code 0

  Scenario: CI fails on serious findings
    Given a repo with one High finding
    When I run haetae --fail-on high
    Then it exits with code 1

  Scenario: Works offline
    Given no network connection
    When I run haetae
    Then all checks except dependency lookups still run
    And the report says dependency vulnerabilities were skipped
```

## 8. Quality bar

- **No false sense of safety:** if a check is skipped (offline, unsupported file type), the report says so.
- **Never leaks what it finds:** secrets are always redacted in every output format.
- **Low noise:** test fixtures and example files can be excluded with `--exclude` or a `.haetaeignore` file.
- **Fast:** a typical small repo scans in under 10 seconds, excluding network lookups.
- **No third-party dependencies:** Python standard library only, so it's easy to audit and install.
- **Tested:** every check has tests against deliberately vulnerable repos, built fresh by each test (see decision 6).

## 9. Milestones

| Milestone | Scope | Definition of done |
|---|---|---|
| **M1** | CLI skeleton, report format, C1 secrets, C3 `.env`/`.gitignore` | Runs on a real repo; tests pass; README with usage |
| **M2** | C2 dependency vulnerabilities via OSV | Offline mode works; findings ranked |
| **M3** | C4 code patterns, C5 insecure defaults | False-positive rate checked on 3 real repos |
| **M4** | C6 hygiene, JSON + Markdown output, `--fail-on`, CI example | Runs in a GitHub Actions workflow on its own repo |
| **M5** | Adoption: `--baseline`/`--write-baseline`, SARIF output, a GitHub Action (`action.yml`), CVE ids on dependency findings | CI runs the action on this repo and validates its SARIF; baselines keep ids stable across line moves |
| **M6** | More languages: Shell and Dockerfiles, Terraform, Java and Spring config; Maven/Gradle dependencies; a note naming languages C4/C5 don't cover | Zero false alarms on four real public repos (spring-petclinic, terraform-aws-vpc, terraform-aws-security-group, nvm) after tuning |

## 10. Decisions

1. haetae scans **its own repo in CI** from day one.
2. **Name:** haetae (해태), the mythical guardian that protects Seoul from disaster. Package name `haetae-scan` (`haetae` is taken on PyPI); the command is `haetae`.
3. **License:** MIT.
4. **Noise from the first real repo (v0.2.1, 2026-10-06).** On a 326-file app every one of 27 findings was a false alarm: a stale git worktree inside the repo, an ignored local `.env`, test fixtures, and password-field labels. haetae now skips git-ignored files and nested repositories (and says so in the report), reports name-based guesses in test files as low, and ignores form-field vocabulary. Provider-format keys are never downgraded.
5. **Code-pattern noise (v0.3.0, 2026-10-06).** First run of C4/C5 on the same app: 5 "SQL built from strings" were parameterised queries with dynamic column names (now their own medium rule, with an allowlist check as the fix), a `'Password'` UI label read as a weak password, and test harnesses using `new Function` were ranked medium. After the fixes: 0 high, 8 medium, 17 low, all accurate. Rules also skip matches inside string literals, so haetae's own rule definitions don't flag themselves.
6. **Test repos are built at runtime, not committed (2026-10-06).** A checked-in vulnerable sample repo would put secret-shaped strings into this repository, tripping GitHub secret scanning and haetae's own self-scan. Each test instead assembles a throwaway git repo, with fake credentials put together from pieces at runtime, so this repo stays clean and the self-scan in CI stays meaningful.
7. **Language noise (v0.5.0, 2026-10-06).** Run on four well-known public repos, the new rules raised three false alarms, all in Terraform: outbound rules inside an `egress_rules` map and an `aws_vpc_security_group_egress_rule` looked like open ingress, and a `Deny` on every action looked like an over-broad grant. Ingress is now judged by direction and port (80/443 are normal; SSH, RDP and database ports are high), and Deny statements are skipped. After the fixes the only code finding across all four repos is a true positive (spring-petclinic exposes every Actuator endpoint).
