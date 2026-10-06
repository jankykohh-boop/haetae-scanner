# Security Policy

## Reporting a vulnerability

Please don't open a public issue for security problems in haetae itself.
Report them privately instead: go to this repository's **Security** tab and click
**Report a vulnerability** ([direct link](https://github.com/jankykohh-boop/haetae-scanner/security/advisories/new)).
Only the maintainer can see your report. You'll get a reply within 7 days.

## What counts

- haetae printing a secret it found without redaction, in any output format
- A crafted repository that makes haetae run code, write files, or hang
- A check that silently reports "clean" when it didn't actually run
