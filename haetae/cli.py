"""Command-line entry point: `haetae [path] [options]`."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .models import Severity
from . import baseline
from .report import render_html, render_json, render_markdown, render_sarif, render_text
from .scanner import scan

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="haetae",
        description="haetae (해태) — a security checklist for your repository.",
    )
    p.add_argument("path", nargs="?", default=".", help="repository to scan (default: current directory)")
    p.add_argument("--history", action="store_true", help="also scan every commit in git history for secrets")
    p.add_argument("--format", choices=["text", "json", "md", "html", "sarif"], default="text",
                   help="output format: text, json, md, html (a standalone report page) or sarif (GitHub code scanning) (default: text)")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of the terminal")
    p.add_argument("--fail-on", default="high", metavar="SEVERITY",
                   help="exit 1 if any finding is at or above this severity: critical, high, medium, low, info (default: high)")
    p.add_argument("--offline", action="store_true",
                   help="don't contact osv.dev; skips the dependency vulnerability check")
    p.add_argument("--include-ignored", action="store_true",
                   help="also scan files git ignores (a local .env, build output); skipped by default")
    p.add_argument("--baseline", metavar="FILE",
                   help="hide findings already accepted in FILE; fail only on new ones")
    p.add_argument("--write-baseline", metavar="FILE",
                   help="accept every current finding: write them to FILE and exit 0")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching this glob; repeatable (also read from .haetaeignore)")
    p.add_argument("--version", action="version", version=f"haetae {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):  # Windows pipes default to a legacy code page
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        threshold = Severity.parse(args.fail_on)
    except ValueError as e:
        print(f"haetae: {e}", file=sys.stderr)
        return EXIT_ERROR

    try:
        result = scan(args.path, history=args.history, exclude=args.exclude, offline=args.offline,
                      include_ignored=args.include_ignored)
    except OSError as e:
        print(f"haetae: cannot scan {args.path}: {e}", file=sys.stderr)
        return EXIT_ERROR

    if args.write_baseline:
        try:
            n = baseline.write(result, args.write_baseline)
        except OSError as e:
            print(f"haetae: cannot write {args.write_baseline}: {e}", file=sys.stderr)
            return EXIT_ERROR
        print(f"haetae: wrote {n} accepted finding(s) to {args.write_baseline}; "
              f"commit it and run with --baseline {args.write_baseline}", file=sys.stderr)
        return EXIT_CLEAN
    if args.baseline:
        try:
            baseline.apply(result, args.baseline)
        except (OSError, ValueError) as e:
            print(f"haetae: cannot use baseline {args.baseline}: {e}", file=sys.stderr)
            return EXIT_ERROR

    if args.format == "json":
        output = render_json(result)
    elif args.format == "sarif":
        output = render_sarif(result)
    elif args.format == "html":
        output = render_html(result)
    elif args.format == "md":
        output = render_markdown(result)
    else:
        output = render_text(result, None if args.output else sys.stdout)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(output + "\n")
        except OSError as e:
            print(f"haetae: cannot write {args.output}: {e}", file=sys.stderr)
            return EXIT_ERROR
        print(f"haetae: report written to {args.output}", file=sys.stderr)
    else:
        _write(output)

    worst = result.worst()
    return EXIT_FINDINGS if worst is not None and worst >= threshold else EXIT_CLEAN


def _write(text: str) -> None:
    try:
        sys.stdout.write(text + "\n")
    except UnicodeEncodeError:  # e.g. a Windows console without UTF-8
        sys.stdout.buffer.write((text + "\n").encode("utf-8", errors="replace"))


if __name__ == "__main__":
    sys.exit(main())
