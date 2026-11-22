"""Command-line interface."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .engine import analyze
from .models import CAPABILITIES, SEVERITY_RANK, START_CAPABILITIES, cap_label
from .reporters import render_console, render_html, render_json, render_markdown, render_sarif
from .rules import RULES
from .scanner import scan


def _write(path: str, text: str) -> None:
    if path == "-":
        sys.stdout.write(text)
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _use_color(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")  # turns on ANSI escape handling in the Windows console
    return True


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chainbreaker",
        description="Find attack chains, not just vulnerabilities. Links weaknesses in code, config and "
                    "containers into the paths a real attacker would take, then tells you which fixes break the most.",
    )
    p.add_argument("--version", action="version", version=f"chainbreaker {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="command")

    s = sub.add_parser("scan", help="scan a directory or file")
    s.add_argument("path", nargs="?", default=".", help="directory or file to scan (default: .)")
    s.add_argument("--html", metavar="FILE", help="write the interactive HTML report")
    s.add_argument("--json", metavar="FILE", help="write JSON ('-' for stdout)")
    s.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 for GitHub code scanning")
    s.add_argument("--markdown", metavar="FILE", help="write a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    s.add_argument("--assume", default=",".join(START_CAPABILITIES),
                   help="what the attacker starts with, comma-separated (default: internet,source_read)")
    s.add_argument("--private-repo", action="store_true",
                   help="assume attackers cannot read the source (drops source_read)")
    s.add_argument("--exclude", default="", help="comma-separated directory/file names or paths to skip")
    s.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none",
                   help="exit with code 1 if any chain is at least this severe (default: none)")
    s.add_argument("--all", action="store_true", help="print every chain, not just the top 8")
    s.add_argument("--no-color", action="store_true", help="disable coloured output")
    s.add_argument("-q", "--quiet", action="store_true", help="no console report")

    sub.add_parser("rules", help="list the detection rules")
    sub.add_parser("capabilities", help="list the capabilities the engine reasons about")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "rules":
        for r in RULES:
            print(f"{r.id}  {r.severity:<8}  {r.title}\n        {r.description}")
        return 0
    if args.cmd == "capabilities":
        for key, c in CAPABILITIES.items():
            tag = f"goal, impact {c.impact}" if c.is_goal else ("start" if key in START_CAPABILITIES else "foothold")
            print(f"{key:<18} {c.label}  ({tag})")
        return 0
    if args.cmd != "scan":
        parser.print_help()
        return 0

    assume = [a.strip() for a in args.assume.split(",") if a.strip()]
    unknown = [a for a in assume if a not in CAPABILITIES]
    if unknown:
        parser.error(f"unknown capability in --assume: {', '.join(unknown)} (see 'chainbreaker capabilities')")
    if args.private_repo:
        assume = [a for a in assume if a != "source_read"]

    try:
        result = scan(args.path, exclude=args.exclude.split(","))
    except FileNotFoundError:
        print(f"chainbreaker: no such file or directory: {args.path}", file=sys.stderr)
        return 2

    target = args.path.replace("\\", "/")
    analysis = analyze(result.findings, assume)
    files = result.files_scanned

    if not args.quiet and args.json != "-":
        sys.stdout.write(render_console(analysis, target, files, color=_use_color(args.no_color),
                                        limit=10_000 if args.all else 8))
    if args.json:
        _write(args.json, render_json(analysis, target, files))
    if args.sarif:
        _write(args.sarif, render_sarif(analysis, target, files))
    if args.markdown:
        _write(args.markdown, render_markdown(analysis, target, files))
    if args.html:
        _write(args.html, render_html(analysis, target, files))
        if not args.quiet and args.json != "-":
            print(f"  HTML report written to {args.html}\n")

    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on]
        failing = [c for c in analysis.chains if SEVERITY_RANK[c.severity] >= threshold]
        if failing:
            if not args.quiet:
                print(f"  Failing: {len(failing)} chain(s) at or above '{args.fail_on}' "
                      f"(worst: {cap_label(failing[0].goals[0])}).", file=sys.stderr)
            return 1
    return 0
