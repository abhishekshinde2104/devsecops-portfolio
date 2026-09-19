#!/usr/bin/env python3
"""Prepare Dependency-Check input and verify it actually analysed it.

Dependency-Check's (experimental) pip analyzer does not understand
pip-compile lockfiles: every ``--hash=`` and ``# via`` line becomes a
"package" and ``pyjwt==2.3.0 \\`` is read as a package *name*, so no version
ever matches the NVD and the scan silently reports zero vulnerabilities.
Found while building this project (the first CI run "passed" with 487
junk dependencies and 0 real matches).

    extract  write plain ``name==version`` pins from the lockfiles
    verify   fail unless the report contains a versioned package for every pin

    python scripts/depcheck_input.py extract requirements.txt requirements-dev.txt -o pins.txt
    python scripts/depcheck_input.py verify pins.txt reports/dependency-check/dependency-check-report.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;\\]+)")


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def extract(lockfiles: list[Path]) -> list[str]:
    pins: set[str] = set()
    for lockfile in lockfiles:
        for line in lockfile.read_text(encoding="utf-8").splitlines():
            if match := _PIN.match(line):
                pins.add(f"{match.group(1)}=={match.group(2)}")
    return sorted(pins, key=str.lower)


def analysed_packages(report: dict) -> set[str]:
    """``name@version`` for every dependency the report resolved to a versioned purl."""
    found: set[str] = set()
    for dep in report.get("dependencies", []) or []:
        for package in dep.get("packages", []) or []:
            purl = unquote(package.get("id") or "")
            if purl.startswith("pkg:pypi/") and "@" in purl:
                name, version = purl.removeprefix("pkg:pypi/").split("@", 1)
                found.add(f"{_normalise(name)}@{version}")
    return found


def verify(pins: list[str], report: dict) -> list[str]:
    """Return the pins Dependency-Check did not analyse (empty list = full coverage)."""
    found = analysed_packages(report)
    missing = []
    for pin in pins:
        name, version = pin.split("==", 1)
        if f"{_normalise(name)}@{version}" not in found:
            missing.append(pin)
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    ex = sub.add_parser("extract")
    ex.add_argument("lockfiles", nargs="+", type=Path)
    ex.add_argument("-o", "--output", type=Path, required=True)
    ve = sub.add_parser("verify")
    ve.add_argument("pins", type=Path)
    ve.add_argument("report", type=Path)
    args = parser.parse_args(argv)

    if args.command == "extract":
        pins = extract(args.lockfiles)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text("\n".join(pins) + "\n", encoding="utf-8")
        print(f"wrote {len(pins)} pins to {args.output}")
        return 0 if pins else 1

    pins = [p for p in args.pins.read_text(encoding="utf-8").splitlines() if p.strip()]
    missing = verify(pins, json.loads(args.report.read_text(encoding="utf-8")))
    if missing:
        print(f"Dependency-Check did not analyse {len(missing)}/{len(pins)} pinned packages:", file=sys.stderr)
        for pin in missing:
            print(f"  {pin}", file=sys.stderr)
        return 1
    print(f"Dependency-Check analysed all {len(pins)} pinned packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
