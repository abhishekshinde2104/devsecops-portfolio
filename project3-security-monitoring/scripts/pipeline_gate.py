#!/usr/bin/env python3
"""CI gate for the security monitoring pipeline (stdlib only).

Reads reports/pipeline-checks.tsv (written by verify_pipeline.py) and fails
unless every expected check ran and passed. Fails closed: a missing file, a
missing expected check, or any failing row blocks the build, so a crashed
verification run cannot look green.

    python scripts/pipeline_gate.py reports/pipeline-checks.tsv [--falco]
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

REQUIRED = ["C01", "C02", "C03", "C04", "C05", "C06", "C07"]


def evaluate(path: Path, require_falco: bool) -> list[str]:
    required = list(REQUIRED) + (["C08"] if require_falco else [])
    try:
        with path.open(encoding="utf-8", newline="") as fh:
            rows = {r["id"]: r for r in csv.DictReader(fh, delimiter="\t")}
    except OSError as exc:
        return [f"cannot read {path}: {exc}"]

    problems = []
    for cid in required:
        row = rows.get(cid)
        if row is None:
            problems.append(f"{cid}: expected check did not run")
        elif row["passed"] != "true":
            problems.append(f"{cid} {row.get('check', '')}: FAILED ({row.get('evidence', '')})")
    return problems


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("report", type=Path)
    p.add_argument("--falco", action="store_true")
    args = p.parse_args(argv)

    problems = evaluate(args.report, args.falco)
    if problems:
        print("P3 pipeline gate: FAILED")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("P3 pipeline gate: PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
