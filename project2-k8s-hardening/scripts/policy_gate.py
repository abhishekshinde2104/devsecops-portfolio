#!/usr/bin/env python3
"""Fail CI unless the hardened deployment meets hardening-policy.toml.

    python scripts/policy_gate.py reports/hardened/summary.json [--policy hardening-policy.toml]

Missing inputs fail the gate (fail closed): a scanner that did not run cannot
count as passing.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

P2_DIR = Path(__file__).resolve().parents[1]


def evaluate(summary: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    problems: list[str] = []

    def need(section: str) -> dict[str, Any] | None:
        value = summary.get(section)
        if not value:
            problems.append(f"{section}: no results (scanner did not run?)")
        return value

    if (verify := need("verify")) and policy["runtime"]["require_all_secure"]:
        for check in verify["checks"]:
            if check["secure"] != "true":
                problems.append(f"runtime {check['id']} {check['check']}: {check['evidence']}")

    if kb := need("kube_bench"):
        allowed = set(policy["kube_bench"]["allowed_failures"])
        unexpected = [c for c in kb["failed_checks"] if c.split()[0] not in allowed]
        if len(unexpected) > policy["kube_bench"]["max_fail"]:
            problems += [f"kube-bench FAIL {c}" for c in unexpected]

    ks = policy["kubescape"]
    if manifests := need("kubescape_manifests"):
        if manifests["score"] < ks["min_manifest_compliance"]:
            problems.append(f"Kubescape manifest compliance {manifests['score']} < {ks['min_manifest_compliance']}")
        if manifests["frameworks"].get("NSA", 0) < ks["min_manifest_nsa"]:
            problems.append(f"Kubescape NSA {manifests['frameworks'].get('NSA')} < {ks['min_manifest_nsa']}")
    if live := need("kubescape_cluster"):
        allowed = set(ks["allowed_app_failures"])
        problems += [
            f"Kubescape live control failing on app resources: {c}"
            for c in live["app_failed_controls"]
            if c.split()[0] not in allowed
        ]

    if pol := need("polaris"):
        if pol["score"] is None or pol["score"] < policy["polaris"]["min_score"]:
            problems.append(f"Polaris score {pol['score']} < {policy['polaris']['min_score']}")
        if pol["danger"] > policy["polaris"]["max_danger"]:
            problems.append(f"Polaris danger findings {pol['danger']} > {policy['polaris']['max_danger']}")

    if tv := need("trivy_triaged"):
        if tv["HIGH"] + tv["CRITICAL"] > policy["trivy"]["max_high_critical"]:
            problems.append(f"Trivy HIGH+CRITICAL {tv['HIGH'] + tv['CRITICAL']} > {policy['trivy']['max_high_critical']}")
        if tv["MEDIUM"] > policy["trivy"]["max_medium"]:
            problems.append(f"Trivy MEDIUM {tv['MEDIUM']} > {policy['trivy']['max_medium']}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("summary", type=Path)
    parser.add_argument("--policy", type=Path, default=P2_DIR / "hardening-policy.toml")
    args = parser.parse_args(argv)

    try:
        summary = json.loads(args.summary.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"policy gate: cannot read {args.summary}: {exc}", file=sys.stderr)
        return 1
    problems = evaluate(summary, tomllib.loads(args.policy.read_text(encoding="utf-8")))
    if problems:
        print("P2 policy gate: FAILED")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("P2 policy gate: PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
