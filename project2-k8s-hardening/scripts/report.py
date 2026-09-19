#!/usr/bin/env python3
"""Summarise one scan run and compare "before" vs "after".

    report.py summarise reports/baseline         -> reports/baseline/summary.json
    report.py compare reports/baseline reports/hardened --markdown docs/results/comparison.md

Standard library only. Every parser tolerates a missing report (shown as
"n/a") so a partial local run still produces a readable summary; the CI gate
(scripts/policy_gate.py) is the component that insists on completeness.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
from pathlib import Path
from typing import Any


def _load(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def kube_bench(data: Any) -> dict | None:
    if not data:
        return None
    totals = data.get("Totals") if isinstance(data, dict) else None
    controls = data.get("Controls", []) if isinstance(data, dict) else data
    failed = []
    for control in controls or []:
        for group in control.get("tests", []) or []:
            for result in group.get("results", []) or []:
                if result.get("status") == "FAIL":
                    failed.append(f"{result.get('test_number')} {result.get('test_desc', '').strip()}")
    if totals is None:
        totals = collections.Counter()
        for control in controls or []:
            for key in ("total_pass", "total_fail", "total_warn", "total_info"):
                totals[key] += control.get(key, 0)
    return {
        "pass": totals.get("total_pass", 0),
        "fail": totals.get("total_fail", 0),
        "warn": totals.get("total_warn", 0),
        "info": totals.get("total_info", 0),
        "version": next((c.get("version") for c in controls or [] if c.get("version")), None),
        "failed_checks": sorted(set(failed)),
    }


# Resources that belong to the application (namespaced objects in the app
# namespace, plus the cluster-scoped binding the insecure baseline adds).
# Everything else a live scan flags is platform-owned: kubeadm's built-in
# bindings such as cluster-admin -> system:masters exist in every cluster.
APP_CLUSTER_SCOPED = {"ClusterRoleBinding/default-sa-cluster-admin"}


def _is_app_resource(resource_id: str, namespace: str | None) -> bool:
    if namespace is None:
        return True
    parts = resource_id.split("/")
    kind_name = "/".join(parts[-2:])
    return f"/{namespace}/" in resource_id or kind_name in APP_CLUSTER_SCOPED or kind_name == f"Namespace/{namespace}"


def kubescape(data: Any, namespace: str | None = None) -> dict | None:
    if not data:
        return None
    summary = data.get("summaryDetails", {})
    names = {cid: c.get("name") for cid, c in summary.get("controls", {}).items()}
    failed = sorted(
        f"{cid} {names[cid]}"
        for cid, c in summary.get("controls", {}).items()
        if c.get("ResourceCounters", {}).get("failedResources", 0) > 0
    )
    app_failed: set[str] = set()
    for result in data.get("results", []) or []:
        if not _is_app_resource(result.get("resourceID", ""), namespace):
            continue
        for control in result.get("controls", []) or []:
            if control.get("status", {}).get("status") == "failed":
                app_failed.add(f"{control['controlID']} {names.get(control['controlID'], '')}")
    return {
        "score": round(summary.get("complianceScore", 0), 1),
        "frameworks": {f["name"]: round(f.get("complianceScore", 0), 1) for f in summary.get("frameworks", [])},
        "failed_controls": failed,
        "app_failed_controls": sorted(app_failed),
    }


def trivy(data: Any) -> dict | None:
    if not data:
        return None
    counts = collections.Counter(
        m.get("Severity", "UNKNOWN")
        for r in data.get("Results", []) or []
        for m in r.get("Misconfigurations", []) or []
        if m.get("Status") == "FAIL"
    )
    return {s: counts.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}


def polaris(data: Any) -> dict | None:
    if not data:
        return None
    counts: collections.Counter[str] = collections.Counter()

    def walk(results: dict | None) -> None:
        for check in (results or {}).values():
            if not check.get("Success", True):
                counts[check.get("Severity", "unknown")] += 1

    for r in data.get("Results", []) or []:
        walk(r.get("Results"))
        pod = r.get("PodResult") or {}
        walk(pod.get("Results"))
        for container in pod.get("ContainerResults", []) or []:
            walk(container.get("Results"))
    return {"score": data.get("Score"), "danger": counts.get("danger", 0), "warning": counts.get("warning", 0)}


def verify(path: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh, delimiter="\t"))
    except OSError:
        return None
    return {
        "secure": sum(r["secure"] == "true" for r in rows),
        "total": len(rows),
        "checks": [{k: r[k] for k in ("id", "check", "secure", "evidence")} for r in rows],
    }


APP_NAMESPACES = {"baseline": "default", "hardened": "invoice-api"}


def summarise(directory: Path) -> dict:
    namespace = APP_NAMESPACES.get(directory.name)
    summary = {
        "verify": verify(directory / "verify.tsv"),
        "kube_bench": kube_bench(_load(directory / "kube-bench.json")),
        "kubescape_cluster": kubescape(_load(directory / "kubescape-cluster.json"), namespace),
        "kubescape_manifests": kubescape(_load(directory / "kubescape-manifests.json")),
        "trivy_raw": trivy(_load(directory / "trivy-config-raw.json")),
        "trivy_triaged": trivy(_load(directory / "trivy-config.json")),
        "polaris": polaris(_load(directory / "polaris.json")),
    }
    (directory / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _get(summary: dict, *path: str) -> Any:
    node: Any = summary
    for key in path:
        if not isinstance(node, dict) or node.get(key) is None:
            return None
        node = node[key]
    return node


def _fmt(value: Any, suffix: str = "") -> str:
    return "n/a" if value is None else f"{value}{suffix}"


def compare(before: dict, after: dict) -> str:
    rows = [
        ("Runtime checks secure (scripts/verify.sh)",
         lambda s: None if not s.get("verify") else f"{s['verify']['secure']}/{s['verify']['total']}"),
        ("kube-bench CIS v1.12: FAIL", lambda s: _get(s, "kube_bench", "fail")),
        ("kube-bench CIS v1.12: WARN (manual checks)", lambda s: _get(s, "kube_bench", "warn")),
        ("kube-bench CIS v1.12: PASS", lambda s: _get(s, "kube_bench", "pass")),
        ("Kubescape live namespace: compliance %", lambda s: _get(s, "kubescape_cluster", "score")),
        ("Kubescape live: failed controls caused by the app's own resources", lambda s:
            None if not s.get("kubescape_cluster") else len(s["kubescape_cluster"]["app_failed_controls"])),
        ("Kubescape live: failed controls in total (incl. kubeadm built-ins)", lambda s:
            None if not s.get("kubescape_cluster") else len(s["kubescape_cluster"]["failed_controls"])),
        ("Kubescape manifests: compliance %", lambda s: _get(s, "kubescape_manifests", "score")),
        ("Kubescape manifests: NSA %", lambda s: _get(s, "kubescape_manifests", "frameworks", "NSA")),
        ("Kubescape manifests: MITRE %", lambda s: _get(s, "kubescape_manifests", "frameworks", "MITRE")),
        ("Kubescape manifests: CIS v1.12 %", lambda s: _get(s, "kubescape_manifests", "frameworks", "cis-v1.12.0")),
        ("Polaris score (0-100)", lambda s: _get(s, "polaris", "score")),
        ("Polaris danger-level findings", lambda s: _get(s, "polaris", "danger")),
        ("Trivy HIGH+CRITICAL misconfigurations", lambda s: None if not s.get("trivy_raw") else
            s["trivy_raw"]["HIGH"] + s["trivy_raw"]["CRITICAL"]),
        ("Trivy MEDIUM (raw / after triage)", lambda s: None if not s.get("trivy_raw") else
            f"{s['trivy_raw']['MEDIUM']} / {_fmt(_get(s, 'trivy_triaged', 'MEDIUM'))}"),
        ("Trivy LOW (raw / after triage)", lambda s: None if not s.get("trivy_raw") else
            f"{s['trivy_raw']['LOW']} / {_fmt(_get(s, 'trivy_triaged', 'LOW'))}"),
    ]
    lines = ["| Measure | Before (kind defaults + insecure manifests) | After (hardened) |", "|---|---|---|"]
    lines += [f"| {label} | {_fmt(fn(before))} | {_fmt(fn(after))} |" for label, fn in rows]

    if before.get("verify") and after.get("verify"):
        lines += ["", "| Runtime check | Before | After | Evidence (after) |", "|---|---|---|---|"]
        prior = {c["id"]: c for c in before["verify"]["checks"]}
        for check in after["verify"]["checks"]:
            b = prior.get(check["id"], {})
            icon = {"true": "✅", "false": "❌"}
            lines.append(
                f"| {check['id']} {check['check']} | {icon.get(b.get('secure', ''), 'n/a')} | "
                f"{icon[check['secure']]} | {check['evidence']} |"
            )

    for label, path in (
        ("kube-bench checks still failing after hardening", ("kube_bench", "failed_checks")),
        ("Kubescape live controls still failing on app resources", ("kubescape_cluster", "app_failed_controls")),
    ):
        remaining = _get(after, *path)
        if remaining:
            lines += ["", f"**{label}** ({len(remaining)}):", ""] + [f"- {c}" for c in remaining]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("summarise")
    s.add_argument("directory", type=Path)
    c = sub.add_parser("compare")
    c.add_argument("before", type=Path)
    c.add_argument("after", type=Path)
    c.add_argument("--markdown", type=Path)
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252

    if args.command == "summarise":
        print(json.dumps(summarise(args.directory), indent=2))
        return 0
    table = compare(summarise(args.before), summarise(args.after))
    print(table)
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(table, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
