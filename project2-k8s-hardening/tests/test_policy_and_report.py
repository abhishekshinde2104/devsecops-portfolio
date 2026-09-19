"""Unit tests for the Project 2 report and policy gate (no cluster needed)."""

from __future__ import annotations

import copy
import json
import sys
import tomllib
from pathlib import Path

import pytest

P2 = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P2 / "scripts"))

import policy_gate  # noqa: E402
import report  # noqa: E402

POLICY = tomllib.loads((P2 / "hardening-policy.toml").read_text())

GOOD = {
    "verify": {"secure": 2, "total": 2, "checks": [
        {"id": "V01", "check": "non-root", "secure": "true", "evidence": "uid=10001"},
        {"id": "V11", "check": "privileged pod rejected", "secure": "true", "evidence": "PSA"},
    ]},
    "kube_bench": {"pass": 81, "fail": 1, "warn": 49, "info": 0, "version": "cis-1.12",
                   "failed_checks": ["1.1.12 Ensure that the etcd data directory ownership is set to etcd:etcd"]},
    "kubescape_cluster": {"score": 62.7, "frameworks": {}, "failed_controls": ["C-0185 x"],
                          "app_failed_controls": ["C-0053 Access container service account"]},
    "kubescape_manifests": {"score": 88.5, "frameworks": {"NSA": 100.0}, "failed_controls": [],
                            "app_failed_controls": []},
    "polaris": {"score": 90, "danger": 0, "warning": 6},
    "trivy_raw": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 15},
    "trivy_triaged": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0},
}


def mutate(**changes):
    summary = copy.deepcopy(GOOD)
    for path, value in changes.items():
        node = summary
        *parents, leaf = path.split("__")
        for key in parents:
            node = node[key]
        node[leaf] = value
    return summary


def test_hardened_summary_passes():
    assert policy_gate.evaluate(GOOD, POLICY) == []


@pytest.mark.parametrize(
    "changes, expected",
    [
        ({"kube_bench__failed_checks": ["1.2.15 profiling"]}, "kube-bench FAIL 1.2.15"),
        ({"kubescape_manifests__score": 70.0}, "manifest compliance"),
        ({"kubescape_manifests__frameworks": {"NSA": 95.0}}, "NSA"),
        ({"kubescape_cluster__app_failed_controls": ["C-0017 Immutable container filesystem"]}, "C-0017"),
        ({"polaris__score": 60}, "Polaris score"),
        ({"polaris__danger": 1}, "danger"),
        ({"trivy_triaged__HIGH": 1}, "HIGH+CRITICAL"),
    ],
)
def test_regressions_fail_the_gate(changes, expected):
    problems = policy_gate.evaluate(mutate(**changes), POLICY)
    assert any(expected in p for p in problems), problems


def test_failed_runtime_check_fails_the_gate():
    summary = copy.deepcopy(GOOD)
    summary["verify"]["checks"][0]["secure"] = "false"
    assert any("V01" in p for p in policy_gate.evaluate(summary, POLICY))


def test_missing_scanner_fails_closed():
    summary = copy.deepcopy(GOOD)
    summary["polaris"] = None
    assert any("no results" in p for p in policy_gate.evaluate(summary, POLICY))


def test_kubescape_attributes_failures_to_app_or_platform():
    data = {
        "summaryDetails": {"complianceScore": 60, "frameworks": [],
                           "controls": {"C-0053": {"name": "SA", "ResourceCounters": {"failedResources": 1}},
                                        "C-0185": {"name": "cluster-admin", "ResourceCounters": {"failedResources": 1}}}},
        "results": [
            {"resourceID": "rbac.authorization.k8s.io/v1/invoice-api/RoleBinding/invoice-api-deployer",
             "controls": [{"controlID": "C-0053", "status": {"status": "failed"}}]},
            {"resourceID": "rbac.authorization.k8s.io/v1//ClusterRoleBinding/cluster-admin",
             "controls": [{"controlID": "C-0185", "status": {"status": "failed"}}]},
        ],
    }
    result = report.kubescape(data, "invoice-api")
    assert result["app_failed_controls"] == ["C-0053 SA"]
    assert len(result["failed_controls"]) == 2


def test_kube_bench_parser_collects_failures():
    data = {"Controls": [{"version": "cis-1.12", "tests": [{"results": [
        {"test_number": "1.2.15", "test_desc": "profiling", "status": "FAIL"},
        {"test_number": "1.2.16", "test_desc": "audit", "status": "PASS"},
    ]}]}], "Totals": {"total_pass": 1, "total_fail": 1, "total_warn": 0, "total_info": 0}}
    result = report.kube_bench(data)
    assert result["fail"] == 1 and result["failed_checks"] == ["1.2.15 profiling"] and result["version"] == "cis-1.12"


def test_compare_renders_before_after(tmp_path):
    before, after = tmp_path / "baseline", tmp_path / "hardened"
    before.mkdir()
    after.mkdir()
    (before / "verify.tsv").write_text("id\tcheck\tsecure\tevidence\nV01\tnon-root\tfalse\tuid=0\n")
    (after / "verify.tsv").write_text("id\tcheck\tsecure\tevidence\nV01\tnon-root\ttrue\tuid=10001\n")
    (after / "polaris.json").write_text(json.dumps({"Score": 90, "Results": []}))
    table = report.compare(report.summarise(before), report.summarise(after))
    assert "| Runtime checks secure (scripts/verify.sh) | 0/1 | 1/1 |" in table
    assert "| Polaris score (0-100) | n/a | 90 |" in table
    assert "| V01 non-root | ❌ | ✅ | uid=10001 |" in table
