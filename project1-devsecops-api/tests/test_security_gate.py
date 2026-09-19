"""The severity gate is security-critical code too: a bug here silently ships vulns."""

from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path

import pytest

from scripts import security_gate as gate

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "gate"
POLICY = gate.load_policy(ROOT / "security-gate.toml")


def _copy(tmp_path: Path, name: str) -> Path:
    dest = tmp_path / name
    shutil.copytree(FIXTURES / name, dest)
    return dest


def test_clean_reports_pass():
    result = gate.evaluate(POLICY, FIXTURES / "clean")
    assert result.passed, gate.render_markdown(result, POLICY)
    assert not result.missing_reports


def test_unfixed_high_is_reported_but_not_blocking():
    result = gate.evaluate(POLICY, FIXTURES / "clean")
    unfixed = [f for f in result.findings if f.rule_id == "CVE-2025-1111"]
    assert unfixed and not any(f.blocking for f in unfixed)


def test_dirty_reports_fail_with_one_blocker_per_class():
    result = gate.evaluate(POLICY, FIXTURES / "dirty")
    assert not result.passed
    blocking = {(f.scanner, f.rule_id) for f in result.findings if f.blocking}
    assert ("semgrep", "fastapi-security.jwt-decode-without-algorithms") in blocking
    assert ("gitleaks", "generic-api-key") in blocking
    assert ("trivy-config", "AVD-DS-0002") in blocking
    assert ("image-policy", "IMG-001") in blocking
    assert any(rule == "CVE-2025-3333" for _, rule in blocking)


def test_same_cve_from_multiple_scanners_blocks_once():
    # trivy reports the CVE id, grype the GHSA id (with CVE alias) and a
    # different package-name case, dependency-check a purl: all one finding.
    result = gate.evaluate(POLICY, FIXTURES / "dirty")
    same = [f for f in result.findings if f.rule_id == "CVE-2025-3333" and f.location == "starlette@0.36.3"]
    assert {f.scanner for f in same} == {"trivy-image", "grype", "dependency-check"}
    assert sum(f.blocking for f in same) == 1


def test_grype_ghsa_is_mapped_to_cve_alias():
    [finding] = gate.parse_grype(json.loads((FIXTURES / "dirty" / "grype.json").read_text()))
    assert finding.rule_id == "CVE-2025-3333"
    assert finding.title.startswith("[GHSA-aaaa-bbbb-cccc]")
    assert finding.location == "starlette@0.36.3"


def test_missing_report_fails_closed(tmp_path):
    reports = _copy(tmp_path, "clean")
    (reports / "gitleaks.json").unlink()
    result = gate.evaluate(POLICY, reports)
    assert not result.passed
    assert any("gitleaks" in m for m in result.missing_reports)


def test_corrupt_report_fails_closed(tmp_path):
    reports = _copy(tmp_path, "clean")
    (reports / "semgrep.json").write_text("{not json")
    assert not gate.evaluate(POLICY, reports).passed


def test_active_exception_waives_finding(tmp_path):
    reports = _copy(tmp_path, "clean")
    (reports / "trivy-image.json").write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "img",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2025-9999",
                                "PkgName": "libz",
                                "InstalledVersion": "1",
                                "FixedVersion": "2",
                                "Severity": "CRITICAL",
                            }
                        ],
                    }
                ]
            }
        )
    )
    exc = gate.Exception_(id="CVE-2025-9999", reason="not reachable", expires=date(2099, 1, 1), approved_by="sec")
    policy = gate.Policy(POLICY.fail_on, POLICY.ignore_unfixed, POLICY.reports, [exc])
    result = gate.evaluate(policy, reports)
    assert result.passed
    assert any(f.waived_by for f in result.findings)

    expired = gate.Exception_(id="CVE-2025-9999", reason="old", expires=date(2020, 1, 1), approved_by="sec")
    policy = gate.Policy(POLICY.fail_on, POLICY.ignore_unfixed, POLICY.reports, [expired])
    result = gate.evaluate(policy, reports)
    assert not result.passed
    assert result.expired_exceptions == [expired]


@pytest.mark.parametrize(
    "raw,expected",
    [("ERROR", "HIGH"), ("warning", "MEDIUM"), ("Moderate", "MEDIUM"), ("Negligible", "LOW"), (None, "UNKNOWN")],
)
def test_severity_normalisation(raw, expected):
    assert gate.normalise_severity(raw) == expected


def test_cli_writes_summary_and_exit_code(tmp_path):
    summary = tmp_path / "summary.md"
    out = tmp_path / "result.json"
    code = gate.main(
        ["--policy", str(ROOT / "security-gate.toml"), "--reports", str(FIXTURES / "dirty"),
         "--summary", str(summary), "--output", str(out)]
    )  # fmt: skip
    assert code == 1
    assert "Security gate: FAILED" in summary.read_text()
    assert json.loads(out.read_text())["passed"] is False
    assert gate.main(["--policy", str(ROOT / "security-gate.toml"), "--reports", str(FIXTURES / "clean")]) == 0


def test_allow_missing_is_explicit_and_scoped(tmp_path):
    reports = _copy(tmp_path, "clean")
    shutil.rmtree(reports / "dependency-check")
    assert not gate.evaluate(POLICY, reports).passed
    assert gate.evaluate(POLICY, reports, allow_missing=["dependency-check"]).passed
    (reports / "gitleaks.json").unlink()
    assert not gate.evaluate(POLICY, reports, allow_missing=["dependency-check"]).passed
