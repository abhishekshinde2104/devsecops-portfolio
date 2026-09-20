"""Unit tests for the P3 pipeline gate (no cluster needed)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

P3 = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P3 / "scripts"))

import pipeline_gate  # noqa: E402

HEADER = "id\tcheck\tpassed\tevidence\n"
ALL_PASS = HEADER + "".join(f"C0{i}\tcheck {i}\ttrue\tok\n" for i in range(1, 8))


def write(tmp_path, content):
    p = tmp_path / "pipeline-checks.tsv"
    p.write_text(content, encoding="utf-8")
    return p


def test_all_checks_pass(tmp_path):
    assert pipeline_gate.evaluate(write(tmp_path, ALL_PASS), require_falco=False) == []


def test_a_failing_check_blocks(tmp_path):
    tsv = ALL_PASS.replace("C03\tcheck 3\ttrue\tok", "C03\trules loaded\tfalse\tmissing InvoiceApiBOLAProbing")
    problems = pipeline_gate.evaluate(write(tmp_path, tsv), require_falco=False)
    assert any("C03" in p and "FAILED" in p for p in problems)


def test_missing_check_fails_closed(tmp_path):
    tsv = HEADER + "".join(f"C0{i}\tcheck {i}\ttrue\tok\n" for i in range(1, 7))  # C07 absent
    problems = pipeline_gate.evaluate(write(tmp_path, tsv), require_falco=False)
    assert any("C07" in p and "did not run" in p for p in problems)


def test_missing_file_fails_closed(tmp_path):
    problems = pipeline_gate.evaluate(tmp_path / "nope.tsv", require_falco=False)
    assert problems and "cannot read" in problems[0]


def test_falco_check_required_only_with_flag(tmp_path):
    path = write(tmp_path, ALL_PASS)  # no C08
    assert pipeline_gate.evaluate(path, require_falco=False) == []
    assert any("C08" in p for p in pipeline_gate.evaluate(path, require_falco=True))


def test_cli_exit_codes(tmp_path, capsys):
    assert pipeline_gate.main([str(write(tmp_path, ALL_PASS))]) == 0
    assert "PASSED" in capsys.readouterr().out
    bad = ALL_PASS.replace("C01\tcheck 1\ttrue\tok", "C01\tscrape\tfalse\tup==0")
    assert pipeline_gate.main([str(write(tmp_path, bad))]) == 1
