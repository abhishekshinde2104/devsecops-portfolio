#!/usr/bin/env python3
"""Severity gate: aggregate scanner reports and decide pass/fail.

Reads the raw reports produced by the pipeline (Semgrep, Gitleaks, Trivy,
Grype, OWASP Dependency-Check), normalises them to one finding model, applies
the policy in security-gate.toml (thresholds, unfixed handling, time-boxed
exceptions) and exits non-zero when blocking findings remain.

The gate fails *closed*: a required report that is missing or unparsable is
itself a blocking condition, so a crashed scanner cannot turn the build green.

Standard library only, so it runs on any runner without installing anything.

    python scripts/security_gate.py --policy security-gate.toml --reports reports/
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
_SEVERITY_ALIASES = {
    "ERROR": "HIGH",  # semgrep
    "WARNING": "MEDIUM",
    "MODERATE": "MEDIUM",  # dependency-check / GHSA
    "NEGLIGIBLE": "LOW",  # grype
    "NOTE": "LOW",
    "INFORMATIONAL": "INFO",
}


def normalise_severity(raw: Any) -> str:
    value = str(raw or "UNKNOWN").strip().upper()
    value = _SEVERITY_ALIASES.get(value, value)
    return value if value in SEVERITIES else "UNKNOWN"


@dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: str
    title: str
    location: str
    fixable: bool | None = None  # None = not applicable (SAST, secrets, misconfig)
    fix_version: str | None = None
    waived_by: str | None = None
    blocking: bool = False

    @property
    def key(self) -> tuple[str, str]:
        return (self.rule_id, self.location)


# --------------------------------------------------------------------- parsers


def _pkg(name: Any, version: Any) -> str:
    # Package names are case-insensitive in PyPI and differ in case between
    # scanners (PyJWT vs pyjwt); normalise so findings deduplicate.
    return f"{str(name).lower()}@{version}"


def parse_semgrep(data: dict) -> Iterable[Finding]:
    for r in data.get("results", []):
        extra = r.get("extra", {})
        yield Finding(
            scanner="semgrep",
            rule_id=r.get("check_id", "unknown"),
            severity=normalise_severity(extra.get("severity")),
            title=(extra.get("message") or "").strip().splitlines()[0][:160] if extra.get("message") else "",
            location=f"{r.get('path')}:{r.get('start', {}).get('line', '?')}",
        )


def parse_gitleaks(data: list) -> Iterable[Finding]:
    # Any committed secret is critical regardless of rule: rotation is required.
    for leak in data or []:
        yield Finding(
            scanner="gitleaks",
            rule_id=leak.get("RuleID", "secret"),
            severity="CRITICAL",
            title=leak.get("Description", "Secret detected"),
            location=f"{leak.get('File')}:{leak.get('StartLine', '?')}@{str(leak.get('Commit', ''))[:8]}",
        )


def parse_trivy(data: dict) -> Iterable[Finding]:
    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            fixed = v.get("FixedVersion") or None
            yield Finding(
                scanner="trivy",
                rule_id=v.get("VulnerabilityID", "unknown"),
                severity=normalise_severity(v.get("Severity")),
                title=(v.get("Title") or v.get("PkgName", ""))[:160],
                location=_pkg(v.get("PkgName"), v.get("InstalledVersion")),
                fixable=fixed is not None,
                fix_version=fixed,
            )
        for m in result.get("Misconfigurations", []) or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            yield Finding(
                scanner="trivy-config",
                rule_id=m.get("AVDID") or m.get("ID", "unknown"),
                severity=normalise_severity(m.get("Severity")),
                title=m.get("Title", "")[:160],
                location=f"{target}:{(m.get('CauseMetadata') or {}).get('StartLine', '?')}",
            )
        for s in result.get("Secrets", []) or []:
            yield Finding(
                scanner="trivy-secret",
                rule_id=s.get("RuleID", "secret"),
                severity="CRITICAL",
                title=s.get("Title", "Secret detected"),
                location=f"{target}:{s.get('StartLine', '?')}",
            )


def parse_grype(data: dict) -> Iterable[Finding]:
    for match in data.get("matches", []) or []:
        vuln = match.get("vulnerability", {})
        art = match.get("artifact", {})
        fix = vuln.get("fix", {}) or {}
        versions = fix.get("versions") or []
        vuln_id = vuln.get("id", "unknown")
        # Grype reports language packages by GHSA ID while Trivy and
        # Dependency-Check use the CVE; prefer the CVE alias so the same
        # vulnerability deduplicates across scanners.
        aliases = [r.get("id", "") for r in match.get("relatedVulnerabilities", []) or []]
        cve = next((a for a in aliases if a.startswith("CVE-")), None)
        yield Finding(
            scanner="grype",
            rule_id=cve if cve and not vuln_id.startswith("CVE-") else vuln_id,
            severity=normalise_severity(vuln.get("severity")),
            title=(f"[{vuln_id}] " if cve else "") + (vuln.get("description") or art.get("name", ""))[:160],
            location=_pkg(art.get("name"), art.get("version")),
            fixable=fix.get("state") == "fixed",
            fix_version=versions[0] if versions else None,
        )


def parse_dependency_check(data: dict) -> Iterable[Finding]:
    for dep in data.get("dependencies", []) or []:
        pkg = (dep.get("packages") or [{}])[0].get("id") or dep.get("fileName", "unknown")
        if pkg.startswith("pkg:"):  # purl, e.g. pkg:pypi/pyjwt@2.3.0 -> pyjwt@2.3.0
            pkg = pkg.rsplit("/", 1)[-1].lower()
        for v in dep.get("vulnerabilities", []) or []:
            severity = v.get("severity")
            if not severity and v.get("cvssv3"):
                severity = v["cvssv3"].get("baseSeverity")
            yield Finding(
                scanner="dependency-check",
                rule_id=v.get("name", "unknown"),
                severity=normalise_severity(severity),
                title=(v.get("description") or "")[:160],
                location=str(pkg),
                # ODC does not report fix availability; treat as fixable so
                # the gate errs on the side of blocking.
                fixable=True,
            )


def parse_image_policy(data: dict) -> Iterable[Finding]:
    for f in data.get("findings", []) or []:
        yield Finding(
            scanner="image-policy",
            rule_id=f.get("id", "unknown"),
            severity=normalise_severity(f.get("severity")),
            title=f.get("title", ""),
            location=f.get("location", "image"),
        )


PARSERS: dict[str, Callable[[Any], Iterable[Finding]]] = {
    "semgrep": parse_semgrep,
    "gitleaks": parse_gitleaks,
    "trivy": parse_trivy,
    "grype": parse_grype,
    "dependency-check": parse_dependency_check,
    "image-policy": parse_image_policy,
}

# --------------------------------------------------------------------- policy


@dataclass
class Exception_:
    id: str
    reason: str
    expires: date
    approved_by: str
    location: str | None = None

    def matches(self, f: Finding) -> bool:
        return f.rule_id == self.id and (self.location is None or self.location == f.location)


@dataclass
class Policy:
    fail_on: set[str]
    ignore_unfixed: bool
    reports: list[dict]
    exceptions: list[Exception_] = field(default_factory=list)


def load_policy(path: Path) -> Policy:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    gate = raw.get("gate", {})
    return Policy(
        fail_on={normalise_severity(s) for s in gate.get("fail_on", ["CRITICAL", "HIGH"])},
        ignore_unfixed=bool(gate.get("ignore_unfixed", True)),
        reports=raw.get("reports", []),
        exceptions=[Exception_(**e) for e in raw.get("exceptions", [])],
    )


# --------------------------------------------------------------------- evaluation


@dataclass
class GateResult:
    passed: bool
    findings: list[Finding]
    missing_reports: list[str]
    expired_exceptions: list[Exception_]
    counts: dict[str, dict[str, int]]


def evaluate(
    policy: Policy, reports_dir: Path, today: date | None = None, allow_missing: Iterable[str] = ()
) -> GateResult:
    today = today or date.today()
    allow_missing = set(allow_missing)
    findings: list[Finding] = []
    missing: list[str] = []

    for report in policy.reports:
        path = reports_dir / report["path"]
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            parsed = list(PARSERS[report["parser"]](data))
            if label := report.get("label"):
                for f in parsed:
                    if f.scanner == report["parser"]:
                        f.scanner = label
            findings.extend(parsed)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, AttributeError) as exc:
            if report.get("required", True) and report["parser"] not in allow_missing:
                missing.append(f"{report['name']} ({path}): {type(exc).__name__}")

    active = [e for e in policy.exceptions if e.expires >= today]
    expired = [e for e in policy.exceptions if e.expires < today]

    seen: set[tuple[str, str]] = set()
    for f in findings:
        waiver = next((e for e in active if e.matches(f)), None)
        if waiver:
            f.waived_by = f"{waiver.approved_by} until {waiver.expires.isoformat()}: {waiver.reason}"
            continue
        if f.severity not in policy.fail_on:
            continue
        if policy.ignore_unfixed and f.fixable is False:
            continue
        # The same CVE on the same package reported by several scanners
        # blocks once.
        if f.key in seen:
            continue
        seen.add(f.key)
        f.blocking = True

    counts: dict[str, dict[str, int]] = {}
    for f in findings:
        counts.setdefault(f.scanner, {})
        counts[f.scanner][f.severity] = counts[f.scanner].get(f.severity, 0) + 1

    passed = not missing and not any(f.blocking for f in findings)
    return GateResult(passed, findings, missing, expired, counts)


# --------------------------------------------------------------------- output


def render_markdown(result: GateResult, policy: Policy) -> str:
    icon = "PASSED" if result.passed else "FAILED"
    lines = [f"## Security gate: {icon}", ""]
    lines.append(
        f"Policy: block on **{', '.join(s for s in SEVERITIES if s in policy.fail_on)}**"
        f"{' (fixable only for dependency/image CVEs)' if policy.ignore_unfixed else ''}; "
        "missing reports block."
    )
    lines += ["", "| Scanner | " + " | ".join(SEVERITIES[:5]) + " |", "|---|" + "---|" * 5]
    for scanner in sorted(result.counts):
        row = [str(result.counts[scanner].get(s, 0)) for s in SEVERITIES[:5]]
        lines.append(f"| {scanner} | " + " | ".join(row) + " |")
    if not result.counts:
        lines.append("| (no findings) | 0 | 0 | 0 | 0 | 0 |")

    if result.missing_reports:
        lines += ["", "### Missing or unreadable reports (blocking)"]
        lines += [f"- {m}" for m in result.missing_reports]

    blocking = [f for f in result.findings if f.blocking]
    if blocking:
        lines += ["", f"### Blocking findings ({len(blocking)})", "", "| Severity | Scanner | ID | Location | Fix |"]
        lines.append("|---|---|---|---|---|")
        for f in sorted(blocking, key=lambda f: SEVERITIES.index(f.severity))[:100]:
            lines.append(f"| {f.severity} | {f.scanner} | `{f.rule_id}` | `{f.location}` | {f.fix_version or '-'} |")

    waived = [f for f in result.findings if f.waived_by]
    if waived:
        lines += ["", f"### Waived by exception ({len(waived)})"]
        lines += [f"- `{f.rule_id}` at `{f.location}`: {f.waived_by}" for f in waived]
    if result.expired_exceptions:
        lines += ["", "### Expired exceptions (no longer applied)"]
        lines += [f"- `{e.id}` expired {e.expires.isoformat()} ({e.approved_by})" for e in result.expired_exceptions]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--policy", type=Path, default=Path("security-gate.toml"))
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    parser.add_argument("--summary", type=Path, help="append markdown summary here (e.g. $GITHUB_STEP_SUMMARY)")
    parser.add_argument("--output", type=Path, help="write normalised findings JSON here")
    parser.add_argument(
        "--allow-missing",
        action="append",
        default=[],
        metavar="PARSER",
        help="local runs only: tolerate a missing report for this parser (never use in CI)",
    )
    args = parser.parse_args(argv)

    policy = load_policy(args.policy)
    result = evaluate(policy, args.reports, allow_missing=args.allow_missing)
    if args.allow_missing:
        print(f"WARNING: reports allowed to be missing (local run): {', '.join(args.allow_missing)}\n")
    markdown = render_markdown(result, policy)
    print(markdown)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as fh:
            fh.write(markdown)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(
                {
                    "passed": result.passed,
                    "missing_reports": result.missing_reports,
                    "findings": [asdict(f) for f in result.findings],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
