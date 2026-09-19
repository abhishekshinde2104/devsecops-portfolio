#!/usr/bin/env python3
"""Image policy check: inspect the *built* image's runtime configuration.

Why this exists: Dockerfile linters (Trivy DS002, Semgrep missing-user) look
at the last ``USER`` instruction in the file. In a multi-stage Dockerfile, a
``USER`` in an earlier stage satisfies them even when the final stage runs as
root; this was found while building this project's red/green demo. Checking
the image config that will actually run closes that gap.

Reads a ``docker save`` / buildx ``type=docker`` archive with the standard
library only and writes a JSON report consumed by security_gate.py.

    python scripts/image_policy.py --image-tar image.tar --output reports/image-policy.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tarfile
from pathlib import Path
from typing import Any

_SECRET_ENV = re.compile(r"(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)", re.IGNORECASE)
_ROOT_USERS = {"", "root", "0"}


def load_image_config(image_tar: Path) -> dict[str, Any]:
    with tarfile.open(image_tar) as tar:
        manifest = json.load(tar.extractfile("manifest.json"))  # type: ignore[arg-type]
        config_name = manifest[0]["Config"]
        return json.load(tar.extractfile(config_name))  # type: ignore[arg-type]


def check(config: dict[str, Any]) -> list[dict[str, str]]:
    runtime = config.get("config") or config.get("Config") or {}
    findings: list[dict[str, str]] = []

    user = str(runtime.get("User") or "")
    if user.split(":", 1)[0] in _ROOT_USERS:
        findings.append(
            {
                "id": "IMG-001",
                "severity": "HIGH",
                "title": f"Image runs as root (User={user or '<unset>'}); set a non-root USER in the final stage",
                "location": "image-config:User",
            }
        )

    for entry in runtime.get("Env") or []:
        name, _, value = entry.partition("=")
        if _SECRET_ENV.search(name) and value:
            findings.append(
                {
                    "id": "IMG-002",
                    "severity": "CRITICAL",
                    "title": f"Secret-like environment variable baked into image: {name}",
                    "location": f"image-config:Env:{name}",
                }
            )

    if not runtime.get("Healthcheck"):
        findings.append(
            {
                "id": "IMG-003",
                "severity": "LOW",
                "title": "No HEALTHCHECK defined",
                "location": "image-config:Healthcheck",
            }
        )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image-tar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    findings = check(load_image_config(args.image_tar))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")
    for f in findings:
        print(f"{f['severity']:8} {f['id']} {f['title']}")
    print(f"image policy: {len(findings)} finding(s)")
    return 0  # the gate decides


if __name__ == "__main__":
    sys.exit(main())
