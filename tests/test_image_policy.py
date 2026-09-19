"""Image policy check against synthetic docker-archive tarballs."""

from __future__ import annotations

import io
import json
import tarfile

import pytest

from scripts import image_policy


def _image_tar(tmp_path, config: dict):
    path = tmp_path / "image.tar"
    files = {
        "manifest.json": json.dumps([{"Config": "blobs/sha256/abc", "RepoTags": ["x:1"], "Layers": []}]),
        "blobs/sha256/abc": json.dumps({"config": config}),
    }
    with tarfile.open(path, "w") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


HEALTHY = {"User": "10001:10001", "Env": ["PATH=/usr/bin"], "Healthcheck": {"Test": ["CMD", "true"]}}


def test_hardened_image_passes(tmp_path):
    out = tmp_path / "report.json"
    assert image_policy.main(["--image-tar", str(_image_tar(tmp_path, HEALTHY)), "--output", str(out)]) == 0
    assert json.loads(out.read_text()) == {"findings": []}


@pytest.mark.parametrize("user", ["", "root", "0", "0:0", "root:root"])
def test_root_user_flagged(tmp_path, user):
    config = {**HEALTHY, "User": user}
    ids = [f["id"] for f in image_policy.check({"config": config})]
    assert ids == ["IMG-001"]


def test_secret_env_flagged_but_empty_placeholders_allowed():
    config = {**HEALTHY, "Env": ["APP_SECRET_KEY=abc123", "DB_PASSWORD=", "APP_ENV=prod"]}
    findings = image_policy.check({"config": config})
    assert [(f["id"], f["severity"]) for f in findings] == [("IMG-002", "CRITICAL")]
    assert "abc123" not in json.dumps(findings)  # the value itself is never reported


def test_missing_healthcheck_is_low():
    config = {k: v for k, v in HEALTHY.items() if k != "Healthcheck"}
    assert [(f["id"], f["severity"]) for f in image_policy.check({"config": config})] == [("IMG-003", "LOW")]
