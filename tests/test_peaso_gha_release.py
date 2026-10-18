"""Safety checks for plans dispatched through wiki-infrastructure Actions."""
from __future__ import annotations

import pytest

from scripts import peaso_gha_release as release


VERSION = "a" * 64
IMAGE = release.WORKER_REPOSITORY + "@sha256:" + "b" * 64


def plan():
    return {
        "variables": {
            "source_version": {"value": VERSION},
            "region": {"value": release.REGION},
            "enable_public_customer_role_template": {"value": True},
            "gcp_platform_sa_secret_arn": {"value": "arn:aws:secretsmanager:us-east-1:202533532952:secret:hacktricks-cspm-gcp-platform-sa-ABC123"},
            "worker_image": {"value": IMAGE},
            "api_zip": {"value": str(release.deploy.BUILD / "api.zip")},
        },
        "resource_changes": [
            {"mode": "managed", "address": address, "change": {"actions": ["update"]}}
            for address in sorted(release.REQUIRED_RUNTIME - {'aws_ecs_task_definition.tasks'})
        ] + [
            {"mode": "managed", "address": f'aws_ecs_task_definition.tasks["{stage}"]',
             "change": {"actions": ["delete", "create"]}}
            for stage in ('collector', 'analyzer')
        ],
        "resource_drift": [],
    }


def test_review_accepts_only_dedicated_runtime_updates():
    summary = release.review_plan(plan(), {"source_version": VERSION})
    assert summary["source_version"] == VERSION
    assert len(summary["changes"]) == 4


@pytest.mark.parametrize("address,actions", [
    ("aws_lambda_function.wiki_backend", ["update"]),
    ("aws_lambda_function.api", ["delete"]),
    ("module.other.aws_lambda_function.api", ["update"]),
])
def test_review_rejects_unowned_or_destructive_change(address, actions):
    candidate = plan()
    candidate["resource_changes"].append(
        {"mode": "managed", "address": address, "change": {"actions": actions}}
    )
    with pytest.raises(ValueError):
        release.review_plan(candidate, {"source_version": VERSION})


def test_review_requires_complete_runtime_and_frozen_image():
    candidate = plan()
    candidate["resource_changes"].pop()
    with pytest.raises(ValueError, match="both collector and analyzer"):
        release.review_plan(candidate, {"source_version": VERSION})
    candidate = plan()
    candidate["resource_changes"].pop(0)
    with pytest.raises(ValueError, match="all CSPM API and worker runtimes"):
        release.review_plan(candidate, {"source_version": VERSION})
    candidate = plan()
    candidate["variables"]["worker_image"]["value"] = IMAGE.replace("@sha256:", ":latest-")
    with pytest.raises(ValueError, match="immutable"):
        release.review_plan(candidate, {"source_version": VERSION})


@pytest.mark.parametrize("member_count,accepted", [(2504, True), (2601, True), (2602, False)])
def test_current_source_member_growth_keeps_an_explicit_upper_bound(tmp_path, monkeypatch, member_count, accepted):
    import json
    import zipfile

    manifest = {"source_version": VERSION, "files": {}}
    archive = tmp_path / f"peaso-source-{VERSION}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
        for index in range(member_count - 1):
            target.writestr(f"source/{index:04d}.txt", b"x")
        target.writestr("release.json", json.dumps(manifest, indent=2).encode())
    monkeypatch.setattr(release.deploy, "BUILD", tmp_path)
    if accepted:
        assert release.verify_source_archive(manifest) == archive
    else:
        with pytest.raises(ValueError, match="member count"):
            release.verify_source_archive(manifest)
