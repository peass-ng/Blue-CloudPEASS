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
            "worker_image": {"value": IMAGE},
            "api_zip": {"value": str(release.deploy.BUILD / "api.zip")},
        },
        "resource_changes": [
            {"mode": "managed", "address": address, "change": {"actions": ["update"]}}
            for address in sorted(release.REQUIRED_RUNTIME)
        ],
        "resource_drift": [],
    }


def test_review_accepts_only_dedicated_runtime_updates():
    summary = release.review_plan(plan(), {"source_version": VERSION})
    assert summary["source_version"] == VERSION
    assert len(summary["changes"]) == 3


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
    with pytest.raises(ValueError, match="all CSPM API and worker runtimes"):
        release.review_plan(candidate, {"source_version": VERSION})
    candidate = plan()
    candidate["variables"]["worker_image"]["value"] = IMAGE.replace("@sha256:", ":latest-")
    with pytest.raises(ValueError, match="immutable"):
        release.review_plan(candidate, {"source_version": VERSION})
