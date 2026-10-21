"""Synthetic derivatives of live CodeArtifact npm package-manager events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_codeartifact_npm_batch80_events.json").read_text())
EXPECTED = {"aws-codeartifact-npm-package-version-published",
            "aws-codeartifact-npm-package-metadata-updated",
            "aws-codeartifact-npm-repository-read"}


def ids(event):
    return {hit.technique_id for hit in detect_aws_events([event]) if hit.technique_id in EXPECTED}


def test_three_live_shapes_match():
    hits = [hit for hit in detect_aws_events(EVENTS) if hit.technique_id in EXPECTED]
    assert len(hits) == 3
    assert {hit.technique_id for hit in hits} == EXPECTED
    assert len({hit.target_id for hit in hits}) == 1


def test_failed_wrong_category_or_account_mismatch_do_not_match():
    for event in EVENTS:
        for change in ({"errorCode": "AccessDeniedException"},
                       {"eventCategory": "Data"},
                       {"managementEvent": False},
                       {"recipientAccountId": "111111111111"}):
            assert not ids({**event, **change})


def test_publish_and_metadata_require_version_and_npm_format():
    for event in EVENTS[:2]:
        changed = copy.deepcopy(event)
        changed["requestParameters"].pop("packageVersion")
        assert not ids(changed)
        changed = copy.deepcopy(event)
        changed["requestParameters"]["packageFormat"] = "generic"
        assert not ids(changed)


def test_read_does_not_claim_a_version_and_needs_valid_package_name():
    assert "packageVersion" not in EVENTS[2]["requestParameters"]
    changed = copy.deepcopy(EVENTS[2])
    changed["requestParameters"]["packageName"] = "bad/name/again"
    assert not ids(changed)
