"""Shape-preserving synthetic derivatives of live batch79 CodeArtifact events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_codeartifact_batch79_events.json").read_text())
EXPECTED = {"aws-codeartifact-authorization-token-requested",
            "aws-codeartifact-generic-package-version-published",
            "aws-codeartifact-generic-asset-read"}


def ids(event):
    return {hit.technique_id for hit in detect_aws_events([event]) if hit.technique_id in EXPECTED}


def test_live_event_shapes_match_the_three_rules():
    hits = [hit for hit in detect_aws_events(EVENTS) if hit.technique_id in EXPECTED]
    assert len(hits) == 3
    assert {hit.technique_id for hit in hits} == EXPECTED


def test_errors_and_wrong_event_categories_do_not_match():
    for event in EVENTS:
        for change in ({"errorCode": "AccessDeniedException"},
                       {"eventCategory": "Data"}, {"managementEvent": False},
                       {"recipientAccountId": "invalid"}):
            assert not ids({**event, **change})


def test_published_version_requires_matching_response_and_digest():
    event = copy.deepcopy(EVENTS[1])
    event["responseElements"]["version"] = "1.2.0"
    assert not ids(event)
    event = copy.deepcopy(EVENTS[1])
    event["responseElements"]["status"] = "Unfinished"
    assert not ids(event)
    event = copy.deepcopy(EVENTS[1])
    event["requestParameters"]["assetSHA256"] = "invalid"
    assert not ids(event)


def test_token_and_asset_require_the_expected_scoped_coordinates():
    event = copy.deepcopy(EVENTS[0])
    event["requestParameters"]["domain"] = "invalid/name"
    assert not ids(event)
    event = copy.deepcopy(EVENTS[2])
    event["requestParameters"]["asset"] = ""
    assert not ids(event)
    event = copy.deepcopy(EVENTS[2])
    event["requestParameters"]["format"] = "npm"
    assert not ids(event)
