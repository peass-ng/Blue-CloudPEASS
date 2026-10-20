"""Exact Kinesis Video selected-fragment endpoint signal."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENT = json.loads((Path(__file__).parent / "fixtures" /
                    "aws_kvs_fragment_media_batch73_event.json").read_text())
TECHNIQUE = "aws-kvs-fragment-list-media-endpoint-discovered"


def _matches(event):
    return [hit for hit in detect_aws_events([event]) if hit.technique_id == TECHNIQUE]


def test_fragment_endpoint_route_matches():
    hits = _matches(EVENT)
    assert len(hits) == 1
    assert hits[0].target_id == EVENT["requestParameters"]["streamARN"]


def test_failed_or_wrong_scope_does_not_match():
    for change in ({"errorCode": "AccessDeniedException"},
                   {"eventCategory": "Data"}, {"readOnly": False},
                   {"recipientAccountId": "000000000000"}):
        assert not _matches({**EVENT, **change})
    wrong = copy.deepcopy(EVENT)
    wrong["requestParameters"]["aPIName"] = "GET_MEDIA"
    assert not _matches(wrong)
    wrong = copy.deepcopy(EVENT)
    wrong["requestParameters"]["streamARN"] = wrong["requestParameters"]["streamARN"].replace(
        ":999999999999:", ":000000000000:")
    assert not _matches(wrong)
