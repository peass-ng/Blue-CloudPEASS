"""Synthetic derivatives for Kinesis Video endpoint discovery routes."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_kvs_more_endpoints_batch72_events.json").read_text())
EXPECTED = {
    "aws-kvs-get-images-endpoint-discovered",
    "aws-kvs-get-clip-endpoint-discovered",
    "aws-kvs-hls-endpoint-discovered",
    "aws-kvs-dash-endpoint-discovered",
    "aws-kvs-put-media-endpoint-discovered",
    "aws-kvs-signaling-master-endpoint-discovered",
}


def _hits(records):
    return {h.technique_id for h in detect_aws_events(records) if h.technique_id in EXPECTED}


def test_six_endpoint_routes_are_distinct():
    assert len(EVENTS) == 6
    assert _hits(EVENTS) == EXPECTED
    for event in EVENTS:
        assert len(_hits([event])) == 1


def test_failed_or_mismatched_requests_do_not_match():
    for event in EVENTS:
        for changed in ({"errorCode": "AccessDeniedException"},
                        {"eventCategory": "Data"}, {"readOnly": False},
                        {"recipientAccountId": "000000000000"}):
            assert not _hits([{**event, **changed}])
    media = copy.deepcopy(EVENTS[0])
    media["requestParameters"]["streamARN"] = media["requestParameters"]["streamARN"].replace(
        ":999999999999:", ":000000000000:")
    assert not _hits([media])
    master = copy.deepcopy(EVENTS[-1])
    master["requestParameters"]["singleMasterChannelEndpointConfiguration"]["role"] = "VIEWER"
    assert not _hits([master])
