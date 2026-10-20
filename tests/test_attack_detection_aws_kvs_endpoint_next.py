"""Kinesis Video endpoint signals from sanitized management-event derivatives."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_kvs_endpoint_batch70_events.json").read_text())
EXPECTED = {
    "aws-kvs-signaling-viewer-endpoint-discovered",
    "aws-kvs-get-media-endpoint-discovered",
    "aws-kvs-list-fragments-endpoint-discovered",
}


def _hits(events):
    return {hit.technique_id for hit in detect_aws_events(events)
            if hit.technique_id in EXPECTED}


def test_each_accepted_endpoint_event_matches_only_its_route():
    assert len(EVENTS) == 3
    assert _hits(EVENTS) == EXPECTED
    for event in EVENTS:
        assert len(_hits([event])) == 1


def test_failures_and_non_management_events_are_not_reported():
    for event in EVENTS:
        for change in ({"errorCode": "AccessDeniedException"},
                       {"eventCategory": "Data"}, {"readOnly": False},
                       {"recipientAccountId": "000000000000"}):
            assert not _hits([{**event, **change}])


def test_endpoint_scope_and_requested_api_are_checked():
    media = copy.deepcopy(EVENTS[1])
    media["requestParameters"]["aPIName"] = "PUT_MEDIA"
    assert not _hits([media])
    media["requestParameters"]["aPIName"] = ["GET_MEDIA"]
    assert not _hits([media])
    media = copy.deepcopy(EVENTS[1])
    media["requestParameters"]["streamARN"] = media["requestParameters"]["streamARN"].replace(
        ":999999999999:", ":000000000000:")
    assert not _hits([media])

    viewer = copy.deepcopy(EVENTS[0])
    viewer["requestParameters"]["singleMasterChannelEndpointConfiguration"]["role"] = "MASTER"
    assert not _hits([viewer])
    viewer = copy.deepcopy(EVENTS[0])
    viewer["requestParameters"]["singleMasterChannelEndpointConfiguration"]["protocols"] = ["WSS"]
    assert not _hits([viewer])
