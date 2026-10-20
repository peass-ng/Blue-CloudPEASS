"""Short signaling TTL detection using a synthetic derivative of live CloudTrail."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENT = json.loads((Path(__file__).parent / "fixtures" /
                    "aws_kvs_channel_ttl_batch71_event.json").read_text())
TECHNIQUE = "aws-kvs-signaling-short-ttl-set"


def _matched(record):
    return [hit for hit in detect_aws_events([record]) if hit.technique_id == TECHNIQUE]


def test_successful_short_ttl_update_matches():
    hits = _matched(EVENT)
    assert len(hits) == 1
    assert hits[0].target_id == EVENT["requestParameters"]["channelARN"]


def test_ttl_failure_and_scope_controls():
    for alteration in ({"errorCode": "AccessDeniedException"},
                       {"readOnly": True}, {"eventCategory": "Data"},
                       {"recipientAccountId": "000000000000"}):
        assert not _matched({**EVENT, **alteration})
    for ttl in (4, 11, 120, True, "5"):
        event = copy.deepcopy(EVENT)
        event["requestParameters"]["singleMasterConfiguration"]["messageTtlSeconds"] = ttl
        assert not _matched(event)
    event = copy.deepcopy(EVENT)
    event["requestParameters"]["channelARN"] = event["requestParameters"]["channelARN"].replace(
        ":999999999999:", ":000000000000:")
    assert not _matched(event)
