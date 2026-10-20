"""DynamoDB management-event signals from a syntheticized live event shape."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_dynamodb_backup_stream_batch75_events.json").read_text())
EXPECTED = {
    "aws-dynamodb-old-new-stream-enabled",
    "aws-dynamodb-all-projection-gsi-created",
    "aws-dynamodb-pitr-enabled",
    "aws-dynamodb-backup-created",
    "aws-dynamodb-backup-restored",
    "aws-dynamodb-ttl-enabled",
    "aws-dynamodb-backup-deleted",
    "aws-dynamodb-table-deleted",
}


def _ids(event):
    return {hit.technique_id for hit in detect_aws_events([event]) if
            hit.technique_id in EXPECTED}


def test_eight_accepted_management_routes_match_distinct_signals():
    hits = [hit for hit in detect_aws_events(EVENTS) if hit.technique_id in EXPECTED]
    assert len(hits) == 8
    assert {hit.technique_id for hit in hits} == EXPECTED


def test_failed_and_data_events_do_not_match():
    for event in EVENTS:
        for change in ({"errorCode": "AccessDeniedException"},
                       {"eventCategory": "Data"}, {"readOnly": True}):
            assert not _ids({**event, **change})


def test_stream_gsi_and_pitr_flags_require_the_observed_request():
    stream = copy.deepcopy(EVENTS[0])
    stream["requestParameters"]["streamSpecification"]["streamViewType"] = "KEYS_ONLY"
    assert "aws-dynamodb-old-new-stream-enabled" not in _ids(stream)
    stream = copy.deepcopy(EVENTS[0])
    stream["responseElements"]["tableDescription"]["tableStatus"] = "ACTIVE"
    assert "aws-dynamodb-old-new-stream-enabled" not in _ids(stream)

    gsi = copy.deepcopy(EVENTS[1])
    gsi["requestParameters"]["globalSecondaryIndexUpdates"][0]["create"][
        "projection"]["projectionType"] = "KEYS_ONLY"
    assert "aws-dynamodb-all-projection-gsi-created" not in _ids(gsi)

    pitr = copy.deepcopy(EVENTS[2])
    pitr["requestParameters"]["pointInTimeRecoverySpecification"][
        "pointInTimeRecoveryEnabled"] = False
    assert "aws-dynamodb-pitr-enabled" not in _ids(pitr)


def test_backup_routes_require_names_and_same_account_backup_arn():
    create = copy.deepcopy(EVENTS[3])
    create["requestParameters"].pop("backupName")
    assert "aws-dynamodb-backup-created" not in _ids(create)
    for original, technique in ((EVENTS[4], "aws-dynamodb-backup-restored"),
                                (EVENTS[6], "aws-dynamodb-backup-deleted")):
        foreign = copy.deepcopy(original)
        foreign["requestParameters"]["backupArn"] = foreign["requestParameters"][
            "backupArn"].replace(":999999999999:", ":000000000000:")
        assert technique not in _ids(foreign)
