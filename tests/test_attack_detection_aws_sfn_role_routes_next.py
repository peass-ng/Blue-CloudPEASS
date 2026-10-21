"""Synthetic derivatives of live batch85 Step Functions management events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_sfn_role_routes_batch85_events.json").read_text())
EXPECTED = {"aws-sfn-teststate-passed-role", "aws-sfn-new-machine-started-with-role",
            "aws-sfn-role-specified-in-update"}


def ids(events):
    return {hit.technique_id for hit in detect_aws_events(events) if hit.technique_id in EXPECTED}


def test_live_shapes_yield_three_distinct_signals():
    assert ids(EVENTS) == EXPECTED
    assert ids([EVENTS[0]]) == {"aws-sfn-teststate-passed-role"}
    assert ids([EVENTS[2]]) == set()
    assert ids([EVENTS[3]]) == {"aws-sfn-role-specified-in-update"}


def test_teststate_requires_completed_state_and_matching_role():
    failed = copy.deepcopy(EVENTS[0])
    failed["responseElements"]["status"] = "FAILED"
    assert not ids([failed])
    wrong_role = copy.deepcopy(EVENTS[0])
    wrong_role["requestParameters"]["roleArn"] = "arn:aws:iam::111111111111:role/foreign"
    assert not ids([wrong_role])
    assert not ids([{**EVENTS[0], "errorCode": "AccessDenied"}])


def test_creation_and_start_require_same_actor_target_and_time_window():
    assert ids(EVENTS[1:3]) == {"aws-sfn-new-machine-started-with-role"}
    wrong_actor = copy.deepcopy(EVENTS[2])
    wrong_actor["userIdentity"]["arn"] = "arn:aws:sts::999999999999:assumed-role/synthetic-other/session"
    assert not ids([EVENTS[1], wrong_actor])
    wrong_machine = copy.deepcopy(EVENTS[2])
    wrong_machine["requestParameters"]["stateMachineArn"] = "arn:aws:states:us-east-1:999999999999:stateMachine:other"
    assert not ids([EVENTS[1], wrong_machine])
    late = copy.deepcopy(EVENTS[2])
    late["eventTime"] = "2026-10-21T00:20:02Z"
    assert not ids([EVENTS[1], late])


def test_update_requires_exact_target_and_accepted_revision():
    event = copy.deepcopy(EVENTS[3])
    event["responseElements"].pop("revisionId")
    assert not ids([event])
    event = copy.deepcopy(EVENTS[3])
    event["recipientAccountId"] = "111111111111"
    assert not ids([event])
    assert not ids([{**EVENTS[3], "eventCategory": "Data"}])
