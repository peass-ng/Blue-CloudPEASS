"""Synthetic derivatives of live batch87 UpdateMapRun management events."""

from peaso.attack_detection import detect_aws_events


ACCOUNT = "999999999999"
MAP_RUN = ("arn:aws:states:us-east-1:999999999999:mapRun:"
           "synthetic-machine/synthetic-map:00000000-0000-4000-8000-000000000001")
IDS = {
    "aws-sfn-map-run-runtime-updated", "aws-sfn-map-run-unbounded-concurrency",
    "aws-sfn-map-run-zero-failure-tolerance",
    "aws-sfn-map-run-nonzero-failure-tolerance",
}


def make_event(**settings):
    return {
        "eventSource": "states.amazonaws.com", "eventName": "UpdateMapRun",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-b87-update", "eventTime": "2026-10-21T00:00:00Z",
        "userIdentity": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-admin/session"},
        "requestParameters": {"mapRunArn": MAP_RUN, **settings},
        "responseElements": None,
    }


def ids(event):
    return {hit.technique_id for hit in detect_aws_events([event])
            if hit.technique_id in IDS}


def test_specific_control_changes_have_distinct_signals():
    generic = "aws-sfn-map-run-runtime-updated"
    assert ids(make_event(maxConcurrency=2)) == {generic}
    assert ids(make_event(maxConcurrency=0)) == {generic, "aws-sfn-map-run-unbounded-concurrency"}
    assert ids(make_event(toleratedFailureCount=0)) == {generic, "aws-sfn-map-run-zero-failure-tolerance"}
    assert ids(make_event(toleratedFailurePercentage=0.0)) == {generic, "aws-sfn-map-run-zero-failure-tolerance"}
    assert ids(make_event(toleratedFailureCount=1)) == {generic, "aws-sfn-map-run-nonzero-failure-tolerance"}
    assert ids(make_event(toleratedFailurePercentage=50.0)) == {generic, "aws-sfn-map-run-nonzero-failure-tolerance"}


def test_error_foreign_target_and_nonmanagement_events_do_not_match():
    for mutation in (
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e.update(recipientAccountId="111111111111"),
        lambda e: e.update(awsRegion="eu-west-1"),
        lambda e: e.update(readOnly=True),
        lambda e: e.update(eventCategory="Data"),
        lambda e: e["requestParameters"].update(mapRunArn="arn:aws:states:us-east-1:999999999999:stateMachine:other"),
    ):
        event = make_event(maxConcurrency=0)
        mutation(event)
        assert not ids(event)


def test_missing_or_malformed_settings_do_not_match():
    for settings in ({}, {"maxConcurrency": True}, {"maxConcurrency": -1},
                     {"toleratedFailureCount": "0"},
                     {"toleratedFailurePercentage": 101},
                     {"maxConcurrency": 1, "toleratedFailurePercentage": -1}):
        assert not ids(make_event(**settings))
