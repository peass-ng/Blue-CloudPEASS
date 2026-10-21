"""Synthetic derivatives of owned Device Farm session management events."""

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-west-2"
PROJECT_UUID = "11111111-1111-4111-8111-111111111111"
SESSION_UUID = "22222222-2222-4222-8222-222222222222"
GRID_UUID = "33333333-3333-4333-8333-333333333333"
PROJECT = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:project:{PROJECT_UUID}"
MOBILE = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:session:{PROJECT_UUID}/{SESSION_UUID}/00000"
DEVICE = f"arn:aws:devicefarm:{REGION}::device:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
GRID = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:testgrid-project:{GRID_UUID}"
GRID_SESSION = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:testgrid-session:{GRID_UUID}/abcdef0123456789abcdef0123456789"
IDS = {
    "aws-devicefarm-remote-session-created",
    "aws-devicefarm-remote-session-read",
    "aws-devicefarm-remote-session-stop",
    "aws-devicefarm-remote-session-deleted",
    "aws-devicefarm-testgrid-sessions-listed",
    "aws-devicefarm-testgrid-session-read",
    "aws-devicefarm-testgrid-actions-listed",
    "aws-devicefarm-testgrid-artifacts-listed",
}


def rules():
    selected = [r for r in load_rules(product="aws") if r.technique_id in IDS]
    assert len(selected) == 8
    return selected


def event(name, index, request, response=None, read_only=False):
    return {
        "eventSource": "devicefarm.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read_only,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T12:{index:02d}:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("CreateRemoteAccessSession", 0,
              {"projectArn": PROJECT, "deviceArn": DEVICE, "name": "synthetic-session"},
              {"remoteAccessSession": {"arn": MOBILE, "status": "PENDING"}}),
        event("GetRemoteAccessSession", 1, {"arn": MOBILE}, read_only=True),
        event("StopRemoteAccessSession", 2, {"arn": MOBILE},
              {"remoteAccessSession": {"arn": MOBILE.replace(":devicefarm:", ":aatp:"), "status": "STOPPING"}}),
        event("DeleteRemoteAccessSession", 3, {"arn": MOBILE}),
        event("ListTestGridSessions", 4, {"projectArn": GRID}, read_only=True),
        event("GetTestGridSession", 5, {"sessionArn": GRID_SESSION}, read_only=True),
        event("ListTestGridSessionActions", 6, {"sessionArn": GRID_SESSION}, read_only=True),
        event("ListTestGridSessionArtifacts", 7,
              {"sessionArn": GRID_SESSION, "type": "VIDEO"}, read_only=True),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_owned_mobile_and_browser_session_sequence_matches_eight_signals():
    found = hits(sample())
    assert len(found) == 8
    assert {f.technique_id for f in found} == IDS


def test_failed_events_and_foreign_session_targets_fail_closed():
    rows = sample()
    for row in rows:
        row["errorCode"] = "ArgumentException"
    assert hits(rows) == []
    rows = sample()
    rows[1]["requestParameters"]["arn"] = MOBILE.replace(ACCOUNT, "888888888888")
    assert not any(f.technique_id == "aws-devicefarm-remote-session-read" for f in hits(rows))


def test_stop_requires_matching_legacy_response_and_artifact_type():
    rows = sample()
    rows[2]["responseElements"]["remoteAccessSession"]["arn"] = MOBILE.replace(SESSION_UUID, GRID_UUID)
    rows[7]["requestParameters"]["type"] = "OTHER"
    found = hits(rows)
    assert not any(f.technique_id == "aws-devicefarm-remote-session-stop" for f in found)
    assert not any(f.technique_id == "aws-devicefarm-testgrid-artifacts-listed" for f in found)


def test_findings_omit_signed_control_and_artifact_urls():
    rows = sample()
    rows[1]["responseElements"] = {"remoteAccessSession": {"endpoints": {"remoteDriverEndpoint": "https://synthetic.example.invalid/control-secret"}}}
    rows[7]["responseElements"] = {"artifacts": [{"url": "https://synthetic.example.invalid/artifact-secret"}]}
    output = str(hits(rows))
    assert "control-secret" not in output
    assert "artifact-secret" not in output
