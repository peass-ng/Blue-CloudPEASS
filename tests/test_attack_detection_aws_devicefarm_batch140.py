"""Synthetic derivatives of owned Device Farm management events."""

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-west-2"
PROJECT = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:project:11111111-1111-4111-8111-111111111111"
UPLOAD = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:upload:11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222"
GRID = f"arn:aws:devicefarm:{REGION}:{ACCOUNT}:testgrid-project:33333333-3333-4333-8333-333333333333"
IDS = {
    "aws-devicefarm-project-configuration-read",
    "aws-devicefarm-runs-listed",
    "aws-devicefarm-uploads-listed",
    "aws-devicefarm-upload-url-requested",
    "aws-devicefarm-testgrid-url-created",
    "aws-devicefarm-upload-deleted",
    "aws-devicefarm-project-deleted",
    "aws-devicefarm-testgrid-project-deleted",
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
        event("GetProject", 0, {"arn": PROJECT}, read_only=True),
        event("ListRuns", 7, {"arn": PROJECT}, read_only=True),
        event("ListUploads", 1, {"arn": PROJECT}, read_only=True),
        event("GetUpload", 2, {"arn": UPLOAD}, read_only=True),
        event("CreateTestGridUrl", 3,
              {"projectArn": GRID, "expiresInSeconds": 60},
              {"url": "HIDDEN_DUE_TO_SECURITY_REASONS", "expires": "2026-10-21T12:04:00Z"}),
        event("DeleteUpload", 4, {"arn": UPLOAD}),
        event("DeleteProject", 5, {"arn": PROJECT}),
        event("DeleteTestGridProject", 6, {"projectArn": GRID}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def by_name(rows, name):
    return next(row for row in rows if row["eventName"] == name)


def test_eight_owned_read_url_and_delete_routes_match():
    findings = hits(sample())
    assert len(findings) == 8
    assert {f.technique_id for f in findings} == IDS


def test_denied_calls_and_wrong_account_arn_do_not_match():
    rows = sample()
    for row in rows:
        row["errorCode"] = "AccessDeniedException"
    assert hits(rows) == []
    rows = sample()
    upload_read = by_name(rows, "GetUpload")
    upload_read["requestParameters"]["arn"] = upload_read["requestParameters"]["arn"].replace(ACCOUNT, "888888888888")
    assert not any(f.technique_id == "aws-devicefarm-upload-url-requested" for f in hits(rows))


def test_signed_url_event_requires_successful_redacted_response():
    rows = sample()
    assert any(f.technique_id == "aws-devicefarm-testgrid-url-created" for f in hits(rows))
    by_name(rows, "CreateTestGridUrl")["responseElements"] = None
    assert not any(f.technique_id == "aws-devicefarm-testgrid-url-created" for f in hits(rows))
    rows = sample()
    by_name(rows, "CreateTestGridUrl")["requestParameters"]["expiresInSeconds"] = 90000
    assert not any(f.technique_id == "aws-devicefarm-testgrid-url-created" for f in hits(rows))


def test_findings_omit_any_signed_url_or_project_secret():
    rows = sample()
    by_name(rows, "GetProject")["responseElements"] = {"project": {"environmentVariables": [{"name": "LAB_SECRET", "value": "synthetic-secret-value"}]}}
    by_name(rows, "CreateTestGridUrl")["responseElements"]["url"] = "https://synthetic.example.invalid/signed-credential"
    output = str(hits(rows))
    assert "synthetic-secret-value" not in output
    assert "signed-credential" not in output
