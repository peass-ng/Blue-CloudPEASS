"""Synthetic derivatives of batch86 Step Functions HTTP connection events."""

from peaso.attack_detection import detect_aws_events


ACCOUNT = "999999999999"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-http-task"
SECRET = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:events!connection/synthetic-http-task/abc123"
IDS = {"aws-sfn-teststate-reveal-connection-secrets",
       "aws-sfn-teststate-connection-secret-read"}


def make_test_state(*, reveal=False, time="2026-10-21T00:00:04Z"):
    return {
        "eventSource": "states.amazonaws.com", "eventName": "TestState",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventTime": time, "eventID": "synthetic-b86-test",
        "userIdentity": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-admin/session"},
        "requestParameters": {
            "definition": "HIDDEN_DUE_TO_SECURITY_REASONS",
            "input": "HIDDEN_DUE_TO_SECURITY_REASONS",
            "roleArn": ROLE, "inspectionLevel": "TRACE", "revealSecrets": reveal,
        },
        "responseElements": {"status": "SUCCEEDED"},
    }


def secret_read(*, time="2026-10-21T00:00:01Z"):
    return {
        "eventSource": "secretsmanager.amazonaws.com", "eventName": "GetSecretValue",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": True,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventTime": time, "eventID": "synthetic-b86-secret",
        "userIdentity": {
            "type": "AssumedRole", "invokedBy": "states.amazonaws.com",
            "sessionContext": {"sessionIssuer": {"arn": ROLE}},
        },
        "requestParameters": {"secretId": SECRET, "secretVersionId": "synthetic-version"},
        "responseElements": None,
    }


def hits(events):
    return {item.technique_id for item in detect_aws_events(events)
            if item.technique_id in IDS}


def test_reveal_and_managed_secret_read_are_separate_signals():
    assert hits([make_test_state(reveal=True)]) == {"aws-sfn-teststate-reveal-connection-secrets"}
    assert hits([make_test_state(), secret_read()]) == {"aws-sfn-teststate-connection-secret-read"}
    assert hits([make_test_state(reveal=True), secret_read()]) == IDS
    assert not hits([secret_read()])


def test_reveal_requires_success_trace_and_explicit_true():
    for change in (lambda x: x["requestParameters"].update(revealSecrets=False),
                   lambda x: x["requestParameters"].update(inspectionLevel="INFO"),
                   lambda x: x["responseElements"].update(status="FAILED"),
                   lambda x: x.update(errorCode="AccessDeniedException"),
                   lambda x: x.update(recipientAccountId="111111111111"),
                   lambda x: x["requestParameters"].update(definition="{}")):
        event = make_test_state(reveal=True)
        change(event)
        assert "aws-sfn-teststate-reveal-connection-secrets" not in hits([event])


def test_correlation_requires_role_service_secret_scope_and_time():
    for change in (lambda x: x["userIdentity"].update(invokedBy="events.amazonaws.com"),
                   lambda x: x["userIdentity"]["sessionContext"]["sessionIssuer"].update(arn=f"arn:aws:iam::{ACCOUNT}:role/other"),
                   lambda x: x["requestParameters"].update(secretId=f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:ordinary"),
                   lambda x: x.update(recipientAccountId="111111111111"),
                   lambda x: x.update(eventTime="2026-10-21T00:00:30Z"),
                   lambda x: x.update(errorCode="AccessDeniedException")):
        event = secret_read()
        change(event)
        assert "aws-sfn-teststate-connection-secret-read" not in hits([make_test_state(), event])
    failed = make_test_state()
    failed["responseElements"]["status"] = "FAILED"
    assert "aws-sfn-teststate-connection-secret-read" not in hits([failed, secret_read()])


def test_legacy_teststate_rule_still_matches_generic_role_testing():
    names = {item.technique_id for item in detect_aws_events([make_test_state()])}
    assert "aws-sfn-teststate-passed-role" in names
