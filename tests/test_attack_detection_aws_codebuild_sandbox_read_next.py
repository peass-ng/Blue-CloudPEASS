"""Synthetic dispatch and privacy checks for five CodeBuild sandbox/read signals."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
REGION = "us-east-1"
PROJECT = "synthetic-project"
SANDBOX = PROJECT + ":aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SENSITIVE = "SYNTHETIC_PRIVATE_VALUE"
CASES = [
    ("UpdateProject", {"name": f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/{PROJECT}",
                       "tags": "HIDDEN_DUE_TO_SECURITY_REASONS"},
     {"project": {"name": PROJECT, "tags": [{"value": SENSITIVE}]}}, False,
     "request.codebuild_project_tags_submitted"),
    ("BatchGetProjects", {"names": [PROJECT]},
     {"projects": [{"environment": {"environmentVariables": [{"value": SENSITIVE}]}}]}, True,
     "request.codebuild_project_configuration_read"),
    ("BatchGetBuilds", {"ids": [SANDBOX]},
     {"builds": [{"environment": {"environmentVariables": [{"value": SENSITIVE}]}}]}, True,
     "request.codebuild_build_configuration_read"),
    ("StartCommandExecution", {"sandboxId": SANDBOX, "command": SENSITIVE, "type": "SHELL"},
     {"commandExecution": {"command": SENSITIVE}}, False,
     "request.codebuild_sandbox_command_started"),
    ("StartSandboxConnection", {"sandboxId": SANDBOX},
     {"ssmSession": {"sessionId": SENSITIVE, "streamUrl": SENSITIVE,
                      "tokenValue": SENSITIVE}}, True,
     "request.codebuild_sandbox_connection_started"),
]


def event(name: str, params: dict, response: dict, read_only: bool) -> dict:
    return {"eventSource": "codebuild.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": read_only,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": "11111111-1111-4111-8111-111111111111",
            "eventTime": "2026-10-20T00:00:00Z",
            "userIdentity": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic/lab",
                             "accountId": ACCOUNT},
            "requestParameters": params, "responseElements": response}


@pytest.mark.parametrize("name,params,response,read_only,signal", CASES)
def test_codebuild_sandbox_read_dispatch(name: str, params: dict, response: dict,
                                         read_only: bool, signal: str) -> None:
    rule = Rule(id="synthetic-" + name, title="Synthetic CodeBuild route",
                description="Synthetic dispatch check", level="medium",
                technique_id="synthetic-route", product="aws",
                selection={"event.source": "codebuild.amazonaws.com",
                           "event.name": name, "event.outcome": "success", signal: True})
    row = event(name, params, response, read_only)
    found = detect_aws_events([row], [rule])
    assert len(found) == 1
    assert found[0].actor_id and found[0].target_id
    assert SENSITIVE not in str(found[0])
    for update in ({"errorCode": "AccessDenied"}, {"readOnly": not read_only},
                   {"eventSource": "wrong.amazonaws.com"}):
        denied = deepcopy(row)
        denied.update(update)
        assert detect_aws_events([denied], [rule]) == []
