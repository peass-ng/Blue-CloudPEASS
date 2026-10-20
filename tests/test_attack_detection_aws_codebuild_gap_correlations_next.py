"""Synthetic derivatives of the live CodeBuild debug and source auth events."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from peaso.attack_detection import detect_aws_events

ACCOUNT = "999999999999"
REGION = "us-east-1"
PROJECT = "synthetic-project"
PROJECT_ARN = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/{PROJECT}"
SECRET = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:synthetic-auth-abc123"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(source, name, request, response, *, minutes=0, read=False):
    return {"eventSource": source, "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": read,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": f"11111111-1111-4111-8111-{minutes+1:012d}",
            "eventTime": (BASE + timedelta(minutes=minutes)).isoformat(),
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": ACTOR},
            "requestParameters": request, "responseElements": response}


def synthetic_rules():
    # Load only the reviewed rules; no private account fixture or external checkout.
    from peaso.attack_detection import Rule
    return [
        Rule(id="synthetic-debug", title="Synthetic debug session", description="Synthetic",
             level="high", technique_id="synthetic", product="aws",
             selection={"event.source": "ssm.amazonaws.com", "event.name": "CodeBuildDebugSessionStarted",
                        "event.outcome": "success", "request.codebuild_debug_session_started": True}),
        Rule(id="synthetic-auth", title="Synthetic source auth read", description="Synthetic",
             level="medium", technique_id="synthetic", product="aws",
             selection={"event.source": "secretsmanager.amazonaws.com",
                        "event.name": "CodeBuildSourceAuthSecretReadAfterUpdate",
                        "event.outcome": "success",
                        "request.codebuild_source_auth_secret_read_after_update": True}),
    ]


def test_debug_session_correlates_exact_build_uuid_without_token_leak():
    build = event("codebuild.amazonaws.com", "StartBuild",
                  {"projectName": PROJECT, "debugSessionEnabled": True,
                   "buildspecOverride": "SYNTHETIC_PRIVATE_BUILDSPEC"},
                  {"build": {"id": f"{PROJECT}:{UUID}", "projectName": PROJECT,
                             "debugSession": {"sessionEnabled": True}}})
    session = event("ssm.amazonaws.com", "StartSession", {"target": "codebuild:" + UUID},
                    {"sessionId": "synthetic-session", "tokenValue": "SYNTHETIC_PRIVATE_TOKEN",
                     "streamUrl": "https://example.invalid/SYNTHETIC_PRIVATE_URL"}, minutes=1)
    found = detect_aws_events([session, build], synthetic_rules())
    assert len(found) == 1 and found[0].target_id == PROJECT_ARN
    assert found[0].evidence["correlation"]["start_build_event_id"] == build["eventID"]
    for private in (UUID, "SYNTHETIC_PRIVATE_BUILDSPEC", "SYNTHETIC_PRIVATE_TOKEN", "SYNTHETIC_PRIVATE_URL"):
        assert private not in str(found[0])
    for replacement in ({"target": "codebuild:ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"},
                        {"target": "i-0123456789abcdef0"}):
        bad = deepcopy(session); bad["requestParameters"] = replacement
        assert detect_aws_events([build, bad], synthetic_rules()) == []
    bad = deepcopy(build); bad["requestParameters"]["debugSessionEnabled"] = False
    assert detect_aws_events([bad, session], synthetic_rules()) == []
    bad = deepcopy(session); bad["eventTime"] = (BASE + timedelta(minutes=31)).isoformat()
    assert detect_aws_events([build, bad], synthetic_rules()) == []
    bad = deepcopy(session); bad["errorCode"] = "AccessDeniedException"
    assert detect_aws_events([build, bad], synthetic_rules()) == []


def test_source_auth_read_requires_matching_returned_secret_and_actor():
    update = event("codebuild.amazonaws.com", "UpdateProject",
                   {"name": PROJECT_ARN, "source": {"type": "GITHUB",
                     "location": "https://example.invalid/SYNTHETIC_PRIVATE_URL",
                     "auth": {"type": "SECRETS_MANAGER", "resource": SECRET}}},
                   {"project": {"arn": PROJECT_ARN, "name": PROJECT,
                     "source": {"auth": {"type": "SECRETS_MANAGER", "resource": SECRET}}}})
    read = event("secretsmanager.amazonaws.com", "GetSecretValue",
                 {"secretId": SECRET}, None, minutes=1, read=True)
    found = detect_aws_events([read, update], synthetic_rules())
    assert len(found) == 1 and found[0].target_id == PROJECT_ARN
    assert found[0].evidence["correlation"]["update_project_event_id"] == update["eventID"]
    assert SECRET not in str(found[0]) and "SYNTHETIC_PRIVATE_URL" not in str(found[0])
    for key, value in (("secretId", SECRET + "-other"),):
        bad = deepcopy(read); bad["requestParameters"][key] = value
        assert detect_aws_events([update, bad], synthetic_rules()) == []
    bad = deepcopy(read); bad["userIdentity"]["arn"] = f"arn:aws:iam::{ACCOUNT}:user/other"
    assert detect_aws_events([update, bad], synthetic_rules()) == []
    bad = deepcopy(update); bad["responseElements"]["project"]["source"]["auth"]["resource"] = SECRET + "-other"
    assert detect_aws_events([bad, read], synthetic_rules()) == []
    bad = deepcopy(read); bad["eventTime"] = (BASE + timedelta(minutes=61)).isoformat()
    assert detect_aws_events([update, bad], synthetic_rules()) == []
    bad = deepcopy(read); bad["errorCode"] = "AccessDeniedException"
    assert detect_aws_events([update, bad], synthetic_rules()) == []
