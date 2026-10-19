"""A role description edit must not look like a twelve-hour session cap."""

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(
    id="role-max-session",
    title="Maximum role session duration",
    level="medium",
    description="The role cap was set to twelve hours.",
    technique_id="aws-iam-update-role-max-session-duration",
    product="aws",
    selection={
        "event.source": "iam.amazonaws.com",
        "event.name": "UpdateRole",
        "event.outcome": "success",
        "request.max_session_duration": 43200,
    },
)


def test_only_successful_twelve_hour_role_update_matches():
    event = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "UpdateRole",
        "requestParameters": {"roleName": "example-role", "maxSessionDuration": 43200},
        "responseElements": None,
    }
    assert len(detect_aws_events([event], (RULE,))) == 1
    for changed in (
        {"requestParameters": {"roleName": "example-role", "description": "approved"}},
        {"requestParameters": {"roleName": "example-role", "maxSessionDuration": 3600}},
        {"requestParameters": {"roleName": "example-role", "maxSessionDuration": True}},
        {"errorCode": "AccessDenied"},
        {"eventSource": "sts.amazonaws.com"},
    ):
        assert detect_aws_events([{**event, **changed}], (RULE,)) == []
