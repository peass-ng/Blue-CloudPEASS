"""Live-shaped CodeBuild management events and negative selectors."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


PUBLIC = Rule(
    id="codebuild-public", title="Public CodeBuild project", level="high",
    description="Visibility accepted", technique_id="aws-codebuild-project-public-visibility",
    product="aws", selection={
        "event.source": "codebuild.amazonaws.com",
        "event.name": "UpdateProjectVisibility",
        "event.outcome": "success",
        "request.codebuild_public_visibility": True,
    },
)
DELETE = Rule(
    id="codebuild-delete", title="CodeBuild project deleted", level="high",
    description="Deletion accepted", technique_id="aws-codebuild-delete-project",
    product="aws", selection={
        "event.source": "codebuild.amazonaws.com",
        "event.name": "DeleteProject",
        "event.outcome": "success",
        "request.codebuild_project_deleted": True,
    },
)
DELETE_CREDENTIAL = Rule(
    id="codebuild-delete-credential", title="CodeBuild credential deleted", level="high",
    description="Credential deletion accepted", technique_id="aws-codebuild-delete-source-credentials",
    product="aws", selection={
        "event.source": "codebuild.amazonaws.com",
        "event.name": "DeleteSourceCredentials",
        "event.outcome": "success",
        "request.codebuild_source_credential_deleted": True,
    },
)
ARN = "arn:aws:codebuild:us-east-1:947247140022:project/peasso-detection-test-build"


def _event(name: str, request: dict) -> dict:
    return {
        "eventSource": "codebuild.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "awsRegion": "us-east-1", "recipientAccountId": "947247140022",
        "eventID": "c5cc4ab9-9776-4d8d-beac-e018bc239cb1",
        "eventTime": "2026-10-19T08:45:31Z",
        "userIdentity": {"type": "IAMUser", "accountId": "947247140022",
                         "arn": "arn:aws:iam::947247140022:user/lab"},
        "requestParameters": request, "responseElements": None,
    }


def _matches(event: dict) -> list:
    return detect_aws_events([event], [PUBLIC, DELETE, DELETE_CREDENTIAL])


def test_live_shaped_public_private_and_delete_events() -> None:
    public = _event("UpdateProjectVisibility", {"projectArn": ARN, "projectVisibility": "PUBLIC_READ"})
    private = _event("UpdateProjectVisibility", {"projectArn": ARN, "projectVisibility": "PRIVATE"})
    deleted = _event("DeleteProject", {"name": ARN})
    assert [m.technique_id for m in _matches(public)] == [PUBLIC.technique_id]
    assert _matches(private) == []
    assert [m.technique_id for m in _matches(deleted)] == [DELETE.technique_id]


def test_failed_incomplete_and_foreign_project_events_do_not_match() -> None:
    for original in (
        _event("UpdateProjectVisibility", {"projectArn": ARN, "projectVisibility": "PUBLIC_READ"}),
        _event("DeleteProject", {"name": ARN}),
    ):
        for edit in ("errorCode", "response_error", "missing_project", "foreign_account", "read_only", "data_event"):
            row = deepcopy(original)
            if edit == "errorCode": row["errorCode"] = "AccessDeniedException"
            if edit == "response_error": row["responseElements"] = {"errorCode": "AccessDeniedException"}
            if edit == "missing_project": row["requestParameters"] = {}
            if edit == "foreign_account": row["recipientAccountId"] = "000000000000"
            if edit == "read_only": row["readOnly"] = True
            if edit == "data_event": row["eventCategory"] = "Data"
            assert _matches(row) == [], edit


def test_source_credential_delete_requires_matching_response_arn() -> None:
    arn = "arn:aws:codebuild:us-east-1:947247140022:token/bitbucket"
    row = _event("DeleteSourceCredentials", {"arn": arn})
    row["responseElements"] = {"arn": arn}
    assert [m.technique_id for m in _matches(row)] == [DELETE_CREDENTIAL.technique_id]
    row["responseElements"] = None
    assert _matches(row) == []
    row["responseElements"] = {"arn": arn.replace("bitbucket", "github")}
    assert _matches(row) == []
    row["responseElements"] = {"arn": arn}
    row["errorCode"] = "AccessDeniedException"
    assert _matches(row) == []
