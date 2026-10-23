"""Synthetic derivatives of an owned DataSync S3 delegated-copy lab."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-datasync-role"
LOCATION = f"arn:aws:datasync:us-east-1:{ACCOUNT}:location/loc-aaaaaaaaaaaaaaaaa"
DEST = f"arn:aws:datasync:us-east-1:{ACCOUNT}:location/loc-bbbbbbbbbbbbbbbbb"
TASK = f"arn:aws:datasync:us-east-1:{ACCOUNT}:task/task-ccccccccccccccccc"
IDS = {
    "CreateLocationS3": ("aws-datasync-s3-location-passrole", "request.datasync_s3_role_bound"),
    "UpdateLocationS3": ("aws-datasync-s3-location-role-update", "request.datasync_s3_role_updated"),
    "CreateTask": ("aws-datasync-scheduled-transfer", "request.datasync_scheduled_task_created"),
}
RULES = [
    Rule(id=name, title=name, description="synthetic", level="low", product="aws",
         technique_id=technique, selection={"event.source": "datasync.amazonaws.com",
                                            "event.name": name, "event.outcome": "success", fact: True})
    for name, (technique, fact) in IDS.items()
]
CORRELATED = Rule(
    id="synthetic-datasync-start", title="New role task started",
    description="synthetic", level="medium", product="aws",
    technique_id="aws-datasync-new-role-task-started",
    selection={"event.source": "datasync.amazonaws.com",
               "event.name": "StartTaskExecution", "event.outcome": "success",
               "request.datasync_new_role_task_started": True},
)


def event(name):
    request = {
        "CreateLocationS3": {"s3BucketArn": "arn:aws:s3:::synthetic-source",
                             "s3Config": {"bucketAccessRoleArn": ROLE}},
        "UpdateLocationS3": {"locationArn": LOCATION, "subdirectory": "/",
                             "s3Config": {"bucketAccessRoleArn": ROLE}},
        "CreateTask": {"sourceLocationArn": LOCATION, "destinationLocationArn": DEST,
                       "schedule": {"scheduleExpression": "cron(0 12 * * ? *)", "status": "ENABLED"}},
    }[name]
    response = ({"taskArn": TASK} if name == "CreateTask" else
                {"locationArn": LOCATION} if name == "CreateLocationS3" else {})
    return {"eventSource": "datasync.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT,
            "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-actor"},
            "eventTime": {"CreateLocationS3": "2026-10-23T01:00:00Z",
                          "CreateTask": "2026-10-23T01:01:00Z",
                          "UpdateLocationS3": "2026-10-23T01:02:00Z"}[name],
            "requestParameters": request, "responseElements": response}


def hits(records):
    return detect_aws_events(records, RULES)


def test_three_accepted_setup_routes_and_private_identifiers_omitted():
    matches = hits([event(name) for name in IDS])
    assert {hit.technique_id for hit in matches} == {pair[0] for pair in IDS.values()}
    assert len(matches) == 3
    assert ROLE not in str(matches)
    assert LOCATION not in str(matches)
    assert TASK not in str(matches)


def test_denied_malformed_and_unscheduled_requests_are_excluded():
    variants = []
    for name in IDS:
        denied = event(name)
        denied["errorCode"] = "AccessDeniedException"
        variants.append(denied)
    no_role = event("CreateLocationS3")
    del no_role["requestParameters"]["s3Config"]
    variants.append(no_role)
    no_role_update = event("UpdateLocationS3")
    del no_role_update["requestParameters"]["s3Config"]
    variants.append(no_role_update)
    disabled = event("CreateTask")
    disabled["requestParameters"]["schedule"]["status"] = "DISABLED"
    variants.append(disabled)
    read_only = deepcopy(event("CreateTask"))
    read_only["readOnly"] = True
    variants.append(read_only)
    assert hits(variants) == []


def test_new_role_task_start_requires_same_actor_task_and_time():
    created = event("CreateLocationS3")
    task = event("CreateTask")
    start = deepcopy(task)
    start.update(eventName="StartTaskExecution", eventTime="2026-10-23T01:03:00Z",
                 requestParameters={"taskArn": TASK},
                 responseElements={"taskExecutionArn": TASK + "/execution/exec-synthetic"})
    assert len(detect_aws_events([start, task, created], [CORRELATED])) == 1
    for change in (
        lambda c, t, s: s["userIdentity"].update(arn=f"arn:aws:iam::{ACCOUNT}:user/other"),
        lambda c, t, s: s["requestParameters"].update(taskArn=TASK + "-other"),
        lambda c, t, s: s.update(eventTime="2026-10-23T03:04:00Z"),
        lambda c, t, s: c.update(errorCode="AccessDeniedException"),
        lambda c, t, s: t["requestParameters"].update(sourceLocationArn=DEST),
    ):
        c, t, s = deepcopy((created, task, start))
        change(c, t, s)
        assert detect_aws_events([c, t, s], [CORRELATED]) == []
