"""Synthetic CloudTrail derivatives of the owned CodeCommit consumer lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
REPO = "synthetic-repository"
PIPELINE = "synthetic-pipeline"
PIPELINE_PROJECT = "synthetic-pipeline-build"
DIRECT_PROJECT = "synthetic-direct-build"
COMMIT = "a" * 40
PUSHER = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-pusher/session"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-build-role"
IDS = {"dd5e53c2-dcad-4ad1-98b3-4f12bf7ef835",
       "be8089e4-f855-4cba-82dc-cafc0671e55f"}


def selected():
    return [r for r in load_rules(product="aws") if r.id in IDS]


def event(source, name, minute, request, response, actor=PUSHER):
    return {"eventSource": source + ".amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "userIdentity": {"arn": actor, "accountId": ACCOUNT},
            "eventID": "synthetic-" + name + "-" + str(minute),
            "eventTime": f"2026-10-20T13:{minute:02d}:00Z",
            "requestParameters": request, "responseElements": response}


def events():
    push = event("codecommit", "GitPush", 10,
                 {"references": [{"ref": "refs/heads/main", "commit": COMMIT}]}, None)
    push["additionalEventData"] = {"repositoryName": REPO, "dataTransferred": True}
    definition = event("codepipeline", "CreatePipeline", 1,
        {"pipeline": {"name": PIPELINE, "stages": [
            {"name": "Source", "actions": [{"actionTypeId": {"category": "Source",
             "provider": "CodeCommit"}, "configuration": {"RepositoryName": REPO,
             "BranchName": "main"}}]},
            {"name": "Build", "actions": [{"actionTypeId": {"category": "Build",
             "provider": "CodeBuild"}, "configuration": {"ProjectName": PIPELINE_PROJECT}}]}]}},
        {"pipeline": {"name": PIPELINE}})
    start = event("codepipeline", "StartPipelineExecution", 11,
                  {"name": PIPELINE}, {"pipelineExecutionId": "synthetic-execution"},
                  f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-event-role/session")
    pipeline_build = event("codebuild", "StartBuild", 12,
        {"projectName": PIPELINE_PROJECT, "sourceVersion": "synthetic-artifact"},
        {"build": {"projectName": PIPELINE_PROJECT, "source": {"type": "CODEPIPELINE"},
                   "serviceRole": ROLE, "initiator": "codepipeline/" + PIPELINE,
                   "resolvedSourceVersion": COMMIT}},
        f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-pipeline-role/session")
    direct_build = event("codebuild", "StartBuild", 13,
        {"projectName": DIRECT_PROJECT, "sourceVersion": COMMIT},
        {"build": {"projectName": DIRECT_PROJECT,
                   "source": {"type": "CODECOMMIT", "location":
                              f"https://git-codecommit.{REGION}.amazonaws.com/v1/repos/{REPO}"},
                   "serviceRole": ROLE}})
    return [push, definition, start, pipeline_build, direct_build]


def test_exact_pushed_revision_starts_two_consumers_without_hash_leak():
    hits = detect_aws_events(events(), selected())
    assert len(hits) == len({h.rule_id for h in hits}) == 2
    assert {h.rule_id for h in hits} == IDS
    assert COMMIT not in repr(hits)
    assert len(next(h for h in hits if h.rule_id.startswith("dd5e")).evidence["correlation"]) == 4


def test_source_and_consumer_mismatches_are_rejected():
    baseline = events()
    mutations = [
        (0, ("additionalEventData", "dataTransferred"), False, 0),
        (0, ("requestParameters", "references", 0, "commit"), "b" * 40, 0),
        (0, ("requestParameters", "references", 0, "ref"), "refs/heads/other", 1),
        (0, ("errorCode",), "AccessDenied", 0),
        (1, ("requestParameters", "pipeline", "stages", 0, "actions", 0,
             "configuration", "RepositoryName"), "other-repository", 1),
        (1, ("requestParameters", "pipeline", "stages", 1, "actions", 0,
             "configuration", "ProjectName"), "other-project", 1),
        (2, ("requestParameters", "name"), "other-pipeline", 1),
        (3, ("responseElements", "build", "resolvedSourceVersion"), "b" * 40, 1),
        (3, ("responseElements", "build", "initiator"), "codepipeline/other", 1),
        (4, ("responseElements", "build", "source", "location"),
             f"https://git-codecommit.{REGION}.amazonaws.com/v1/repos/other", 1),
        (4, ("requestParameters", "sourceVersion"), "b" * 40, 1),
    ]
    for index, path, value, expected in mutations:
        changed = deepcopy(baseline)
        place = changed[index]
        for part in path[:-1]:
            place = place[part]
        place[path[-1]] = value
        assert len(detect_aws_events(changed, selected())) == expected, (index, path)


def test_missing_history_and_cross_account_events_do_not_join():
    baseline = events()
    assert len(detect_aws_events([baseline[0], baseline[2], baseline[3], baseline[4]], selected())) == 1
    changed = deepcopy(baseline)
    changed[0]["recipientAccountId"] = "888888888888"
    assert not detect_aws_events(changed, selected())
    changed = deepcopy(baseline)
    changed[3]["eventTime"] = "2026-10-22T13:12:00Z"
    assert len(detect_aws_events(changed, selected())) == 1
    changed = deepcopy(baseline)
    changed[4]["eventTime"] = "2026-10-22T13:13:00Z"
    assert len(detect_aws_events(changed, selected())) == 1
