"""Synthetic derivatives of an owned EventBridge Pipes SQS relay lab."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
NAME = "synthetic-pipe"
ARN = f"arn:aws:pipes:us-east-1:{ACCOUNT}:pipe/{NAME}"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-pipe-role"
SOURCE = f"arn:aws:sqs:us-east-1:{ACCOUNT}:synthetic-source"
TARGET_A = f"arn:aws:sqs:us-east-1:{ACCOUNT}:synthetic-target-a"
TARGET_B = f"arn:aws:sqs:us-east-1:{ACCOUNT}:synthetic-target-b"
RULES = [
    Rule(id="pipe-create", title="Pipe created", description="synthetic", level="medium",
         product="aws", technique_id="aws-pipes-role-source-target-bound",
         selection={"event.source": "pipes.amazonaws.com", "event.name": "CreatePipe",
                    "event.outcome": "success", "request.pipes_role_source_target_bound": True}),
    Rule(id="pipe-update", title="Pipe updated", description="synthetic", level="medium",
         product="aws", technique_id="aws-pipes-role-target-updated",
         selection={"event.source": "pipes.amazonaws.com", "event.name": "UpdatePipe",
                    "event.outcome": "success", "request.pipes_role_target_updated": True}),
    Rule(id="pipe-read", title="Pipe template read", description="synthetic", level="low",
         product="aws", technique_id="aws-pipes-other-actor-template-read",
         selection={"event.source": "pipes.amazonaws.com", "event.name": "DescribePipe",
                    "event.outcome": "success", "request.pipes_other_actor_read_configured_template": True}),
]


def event(kind, *, actor="creator"):
    name = {"create": "CreatePipe", "update": "UpdatePipe", "read": "DescribePipe"}[kind]
    request = {"Name": NAME}
    if kind == "create":
        request.update(RoleArn=ROLE, Source=SOURCE, Target=TARGET_A,
                       TargetParameters={"InputTemplate": '{"marker":"synthetic"}'})
    elif kind == "update":
        request.update(RoleArn=ROLE, Target=TARGET_B,
                       TargetParameters={"InputTemplate": '{"marker":"synthetic-2"}'})
    return {"eventSource": "pipes.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": kind == "read",
            "eventTime": {"create": "2026-10-23T01:00:00Z",
                          "update": "2026-10-23T01:01:00Z",
                          "read": "2026-10-23T01:02:00Z"}[kind],
            "recipientAccountId": ACCOUNT,
            "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/{actor}"},
            "requestParameters": request,
            "responseElements": None if kind == "read" else {"Name": NAME, "Arn": ARN},
    }


def test_role_route_update_and_other_actor_template_read():
    records = [event("read", actor="reader"), event("update"), event("create")]
    hits = detect_aws_events(records, RULES)
    assert {hit.technique_id for hit in hits} == {rule.technique_id for rule in RULES}
    assert len(hits) == 3
    assert all(raw not in str(hits) for raw in (NAME, ROLE, SOURCE, TARGET_A, TARGET_B))


def test_denied_incomplete_and_unrelated_reads_are_excluded():
    for kind in ("create", "update"):
        failed = event(kind)
        failed["errorCode"] = "AccessDeniedException"
        assert detect_aws_events([failed], RULES) == []
        no_role = event(kind)
        del no_role["requestParameters"]["RoleArn"]
        assert detect_aws_events([no_role], RULES) == []
    create = event("create")
    for change in (
        lambda r: r.update(eventTime="2026-10-23T03:01:00Z"),
        lambda r: r["requestParameters"].update(Name="another-pipe"),
        lambda r: r.update(errorCode="AccessDeniedException"),
        lambda r: r.update(readOnly=False),
    ):
        read = event("read", actor="reader")
        change(read)
        hits = detect_aws_events([create, read], RULES)
        assert [hit.technique_id for hit in hits] == [RULES[0].technique_id]
    same_actor = event("read")
    assert [hit.technique_id for hit in detect_aws_events([create, same_actor], RULES)] == [RULES[0].technique_id]
    no_template = deepcopy(create)
    no_template["requestParameters"]["TargetParameters"]["InputTemplate"] = ""
    assert [hit.technique_id for hit in detect_aws_events([no_template, event("read", actor="reader")], RULES)] == [RULES[0].technique_id]
