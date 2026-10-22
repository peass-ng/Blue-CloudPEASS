"""Synthetic derivatives of observed EMR classic CloudTrail management calls."""

from copy import deepcopy

from peaso.attack_detection.aws_emr_classic import normalize_aws_emr_classic
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
REGION = "us-east-2"
CLUSTER = "j-ABCDEFGHIJKL12345678"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"


def event(action: str) -> dict:
    request = ({"jobFlowRole": "synthetic-instance-profile",
                "serviceRole": "synthetic-service-role",
                "instances": {"instanceGroups": [{"instanceRole": "MASTER",
                                                 "instanceType": "m5.xlarge"}]}}
               if action == "RunJobFlow" else
               {"jobFlowId": CLUSTER, "steps": [{"name": "synthetic-step",
                    "hadoopJarStep": {"jar": "command-runner.jar", "args": []}}]})
    response = ({"jobFlowId": CLUSTER,
                 "clusterArn": f"arn:aws:elasticmapreduce:{REGION}:{ACCOUNT}:cluster/{CLUSTER}"}
                if action == "RunJobFlow" else {"stepIds": ["s-ABCDEFGHIJKL12345678"]})
    return {
        "eventSource": "elasticmapreduce.amazonaws.com", "eventName": action,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": "synthetic-" + action, "eventTime": "2026-10-23T12:00:00Z",
        "userIdentity": {"accountId": ACCOUNT, "arn": ACTOR},
        "requestParameters": request, "responseElements": response,
    }


def rules(tmp_path):
    for action, flag, index in (
        ("RunJobFlow", "emr_instance_profile_selected", 1),
        ("AddJobFlowSteps", "emr_command_runner_step_added", 2),
    ):
        (tmp_path / f"emr-{index}.yml").write_text(f"""title: Synthetic EMR classic {index}
id: b3870000-0000-4000-8000-00000000000{index}
status: experimental
description: Synthetic test rule.
references: [https://example.test/emr]
logsource: {{product: aws, service: cloudtrail}}
detection:
  selection:
    event.source: elasticmapreduce.amazonaws.com
    event.name: {action}
    event.outcome: success
    request.{flag}: true
  condition: selection
falsepositives: [Approved EMR operation]
level: medium
x_hacktricks_technique_id: synthetic-emr-{index}
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_cluster_and_step_events_match_without_exposing_role_or_args(tmp_path):
    cluster = event("RunJobFlow")
    step = event("AddJobFlowSteps")
    step["requestParameters"]["steps"][0]["hadoopJarStep"]["args"] = [
        "bash", "-c", "synthetic-secret-marker"]
    hits = detect_aws_events([cluster, step], rules(tmp_path))
    assert {hit.technique_id for hit in hits} == {"synthetic-emr-1", "synthetic-emr-2"}
    assert len({hit.target_id for hit in hits}) == 1
    assert all(hit.target_id.startswith("sha256:") for hit in hits)
    assert "synthetic-secret-marker" not in str(hits)
    assert "synthetic-instance-profile" not in str(hits)


def test_cluster_requires_confirmed_profile_and_matching_response():
    base = event("RunJobFlow")
    for change in (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
        lambda x: x.update(eventCategory="Data"),
        lambda x: x["userIdentity"].update(accountId="111111111111"),
        lambda x: x["requestParameters"].update(jobFlowRole=""),
        lambda x: x["requestParameters"].update(jobFlowRole="arn:aws:iam::111111111111:instance-profile/foreign"),
        lambda x: x["responseElements"].update(clusterArn="unrelated"),
        lambda x: x["responseElements"].update(jobFlowId="j-WRONG123456"),
        lambda x: x["requestParameters"].update(instances=None),
    ):
        variant = deepcopy(base)
        change(variant)
        assert normalize_aws_emr_classic(variant) is None


def test_step_requires_accepted_command_runner_and_step_ids():
    base = event("AddJobFlowSteps")
    for change in (
        lambda x: x.update(errorCode="ValidationException"),
        lambda x: x.update(readOnly=True),
        lambda x: x.update(eventType="AwsServiceEvent"),
        lambda x: x["requestParameters"].update(jobFlowId="j-invalid"),
        lambda x: x["requestParameters"].update(steps=[]),
        lambda x: x["requestParameters"]["steps"][0]["hadoopJarStep"].update(jar="other.jar"),
        lambda x: x["responseElements"].update(stepIds=[]),
    ):
        variant = deepcopy(base)
        change(variant)
        assert normalize_aws_emr_classic(variant) is None
