"""Synthetic derivatives of EMR termination-control management events."""

from copy import deepcopy

from peaso.attack_detection.aws_emr_lifecycle import normalize_aws_emr_lifecycle
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
CLUSTER = "j-ABCDEFGH12345678"


def event(action: str, protected: bool | None = None) -> dict:
    request = ({"jobFlowIds": [CLUSTER], "terminationProtected": protected}
               if action == "SetTerminationProtection" else {"clusterId": CLUSTER})
    return {
        "eventSource": "elasticmapreduce.amazonaws.com", "eventName": action,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-2",
        "eventID": f"synthetic-{action}-{protected}",
        "eventTime": "2026-10-23T12:00:00Z",
        "userIdentity": {"accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": None,
    }


def rules(tmp_path):
    for index, (action, flag) in enumerate((
        ("SetTerminationProtection", "emr_termination_protection_enabled"),
        ("SetTerminationProtection", "emr_termination_protection_disabled"),
        ("RemoveAutoTerminationPolicy", "emr_auto_termination_policy_removed"),
    ), start=1):
        (tmp_path / f"emr-{index}.yml").write_text(f"""title: Synthetic EMR lifecycle {index}
id: b3980000-0000-4000-8000-00000000000{index}
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
falsepositives: [Approved lifecycle change]
level: medium
x_hacktricks_technique_id: synthetic-emr-lifecycle-{index}
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_three_lifecycle_changes_are_distinct_and_redacted(tmp_path):
    records = [event("SetTerminationProtection", True),
               event("RemoveAutoTerminationPolicy"),
               event("SetTerminationProtection", False)]
    hits = detect_aws_events(records, rules(tmp_path))
    assert {hit.technique_id for hit in hits} == {
        "synthetic-emr-lifecycle-1", "synthetic-emr-lifecycle-2",
        "synthetic-emr-lifecycle-3"}
    assert CLUSTER not in str(hits)


def test_rejected_or_malformed_change_does_not_match():
    for base in (event("SetTerminationProtection", True),
                 event("SetTerminationProtection", False),
                 event("RemoveAutoTerminationPolicy")):
        for change in (
            lambda e: e.update(errorCode="AccessDeniedException"),
            lambda e: e.update(readOnly=True),
            lambda e: e.update(managementEvent=False),
            lambda e: e.update(eventCategory="Data"),
            lambda e: e.update(eventType="AwsServiceEvent"),
            lambda e: e["userIdentity"].update(accountId="111111111111"),
            lambda e: e.update(eventID=""),
        ):
            variant = deepcopy(base)
            change(variant)
            assert normalize_aws_emr_lifecycle(variant) is None
    invalid = event("SetTerminationProtection", True)
    invalid["requestParameters"]["terminationProtected"] = "true"
    assert normalize_aws_emr_lifecycle(invalid) is None
    invalid = event("RemoveAutoTerminationPolicy")
    invalid["requestParameters"]["clusterId"] = "invalid"
    assert normalize_aws_emr_lifecycle(invalid) is None
