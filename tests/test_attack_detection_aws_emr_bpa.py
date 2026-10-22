"""Synthetic derivatives of accepted regional EMR BPA changes."""

from copy import deepcopy

from peaso.attack_detection.aws_emr_bpa import normalize_aws_emr_bpa
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
REGION = "us-east-2"


def event(config: dict) -> dict:
    return {
        "eventSource": "elasticmapreduce.amazonaws.com",
        "eventName": "PutBlockPublicAccessConfiguration",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": "synthetic-bpa-1", "eventTime": "2026-10-23T12:00:00Z",
        "userIdentity": {"accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"blockPublicAccessConfiguration": config},
        "responseElements": None,
    }


def rules(tmp_path):
    for suffix, field in (("disabled", "emr_bpa_disabled"),
                          ("allports", "emr_bpa_all_ports_exception")):
        (tmp_path / f"emr-{suffix}.yml").write_text(f"""title: Synthetic EMR BPA {suffix}
id: b3950000-0000-4000-8000-00000000000{1 if suffix == 'disabled' else 2}
status: experimental
description: Synthetic test rule.
references: [https://example.test/emr]
logsource: {{product: aws, service: cloudtrail}}
detection:
  selection:
    event.source: elasticmapreduce.amazonaws.com
    event.name: PutBlockPublicAccessConfiguration
    event.outcome: success
    request.{field}: true
  condition: selection
falsepositives: [Approved change]
level: high
x_hacktricks_technique_id: synthetic-emr-bpa-{suffix}
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_disabled_and_all_ports_are_distinct_signals(tmp_path):
    disabled = event({"blockPublicSecurityGroupRules": False})
    allports = event({"blockPublicSecurityGroupRules": True,
                      "permittedPublicSecurityGroupRuleRanges":
                      [{"minRange": 0, "maxRange": 65535}]})
    hits = detect_aws_events([disabled, allports], rules(tmp_path))
    assert {hit.technique_id for hit in hits} == {
        "synthetic-emr-bpa-disabled", "synthetic-emr-bpa-allports"}


def test_restrictive_restore_or_failed_request_does_not_match():
    disabled = event({"blockPublicSecurityGroupRules": False})
    allports = event({"blockPublicSecurityGroupRules": True,
                      "permittedPublicSecurityGroupRuleRanges":
                      [{"minRange": 0, "maxRange": 65535}]})
    restrictive = event({"blockPublicSecurityGroupRules": True,
                         "permittedPublicSecurityGroupRuleRanges":
                         [{"minRange": 22, "maxRange": 22}]})
    assert normalize_aws_emr_bpa(restrictive) is None
    for base in (disabled, allports):
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
            assert normalize_aws_emr_bpa(variant) is None
