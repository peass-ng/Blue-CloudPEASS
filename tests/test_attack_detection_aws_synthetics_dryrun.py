"""Synthetics replacement-code dry runs require accepted, scoped evidence."""

from __future__ import annotations

from copy import deepcopy

from peaso.attack_detection.aws_synthetics_dryrun import normalize_aws_synthetics_dryrun
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
NAME = "synthetic-canary"
ARN = f"arn:aws:synthetics:us-east-2:{ACCOUNT}:canary:{NAME}"
SENTINEL = "private-canary-code-or-bucket"


def event(name="StartCanaryDryRun"):
    request = {"name": NAME}
    response = {}
    if name == "StartCanaryDryRun":
        request["Code"] = {"ZipFile": SENTINEL, "Handler": "canary.handler"}
        response["DryRunConfig"] = {"DryRunId": "synthetic-dry-run"}
    return {"eventSource": "synthetics.amazonaws.com", "eventName": name,
            "eventType": "AwsApiCall", "eventCategory": "Management",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-2",
            "eventID": "synthetic-" + name, "eventTime": "2026-10-22T12:00:00Z",
            "userIdentity": {"accountId": ACCOUNT,
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
            "requestParameters": request, "responseElements": response,
            "resources": [{"type": "AWS::Synthetics::Canary", "ARN": ARN}]}


def rules(tmp_path):
    (tmp_path / "start.yml").write_text("""title: Synthetic canary start
id: b3750000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/start]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: synthetics.amazonaws.com
    event.name: StartCanary
    event.category: Management
    event.outcome: success
    event.read_only: false
    resource.type: AWS::Synthetics::Canary
  condition: selection
falsepositives: [Approved test]
level: medium
x_hacktricks_technique_id: synthetic-canary-start
x_cloudtrail_raw: true
""", encoding="utf-8")
    (tmp_path / "dry.yml").write_text("""title: Synthetic canary replacement code
id: b3750000-0000-4000-8000-000000000002
status: experimental
description: Synthetic test rule.
references: [https://example.test/dry]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: synthetics.amazonaws.com
    event.name: StartCanaryDryRun
    event.outcome: success
    request.synthetics_dry_run_replacement_code_requested: true
  condition: selection
falsepositives: [Approved test]
level: high
x_hacktricks_technique_id: synthetic-canary-dry-run
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_manual_start_and_replacement_code_dryrun_match_without_private_content(tmp_path):
    hits = detect_aws_events([event("StartCanary"), event()], rules(tmp_path))
    assert {x.technique_id for x in hits} == {"synthetic-canary-start",
                                                 "synthetic-canary-dry-run"}
    assert SENTINEL not in str(hits)
    assert ARN not in str(hits)
    assert all(x.target_id.startswith("sha256:") for x in hits)


def test_denied_unscoped_and_no_replacement_dryruns_are_excluded(tmp_path):
    base = event()
    variants = []
    for change in (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
        lambda x: x.update(eventCategory="Data"),
        lambda x: x["userIdentity"].update(accountId="111111111111"),
        lambda x: x["requestParameters"].update(name="different"),
        lambda x: x["requestParameters"].pop("Code"),
        lambda x: x["requestParameters"].update(Code={"Handler": "canary.handler"}),
        lambda x: x["requestParameters"].update(ExecutionRoleArn="arn:aws:iam::111111111111:role/foreign"),
        lambda x: x["responseElements"].update(DryRunConfig={}),
        lambda x: x.update(resources=[]),
    ):
        item = deepcopy(base)
        change(item)
        variants.append(item)
    assert detect_aws_events(variants, rules(tmp_path)) == []


def test_s3_replacement_archive_is_supported(tmp_path):
    item = event()
    item["requestParameters"]["Code"] = {"S3Bucket": SENTINEL,
                                          "S3Key": "archive.zip", "Handler": "canary.handler"}
    assert normalize_aws_synthetics_dryrun(item) is not None
    assert len(detect_aws_events([item], rules(tmp_path))) == 1
