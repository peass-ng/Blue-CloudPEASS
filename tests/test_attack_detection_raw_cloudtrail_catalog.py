"""Catalog-only CloudTrail rules use a bounded, private envelope."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from urllib.parse import quote

import pytest

from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
TABLE = f"arn:aws:cassandra:us-east-1:{ACCOUNT}:/keyspace/synthetic/table/records"
STREAM = TABLE + "/stream/synthetic-label"


def rule(directory: Path, *, extra: str = "", selection_extra: str = ""):
    (directory / "example.yml").write_text(
        """title: Synthetic CDC request
id: 14400000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/source]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: cassandra.amazonaws.com
    event.name: GetRecords
    event.category: Data
    event.outcome: success
    resource.type: AWS::Cassandra::Table
""" + selection_extra + """  condition: selection
falsepositives: [Approved CDC poll]
level: medium
tags: [attack.collection]
x_hacktricks_technique_id: synthetic-cdc-request
x_cloudtrail_raw: true
""" + extra, encoding="utf-8")
    return load_rules(directory, product="aws")


def event():
    return {
        "eventSource": "cassandra.amazonaws.com", "eventName": "GetRecords",
        "eventType": "AwsApiCall", "eventCategory": "Data",
        "managementEvent": False, "readOnly": True,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-event", "eventTime": "2026-10-21T12:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": {"shardIterator": "private-opaque-iterator"},
        "resources": [
            {"type": "AWS::Cassandra::Stream", "ARN": STREAM},
            {"type": "AWS::Cassandra::Table", "ARN": TABLE},
        ],
    }


def test_new_catalog_rule_matches_without_service_normalizer(tmp_path):
    hits = detect_aws_events([event()], rule(tmp_path))
    assert len(hits) == 1
    assert hits[0].technique_id == "synthetic-cdc-request"
    assert hits[0].target_id.startswith("sha256:")
    assert TABLE not in str(hits)
    assert "private-opaque-iterator" not in str(hits)


def test_denials_cross_account_resources_and_wrong_categories_fail_closed(tmp_path):
    selected = rule(tmp_path)
    denied = deepcopy(event()); denied["errorCode"] = "AccessDeniedException"
    foreign = deepcopy(event()); foreign["resources"][1]["ARN"] = TABLE.replace(ACCOUNT, "111111111111")
    wrong = deepcopy(event()); wrong["eventCategory"] = "Management"
    no_resources = deepcopy(event()); no_resources["resources"] = []
    assert detect_aws_events([denied, foreign, wrong, no_resources], selected) == []


def test_aws_owned_artifact_report_arn_is_allowed_only_for_artifact_reports(tmp_path):
    (tmp_path / "artifact.yml").write_text("""title: Synthetic Artifact report read
id: 17300000-0000-4000-8000-000000000099
status: experimental
description: Synthetic Artifact test.
references: [https://example.test/artifact]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: artifact.amazonaws.com
    event.name: GetReportMetadata
    event.category: Management
    event.outcome: success
    event.read_only: true
    resource.type: AWS::Artifact::Report
  condition: selection
falsepositives: [Approved report review]
level: low
x_hacktricks_technique_id: synthetic-artifact-report-read
x_cloudtrail_raw: true
""", encoding="utf-8")
    selected = load_rules(tmp_path, product="aws")
    item = event()
    report = "arn:aws:artifact:us-east-1::report/report-synthetic:1"
    item.update({"eventSource": "artifact.amazonaws.com", "eventName": "GetReportMetadata",
                 "eventCategory": "Management", "managementEvent": True, "readOnly": True,
                 "resources": [{"type": "AWS::Artifact::Report", "ARN": report}]})
    hits = detect_aws_events([item], selected)
    assert len(hits) == 1
    assert hits[0].target_id.startswith("sha256:")
    assert report not in str(hits)
    for field, value in (
        ("eventSource", "other.amazonaws.com"),
        ("resources", [{"type": "AWS::Other::Report", "ARN": report}]),
        ("resources", [{"type": "AWS::Artifact::Report", "ARN": report.replace("us-east-1", "us-west-2")}]),
        ("resources", [{"type": "AWS::Artifact::Report", "ARN": "arn:aws:artifact:us-east-1::report/../private"}]),
        ("errorCode", "AccessDeniedException"),
    ):
        rejected = deepcopy(item)
        rejected[field] = value
        assert detect_aws_events([rejected], selected) == []


def test_unscoped_management_event_keeps_request_token_private(tmp_path):
    (tmp_path / "unscoped.yml").write_text("""title: Synthetic request status read
id: 15300000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/source]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: cloudcontrolapi.amazonaws.com
    event.name: GetResourceRequestStatus
    event.category: Management
    event.outcome: success
    event.read_only: true
    resource.type: CloudTrail::UnscopedEvent
  condition: selection
falsepositives: [Approved deployment monitoring]
level: low
x_hacktricks_technique_id: synthetic-request-status-read
x_cloudtrail_raw: true
""", encoding="utf-8")
    selected = load_rules(tmp_path, product="aws")
    item = event()
    item.update({"eventSource": "cloudcontrolapi.amazonaws.com",
                 "eventName": "GetResourceRequestStatus", "eventCategory": "Management",
                 "managementEvent": True,
                 "requestParameters": {"requestToken": "private-request-token"}})
    del item["resources"]
    hits = detect_aws_events([item], selected)
    assert len(hits) == 1
    assert hits[0].target_id.startswith("sha256:")
    assert "private-request-token" not in str(hits)
    assert "requestToken" not in str(hits)
    empty = deepcopy(item); empty["resources"] = []
    assert len(detect_aws_events([empty], selected)) == 1
    malformed = deepcopy(item); malformed["resources"] = "not-a-list"
    denied = deepcopy(item); denied["errorCode"] = "AccessDeniedException"
    assert detect_aws_events([malformed, denied], selected) == []


def test_console_signin_token_event_uses_private_bounded_envelope(tmp_path):
    (tmp_path / "signin.yml").write_text("""title: Synthetic console federation token
id: 16100000-0000-4000-8000-000000000002
status: experimental
description: Synthetic sign-in test.
references: [https://example.test/source]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: signin.amazonaws.com
    event.name: GetSigninToken
    event.category: Management
    event.outcome: success
    event.read_only: false
    resource.type: CloudTrail::UnscopedEvent
  condition: selection
falsepositives: [Approved federation]
level: low
x_hacktricks_technique_id: synthetic-console-federation-token
x_cloudtrail_raw: true
""", encoding="utf-8")
    selected = load_rules(tmp_path, product="aws")
    item = event()
    item.update({"eventSource": "signin.amazonaws.com", "eventName": "GetSigninToken",
                 "eventType": "AwsConsoleSignIn", "eventCategory": "Management",
                 "managementEvent": True, "readOnly": False, "resources": None,
                 "responseElements": {"GetSigninToken": "Success",
                                      "credentials": {"accessKeyId": "private-key"}},
                 "userIdentity": {"arn": f"arn:aws:sts::{ACCOUNT}:federated-user/private-name"}})
    hits = detect_aws_events([item], selected)
    assert len(hits) == 1
    assert hits[0].target_id.startswith("sha256:")
    assert "private-name" not in str(hits)
    assert "private-key" not in str(hits)
    for field, value in (("responseElements", {}), ("eventType", "AwsApiCall"),
                         ("resources", "malformed"), ("errorCode", "AccessDenied")):
        denied = deepcopy(item)
        denied[field] = value
        assert detect_aws_events([denied], selected) == []


def test_raw_rule_grammar_rejects_request_fields_and_unsafe_modes(tmp_path):
    with pytest.raises(ValueError, match="Unsupported raw CloudTrail rule"):
        rule(tmp_path, selection_extra="    request.shard_iterator: private\n")
    with pytest.raises(ValueError, match="Unsupported raw CloudTrail rule"):
        rule(tmp_path, extra="x_cloudtrail_raw: maybe\n")


def test_existing_rules_do_not_match_the_raw_envelope(tmp_path):
    selected = rule(tmp_path)
    old = selected[0].__class__(**{**selected[0].__dict__, "raw_cloudtrail": False})
    assert detect_aws_events([event()], [old]) == []


def test_latest_catalog_preserves_raw_rule_opt_in(monkeypatch, tmp_path):
    from peaso.attack_detection import catalog

    rule(tmp_path)
    source = (tmp_path / "example.yml").read_text(encoding="utf-8")
    monkeypatch.setattr(catalog, "resolve_main_commit", lambda _repo: "a" * 40)
    monkeypatch.setattr(catalog, "fetch_rules", lambda _repo, _commit, _digest: {
        "aws/keyspaces/example.yml": source,
    })
    selected = catalog.select_catalog("latest", product="aws")
    assert selected.commit == "a" * 40
    assert selected.rules[0].raw_cloudtrail is True
    assert len(detect_aws_events([event()], selected.rules)) == 1


def test_resource_path_prefix_scopes_raw_rule_without_exposing_arn(tmp_path):
    selected = rule(tmp_path, extra="x_cloudtrail_resource_path_prefix: /keyspace/system\n",
                    selection_extra="    resource.path_scope_checked: true\n")
    assert detect_aws_events([event()], selected) == []
    system = deepcopy(event())
    system["resources"] = [{
        "type": "AWS::Cassandra::Table",
        "ARN": f"arn:aws:cassandra:us-east-1:{ACCOUNT}:/keyspace/system_schema/table/tables",
    }]
    hits = detect_aws_events([system], selected)
    assert len(hits) == 1
    assert "/keyspace/system" not in str(hits)


def test_resource_path_prefix_rejects_unsafe_or_nonraw_values(tmp_path):
    with pytest.raises(ValueError, match="Unsupported raw CloudTrail resource prefix"):
        rule(tmp_path, extra="x_cloudtrail_resource_path_prefix: ../private\n")
    with pytest.raises(ValueError, match="Unsupported raw CloudTrail resource prefix"):
        rule(tmp_path, extra="x_cloudtrail_resource_path_prefix: /keyspace/system\n")


def test_networkmanager_attachment_tag_scope_uses_same_account_arn_without_leaking_it(tmp_path):
    attachment = f"arn:aws:networkmanager::{ACCOUNT}:attachment/attachment-0123456789abcdef0"
    text = """title: Synthetic Cloud WAN attachment tagging
id: 28300000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/source]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: networkmanager.amazonaws.com
    event.name: TagResource
    event.category: Management
    event.outcome: success
    event.read_only: false
    resource.type: AWS::NetworkManager::Attachment
  condition: selection
falsepositives: [Approved tagging]
level: low
x_hacktricks_technique_id: synthetic-attachment-tag
x_cloudtrail_raw: true
"""
    (tmp_path / "attachment.yml").write_text(text, encoding="utf-8")
    selected = load_rules(tmp_path, product="aws")
    item = event()
    item.update({
        "eventSource": "networkmanager.amazonaws.com", "eventName": "TagResource",
        "eventCategory": "Management", "managementEvent": True, "readOnly": False,
        "requestParameters": {"resourceArn": attachment, "Tags": [{"Key": "environment", "Value": "synthetic"}]},
        "resources": [],
    })
    hits = detect_aws_events([item], selected)
    assert len(hits) == 1 and hits[0].target_id.startswith("sha256:")
    assert attachment not in str(hits) and ACCOUNT not in str(hits[0].evidence)
    encoded = deepcopy(item)
    encoded["requestParameters"]["resourceArn"] = quote(attachment, safe="")
    encoded_hits = detect_aws_events([encoded], selected)
    assert len(encoded_hits) == 1 and encoded_hits[0].target_id == hits[0].target_id
    for bad_arn in (
        attachment.replace(ACCOUNT, "111111111111"),
        attachment.replace("attachment/", "core-network/"),
        attachment + "/extra",
        quote(attachment, safe="").replace("%3A", "%253A", 1),
    ):
        bad = deepcopy(item)
        bad["requestParameters"]["resourceArn"] = bad_arn
        assert detect_aws_events([bad], selected) == []
    denied = deepcopy(item)
    denied["errorCode"] = "AccessDeniedException"
    assert detect_aws_events([denied], selected) == []

    (tmp_path / "attachment.yml").write_text(
        text.replace("event.name: TagResource", "event.name: UntagResource"), encoding="utf-8"
    )
    untagged = deepcopy(item)
    untagged["eventName"] = "UntagResource"
    untagged["requestParameters"] = {"resourceArn": attachment, "TagKeys": ["environment"]}
    other = detect_aws_events([untagged], load_rules(tmp_path, product="aws"))
    assert len(other) == 1 and other[0].target_id == hits[0].target_id
