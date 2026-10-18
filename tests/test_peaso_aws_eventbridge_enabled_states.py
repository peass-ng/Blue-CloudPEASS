"""Both documented enabled EventBridge states preserve configured event routing."""
import copy
import json

import pytest

from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

EXTENDED = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
SCOPE = "123456789012/us-east-1"
TARGET = "arn:aws:lambda:us-east-1:123456789012:function:fixture"
CASES = {
    "aws_guardduty_high_finding_alert": ("aws.guardduty", "GuardDuty Finding", {}, {}),
    "aws_guardduty_siem_forwarding": ("aws.guardduty", "GuardDuty Finding", {}, {"approved_siem_forwarder_arns": [TARGET]}),
    "aws_incident_automated_containment": ("aws.guardduty", "GuardDuty Finding", {}, {"approved_incident_event_classes": [{"source": "aws.guardduty", "detail_type": "GuardDuty Finding", "document_arn": TARGET}]}),
    "aws_inspector_findings_metric_export": ("aws.inspector2", "Inspector2 Finding", {"resources": {"type": ["AWS_EC2_INSTANCE"]}}, {"approved_metric_pipeline_arn": TARGET}),
    "aws_securityhub_critical_findings_alert": ("aws.securityhub", "Security Hub Findings - Imported", {"findings": {"Severity": {"Label": ["CRITICAL"]}}}, {}),
}


def native_fixture(check_id, state):
    source, detail_type, detail, inputs = CASES[check_id]
    pattern = {"source": [source], "detail-type": [detail_type]}
    if detail:
        pattern["detail"] = copy.deepcopy(detail)
    rule = {"Name": "fixture", "EventBusName": "default", "State": state,
            "EventPattern": json.dumps(pattern), "Targets": {"collection_status": "collected", "items": [{"Id": "target", "Arn": TARGET}]}}
    return rule, inputs


def outcome(check_id, rules, inputs):
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "eventbridge_rule", "scope": SCOPE, "status": "collected", "items": rules}],
                             metadata={"compliance_inputs": inputs})
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[check_id])
    return report["findings"][0]["status"]


@pytest.mark.parametrize("check_id", CASES)
@pytest.mark.parametrize("state,expected", [("ENABLED", "PASS"), (EXTENDED, "PASS"), ("DISABLED", "FAIL")])
def test_documented_rule_states_preserve_configured_routing_semantics(check_id, state, expected):
    rule, inputs = native_fixture(check_id, state)
    assert outcome(check_id, [rule], inputs) == expected


@pytest.mark.parametrize("check_id", CASES)
def test_unknown_state_cannot_prove_configuration(check_id):
    rule, inputs = native_fixture(check_id, "UNRECOGNIZED")
    assert outcome(check_id, [rule], inputs) == "UNKNOWN"


@pytest.mark.parametrize("check_id", CASES)
def test_enabled_extended_state_does_not_overcome_denied_target_read(check_id):
    rule, inputs = native_fixture(check_id, EXTENDED)
    rule["Targets"] = {"collection_status": "denied", "items": []}
    assert outcome(check_id, [rule], inputs) == "UNKNOWN"


def test_unrelated_valid_extended_rule_does_not_invalidate_existing_alert():
    check_id = "aws_guardduty_high_finding_alert"
    rule, inputs = native_fixture(check_id, "ENABLED")
    extra = copy.deepcopy(rule)
    extra.update(Name="unrelated", State=EXTENDED, EventPattern=json.dumps({"source": ["aws.ec2"], "detail-type": ["EC2 State Change"]}))
    assert outcome(check_id, [rule, extra], inputs) == "PASS"
