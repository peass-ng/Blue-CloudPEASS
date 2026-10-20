"""Synthetic derivatives of owned IoT provisioning and Jobs events."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_iot_provision_jobs_lab_events.json"
IDS = {
    "a5ec8edf-f50a-44ae-afe4-991cd8574740",
    "2954d132-8e03-43e2-a56b-091a17d8c000",
    "ac041fe6-c294-425a-869a-213862e0b2fe",
    "63f9b3f5-3ab8-4d6a-a2c0-66ed62495990",
    "24a4390a-06ef-4902-aacb-45364de6a877",
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(rules) == 5
    return rules


def hits(records):
    return {x.rule_id for x in detect_aws_events(records, selected())}


def test_five_iot_management_signals_without_secret_material():
    records = events()
    found = detect_aws_events(records, selected())
    assert len(records) == 5
    assert len(found) == 5
    assert {x.rule_id for x in found} == IDS
    assert {x["recipientAccountId"] for x in records} == {"999999999999"}
    assert all(x["eventID"].startswith("synthetic-") for x in records)
    assert "SYNTHETIC PUBLIC CERTIFICATE" not in repr(found)
    assert "PrivateKey" not in repr(found)


def test_template_and_claim_require_accepted_specific_parameters():
    baseline = events()
    for index, mutation, missing in [
        (0, lambda x: x["requestParameters"].update(enabled=False),
         "a5ec8edf-f50a-44ae-afe4-991cd8574740"),
        (0, lambda x: x["responseElements"].update(templateArn="arn:aws:iot:us-east-1:000000000000:provisioningtemplate/other"),
         "a5ec8edf-f50a-44ae-afe4-991cd8574740"),
        (1, lambda x: x["responseElements"].pop("certificateId"),
         "2954d132-8e03-43e2-a56b-091a17d8c000"),
        (1, lambda x: x.update(errorCode="AccessDenied"),
         "2954d132-8e03-43e2-a56b-091a17d8c000"),
    ]:
        records = deepcopy(baseline)
        mutation(records[index])
        assert hits(records) == IDS - {missing}


def test_byo_certificate_policy_correlation_requires_exact_identity_and_time():
    baseline = events()
    byoid = "ac041fe6-c294-425a-869a-213862e0b2fe"
    attachid = "63f9b3f5-3ab8-4d6a-a2c0-66ed62495990"
    for index, mutation, expected in [
        (2, lambda x: x["requestParameters"].update(status="INACTIVE"), IDS - {byoid, attachid}),
        (3, lambda x: x["requestParameters"].update(target="arn:aws:iot:us-east-1:999999999999:cert/" + "b" * 64), IDS - {attachid}),
        (3, lambda x: x["userIdentity"].update(arn="arn:aws:sts::999999999999:assumed-role/Other/session"), IDS - {attachid}),
        (3, lambda x: x.update(eventTime="2026-10-20T16:00:00Z"), IDS - {attachid}),
        (3, lambda x: x.update(errorCode="AccessDenied"), IDS - {attachid}),
    ]:
        records = deepcopy(baseline)
        mutation(records[index])
        assert hits(records) == expected


def test_job_document_rule_reports_read_not_contents():
    records = events()
    read = records[-1]
    read["readOnly"] = False
    assert hits(records) == IDS - {"24a4390a-06ef-4902-aacb-45364de6a877"}
