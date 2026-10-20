"""Synthetic derivatives of disposable Chime Media Insights events."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_chime_insights_batch69_events.json"
IDS = {
    "72ce1ba0-7191-48c2-a5b7-42effad086c8",
    "64afa9f7-c582-47d4-a0c7-d06b0801a181",
    "66f73a04-0b9d-4cc3-9d68-b8372079a09e",
    "6a818ea8-c688-4674-8d88-138f9125ad04",
    "0cf14397-0251-4b2f-afca-4c0e4313b58b",
    "ea5e50c1-6170-4072-8cf1-92a2dab3eeff",
    "35460b09-3ae3-4ef3-8bb3-68059d8c468a",
    "e2671e06-2820-4502-8bfd-4d1efa2e1a00",
}
REBIND = "66f73a04-0b9d-4cc3-9d68-b8372079a09e"
AFTER_REBIND = "35460b09-3ae3-4ef3-8bb3-68059d8c468a"


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def found(rows):
    selected = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(selected) == 8
    return detect_aws_events(rows, selected)


def ids(rows):
    return {d.rule_id for d in found(rows)}


def test_eight_rules_match_six_live_shaped_events():
    rows = events()
    detections = found(rows)
    assert len(rows) == 6 and len(detections) == 8
    assert {d.rule_id for d in detections} == IDS
    assert {e["recipientAccountId"] for e in rows} == {"999999999999"}
    assert all(e["eventID"].startswith("synthetic-") for e in rows)
    assert "synthetic-sink" not in json.dumps([d.evidence for d in detections])


def test_role_rebind_requires_different_role_on_same_configuration():
    rows = events()
    role_a = rows[0]["requestParameters"]["resourceAccessRoleArn"]
    rows[3]["requestParameters"]["resourceAccessRoleArn"] = role_a
    rows[3]["responseElements"]["mediaInsightsPipelineConfiguration"]["resourceAccessRoleArn"] = role_a
    assert REBIND not in ids(rows)
    assert AFTER_REBIND not in ids(rows)


def test_rebind_and_pipeline_link_require_exact_identity_and_window():
    for mutate in (
        lambda rows: rows[3]["requestParameters"].update(identifier="arn:aws:chime:us-east-1:999999999999:media-insights-pipeline-configuration/other-name"),
        lambda rows: rows[3].update(eventTime="2026-10-22T20:03:00Z"),
        lambda rows: rows[3].update(errorCode="BadRequestException"),
    ):
        rows = events()
        mutate(rows)
        assert REBIND not in ids(rows)
        assert AFTER_REBIND not in ids(rows)


def test_pipeline_creation_after_rebind_requires_accepted_same_config():
    rows = events()
    rows[4]["responseElements"]["mediaInsightsPipeline"]["mediaInsightsPipelineConfigurationArn"] = (
        "arn:aws:chime:us-east-1:999999999999:media-insights-pipeline-configuration/other-name"
    )
    assert AFTER_REBIND not in ids(rows)
    assert "ea5e50c1-6170-4072-8cf1-92a2dab3eeff" not in ids(rows)
    assert REBIND in ids(rows)


def test_read_list_delete_require_successful_management_events():
    rows = events()
    rows[1]["errorCode"] = "NotFoundException"
    rows[2]["eventSource"] = "chime.amazonaws.com"
    rows[5]["managementEvent"] = False
    matches = ids(rows)
    assert "6a818ea8-c688-4674-8d88-138f9125ad04" not in matches
    assert "0cf14397-0251-4b2f-afca-4c0e4313b58b" not in matches
    assert "e2671e06-2820-4502-8bfd-4d1efa2e1a00" not in matches
