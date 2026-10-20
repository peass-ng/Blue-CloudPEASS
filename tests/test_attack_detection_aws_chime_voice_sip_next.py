"""Synthetic derivatives of disposable Chime SDK Voice SIP management events."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_chime_voice_sip_batch67_events.json"
IDS = {
    "37f36eb4-1fcd-48cb-9f9f-c6cd2798aea2",
    "587b33df-f88f-45e0-9399-e4aa26b350b8",
    "baae4795-4b4d-415e-8a07-0c5fee746a0c",
    "612be900-292b-4b81-abe4-378c3e0a3303",
    "bf1142fa-6484-4701-8e13-d878590e7c67",
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def found(rows):
    selected = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(selected) == 5
    return detect_aws_events(rows, selected)


def ids(rows):
    return {d.rule_id for d in found(rows)}


def test_five_rules_match_five_live_shaped_management_events():
    rows = events()
    detections = found(rows)
    assert len(rows) == len(detections) == 5
    assert {d.rule_id for d in detections} == IDS
    assert all(row["eventID"].startswith("synthetic-") for row in rows)
    assert {row["recipientAccountId"] for row in rows} == {"999999999999"}
    assert "HIDDEN_DUE_TO_SECURITY_REASONS" not in json.dumps([d.evidence for d in detections])


def test_encryption_downgrade_requires_accepted_false_value():
    for mutate in (
        lambda row: row["responseElements"]["voiceConnector"].update(requireEncryption=True),
        lambda row: row.update(errorCode="BadRequestException"),
        lambda row: row["requestParameters"].update(requireEncryption=True),
    ):
        rows = events()
        mutate(rows[0])
        assert "37f36eb4-1fcd-48cb-9f9f-c6cd2798aea2" not in ids(rows)


def test_sip_endpoint_changes_require_accepted_matching_endpoint():
    rows = events()
    rows[1]["responseElements"]["sipMediaApplication"]["endpoints"] = []
    rows[2]["responseElements"]["sipMediaApplication"]["sipMediaApplicationId"] = (
        "44444444-4444-4444-8444-444444444444"
    )
    assert "587b33df-f88f-45e0-9399-e4aa26b350b8" not in ids(rows)
    assert "baae4795-4b4d-415e-8a07-0c5fee746a0c" not in ids(rows)


def test_rule_creation_can_be_disabled_but_update_must_enable_target():
    rows = events()
    assert rows[3]["requestParameters"]["disabled"] is True
    assert "612be900-292b-4b81-abe4-378c3e0a3303" in ids(rows)
    rows[4]["responseElements"]["sipRule"]["disabled"] = True
    assert "bf1142fa-6484-4701-8e13-d878590e7c67" not in ids(rows)


def test_rule_target_and_management_event_are_required():
    rows = events()
    rows[3]["responseElements"]["sipRule"]["targetApplications"] = []
    rows[4]["managementEvent"] = False
    assert "612be900-292b-4b81-abe4-378c3e0a3303" not in ids(rows)
    assert "bf1142fa-6484-4701-8e13-d878590e7c67" not in ids(rows)
