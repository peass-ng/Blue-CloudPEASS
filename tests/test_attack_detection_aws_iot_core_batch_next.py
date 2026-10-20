"""IoT Core management signals from synthetic derivatives of an owned lab."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_iot_core_batch_lab_events.json"
IDS = {
    "46ceffbf-d319-4b7b-9148-dd2ed252e7fa",
    "cd49bfb2-0d67-45fc-93ad-dddb200afda4",
    "1712b009-fa03-42ff-8b93-0ae47ac5bf5e",
    "37057165-3fb0-46be-abea-801f85098b8c",
    "840ecf63-3816-41d9-b4f9-9b4e23c55afc",
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(rules) == 5
    return rules


def hits(records):
    return {x.rule_id for x in detect_aws_events(records, selected())}


def test_five_management_events_match_without_secrets():
    records = events()
    assert len(records) == 5
    found = detect_aws_events(records, selected())
    assert len(found) == 5
    assert {x.rule_id for x in found} == IDS
    assert {x["recipientAccountId"] for x in records} == {"999999999999"}
    assert all(x["eventID"].startswith("synthetic-") for x in records)
    assert "sourceAccessToken" not in repr(found)
    assert "secretAccessKey" not in repr(found)


def test_alias_requires_successful_exact_role_and_response():
    baseline = events()
    for change in [
        lambda x: x["requestParameters"].update(roleArn="arn:aws:iam::000000000000:role/Other"),
        lambda x: x["responseElements"].update(roleAliasArn="arn:aws:iot:us-east-1:000000000000:rolealias/other"),
        lambda x: x.update(errorCode="AccessDenied"),
    ]:
        records = deepcopy(baseline)
        change(records[0])
        assert hits(records) == IDS - {"46ceffbf-d319-4b7b-9148-dd2ed252e7fa"}


def test_tunnel_rotation_requires_source_or_all_and_matching_tunnel():
    baseline = events()
    for change in [
        lambda x: x["requestParameters"].update(clientMode="DESTINATION"),
        lambda x: x["responseElements"].update(tunnelArn="arn:aws:iot:us-east-1:999999999999:tunnel/other"),
        lambda x: x.update(errorCode="ResourceNotFoundException"),
    ]:
        records = deepcopy(baseline)
        change(records[-1])
        assert hits(records) == IDS - {"840ecf63-3816-41d9-b4f9-9b4e23c55afc"}


def test_topic_rule_event_does_not_claim_wildcard_or_sink():
    records = events()
    assert set(records[2]["requestParameters"]) == {"ruleName"}
    matches = [x for x in detect_aws_events(records, selected()) if x.rule_id == "1712b009-fa03-42ff-8b93-0ae47ac5bf5e"]
    assert len(matches) == 1
    assert "SELECT * FROM '#'" not in repr(matches[0])
    assert "queueUrl" not in repr(matches[0])
