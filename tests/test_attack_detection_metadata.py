"""Rule context stays attached to evidence without changing match semantics."""

from peaso.attack_detection import detect_aws_events, load_rules


def test_authorized_context_is_reported_with_matched_evidence(tmp_path):
    (tmp_path / "example.yml").write_text(
        "id: example\n"
        "title: Example IAM action\n"
        "level: medium\n"
        "description: A successful IAM action occurred; prior effective access is unknown.\n"
        "falsepositives:\n"
        "  - Approved IAM administration\n"
        "x_hacktricks_technique_id: example\n"
        "logsource: {product: aws, service: cloudtrail}\n"
        "detection:\n"
        "  selection: {event.name: ExampleAction, event.outcome: success}\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    rules = load_rules(tmp_path, product="aws")
    events = [{
        "eventSource": "iam.amazonaws.com", "eventName": "ExampleAction",
        "eventID": "test-event", "requestParameters": {},
    }]
    matches = detect_aws_events(events, rules)
    assert len(matches) == 1
    assert matches[0].description == "A successful IAM action occurred; prior effective access is unknown."
    assert matches[0].legitimate_context == ("Approved IAM administration",)
    assert matches[0].evidence == {"event.name": "ExampleAction", "event.outcome": "success"}


def test_azure_activity_rule_is_loaded_from_reviewed_sigma_subset(tmp_path):
    (tmp_path / "azure.yml").write_text(
        "id: azure-example\n"
        "title: Reviewed Azure activity\n"
        "level: high\n"
        "description: A correlated role assignment completed.\n"
        "x_hacktricks_technique_id: azure-example\n"
        "logsource: {product: azure, service: activity}\n"
        "detection:\n"
        "  selection: {event.name: role_self_assignment, event.outcome: success}\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    rules = load_rules(tmp_path, product="azure")
    assert len(rules) == 1
    assert rules[0].selection["event.name"] == "role_self_assignment"
