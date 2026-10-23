"""Synthetic derivatives for AppStream entitlement and transfer configuration."""

from copy import deepcopy

from peaso.attack_detection.aws_appstream_controls_batch193 import normalize


def event(name, request):
    return {
        "eventSource": "appstream.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": "999999999999", "awsRegion": "us-east-1",
        "eventID": "synthetic-event", "eventTime": "2026-10-22T00:00:00Z",
        "userIdentity": {"type": "IAMUser", "accountId": "999999999999",
                         "arn": "arn:aws:iam::999999999999:user/synthetic"},
        "requestParameters": request, "responseElements": {},
    }


def entitlement(name, visibility="ALL"):
    return event(name, {"stackName": "synthetic-stack", "name": "synthetic-entitlement",
                        "appVisibility": visibility,
                        "attributes": [{"name": "groups", "value": "synthetic-group"}]})


def test_entitlement_all_requires_accepted_exact_visibility_and_attributes():
    for name in ("CreateEntitlement", "UpdateEntitlement"):
        row = entitlement(name)
        signal = normalize(row)
        assert len(signal) == 1
        assert signal[0]["request.appstream_entitlement_all_apps"] is True
        assert signal[0]["target.id"].startswith("sha256:")
        assert "synthetic-group" not in str(signal)
        assert "synthetic-stack" not in str(signal)
        for change in (
            {"requestParameters": {**row["requestParameters"], "appVisibility": "ASSOCIATED"}},
            {"requestParameters": {**row["requestParameters"], "attributes": []}},
            {"errorCode": "ResourceNotFoundException"},
            {"readOnly": True},
            {"userIdentity": {"type": "AWSService", "invokedBy": "appstream.amazonaws.com"}},
        ):
            bad = deepcopy(row)
            bad.update(change)
            assert normalize(bad) == []


def test_transfer_channel_requires_explicit_enablement():
    row = event("UpdateStack", {
        "name": "synthetic-stack", "userSettings": [
            {"action": "FILE_DOWNLOAD", "permission": "ENABLED"},
            {"action": "FILE_UPLOAD", "permission": "DISABLED"},
        ],
    })
    assert normalize(row)[0]["request.appstream_transfer_channel_enabled"] is True
    disabled = deepcopy(row)
    disabled["requestParameters"]["userSettings"][0]["permission"] = "DISABLED"
    assert normalize(disabled) == []
    unknown = deepcopy(row)
    unknown["requestParameters"]["userSettings"][0]["action"] = "UNKNOWN"
    assert normalize(unknown) == []


def test_agent_input_requires_explicit_enablement_and_success():
    row = event("UpdateStack", {
        "name": "synthetic-stack", "agentAccessConfig": {"settings": [
            {"agentAction": "COMPUTER_VISION", "permission": "ENABLED"},
            {"agentAction": "COMPUTER_INPUT", "permission": "ENABLED"},
        ]},
    })
    assert normalize(row)[0]["request.appstream_agent_input_enabled"] is True
    disabled = deepcopy(row)
    disabled["requestParameters"]["agentAccessConfig"]["settings"][1]["permission"] = "DISABLED"
    assert normalize(disabled) == []
    failed = deepcopy(row)
    failed["errorCode"] = "InvalidParameterCombinationException"
    assert normalize(failed) == []


def test_agent_tool_forwarding_and_observer_mode_are_distinct():
    row = event("UpdateStack", {
        "name": "synthetic-stack", "agentAccessConfig": {
            "settings": [{"agentAction": "FORWARD_MCP_TOOLS", "permission": "ENABLED"}],
            "userControlMode": "DISABLED",
        },
    })
    signal = normalize(row)[0]
    assert signal["request.appstream_agent_tools_forwarded"] is True
    assert signal["request.appstream_agent_observer_disabled"] is True
    assert "request.appstream_agent_input_enabled" not in signal
    allowed = deepcopy(row)
    allowed["requestParameters"]["agentAccessConfig"]["userControlMode"] = "VIEW_STOP"
    assert "request.appstream_agent_observer_disabled" not in normalize(allowed)[0]
    disabled = deepcopy(row)
    disabled["requestParameters"]["agentAccessConfig"]["settings"][0]["permission"] = "DISABLED"
    assert "request.appstream_agent_tools_forwarded" not in normalize(disabled)[0]


def test_unrelated_events_and_invalid_structure_fail_closed():
    row = entitlement("CreateEntitlement")
    for key, value in (("eventSource", "other.amazonaws.com"),
                       ("eventCategory", "Data"), ("managementEvent", False),
                       ("recipientAccountId", "invalid"), ("eventTime", "invalid")):
        altered = deepcopy(row)
        altered[key] = value
        assert normalize(altered) == []
