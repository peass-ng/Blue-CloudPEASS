"""Synthetic derivatives of owned standard and custom routing labs."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
ACC = f"arn:aws:globalaccelerator::{ACCOUNT}:accelerator/synthetic"
LISTENER = ACC + "/listener/synthetic"
GROUP = LISTENER + "/endpoint-group/synthetic"
IDS = {"aws-globalaccelerator-" + name for name in (
    "source-ip-affinity", "endpoint-weight-zero", "endpoint-group-replaced",
    "flow-logs-disabled", "custom-mappings-read", "custom-allow-all",
    "custom-deny-all")}


def event(name, request, response, minute, read=False):
    return {"eventSource": "globalaccelerator.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": read,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-west-2",
            "eventID": f"22222222-2222-4222-8222-{minute+1:012d}",
            "eventTime": (datetime(2026, 10, 21, tzinfo=timezone.utc)
                          + timedelta(minutes=minute)).isoformat(),
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
            "requestParameters": request, "responseElements": response}


def endpoint(endpoint_id, weight):
    return {"endpointId": endpoint_id, "weight": weight}


def group_update(endpoint_id, weight, minute):
    cfg = [endpoint(endpoint_id, weight)]
    return event("UpdateEndpointGroup", {"endpointGroupArn": GROUP,
                 "endpointConfigurations": cfg},
                 {"endpointGroup": {"endpointGroupArn": GROUP,
                                    "endpointDescriptions": cfg}}, minute)


def fixtures():
    first = "eipalloc-synthetic-1"
    second = "eipalloc-synthetic-2"
    return [
        event("UpdateListener", {"listenerArn": LISTENER, "clientAffinity": "SOURCE_IP"},
              {"listener": {"listenerArn": LISTENER, "clientAffinity": "SOURCE_IP"}}, 0),
        group_update(first, 128, 1),
        group_update(first, 0, 2),
        group_update(second, 128, 3),
        event("UpdateAcceleratorAttributes", {"acceleratorArn": ACC,
              "flowLogsEnabled": False}, {"acceleratorAttributes": {"flowLogsEnabled": False}}, 4),
        event("ListCustomRoutingPortMappings", {"acceleratorArn": ACC,
              "endpointGroupArn": GROUP}, None, 5, read=True),
        event("AllowCustomRoutingTraffic", {"endpointGroupArn": GROUP,
              "endpointId": "subnet-synthetic", "allowAllTrafficToEndpoint": True}, None, 6),
        event("DenyCustomRoutingTraffic", {"endpointGroupArn": GROUP,
              "endpointId": "subnet-synthetic", "denyAllTrafficToEndpoint": True}, None, 7),
    ]


def rules():
    return [r for r in load_rules(product="aws") if r.technique_id in IDS]


def test_seven_routes_match_synthetic_derivatives():
    selected = rules()
    assert len(selected) == 7
    hits = detect_aws_events(fixtures(), selected)
    assert len(hits) == 7
    assert {hit.technique_id for hit in hits} == IDS
    assert "eipalloc-synthetic" not in str(hits)


def test_denied_calls_and_inconsistent_responses_are_excluded():
    selected = rules()
    for record in fixtures():
        rejected = deepcopy(record)
        rejected["errorCode"] = "AccessDeniedException"
        assert detect_aws_events([rejected], selected) == []
    bad = deepcopy(fixtures())
    bad[2]["responseElements"]["endpointGroup"]["endpointDescriptions"][0]["weight"] = 128
    assert "aws-globalaccelerator-endpoint-weight-zero" not in {
        hit.technique_id for hit in detect_aws_events(bad, selected)}


def test_replacement_requires_same_actor_and_disjoint_endpoint_sets():
    selected = rules()
    records = [group_update("eipalloc-synthetic-1", 128, 1),
               group_update("eipalloc-synthetic-2", 128, 2)]
    assert any(h.technique_id == "aws-globalaccelerator-endpoint-group-replaced"
               for h in detect_aws_events(records, selected))
    records[1]["userIdentity"]["arn"] = f"arn:aws:iam::{ACCOUNT}:user/synthetic-other"
    assert not any(h.technique_id == "aws-globalaccelerator-endpoint-group-replaced"
                   for h in detect_aws_events(records, selected))
