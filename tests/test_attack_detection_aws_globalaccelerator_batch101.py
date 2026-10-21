"""Synthetic CloudTrail derivatives of the owned Global Accelerator lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-west-2"
BASE = f"arn:aws:globalaccelerator::{ACCOUNT}:accelerator/synthetic"
TARGETS = {"UpdateAccelerator": ("acceleratorArn", BASE, "accelerator"),
           "UpdateListener": ("listenerArn", BASE + "/listener/synthetic", "listener"),
           "UpdateEndpointGroup": ("endpointGroupArn", BASE + "/listener/synthetic/endpoint-group/synthetic", "endpointGroup")}
IDS = {f"aws-globalaccelerator-{suffix}" for suffix in (
    "traffic-dial-zero", "health-port-changed", "port-override-added",
    "listener-ports-updated", "listener-udp-selected", "disabled")}


def event(name, extra_request, extra_result, index):
    key, target, obj = TARGETS[name]
    return {"eventSource": "globalaccelerator.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": f"11111111-1111-4111-8111-{index:012d}",
            "eventTime": "2026-10-21T00:00:00Z",
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
            "requestParameters": {key: target, **extra_request},
            "responseElements": {obj: {key: target, **extra_result}}}


def fixtures():
    override = [{"listenerPort": 18080, "endpointPort": 18081}]
    ports = [{"fromPort": 18081, "toPort": 18081}]
    return [event("UpdateEndpointGroup", {"trafficDialPercentage": 0.0},
                  {"trafficDialPercentage": 0.0}, 1),
            event("UpdateEndpointGroup", {"healthCheckPort": 65000},
                  {"healthCheckPort": 65000}, 2),
            event("UpdateEndpointGroup", {"portOverrides": override},
                  {"portOverrides": override}, 3),
            event("UpdateListener", {"portRanges": ports}, {"portRanges": ports}, 4),
            event("UpdateListener", {"protocol": "UDP"}, {"protocol": "UDP"}, 5),
            event("UpdateAccelerator", {"enabled": False}, {"enabled": False}, 6)]


def rules():
    return [r for r in load_rules(product="aws") if r.technique_id in IDS]


def test_six_successful_management_changes_match():
    selected = rules()
    assert len(selected) == 6
    hits = detect_aws_events(fixtures(), selected)
    assert len(hits) == 6
    assert {h.technique_id for h in hits} == IDS
    assert all(h.target_id and "synthetic" in h.target_id for h in hits)


def test_denied_and_mismatched_responses_do_not_match():
    selected = rules()
    for source in fixtures():
        denied = deepcopy(source)
        denied["errorCode"] = "AccessDeniedException"
        assert detect_aws_events([denied], selected) == []
        mismatch = deepcopy(source)
        obj = TARGETS[source["eventName"]][2]
        mismatch["responseElements"][obj][TARGETS[source["eventName"]][0]] = "arn:aws:globalaccelerator::999999999999:accelerator/other"
        assert detect_aws_events([mismatch], selected) == []


def test_empty_override_and_enabled_accelerator_do_not_match():
    empty = event("UpdateEndpointGroup", {"portOverrides": []}, {"portOverrides": []}, 7)
    enabled = event("UpdateAccelerator", {"enabled": True}, {"enabled": True}, 8)
    assert detect_aws_events([empty, enabled], rules()) == []
