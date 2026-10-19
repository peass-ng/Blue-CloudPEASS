"""WAF rule order and count-only ACL observations."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULES = [
    Rule(id="allow-before-block", title="Allow before block", level="high", description="allow",
         technique_id="aws-waf-allow-overrides-same-block", product="aws",
         selection={"event.source": "wafv2.amazonaws.com", "event.name": "UpdateWebACL",
                    "event.outcome": "success", "request.waf_allow_overrides_same_block": True}),
    Rule(id="count-only", title="Count only", level="medium", description="count",
         technique_id="aws-waf-all-rules-count-default-allow", product="aws",
         selection={"event.source": "wafv2.amazonaws.com", "event.name": "UpdateWebACL",
                    "event.outcome": "success", "request.waf_all_rules_count_default_allow": True}),
    Rule(id="managed-count", title="Managed count", level="medium", description="count",
         technique_id="aws-waf-managed-group-count-unblocked", product="aws",
         selection={"event.source": "wafv2.amazonaws.com", "event.name": "UpdateWebACL",
                    "event.outcome": "success", "request.waf_managed_group_count_unblocked": True}),
]


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], RULES)]


def _event() -> dict:
    statement = {"byteMatchStatement": {"searchString": {"hb": [98, 108, 111, 99, 107]},
                 "fieldToMatch": {"singleHeader": {"name": "x-peasso-test"}},
                 "positionalConstraint": "EXACTLY"}}
    return {"eventSource": "wafv2.amazonaws.com", "eventName": "UpdateWebACL",
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": "947247140022",
            "requestParameters": {"id": "a4fceb6d-1195-4087-9b83-4709e869a14c",
                                  "name": "synthetic-acl", "defaultAction": {"allow": {}},
                                  "rules": [{"name": "allow", "priority": 0, "action": {"allow": {}},
                                             "statement": deepcopy(statement)},
                                            {"name": "block", "priority": 10, "action": {"block": {}},
                                             "statement": deepcopy(statement)}]},
            "responseElements": {"nextLockToken": "synthetic-lock"}}


def test_allow_precedes_identical_block() -> None:
    event = _event()
    assert _hits(event) == ["aws-waf-allow-overrides-same-block"]
    for variant in ("different_statement", "lower_priority", "failed", "no_token", "data_event"):
        item = deepcopy(event)
        rules = item["requestParameters"]["rules"]
        if variant == "different_statement":
            rules[0]["statement"]["byteMatchStatement"]["searchString"]["hb"] = [97]
        if variant == "lower_priority": rules[0]["priority"] = 20
        if variant == "failed": item["errorCode"] = "WAFOptimisticLockException"
        if variant == "no_token": item["responseElements"] = {}
        if variant == "data_event": item["eventCategory"] = "Data"
        assert _hits(item) == [], variant


def test_all_count_rules_with_default_allow() -> None:
    event = _event()
    event["requestParameters"]["rules"] = [{"name": "block", "priority": 10,
        "action": {"count": {}}, "statement": {"byteMatchStatement": {}}}]
    assert _hits(event) == ["aws-waf-all-rules-count-default-allow"]
    for variant in ("block_rule", "default_block", "empty_rules", "failed"):
        item = deepcopy(event)
        if variant == "block_rule":
            item["requestParameters"]["rules"].append({"action": {"block": {}}, "priority": 20})
        if variant == "default_block": item["requestParameters"]["defaultAction"] = {"block": {}}
        if variant == "empty_rules": item["requestParameters"]["rules"] = []
        if variant == "failed": item["errorCode"] = "AccessDeniedException"
        assert _hits(item) == [], variant


def test_managed_group_count_override_with_no_blocking_rule() -> None:
    event = _event()
    event["requestParameters"]["rules"] = [{"name": "managed", "priority": 0,
        "statement": {"managedRuleGroupStatement": {"vendorName": "AWS",
                                                      "name": "AWSManagedRulesCommonRuleSet"}},
        "overrideAction": {"count": {}}}]
    assert _hits(event) == ["aws-waf-managed-group-count-unblocked"]
    for variant in ("override_none", "default_block", "other_block", "failed"):
        item = deepcopy(event)
        if variant == "override_none": item["requestParameters"]["rules"][0]["overrideAction"] = {"none": {}}
        if variant == "default_block": item["requestParameters"]["defaultAction"] = {"block": {}}
        if variant == "other_block":
            item["requestParameters"]["rules"].append({"action": {"block": {}}, "priority": 1})
        if variant == "failed": item["errorCode"] = "AccessDeniedException"
        assert _hits(item) == [], variant
