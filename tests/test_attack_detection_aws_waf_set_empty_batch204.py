"""Synthetic WAF empty-set CloudTrail derivatives."""

from copy import deepcopy

from peaso.attack_detection.aws_waf_set_empty_batch204 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"


def event(name):
    field = "addresses" if name == "UpdateIPSet" else "regularExpressionList"
    return {
        "eventSource": "wafv2.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-" + name, "eventTime": "2026-10-22T00:00:00Z",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-admin"},
        "requestParameters": {"name": "synthetic-set", "id": "synthetic-id",
                              "scope": "REGIONAL", field: [], "lockToken": "synthetic-old-token"},
        "responseElements": {"nextLockToken": "synthetic-new-token"},
    }


def rules():
    return tuple(Rule(
        id=f"20400000-0000-4000-8000-{i:012d}", title=name, level="medium",
        description=name, technique_id="aws-waf-" + name.lower(), product="aws",
        selection={"event.source": "wafv2.amazonaws.com", "event.name": name,
                   "event.outcome": "success", flag: True},
    ) for i, (name, flag) in enumerate([
        ("UpdateIPSet", "request.waf_ip_set_emptied"),
        ("UpdateRegexPatternSet", "request.waf_regex_pattern_set_emptied"),
    ], 3))


def test_both_empty_updates_match_without_set_or_token_leak():
    rows = [event("UpdateIPSet"), event("UpdateRegexPatternSet")]
    signals = [normalize(row) for row in rows]
    assert all(signals)
    assert len(detect_aws_events(rows, rules())) == 2
    for signal in signals:
        assert signal["target.id"].startswith("sha256:")
        assert "synthetic-set" not in str(signal)
        assert "synthetic-old-token" not in str(signal)


def test_nonempty_failed_and_wrong_event_variants_do_not_match():
    base = event("UpdateIPSet")
    negatives = []
    for field, value in [("errorCode", "WAFOptimisticLockException"),
                         ("eventCategory", "Data"), ("readOnly", True),
                         ("eventSource", "other.amazonaws.com")]:
        changed = deepcopy(base);changed[field] = value;negatives.append(changed)
    changed = deepcopy(base);changed["requestParameters"]["addresses"] = ["203.0.113.1/32"]
    negatives.append(changed)
    changed = deepcopy(base);changed["responseElements"] = None;negatives.append(changed)
    changed = deepcopy(base);changed["requestParameters"]["scope"] = "INVALID";negatives.append(changed)
    changed = deepcopy(event("UpdateRegexPatternSet"))
    changed["requestParameters"]["regularExpressionList"] = [{"regexString": "^/admin"}]
    negatives.append(changed)
    assert all(normalize(row) is None for row in negatives)
    assert detect_aws_events(negatives, rules()) == []
