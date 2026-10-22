"""Synthetic WAF IP set tag-removal event."""

from copy import deepcopy

from peaso.attack_detection.aws_waf_ipset_untag_batch205 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
ARN = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:regional/ipset/synthetic-set/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def event():
    return {
        "eventSource": "wafv2.amazonaws.com", "eventName": "UntagResource",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-untag", "eventTime": "2026-10-22T00:00:00Z",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-admin"},
        "requestParameters": {"resourceARN": ARN, "tagKeys": ["synthetic-security-tag"]},
        "responseElements": None,
    }


def rule():
    return Rule(
        id="20500000-0000-4000-8000-000000000002",
        title="WAF IP set tags removed", level="low",
        description="Accepted IP set untag", technique_id="aws-waf-ipset-tags-removed",
        product="aws", selection={
            "event.source": "wafv2.amazonaws.com", "event.name": "UntagResource",
            "event.outcome": "success", "request.waf_ipset_tags_removed": True,
        },
    )


def test_tag_removal_matches_without_exporting_tag_or_arn():
    row = event()
    signal = normalize(row)
    assert signal is not None
    assert signal["target.id"].startswith("sha256:")
    assert ARN not in str(signal) and "synthetic-security-tag" not in str(signal)
    assert len(detect_aws_events([row], (rule(),))) == 1


def test_wrong_scope_failed_and_empty_tag_list_do_not_match():
    base = event()
    variants = []
    for field, value in [("errorCode", "WAFNonexistentItemException"),
                         ("eventCategory", "Data"), ("readOnly", True),
                         ("eventName", "TagResource")]:
        changed = deepcopy(base);changed[field] = value;variants.append(changed)
    changed = deepcopy(base);changed["requestParameters"]["tagKeys"] = [];variants.append(changed)
    changed = deepcopy(base);changed["requestParameters"]["resourceARN"] = ARN.replace("regional/ipset", "regional/webacl")
    variants.append(changed)
    changed = deepcopy(base);changed["requestParameters"]["resourceARN"] = ARN.replace(ACCOUNT, "888888888888")
    variants.append(changed)
    changed = deepcopy(base); changed["userIdentity"]["accountId"] = "888888888888"
    variants.append(changed)
    assert all(normalize(row) is None for row in variants)
    assert detect_aws_events(variants, (rule(),)) == []
