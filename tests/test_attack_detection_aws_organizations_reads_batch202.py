"""Synthetic Organizations ARNPrefix read events."""

from copy import deepcopy

from peaso.attack_detection.aws_organizations_reads_batch202 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
NAMES = {
    "ListRoots": "AWS::Organizations::Root",
    "ListAccounts": "AWS::Organizations::Account",
    "ListDelegatedAdministrators": "AWS::Organizations::Account",
    "ListPolicies": "AWS::Organizations::Policy",
}


def event(name):
    return {
        "eventSource": "organizations.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": True,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-" + name, "eventTime": "2026-10-22T00:00:00Z",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-reader"},
        "requestParameters": {"filter": "SERVICE_CONTROL_POLICY"} if name == "ListPolicies" else {},
        "responseElements": None,
        "resources": [{"type": NAMES[name], "accountId": ACCOUNT,
                       "ARNPrefix": f"arn:aws:organizations::{ACCOUNT}:synthetic/"}],
    }


def rules():
    return tuple(Rule(
        id=f"20200000-0000-4000-8000-{i:012d}", title=name, level="low",
        description=name, technique_id="aws-organizations-" + name.lower(),
        product="aws", selection={
            "event.source": "organizations.amazonaws.com", "event.name": name,
            "event.outcome": "success", "request.organizations_scope_listed": True,
        },
    ) for i, name in enumerate(NAMES, 3))


def test_four_reads_match_without_exporting_org_identifiers():
    rows = [event(name) for name in NAMES]
    signals = [normalize(row) for row in rows]
    assert all(signals)
    assert len(detect_aws_events(rows, rules())) == 4
    for signal in signals:
        assert signal["target.id"].startswith("sha256:")
        assert "synthetic/" not in str(signal)


def test_errors_resource_mismatch_and_non_scp_filter_do_not_match():
    base = event("ListPolicies")
    negatives = []
    for field, value in [("errorCode", "AccessDeniedException"),
                         ("eventCategory", "Data"), ("readOnly", False),
                         ("eventSource", "other.amazonaws.com")]:
        changed = deepcopy(base); changed[field] = value; negatives.append(changed)
    changed = deepcopy(base); changed["resources"][0]["type"] = "AWS::Organizations::Account"
    negatives.append(changed)
    changed = deepcopy(base); changed["resources"][0]["accountId"] = "888888888888"
    negatives.append(changed)
    changed = deepcopy(base); changed["resources"][0]["ARNPrefix"] = "invalid"
    negatives.append(changed)
    changed = deepcopy(base); changed["requestParameters"]["filter"] = "TAG_POLICY"
    negatives.append(changed)
    assert all(normalize(row) is None for row in negatives)
    assert detect_aws_events(negatives, rules()) == []
