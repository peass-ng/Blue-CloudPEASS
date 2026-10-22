"""Broad AOSS policy writes are distinct from narrow or denied writes."""

from __future__ import annotations

from copy import deepcopy
import json

from peaso.attack_detection.aws_aoss_broad_grant import normalize_aws_aoss_broad_grant
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic"


def policy(*, broad=True, principal=ROLE):
    resource = "*" if broad else "synthetic-only"
    return json.dumps([{"Rules": [
        {"ResourceType": "collection", "Resource": [f"collection/{resource}"],
         "Permission": ["aoss:*" if broad else "aoss:DescribeCollectionItems"]},
        {"ResourceType": "index", "Resource": [f"index/{resource}/*"],
         "Permission": ["aoss:*" if broad else "aoss:ReadDocument"]},
    ], "Principal": [principal]}])


def event(action="CreateAccessPolicy", *, broad=True):
    return {
        "eventSource": "aoss.amazonaws.com", "eventName": action,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-2",
        "eventID": "synthetic-event", "eventTime": "2026-10-22T12:00:00Z",
        "userIdentity": {"accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"name": "synthetic-policy", "type": "data",
                              "policy": policy(broad=broad)},
        "responseElements": {"accessPolicyDetail": {
            "name": "synthetic-policy", "type": "data",
            "policyVersion": "synthetic-version", "policy": "[AWS map rendering]"}},
    }


def rules(tmp_path):
    for action, suffix in (("CreateAccessPolicy", "create"), ("UpdateAccessPolicy", "update")):
        (tmp_path / f"{suffix}.yml").write_text(f"""title: Synthetic AOSS {suffix}
id: b3790000-0000-4000-8000-00000000000{1 if suffix == 'create' else 2}
status: experimental
description: Synthetic test rule.
references: [https://example.test/aoss]
logsource: {{product: aws, service: cloudtrail}}
detection:
  selection:
    event.source: aoss.amazonaws.com
    event.name: {action}
    event.outcome: success
    request.aoss_broad_access_grant_requested: true
  condition: selection
falsepositives: [Approved broad grant]
level: high
x_hacktricks_technique_id: synthetic-aoss-{suffix}
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_create_and_update_broad_grants_match_without_policy_content(tmp_path):
    hits = detect_aws_events([event(), event("UpdateAccessPolicy")], rules(tmp_path))
    assert {x.technique_id for x in hits} == {"synthetic-aoss-create", "synthetic-aoss-update"}
    assert all(x.target_id.startswith("sha256:") for x in hits)
    assert ROLE not in str(hits)
    assert "collection/*" not in str(hits)


def test_narrow_denied_foreign_and_unconfirmed_grants_fail_closed(tmp_path):
    base = event()
    variants = [event(broad=False)]
    changes = (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
        lambda x: x["userIdentity"].update(accountId="111111111111"),
        lambda x: x["requestParameters"].update(type="network"),
        lambda x: x["requestParameters"].update(policy=policy(principal=ROLE.replace(ACCOUNT, "111111111111"))),
        lambda x: x["responseElements"]["accessPolicyDetail"].update(name="other"),
        lambda x: x["responseElements"].update(accessPolicyDetail={}),
        lambda x: x.update(eventSource="other.amazonaws.com"),
        lambda x: x["requestParameters"].update(policy="invalid-json"),
    )
    for change in changes:
        variant = deepcopy(base)
        change(variant)
        variants.append(variant)
    assert detect_aws_events(variants, rules(tmp_path)) == []


def test_collection_and_index_grants_must_reach_same_principal():
    split = event()
    document = json.loads(policy())
    document[0]["Rules"] = document[0]["Rules"][:1]
    document.append({"Principal": [f"arn:aws:iam::{ACCOUNT}:role/another"],
                     "Rules": json.loads(policy())[0]["Rules"][1:]})
    split["requestParameters"]["policy"] = json.dumps(document)
    assert normalize_aws_aoss_broad_grant(split) is None
