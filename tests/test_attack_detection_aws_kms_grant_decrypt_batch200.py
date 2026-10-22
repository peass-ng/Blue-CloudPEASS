"""KMS grant-to-Decrypt correlation with synthetic CloudTrail derivatives."""

from copy import deepcopy

from peaso.attack_detection.aws_kms_grant_decrypt_batch200 import correlate
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
KEY = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY}"
USER = f"arn:aws:iam::{ACCOUNT}:user/synthetic-grantee"
ADMIN = f"arn:aws:iam::{ACCOUNT}:user/synthetic-admin"


def event(name, request, *, actor=ADMIN, stamp="2026-10-22T00:00:00Z", event_id=None):
    return {
        "eventSource": "kms.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": name == "Decrypt",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": event_id or "synthetic-" + name,
        "eventTime": stamp, "userIdentity": {"type": "IAMUser", "arn": actor},
        "requestParameters": {"keyId": KEY, **request},
        "responseElements": None,
    }


def grant():
    row = event("CreateGrant", {"granteePrincipal": USER, "operations": ["Decrypt"]})
    row["responseElements"] = {"grantId": "synthetic-grant", "keyId": ARN}
    return row


def decrypt():
    return event("Decrypt", {"encryptionContext": {"synthetic": "canary"}}, actor=USER)


def rule():
    return Rule(
        id="20000000-0000-4000-8000-000000000001",
        title="KMS Decrypt by recently granted principal", level="medium",
        description="Accepted Decrypt close to a successful grant", technique_id="aws-kms-recent-grantee-decrypt",
        product="aws", selection={
            "event.source": "kms.amazonaws.com", "event.name": "Decrypt",
            "event.outcome": "success", "request.kms_recent_grantee_decrypt": True,
        },
    )


def test_recent_grant_and_decrypt_match_even_if_input_is_unordered():
    rows = [decrypt(), grant()]
    signal = correlate(rows)
    assert len(signal) == 1
    assert signal[0]["request.kms_recent_grantee_decrypt"] is True
    assert signal[0]["correlation_evidence"] == {"paired_grant_event_id": "synthetic-CreateGrant"}
    assert signal[0]["target.id"].startswith("sha256:")
    assert KEY not in str(signal) and "canary" not in str(signal)
    assert len(detect_aws_events(rows, (rule(),))) == 1


def test_unrelated_failed_old_or_revoked_grants_do_not_match():
    base = grant()
    current = decrypt()
    variants = []
    changed = deepcopy(base)
    changed["errorCode"] = "InvalidArnException"
    variants.append([changed, current])
    changed = deepcopy(base)
    changed["requestParameters"]["granteePrincipal"] = ADMIN
    variants.append([changed, current])
    changed = deepcopy(base)
    changed["requestParameters"]["operations"] = ["Encrypt"]
    variants.append([changed, current])
    changed = deepcopy(current)
    changed["requestParameters"]["keyId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    variants.append([base, changed])
    changed = deepcopy(current)
    changed["errorCode"] = "AccessDeniedException"
    variants.append([base, changed])
    changed = deepcopy(current)
    changed["eventTime"] = "2026-10-22T00:16:00Z"
    variants.append([base, changed])
    revoke = event("RevokeGrant", {"grantId": "synthetic-grant"}, stamp="2026-10-22T00:00:01Z")
    changed = deepcopy(current)
    changed["eventTime"] = "2026-10-22T00:00:02Z"
    variants.append([base, revoke, changed])
    for rows in variants:
        assert correlate(rows) == []
        assert detect_aws_events(rows, (rule(),)) == []


def test_malformed_input_is_ignored_by_event_dispatcher():
    assert detect_aws_events([None, "invalid", grant(), decrypt()], (rule(),)) == [
        *detect_aws_events([grant(), decrypt()], (rule(),))
    ]
