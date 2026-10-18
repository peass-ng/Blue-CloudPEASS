"""KMS DescribeKey decisions independent of unread ListResourceTags."""
from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

ACCOUNT = "123456789012"
REGION = "us-east-1"
KEY_ID = "1234abcd-12ab-34cd-56ef-1234567890ab"
ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/{KEY_ID}"
CHECK = "aws_kms_key_expiry"


def run(monkeypatch, *, origin="AWS_KMS", state="Enabled", model=None, valid_to=None,
        tags=None, denied_tags=False, partial_tags=False, detail_denied=False,
        foreign=False, enabled_override=None):
    session = boto3.Session(aws_access_key_id="fixture-key", aws_secret_access_key="fixture-secret", region_name=REGION)
    sts, kms = (session.client(service, region_name=REGION) for service in ("sts", "kms"))
    ss, ks = Stubber(sts), Stubber(kms)
    ss.add_response("get_caller_identity", {"Account": ACCOUNT,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAREVIEWER"}, {})
    ks.add_response("list_keys", {"Keys": [{"KeyId": KEY_ID, "KeyArn": ARN}], "Truncated": False}, {})
    if detail_denied:
        ks.add_client_error("describe_key", "AccessDeniedException", expected_params={"KeyId": KEY_ID})
    else:
        metadata = {"KeyId": KEY_ID, "Arn": ARN, "AWSAccountId": "999999999999" if foreign else ACCOUNT,
                    "Origin": origin, "KeyState": state,
                    "Enabled": state == "Enabled" if enabled_override is None else enabled_override}
        if model is not None:
            metadata["ExpirationModel"] = model
        if valid_to is not None:
            metadata["ValidTo"] = datetime.fromisoformat(valid_to.replace("Z", "+00:00"))
        ks.add_response("describe_key", {"KeyMetadata": metadata}, {"KeyId": KEY_ID})
    ks.add_response("get_key_rotation_status", {"KeyRotationEnabled": False}, {"KeyId": KEY_ID})
    ks.add_response("get_key_policy", {"Policy": '{"Version":"2012-10-17","Statement":[]}'},
                    {"KeyId": KEY_ID, "PolicyName": "default"})
    if partial_tags:
        ks.add_response("list_resource_tags", {"Tags": [{"TagKey": "Other", "TagValue": "x"}],
                                               "Truncated": True, "NextMarker": "more"}, {"KeyId": KEY_ID})
        ks.add_client_error("list_resource_tags", "AccessDeniedException",
                            expected_params={"KeyId": KEY_ID, "Marker": "more"})
    elif denied_tags:
        ks.add_client_error("list_resource_tags", "AccessDeniedException", expected_params={"KeyId": KEY_ID})
    else:
        ks.add_response("list_resource_tags", {"Tags": tags or [], "Truncated": False}, {"KeyId": KEY_ID})
    clients = {"sts": sts, "kms": kms}
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: clients[service])
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "fixture"))
    with ss, ks:
        snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT],
                                "options": {"regions": [REGION], "service_concurrency": 1}}, ["kms_key"])
        findings = [row for row in evaluate_snapshot(snapshot, checks=[CHECK])["findings"]
                    if row["check_id"] == CHECK and not row["resource_id"].startswith("inventory:")]
        assert len(findings) == 1
        return findings[0], snapshot


@pytest.mark.parametrize("state,model,valid_to,expected", [
    ("PendingImport", "KEY_MATERIAL_EXPIRES", "2026-01-01T00:00:00Z", "FAIL"),
    ("Disabled", None, None, "PASS"),
    ("Disabled", "KEY_MATERIAL_EXPIRES", "2027-01-01T00:00:00Z", "PASS"),
    ("Enabled", None, None, "UNKNOWN"),
    ("Enabled", "KEY_MATERIAL_EXPIRES", "2027-01-01T00:00:00Z", "UNKNOWN"),
])
def test_denied_tags_only_independent_describe_key_decides(monkeypatch, state, model, valid_to, expected):
    origin = "EXTERNAL" if model else "AWS_KMS"
    row, snapshot = run(monkeypatch, origin=origin, state=state, model=model,
                        valid_to=valid_to, denied_tags=True)
    assert row["status"] == expected
    item = next(c for c in snapshot["collections"] if c["type"] == "kms_key")["items"][0]
    assert item["_coverage"]["Tags"]["status"] == "denied"
    assert "Tags" not in item
    if expected != "UNKNOWN":
        assert row["evidence"]["retirement_marker"] == "not_evaluated"
        assert "retired" not in row["evidence"]


def test_partial_tags_and_complete_tags(monkeypatch):
    expired, snapshot = run(monkeypatch, origin="EXTERNAL", state="PendingImport",
        model="KEY_MATERIAL_EXPIRES", valid_to="2026-01-01T00:00:00Z", partial_tags=True)
    assert expired["status"] == "FAIL"
    item = next(c for c in snapshot["collections"] if c["type"] == "kms_key")["items"][0]
    assert item["_coverage"]["Tags"]["status"] == "partial"
    assert run(monkeypatch, partial_tags=True)[0]["status"] == "UNKNOWN"
    assert run(monkeypatch, tags=[{"TagKey": "Retired", "TagValue": "true"}])[0]["status"] == "FAIL"
    assert run(monkeypatch, state="Disabled", tags=[{"TagKey": "Retired", "TagValue": "true"}])[0]["status"] == "PASS"
    assert run(monkeypatch, tags=[])[0]["status"] == "PASS"


def test_required_detail_identity_and_model_guards(monkeypatch):
    assert run(monkeypatch, state="Disabled", denied_tags=True, foreign=True)[0]["status"] == "UNKNOWN"
    assert run(monkeypatch, state="Disabled", denied_tags=True, detail_denied=True)[0]["status"] == "UNKNOWN"
    assert run(monkeypatch, state="Disabled", denied_tags=True, enabled_override=True)[0]["status"] == "UNKNOWN"
    assert run(monkeypatch, origin="EXTERNAL", state="Disabled", model="unexpected",
               denied_tags=True)[0]["status"] == "UNKNOWN"
