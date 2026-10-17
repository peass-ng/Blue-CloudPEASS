"""Independent date, applicability, join and collection truth cases."""
import copy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.checks import CHECKS, aws_a_iam_lifecycle as rules
from peaso.checks.fixtures import CASES
from peaso.checks.aws_a_facts import scope_fixture

REGISTRY = {c.id: c for c in CHECKS if c.id in rules.NATIVE_IDS}


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_real_source_variant_states_and_input_purity(cid):
    cases = CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item = copy.deepcopy(cases[state])
        index = copy.deepcopy(cases.get(state + "_index", cases.get("index", {})))
        before = copy.deepcopy((item, index))
        if cid == "aws.a.iam.console_key_created_at_setup" and state == "fail":
            expected = "UNKNOWN"  # Rotation is not evidence of first-key creation.
        assert REGISTRY[cid].evaluate(item, index)[0] == expected
        assert (item, index) == before
    assert REGISTRY[cid].evaluate({"collection_status": "denied"}, cases.get("index", {}))[0] == "UNKNOWN"


def test_active_key_date_cutoff_is_inclusive_and_inactive_key_skips():
    check = REGISTRY["aws.a.iam.active_key_age_90"]
    cutoff = datetime(2026, 10, 10, tzinfo=timezone.utc) - timedelta(days=90)
    assert check.evaluate({"Status": "Active", "CreateDate": cutoff.isoformat()}, rules.CLOCK)[0] == "FAIL"
    assert check.evaluate({"Status": "Active", "CreateDate": (cutoff + timedelta(seconds=1)).isoformat()}, rules.CLOCK)[0] == "PASS"
    assert check.evaluate({"Status": "Inactive"}, {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({"Status": "unknown"}, rules.CLOCK)[0] == "UNKNOWN"


def test_certificate_preserves_sql_date_minus_one_second_boundary():
    check = REGISTRY["aws.a.iam.server_certificate_expiry_date"]
    cutoff = datetime(2026, 10, 9, 23, 59, 59, tzinfo=timezone.utc)
    assert check.evaluate({"Expiration": cutoff.isoformat()}, rules.CLOCK)[0] == "PASS"
    assert check.evaluate({"Expiration": (cutoff - timedelta(seconds=1)).isoformat()}, rules.CLOCK)[0] == "FAIL"
    assert check.evaluate({"Expiration": "2026-10-10T06:00:00+00:00"}, rules.CLOCK)[0] == "PASS"


@pytest.mark.parametrize("seconds", [-1, 0, 9, 10, 11])
def test_console_and_key_setup_rotation_does_not_prove_creation(seconds):
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    item = {**rules.SETUP, "access_key_1_last_rotated": (created + timedelta(seconds=seconds)).isoformat()}
    assert REGISTRY["aws.a.iam.console_key_created_at_setup"].evaluate(item, {})[0] == "UNKNOWN"


def test_disabled_console_and_null_key_pass_but_malformed_dates_do_not():
    check = REGISTRY["aws.a.iam.console_key_created_at_setup"]
    assert check.evaluate({"password_enabled": "false"}, {})[0] == "PASS"
    assert check.evaluate({"password_enabled": "true", "access_key_1_last_rotated": "N/A"}, {})[0] == "PASS"
    assert check.evaluate({**rules.SETUP, "access_key_1_last_rotated": "not-a-date"}, {})[0] == "UNKNOWN"


def test_direct_inline_and_managed_policy_variants_are_distinct():
    item = {"AttachedManagedPolicies": [], "UserPolicyList": [{"PolicyName": "inert"}]}
    assert REGISTRY["aws.a.iam.user_no_managed_policies"].evaluate(item, {})[0] == "PASS"
    assert REGISTRY["aws.a.iam.user_no_direct_policies"].evaluate(item, {})[0] == "FAIL"
    assert REGISTRY["aws.a.iam.user_no_direct_policies"].evaluate({"AttachedManagedPolicies": []}, {})[0] == "UNKNOWN"


def test_root_virtual_mfa_join_and_complete_known_empty_are_required():
    check = REGISTRY["aws.a.iam.root_hardware_mfa"]
    item = CASES[check.id]["pass"]
    index = copy.deepcopy(rules.GOOD)
    device = {"SerialNumber": "arn:aws:iam::123456789012:mfa/root", "User": {"Arn": "arn:aws:iam::123456789012:root"}}
    index["collections"]["iam_virtual_mfa_device"] = scope_fixture("iam_virtual_mfa_device", [device])["collections"]["iam_virtual_mfa_device"]
    assert check.evaluate(item, index)[0] == "FAIL"
    device["User"]["Arn"] = "arn:aws:iam::123456789012:user/reviewer"
    assert check.evaluate(item, index)[0] == "PASS"
    index["collections"]["iam_virtual_mfa_device"][0]["status"] = "denied"
    assert check.evaluate(item, index)[0] == "UNKNOWN"
    index["collections"]["iam_virtual_mfa_device"][0].update(status="empty", items=[])
    assert check.evaluate(item, index)[0] == "PASS"


def test_missing_clock_and_timezone_stay_unknown():
    check = REGISTRY["aws.a.iam.server_certificate_expiry_date"]
    assert check.evaluate({"Expiration": "2027-01-01T00:00:00+00:00"}, {})[0] == "UNKNOWN"
    assert check.evaluate({"Expiration": "2027-01-01T00:00:00"}, rules.CLOCK)[0] == "UNKNOWN"


@pytest.fixture
def iam_sdk(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    client = session.client("iam", region_name="us-east-1")
    stub = Stubber(client)
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    with stub:
        yield aws, session, stub
        stub.assert_no_pending_responses()


def test_access_key_inventory_is_paginated_deduplicated_and_identifiers_fingerprinted(iam_sdk):
    import json
    aws, session, stub = iam_sdk
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    user = {"Path": "/", "UserName": "reviewer", "UserId": "INERT1234567890123", "Arn": "arn:aws:iam::123456789012:user/reviewer", "CreateDate": created}
    stub.add_response("list_users", {"Users": [user], "IsTruncated": False}, {})
    for n in (1, 2):
        data = {"AccessKeyMetadata": [{"UserName": "reviewer", "AccessKeyId": "INERT_KEY_MARKER_" + str(n), "Status": "Active", "CreateDate": created}], "IsTruncated": n == 1}
        if n == 1:
            data["Marker"] = "second"
        stub.add_response("list_access_keys", data, {"UserName": "reviewer", **({"Marker": "second"} if n == 2 else {})})
    requests = aws.Requests({})
    first = aws._access_keys(requests, session, "us-east-1")
    second = aws._access_keys(requests, session, "us-east-1")
    assert first.status == "collected" and len(first.items) == 2
    assert first.items == second.items and requests.calls == 3
    assert "INERT_KEY_MARKER" not in json.dumps(first.items)
    assert all(len(item["AccessKeyFingerprint"]) == 64 and item["UserArn"] == user["Arn"] for item in first.items)


def test_key_inventory_denial_never_becomes_known_empty(iam_sdk):
    aws, session, stub = iam_sdk
    stub.add_client_error("list_users", "AccessDenied", expected_params={})
    read = aws._access_keys(aws.Requests({}), session, "us-east-1")
    assert read.status == "denied" and read.items == []


def test_virtual_device_and_server_certificate_operations_keep_only_metadata(iam_sdk):
    import json
    aws, session, stub = iam_sdk
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    stub.add_response("list_virtual_mfa_devices", {"VirtualMFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/inert", "Base32StringSeed": b"INERT_MFA_SEED", "QRCodePNG": b"INERT_QR"}], "IsTruncated": False}, {})
    stub.add_response("list_server_certificates", {"ServerCertificateMetadataList": [{"Path": "/", "ServerCertificateName": "inert", "ServerCertificateId": "INERT1234567890123", "Arn": "arn:aws:iam::123456789012:server-certificate/inert", "UploadDate": created, "Expiration": created}], "IsTruncated": False}, {})
    requests = aws.Requests({})
    for kind in ("iam_virtual_mfa_device", "iam_server_certificate"):
        service, operation, expression = aws.SPECS[kind]
        read = requests.pages(session, service, "us-east-1", operation, expression)
        assert read.status == "collected"
        serialized = json.dumps(aws._safe(read.items))
        assert "INERT_MFA_SEED" not in serialized and "INERT_QR" not in serialized
        assert "Base32StringSeed" not in serialized and "QRCodePNG" not in serialized
