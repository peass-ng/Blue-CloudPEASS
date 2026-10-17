"""Account-wide Lambda role-use summary from already collected immutable facts."""
from peaso.collectors.aws_lambda_role_usage import summarize_lambda_role_usage


ACCOUNT = "123456789012"
CALLER = {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/Audit/read"}
ROLE = f"arn:aws:iam::{ACCOUNT}:role/shared"


def function(region, name, *, role=ROLE, state="Active", detail_status="collected"):
    arn = f"arn:aws:lambda:{region}:{ACCOUNT}:function:{name}"
    return {"FunctionArn": arn, "Role": role, "AccountId": ACCOUNT, "Region": region,
            "Configuration": {"collection_status": detail_status, "FunctionArn": arn,
                              "Role": role, "State": state}}


def envelope(region, functions, status="collected"):
    return {"type": "lambda_function", "scope": f"{ACCOUNT}/{region}", "account_id": ACCOUNT,
            "global": False, "status": status, "items": functions}


def summarize(envelopes, *, regions=None, identities=None, explicit=False):
    discovery = [{"account_id": ACCOUNT, "status": "collected",
                  "regions": ["eu-west-1", "us-east-1"]}] if regions is None else regions
    return summarize_lambda_role_usage(envelopes, [CALLER] if identities is None else identities,
                                       discovery, explicit_regions=explicit)["accounts"][0]


def test_complete_regions_distinguish_shared_and_distinct_active_roles():
    west = envelope("eu-west-1", [function("eu-west-1", "west")])
    east = envelope("us-east-1", [function("us-east-1", "east")])
    row = summarize([east, west])
    assert row["status"] == "collected" and row["active_function_count"] == 2
    assert row["shared_active_roles"] == [{"role_arn": ROLE, "function_count": 2}]
    east["items"][0] = function("us-east-1", "east", role=f"arn:aws:iam::{ACCOUNT}:role/dedicated")
    row = summarize([west, east])
    assert row["status"] == "collected" and row["shared_active_roles"] == []
    assert row["observed_regions"] == ["eu-west-1", "us-east-1"]


def test_partial_peer_keeps_observed_duplicate_but_cannot_prove_absence():
    west = envelope("eu-west-1", [function("eu-west-1", "a"), function("eu-west-1", "b")])
    east = envelope("us-east-1", [], "denied")
    row = summarize([west, east])
    assert row["status"] == "partial" and row["shared_active_roles"] == [{"role_arn": ROLE, "function_count": 2}]
    assert "lambda_inventory_incomplete" in row["issue_codes"]
    assert summarize([west])["status"] == "partial"
    assert summarize([west, envelope("us-east-1", [])], explicit=True)["status"] == "partial"
    assert summarize([west, envelope("us-east-1", [])], regions=[{"account_id": ACCOUNT, "status": "denied"}])["status"] == "partial"


def test_denied_missing_or_future_configuration_is_incomplete():
    west = envelope("eu-west-1", [function("eu-west-1", "a", detail_status="denied")])
    east = envelope("us-east-1", [])
    assert "lambda_state_unavailable" in summarize([west, east])["issue_codes"]
    west["items"][0]["Configuration"].pop("State")
    west["items"][0]["Configuration"]["collection_status"] = "collected"
    assert "lambda_state_unavailable" in summarize([west, east])["issue_codes"]
    west["items"][0]["Configuration"]["State"] = "FutureState"
    assert "lambda_state_unavailable" in summarize([west, east])["issue_codes"]
    for malformed in ([], {}):
        west["items"][0]["Configuration"]["State"] = malformed
        assert "lambda_state_unavailable" in summarize([west, east])["issue_codes"]


def test_duplicate_foreign_identity_and_nonactive_state_do_not_count_as_safe():
    west = envelope("eu-west-1", [function("eu-west-1", "a", state="Inactive")])
    east = envelope("us-east-1", [])
    row = summarize([west, east])
    assert row["status"] == "collected" and row["active_function_count"] == 0
    west["items"].append(west["items"][0])
    assert "lambda_function_duplicate" in summarize([west, east])["issue_codes"]
    west["items"] = [function("eu-west-1", "a", role="arn:aws-cn:iam::123456789012:role/foreign")]
    assert "lambda_identity_malformed" in summarize([west, east])["issue_codes"]
    assert summarize([east], identities=[{"Account": ACCOUNT, "Arn": "malformed"}])["status"] == "partial"


def test_sdk_documented_nonactive_states_are_outside_active_population():
    east = envelope("us-east-1", [])
    for state in ("Pending", "Inactive", "Failed", "Deactivating", "Deactivated",
                  "ActiveNonInvocable", "Deleting"):
        west = envelope("eu-west-1", [function("eu-west-1", "a", state=state)])
        row = summarize([west, east])
        assert row["status"] == "collected" and row["active_function_count"] == 0


def test_success_label_with_envelope_error_is_not_complete():
    west = envelope("eu-west-1", [])
    west["error"] = {"code": "page_error"}
    row = summarize([west, envelope("us-east-1", [])])
    assert row["status"] == "partial" and "lambda_inventory_incomplete" in row["issue_codes"]


def test_real_collector_emits_complete_enabled_region_summary_without_new_calls(monkeypatch):
    import pytest
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws

    session = boto3.Session(aws_access_key_id="inert-key", aws_secret_access_key="inert-secret",
                            region_name="us-east-1")
    clients, stubs = {}, []
    for service, region in (("sts", "us-east-1"), ("ec2", "us-east-1"),
                            ("lambda", "us-east-1"), ("lambda", "eu-west-1")):
        client = session.client(service, region_name=region)
        stub = Stubber(client)
        stub.activate()
        clients[(service, region)] = client
        stubs.append(stub)
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "test-pinned"))
    monkeypatch.setattr(aws.Requests, "client", lambda self, sess, service, region: clients[(service, region)])
    stubs[0].add_response("get_caller_identity", {"Account": ACCOUNT,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAREVIEWER"}, {})
    stubs[1].add_response("describe_regions", {"Regions": [
        {"RegionName": "eu-west-1", "OptInStatus": "opt-in-not-required"},
        {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]}, {"AllRegions": True})
    stubs[2].add_response("list_functions", {"Functions": []}, {})
    stubs[3].add_response("list_functions", {"Functions": []}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "chosen"},
                            "options": {"service_concurrency": 1}}, ["lambda_function"])
    usage = snapshot["metadata"]["lambda_execution_role_usage"]["accounts"][0]
    assert usage["status"] == "collected" and usage["enabled_regions"] == ["eu-west-1", "us-east-1"]
    assert usage["observed_regions"] == ["eu-west-1", "us-east-1"] and usage["shared_active_roles"] == []
    for stub in stubs:
        stub.assert_no_pending_responses()
        stub.deactivate()
