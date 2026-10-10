"""Native AWS response contracts tested with botocore's validating Stubber."""
import concurrent.futures
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.exceptions import ReadTimeoutError
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.snapshot import validate

ACCOUNT = "123456789012"
REGION = "us-east-1"
IDENTITY = {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAREVIEWER"}
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id="selected-key-must-not-leak",
        aws_secret_access_key="selected-secret-must-not-leak", aws_session_token="selected-token-must-not-leak", region_name=REGION)
    clients, stubs = {}, {}

    def add(service, region=REGION):
        key = (service, region)
        if key not in clients:
            clients[key] = session.client(service, region_name=region)
            stubs[key] = Stubber(clients[key])
            stubs[key].activate()
        return stubs[key]

    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: clients[(service, region)])
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "test-pinned"))
    yield session, add, clients
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def envelope(snapshot, kind, region=REGION):
    return next(c for c in snapshot["collections"] if c["type"] == kind and c["scope"] == f"{ACCOUNT}/{region}")


def test_identity_scopes_required_facts_empty_and_omitted(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "chosen"}, "options": {"regions": [REGION]}}, ["vpc"])
    assert validate(snapshot) == snapshot
    assert snapshot["scopes"] == [f"{ACCOUNT}/{REGION}"]
    assert snapshot["metadata"]["calls"] == 2
    assert snapshot["metadata"]["caller_identities"] == [IDENTITY]
    assert envelope(snapshot, "vpc")["status"] == "empty"
    assert envelope(snapshot, "bucket")["status"] == "not_collected"
    assert envelope(snapshot, "aws_account")["items"][0]["Account"] == ACCOUNT
    assert "selected-key-must-not-leak" not in json.dumps(snapshot)


def test_network_pagination_native_ids_and_relationships(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    ec2 = add("ec2")
    ec2.add_response("describe_subnets", {"Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-shared"}], "NextToken": "next"}, {})
    ec2.add_response("describe_subnets", {"Subnets": [{"SubnetId": "subnet-2", "VpcId": "vpc-shared"}]}, {"NextToken": "next"})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"service_concurrency": 1}}, ["subnet"])
    subnets = envelope(snapshot, "subnet")
    assert subnets["status"] == "collected"
    assert {x["id"] for x in subnets["items"]} == {"subnet-1", "subnet-2"}
    assert len(snapshot["metadata"]["network_relationships"]) == 2
    assert all(x["reachability"] == "unknown" for x in snapshot["metadata"]["network_relationships"])


def test_iam_marker_pagination_shared_request_cache(sdk):
    session, add, _ = sdk
    iam = add("iam")
    iam.add_response("get_account_authorization_details", {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": [], "IsTruncated": True, "Marker": "next"}, {})
    iam.add_response("get_account_authorization_details", {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [{"RoleName": "review", "RoleId": "AROAREVIEWROLE1234567", "Arn": f"arn:aws:iam::{ACCOUNT}:role/review", "Path": "/", "CreateDate": NOW, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": []})}], "Policies": [], "IsTruncated": False}, {"Marker": "next"})
    requests = aws.Requests({})
    results = aws._iam(requests, session, REGION, {"iam_user", "iam_group", "iam_role", "iam_policy"})
    assert results["iam_role"].status == "collected"
    assert results["iam_user"].status == "empty"
    assert requests.calls == 2
    assert requests.cache_hits == 6


def test_throttle_retry_denial_cached_and_message_redacted(sdk):
    session, add, _ = sdk
    iam = add("iam")
    iam.add_client_error("get_account_summary", "Throttling", "secret-value-must-not-leak", expected_params={})
    iam.add_response("get_account_summary", {"SummaryMap": {"Users": 1}}, {})
    iam.add_client_error("get_account_password_policy", "AccessDenied", "selected-token-must-not-leak", expected_params={})
    waits = []
    requests = aws.Requests({}, sleep=waits.append)
    assert requests.call(session, "iam", REGION, "get_account_summary")["SummaryMap"]["Users"] == 1
    assert waits == [0.2]
    first = requests.detail(session, "iam", REGION, "get_account_password_policy")
    second = requests.detail(session, "iam", REGION, "get_account_password_policy")
    assert first == second == {"collection_status": "denied", "error": {"code": "AccessDenied"}}
    assert requests.calls == 3
    assert "secret" not in json.dumps(first)


def test_throttle_exhaustion_preserves_unknown(sdk):
    session, add, _ = sdk
    iam = add("iam")
    for _ in range(2):
        iam.add_client_error("get_account_summary", "ThrottlingException", expected_params={})
    requests = aws.Requests({"retry_attempts": 2}, sleep=lambda _: None)
    result = requests.detail(session, "iam", REGION, "get_account_summary")
    assert result["collection_status"] == "unknown"
    assert result["error"]["code"] == "ThrottlingException"
    assert requests.calls == 2


def test_singleflight_concurrent_identical_reads(sdk):
    session, add, _ = sdk
    add("iam").add_response("get_account_summary", {"SummaryMap": {"Users": 2}}, {})
    requests = aws.Requests({})
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: requests.call(session, "iam", REGION, "get_account_summary"), range(8)))
    assert requests.calls == 1
    assert requests.cache_hits == 7
    results[0]["SummaryMap"]["Users"] = 99
    assert results[1]["SummaryMap"]["Users"] == 2


@pytest.mark.parametrize("fault", ["page_limit", "repeated_pagination_token", "malformed_response", "missing_pagination_token", "resource_limit"])
def test_pagination_limit_and_malformed_are_partial(sdk, fault, monkeypatch):
    session, add, _ = sdk
    iam = add("iam")
    options = {"max_pages": 1} if fault == "page_limit" else {"max_resources": 1} if fault == "resource_limit" else {}
    if fault == "malformed_response":
        iam.add_response("list_users", {"Users": [], "IsTruncated": True, "Marker": "next"}, {})
        # An output accepted by Stubber's optional schema, but missing native list.
        iam.add_response("list_users", {"Users": [], "IsTruncated": False}, {"Marker": "next"})
        client = sdk[2][("iam", REGION)]
        native = client.list_users
        def malformed(**kwargs):
            response = native(**kwargs)
            if kwargs:
                response.pop("Users")
            return response
        monkeypatch.setattr(client, "list_users", malformed)
    else:
        user = {"Path": "/", "UserName": "review", "UserId": "AIDAREVIEWUSER1234567", "Arn": f"arn:aws:iam::{ACCOUNT}:user/review", "CreateDate": NOW}
        first = {"Users": [user], "IsTruncated": True}
        if fault != "missing_pagination_token":
            first["Marker"] = "next"
        iam.add_response("list_users", first, {})
        if fault == "repeated_pagination_token":
            iam.add_response("list_users", first, {"Marker": "next"})
    read = aws.Requests(options).pages(session, "iam", REGION, "list_users", "Users")
    assert read.status == ("malformed" if fault == "malformed_response" else "partial")
    assert read.error["code"] == fault


def test_timeout_explicit_and_non_read_operation_blocked(sdk, monkeypatch):
    session, add, clients = sdk
    add("iam")
    monkeypatch.setattr(clients[("iam", REGION)], "get_account_summary", lambda **kwargs: (_ for _ in ()).throw(ReadTimeoutError(endpoint_url="https://iam.amazonaws.com")))
    requests = aws.Requests({})
    assert requests.detail(session, "iam", REGION, "get_account_summary")["collection_status"] == "timeout"
    with pytest.raises(aws.ReadFailure, match="non_read_operation"):
        requests.call(session, "iam", REGION, "generate_credential_report")
    assert requests.calls == 1


def test_denial_after_success_retains_partial_evidence(sdk):
    session, add, _ = sdk
    ec2 = add("ec2")
    ec2.add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-1"}], "NextToken": "next"}, {})
    ec2.add_client_error("describe_vpcs", "UnauthorizedOperation", expected_params={"NextToken": "next"})
    read = aws.Requests({}).pages(session, "ec2", REGION, "describe_vpcs", "Vpcs")
    assert read.status == "partial"
    assert read.items == [{"VpcId": "vpc-1"}]
    assert read.error == {"code": "UnauthorizedOperation", "cause_status": "denied"}


def test_identity_failure_never_reads_service_or_default(sdk):
    session, add, _ = sdk
    add("sts").add_client_error("get_caller_identity", "InvalidClientTokenId", "do not leak token", expected_params={})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "bad"}}, ["vpc"])
    assert envelope(snapshot, "aws_account")["status"] == "denied"
    assert envelope(snapshot, "vpc")["status"] == "denied"
    assert snapshot["metadata"]["calls"] == 1
    assert snapshot["metadata"]["caller_identities"] == []
    assert "do not leak" not in json.dumps(snapshot)


def test_access_keys_usage_redacted_and_missing_profile_explicit(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    iam = add("iam")
    iam.add_response("get_account_authorization_details", {"UserDetailList": [{"Path": "/", "UserName": "review", "UserId": "AIDAREVIEWUSER1234567", "Arn": f"arn:aws:iam::{ACCOUNT}:user/review", "CreateDate": NOW, "UserPolicyList": [{"PolicyName": "audit", "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": []})}]}], "IsTruncated": False}, {})
    key = "AKIAMETADATAKEYONLY"
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [{"UserName": "review", "AccessKeyId": key, "Status": "Active", "CreateDate": NOW}]}, {"UserName": "review"})
    iam.add_response("get_access_key_last_used", {"UserName": "review", "AccessKeyLastUsed": {"LastUsedDate": NOW, "ServiceName": "s3", "Region": REGION}}, {"AccessKeyId": key})
    iam.add_client_error("get_login_profile", "NoSuchEntity", expected_params={"UserName": "review"})
    iam.add_response("list_mfa_devices", {"MFADevices": []}, {"UserName": "review"})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"service_concurrency": 1}}, ["iam_user"])
    user = envelope(snapshot, "iam_user")["items"][0]
    assert user["PolicySources"][0]["source_type"] == "inline_policy"
    assert user["AccessKeys"]["items"][0]["LastUsed"]["AccessKeyLastUsed"]["ServiceName"] == "s3"
    assert len(user["AccessKeys"]["items"][0]["AccessKeyFingerprint"]) == 64
    assert key not in json.dumps(snapshot)
    assert user["LoginProfile"]["absent"] is True


def test_secret_metadata_only_and_lambda_environment_redaction(sdk):
    session, add, _ = sdk
    secret_arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:metadata-only-123456"
    sm = add("secretsmanager")
    sm.add_response("list_secrets", {"SecretList": [{"ARN": secret_arn, "Name": "metadata-only", "KmsKeyId": "key-1"}]}, {})
    sm.add_response("get_resource_policy", {"ARN": secret_arn, "Name": "metadata-only", "ResourcePolicy": '{"Version":"2012-10-17","Statement":[]}'}, {"SecretId": secret_arn})
    requests = aws.Requests({})
    read = requests.pages(session, "secretsmanager", REGION, "list_secrets", "SecretList")
    enriched = aws._enrich(requests, session, REGION, "secret", read.items)
    assert enriched[0]["Policy"]["ResourcePolicy"]["Statement"] == []
    safe = aws._safe({"Environment": {"Variables": {"PASSWORD": "env-secret"}}, "Code": {"Location": "signed-download-url"}, "SecretString": "stored-secret", "FunctionName": "audit"})
    assert safe == {"FunctionName": "audit"}
    assert requests.calls == 2


def test_existing_credential_report_no_generation(sdk):
    session, add, _ = sdk
    add("iam").add_response("get_credential_report", {"Content": b"user,arn,password_enabled,mfa_active\nreview,arn:aws:iam::123456789012:user/review,true,false\n", "ReportFormat": "text/csv", "GeneratedTime": NOW}, {})
    requests = aws.Requests({})
    read = aws._credentials_report(requests, session, REGION)
    assert read.status == "collected"
    assert read.items[0]["mfa_active"] == "false"
    assert requests.calls == 1


def test_existing_credential_report_missing_is_not_collected(sdk):
    session, add, _ = sdk
    add("iam").add_client_error("get_credential_report", "CredentialReportNotPresent", expected_params={})
    read = aws._credentials_report(aws.Requests({}), session, REGION)
    assert read.status == "not_collected"
    assert read.items == []


def test_call_and_total_resource_budgets(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"max_calls": 1, "service_concurrency": 1}}, ["aws_account", "vpc"])
    assert snapshot["metadata"]["calls"] == 1
    assert envelope(snapshot, "vpc")["status"] == "not_collected"
    assert envelope(snapshot, "vpc")["error"]["code"] == "call_limit"


def test_missing_explicit_account_target_cannot_use_base_account(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    target = "999999999999"
    snapshot = aws.collect({"provider": "aws", "scopes": [target]}, ["vpc"])
    assert snapshot["scopes"] == [f"{target}/{REGION}"]
    assert all(c["items"] == [] for c in snapshot["collections"])
    assert snapshot["metadata"]["calls"] == 1


def test_invalid_selected_profile_does_not_fallback(monkeypatch):
    calls = []
    def session(**kwargs):
        calls.append(kwargs)
        raise RuntimeError("private credential message")
    monkeypatch.setattr(boto3, "Session", session)
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "absent"}}, ["vpc"])
    assert calls == [{"region_name": REGION, "profile_name": "absent"}]
    assert envelope(snapshot, "vpc")["status"] == "unknown"
    assert "private credential" not in json.dumps(snapshot)


@pytest.mark.parametrize("options", [{"max_calls": True}, {"service_concurrency": 17}, {"region_concurrency": 0}, {"scope_concurrency": 9}, {"regions": ["not-a-region"]}, {"inventories": ["secret_values"]}])
def test_invalid_bounds_rejected_before_network(options):
    with pytest.raises(ValueError):
        aws.collect({"provider": "aws", "options": options})


def assumed_credentials():
    return {"Credentials": {"AccessKeyId": "ASIAASSUMED123456789", "SecretAccessKey": "assumed-secret-do-not-leak", "SessionToken": "assumed-token-do-not-leak", "Expiration": NOW}}


def test_role_chain_external_id_session_name_and_identity(sdk):
    session, add, _ = sdk
    sts = add("sts")
    intermediate = f"arn:aws:iam::{ACCOUNT}:role/platform-scanner"
    target = f"arn:aws:iam::{ACCOUNT}:role/audit"
    sts.add_response("assume_role", assumed_credentials(), {"RoleArn": intermediate, "RoleSessionName": "peaso-scan", "ExternalId": "first-external"})
    sts.add_response("assume_role", assumed_credentials(), {"RoleArn": target, "RoleSessionName": "target-session", "ExternalId": "second-external"})
    sts.add_response("get_caller_identity", {**IDENTITY, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/audit/target-session"}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"role_session_name": "peaso-scan", "role_chain": [{"role_arn": intermediate, "external_id": "first-external"}, {"role_arn": target, "external_id": "second-external", "role_session_name": "target-session"}]}}, [])
    assert snapshot["metadata"]["calls"] == 3
    assert "assumed-role/audit/target-session" in snapshot["metadata"]["caller_identities"][0]["Arn"]
    serialized = json.dumps(snapshot)
    assert "assumed-secret-do-not-leak" not in serialized
    assert "assumed-token-do-not-leak" not in serialized
    assert "ASIAASSUMED123456789" not in serialized


def test_assume_role_failure_no_base_credential_fallback(sdk):
    session, add, _ = sdk
    target = f"arn:aws:iam::{ACCOUNT}:role/audit"
    add("sts").add_client_error("assume_role", "AccessDenied", "private-external-id", expected_params={"RoleArn": target, "RoleSessionName": "peaso-read-only", "ExternalId": "private-external-id"})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"role_arn": target, "external_id": "private-external-id"}}, ["vpc"])
    assert envelope(snapshot, "vpc")["status"] == "denied"
    assert snapshot["metadata"]["caller_identities"] == []
    assert snapshot["metadata"]["calls"] == 1
    assert "private-external-id" not in json.dumps(snapshot)


def test_explicit_account_region_pairs_not_broadened(sdk):
    session, add, _ = sdk
    add("sts", "eu-west-1").add_response("get_caller_identity", IDENTITY, {})
    add("ec2", "us-east-1").add_response("describe_vpcs", {"Vpcs": []}, {})
    options = {"regions": ["eu-west-1"]}
    snapshot = aws.collect({"provider": "aws", "scopes": [f"{ACCOUNT}/us-east-1"], "options": options}, ["vpc"])
    assert snapshot["scopes"] == [f"{ACCOUNT}/us-east-1"]
    assert options == {"regions": ["eu-west-1"]}
    assert snapshot["metadata"]["calls"] == 2


def test_total_resources_cap_includes_identity(sdk):
    session, add, _ = sdk
    add("sts").add_response("get_caller_identity", IDENTITY, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-1"}, {"VpcId": "vpc-2"}]}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"max_resources": 2}}, ["vpc"])
    assert snapshot["metadata"]["resource_count"] == 2
    assert envelope(snapshot, "vpc")["status"] == "partial"
    assert envelope(snapshot, "vpc")["error"]["code"] == "resource_limit"
    assert len(envelope(snapshot, "vpc")["items"]) == 1


def test_s3_native_security_detail_and_absent_policy(sdk):
    session, add, _ = sdk
    s3 = add("s3")
    s3.add_response("list_buckets", {"Buckets": [{"Name": "audit-bucket", "CreationDate": NOW}]}, {})
    s3.add_response("get_bucket_location", {"LocationConstraint": ""}, {"Bucket": "audit-bucket"})
    s3.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}, {"Bucket": "audit-bucket"})
    s3.add_client_error("get_bucket_policy_status", "NoSuchBucketPolicy", expected_params={"Bucket": "audit-bucket"})
    s3.add_client_error("get_bucket_policy", "NoSuchBucketPolicy", expected_params={"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_encryption", {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}, {"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_versioning", {"Status": "Enabled"}, {"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_acl", {"Grants": []}, {"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_ownership_controls", {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}, {"Bucket": "audit-bucket"})
    s3.add_response("get_bucket_logging", {}, {"Bucket": "audit-bucket"})
    result = aws._buckets(aws.Requests({}), session, REGION)
    assert result.status == "collected"
    assert result.items[0]["Policy"]["collection_status"] == "empty"
    assert result.items[0]["Policy"]["absent"] is True
    assert result.items[0]["Encryption"]["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"


def test_session_pins_selected_profile_credentials(monkeypatch):
    calls = []
    credentials = SimpleNamespace(method="sso", get_frozen_credentials=lambda: SimpleNamespace(access_key="sso-key", secret_key="sso-secret", token="sso-token"))
    selected = SimpleNamespace(get_credentials=lambda: credentials)
    pinned = SimpleNamespace()
    def new_session(**kwargs):
        calls.append(kwargs)
        return selected if "profile_name" in kwargs else pinned
    monkeypatch.setattr(boto3, "Session", new_session)
    resolved, method = aws._session({"method": "sso", "profile": "chosen-sso"}, REGION)
    assert resolved is pinned
    assert method == "sso"
    assert calls == [{"region_name": REGION, "profile_name": "chosen-sso"}, {"aws_access_key_id": "sso-key", "aws_secret_access_key": "sso-secret", "aws_session_token": "sso-token", "region_name": REGION}]


@pytest.mark.parametrize("auth", [{"method": "profile"}, {"method": "access_keys"}, {"aws_access_key_id": "only-key"}, {"aws_access_key_id": "key", "aws_secret_access_key": "secret", "profile": "ambiguous"}])
def test_incomplete_or_ambiguous_auth_does_not_resolve_default(auth, monkeypatch):
    monkeypatch.setattr(boto3, "Session", lambda **kwargs: pytest.fail("default resolution forbidden"))
    with pytest.raises(ValueError):
        aws._session(auth, REGION)


def test_sensitive_value_and_mutation_apis_blocked(sdk):
    session, add, _ = sdk
    requests = aws.Requests({})
    for service, operation in [("secretsmanager", "get_secret_value"), ("s3", "get_object"), ("logs", "get_log_events"), ("accessanalyzer", "create_analyzer"), ("ec2", "create_network_insights_path")]:
        with pytest.raises(aws.ReadFailure, match="non_read_operation"):
            requests.call(session, service, REGION, operation)
    assert requests.calls == 0


def test_organization_accessible_role_requires_explicit_name_and_verifies_account(sdk):
    session, add, _ = sdk
    target = "999999999999"
    sts = add("sts")
    sts.add_response("get_caller_identity", IDENTITY, {})
    sts.add_response("assume_role", assumed_credentials(), {"RoleArn": f"arn:aws:iam::{target}:role/explicit-audit", "RoleSessionName": "peaso-read-only"})
    sts.add_response("get_caller_identity", {"Account": target, "Arn": f"arn:aws:sts::{target}:assumed-role/explicit-audit/peaso-read-only", "UserId": "AROAREVIEWUSER1234567:peaso-read-only"}, {})
    add("organizations").add_response("list_accounts", {"Accounts": [{"Id": ACCOUNT, "State": "ACTIVE"}, {"Id": target, "State": "ACTIVE"}, {"Id": "888888888888", "State": "SUSPENDED"}]}, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [target], "options": {"organization_role_name": "explicit-audit"}}, ["vpc"])
    assert snapshot["scopes"] == [f"{target}/{REGION}"]
    assert snapshot["metadata"]["caller_identities"][0]["Account"] == target
    assert snapshot["metadata"]["calls"] == 5
    assert snapshot["metadata"]["organization_discovery"]["accounts_seen"] == 3


def test_cross_account_identity_mismatch_fails_without_base_fallback(sdk):
    session, add, _ = sdk
    target = "999999999999"
    role = f"arn:aws:iam::{target}:role/audit"
    sts = add("sts")
    sts.add_response("get_caller_identity", IDENTITY, {})
    sts.add_response("assume_role", assumed_credentials(), {"RoleArn": role, "RoleSessionName": "peaso-read-only"})
    sts.add_response("get_caller_identity", IDENTITY, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [target], "auth": {"assume_roles": [role]}}, ["vpc"])
    collection = next(c for c in snapshot["collections"] if c["type"] == "vpc")
    assert collection["status"] == "denied"
    assert collection["error"]["code"] == "account_identity_mismatch"
    assert snapshot["metadata"]["caller_identities"] == []
    assert snapshot["metadata"]["calls"] == 3


def test_vpn_pre_shared_keys_and_gateway_xml_never_serialized():
    response = {"VpnConnectionId": "vpn-1", "CustomerGatewayConfiguration": "<pre_shared_key>vpn-secret</pre_shared_key>", "Options": {"TunnelOptions": [{"OutsideIpAddress": "203.0.113.1", "PreSharedKey": "vpn-secret"}]}}
    safe = aws._safe(response)
    assert "vpn-secret" not in json.dumps(safe)
    assert safe == {"VpnConnectionId": "vpn-1", "Options": {"TunnelOptions": [{"OutsideIpAddress": "203.0.113.1"}]}}


def test_nested_instance_projection_missing_children_is_malformed(sdk):
    session, add, _ = sdk
    add("ec2").add_response("describe_instances", {"Reservations": [{"ReservationId": "r-1"}]}, {})
    read = aws.Requests({}).pages(session, "ec2", REGION, "describe_instances", "Reservations[].Instances[]")
    assert read.status == "malformed"
    assert read.items == []
    assert read.error["code"] == "malformed_response"


def test_policy_json_preserves_literal_percent_encoded_conditions():
    document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"StringEquals": {"s3:prefix": "literal%2Fprefix"}}}]}
    assert aws._policy(json.dumps(document)) == document
    from urllib.parse import quote
    assert aws._policy(quote(json.dumps(document))) == document
    assert aws._policy("malformed")["collection_status"] == "malformed"
