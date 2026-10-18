"""Full-default, explicit-cap and inherited-SCP evidence contract tests."""
import json
from datetime import datetime, timezone

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber
from botocore.exceptions import EndpointConnectionError, ConnectionClosedError

from peaso.collectors import aws

ACCOUNT = "123456789012"
REGION = "us-east-1"
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id="inert-test-key", aws_secret_access_key="inert-test-secret", region_name=REGION)
    clients, stubs = {}, {}
    def add(service, region=REGION):
        key = (service, region)
        if key not in clients:
            clients[key] = session.client(service, region_name=region)
            stubs[key] = Stubber(clients[key])
            stubs[key].activate()
        return stubs[key]
    monkeypatch.setattr(aws.Requests, "client", lambda self, context, service, region: clients[(service, region)])
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "inert-pinned"))
    yield session, add
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def test_default_pagination_exceeds_10_pages_200_calls_and_10000_items_without_caps(sdk):
    session, add = sdk
    iam = add("iam")
    pages, per_page = 205, 51
    for number in range(pages):
        users = [{"Path": "/", "UserName": f"user-{number}-{i}", "UserId": "AIDAINERT123456789", "Arn": f"arn:aws:iam::{ACCOUNT}:user/user-{number}-{i}", "CreateDate": NOW} for i in range(per_page)]
        response = {"Users": users, "IsTruncated": number + 1 < pages}
        if number + 1 < pages:
            response["Marker"] = f"next-{number}"
        expected = {} if number == 0 else {"Marker": f"next-{number-1}"}
        iam.add_response("list_users", response, expected)
    requests = aws.Requests({})
    assert requests.max_calls is requests.max_pages is requests.max_items is None
    read = requests.pages(session, "iam", REGION, "list_users", "Users")
    assert read.status == "collected"
    assert read.error is None
    assert requests.calls == 205
    assert len(read.items) == 10455


def test_explicit_page_cap_retains_intentional_partial_evidence(sdk):
    session, add = sdk
    ec2 = add("ec2")
    ec2.add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-1"}], "NextToken": "next"}, {})
    read = aws.Requests({"max_pages": 1}).pages(session, "ec2", REGION, "describe_vpcs", "Vpcs")
    assert read.status == "partial"
    assert read.error["code"] == "page_limit"
    assert read.items == [{"VpcId": "vpc-1"}]


def test_default_unfiltered_scan_collects_every_supported_inventory_without_omission_caps(sdk, monkeypatch):
    session, add = sdk
    monkeypatch.setattr(aws, "AWS_TYPES", ["aws_account", "vpc"])
    monkeypatch.setattr(aws, "GLOBAL_TYPES", {"aws_account"})
    monkeypatch.setattr(aws, "SPECS", {"vpc": ("ec2", "describe_vpcs", "Vpcs")})
    monkeypatch.setattr(aws, "FETCHERS", {})
    monkeypatch.setattr(aws, "ENRICHERS", {})
    add("sts").add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAINERT123456789"}, {})
    add("ec2").add_response("describe_regions", {"Regions": [{"RegionName": REGION, "OptInStatus": "opt-in-not-required"}]}, {"AllRegions": True})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT]})
    assert {c["type"] for c in snapshot["collections"]} == set(aws.AWS_TYPES)
    assert all(c["status"] in {"collected", "empty"} for c in snapshot["collections"])
    assert snapshot["metadata"]["intentional_limits"] == {}
    assert snapshot["metadata"]["omitted_inventories"] == []


def test_cancellation_and_explicit_deadline_stop_new_sdk_reads(sdk):
    import threading
    session, add = sdk
    cancelled = threading.Event()
    cancelled.set()
    requests = aws.Requests({"cancel_event": cancelled})
    with pytest.raises(aws.ReadFailure, match="collection_cancelled"):
        requests.call(session, "iam", REGION, "get_account_summary")
    assert requests.calls == 0
    requests = aws.Requests({"deadline_seconds": 0.001})
    requests.deadline = 0
    with pytest.raises(aws.ReadFailure, match="intentional_scan_deadline"):
        requests.call(session, "iam", REGION, "get_account_summary")
    assert requests.calls == 0


def test_default_region_discovery_collects_all_enabled_regions_and_excludes_disabled(sdk):
    session, add = sdk
    add("sts").add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAINERT123456789"}, {})
    add("ec2").add_response("describe_regions", {"Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}, {"RegionName": "eu-west-1", "OptInStatus": "opted-in"}, {"RegionName": "af-south-1", "OptInStatus": "not-opted-in"}]}, {"AllRegions": True})
    add("ec2", "eu-west-1").add_response("describe_vpcs", {"Vpcs": []}, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, {})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "options": {"service_concurrency": 1}}, ["vpc"])
    assert snapshot["scopes"] == [f"{ACCOUNT}/eu-west-1", f"{ACCOUNT}/us-east-1"]
    assert snapshot["metadata"]["region_discovery"][0]["status"] == "collected"
    assert snapshot["metadata"]["intentional_limits"] == {}
    assert snapshot["metadata"]["calls"] == 4
    assert all(c["status"] == "empty" for c in snapshot["collections"] if c["type"] == "vpc")


def test_region_discovery_denial_does_not_silently_scan_a_default_region(sdk):
    session, add = sdk
    add("sts").add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAINERT123456789"}, {})
    add("ec2").add_client_error("describe_regions", "AccessDenied", expected_params={"AllRegions": True})
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT]}, ["vpc"])
    collection = next(c for c in snapshot["collections"] if c["type"] == "vpc")
    assert collection["status"] == "denied"
    assert collection["items"] == []
    assert collection["error"]["reason"] == "default_region_discovery_incomplete"
    assert snapshot["metadata"]["calls"] == 2


@pytest.mark.parametrize("code", ["ReportNotPresent", "ReportExpired", "ReportInProgress"])
def test_credential_report_missing_or_expired_authorized_generation_then_fresh_read(sdk, code):
    session, add = sdk
    add("iam").add_client_error("get_credential_report", code, expected_params={})
    requests = aws.Requests({})
    read = aws._credentials_report(requests, session, REGION)
    assert read.status == "not_collected" and read.items == []
    assert read.error == {"code": "credential_report_generation_disabled", "source_code": code}
    assert requests.calls == 1 and requests.evidence_generations == 0


def test_credential_report_generation_denial_stays_denied(sdk):
    session, add = sdk
    add("iam").add_client_error("get_credential_report", "AccessDenied", expected_params={})
    requests = aws.Requests({})
    read = aws._credentials_report(requests, session, REGION)
    assert read.status == "denied" and read.error["code"] == "AccessDenied"
    assert requests.calls == 1 and requests.evidence_generations == 0


def policy(policy_id):
    return {"Id": policy_id, "Name": policy_id, "Description": "inert policy", "Type": "SERVICE_CONTROL_POLICY", "AwsManaged": False}


def policy_detail(policy_id):
    return {"Policy": {"PolicySummary": policy(policy_id), "Content": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "iam:CreateUser", "Resource": "*"}]})}}


def test_inherited_scp_reads_account_ou_root_preserving_attachment_paths_and_dedup(sdk):
    session, add = sdk
    org = add("organizations")
    org.add_response("list_policies_for_target", {"Policies": [policy("p-shared11")]}, {"TargetId": ACCOUNT, "Filter": "SERVICE_CONTROL_POLICY"})
    org.add_response("describe_policy", policy_detail("p-shared11"), {"PolicyId": "p-shared11"})
    org.add_response("list_parents", {"Parents": [{"Id": "ou-abcd-12345678", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": ACCOUNT})
    org.add_response("list_policies_for_target", {"Policies": [policy("p-shared11")]}, {"TargetId": "ou-abcd-12345678", "Filter": "SERVICE_CONTROL_POLICY"})
    org.add_response("list_parents", {"Parents": [{"Id": "r-abcd", "Type": "ROOT"}]}, {"ChildId": "ou-abcd-12345678"})
    org.add_response("list_policies_for_target", {"Policies": [policy("p-root0001")]}, {"TargetId": "r-abcd", "Filter": "SERVICE_CONTROL_POLICY"})
    org.add_response("describe_policy", policy_detail("p-root0001"), {"PolicyId": "p-root0001"})
    requests = aws.Requests({})
    read = aws._scp_policies(requests, session, REGION, ACCOUNT)
    assert read.status == "collected"
    assert requests.calls == 7
    assert len(read.items) == 2
    shared = next(p for p in read.items if p["Id"] == "p-shared11")
    assert [a["TargetType"] for a in shared["Attachments"]] == ["ACCOUNT", "ORGANIZATIONAL_UNIT"]
    assert shared["InheritanceComplete"] is True
    assert shared["InheritedPolicies"]["ParentPath"][-1] == {"Id": "r-abcd", "Type": "ROOT"}


def test_inherited_scp_restricted_parent_visibility_is_partial_not_complete(sdk):
    session, add = sdk
    org = add("organizations")
    org.add_response("list_policies_for_target", {"Policies": [policy("p-direct11")]}, {"TargetId": ACCOUNT, "Filter": "SERVICE_CONTROL_POLICY"})
    org.add_response("describe_policy", policy_detail("p-direct11"), {"PolicyId": "p-direct11"})
    org.add_client_error("list_parents", "AccessDeniedException", expected_params={"ChildId": ACCOUNT})
    read = aws._scp_policies(aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "partial"
    assert read.items[0]["InheritanceComplete"] is False
    assert read.items[0]["InheritedPolicies"]["collection_status"] == "denied"


def test_inherited_scp_parent_cycle_is_malformed_partial_evidence(sdk):
    session, add = sdk
    org = add("organizations")
    org.add_response("list_policies_for_target", {"Policies": [policy("p-direct11")]}, {"TargetId": ACCOUNT, "Filter": "SERVICE_CONTROL_POLICY"})
    org.add_response("describe_policy", policy_detail("p-direct11"), {"PolicyId": "p-direct11"})
    org.add_response("list_parents", {"Parents": [{"Id": "ou-abcd-12345678", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": ACCOUNT})
    org.add_response("list_policies_for_target", {"Policies": []}, {"TargetId": "ou-abcd-12345678", "Filter": "SERVICE_CONTROL_POLICY"})
    org.add_response("list_parents", {"Parents": [{"Id": "ou-abcd-12345678", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": "ou-abcd-12345678"})
    read = aws._scp_policies(aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "partial"
    assert read.error["code"] == "organization_parent_cycle"
    assert read.items[0]["InheritanceComplete"] is False


def test_organization_parent_inventory_collects_native_account_ou_root_edges(sdk):
    session, add = sdk
    org = add("organizations")
    org.add_response("list_parents", {"Parents": [{"Id": "ou-abcd-12345678", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": ACCOUNT})
    org.add_response("list_parents", {"Parents": [{"Id": "r-abcd", "Type": "ROOT"}]}, {"ChildId": "ou-abcd-12345678"})
    requests = aws.Requests({})
    read = aws._organization_parents(requests, session, REGION, ACCOUNT)
    assert read.status == "collected"
    assert requests.calls == 2
    assert [(item["ChildId"], item["ParentId"], item["Type"]) for item in read.items] == [(ACCOUNT, "ou-abcd-12345678", "ORGANIZATIONAL_UNIT"), ("ou-abcd-12345678", "r-abcd", "ROOT")]
    assert all(item["InheritanceComplete"] is True for item in read.items)
    assert read.items[-1]["ParentPath"] == [ACCOUNT, "ou-abcd-12345678", "r-abcd"]


def test_organization_parent_inventory_denied_ou_keeps_explicit_partial_path(sdk):
    session, add = sdk
    org = add("organizations")
    org.add_response("list_parents", {"Parents": [{"Id": "ou-abcd-12345678", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": ACCOUNT})
    org.add_client_error("list_parents", "AccessDeniedException", expected_params={"ChildId": "ou-abcd-12345678"})
    read = aws._organization_parents(aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "partial"
    assert read.items[0]["InheritanceComplete"] is False
    assert read.items[0]["ParentCollection"]["collection_status"] == "denied"


def test_organization_parent_inventory_rejects_a_cycle(sdk):
    session, add = sdk
    org = add("organizations")
    org.add_response("list_parents", {"Parents": [{"Id": "ou-abcd-12345678", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": ACCOUNT})
    org.add_response("list_parents", {"Parents": [{"Id": "ou-abcd-12345678", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": "ou-abcd-12345678"})
    read = aws._organization_parents(aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "partial"
    assert read.error["code"] == "organization_parent_cycle"


@pytest.mark.parametrize("kind,service,operation,response", [
    ("cloudfront_distribution", "cloudfront", "list_distributions", {"DistributionList": {"Marker": "", "MaxItems": 100, "IsTruncated": False, "Quantity": 0}}),
    ("route53_zone", "route53", "list_hosted_zones", {"HostedZones": [], "Marker": "", "IsTruncated": False, "MaxItems": "100"}),
    ("route53_health_check", "route53", "list_health_checks", {"HealthChecks": [], "Marker": "", "IsTruncated": False, "MaxItems": "100"}),
])
def test_declared_global_plugin_specs_are_dispatched_once_not_unsupported(sdk, monkeypatch, kind, service, operation, response):
    session, add = sdk
    add("sts").add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAINERT123456789"}, {})
    add(service).add_response(operation, response, {})
    # Exercise the generic spec path explicitly, even if a later plugin version
    # adds a custom fetcher. Its declaration still must not become unsupported.
    monkeypatch.setattr(aws, "FETCHERS", {k: v for k, v in aws.FETCHERS.items() if k != kind})
    enrich_calls = []
    monkeypatch.setattr(aws, "ENRICHERS", {**aws.ENRICHERS, kind: lambda requests, context, region, items: enrich_calls.append((context, region)) or items})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION]}, [kind])
    collection = next(c for c in snapshot["collections"] if c["type"] == kind)
    assert collection["status"] == "empty"
    assert collection["global"] is True
    assert collection["account_id"] == ACCOUNT
    assert snapshot["metadata"]["calls"] == 2
    assert enrich_calls == [(session, REGION)]


def test_report_usage_provenance_matches_authorized_generation_then_read(sdk):
    session, add = sdk
    add("sts").add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAINERT123456789"}, {})
    add("iam").add_client_error("get_credential_report", "ReportNotPresent", expected_params={})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION]}, ["iam_credential_report"])
    assert snapshot["metadata"]["authorized_evidence_generation"] == {"iam_credential_report": False,
        "generation_requests": 0, "iam_service_last_accessed_report": False,
        "service_last_accessed_generation_requests": 0}
    assert snapshot["metadata"]["usage_evidence"]["credential_report"] == "report_unavailable_or_not_requested"


@pytest.mark.parametrize("kind,service,operation,expression,response,arguments", [
    ("cloudfront_distribution", "cloudfront", "list_distributions", "DistributionList.Items || `[]`", {"DistributionList": {"Marker": "", "MaxItems": 100, "IsTruncated": False, "Quantity": 0}}, {}),
    ("cognito_user_pool", "cognito-idp", "list_user_pools", "UserPools", {"UserPools": []}, {"MaxResults": 60}),
])
def test_custom_global_and_regional_fetchers_pass_through_one_enrichment(sdk, monkeypatch, kind, service, operation, expression, response, arguments):
    session, add = sdk
    add("sts").add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAINERT123456789"}, {})
    add(service).add_response(operation, response, arguments)
    def fetch(requests, context, region, account):
        assert account == ACCOUNT
        return requests.pages(context, service, region, operation, expression, **arguments)
    enrich_calls = []
    monkeypatch.setattr(aws, "FETCHERS", {**aws.FETCHERS, kind: fetch})
    monkeypatch.setattr(aws, "ENRICHERS", {**aws.ENRICHERS, kind: lambda requests, context, region, items: enrich_calls.append((context, region)) or items})
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION]}, [kind])
    assert next(c for c in snapshot["collections"] if c["type"] == kind)["status"] == "empty"
    assert enrich_calls == [(session, REGION)]
    assert snapshot["metadata"]["calls"] == 2


def test_failed_endpoint_in_region_excluded_by_sdk_support_is_explicit_unsupported(sdk, monkeypatch):
    session, add = sdk
    region = "ap-northeast-3"
    client = session.client("memorydb", region_name=region)
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    monkeypatch.setattr(client, "describe_clusters", lambda **kwargs: (_ for _ in ()).throw(EndpointConnectionError(endpoint_url="https://inert.invalid")))
    monkeypatch.setattr(session, "get_available_regions", lambda service, partition_name: ["us-east-1"])
    read = aws.Requests({}).pages(session, "memorydb", region, "describe_clusters", "Clusters")
    assert read.status == "not_collected"
    assert read.error["code"] == "unsupported_region_service"
    assert read.items == []


def test_failed_endpoint_in_supported_region_stays_unknown_not_unsupported(sdk, monkeypatch):
    session, add = sdk
    client = session.client("memorydb", region_name=REGION)
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    monkeypatch.setattr(client, "describe_clusters", lambda **kwargs: (_ for _ in ()).throw(EndpointConnectionError(endpoint_url="https://inert.invalid")))
    monkeypatch.setattr(session, "get_available_regions", lambda service, partition_name: [REGION])
    read = aws.Requests({}).pages(session, "memorydb", REGION, "describe_clusters", "Clusters")
    assert read.status == "unknown"
    assert read.items == []


def test_transient_transport_recovery_retries_are_bounded_counted_and_cached(sdk, monkeypatch):
    session, add = sdk
    client = session.client("backup", region_name=REGION)
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    attempts = []
    def operation(**kwargs):
        attempts.append(kwargs)
        if len(attempts) == 1:
            raise ConnectionClosedError(endpoint_url="https://inert.invalid")
        return {"Results": []}
    monkeypatch.setattr(client, "list_protected_resources", operation)
    sleeps = []
    requests = aws.Requests({"retry_attempts": 2}, sleep=sleeps.append)
    read = requests.pages(session, "backup", REGION, "list_protected_resources", "Results")
    assert read.status == "empty"
    assert requests.calls == 2
    assert sleeps == [0.2]
    again = requests.pages(session, "backup", REGION, "list_protected_resources", "Results")
    assert again.status == "empty"
    assert requests.calls == 2


def test_transient_transport_exhaustion_never_fabricates_empty_success(sdk, monkeypatch):
    session, add = sdk
    client = session.client("backup", region_name=REGION)
    monkeypatch.setattr(aws.Requests, "client", lambda *args: client)
    monkeypatch.setattr(client, "list_protected_resources", lambda **kwargs: (_ for _ in ()).throw(ConnectionClosedError(endpoint_url="https://inert.invalid")))
    requests = aws.Requests({"retry_attempts": 2}, sleep=lambda _: None)
    read = requests.pages(session, "backup", REGION, "list_protected_resources", "Results")
    assert read.status == "unknown"
    assert read.items == []
    assert requests.calls == 2


def test_native_insight_not_enabled_is_known_absence_not_unknown_or_pass(sdk):
    session, add = sdk
    add("cloudtrail").add_client_error("get_insight_selectors", "InsightNotEnabledException", expected_params={"TrailName": "audit"})
    requests = aws.Requests({})
    detail = requests.detail(session, "cloudtrail", REGION, "get_insight_selectors", TrailName="audit", absent=("InsightNotEnabledException",))
    assert detail["collection_status"] == "empty"
    assert detail["absent"] is True
    assert detail["error"]["code"] == "InsightNotEnabledException"
    assert requests.calls == 1


def test_aws_progress_is_transient_cumulative_and_includes_empty_settlement(sdk):
    session, add = sdk
    add("sts").add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAINERT123456789"}, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, {})
    events = []
    connector = {"provider": "aws", "scopes": [REGION], "options": {"_progress_callback": events.append}}
    snapshot = aws.collect(connector, ["vpc"])
    assert events[0]["phase"] == "discovering"
    assert events[-1]["phase"] == "completed"
    assert events[-1]["completed"] == events[-1]["total"] == len(snapshot["collections"])
    assert [event["completed"] for event in events] == sorted(event["completed"] for event in events)
    assert all(set(event) <= {"phase", "provider", "scope", "completed", "total", "resources", "dynamic_total"} for event in events)
    assert "_progress_callback" not in json.dumps(snapshot)
    assert connector["options"]["_progress_callback"] == events.append


def test_aws_progress_callback_failure_cannot_change_coverage(sdk):
    session, add = sdk
    add("sts").add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "AIDAINERT123456789"}, {})
    def broken(event):
        raise RuntimeError("inert callback failure")
    snapshot = aws.collect({"provider": "aws", "scopes": [REGION], "options": {"_progress_callback": broken}}, [])
    assert next(c for c in snapshot["collections"] if c["type"] == "aws_account")["status"] == "collected"
