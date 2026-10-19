"""Owned analyzer creation, warm-up, evidence preservation and cleanup."""
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from peaso.collectors import aws
from peaso.collectors import aws_access_analyzer_lifecycle as lifecycle

ACCOUNT = "123456789012"
IDENTITY = {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/scanner"}
REGIONS = ["us-east-1", "eu-west-1"]


def denied(operation):
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": "private"}}, operation)


class FakeRequests:
    def __init__(self, monkeypatch, inventories=None):
        self.now = 0
        self.inventories = inventories or {}
        self.records = {}
        self.calls = []
        self.events = []
        self.cancelled = False
        self.fail_create = self.fail_delete = self.fail_read = False
        self.creating = False
        monkeypatch.setattr(lifecycle.time, "monotonic", lambda: self.now)

    def _sleep(self, seconds):
        self.now += seconds

    def check_deadline(self):
        if self.cancelled:
            raise aws.ReadFailure("not_collected", "collection_cancelled")

    def pages(self, session, service, region, operation, expression):
        read = self.inventories.get(region, aws.ReadResult([], "empty"))
        return aws.ReadResult([dict(row) for row in read.items], read.status, read.error)

    def client(self, session, service, region):
        def create(**args):
            self.calls.append(("create", region, self.now, args))
            if self.fail_create:
                raise denied("CreateAnalyzer")
            arn = f'arn:aws:access-analyzer:{region}:{ACCOUNT}:analyzer/{args["analyzerName"]}'
            self.records[args["analyzerName"]] = {"arn": arn, "name": args["analyzerName"], "type": args["type"], "status": "ACTIVE"}
            return {"arn": arn}

        def delete(**args):
            self.calls.append(("delete", region, self.now, args))
            if self.fail_delete:
                raise denied("DeleteAnalyzer")
            del self.records[args["analyzerName"]]
        return SimpleNamespace(create_analyzer=create, delete_analyzer=delete,
                               get_analyzer=lambda **args: self.call(session, service, region, "get_analyzer", **args))

    def call(self, session, service, region, operation, **args):
        self.calls.append(("get", region, self.now, args))
        if self.fail_read:
            raise denied("GetAnalyzer")
        row = dict(self.records[args["analyzerName"]])
        if self.creating:
            row["status"] = "CREATING"
        return {"analyzer": row}


SESSION = SimpleNamespace(get_partition_for_region=lambda region: "aws")


def enrich(requests, session, region, items):
    requests.calls.append(("evidence", region, requests.now, {}))
    return [{**item, "Findings": [{"id": "preserved"}]} for item in items]


def test_native_scan_creates_one_unused_and_external_per_region_waits_and_cleans(monkeypatch):
    requests = FakeRequests(monkeypatch)
    with lifecycle.AnalyzerLifecycle(requests, requests.events) as manager:
        manager.prepare(SESSION, IDENTITY, REGIONS)
        creates = [call for call in requests.calls if call[0] == "create"]
        assert [call[3]["type"] for call in creates] == ["ACCOUNT", "ACCOUNT_UNUSED_ACCESS", "ACCOUNT"]
        assert creates[1][3]["configuration"] == {"unusedAccess": {"unusedAccessAge": 90}}
        for region in REGIONS:
            read = manager.collect(SESSION, IDENTITY, region, enrich)
            assert read.status == "partial"
            assert all(item["Findings"] == [{"id": "preserved"}] for item in read.items)
            assert all(item["_coverage"]["InitialAnalysis"]["status"] == "partial" for item in read.items)
    assert all(call[2] >= 180 for call in requests.calls if call[0] in {"get", "evidence"})
    assert not requests.records
    assert all(event["cleanup_status"] == "deleted" for event in requests.events)
    assert all("ready_after" not in event for event in requests.events)


def test_existing_analyzers_in_other_region_are_reused_and_never_deleted(monkeypatch):
    external = {"arn": "existing-external", "type": "ACCOUNT", "status": "ACTIVE"}
    unused = {"arn": "existing-unused", "type": "ACCOUNT_UNUSED_ACCESS", "status": "ACTIVE"}
    requests = FakeRequests(monkeypatch, {
        REGIONS[0]: aws.ReadResult([external]), REGIONS[1]: aws.ReadResult([external, unused])})
    with lifecycle.AnalyzerLifecycle(requests, requests.events) as manager:
        manager.prepare(SESSION, IDENTITY, REGIONS)
        for region in REGIONS:
            assert manager.collect(SESSION, IDENTITY, region, enrich).status == "collected"
    assert requests.now == 0
    assert {call[0] for call in requests.calls} == {"evidence"}


def test_denied_listing_never_creates_analyzers_or_duplicates_unused(monkeypatch):
    requests = FakeRequests(monkeypatch, {REGIONS[0]: aws.ReadResult([], "denied", {"code": "AccessDenied"})})
    with lifecycle.AnalyzerLifecycle(requests, requests.events) as manager:
        manager.prepare(SESSION, IDENTITY, REGIONS)
    creates = [call for call in requests.calls if call[0] == "create"]
    assert len(creates) == 1 and creates[0][1] == REGIONS[1] and creates[0][3]["type"] == "ACCOUNT"
    assert not requests.records


def test_creation_denied_continues_without_wait_or_cleanup(monkeypatch):
    requests = FakeRequests(monkeypatch)
    requests.fail_create = True
    with lifecycle.AnalyzerLifecycle(requests, requests.events) as manager:
        manager.prepare(SESSION, IDENTITY, REGIONS[:1])
        result = manager.collect(SESSION, IDENTITY, REGIONS[0], enrich)
    assert result.status == "denied"
    assert requests.now == 0
    assert not any(call[0] == "delete" for call in requests.calls)


@pytest.mark.parametrize("failure", ["cancel", "read", "enrich", "never_active", "before_collection"])
def test_cleanup_on_failures_and_cancellation(monkeypatch, failure):
    requests = FakeRequests(monkeypatch)
    with lifecycle.AnalyzerLifecycle(requests, requests.events) as manager:
        manager.prepare(SESSION, IDENTITY, REGIONS[:1])
        requests.cancelled = failure == "cancel"
        requests.fail_read = failure == "read"
        requests.creating = failure == "never_active"
        def read(*args):
            if failure == "enrich":
                raise TimeoutError()
            return enrich(*args)
        if failure != "before_collection":
            result = manager.collect(SESSION, IDENTITY, REGIONS[0], read)
            assert result.status == "partial"
    assert not requests.records
    assert len([call for call in requests.calls if call[0] == "delete"]) == 2


def test_cleanup_denial_retains_arns_and_sanitized_failure(monkeypatch):
    requests = FakeRequests(monkeypatch)
    requests.fail_delete = True
    with lifecycle.AnalyzerLifecycle(requests, requests.events) as manager:
        manager.prepare(SESSION, IDENTITY, REGIONS[:1])
        manager.collect(SESSION, IDENTITY, REGIONS[0], enrich)
    assert all(event["cleanup_status"] == "failed" for event in requests.events)
    assert all(event["cleanup_error"] == {"code": "AccessDeniedException"} for event in requests.events)
    assert all(event["arn"].startswith("arn:aws:access-analyzer:") for event in requests.events)
    assert "private" not in str(requests.events)


def test_timed_out_create_is_cleaned_up_even_if_response_is_lost(monkeypatch):
    requests = FakeRequests(monkeypatch)
    original = requests.client
    def client(*args):
        value = original(*args)
        create = value.create_analyzer
        def lost_response(**kwargs):
            create(**kwargs)
            raise TimeoutError()
        value.create_analyzer = lost_response
        return value
    requests.client = client
    with lifecycle.AnalyzerLifecycle(requests, requests.events) as manager:
        manager.prepare(SESSION, IDENTITY, REGIONS[:1])
    assert not requests.records
    assert all(event["create_status"] == "uncertain" and event["cleanup_status"] == "deleted" for event in requests.events)


def test_full_native_collector_uses_lifecycle_and_preserves_findings(monkeypatch):
    from datetime import datetime, timezone
    import boto3
    from botocore.stub import Stubber
    from peaso.snapshot import validate
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name=REGIONS[0])
    clients = {service: session.client(service) for service in ("sts", "accessanalyzer")}
    monkeypatch.setattr(aws, "_session", lambda *args: (session, "test-pinned"))
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: clients[service])
    counter = iter(["a" * 32, "b" * 32])
    monkeypatch.setattr(lifecycle.uuid, "uuid4", lambda: SimpleNamespace(hex=next(counter)))
    clock = [0.0]
    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: clock[0])
    original_init = aws.Requests.__init__
    def init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._sleep = lambda seconds: clock.__setitem__(0, clock[0] + seconds)
    monkeypatch.setattr(aws.Requests, "__init__", init)
    now = datetime(2026, 10, 19, tzinfo=timezone.utc)
    external = "peaso-scan-" + "a" * 32 + "-external"
    unused = "peaso-scan-" + "b" * 32 + "-unused"
    arns = [f"arn:aws:access-analyzer:{REGIONS[0]}:{ACCOUNT}:analyzer/{name}" for name in (external, unused)]
    with Stubber(clients["sts"]) as sts, Stubber(clients["accessanalyzer"]) as analyzer:
        sts.add_response("get_caller_identity", {**IDENTITY, "UserId": "AIDASCANNER"}, {})
        analyzer.add_response("list_analyzers", {"analyzers": []}, {})
        for name, arn, kind in zip((external, unused), arns, ("ACCOUNT", "ACCOUNT_UNUSED_ACCESS")):
            args = {"analyzerName": name, "type": kind, "clientToken": name}
            if kind.endswith("UNUSED_ACCESS"):
                args["configuration"] = {"unusedAccess": {"unusedAccessAge": 90}}
            analyzer.add_response("create_analyzer", {"arn": arn}, args)
        for name, arn, kind in zip((external, unused), arns, ("ACCOUNT", "ACCOUNT_UNUSED_ACCESS")):
            analyzer.add_response("get_analyzer", {"analyzer": {"arn": arn, "name": name, "type": kind,
                "status": "ACTIVE", "createdAt": now}}, {"analyzerName": name})
        # Finding list pagination and per-finding detail must finish before DeleteAnalyzer.
        for analyzer_index, arn in enumerate(arns):
            finding_type = "ExternalAccess" if analyzer_index == 0 else "UnusedPermission"
            resource_type = "AWS::S3::Bucket" if analyzer_index == 0 else "AWS::IAM::Role"
            resource_arn = "arn:aws:s3:::bucket" if analyzer_index == 0 else f"arn:aws:iam::{ACCOUNT}:role/unused"
            details = {"externalAccessDetails": {"isPublic": True, "condition": {}}} if analyzer_index == 0 else {
                "unusedPermissionDetails": {"serviceNamespace": "s3", "actions": [{"action": "ListBucket"}]}}
            for index in range(2):
                args = {"analyzerArn": arn, "filter": {"status": {"eq": ["ACTIVE"]}}}
                if index:
                    args["nextToken"] = "next"
                finding = {"id": f"f{index}", "resource": resource_arn, "resourceType": resource_type,
                    "resourceOwnerAccount": ACCOUNT, "status": "ACTIVE", "createdAt": now, "updatedAt": now,
                    "analyzedAt": now, "findingType": finding_type}
                analyzer.add_response("list_findings_v2", {"findings": [finding], **({"nextToken": "next"} if index == 0 else {})}, args)
            for index in range(2):
                analyzer.add_response("get_finding_v2", {"id": f"f{index}", "resource": resource_arn,
                    "resourceType": resource_type, "resourceOwnerAccount": ACCOUNT, "status": "ACTIVE",
                    "createdAt": now, "updatedAt": now, "analyzedAt": now, "findingType": finding_type,
                    "findingDetails": [details]}, {"analyzerArn": arn, "id": f"f{index}"})
        for name in (external, unused):
            analyzer.add_response("delete_analyzer", {}, {"analyzerName": name, "clientToken": name})
        snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT],
            "options": {"regions": REGIONS[:1], "service_concurrency": 1}}, ["access_analyzer"])
        assert validate(snapshot) == snapshot
        collection = next(row for row in snapshot["collections"] if row["type"] == "access_analyzer")
        assert collection["status"] == "partial"
        assert len(collection["items"]) == 2
        assert all(len(row["Findings"]) == 2 for row in collection["items"])
        external_row = next(row for row in collection["items"] if row["type"] == "ACCOUNT")
        unused_row = next(row for row in collection["items"] if row["type"] == "ACCOUNT_UNUSED_ACCESS")
        assert all(finding["FindingDetails"]["items"][0]["externalAccessDetails"]["isPublic"]
                   for finding in external_row["Findings"])
        assert all(finding["UnusedPermissionDetails"]["items"][0]["unusedPermissionDetails"]["actions"] == [{"action": "ListBucket"}]
                   for finding in unused_row["Findings"])
        assert clock[0] >= 180
        assert all(event["cleanup_status"] == "deleted" for event in snapshot["metadata"]["access_analyzer_lifecycle"]), snapshot["metadata"]["access_analyzer_lifecycle"]
        sts.assert_no_pending_responses()
        analyzer.assert_no_pending_responses()


def test_cleanup_retries_transient_failures(monkeypatch):
    requests = FakeRequests(monkeypatch)
    original = requests.client
    attempts = []
    def client(*args):
        value = original(*args)
        delete = value.delete_analyzer
        def throttled(**kwargs):
            attempts.append(kwargs["analyzerName"])
            if attempts.count(kwargs["analyzerName"]) == 1:
                raise ClientError({"Error": {"Code": "ThrottlingException"}}, "DeleteAnalyzer")
            return delete(**kwargs)
        value.delete_analyzer = throttled
        return value
    requests.client = client
    with lifecycle.AnalyzerLifecycle(requests, requests.events) as manager:
        manager.prepare(SESSION, IDENTITY, REGIONS[:1])
    assert len(attempts) == 4
    assert not requests.records
    assert all(event["cleanup_status"] == "deleted" for event in requests.events)
