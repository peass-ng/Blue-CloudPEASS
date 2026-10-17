"""Access-point denial evidence from the collector through native evaluation."""

from peaso.collectors import aws
from peaso.collectors import aws_facts_cb_ca
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot, resources


ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
CHECK = "aws.claude_a.s3.access_point_public_access_block"
FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def point(name):
    return {"Name": name, "AccessPointArn": f"arn:aws:s3:{REGION}:{ACCOUNT}:accesspoint/{name}",
            "Bucket": "bucket-a", "NetworkOrigin": "Internet"}


class FakeRequests:
    def __init__(self, listing, details=()):
        self.listing = listing
        self.details = iter(details)
        self.calls = []

    def pages(self, session, service, region, operation, expression, **arguments):
        self.calls.append((operation, arguments))
        assert (service, region, operation, expression) == (
            "s3control", REGION, "list_access_points", "AccessPointList")
        assert arguments == {"_tokens": ("NextToken", "NextToken"), "AccountId": ACCOUNT}
        return self.listing

    def detail(self, session, service, region, operation, **arguments):
        self.calls.append((operation, arguments))
        assert (service, region, operation) == ("s3control", REGION, "get_access_point")
        assert arguments["AccountId"] == ACCOUNT
        return next(self.details)


def collect_and_evaluate(requests):
    read = aws_facts_cb_ca.FETCHERS["s3_access_point"](requests, object(), REGION, ACCOUNT)
    collection = {"type": "s3_access_point", "scope": SCOPE, "service": "s3control",
                  "status": read.status, "items": read.items}
    if read.error:
        collection["error"] = read.error
    snapshot = make_snapshot("aws", [SCOPE], [collection])
    report = evaluate_snapshot(snapshot, categories=["exposure"], checks=[CHECK])
    findings = [row for row in report["findings"] if row["check_id"] == CHECK]
    return read, snapshot, resources(snapshot), report, findings


def test_denied_list_remains_denied_inventory_without_resources():
    requests = FakeRequests(aws.ReadResult([], "denied", {"code": "AccessDenied", "cause_status": "denied"}))
    read, snapshot, inventory, report, findings = collect_and_evaluate(requests)
    assert read.status == snapshot["collections"][0]["status"] == "denied"
    assert inventory == report["resources"] == []
    assert len(findings) == 1
    assert findings[0]["status"] == "DENIED"
    assert findings[0]["resource_id"] == "inventory:s3_access_point"
    assert findings[0]["evidence"]["collection_status"] == "denied"
    assert not report["stats"]["coverage_complete"]
    assert requests.calls == [("list_access_points", {"_tokens": ("NextToken", "NextToken"), "AccountId": ACCOUNT})]


def test_denied_detail_keeps_identity_and_evaluates_unknown():
    row = point("denied")
    requests = FakeRequests(aws.ReadResult([row]), [
        {"collection_status": "denied", "error": {"code": "AccessDenied"}}])
    read, snapshot, inventory, report, findings = collect_and_evaluate(requests)
    assert read.status == "collected" and len(read.items) == 1
    assert read.items[0]["AccessPointArn"] == row["AccessPointArn"]
    assert read.items[0]["collection_status"] == "denied"
    assert read.items[0]["error"] == {"code": "AccessDenied", "operation": "get_access_point"}
    assert "PublicAccessBlockConfiguration" not in read.items[0]
    assert len(inventory) == len(findings) == 1
    assert inventory[0]["native_id"] == row["Name"]
    assert findings[0]["resource_id"] == inventory[0]["id"]
    assert findings[0]["status"] == "UNKNOWN"
    assert not report["stats"]["coverage_complete"]


def test_complete_true_and_false_flags_evaluate_pass_and_fail():
    rows = [point("safe"), point("weak")]
    all_true = {name: True for name in FLAGS}
    one_false = {**all_true, "BlockPublicPolicy": False}
    requests = FakeRequests(aws.ReadResult(rows), [
        {"collection_status": "collected", "PublicAccessBlockConfiguration": all_true},
        {"collection_status": "collected", "PublicAccessBlockConfiguration": one_false},
    ])
    read, _, inventory, _, findings = collect_and_evaluate(requests)
    assert read.status == "collected"
    assert {row["native_id"] for row in inventory} == {"safe", "weak"}
    names = {row["id"]: row["native_id"] for row in inventory}
    assert {names[row["resource_id"]]: row["status"] for row in findings} == {
        "safe": "PASS", "weak": "FAIL"}


def test_mixed_rows_keep_distinct_identity_evidence_and_unknown_detail():
    rows = [point("safe"), point("unreadable"), point("weak")]
    all_true = {name: True for name in FLAGS}
    requests = FakeRequests(aws.ReadResult(rows), [
        {"collection_status": "collected", "PublicAccessBlockConfiguration": all_true},
        {"collection_status": "denied", "error": {"code": "AccessDenied"}},
        {"collection_status": "collected", "PublicAccessBlockConfiguration": {
            **all_true, "RestrictPublicBuckets": False}},
    ])
    read, snapshot, inventory, report, findings = collect_and_evaluate(requests)
    assert snapshot["collections"][0]["status"] == "collected"
    assert len(read.items) == len(inventory) == len(findings) == 3
    names = {row["id"]: row["native_id"] for row in inventory}
    by_name = {names[row["resource_id"]]: row for row in findings}
    assert {name: row["status"] for name, row in by_name.items()} == {
        "safe": "PASS", "unreadable": "UNKNOWN", "weak": "FAIL"}
    assert by_name["safe"]["evidence"]["settings"] == all_true
    assert by_name["weak"]["evidence"]["settings"]["RestrictPublicBuckets"] is False
    assert read.items[1]["AccessPointArn"] == rows[1]["AccessPointArn"]
    assert read.items[1]["error"] == {"code": "AccessDenied", "operation": "get_access_point"}
    assert "PublicAccessBlockConfiguration" not in read.items[1]
    assert not report["stats"]["coverage_complete"]
