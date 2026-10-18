"""Inspector admin applicability requires native proof, never an error heuristic."""
import copy
import pytest
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks import aws_b_inspector as module
from peaso.checks.fixtures import CASES
from peaso.collectors import aws_b_services as plugin
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


def check(cid):
    return next(c for c in CHECKS if c.id == cid)


@pytest.mark.parametrize("cid", module.IDS)
def test_admin_only_pass_fail_and_explicit_dependency_truth(cid):
    c = check(cid)
    fixture = CASES[cid]
    for label, expected in (("pass", "PASS"), ("fail", "FAIL")):
        index = copy.deepcopy(fixture[label + "_index"])
        before = copy.deepcopy(index)
        assert c.evaluate(fixture[label], index)[0] == expected
        assert index == before
    assert c.evaluate({}, {})[0] == "UNKNOWN"
    assert HACKTRICKS in c.frameworks
    assert c.dependencies == [module.KIND]


@pytest.mark.parametrize("cid", module.IDS)
def test_foreign_enabled_admin_proves_na_even_when_configuration_is_denied(cid):
    index = copy.deepcopy(CASES[cid]["pass_index"])
    row = index[module.KIND][0]["data"]
    row["Administrator"]["delegatedAdmin"]["accountId"] = "222222222222"
    row["Configuration"] = {"collection_status": "denied", "error": {"code": "AccessDenied"}}
    status, evidence = check(cid).evaluate({}, index)
    assert status == "NOT_APPLICABLE"
    assert evidence["configuration_read_status"] == "denied"
    assert evidence["delegated_admin_account"] != evidence["caller_account"]


@pytest.mark.parametrize("state", ["denied", "unknown", "not_collected", "empty"])
def test_unavailable_admin_proof_never_becomes_na(state):
    cid = module.IDS[0]
    index = copy.deepcopy(CASES[cid]["pass_index"])
    index[module.KIND][0]["data"]["Administrator"] = {"collection_status": state}
    assert check(cid).evaluate({}, index)[0] == ("DENIED" if state == "denied" else "UNKNOWN")


@pytest.mark.parametrize("relationship", ["DISABLED", "INVITED", "REGION_DISABLED", "invented"])
def test_only_positive_enabled_proof_establishes_foreign_admin(relationship):
    cid = module.IDS[0]
    index = copy.deepcopy(CASES[cid]["pass_index"])
    index[module.KIND][0]["data"]["Administrator"]["delegatedAdmin"].update(accountId="222222222222", relationshipStatus=relationship)
    assert check(cid).evaluate({}, index)[0] == "UNKNOWN"


def test_missing_malformed_foreign_caller_and_admin_configuration_remain_explicit():
    cid = module.IDS[0]
    index = copy.deepcopy(CASES[cid]["pass_index"])
    row = index[module.KIND][0]["data"]
    row["Configuration"] = {"collection_status": "denied"}
    assert check(cid).evaluate({}, index)[0] == "DENIED"
    row["AccountId"] = "222222222222"
    assert check(cid).evaluate({}, index)[0] == "UNKNOWN"
    row["AccountId"] = "111111111111"
    row["Administrator"]["delegatedAdmin"]["accountId"] = "invalid"
    assert check(cid).evaluate({}, index)[0] == "UNKNOWN"
    row["Administrator"] = {"collection_status": "collected"}
    assert check(cid).evaluate({}, index)[0] == "UNKNOWN"


def test_plugin_record_preserves_independent_read_statuses_and_uses_only_shared_requests():
    class Reads:
        calls = []
        def detail(self, session, service, region, operation, **kwargs):
            self.calls.append((service, region, operation, kwargs))
            if operation == "get_delegated_admin_account":
                return {"collection_status": "collected", "delegatedAdmin": {"accountId": "222222222222", "relationshipStatus": "ENABLED"}}
            return {"collection_status": "denied", "error": {"code": "AccessDenied"}}
    reads = Reads()
    record = plugin.FETCHERS[module.KIND](reads, object(), "us-east-1", "111111111111")
    assert record.status == "collected"
    assert record.items[0]["Configuration"]["collection_status"] == "denied"
    assert record.items[0]["Administrator"]["collection_status"] == "collected"
    assert reads.calls == [("inspector2", "us-east-1", "get_delegated_admin_account", {}),
                           ("inspector2", "us-east-1", "describe_organization_configuration", {})]


def test_engine_admin_variant_does_not_rewrite_literal_source_variant():
    scope = "111111111111/us-east-1"
    record = {"AccountId": "111111111111", "Administrator": {"collection_status": "collected", "delegatedAdmin": {"accountId": "222222222222", "relationshipStatus": "ENABLED"}}, "Configuration": {"collection_status": "denied"}}
    snapshot = make_snapshot("aws", [scope], [{"type": module.KIND, "scope": scope, "status": "collected", "items": [record]},
                 {"type": "inspector_organization_configuration", "scope": scope, "status": "denied", "items": []}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.b.inspector.admin_ec2_auto_enable", "aws.b.inspector.ec2_organization_auto_enable"])
    statuses = {f["check_id"]: f["status"] for f in report["findings"]}
    assert statuses == {"aws.b.inspector.admin_ec2_auto_enable": "NOT_APPLICABLE", "aws.b.inspector.ec2_organization_auto_enable": "DENIED"}


@pytest.mark.parametrize("code, expected", [("no_delegated_administrator", "NOT_APPLICABLE"), ("region_operation_unsupported", "UNKNOWN"), (None, "UNKNOWN")])
def test_documented_no_delegated_admin_reply_is_na_only_with_exact_state(code, expected):
    cid = module.IDS[0]
    index = copy.deepcopy(CASES[cid]["pass_index"])
    index[module.KIND][0]["data"]["Administrator"] = {"collection_status": "empty", "absent": True, **({"error": {"code": code}} if code else {})}
    assert check(cid).evaluate({}, index)[0] == expected


def test_collector_detail_keeps_sanitized_service_state_code():
    from peaso.collectors import aws
    from botocore.exceptions import ClientError
    requests = aws.Requests({})
    def raiser(*args, **kwargs):
        raise aws._failure(ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": "No delegated admin found for caller account."}}, "GetDelegatedAdminAccount"))
    requests.call = raiser
    detail = plugin._detail(requests, None, "us-east-1", "inspector2", "get_delegated_admin_account")
    assert detail == {"collection_status": "empty", "absent": True, "error": {"code": "no_delegated_administrator"}}
