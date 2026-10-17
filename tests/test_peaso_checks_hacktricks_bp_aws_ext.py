import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import hacktricks_bp_aws_ext as ext
from peaso.checks.fixtures import CASES
from peaso.checks.hacktricks_bp_common import HTBP_IDS

REGISTRY = {c.id: c for c in CHECKS}
IDS = ["aws.htbp.lambda.layer_version_trust_boundary", "aws.htbp.lambda.runtime_updates_not_pinned_manual",
       "aws.htbp.lambda.env_var_names_not_credentials",
       "aws.htbp.ecr.registry_policy_trust_boundary", "aws.htbp.ecr.replication_destinations_trust_boundary",
       "aws.htbp.ecr.creation_template_policy_trust_boundary", "aws.htbp.eks.access_entry_principal_trust_boundary",
       "aws.htbp.kms.grant_grantee_trust_boundary", "aws.htbp.opensearch.connection_peer_trust_boundary"]
EXPECTED = {"pass": "PASS", "fail": "FAIL", "manual": "MANUAL", "not_applicable": "NOT_APPLICABLE", "missing": "UNKNOWN", "malformed": "UNKNOWN"}


def run(cid, item, index=None):
    return REGISTRY[cid].evaluate(copy.deepcopy(item), copy.deepcopy(index if index is not None else CASES[cid].get("index", {})))


def test_module_registers_nine_htbp_checks():
    assert all(cid in HTBP_IDS and cid in REGISTRY and cid in CASES for cid in IDS)
    assert len(set(IDS)) == 9


@pytest.mark.parametrize("cid", IDS)
def test_fixture_states(cid):
    for name, case in CASES[cid].items():
        if name == "index":
            continue
        expected = next(state for key, state in EXPECTED.items() if name == key or name.startswith(key + "_"))
        assert run(cid, case)[0] == expected, (cid, name)


TRUST_BOUNDARY_IDS = [cid for cid in IDS if cid.endswith("_trust_boundary")]


@pytest.mark.parametrize("cid", TRUST_BOUNDARY_IDS)
def test_out_of_account_without_org_inventory_is_manual_not_fail(cid):
    index = ext._org_index(org=False)
    cases = CASES[cid]
    # The org peer is outside the audited account; without the org inventory it cannot be proven external.
    peer = {"aws.htbp.lambda.layer_version_trust_boundary": cases["pass"],
            "aws.htbp.ecr.registry_policy_trust_boundary": cases["pass"],
            "aws.htbp.ecr.replication_destinations_trust_boundary": cases["pass"],
            "aws.htbp.ecr.creation_template_policy_trust_boundary": ext._templates(ext._allow({"AWS": ext.ORG_PEER})),
            "aws.htbp.eks.access_entry_principal_trust_boundary": ext._entry("arn:aws:iam::%s:role/ops" % ext.ORG_PEER),
            "aws.htbp.kms.grant_grantee_trust_boundary": ext._grant("arn:aws:iam::%s:role/ops" % ext.ORG_PEER),
            "aws.htbp.opensearch.connection_peer_trust_boundary": cases["pass"]}[cid]
    status, evidence = run(cid, peer, index)
    assert status == "MANUAL" and evidence["external_accounts"] == [ext.ORG_PEER]
    # A configured trusted account is inside the boundary.
    assert run(cid, peer, ext._org_index(org=False, trusted=[ext.ORG_PEER]))[0] == "PASS"


def test_public_policy_fails_even_without_org_inventory():
    cid = "aws.htbp.lambda.layer_version_trust_boundary"
    status, evidence = run(cid, CASES[cid]["fail"], ext._org_index(org=False))
    assert status == "FAIL" and evidence["public"] is True


def test_account_scoped_condition_restricts_wildcard_principal():
    cid = "aws.htbp.ecr.registry_policy_trust_boundary"
    policy = ext._allow("*", {"StringEquals": {"aws:PrincipalAccount": ext.ACCOUNT}}, action="ecr:ReplicateImage")
    item = ext._registry(RegistryPolicy={"collection_status": "collected", "policyText": policy})
    assert run(cid, item)[0] == "PASS"
    deny = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*"}]}
    assert run(cid, ext._registry(RegistryPolicy={"collection_status": "collected", "policyText": deny}))[0] == "PASS"


def test_missing_audited_account_is_unknown():
    cid = "aws.htbp.kms.grant_grantee_trust_boundary"
    assert run(cid, CASES[cid]["pass"], {})[0] == "UNKNOWN"


def test_incomplete_org_inventory_is_manual():
    cid = "aws.htbp.eks.access_entry_principal_trust_boundary"
    index = ext._org_index()
    index["collections"]["organization_account"][0]["status"] = "partial"
    assert run(cid, CASES[cid]["fail"], index)[0] == "MANUAL"


def test_registry_without_template_policy_passes():
    cid = "aws.htbp.ecr.creation_template_policy_trust_boundary"
    item = ext._registry(RepositoryCreationTemplates={"collection_status": "collected", "items": [{"prefix": "x", "appliedFor": ["CREATE_ON_PUSH"]}]})
    assert run(cid, item)[0] == "PASS"


def test_fail_evidence_names_the_external_party():
    cid = "aws.htbp.opensearch.connection_peer_trust_boundary"
    status, evidence = run(cid, CASES[cid]["fail_inbound"])
    assert status == "FAIL" and evidence["external_accounts"] == [ext.OUTSIDER] and evidence["direction"] == "inbound"


@pytest.mark.parametrize("org_status,expected", [("collected", "FAIL"), ("denied", "MANUAL")])
def test_engine_scoped_index_carries_the_global_organization_inventory(org_status, expected):
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    acct, regional = ext.ACCOUNT, ext.ACCOUNT + "/us-east-1"
    entry = {**ext._entry("arn:aws:iam::%s:role/backdoor" % ext.OUTSIDER), "id": "prod/backdoor", "AccountId": acct, "Region": "us-east-1"}
    org_items = [{"Id": acct, "AccountId": acct}, {"Id": ext.ORG_PEER, "AccountId": acct}] if org_status == "collected" else []
    snapshot = make_snapshot("aws", [regional], [
        {"type": "eks_access_entry", "scope": regional, "service": "eks", "status": "collected", "items": [entry], "account_id": acct},
        {"type": "organization_account", "scope": acct + "/global", "service": "organizations", "status": org_status,
         "items": org_items, "account_id": acct, "global": True}])
    report = evaluate_snapshot(snapshot, categories=["least_privilege"], checks=["aws.htbp.eks.access_entry_principal_trust_boundary"])
    assert [row["status"] for row in report["findings"]] == [expected]
