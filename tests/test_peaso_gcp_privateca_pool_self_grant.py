"""A CA pool self-grant uses exact policy write and new issuance authority."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
POOL = PROJECT + "/locations/us-central1/caPools/trusted"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/poolPolicyWriter"
ENTRY = next(e for e in privesc.catalog()["entries"]
             if e["id"] == "gcp-privateca-capools-setiampolicy-ca-pool-self-grant")


def report(permissions=("privateca.caPools.setIamPolicy",)):
    return snapshot("gcp", [
        ("project", PROJECT, [{"name": "projects/1234", "projectId": "p1"}]),
        ("iam_role", PROJECT, [{"name": ROLE, "includedPermissions": list(permissions)}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": ROLE, "members": [SOURCE]}]}]),
        ("service_account", PROJECT, [], "empty"),
        ("ca_pool", PROJECT, [{"name": POOL, "iamPolicy": {"bindings": []},
                               "_coverage": {"iamPolicy": {"status": "collected"}}}]),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("org_policy_effective", PROJECT, [], "empty"),
        ("group", PROJECT, [], "empty"),
        ("group_membership", PROJECT, [], "empty"),
    ])


def reaches(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def collection(snap, kind):
    return next(row for row in snap["collections"] if row["type"] == kind)


def test_exact_pool_policy_write_can_grant_new_certificate_issuance():
    assert reaches(report()) == [(
        "gcp_verified_authority:possible-ca-pool-self-grant:" + POOL, "conditional")]


def test_already_held_issuance_or_wrong_pool_grant_is_not_a_new_path():
    snap = report(("privateca.caPools.setIamPolicy", "privateca.certificates.create"))
    assert reaches(snap) == []
    snap = report()
    collection(snap, "iam_policy")["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + PROJECT +
                      "/locations/us-central1/caPools/other'"}
    assert not any(target.startswith("gcp_verified_authority:") for target, _ in reaches(snap))


def test_missing_policy_read_or_pool_inventory_remains_unresolved():
    snap = report()
    collection(snap, "ca_pool")["items"][0]["_coverage"]["iamPolicy"]["status"] = "denied"
    assert not any(confidence == "conditional" for _, confidence in reaches(snap))
    snap = report()
    collection(snap, "ca_pool")["status"] = "denied"
    collection(snap, "ca_pool")["items"] = []
    assert not any(target.startswith("gcp_verified_authority:") for target, _ in reaches(snap))


def test_conditional_write_never_becomes_definite():
    snap = report()
    collection(snap, "iam_policy")["items"][0]["bindings"][0]["condition"] = {
        "expression": "request.time < timestamp('2099-01-01T00:00:00Z')"}
    assert not any(confidence == "derived" for _, confidence in reaches(snap))


def test_malformed_pool_policy_cannot_support_a_conditional_path():
    snap = report()
    collection(snap, "ca_pool")["items"][0]["iamPolicy"] = {"bindings": {}}
    assert not any(confidence == "conditional" for _, confidence in reaches(snap))
