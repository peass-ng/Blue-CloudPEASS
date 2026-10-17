"""Regression tests: missing selector facts never expand to every principal, and service-managed identities
(AWS service-linked roles, Google-managed service agents, Microsoft first-party SPs) are never targets."""
from __future__ import annotations

import pytest

from peaso import privesc
from peaso.privesc import MODELS
from peaso.privesc.effective_permissions import Node
from peaso.privesc.effective_permissions.azure import AzureModel
from peaso.privesc.effective_permissions.gcp import _google_managed
from peaso.privesc.evaluator import COVERED_BY, LOCALIZING_SELECTORS

from test_peaso_privesc_followups import (ACCOUNT, ALICE, aws_snap, catalog_entry as active_catalog_entry, archived_catalog_entry, edges, entry, gcp_snap, gsa, reached,
                                          role, snapshot, trust_service, user)


def catalog_entry(eid):
    return archived_catalog_entry(eid) if eid in {"aws-codedeploy-createdeployment-instance-roles", "aws-ecr-push-consumed-tag"} else active_catalog_entry(eid)

SLR = f"arn:aws:iam::{ACCOUNT}:role/aws-service-role/remediation.config.amazonaws.com/AWSServiceRoleForConfigRemediation"


def slr_role():
    item = role("AWSServiceRoleForConfigRemediation", trust_service("remediation.config.amazonaws.com"))
    item.update(Arn=SLR, Path="/aws-service-role/remediation.config.amazonaws.com/")
    return item


def nodes(result):
    return {n["id"]: n for n in result["graph"]["nodes"]}


def target_nodes(result, source=None):
    by_id = nodes(result)
    return [by_id[e["target"]] for e in edges(result, source)]


def assert_unresolved_only(result, source):
    targets = target_nodes(result, source)
    assert targets, "expected an unresolved placeholder edge"
    for node in targets:
        assert node["id"].startswith("unresolved:"), node["id"]
        assert node["label"].startswith("Unresolved: ")
        assert node["underlying_count"] == 0 and node["members"] == [] and node["confidence"] == "unknown"
        assert node["unresolved_reason"] and node["facts_needed"]
    return targets


# --- the reported false positive -------------------------------------------------------------------
def test_missing_selector_facts_give_one_placeholder_not_every_role():
    """AWSServiceRoleForConfigRemediation (and every other role) was a member of CodeDeploy/ECR aggregates whose
    selector facts were never collected."""
    alice = user("alice", {"Effect": "Allow", "Action": ["codedeploy:*", "ecr:*"], "Resource": "*"})
    roles = [slr_role(), role("app", trust_service("ec2.amazonaws.com")), role("ci", trust_service("codebuild.amazonaws.com"))]
    entries = [catalog_entry("aws-codedeploy-createdeployment-instance-roles"), catalog_entry("aws-ecr-push-consumed-tag")]
    result = privesc.analyze(aws_snap([alice], roles), entries=entries, include_unknown=True)
    targets = assert_unresolved_only(result, ALICE)
    assert len(targets) == 2  # one placeholder per aggregate (and scope)
    assert all(not n.get("members") or SLR not in n["members"] for n in result["graph"]["nodes"])
    assert {f["status"] for f in result["findings"]} == {"UNKNOWN"}
    assert all(f["evidence"]["target_count"] == 0 for f in result["findings"])
    reasons = {c["reason"] for c in result["coverage"] if c.get("kind") == "selector"}
    assert "selector codedeploy_group_instance_role_covered_by not evaluated" in reasons


def test_placeholder_needs_the_source_to_hold_the_per_target_action_somewhere():
    bob = user("bob", {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})
    result = privesc.analyze(aws_snap([bob], [role("app", trust_service("ec2.amazonaws.com"))]),
                             entries=[catalog_entry("aws-codedeploy-createdeployment-instance-roles")])
    assert edges(result) == []


def test_unknown_confidence_selector_match_is_not_a_member():
    """attached_to_service without the host inventory: roles trusting the service are not proven attached."""
    lam = entry("aws-t-update-fn", "aws", {"all_of": [{"action": "lambda:UpdateFunctionCode", "resource": "*"}]},
                {"kind": "aws_role", "selector": {"attached_to_service": "lambda"}, "scope": "same_account"})
    alice = user("alice", {"Effect": "Allow", "Action": "lambda:UpdateFunctionCode", "Resource": "*"})
    roles = [role(f"fn{i}", trust_service("lambda.amazonaws.com")) for i in range(3)]
    result = privesc.analyze(aws_snap([alice], roles), entries=[lam], include_unknown=True)
    assert_unresolved_only(result, ALICE)
    fn = {"FunctionName": "f", "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:f",
          "Role": f"arn:aws:iam::{ACCOUNT}:role/fn0"}
    result = privesc.analyze(aws_snap([alice], roles, extra=[("lambda_function", f"{ACCOUNT}/us-east-1", [fn])]), entries=[lam])
    assert reached(result, ALICE) == {f"arn:aws:iam::{ACCOUNT}:role/fn0": "derived"}


def test_dynamic_selector_without_facts_gives_placeholder():
    dyn = entry("aws-t-dyn", "aws", {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"}]},
                {"kind": "aws_role", "selector": {"kube2iam_namespace_permits_role": True}, "scope": "same_account"})
    alice = user("alice", {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"})
    result = privesc.analyze(aws_snap([alice], [role(f"r{i}", trust_service("ec2.amazonaws.com")) for i in range(4)]),
                             entries=[dyn], include_unknown=True)
    targets = assert_unresolved_only(result, ALICE)
    assert len(targets) == 1


def test_has_instance_profile_without_profile_list_is_unresolved():
    item = role("app", trust_service("ec2.amazonaws.com"))
    item.pop("InstanceProfileList")
    ec2 = entry("aws-t-profile", "aws", {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"}]},
                {"kind": "aws_role", "selector": {"has_instance_profile": True}, "scope": "same_account"})
    alice = user("alice", {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"})
    assert_unresolved_only(privesc.analyze(aws_snap([alice], [item]), entries=[ec2], include_unknown=True), ALICE)


def test_unresolvable_target_placeholder_requirement_is_unresolved():
    """{target.consumer_input_arn} cannot be resolved from the snapshot: no instance-profile role is proven."""
    dp = entry("aws-t-input", "aws", {"all_of": [{"action": "s3:PutObject", "resource": "{target.consumer_input_arn}"}]},
               {"kind": "aws_role", "selector": {"has_instance_profile": True}, "scope": "same_account"})
    alice = user("alice", {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"})
    roles = [role(f"r{i}", trust_service("ec2.amazonaws.com"), profile=True) for i in range(6)]
    targets = assert_unresolved_only(privesc.analyze(aws_snap([alice], roles), entries=[dp], include_unknown=True), ALICE)
    assert len(targets) == 1 and "consumer_input_arn" in targets[0]["unresolved_reason"]


def test_include_unknown_false_drops_placeholders():
    alice = user("alice", {"Effect": "Allow", "Action": ["codedeploy:*"], "Resource": "*"})
    result = privesc.analyze(aws_snap([alice], [role("app", trust_service("ec2.amazonaws.com"))]),
                             entries=[catalog_entry("aws-codedeploy-createdeployment-instance-roles")], include_unknown=False)
    assert edges(result) == []


# --- service-managed identities -----------------------------------------------------------------
def test_service_linked_role_is_never_a_target():
    passrole = entry("aws-t-pass", "aws", {"all_of": [{"action": "iam:PassRole", "resource": "{target.arn}"}]},
                     {"kind": "aws_role", "selector": {"trust_allows_service": "remediation.config.amazonaws.com"},
                      "scope": "same_account"})
    alice = user("alice", {"Effect": "Allow", "Action": "*", "Resource": "*"})
    bob = user("bob", {"Effect": "Allow", "Action": ["iam:PassRole", "iam:UpdateAssumeRolePolicy"], "Resource": "*"})
    trust = entry("aws-t-trust", "aws", {"all_of": [{"action": "iam:UpdateAssumeRolePolicy", "resource": "{target.arn}"}]},
                  {"kind": "aws_role", "scope": "same_account"})
    result = privesc.analyze(aws_snap([alice, bob], [slr_role(), role("app", trust_service("ec2.amazonaws.com"))]),
                             entries=[passrole, trust])
    bob_arn = f"arn:aws:iam::{ACCOUNT}:user/bob"
    assert SLR not in reached(result, bob_arn)
    assert reached(result, bob_arn) == {f"arn:aws:iam::{ACCOUNT}:role/app": "derived"}
    assert all(SLR not in (n.get("members") or []) for n in result["graph"]["nodes"])
    # An entry that explicitly targets service-managed identities keeps them.
    explicit = dict(passrole, target=dict(passrole["target"], include_service_managed=True))
    result = privesc.analyze(aws_snap([bob], [slr_role()]), entries=[explicit])
    assert reached(result, bob_arn) == {SLR: "derived"}


def test_validator_accepts_include_service_managed_boolean_only():
    from peaso.privesc.schema import validate_entry
    base = catalog_entry("aws-codedeploy-createdeployment-instance-roles")
    ok = dict(base, target=dict(base["target"], include_service_managed=True))
    bad = dict(base, target=dict(base["target"], include_service_managed="yes"))
    assert not [e for e in validate_entry(ok, hacktricks_root="/nonexistent")[0] if "include_service_managed" in e]
    assert [e for e in validate_entry(bad, hacktricks_root="/nonexistent")[0] if "include_service_managed" in e]


@pytest.mark.parametrize("email,managed", [
    ("service-123@gcp-sa-aiplatform-cc.iam.gserviceaccount.com", True),
    ("service-123@container-engine-robot.iam.gserviceaccount.com", True),
    ("123@cloudservices.gserviceaccount.com", True),
    ("123@cloudbuild.gserviceaccount.com", True),
    ("app@p1.iam.gserviceaccount.com", False),
    ("123-compute@developer.gserviceaccount.com", False),
    ("p1@appspot.gserviceaccount.com", False),
    ("alice@x.com", False),
])
def test_google_managed_service_agent_detection(email, managed):
    assert _google_managed(email) is managed


def test_gcp_service_agent_excluded_unless_selected_by_attachment():
    agent = "service-123@gcp-sa-aiplatform-cc.iam.gserviceaccount.com"
    app = "app@p1.iam.gserviceaccount.com"
    actas = {"name": "projects/p1/roles/actas", "includedPermissions": ["iam.serviceAccounts.getAccessToken"]}
    tok = entry("gcp-t-token", "gcp", {"all_of": [{"permission": "iam.serviceAccounts.getAccessToken", "resource": "{target.email}"}]},
                {"kind": "gcp_service_account", "scope": "any"})
    snap = gcp_snap([{"role": "projects/p1/roles/actas", "members": ["user:alice@x.com"]}],
                    sas=[gsa(app), dict(gsa(agent))], roles=[actas])
    result = privesc.analyze(snap, entries=[tok])
    assert set(reached(result, "user:alice@x.com")) == {f"serviceAccount:{app}"}


def test_gcp_attachment_without_inventory_is_unresolved():
    app = "app@p1.iam.gserviceaccount.com"
    upd = {"name": "projects/p1/roles/upd", "includedPermissions": ["cloudfunctions.functions.update"]}
    fn = entry("gcp-t-fn", "gcp", {"all_of": [{"permission": "cloudfunctions.functions.update", "resource": "*"}]},
               {"kind": "gcp_service_account", "selector": {"attached_to_service": "cloudfunctions_function"}, "scope": "any"})
    snap = gcp_snap([{"role": "projects/p1/roles/upd", "members": ["user:alice@x.com"]}], sas=[gsa(app)], roles=[upd])
    assert_unresolved_only(privesc.analyze(snap, entries=[fn], include_unknown=True), "user:alice@x.com")


def test_azure_first_party_service_principal_is_service_managed():
    model = AzureModel(snapshot("azure", []))
    first = Node("sp1", "azure_service_principal", "azure", "t", "Graph", attrs={"app_owner_org": "f8cdef31-a31e-4b4a-93e4-5f571e91255a"})
    mine = Node("sp2", "azure_service_principal", "azure", "t", "mine", attrs={"app_owner_org": "00000000-0000-0000-0000-000000000001"})
    assert model.service_managed(first) and not model.service_managed(mine)
    creds = catalog_entry("azure-entraid-sp-credentials-update")
    assert model.include_service_managed({"entry": creds})  # models first-party SPs through its condition
    assert not model.include_service_managed({"entry": {"target": {"kind": "azure_service_principal"}}})


# --- selector audit: a missing fact never yields a proven (derived) match ------------------------------
# Selectors that are structural (no facts involved) or enforced by a requirement elsewhere.
STRUCTURAL = {
    "any_principal_in_scope", "same_as_source", "source_kind", "name_prefix", "exclude_names", "k8s_sa_in_namespace",
    "k8s_node_schedulable", "entra_role_assignment_scope_covers_target", "entra_group_type_covered_by_permission",
    "entra_role_assignable", "_resource_type_from_action",
}


def _audit_cases():
    cases = []
    for e in privesc.catalog()["entries"]:
        for key, value in ((e.get("target") or {}).get("selector") or {}).items():
            if key in STRUCTURAL or key in LOCALIZING_SELECTORS or (key in COVERED_BY and key != "trust_allows_saml_provider_covered_by"):
                continue
            cases.append((e["provider"], key, value))
    return sorted(set((p, k, repr(v)) for p, k, v in cases))


@pytest.mark.parametrize("provider,key,value", _audit_cases())
def test_selector_without_facts_never_matches(provider, key, value):
    model = MODELS[provider](snapshot(provider, []))
    attrs = {"policy_ids": [], "groups": [], "grants": [], "namespace": "ns", "name": "n", "cluster": "c", "email": "e@x.com"}
    source = Node("src", "user", provider, "s", "src", attrs=dict(attrs))
    candidates = {"t": Node("t", "target", provider, "s", "t", attrs={"hosts": []})}
    verdict = model.selector(key, eval(value), candidates, source)  # noqa: S307 - repr of catalog literals
    if verdict is None:
        return  # unresolved placeholder
    for tid, why in verdict.items():
        assert why is not None, f"{provider} {key}: derived match without facts"
