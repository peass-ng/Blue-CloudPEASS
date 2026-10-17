"""Guard legacy escalation claims held for exact target and consumer evidence."""

from __future__ import annotations

import copy
import pytest
import json
from pathlib import Path

from peaso import privesc
from peaso.engine import privesc_technique_details
from peaso.privesc.schema import validate_entry
from peaso.privesc.effective_permissions.credential_evidence import SCOPED_IDS
from peaso.privesc.effective_permissions.azure_disclosure_effects import CONTRACT as DISCLOSURES
from peaso.privesc.versioned_catalog import (
    BINDING_SCHEMA, LEGACY_MANIFEST, LEGACY_REVISION, card_technique_ids,
    current_binding, lookup_entries, V4_MANIFEST, V4_EFFECTIVE_TREE, V4_REVISION,
)
from peaso.privesc import versioned_catalog as vc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import az
from tests.test_peaso_privesc_schema_v3_azure import _case as azure_challenge_case


HELD = (
    "aws-codecommit-gitpush-pipeline-source",
    "aws-ec2-passrole-associate-instance-profile",
    "aws-v3-05-add-or-replace-a-workspaces-web-portal-saml-oidc-identi",
    "gcp-appengine-versions-create-actas",
    "gcp-appintegration-runas-sa-actas",
    "gcp-artifactregistry-gcrio-namespace-squat",
    "gcp-privatecatalog-product-version-poison",
)
_HISTORY = json.loads((Path(__file__).resolve().parents[1] /
                       "peaso/privesc/catalog_versions/legacy-0b3633-delta.json").read_text())
# Behavioral fixtures here describe the archived v4 catalog, including claims
# intentionally removed from the strict active escalation catalog.
_ARCHIVED, _ = vc._verified_prior()
_CATALOG = tuple({key: value for key, value in entry.items() if key != "_file"}
                 for entry in _ARCHIVED.values())
_BY_ID = {entry["id"]: entry for entry in _CATALOG}
ADDED_IDS = tuple(entry["id"] for entry in _CATALOG
                  if entry["id"] not in set(_HISTORY["legacy_ids"]) and entry["id"] not in SCOPED_IDS and entry["target"].get("outcome") != "bounded_authority")


def _entry(ident):
    return copy.deepcopy(_BY_ID[ident])


def _col(kind, scope, items, status="collected"):
    return {"type": kind, "scope": scope, "service": kind, "status": status,
            "items": items, "error": None}


def _required_actions(value):
    if isinstance(value, dict):
        actions = [value["action"]] if isinstance(value.get("action"), str) else []
        return actions + [action for child in value.values() for action in _required_actions(child)]
    if isinstance(value, list):
        return [action for child in value for action in _required_actions(child)]
    return []


def _snapshot(entry):
    if entry["provider"] == "aws":
        scope = "111111111111/us-east-1"
        source = "arn:aws:iam::111111111111:user/alice"
        target = "arn:aws:iam::111111111111:role/victim"
        actions = sorted(set(_required_actions(entry.get("requires", {}))))
        user = {"UserName": "alice", "Arn": source, "GroupList": [], "AttachedManagedPolicies": [],
                "UserPolicyList": [{"PolicyName": "test", "PolicyDocument": {"Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": actions or ["*"], "Resource": "*"}]}}]}
        role = {"RoleName": "victim", "Arn": target, "Path": "/", "RolePolicyList": [],
                "AttachedManagedPolicies": [], "InstanceProfileList": [],
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}
        fact = {"TechniqueId": entry["id"], "SourceArn": source,
                "TargetKind": entry["target"]["kind"], "TargetId": target,
                "TargetAccount": "111111111111", "Status": "verified",
                "VerifiedPreconditions": True}
        collections = [_col("iam_user", scope, [user]), _col("iam_role", scope, [role]),
                       _col("iam_group", scope, []), _col("iam_policy", scope, []),
                       _col("scp_policy", scope, [], "empty"),
                       _col("aws_privesc_challenge_evidence", scope, [fact])]
    else:
        scope = "projects/p1"
        source = "user:alice@corp.com"
        target = "serviceAccount:victim@p1.iam.gserviceaccount.com"
        role_name = "projects/p1/roles/tester"
        actions = sorted(set(_required_actions(entry.get("requires", {}))))
        fact = {"TechniqueId": entry["id"], "SourceId": source,
                "TargetKind": entry["target"]["kind"], "TargetId": target,
                "TargetScope": scope, "Status": "verified", "VerifiedPreconditions": True}
        collections = [_col("project", scope, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
                       _col("iam_policy", scope, [{"name": scope,
                                                   "bindings": [{"role": role_name, "members": [source]}]}]),
                       _col("iam_role", scope, [{"name": role_name, "includedPermissions": actions}]),
                       _col("service_account", scope, [{"email": "victim@p1.iam.gserviceaccount.com",
                                                          "projectId": "p1", "name": "projects/p1/serviceAccounts/victim@p1.iam.gserviceaccount.com"}]),
                       _col("iam_deny_policy", scope, [], "empty"),
                       _col("gcp_privesc_challenge_evidence", scope, [fact])]
    return {"schema_version": 1, "provider": entry["provider"], "scopes": [scope],
            "collections": collections, "metadata": {}}


@pytest.mark.parametrize("ident", HELD)
@pytest.mark.parametrize("include_unknown", (True, False))
def test_unreviewed_legacy_claim_has_no_reach_even_with_synthetic_fact(ident, include_unknown):
    entry = _entry(ident)
    result = privesc.analyze(_snapshot(entry), entries=[entry], include_unknown=include_unknown)
    assert not any(ident in edge.get("techniques", ()) for edge in result["graph"]["edges"])
    assert not any(f["status"] == "FAIL" for f in result["findings"])
    assert any(c.get("status") == "unresolved" and ident in c.get("reason", "")
               for c in result["coverage"])


def test_additive_catalog_preserves_legacy_and_binds_new_entries():
    root = Path(__file__).resolve().parents[1]
    history = json.loads((root / "peaso/privesc/catalog_versions/legacy-0b3633-delta.json").read_text())
    current = current_binding()
    old = {"schema": BINDING_SCHEMA, "manifest_sha256": LEGACY_MANIFEST,
           "source_revision": LEGACY_REVISION, "tenant_id": "tenant-a"}
    new = dict(current, tenant_id="tenant-a")
    legacy, legacy_status = lookup_entries(history["legacy_ids"], old, tenant_id="tenant-a")
    catalog_ids = list(_ARCHIVED)
    active_ids = {entry["id"] for entry in privesc.load_catalog()["entries"]}
    present, present_status = lookup_entries(active_ids, new, tenant_id="tenant-a")
    assert legacy_status == "exact_legacy"
    assert present_status == "exact_strict_privesc"
    bulk_ids = set(json.loads((root / 'peaso/privesc/bulk_principal_tranche.json').read_text()))
    assert len(bulk_ids) == 98
    assert len(legacy) == 1004 and set(present) == active_ids
    # The loader adds a runtime _file pointer. Historical delta entries are
    # stored without that pointer; all authored semantics must match.
    authored = lambda entry: {key: value for key, value in entry.items() if not key.startswith("_")}
    assert all(authored(legacy[ident]) == authored(_ARCHIVED[ident])
               for ident in legacy if ident not in history["old_entries"])
    added = set(_ARCHIVED) - set(legacy)
    assert len(added) == 122 + len(bulk_ids) + len(SCOPED_IDS) + len(DISCLOSURES)
    assert bulk_ids <= added
    from peaso.privesc.versioned_catalog import BOUNDED_MANIFEST, BOUNDED_TREE
    bulk_binding = dict(new, manifest_sha256=BOUNDED_MANIFEST, effective_tree_sha256=BOUNDED_TREE)
    before_scoped, bulk_status = lookup_entries(catalog_ids, bulk_binding, tenant_id="tenant-a")
    assert bulk_status == "exact_bounded_v5" and len(before_scoped) == 1224
    assert not SCOPED_IDS.intersection(before_scoped)
    assert all(authored(before_scoped[ident]) == authored(_ARCHIVED[ident]) for ident in before_scoped)
    from peaso.privesc.versioned_catalog import PRIOR_BOUNDED_MANIFEST, PRIOR_BOUNDED_TREE
    prior_binding = dict(new, manifest_sha256=PRIOR_BOUNDED_MANIFEST, effective_tree_sha256=PRIOR_BOUNDED_TREE)
    prior, prior_status = lookup_entries(catalog_ids, prior_binding, tenant_id='tenant-a')
    assert prior_status == 'exact_bounded_v5' and len(prior) == 1126
    assert all(authored(prior[ident]) == authored(_ARCHIVED[ident]) for ident in prior)
    historical_binding = dict(new, manifest_sha256=V4_MANIFEST, effective_tree_sha256=V4_EFFECTIVE_TREE, source_revision=V4_REVISION)
    historical, status = lookup_entries(catalog_ids, historical_binding, tenant_id="tenant-a")
    assert status == "exact_additive_v4" and len(historical) == 1052
    assert all(authored(historical[ident]) == authored(_ARCHIVED[ident]) for ident in historical)
    assert all(_ARCHIVED[ident]["confidence"] == "conditional" for ident in added)


def test_catalog_binding_rejects_wrong_tenant_or_manifest_and_scopes_card_edges():
    history = json.loads((Path(__file__).resolve().parents[1] /
                          "peaso/privesc/catalog_versions/legacy-0b3633-delta.json").read_text())
    ident = history["legacy_ids"][0]
    binding = dict(current_binding(), tenant_id="tenant-a")
    for wrong, tenant, reason in ((binding, "tenant-b", "tenant_binding_mismatch"),
                                  (dict(binding, manifest_sha256="wrong"), "tenant-a", "unknown_catalog_manifest"),
                                  ({}, "tenant-a", "invalid_catalog_binding")):
        entries, status = lookup_entries([ident], wrong, tenant_id=tenant)
        assert entries == {} and status == reason
        detail = privesc_technique_details([ident], catalog_binding=wrong, tenant_id=tenant)[ident]
        assert detail["unknown"] is True and detail["catalog_lookup_status"] == reason
    card = {"member_of_aggregates": ["aggregate-a"],
            "outgoing": [{"source": "principal-a", "techniques": ["own-out"]},
                         {"source": "principal-b", "techniques": ["foreign-out"]}],
            "incoming": [{"target": "principal-a", "techniques": ["own-in"]},
                         {"target": "principal-b", "techniques": ["foreign-in"]},
                         {"target": "aggregate-a", "via_aggregate": "aggregate-a", "techniques": ["own-aggregate"]},
                         {"target": "aggregate-a", "via_aggregate": "aggregate-b", "techniques": ["wrong-aggregate"]}]}
    assert card_technique_ids(card, "principal-a") == ["own-aggregate", "own-in", "own-out"]


@pytest.mark.parametrize("ident", ADDED_IDS)
def test_new_principal_rule_never_claims_definite_reach_without_exact_fact(ident):
    entry = _entry(ident)
    assert validate_entry(entry)[0] == []
    assert entry["confidence"] == "conditional"
    assert entry["target"]["kind"] in {
        "gcp_service_account", "azure_service_principal", "azure_managed_identity",
        "aws_role", "gcp_workspace_user", "k8s_service_account", "azure_user",
        "aws_account_admin", "aws_user",
    }
    if entry["provider"] == "azure":
        snap = az()
    else:
        snap = _snapshot(entry)
        snap["collections"] = [c for c in snap["collections"]
                               if not c["type"].endswith("_privesc_challenge_evidence")]
    result = privesc.analyze(snap, entries=[entry])
    assert not any(f["check_id"] == entry["id"] and f["status"] == "FAIL"
                   for f in result["findings"])
    assert not any(edge["confidence"] in ("derived", "confirmed")
                   and entry["id"] in edge.get("techniques", ()) for edge in result["graph"]["edges"])


def test_aws_cdk_fact_binds_exact_user_and_role():
    entry = _entry("aws-pa-persist-s01-30")
    source = "arn:aws:iam::111111111111:user/alice"
    target = "arn:aws:iam::111111111111:role/victim"
    snap = _snapshot(entry)
    user = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"] = [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "cloudformation:UpdateStack", "Resource": "*"}]}}]
    fact = next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")["items"][0]
    fact.update({"TechniqueId": entry["id"], "SourceArn": source, "TargetKind": "aws_role", "TargetId": target})
    assert reached(privesc.analyze(snap, entries=[entry]), source, entry["id"]) == {target: "conditional"}
    for change in ({"SourceArn": source + "-other"}, {"TargetId": target + "-other"},
                   {"VerifiedPreconditions": False}, {"Status": "disproven"}):
        next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")["items"] = [
            {**fact, **change}]
        assert target not in reached(privesc.analyze(snap, entries=[entry]), source, entry["id"])


def test_gcp_privatecatalog_fact_binds_exact_source_and_service_account():
    entry = _entry("gcp-privatecatalog-terraform-version-poison")
    source = "user:alice@corp.com"
    target = "serviceAccount:victim@p1.iam.gserviceaccount.com"
    snap = _snapshot(entry)
    role = "projects/p1/roles/tester"
    next(c for c in snap["collections"] if c["type"] == "iam_policy")["items"][0]["bindings"] = [
        {"role": role, "members": [source]}]
    next(c for c in snap["collections"] if c["type"] == "iam_role")["items"] = [
        {"name": role, "includedPermissions": ["cloudprivatecatalogproducer.products.update"]}]
    fact = next(c for c in snap["collections"] if c["type"] == "gcp_privesc_challenge_evidence")["items"][0]
    fact.update({"TechniqueId": entry["id"], "SourceId": source, "TargetKind": "gcp_service_account",
                 "TargetId": target})
    assert reached(privesc.analyze(snap, entries=[entry]), source, entry["id"]) == {target: "conditional"}
    for change in ({"SourceId": "user:bob@corp.com"}, {"TargetId": target + "-other"},
                   {"VerifiedPreconditions": False}, {"Status": "disproven"}):
        next(c for c in snap["collections"] if c["type"] == "gcp_privesc_challenge_evidence")["items"] = [
            {**fact, **change}]
        assert target not in reached(privesc.analyze(snap, entries=[entry]), source, entry["id"])


def test_azure_vm_fact_binds_exact_source_and_managed_identity():
    entry = _entry("azure-vm-verified-ssrf-imds")
    snap, source = azure_challenge_case(entry)
    got = reached(privesc.analyze(snap, entries=[entry]), source, entry["id"])
    assert len(got) == 1 and set(got.values()) == {"conditional"}
    for variant in ("wrong_source", "disproven", "unverified", "empty"):
        snap, source = azure_challenge_case(entry, facts=variant)
        got = reached(privesc.analyze(snap, entries=[entry]), source, entry["id"])
        assert all(confidence == "unknown" for confidence in got.values())

