"""Taxonomy grants need an actual descendant tag with newly gained access."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_gcp_datacatalog_policy_tag_self_grant import (
    PROJECT, TAXONOMY, PARENT, TAG, SOURCE, snapshot as tag_snapshot)


TECHNIQUE = "gcp-datacatalog-taxonomies-setiampolicy-taxonomy-self-grant"
PREFIX = "gcp_verified_authority:possible-datacatalog-taxonomy-self-grant:"


def snapshot(*, write=True, reader_at=None, taxonomy_policy="collected",
             tag_policy="collected", parent_policy="collected"):
    snap = tag_snapshot(write=True, reader_at=reader_at,
                        taxonomy_policy=taxonomy_policy, tag_policy=tag_policy,
                        parent_policy=parent_policy)
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    role["includedPermissions"] = ["datacatalog.taxonomies.setIamPolicy"] if write else []
    return snap


def targets(snap, *, prefix=PREFIX):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items() if target.startswith(prefix)}


def test_taxonomy_write_reaches_each_tag_with_new_reader_access():
    assert targets(snapshot()) == {PREFIX + PARENT: "conditional", PREFIX + TAG: "conditional"}
    snap = snapshot(reader_at=TAG)
    assert targets(snap) == {PREFIX + PARENT: "conditional"}
    snap = snapshot()
    for collection in snap["collections"]:
        if collection["type"] not in ("datacatalog_taxonomy", "datacatalog_policy_tag"):
            continue
        for item in collection["items"]:
            item["name"] = item["name"].replace(PROJECT, "projects/123", 1)
            if item.get("parentPolicyTag"):
                item["parentPolicyTag"] = item["parentPolicyTag"].replace(PROJECT, "projects/123", 1)
    assert targets(snap) == {PREFIX + PARENT: "conditional", PREFIX + TAG: "conditional"}


def test_no_write_existing_ancestor_reader_or_no_tags_has_no_new_path():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(reader_at=TAXONOMY))
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "datacatalog_policy_tag")["items"] = []
    assert not targets(snap)


def test_inactive_taxonomy_or_missing_hierarchy_evidence_is_unresolved():
    for kwargs in ({"taxonomy_policy": "denied"}, {"tag_policy": "denied"},
                   {"parent_policy": "denied"}):
        assert targets(snapshot(**kwargs)).get(PREFIX + TAG) != "conditional"
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "datacatalog_taxonomy")[
        "items"][0]["activatedPolicyTypes"] = []
    assert "conditional" not in targets(snap).values()
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "datacatalog_policy_tag")[
        "items"][1]["parentPolicyTag"] = TAXONOMY + "/policyTags/missing"
    assert targets(snap).get(PREFIX + TAG) != "conditional"
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "datacatalog_taxonomy")[
        "items"][0]["iamPolicy"]["bindings"] = "malformed"
    assert "conditional" not in targets(snap).values()
    snap = snapshot()
    taxonomy_collection = next(c for c in snap["collections"]
                               if c["type"] == "datacatalog_taxonomy")
    taxonomy_collection["status"] = "denied"
    taxonomy_collection["items"] = []
    model = GcpModel(snap)
    entry, = [item for item in privesc.catalog()["entries"] if item["id"] == TECHNIQUE]
    model.current_entry = entry
    model.current_selector = entry["target"]["selector"]
    assert PROJECT in model.unknown_target_scopes("gcp_verified_authority")


def test_reviewed_taxonomy_mutation_requires_exact_tag_and_current_binding():
    record = {"TechniqueId": TECHNIQUE, "SourceId": SOURCE, "TargetScope": PROJECT,
              "TargetResource": TAXONOMY, "GrantedResource": TAG,
              "AccessPermission": "datacatalog.taxonomies.setIamPolicy",
              "GrantedPrincipalId": SOURCE,
              "GrantedPermissions": ["datacatalog.categories.fineGrainedGet"],
              "PriorTestedPermission": "datacatalog.categories.fineGrainedGet",
              "AfterTestedPermission": "datacatalog.categories.fineGrainedGet",
              "PriorTestedResource": TAG, "AfterTestedResource": TAG,
              "AcceptedBindingMember": SOURCE,
              "AcceptedBindingRole": "roles/datacatalog.categoryFineGrainedReader",
              "BindingPresentAtSnapshot": True,
              "PriorAccessCheckedAt": "2026-10-21T10:00:00Z",
              "PolicyMutationObservedAt": "2026-10-21T10:01:00Z",
              "AfterAccessCheckedAt": "2026-10-21T10:02:00Z",
              "BindingCheckedAt": "2026-10-21T10:03:00Z",
              "EvidenceObservedAt": "2026-10-21T10:04:00Z",
              "PriorPermissionAbsent": True, "PolicyMutationAuthorized": True,
              "PolicyMutationAccepted": True, "AfterPermissionAllowed": True,
              "Status": "verified", "EvidenceRef": "reviewed-taxonomy-policy-1"}
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "datacatalog_taxonomy")[
        "items"][0]["iamPolicy"]["bindings"] = [
            {"role": "roles/datacatalog.categoryFineGrainedReader", "members": [SOURCE]}]
    snap["collections"].append({"type": "gcp_resource_self_grant_evidence",
        "scope": PROJECT, "service": "reviewed", "status": "collected",
        "items": [record], "error": None})
    assert len(targets(snap, prefix="gcp_verified_authority:self-grant:")) == 1
    for field, value in (("TargetResource", PARENT), ("GrantedResource", TAXONOMY),
                         ("AfterTestedResource", PARENT),
                         ("AcceptedBindingRole", "roles/datacatalog.viewer")):
        changed = deepcopy(snap)
        next(c for c in changed["collections"] if c["type"] ==
             "gcp_resource_self_grant_evidence")["items"][0][field] = value
        assert not targets(changed, prefix="gcp_verified_authority:self-grant:"), field
    changed = deepcopy(snap)
    next(c for c in changed["collections"] if c["type"] == "datacatalog_taxonomy")[
        "items"][0]["iamPolicy"]["bindings"] = []
    assert not targets(changed, prefix="gcp_verified_authority:self-grant:")
