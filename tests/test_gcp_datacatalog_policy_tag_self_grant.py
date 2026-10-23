"""Policy-tag self-grants respect the tag, parent tags, and taxonomy."""
import sys
import types
from pathlib import Path
from copy import deepcopy
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
TAXONOMY = PROJECT + "/locations/us/taxonomies/t1"
PARENT = TAXONOMY + "/policyTags/parent"
TAG = TAXONOMY + "/policyTags/child"
SOURCE = "user:writer@example.com"
TECHNIQUE = "gcp-datacatalog-categories-setiampolicy-policy-tag-self-grant"


def snapshot(*, write=True, reader_at=None, tag_policy="collected",
             parent_policy="collected", taxonomy_policy="collected"):
    def row(kind, data, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": data, "error": None}
    writer = PROJECT + "/roles/tagPolicyWriter"
    def resource(name, coverage="collected", *, parent=None):
        bindings = ([{"role": "roles/datacatalog.categoryFineGrainedReader",
                      "members": [SOURCE]}] if reader_at == name else [])
        return {"name": name, "iamPolicy": {"bindings": bindings},
                "_coverage": {"iamPolicy": {"status": coverage}},
                **({"parentPolicyTag": parent} if parent else {})}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "created_at": "2026-10-21T10:05:00Z", "collections": [
                row("project", [{"projectId": "p1", "name": "projects/123"}]),
                row("iam_role", [{"name": writer, "includedPermissions":
                    ["datacatalog.categories.setIamPolicy"] if write else []}]),
                row("iam_policy", [{"name": PROJECT, "bindings": [
                    {"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("datacatalog_taxonomy", [{**resource(TAXONOMY, taxonomy_policy),
                    "activatedPolicyTypes": ["FINE_GRAINED_ACCESS_CONTROL"]}]),
                row("datacatalog_policy_tag", [resource(PARENT, parent_policy),
                    resource(TAG, tag_policy, parent=PARENT)]),
            ]}


def targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:possible-datacatalog-tag-self-grant:")}


def test_exact_tag_and_parent_tag_can_gain_new_reader_permission():
    result = targets(snapshot())
    assert result["gcp_verified_authority:possible-datacatalog-tag-self-grant:" + TAG] == "conditional"
    assert result["gcp_verified_authority:possible-datacatalog-tag-self-grant:" + PARENT] == "conditional"
    snap = snapshot()
    for collection in snap["collections"]:
        if collection["type"] not in ("datacatalog_taxonomy", "datacatalog_policy_tag"):
            continue
        for item in collection["items"]:
            item["name"] = item["name"].replace(PROJECT, "projects/123", 1)
            if item.get("parentPolicyTag"):
                item["parentPolicyTag"] = item["parentPolicyTag"].replace(PROJECT, "projects/123", 1)
    assert targets(snap)["gcp_verified_authority:possible-datacatalog-tag-self-grant:" + TAG] == "conditional"


def test_no_write_or_existing_ancestor_reader_is_not_new_access():
    assert not targets(snapshot(write=False))
    for parent in (TAG, PARENT, TAXONOMY):
        assert "gcp_verified_authority:possible-datacatalog-tag-self-grant:" + TAG not in targets(
            snapshot(reader_at=parent))


def test_missing_ancestor_policy_or_wrong_parent_is_unresolved():
    for kwargs in ({"tag_policy": "denied"}, {"parent_policy": "denied"},
                   {"taxonomy_policy": "denied"}):
        result = targets(snapshot(**kwargs))
        assert result.get("gcp_verified_authority:possible-datacatalog-tag-self-grant:" + TAG) != "conditional"
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "datacatalog_policy_tag")[
        "items"][1]["parentPolicyTag"] = TAXONOMY + "/policyTags/missing"
    assert targets(snap).get("gcp_verified_authority:possible-datacatalog-tag-self-grant:" + TAG) != "conditional"
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "datacatalog_taxonomy")[
        "items"][0]["activatedPolicyTypes"] = []
    assert targets(snap).get("gcp_verified_authority:possible-datacatalog-tag-self-grant:" + TAG) != "conditional"
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "datacatalog_policy_tag")[
        "items"][0]["iamPolicy"]["bindings"] = "malformed"
    assert targets(snap).get("gcp_verified_authority:possible-datacatalog-tag-self-grant:" + TAG) != "conditional"


def test_collector_lists_taxonomies_tags_and_exact_policies(monkeypatch):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp
    assert "datacatalog.googleapis.com" in gcp.HOSTS

    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url))
            if url.endswith("/taxonomies"):
                return {"taxonomies": [{"name": TAXONOMY,
                    "activatedPolicyTypes": ["FINE_GRAINED_ACCESS_CONTROL"]}]}, "taxonomies"
            if url.endswith("/policyTags"):
                return {"policyTags": [{"name": PARENT},
                    {"name": TAG, "parentPolicyTag": PARENT}]}, "tags"
            if url.endswith(":getIamPolicy"):
                return {"bindings": []}, "policy"
            raise AssertionError(url)

    transport = Transport()
    connector = {"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["datacatalog_policy_tag"], "datacatalog_locations": ["us"],
        "include_inherited": False, "metrics_scopes": False, "concurrency": 1}}
    collector = gcp.GCPCollector(connector, transport=transport)
    assert "datacatalog_taxonomy" in collector.needed
    jobs = {job[0]: job for job in collector.scope_jobs(PROJECT)
            if job[0] in ("datacatalog_taxonomy", "datacatalog_policy_tag")}
    taxonomy_row = collector.envelope(*jobs["datacatalog_taxonomy"][:3],
                                      jobs["datacatalog_taxonomy"][3])
    tag_row = collector.envelope(*jobs["datacatalog_policy_tag"][:3],
                                 jobs["datacatalog_policy_tag"][3])
    assert taxonomy_row["status"] == tag_row["status"] == "collected"
    assert [item["name"] for item in tag_row["items"]] == [PARENT, TAG]
    assert all(item["_coverage"]["iamPolicy"]["status"] == "collected"
               for item in [*taxonomy_row["items"], *tag_row["items"]])
    assert ("POST", "https://datacatalog.googleapis.com/v1/" + TAG + ":getIamPolicy") in transport.calls


def test_reviewed_mutation_requires_exact_tag_and_current_binding():
    record = {"TechniqueId": TECHNIQUE, "SourceId": SOURCE, "TargetScope": PROJECT,
              "TargetResource": TAG, "GrantedResource": TAG,
              "AccessPermission": "datacatalog.categories.setIamPolicy",
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
              "Status": "verified", "EvidenceRef": "reviewed-tag-policy-1"}
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "datacatalog_policy_tag")[
        "items"][1]["iamPolicy"]["bindings"] = [
            {"role": "roles/datacatalog.categoryFineGrainedReader", "members": [SOURCE]}]
    snap["collections"].append({"type": "gcp_resource_self_grant_evidence",
        "scope": PROJECT, "service": "reviewed", "status": "collected",
        "items": [record], "error": None})
    def reviewed(value):
        entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
        return [target for reach in Evaluator(GcpModel(value), [entry]).run()
                if reach.source.id == SOURCE for target in reach.targets
                if target.startswith("gcp_verified_authority:self-grant:")]
    assert len(reviewed(snap)) == 1
    for field, value in (("TargetResource", PARENT), ("GrantedResource", TAG + "/child"),
                         ("AfterTestedResource", PARENT),
                         ("PriorAccessCheckedAt", "2026-10-21T10:02:00Z")):
        changed = deepcopy(snap)
        next(c for c in changed["collections"] if c["type"] ==
             "gcp_resource_self_grant_evidence")["items"][0][field] = value
        assert not reviewed(changed), field
    changed = deepcopy(snap)
    next(c for c in changed["collections"] if c["type"] == "datacatalog_policy_tag")[
        "items"][1]["iamPolicy"]["bindings"] = []
    assert not reviewed(changed)
