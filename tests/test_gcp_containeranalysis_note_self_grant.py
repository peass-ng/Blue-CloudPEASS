"""A note policy write only grants a new permission on the exact note."""
import sys
import types
from pathlib import Path
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
SOURCE = "user:writer@example.com"
TECHNIQUE = "gcp-containeranalysis-notes-setiampolicy-note-self-grant"


def snapshot(note, *, write=True, prior=False, note_policy="collected"):
    def row(kind, data, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": data, "error": None}
    writer = PROJECT + "/roles/notePolicyWriter"
    permissions = ["containeranalysis.notes.setIamPolicy"] if write else []
    if prior:
        permissions.append("containeranalysis.notes.attachOccurrence")
    roles = [{"name": writer, "includedPermissions": permissions}]
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "created_at": "2026-10-21T10:05:00Z", "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", roles),
                row("iam_policy", [{"name": PROJECT,
                    "bindings": [{"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("containeranalysis_note", [{"name": note, "iamPolicy": {"bindings": []},
                    "_coverage": {"iamPolicy": {"status": note_policy}}}]),
            ]}


def targets(snap, *, prefix="possible-containeranalysis-note-self-grant"):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:" + prefix + ":")}


def test_global_and_regional_notes_have_exact_conditional_path():
    for note in (PROJECT + "/notes/n1", PROJECT + "/locations/us/notes/n1"):
        assert targets(snapshot(note)) == {
            "gcp_verified_authority:possible-containeranalysis-note-self-grant:" + note:
            "conditional"}


def test_absent_write_prior_access_and_foreign_note_do_not_claim_gain():
    note = PROJECT + "/notes/n1"
    assert not targets(snapshot(note, write=False))
    assert not targets(snapshot(note, prior=True))
    snap = snapshot(note)
    next(c for c in snap["collections"] if c["type"] == "containeranalysis_note")[
        "items"][0]["name"] = "projects/p2/notes/n1"
    assert not targets(snap)


def test_missing_policy_or_ancestor_inventory_keeps_path_unresolved():
    note = PROJECT + "/notes/n1"
    assert "conditional" not in targets(snapshot(note, note_policy="denied")).values()
    snap = snapshot(note)
    next(c for c in snap["collections"] if c["type"] == "iam_policy")["status"] = "denied"
    assert "conditional" not in targets(snap).values()
    snap = snapshot(note)
    next(c for c in snap["collections"] if c["type"] == "containeranalysis_note")[
        "items"][0]["iamPolicy"]["bindings"] = "malformed"
    assert "conditional" not in targets(snap).values()
    snap = snapshot(note)
    next(c for c in snap["collections"] if c["type"] == "iam_policy")[
        "items"][0]["bindings"].append(
            {"role": "roles/containeranalysis.notes.attacher", "members": [SOURCE]})
    assert not targets(snap)


def test_reviewed_mutation_requires_same_note_binding_and_ordered_evidence():
    note = PROJECT + "/locations/us/notes/n1"
    record = {"TechniqueId": TECHNIQUE, "SourceId": SOURCE, "TargetScope": PROJECT,
              "TargetResource": note, "GrantedResource": note,
              "AccessPermission": "containeranalysis.notes.setIamPolicy",
              "GrantedPrincipalId": SOURCE,
              "GrantedPermissions": ["containeranalysis.notes.attachOccurrence"],
              "PriorTestedPermission": "containeranalysis.notes.attachOccurrence",
              "AfterTestedPermission": "containeranalysis.notes.attachOccurrence",
              "PriorTestedResource": note, "AfterTestedResource": note,
              "AcceptedBindingMember": SOURCE,
              "AcceptedBindingRole": "roles/containeranalysis.notes.attacher",
              "BindingPresentAtSnapshot": True,
              "PriorAccessCheckedAt": "2026-10-21T10:00:00Z",
              "PolicyMutationObservedAt": "2026-10-21T10:01:00Z",
              "AfterAccessCheckedAt": "2026-10-21T10:02:00Z",
              "BindingCheckedAt": "2026-10-21T10:03:00Z",
              "EvidenceObservedAt": "2026-10-21T10:04:00Z",
              "PriorPermissionAbsent": True, "PolicyMutationAuthorized": True,
              "PolicyMutationAccepted": True, "AfterPermissionAllowed": True,
              "Status": "verified", "EvidenceRef": "reviewed-note-policy-1"}
    snap = snapshot(note)
    note_item = next(c for c in snap["collections"] if c["type"] == "containeranalysis_note")["items"][0]
    note_item["iamPolicy"]["bindings"] = [
        {"role": "roles/containeranalysis.notes.attacher", "members": [SOURCE]}]
    snap["collections"].append({"type": "gcp_resource_self_grant_evidence",
        "scope": PROJECT, "service": "reviewed", "status": "collected",
        "items": [record], "error": None})
    assert len(targets(snap, prefix="self-grant")) == 1
    for field, value in (("TargetResource", PROJECT + "/notes/other"),
                         ("GrantedResource", note + "/child"),
                         ("AfterTestedResource", PROJECT + "/notes/other"),
                         ("PolicyMutationObservedAt", "2026-10-21T09:59:00Z")):
        changed = deepcopy(snap)
        next(c for c in changed["collections"] if c["type"] ==
             "gcp_resource_self_grant_evidence")["items"][0][field] = value
        assert not targets(changed, prefix="self-grant"), field
    changed = deepcopy(snap)
    next(c for c in changed["collections"] if c["type"] ==
         "containeranalysis_note")["items"][0]["iamPolicy"]["bindings"] = []
    assert not targets(changed, prefix="self-grant")


def test_collector_reads_global_and_regional_notes_and_their_policies(monkeypatch):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    global_note = PROJECT + "/notes/global-note"
    regional_note = PROJECT + "/locations/us/notes/regional-note"

    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url.endswith("/locations"):
                return {"locations": [{"name": PROJECT + "/locations/us"}]}, "locations"
            if url.endswith("/notes"):
                name = regional_note if "/locations/us/notes" in url else global_note
                return {"notes": [{"name": name}]}, name
            if url.endswith(":getIamPolicy"):
                return {"bindings": []}, "policy"
            raise AssertionError(url)

    transport = Transport()
    connector = {"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["containeranalysis_note"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}
    collector = gcp.GCPCollector(connector, transport=transport)
    job, = [job for job in collector.scope_jobs(PROJECT) if job[0] == "containeranalysis_note"]
    result = collector.envelope(*job[:3], job[3])
    assert result["status"] == "collected"
    assert {item["name"] for item in result["items"]} == {global_note, regional_note}
    assert all(item["_coverage"]["iamPolicy"]["status"] == "collected"
               for item in result["items"])
    assert [(method, url) for method, url, _ in transport.calls] == [
        ("GET", "https://containeranalysis.googleapis.com/v1/" + PROJECT + "/notes"),
        ("POST", "https://containeranalysis.googleapis.com/v1/" + global_note + ":getIamPolicy"),
        ("GET", "https://artifactregistry.googleapis.com/v1/" + PROJECT + "/locations"),
        ("GET", "https://containeranalysis.googleapis.com/v1/" + PROJECT + "/locations/us/notes"),
        ("POST", "https://containeranalysis.googleapis.com/v1/" + regional_note + ":getIamPolicy")]


def test_collector_marks_unreadable_note_policy_or_location_list_incomplete(monkeypatch):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def __init__(self, location_denied):
            self.location_denied = location_denied

        def request(self, method, url, **kwargs):
            if url.endswith("/notes"):
                return {"notes": [{"name": PROJECT + "/notes/n1"}]}, "notes"
            if url.endswith(":getIamPolicy"):
                raise gcp.ReadError("denied", "permission_denied", http_status=403)
            if url.endswith("/locations"):
                if self.location_denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"locations": []}, "locations"
            raise AssertionError(url)

    connector = {"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["containeranalysis_note"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}
    for location_denied in (False, True):
        collector = gcp.GCPCollector(connector, transport=Transport(location_denied))
        job, = [job for job in collector.scope_jobs(PROJECT) if job[0] == "containeranalysis_note"]
        result = collector.envelope(*job[:3], job[3])
        assert result["items"][0]["_coverage"]["iamPolicy"]["status"] == "denied"
        assert result["status"] == ("partial" if location_denied else "collected")
