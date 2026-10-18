"""Normal GCP planner, native transport/collector and registered sink evaluator."""
import copy
import pytest
from peaso.collectors import gcp
from peaso.engine import plan_collection, collect_snapshot, evaluate_snapshot
from peaso.snapshot import seal

CID = "gcp.claude.logging.project_sink_all_entries"
SCOPE = "projects/p-one"
ORG = "organizations/34"
FOLDER = "folders/12"
GOOD = {"name": "all", "destination": "storage.googleapis.com/archive", "includeChildren": True,
        "filter": "", "disabled": False, "exclusions": []}


class API:
    def __init__(self, *, local=None, folder=None, org=None, denied=None, partial=None, ancestry=None):
        self.local, self.folder, self.org = local or [], folder or [], org or []
        self.denied, self.partial = denied, partial
        self.ancestry = ancestry or [{"resourceId": {"type": "project", "id": "p-one"}},
                                     {"resourceId": {"type": "folder", "id": "12"}},
                                     {"resourceId": {"type": "organization", "id": "34"}}]
        self.requests, self.evidence = [], []
    def request(self, method, url, **kwargs):
        scope = kwargs.get("scope")
        request_id = f"request-{len(self.requests)+1}"
        self.requests.append((method, url, scope))
        if scope == self.denied and url.endswith("/sinks"):
            error = gcp.ReadError("denied", "api_error", http_status=403)
            error.request_id = request_id
            self.evidence.append({"id": request_id, "method": method, "url": url, "scope": scope,
                                  "status": "denied", "error": error.error})
            raise error
        if url.endswith(":getAncestry"):
            assert method == "POST"
            data = {"ancestor": self.ancestry}
        elif url == f"https://cloudresourcemanager.googleapis.com/v3/{SCOPE}":
            data = {"name": "projects/111", "projectId": "p-one"}
        elif url == f"https://compute.googleapis.com/compute/v1/{SCOPE}":
            data = {}
        elif url.endswith("/sinks"):
            assert method == "GET"
            rows = self.local if scope == SCOPE else self.folder if scope == FOLDER else self.org
            data = {"sinks": rows}
            if scope == self.partial:
                data["nextPageToken"] = "another-page"
        else:
            raise AssertionError((method, url, scope))
        self.evidence.append({"id": request_id, "method": method, "url": url, "scope": scope,
                              "status": "collected"})
        return copy.deepcopy(data), request_id
    def close(self):
        pass


def observed(monkeypatch, *, local=None, folder=None, org=None, denied=None, partial=None,
             ancestry=None, mutate=None):
    api = API(local=local, folder=folder, org=org, denied=denied, partial=partial, ancestry=ancestry)
    monkeypatch.setattr(gcp, "Credentials", lambda *a, **kw: None)
    monkeypatch.setattr(gcp, "Transport", lambda *a, **kw: api)
    options = {"include_inherited": True, "metrics_scopes": False, "concurrency": 1}
    if partial:
        options["max_pages"] = 1
    request = {"connector": {"provider": "gcp", "scopes": [SCOPE], "options": options}, "checks": [CID]}
    assert plan_collection(request) == ["log_sink", "project"]
    snapshot = collect_snapshot(request)
    project = next(c for c in snapshot["collections"] if c["type"] == "project" and c["scope"] == SCOPE)["items"][0]
    if mutate:
        mutate(project, snapshot)
        snapshot = seal(snapshot)
    findings = [f for f in evaluate_snapshot(snapshot, checks=[CID])["findings"] if f["check_id"] == CID]
    assert len(findings) == 1
    return project, findings[0], api


def test_proven_ancestor_aggregated_route_passes(monkeypatch):
    project, finding, api = observed(monkeypatch, org=[GOOD])
    assert finding["status"] == "PASS"
    assert finding["evidence"]["source"] == "ancestor aggregated sink"
    assert project["_coverage"]["_inherited_sinks"]["ancestors"] == [FOLDER, ORG]
    assert {scope for method, url, scope in api.requests if url.endswith("/sinks")} == {SCOPE, FOLDER, ORG}


def test_same_project_route_passes_with_complete_ancestor_chain(monkeypatch):
    _, finding, _ = observed(monkeypatch, local=[{"name": "local", "destination": "storage.googleapis.com/archive"}])
    assert finding["status"] == "PASS" and finding["evidence"]["source"] == "project"


def test_local_route_with_unread_ancestor_is_unknown(monkeypatch):
    _, finding, _ = observed(monkeypatch, local=[{"name": "local", "destination": "storage.googleapis.com/archive"}], denied=ORG)
    assert finding["status"] == "UNKNOWN"


def test_intercepting_ancestor_can_block_local_all_entry_route(monkeypatch):
    partial = {**GOOD, "destination": "logging.googleapis.com/projects/central",
               "filter": "severity>=ERROR", "interceptChildren": True}
    _, finding, _ = observed(monkeypatch, local=[{"name": "local", "destination": "storage.googleapis.com/archive"}], org=[partial])
    assert finding["status"] == "UNKNOWN"


@pytest.mark.parametrize("org", [[], [{**GOOD, "includeChildren": False}], [{**GOOD, "disabled": True}],
                                 [{**GOOD, "filter": "severity>=ERROR"}],
                                 [{**GOOD, "exclusions": [{"name": "drop", "filter": "severity<WARNING"}]}]])
def test_complete_absence_or_ineligible_ancestor_fails(monkeypatch, org):
    _, finding, _ = observed(monkeypatch, org=org)
    assert finding["status"] == "FAIL"


def test_complete_project_only_ancestry_absence_fails(monkeypatch):
    ancestry = [{"resourceId": {"type": "project", "id": "p-one"}}]
    project, finding, _ = observed(monkeypatch, ancestry=ancestry)
    assert project["_coverage"]["_inherited_sinks"]["ancestors"] == []
    assert finding["status"] == "FAIL"


def test_foreign_local_sink_identity_is_unknown(monkeypatch):
    _, finding, _ = observed(monkeypatch, local=[{"name": "projects/other/sinks/foreign",
        "destination": "storage.googleapis.com/archive"}])
    assert finding["status"] == "UNKNOWN"


@pytest.mark.parametrize("scope", [FOLDER, ORG])
def test_denied_ancestor_stays_unknown(monkeypatch, scope):
    project, finding, _ = observed(monkeypatch, org=[GOOD], denied=scope)
    assert "_inherited_sinks" not in project
    assert finding["status"] == "UNKNOWN"


def test_partial_ancestor_page_stays_unknown(monkeypatch):
    project, finding, _ = observed(monkeypatch, org=[GOOD], partial=ORG)
    assert "_inherited_sinks" not in project
    assert finding["status"] == "UNKNOWN"


def test_foreign_or_malformed_sink_is_unknown(monkeypatch):
    for sink in ({**GOOD, "name": "folders/999/sinks/foreign"}, {**GOOD, "includeChildren": None},
                 {**GOOD, "exclusions": None}):
        _, finding, _ = observed(monkeypatch, org=[sink])
        assert finding["status"] == "UNKNOWN"


def test_coverage_provenance_and_ancestry_tampering_unknown(monkeypatch):
    mutations = [
        lambda project, snapshot: project["_coverage"]["_inherited_sinks"].update(ancestors=[ORG]),
        lambda project, snapshot: project["_coverage"]["_inherited_sinks"].update(source_requests=["foreign-request"]),
        lambda project, snapshot: project["_inherited_sinks"][0].update(ancestor=FOLDER),
        lambda project, snapshot: project["_coverage"]["_inherited_sinks"].update(status="denied"),
        lambda project, snapshot: project["_inherited_sinks"][0].setdefault("_coverage", {}).update(includeChildren={"status": "denied"}),
    ]
    for mutate in mutations:
        _, finding, _ = observed(monkeypatch, org=[GOOD], mutate=mutate)
        assert finding["status"] == "UNKNOWN"


def test_foreign_project_ancestry_root_unknown(monkeypatch):
    ancestry = [{"resourceId": {"type": "project", "id": "other"}},
                {"resourceId": {"type": "organization", "id": "34"}}]
    _, finding, _ = observed(monkeypatch, org=[GOOD], ancestry=ancestry)
    assert finding["status"] == "UNKNOWN"


@pytest.mark.parametrize("local", [[], [{"name": "local", "destination": "storage.googleapis.com/archive"}]])
def test_higher_interceptor_blocks_descendant_aggregated_route(monkeypatch, local):
    partial = {**GOOD, "destination": "logging.googleapis.com/projects/central",
               "filter": "severity>=ERROR", "interceptChildren": True}
    _, finding, _ = observed(monkeypatch, local=local, folder=[GOOD], org=[partial])
    assert finding["status"] == "UNKNOWN"


def test_disabled_higher_interceptor_does_not_block_folder_route(monkeypatch):
    partial = {**GOOD, "destination": "logging.googleapis.com/projects/central",
               "filter": "severity>=ERROR", "interceptChildren": True, "disabled": True}
    _, finding, _ = observed(monkeypatch, folder=[GOOD], org=[partial])
    assert finding["status"] == "PASS"


def test_lower_interceptor_does_not_block_organization_route(monkeypatch):
    partial = {**GOOD, "destination": "logging.googleapis.com/projects/central",
               "filter": "severity>=ERROR", "interceptChildren": True}
    _, finding, _ = observed(monkeypatch, folder=[partial], org=[GOOD])
    assert finding["status"] == "PASS"


def test_same_level_interceptor_only_blocks_children(monkeypatch):
    partial = {**GOOD, "name": "partial", "destination": "logging.googleapis.com/projects/central",
               "filter": "severity>=ERROR", "interceptChildren": True}
    _, finding, _ = observed(monkeypatch, org=[partial, GOOD])
    assert finding["status"] == "PASS"


def test_duplicate_inherited_sink_identity_is_unknown(monkeypatch):
    def duplicate(project, snapshot):
        project["_inherited_sinks"].append(copy.deepcopy(project["_inherited_sinks"][0]))
    _, finding, _ = observed(monkeypatch, org=[GOOD], mutate=duplicate)
    assert finding["status"] == "UNKNOWN"
