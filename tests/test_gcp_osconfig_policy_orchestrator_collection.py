"""Enumerate orchestrators at their actual project, folder, or organization parent."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType

import pytest


@pytest.fixture
def module(monkeypatch):
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_orchestrator_collector")
    package.__path__ = [str(root)]
    gcp = ModuleType(package.__name__ + ".gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, gcp.__name__, gcp)
    name = package.__name__ + ".gcp_osconfig_policy_orchestrator"
    spec = importlib.util.spec_from_file_location(name, root / "gcp_osconfig_policy_orchestrator.py")
    result = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, result)
    spec.loader.exec_module(result)
    return result, gcp.ReadError


class Collector:
    needed = {"osconfig_policy_orchestrator"}
    scopes = ["projects/p1"]

    def __init__(self, names=None):
        self.names = names or {}
        self.jobs = []

    def items(self, kind):
        rows = {"folder": [{"name": "folders/42"}],
                "organization": [{"name": "organizations/17"}],
                "project": [{"name": "projects/1234", "projectId": "p1",
                             "_ancestry": [{"resourceId": {"type": "folder", "id": "42"}},
                                           {"resourceId": {"type": "organization", "id": "17"}}]}]}
        return [(row["name"], row) for row in rows[kind]]

    def _data_project_binding(self, scope, *, require_alias=False):
        assert scope == "projects/p1" and require_alias
        return {"project_id": "p1", "project_number": "1234"}

    def pages(self, url, scope, *, key=None, transform=None):
        assert url == "https://osconfig.googleapis.com/v2/" + scope + "/locations/global/policyOrchestrators"
        assert key == "policyOrchestrators"
        yield [transform({"name": name}) for name in self.names.get(scope, [])], "page"

    def run_jobs(self, jobs):
        self.jobs = jobs


def test_collects_all_actual_parent_scopes_and_canonicalizes_project_number(module):
    orchestrators, _ = module
    collector = Collector({
        "projects/p1": ["projects/1234/locations/global/policyOrchestrators/one"],
        "folders/42": ["folders/42/locations/global/policyOrchestrators/two"],
        "organizations/17": ["organizations/17/locations/global/policyOrchestrators/three"]})
    orchestrators.collect(collector)
    assert {job[1] for job in collector.jobs} == {
        "projects/p1", "folders/42", "organizations/17"}
    assert {job[1]: list(job[3]())[0][0][0]["name"] for job in collector.jobs} == {
        "projects/p1": "projects/p1/locations/global/policyOrchestrators/one",
        "folders/42": "folders/42/locations/global/policyOrchestrators/two",
        "organizations/17": "organizations/17/locations/global/policyOrchestrators/three"}


def test_rejects_foreign_and_duplicate_names(module):
    orchestrators, read_error = module
    name = "projects/p1/locations/global/policyOrchestrators/one"
    for names in ([name, name], ["projects/other/locations/global/policyOrchestrators/one"]):
        fetch = orchestrators.scope_job(Collector({"projects/p1": names}), "projects/p1")[3]
        with pytest.raises(read_error):
            list(fetch())
