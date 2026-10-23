"""Collect exact zonal OS policy assignment names for VM zones."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType

import pytest


PROJECT = "projects/p1"
ZONE = PROJECT + "/locations/us-central1-a"


@pytest.fixture
def modules(monkeypatch):
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_osconfig_assignments")
    package.__path__ = [str(root)]
    gcp = ModuleType(package.__name__ + ".gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    wave = ModuleType(package.__name__ + ".gcp_compliance_wave")
    wave.complete_parent = lambda *_: {"items": [{"zone": "us-central1-a"}]}
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, gcp.__name__, gcp)
    monkeypatch.setitem(sys.modules, wave.__name__, wave)
    name = package.__name__ + ".gcp_osconfig_guest_policy"
    spec = importlib.util.spec_from_file_location(name, root / "gcp_osconfig_guest_policy.py")
    result = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, result)
    spec.loader.exec_module(result)
    return result, wave, gcp.ReadError


class Collector:
    needed = {"osconfig_os_policy_assignment"}

    def __init__(self, names):
        self.names = names
        self.urls = []

    def _data_project_binding(self, scope, *, require_alias=False):
        assert scope == PROJECT and require_alias
        return {"project_id": "p1", "project_number": "1234"}

    def pages(self, url, scope, *, key=None, params=None, transform=None):
        assert scope == PROJECT and key == "osPolicyAssignments"
        assert params == {"fields": "osPolicyAssignments(name),nextPageToken"}
        self.urls.append(url)
        yield [transform({"name": name}) for name in self.names], "page"


def test_lists_only_zones_with_recorded_vms_and_normalizes_project_alias(modules):
    collector_module, wave, _ = modules
    wave.complete_parent = lambda *_: {
        "items": [{"zone": "https://www.googleapis.com/compute/v1/projects/p1/zones/us-central1-a"}]}
    collector = Collector(["projects/1234/locations/us-central1-a/osPolicyAssignments/production"])
    jobs = collector_module.scope_jobs(collector, PROJECT)
    assert [job[0] for job in jobs] == ["osconfig_os_policy_assignment"]
    assert list(jobs[0][3]())[0][0] == [{"name": ZONE + "/osPolicyAssignments/production"}]
    assert collector.urls == ["https://osconfig.googleapis.com/v1/" + ZONE + "/osPolicyAssignments"]


def test_rejects_duplicate_or_foreign_assignment(modules):
    collector_module, _, read_error = modules
    name = ZONE + "/osPolicyAssignments/production"
    for names in ([name, name], ["projects/other/locations/us-central1-a/osPolicyAssignments/production"]):
        fetch = collector_module.scope_jobs(Collector(names), PROJECT)[0][3]
        with pytest.raises(read_error):
            list(fetch())
