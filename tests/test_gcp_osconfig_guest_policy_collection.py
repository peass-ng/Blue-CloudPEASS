"""Legacy guest policies and feature settings use their native read APIs."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType

import pytest


PROJECT = "projects/p1"
POLICY = PROJECT + "/guestPolicies/legacy"
SETTINGS = PROJECT + "/locations/global/projectFeatureSettings"


def module():
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_osconfig_collector")
    package.__path__ = [str(root)]
    gcp = ModuleType("isolated_osconfig_collector.gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    names = ("isolated_osconfig_collector", "isolated_osconfig_collector.gcp",
             "isolated_osconfig_collector.gcp_osconfig_guest_policy")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        sys.modules[names[0]] = package
        sys.modules[names[1]] = gcp
        spec = importlib.util.spec_from_file_location(names[2], root / "gcp_osconfig_guest_policy.py")
        result = importlib.util.module_from_spec(spec)
        sys.modules[names[2]] = result
        spec.loader.exec_module(result)
        return result, gcp.ReadError
    finally:
        for name, prior in previous.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior


class Collector:
    needed = {"osconfig_guest_policy", "osconfig_project_feature_settings"}

    def __init__(self, names=None, settings_name=SETTINGS):
        self.names = names or [POLICY]
        self.settings_name = settings_name
        self.urls = []

    def _data_project_binding(self, scope, *, require_alias=False):
        assert scope == PROJECT and require_alias
        return {"project_id": "p1", "project_number": "1234"}

    def pages(self, url, scope, *, key=None, single=False, transform=None):
        self.urls.append(url)
        assert scope == PROJECT
        if key == "guestPolicies":
            yield [transform({"name": name, "recipes": [{"name": "app", "version": "1.0",
                            "desiredState": "UPDATED", "updateSteps": [{"scriptRun": {"script": "id"}}]}]})
                   for name in self.names], "guest-list"
        elif single:
            assert url.endswith(SETTINGS)
            yield [transform({"name": self.settings_name, "patchAndConfigFeatureSet": "OSCONFIG_C"})], "settings"
        else:
            raise AssertionError(url)


def test_reads_exact_policies_and_project_feature_setting():
    m, _ = module()
    collector = Collector()
    jobs = m.scope_jobs(collector, PROJECT)
    assert {job[0] for job in jobs} == collector.needed
    results = {kind: list(fetch()) for kind, _, _, fetch in jobs}
    assert results["osconfig_guest_policy"][0][0][0]["name"] == POLICY
    assert results["osconfig_project_feature_settings"][0][0][0]["patchAndConfigFeatureSet"] == "OSCONFIG_C"
    assert collector.urls == ["https://osconfig.googleapis.com/v1beta/" + PROJECT + "/guestPolicies",
                              "https://osconfig.googleapis.com/v1/" + SETTINGS]


def test_rejects_foreign_and_duplicate_policy_identities():
    m, error = module()
    for names in (["projects/other/guestPolicies/legacy"], [POLICY, POLICY]):
        fetch = m.scope_jobs(Collector(names), PROJECT)[0][3]
        with pytest.raises(error):
            list(fetch())


def test_verified_project_number_alias_is_canonicalized():
    m, _ = module()
    jobs = m.scope_jobs(Collector(["projects/1234/guestPolicies/legacy"],
                                  "projects/1234/locations/global/projectFeatureSettings"), PROJECT)
    assert list(jobs[0][3]())[0][0][0]["name"] == POLICY
    assert list(jobs[1][3]())[0][0][0]["name"] == SETTINGS
