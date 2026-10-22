"""Cloud Deploy pipeline policies are tied to the exact listed pipeline."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
PIPELINE = PROJECT + "/locations/us-central1/deliveryPipelines/p1"


def collect(monkeypatch, *, denied=False, wrong_name=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def request(self, method, url, **kwargs):
            if url.endswith("/v1/projects/p1/locations"):
                return {"locations": [{"name": PROJECT + "/locations/us-central1"}]}, "locations"
            if url.endswith("/deliveryPipelines"):
                return {"deliveryPipelines": [{"name": PIPELINE + "/wrong" if wrong_name else PIPELINE,
                    "serialPipeline": {"stages": []}}]}, "pipelines"
            if url.endswith("/deliveryPipelines/p1:getIamPolicy"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": []}, "policy"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["clouddeploy_delivery_pipeline"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    kind, scope, service, factory = next(job for job in collector.scope_jobs(PROJECT)
                                          if job[0] == "clouddeploy_delivery_pipeline")
    return collector.envelope(kind, scope, service, factory)


def test_pipeline_policy_is_collected_for_exact_name(monkeypatch):
    row = collect(monkeypatch)
    pipeline, = row["items"]
    assert pipeline["name"] == PIPELINE
    assert pipeline["iamPolicy"] == {"bindings": []}
    assert pipeline["_coverage"]["iamPolicy"]["status"] == "collected"


def test_denied_pipeline_policy_is_recorded(monkeypatch):
    row = collect(monkeypatch, denied=True)
    pipeline, = row["items"]
    assert pipeline["_coverage"]["iamPolicy"]["status"] == "denied"


def test_wrong_pipeline_name_rejects_inventory(monkeypatch):
    row = collect(monkeypatch, wrong_name=True)
    assert row["status"] == "malformed"
