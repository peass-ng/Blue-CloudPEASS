"""Scheduled-query config reads keep only exact metadata needed for a path join."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
CONFIG = PROJECT + "/locations/US/transferConfigs/one"


def collect(monkeypatch, *, denied=False, wrong_name=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def request(self, method, url, **kwargs):
            if url.endswith("/datasets"):
                return {"datasets": [{"id": "p1:private", "datasetReference":
                    {"projectId": "p1", "datasetId": "private"}}]}, "datasets"
            if url.endswith("/datasets/private"):
                return {"id": "p1:private", "datasetReference":
                    {"projectId": "p1", "datasetId": "private"}, "location": "US", "access": []}, "dataset"
            if url.endswith("/transferConfigs"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"transferConfigs": [{"name": CONFIG.replace("/locations/US/", "/locations/EU/")
                    if wrong_name else CONFIG,
                    "dataSourceId": "scheduled_query", "destinationDatasetId": "private",
                    "params": {"query": "SELECT private_column FROM protected"},
                    "disabled": False}]}, "transfer-configs"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigquery_transfer_config"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    collector._data_project_binding = lambda scope: {"project_id": "p1", "project_number": "111"}
    return next(row for row in collector.collect()["collections"]
                if row["type"] == "bigquery_transfer_config")


def test_exact_transfer_config_omits_sql(monkeypatch):
    row = collect(monkeypatch)
    assert row["status"] == "collected"
    config, = row["items"]
    assert config["name"] == CONFIG
    assert config["destinationDatasetId"] == "private"
    assert "params" not in config
    assert "SELECT" not in str(config)


def test_model_joins_existing_config_to_destination(monkeypatch):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.privesc.effective_permissions.gcp import GcpModel
    from peaso.collectors import gcp
    class Transport:
        def request(self, method, url, **kwargs):
            if url.endswith("/datasets"):
                return {"datasets": [{"id": "p1:private", "datasetReference":
                    {"projectId": "p1", "datasetId": "private"}}]}, "datasets"
            if url.endswith("/datasets/private"):
                return {"id": "p1:private", "datasetReference":
                    {"projectId": "p1", "datasetId": "private"}, "location": "US", "access": []}, "dataset"
            if url.endswith("/transferConfigs"):
                return {"transferConfigs": [{"name": CONFIG, "dataSourceId": "scheduled_query",
                    "destinationDatasetId": "private", "disabled": False}]}, "configs"
            raise AssertionError(url)
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigquery_transfer_config"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    collector._data_project_binding = lambda scope: {"project_id": "p1", "project_number": "111"}
    snapshot = collector.collect()
    model = GcpModel(snapshot)
    assert CONFIG in model.transfer_configs
    assert model.transfer_configs[CONFIG]["dataset"] == PROJECT + "/datasets/private"


def test_denied_or_mismatched_config_never_becomes_a_bound_record(monkeypatch):
    assert collect(monkeypatch, denied=True)["status"] == "denied"
    assert collect(monkeypatch, wrong_name=True)["status"] == "malformed"
