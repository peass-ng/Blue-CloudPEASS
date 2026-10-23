"""Config Delivery's documented region does not require location discovery."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace


def catalog():
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_gcp_collector")
    package.__path__ = [str(root)]
    gcp = ModuleType("isolated_gcp_collector.gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    names = ("isolated_gcp_collector", "isolated_gcp_collector.gcp",
             "isolated_gcp_collector.gcp_network_catalog")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        sys.modules[names[0]] = package
        sys.modules[names[1]] = gcp
        spec = importlib.util.spec_from_file_location(names[2], root / "gcp_network_catalog.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[names[2]] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name, prior in previous.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior


def test_config_delivery_uses_documented_region_without_locations_call():
    module = catalog()
    def unexpected(*args, **kwargs):
        raise AssertionError("location discovery was requested")
    collector = SimpleNamespace(options={}, pages=unexpected)
    assert list(module.locations(collector, "projects/demo-project1",
                                 "config_delivery_fleet_package")) == [(["us-central1"], None)]
    collector.options = {"regions": ["europe-west1"]}
    assert list(module.locations(collector, "projects/demo-project1",
                                 "config_delivery_fleet_package")) == [(["europe-west1"], None)]


def test_fleet_package_list_and_detail_keep_target_selector():
    module = catalog()
    plan = module.PRIVATE_SERVICES["config_delivery_fleet_package"]
    name = "projects/demo-project1/locations/us-central1/fleetPackages/existing"
    calls = []
    def pages(url, scope, **kwargs):
        calls.append((url, kwargs))
        if url.endswith("/fleetPackages"):
            assert kwargs["params"]["fields"] == plan["fields"]
            yield [{"name": name}], "list-receipt"
        else:
            assert url.endswith("/" + name)
            assert kwargs["params"]["fields"] == plan["get_fields"]
            yield [{"name": name, "state": "ACTIVE", "target": {"fleet": {
                "project": "projects/demo-project1",
                "selector": {"matchLabels": {"env": "prod"}}}}}], "detail-receipt"
    collector = SimpleNamespace(pages=pages)
    pages_read = list(module.inventory_pages(
        collector, "projects/demo-project1", plan,
        "projects/demo-project1/locations/us-central1", "https://configdelivery.googleapis.com/v1"))
    rows = [row for page, _ in pages_read for row in page]
    assert len(calls) == 2
    assert rows[0]["target"]["fleet"]["selector"]["matchLabels"] == {"env": "prod"}


def test_hypercompute_cluster_uses_region_and_keeps_exact_login_vm_names():
    module = catalog()
    plan = module.PRIVATE_SERVICES["hypercompute_cluster"]
    name = "projects/demo-project1/locations/us-central1/clusters/existing"
    vm = "projects/demo-project1/zones/us-central1-a/instances/login1"
    collector = SimpleNamespace(options={"regions": ["us-central1"]})
    assert list(module.locations(collector, "projects/demo-project1", "hypercompute_cluster")) == [
        (["us-central1"], None)]
    calls = []
    def pages(url, scope, **kwargs):
        calls.append((url, kwargs))
        assert "loginNodes(count,zone,instances(instance))" in kwargs["params"]["fields"]
        if url.endswith("/clusters"):
            yield [{"name": name}], "list-receipt"
        else:
            assert url.endswith("/" + name)
            yield [{"name": name, "reconciling": False, "orchestrator": {"slurm": {
                "loginNodes": {"count": "1", "zone": "us-central1-a",
                               "instances": [{"instance": vm}]}}}}], "detail-receipt"
    collector.pages = pages
    result = list(module.inventory_pages(
        collector, "projects/demo-project1", plan,
        "projects/demo-project1/locations/us-central1",
        "https://hypercomputecluster.googleapis.com/v1"))
    rows = [row for page, _ in result for row in page]
    assert len(calls) == 2
    assert rows[0]["orchestrator"]["slurm"]["loginNodes"]["instances"] == [
        {"instance": vm}]
