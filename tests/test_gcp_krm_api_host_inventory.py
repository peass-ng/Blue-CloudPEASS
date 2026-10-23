"""Config Controller host collection binds IAM reads to listed host names."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace


def collection_pages(collector, scope):
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_krm_collector")
    package.__path__ = [str(root)]
    gcp = ModuleType("isolated_krm_collector.gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    names = ("isolated_krm_collector", "isolated_krm_collector.gcp",
             "isolated_krm_collector.gcp_krm_api_hosts")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        sys.modules[names[0]] = package
        sys.modules[names[1]] = gcp
        spec = importlib.util.spec_from_file_location(names[2], root / "gcp_krm_api_hosts.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[names[2]] = module
        spec.loader.exec_module(module)
        yield from module.collection_pages(collector, scope)
    finally:
        for name, prior in previous.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior


def test_listed_host_policy_uses_documented_get_method():
    scope = "projects/demo-project1"
    location = scope + "/locations/us-central1"
    host = location + "/krmApiHosts/controller1"
    calls = []
    def pages(url, requested_scope, **kwargs):
        assert requested_scope == scope
        if url.endswith("/locations"):
            assert kwargs["key"] == "locations"
            yield [{"name": location}], "locations-receipt"
        else:
            assert url == "https://krmapihosting.googleapis.com/v1/" + location + "/krmApiHosts"
            assert kwargs["key"] == "krmApiHosts"
            yield [{"name": host, "state": "RUNNING"}], "hosts-receipt"
    def hydrate(item, field, url, requested_scope, **kwargs):
        calls.append((item, field, url, requested_scope, kwargs))
        return {**item, "iamPolicy": {"bindings": []},
                "_coverage": {"iamPolicy": {"status": "collected"}}}
    collector = SimpleNamespace(pages=pages, hydrate=hydrate,
                                parallel=lambda fn, rows: [fn(row) for row in rows])
    rows = [item for page, _ in collection_pages(collector, scope) for item in page]
    assert [row["name"] for row in rows] == [host]
    assert calls == [({"name": host, "state": "RUNNING"}, "iamPolicy",
        "https://krmapihosting.googleapis.com/v1/" + host + ":getIamPolicy",
        scope, {"params": {"options.requestedPolicyVersion": 3}})]
