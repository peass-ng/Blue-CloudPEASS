"""Logging view inventory uses the wildcard bucket list and exact view policies."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace


def collection_pages(collector, scope):
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_logging_collector")
    package.__path__ = [str(root)]
    gcp = ModuleType("isolated_logging_collector.gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    names = ("isolated_logging_collector", "isolated_logging_collector.gcp",
             "isolated_logging_collector.gcp_logging_views")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        sys.modules[names[0]] = package
        sys.modules[names[1]] = gcp
        spec = importlib.util.spec_from_file_location(names[2], root / "gcp_logging_views.py")
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


def test_exact_view_policy_is_read_only_post():
    scope = "projects/demo-project1"
    bucket = scope + "/locations/global/buckets/_Default"
    view = bucket + "/views/custom"
    calls = []
    def pages(url, requested_scope, **kwargs):
        assert requested_scope == scope
        if url.endswith("/locations/-/buckets"):
            assert kwargs["key"] == "buckets"
            yield [{"name": bucket}], "bucket-list"
        else:
            assert url == "https://logging.googleapis.com/v2/" + bucket + "/views"
            assert kwargs["key"] == "views"
            yield [{"name": view, "filter": "severity>=ERROR"}], "view-list"
    def hydrate(item, field, url, requested_scope, **kwargs):
        calls.append((item, field, url, requested_scope, kwargs))
        return {**item, "iamPolicy": {"bindings": []},
                "_coverage": {"iamPolicy": {"status": "collected"}}}
    collector = SimpleNamespace(pages=pages, hydrate=hydrate,
                                parallel=lambda fn, rows: [fn(row) for row in rows])
    rows = [item for page, _ in collection_pages(collector, scope) for item in page]
    assert [row["name"] for row in rows] == [view]
    assert calls == [({"name": view, "filter": "severity>=ERROR"}, "iamPolicy",
        "https://logging.googleapis.com/v2/" + view + ":getIamPolicy", scope,
        {"method": "POST", "body": {"options": {"requestedPolicyVersion": 3}}})]
