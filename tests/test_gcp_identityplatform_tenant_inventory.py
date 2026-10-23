"""Tenant collection binds policy reads to listed tenant names."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace


def collection_pages(collector, scope):
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_tenant_collector")
    package.__path__ = [str(root)]
    gcp = ModuleType("isolated_tenant_collector.gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    names = ("isolated_tenant_collector", "isolated_tenant_collector.gcp",
             "isolated_tenant_collector.gcp_identityplatform_tenants")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        sys.modules[names[0]] = package
        sys.modules[names[1]] = gcp
        spec = importlib.util.spec_from_file_location(names[2], root / "gcp_identityplatform_tenants.py")
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


def test_lists_exact_tenant_and_reads_its_policy():
    scope = "projects/demo-project1"
    tenant = scope + "/tenants/customer1"
    calls = []
    def pages(url, requested_scope, **kwargs):
        assert url == "https://identitytoolkit.googleapis.com/v2/" + scope + "/tenants"
        assert requested_scope == scope and kwargs["key"] == "tenants"
        yield [{"name": tenant}], "list-receipt"
    def hydrate(item, field, url, requested_scope, **kwargs):
        calls.append((item, field, url, requested_scope, kwargs))
        return {**item, "iamPolicy": {"bindings": []},
                "_coverage": {"iamPolicy": {"status": "collected"}}}
    collector = SimpleNamespace(pages=pages, hydrate=hydrate,
                                parallel=lambda fn, rows: [fn(row) for row in rows])
    rows = [item for page, _ in collection_pages(collector, scope) for item in page]
    assert rows[0]["name"] == tenant
    assert calls == [({"name": tenant}, "iamPolicy",
        "https://identitytoolkit.googleapis.com/admin/v2/" + tenant + ":getIamPolicy",
        scope, {"method": "POST", "body": {"options": {"requestedPolicyVersion": 3}}})]
