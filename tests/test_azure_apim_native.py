"""Offline producer→snapshot→native APIM candidate contract."""
import copy
import importlib.util
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from peaso.collectors.azure import _Reader
from peaso.engine import _index
from peaso.snapshot import make_snapshot, resources
from peaso.checks.facts import MemoIndex

ROOT = Path(__file__).resolve().parents[1]

def _module(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

COLLECT = _module("peaso/collectors/azure_apim_native.py", "candidate_apim_collector")
CHECK = _module("peaso/checks/azure_apim_native.py", "candidate_apim_checks")
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000000"
SERVICE = SCOPE + "/resourceGroups/rg/providers/Microsoft.ApiManagement/service/gateway"
API = SERVICE + "/apis/orders"
LOGGER = SERVICE + "/loggers/ai"
COMPONENT = SCOPE + "/resourceGroups/rg/providers/Microsoft.Insights/components/ai"
VERSION = "?api-version=2024-05-01"


def _pages(*, api_diagnostic=True, sample=50, logger_id=LOGGER):
    diagnostic = {"id": API + "/diagnostics/applicationinsights", "properties": {
        "loggerId": logger_id, "sampling": {"samplingType": "fixed", "percentage": sample},
        "verbosity": "information", "frontend": {"request": {"headers": ["x-safe"], "body": {"bytes": 0}}},
        "credentials": {"connectionString": "SECRET-MUST-NOT-SURVIVE"}}}
    return {
        SERVICE + "/apis" + VERSION: {"value": [{"id": API, "properties": {"protocols": ["https"], "isCurrent": True}}], "nextLink": ""},
        SERVICE + "/loggers" + VERSION: {"value": [{"id": LOGGER, "properties": {"loggerType": "applicationInsights", "resourceId": COMPONENT,
            "credentials": {"connectionString": "SECRET-MUST-NOT-SURVIVE", "instrumentationKey": "SECRET-MUST-NOT-SURVIVE"}}}], "nextLink": ""},
        SERVICE + "/diagnostics" + VERSION: {"value": [], "nextLink": ""},
        API + "/revisions" + VERSION: {"value": [{"apiId": API, "isOnline": True, "isCurrent": True}], "nextLink": ""},
        API + "/diagnostics" + VERSION: {"value": [diagnostic] if api_diagnostic else [], "nextLink": ""},
    }


def _produce(pages, reader_options=None):
    calls = Counter()
    def request(url, *, body=None, audience=None):
        calls[urlsplit(url).path] += 1
        value = pages.get(url.removeprefix("https://management.azure.com"))
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise AssertionError("unexpected APIM URL: " + url)
        return copy.deepcopy(value)
    reader = _Reader({"concurrency": 2, "retries": 0, **(reader_options or {})})
    parent = {"type": "api_management", "scope": SCOPE, "service": "Microsoft.ApiManagement", "status": "collected", "items": [{"id": SERVICE, "properties": {}}]}
    native = COLLECT.collect_apim(reader, request, [parent])
    component = {"type": "application_insights", "scope": SCOPE, "service": "Microsoft.Insights", "status": "collected", "items": [{"id": COMPONENT, "properties": {}}]}
    snapshot = make_snapshot("azure", [SCOPE], [parent, *native, component])
    inventory = resources(snapshot)
    raw = _index(snapshot, inventory)
    index = MemoIndex(raw)
    index["context"] = {"provider": "azure", "scope": SCOPE}
    return snapshot, index, parent["items"][0], calls


def test_appinsights_pass_fail_unknown_and_no_secrets():
    snapshot, index, parent, calls = _produce(_pages())
    assert CHECK.evaluate_appinsights(parent, index)[0] == "PASS"
    assert "SECRET-MUST-NOT-SURVIVE" not in str(snapshot)
    assert all(n == 1 for n in calls.values()), calls
    snapshot, index, parent, _ = _produce(_pages(api_diagnostic=False))
    assert CHECK.evaluate_appinsights(parent, index)[0] == "FAIL"
    snapshot, index, parent, _ = _produce(_pages(sample=0))
    assert CHECK.evaluate_appinsights(parent, index)[0] == "FAIL"
    snapshot, index, parent, _ = _produce(_pages(sample=None))
    assert CHECK.evaluate_appinsights(parent, index)[0] == "UNKNOWN"


def test_pagination_denial_foreign_id_and_inheritance():
    pages = _pages(api_diagnostic=False)
    pages[SERVICE + "/diagnostics" + VERSION] = {"value": [{"id": SERVICE + "/diagnostics/applicationinsights", "properties": {
        "loggerId": LOGGER, "sampling": {"samplingType": "fixed", "percentage": 10}}}], "nextLink": ""}
    _, index, parent, _ = _produce(pages)
    assert CHECK.evaluate_appinsights(parent, index)[0] == "PASS"
    pages = _pages()
    pages[SERVICE + "/apis" + VERSION] = {"value": [], "nextLink": "https://management.azure.com" + SERVICE + "/apis?$skip=1&api-version=2024-05-01"}
    pages[SERVICE + "/apis?$skip=1&api-version=2024-05-01"] = {"value": [{"id": API, "properties": {"protocols": ["https"]}}], "nextLink": ""}
    _, index, parent, calls = _produce(pages)
    assert CHECK.evaluate_appinsights(parent, index)[0] == "PASS"
    assert calls[SERVICE + "/apis"] == 2
    pages = _pages()
    pages[API + "/diagnostics" + VERSION] = PermissionError("denied")
    _, index, parent, _ = _produce(pages)
    assert CHECK.evaluate_appinsights(parent, index)[0] == "UNKNOWN"
    pages = _pages()
    pages[API + "/diagnostics" + VERSION]["value"][0]["id"] = SERVICE + "/apis/foreign/diagnostics/applicationinsights"
    _, index, parent, _ = _produce(pages)
    assert CHECK.evaluate_appinsights(parent, index)[0] == "UNKNOWN"


def test_protocol_policy_is_explicit_and_no_cloud_calls_in_evaluator():
    _, index, parent, calls = _produce(_pages())
    before = sum(calls.values())
    assert CHECK.evaluate_protocol(parent, index)[0] == "UNKNOWN"
    index["context"]["policy_inputs"] = {"status": "collected", "scope": SCOPE, CHECK.PROTOCOL_ID: {
        "service_id": SERVICE, "expected_by_api": {API: "https"}, "forbidden_by_api": {API: ["http"]}}}
    assert CHECK.evaluate_protocol(parent, index)[0] == "PASS"
    index["context"]["policy_inputs"][CHECK.PROTOCOL_ID]["expected_by_api"][API] = "http"
    assert CHECK.evaluate_protocol(parent, index)[0] == "FAIL"
    assert sum(calls.values()) == before


def test_opt_in_main_collector_to_snapshot_to_engine(monkeypatch):
    """Load the private azure.py mirror and run its actual collect selector/hook."""
    import sys
    from peaso.engine import evaluate_snapshot, plan_collection
    from peaso.collectors import azure as public_azure
    monkeypatch.setitem(sys.modules, "peaso.collectors.azure_apim_native", COLLECT)
    candidate = _module("peaso/collectors/azure.py", "peaso.collectors.azure_candidate_apim")
    pages = _pages()
    pages[SCOPE + "/providers/Microsoft.ApiManagement/service" + VERSION] = {
        "value": [{"id": SERVICE, "type": "Microsoft.ApiManagement/service", "properties": {}}], "nextLink": ""}
    pages[SERVICE + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"] = {"value": [], "nextLink": ""}
    pages[SCOPE + "/providers/Microsoft.Insights/components?api-version=2020-02-02"] = {
        "value": [{"id": COMPONENT, "type": "Microsoft.Insights/components", "properties": {}}], "nextLink": ""}
    pages[COMPONENT + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"] = {"value": [], "nextLink": ""}
    calls = Counter()
    class Transport:
        tenant = None
        verified_tenant = None
        def request(self, url, *, body=None, audience=None):
            calls[urlsplit(url).path] += 1
            value = pages.get(url.removeprefix("https://management.azure.com"))
            if value is None:
                raise AssertionError("unexpected main Azure collector URL: " + url)
            return copy.deepcopy(value)
    from peaso.checks import CHECKS
    if CHECK.INSIGHTS_ID not in {check.id for check in CHECKS}:
        CHECK.install()
    registered = next(c for c in CHECKS if c.id == CHECK.INSIGHTS_ID)
    assert registered.category == "hardening" and registered.dependencies == ["api_management", "apim_native", "application_insights"]
    monkeypatch.setattr(public_azure, "TYPES", candidate.TYPES)
    connector = {"provider": "azure", "scopes": [SCOPE], "auth": {}, "options": {"concurrency": 2, "retries": 0}}
    planned = plan_collection({"connector": connector, "checks": [CHECK.INSIGHTS_ID], "categories": ["hardening"]})
    assert set(planned) == {"api_management", "apim_native", "application_insights"}
    unrelated = plan_collection({"connector": connector, "checks": ["azure.port.redis_cache_ssl_enabled"], "categories": ["hardening"]})
    assert "apim_native" not in unrelated
    snapshot = candidate.collect(connector, requirements=planned, transport=Transport())
    assert next(c for c in snapshot["collections"] if c["type"] == "apim_native")["status"] == "collected"
    assert "SECRET-MUST-NOT-SURVIVE" not in str(snapshot)
    assert all(n == 1 for n in calls.values()), calls
    report = evaluate_snapshot(snapshot, checks=[CHECK.INSIGHTS_ID])
    matches = [f for f in report["findings"] if f["check_id"] == CHECK.INSIGHTS_ID]
    assert len(matches) == 1 and matches[0]["status"] == "PASS", matches


def test_api_override_blocks_inherited_service_logger_and_partial_revision_unknown():
    pages = _pages()
    pages[SERVICE + "/diagnostics" + VERSION] = {"value": [{"id": SERVICE + "/diagnostics/applicationinsights",
        "properties": {"loggerId": LOGGER, "sampling": {"samplingType": "fixed", "percentage": 100}}}], "nextLink": ""}
    pages[API + "/diagnostics" + VERSION]["value"][0]["properties"]["sampling"]["percentage"] = 0
    _, index, parent, _ = _produce(pages)
    assert CHECK.evaluate_appinsights(parent, index)[0] == "FAIL"
    pages = _pages()
    pages[API + "/revisions" + VERSION] = {"value": [], "nextLink": ""}
    _, index, parent, _ = _produce(pages)
    assert CHECK.evaluate_appinsights(parent, index)[0] == "UNKNOWN"


def test_explicit_resource_cap_stays_unknown():
    _, index, parent, _ = _produce(_pages(), {"max_resources": 1})
    assert CHECK.evaluate_appinsights(parent, index)[0] == "UNKNOWN"


def test_logger_revision_and_diagnostic_nextlinks_are_fully_followed():
    pages = _pages()
    for path in (SERVICE + "/loggers", API + "/revisions", API + "/diagnostics"):
        first = path + VERSION
        second = path + "?$skip=1&api-version=2024-05-01"
        pages[second] = pages[first]
        pages[first] = {"value": [], "nextLink": "https://management.azure.com" + second}
    _, index, parent, calls = _produce(pages)
    assert CHECK.evaluate_appinsights(parent, index)[0] == "PASS"
    for path in (SERVICE + "/loggers", API + "/revisions", API + "/diagnostics"):
        assert calls[path] == 2



def test_unrelated_kind_api_diagnostic_keeps_fallback_but_routing_unknown():
    pages = _pages(api_diagnostic=False)
    pages[SERVICE + "/diagnostics" + VERSION] = {"value": [{"id": SERVICE + "/diagnostics/applicationinsights",
        "properties": {"loggerId": LOGGER, "sampling": {"samplingType": "fixed", "percentage": 100}}}], "nextLink": ""}
    pages[API + "/diagnostics" + VERSION] = {"value": [{"id": API + "/diagnostics/azuremonitor",
        "properties": {"loggerId": SERVICE + "/loggers/other", "sampling": {"samplingType": "fixed", "percentage": 100}}}], "nextLink": ""}
    _, index, parent, _ = _produce(pages)
    assert CHECK.evaluate_appinsights(parent, index)[0] == "UNKNOWN"


def test_each_api_base_requires_complete_revision_inventory():
    second = SERVICE + "/apis/invoices"
    pages = _pages()
    pages[SERVICE + "/apis" + VERSION]["value"].append({"id": second, "properties": {"protocols": ["https"]}})
    pages[second + "/revisions" + VERSION] = {"value": [], "nextLink": ""}
    _, index, parent, _ = _produce(pages)
    assert CHECK.evaluate_appinsights(parent, index)[0] == "UNKNOWN"


def test_revision_get_hydration_debits_explicit_resource_cap():
    revised = API + ";rev=2"
    pages = _pages()
    pages[API + "/revisions" + VERSION] = {"value": [{"apiId": revised, "isOnline": True, "isCurrent": False}], "nextLink": ""}
    pages[revised + VERSION] = {"id": revised, "properties": {"protocols": ["https"], "isOnline": True}}
    pages[revised + "/diagnostics" + VERSION] = {"value": [{"id": revised + "/diagnostics/applicationinsights", "properties": {
        "loggerId": LOGGER, "sampling": {"samplingType": "fixed", "percentage": 50}}}], "nextLink": ""}
    _, index, parent, _ = _produce(pages)
    assert CHECK.evaluate_appinsights(parent, index)[0] == "PASS"
    _, index, parent, _ = _produce(pages, {"max_resources": 3})
    assert CHECK.evaluate_appinsights(parent, index)[0] == "UNKNOWN"
