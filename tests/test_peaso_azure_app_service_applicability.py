"""Offline App Service OS logging and VNet integration fact fixtures."""

import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES


REGISTRY = {check.id: check for check in CHECKS}
PREFIX = "azure.claude2."
SUBNET = "/subscriptions/s/resourceGroups/r/providers/Microsoft.Network/virtualNetworks/v/subnets/a"
VNET = SUBNET.rsplit("/subnets/", 1)[0]
OTHER_VNET = VNET.replace("/virtualNetworks/v", "/virtualNetworks/other")


def assess(slug, item):
    original = copy.deepcopy(item)
    status, evidence = REGISTRY[PREFIX + slug].evaluate(item, {})
    assert item == original
    return status, evidence


def site(*, kind="app", reserved=None, flags=None, tracing=None, subnet_marker=None, name_marker=None,
         connections_marker=None, coverage=None):
    item = {"kind": kind, "properties": {}}
    if reserved is not None:
        item["properties"]["reserved"] = reserved
    if flags is not None or name_marker is not None:
        item["configuration"] = {"properties": {**(flags or {})}}
        if name_marker is not None:
            item["configuration"]["properties"]["vnetName"] = name_marker
    if tracing is not None:
        item["logsConfiguration"] = {"properties": {"failedRequestsTracing": {"enabled": tracing}}}
    if subnet_marker is not None:
        item["properties"]["virtualNetworkSubnetId"] = subnet_marker
    if connections_marker is not None:
        item["vnetConnections"] = connections_marker
    if coverage is not None:
        item["_coverage"] = {"vnetConnections": {"status": coverage}}
    return item


FLAGS_ON = {"detailedErrorLoggingEnabled": True, "httpLoggingEnabled": True, "requestTracingEnabled": True}
FLAGS_HTTP_OFF = {**FLAGS_ON, "httpLoggingEnabled": False}


@pytest.mark.parametrize("kind", ["app", "api", "app,windows"])
def test_explicit_windows_web_table_logs_and_tracing(kind):
    assert assess("web_app_diagnostic_logs_enabled", site(kind=kind, reserved=False, flags=FLAGS_ON))[0] == "PASS"
    assert assess("web_app_diagnostic_logs_enabled", site(kind=kind, reserved=False, flags=FLAGS_HTTP_OFF))[0] == "FAIL"
    assert assess("web_app_failed_request_tracing", site(kind=kind, reserved=False, tracing=True))[0] == "PASS"
    assert assess("web_app_failed_request_tracing", site(kind=kind, reserved=False, tracing=False))[0] == "FAIL"


def test_linux_and_function_apps_do_not_get_windows_iis_failures():
    linux = site(kind="app,linux", reserved=True, flags=FLAGS_HTTP_OFF, tracing=False)
    for slug in ("web_app_diagnostic_logs_enabled", "web_app_failed_request_tracing"):
        assert assess(slug, linux)[0] == "NOT_APPLICABLE"
        assert assess(slug, site(kind="functionapp,linux", reserved=True))[0] == "NOT_APPLICABLE"
    # The separate HTTP diagnostic-category requirement remains present for Linux.
    separate = copy.deepcopy(CASES[PREFIX + "web_app_diagnostic_http_log_category"]["pass"])
    separate["kind"] = "app,linux"
    assert assess("web_app_diagnostic_http_log_category", separate)[0] == "PASS"


@pytest.mark.parametrize("item", [
    site(kind="app", flags=FLAGS_HTTP_OFF, tracing=False),
    site(kind="app,linux", reserved=False, flags=FLAGS_HTTP_OFF, tracing=False),
    site(kind="app,windows", reserved=True, flags=FLAGS_HTTP_OFF, tracing=False),
    site(kind="app", reserved="false", flags=FLAGS_HTTP_OFF, tracing=False),
    {**site(kind="app", reserved=False, flags=FLAGS_HTTP_OFF, tracing=False), "collection_status": "denied"},
])
def test_unknown_or_conflicting_os_does_not_produce_iis_fail(item):
    for slug in ("web_app_diagnostic_logs_enabled", "web_app_failed_request_tracing"):
        assert assess(slug, item)[0] == "UNKNOWN"


def test_missing_or_denied_windows_log_fields_remain_unknown():
    assert assess("web_app_diagnostic_logs_enabled", site(reserved=False, flags={"httpLoggingEnabled": False}))[0] == "UNKNOWN"
    assert assess("web_app_failed_request_tracing", site(reserved=False))[0] == "UNKNOWN"
    item = site(reserved=False, flags=FLAGS_ON, tracing=True)
    item["_coverage"] = {"logsConfiguration": {"status": "denied"}}
    assert assess("web_app_failed_request_tracing", item)[0] == "UNKNOWN"


def test_current_regional_subnet_and_native_legacy_connection_are_positive_facts():
    status, evidence = assess("web_app_vnet_connection", site(subnet_marker=SUBNET))
    assert status == "PASS" and evidence["regional_subnet_id"] == SUBNET
    connection = {"name": "legacy", "properties": {"vnetResourceId": VNET}}
    status, evidence = assess("web_app_vnet_connection", site(connections_marker=[connection], coverage="collected"))
    assert status == "PASS" and evidence["vnet_connection_ids"] == [VNET]
    coexist = site(subnet_marker=SUBNET, connections_marker=[{"name": "other", "properties": {"vnetResourceId": OTHER_VNET}}],
                   coverage="collected")
    assert assess("web_app_vnet_connection", coexist)[0] == "PASS"  # Two valid modes can coexist.


def test_legacy_name_is_a_pointer_only_and_complete_absence_is_required_for_fail():
    assert assess("web_app_vnet_connection", site(name_marker="legacy"))[0] == "UNKNOWN"
    assert assess("web_app_vnet_connection", site(subnet_marker="", name_marker="", connections_marker=[]))[0] == "UNKNOWN"
    complete = site(subnet_marker="", name_marker="", connections_marker=[], coverage="empty")
    assert assess("web_app_vnet_connection", complete)[0] == "FAIL"
    complete["configuration"]["properties"]["vnetName"] = "legacy"
    assert assess("web_app_vnet_connection", complete)[0] == "UNKNOWN"


def test_missing_denied_or_malformed_vnet_facts_do_not_create_false_failure():
    valid_connection = {"properties": {"vnetResourceId": VNET}}
    for item in (site(subnet_marker="bad", connections_marker=[valid_connection], coverage="collected"),
                 site(subnet_marker="", name_marker="", connections_marker=[], coverage="denied"),
                 site(subnet_marker="", name_marker="", connections_marker=[{"properties": {"vnetResourceId": "bad"}}], coverage="collected"),
                 site(subnet_marker="", name_marker="", connections_marker=[])):
        assert assess("web_app_vnet_connection", item)[0] == "UNKNOWN"
