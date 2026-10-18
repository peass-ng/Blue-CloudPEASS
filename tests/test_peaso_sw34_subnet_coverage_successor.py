"""Scoped subnet firewall route coverage regressions."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import evaluate_check
from tests.compliance_draft_isolation import staged_registry
with staged_registry(("compliance_new_sw34",)):
    from tests.test_peaso_compliance_new_sw34 import (
        NIC, ROUTES, SCOPE, SUBNET, VNET, firewall, route, route_fact, subnet, subnet_index, sw34,
    )

VM = SCOPE + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"


def test_sampled_native_safe_routes_cannot_be_promoted_by_self_declared_full_flags():
    row = subnet()
    fact = route_fact()
    fact["nicEvidence"] = [{"nicId": NIC, "vmId": VM, "activeRoutes": [
        {"nicId": NIC, "destinationPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance",
         "nextHopIpAddress": "10.0.0.4", "sourceOperation": "networkInterfaces/getEffectiveRouteTable"}],
         "directInternetWitness": None}]
    fact["_provenance"].update(nic_inventory_operation="get", vm_attachment_operation="get")
    status, _ = evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [fact]))
    assert status == "UNKNOWN"


def test_complete_approved_route_coverage_can_pass_exact_subnet():
    row = subnet()
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row))[0] == "PASS"


def test_self_declared_exhaustive_routes_without_independent_coverage_are_unknown():
    row = subnet()
    fact = route_fact()
    fact.pop("coverage")
    assert fact["exhaustiveInternetDestinations"] and fact["allAttachedNicsCovered"]
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [fact]))[0] == "UNKNOWN"


@pytest.mark.parametrize("mutation", [
    "unapproved_source", "foreign_parent", "stale_capture",
    "unbound_nics", "altered_routes", "incomplete_tables",
])
def test_full_route_coverage_binding_is_required(mutation):
    row = subnet()
    fact = route_fact()
    coverage = fact["coverage"]
    if mutation == "unapproved_source":
        coverage["_provenance"]["source_id"] = "unapproved-audit"
    elif mutation == "foreign_parent":
        coverage["subnet_id"] = VNET.casefold() + "/subnets/other"
    elif mutation == "stale_capture":
        coverage["_provenance"]["captured_at"] = "2026-10-11T12:00:00+00:00"
    elif mutation == "unbound_nics":
        coverage["nicIds"] = [SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/other"]
    elif mutation == "altered_routes":
        coverage["routeRowsSha256"] = "0" * 64
    else:
        coverage["activeRouteTablesComplete"] = False
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [fact]))[0] == "UNKNOWN"


def test_duplicate_active_prefix_cannot_prove_complete_protection():
    row = subnet()
    fact = route_fact([route(), route()])
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [fact]))[0] == "UNKNOWN"


def test_complete_active_more_specific_internet_bypass_fails():
    row = subnet()
    fact = route_fact([route(), route("8.8.8.0/24", "Internet")])
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [fact]))[0] == "FAIL"


def test_native_direct_internet_witness_fails_without_full_coverage():
    row = subnet()
    fact = route_fact()
    fact.pop("coverage")
    fact["allAttachedNicsCovered"] = False
    fact["exhaustiveInternetDestinations"] = False
    routes = [{"nicId": NIC, "destinationPrefix": "0.0.0.0/0", "nextHopType": "Internet",
               "nextHopIpAddress": None, "sourceOperation": "networkInterfaces/getEffectiveRouteTable"}]
    fact["nicEvidence"] = [{"nicId": NIC, "vmId": VM, "activeRoutes": routes,
                            "directInternetWitness": {"destinationIp": "1.1.1.1",
                                "selectedPrefix": "0.0.0.0/0", "nextHopType": "Internet", "nicId": NIC}}]
    fact["_provenance"].update(nic_inventory_operation="get", vm_attachment_operation="get")
    assert evaluate_check(sw34.SUBNET_ID, row, subnet_index(row, [fact]))[0] == "FAIL"
