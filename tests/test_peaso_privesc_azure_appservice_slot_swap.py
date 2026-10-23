"""Slot swaps must join staged code, the swap action, and the production identity."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-slot-swap-promote-code"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
SLOT = APP + "/slots/staging"
OTHER = APP + "/slots/other"
SWAP = "Microsoft.Web/sites/slotsswap/action"
SLOT_SWAP = "Microsoft.Web/sites/slots/slotsswap/action"
PUBLISH = "Microsoft.Web/sites/slots/publish/action"
CONTAINER = "Microsoft.Web/sites/slots/sitecontainers/write"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, code_scope=SLOT, swap_scope=APP, swap_action=SWAP,
         code_action=PUBLISH, include_slots=True, fx="sitecontainers",
         prod_host=APP, include_unknown=False):
    production = {"id": APP, "type": "Microsoft.Web/sites", "name": "app",
                  "kind": "app,linux", "identity": {"principalId": "mi-prod"},
                  "properties": {"state": "Running"}}
    slot_rows = [{"id": SLOT, "type": "Microsoft.Web/sites/slots", "name": "app/staging",
                  "kind": "app,linux", "identity": {"principalId": "mi-slot"},
                  "properties": {"state": "Running", "siteConfig": {"linuxFxVersion": fx}}},
                 {"id": OTHER, "type": "Microsoft.Web/sites/slots", "name": "app/other",
                  "kind": "app,linux", "properties": {"state": "Running"}}]
    graph = [production, *slot_rows] if include_slots else [production]
    extra = [("app_service", SUB, [production])]
    if include_slots:
        extra.append(("app_service_slot", SUB, slot_rows))
    if prod_host != APP:
        production["identity"] = None
        slot_rows[0]["identity"] = {"principalId": "mi-prod"}
    snap = az([("u-alice", "User", code_scope, ROLE_ID),
               ("u-alice", "User", swap_scope, ROLE_ID + "-swap")],
              roles={ROLE_ID: ([code_action], []), ROLE_ID + "-swap": ([swap_action], [])},
              graph=graph, extra=extra)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_same_slot_code_and_site_or_slot_swap_reaches_production_identity():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-prod": "conditional"}
    assert reached(_run(swap_action=SLOT_SWAP, swap_scope=SLOT), "u-alice", TID) == {
        "mi-prod": "conditional"}
    assert reached(_run(code_action=CONTAINER,
                        code_scope=SLOT + "/sitecontainers/main"), "u-alice", TID) == {
        "mi-prod": "conditional"}


def test_different_slot_and_wrong_swap_scope_do_not_join():
    assert "mi-prod" not in reached(_run(code_scope=OTHER, swap_action=SLOT_SWAP,
                                          swap_scope=SLOT), "u-alice", TID)
    assert "mi-prod" not in reached(_run(swap_scope=OTHER, swap_action=SWAP),
                                    "u-alice", TID)


def test_slot_identity_and_uncollected_slots_are_not_production_evidence():
    assert "mi-prod" not in reached(_run(prod_host=SLOT), "u-alice", TID)
    assert "mi-prod" not in reached(_run(include_slots=False), "u-alice", TID)


def test_sitecontainer_requires_sitecontainers_mode():
    assert "mi-prod" not in reached(_run(code_action=CONTAINER,
                                          code_scope=SLOT + "/sitecontainers/main",
                                          fx="DOCKER|image"), "u-alice", TID)
