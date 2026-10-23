"""Slot credentials need an enabled policy on the identity's own slot."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-slot-publishxml"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
SLOT = APP + "/slots/staging"
OTHER = APP + "/slots/other"
PUBLISH_XML = "Microsoft.Web/sites/slots/publishxml/action"
CONFIG_LIST = "Microsoft.Web/sites/slots/config/list/action"
START = "Microsoft.Web/sites/slots/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, action=PUBLISH_XML, grant=SLOT, identity_host=SLOT,
         policy=True, policy_present=True, kind="app,linux", state="Running",
         actions=None, include_unknown=False):
    production = {"id": APP, "type": "Microsoft.Web/sites", "name": "app",
                  "kind": "app,linux", "identity": {"principalId": "mi-prod"}}
    slots = [{"id": SLOT, "type": "Microsoft.Web/sites/slots", "name": "app/staging",
              "kind": kind, "properties": {"state": state}},
             {"id": OTHER, "type": "Microsoft.Web/sites/slots", "name": "app/other",
              "kind": "app,linux", "properties": {"state": "Running"}}]
    next(slot for slot in slots if slot["id"] == identity_host)["identity"] = {
        "principalId": "mi-slot"}
    if policy_present:
        slots[0]["scmBasicAuthPolicy"] = {"properties": {"allow": policy}}
    snap = az([("u-alice", "User", grant, ROLE_ID)],
              roles={ROLE_ID: (list(actions or (action,)), [])}, graph=[production, *slots],
              extra=[("app_service", SUB, [production]), ("app_service_slot", SUB, slots)])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_either_credential_action_on_exact_enabled_slot_is_conditional():
    assert validate_entry(ENTRY)[0] == []
    for action in (PUBLISH_XML, CONFIG_LIST):
        assert reached(_run(action=action), "u-alice", TID) == {"mi-slot": "conditional"}


def test_disabled_policy_and_other_slot_grant_do_not_match():
    for result in (_run(policy=False), _run(identity_host=OTHER), _run(grant=OTHER)):
        assert "mi-slot" not in reached(result, "u-alice", TID)
    assert reached(_run(grant=APP), "u-alice", TID) == {"mi-slot": "conditional"}


def test_missing_policy_and_custom_container_remain_unresolved():
    for result in (_run(policy_present=False, include_unknown=True),
                   _run(kind="app,linux,container", include_unknown=True)):
        targets = reached(result, "u-alice", TID)
        assert "mi-slot" not in targets
        assert "unknown" in targets.values()


def test_stopped_slot_needs_slot_start_permission():
    assert "mi-slot" not in reached(_run(state="Stopped"), "u-alice", TID)
    assert reached(_run(state="Stopped", actions=(PUBLISH_XML, START)), "u-alice", TID) == {
        "mi-slot": "conditional"}
