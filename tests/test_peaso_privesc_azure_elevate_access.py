"""Global Administrator elevation is a tenant-root path for active users."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

from peaso import privesc
from peaso.privesc.effective_permissions.azure import GLOBAL_ADMIN
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


TID = "azure-authorization-elevateaccess-global-admin"
ENTRY = next({key: value for key, value in item.items() if not key.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
PIM_TID = "azure-authorization-elevateaccess-pim-eligible-global-admin"
PIM_ENTRY = next({key: value for key, value in item.items() if not key.startswith("_")}
                 for item in privesc.load_catalog()["entries"] if item["id"] == PIM_TID)


def _run(*, principal="u-alice", scope="/", active=True, eligible=False, role=GLOBAL_ADMIN,
         role_definition_id=None, instance_state="current"):
    snap = az(users=("u-alice",), sps=("sp-bot",))
    role_definition_id = role_definition_id or role
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs["items"] = [{"id": role_definition_id, "templateId": role,
                      "displayName": "Global Administrator" if role == GLOBAL_ADMIN else "Helpdesk Administrator"}]
    defs["status"] = "collected"
    assignments = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    if active:
        assignments["items"] = [{"id": "active-global-admin", "principalId": principal,
                                 "roleDefinitionId": role_definition_id, "directoryScopeId": scope}]
        assignments["status"] = "collected"
    if eligible:
        snap["collections"].append({"type": "directory_role_eligibility_schedule", "scope": T,
                                    "status": "collected", "items": [{"id": "eligible-global-admin",
                                    "principalId": principal, "roleDefinitionId": role_definition_id,
                                    "directoryScopeId": scope, "status": "Provisioned"}]})
        if instance_state != "missing":
            now = datetime.now(timezone.utc)
            start = now + timedelta(days=1) if instance_state == "future" else now - timedelta(days=2)
            end = now - timedelta(days=1) if instance_state == "expired" else now + timedelta(days=2)
            snap["collections"].append({"type": "directory_role_eligibility_instance", "scope": T,
                                        "status": "collected", "items": [{"id": "instance-global-admin",
                                        "principalId": principal, "roleDefinitionId": role_definition_id,
                                        "directoryScopeId": scope,
                                        "startDateTime": start.isoformat(), "endDateTime": end.isoformat()}]})
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY), copy.deepcopy(PIM_ENTRY)])


def test_active_tenant_global_administrator_reaches_only_root():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"azure_scope_owner:/": "derived"}


def test_eligible_or_administrative_unit_scoped_role_is_not_active_tenant_admin():
    assert reached(_run(active=False, eligible=True), "u-alice", TID) == {}
    assert reached(_run(scope="/administrativeUnits/au"), "u-alice", TID) == {}


def test_other_role_and_service_principal_do_not_elevate():
    assert reached(_run(role="helpdesk"), "u-alice", TID) == {}
    assert reached(_run(principal="sp-bot"), "sp-bot", TID) == {}


def test_current_tenant_global_admin_eligibility_is_conditional():
    assert validate_entry(PIM_ENTRY)[0] == []
    result = _run(active=False, eligible=True, role_definition_id="actual-role-definition-id")
    assert reached(result, "u-alice", TID) == {}
    assert reached(result, "u-alice", PIM_TID) == {"azure_scope_owner:/": "conditional"}


def test_pim_route_rejects_other_role_scope_and_service_principal():
    for kwargs in ({"role": "helpdesk"}, {"scope": "/administrativeUnits/au"},
                   {"principal": "sp-bot"}):
        result = _run(active=False, eligible=True, **kwargs)
        assert reached(result, "u-alice" if kwargs.get("principal") != "sp-bot" else "sp-bot", PIM_TID) == {}


def test_pim_route_needs_a_current_collected_eligibility_instance():
    for state in ("future", "expired", "missing"):
        result = _run(active=False, eligible=True, instance_state=state)
        assert "conditional" not in reached(result, "u-alice", PIM_TID).values()
