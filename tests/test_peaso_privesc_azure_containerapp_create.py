"""A new Container App must have one exact app and environment creation path."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-containerapp-create-with-user-assigned-identity"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
ENV = RG + "/providers/Microsoft.App/managedEnvironments/work"
OTHER_ENV = RG + "/providers/Microsoft.App/managedEnvironments/other"
EXISTING_APP = RG + "/providers/Microsoft.App/containerApps/old"
UAI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
APP_ROLE = "22222222-2222-2222-2222-222222222222"
JOIN_ROLE = "33333333-3333-3333-3333-333333333333"
ENV_ROLE = "44444444-4444-4444-4444-444444444444"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
APP_WRITE = "Microsoft.App/containerApps/write"
JOIN = "Microsoft.App/managedEnvironments/join/action"
ENV_WRITE = "Microsoft.App/managedEnvironments/write"


def _run(*, environment=True, env_state="Succeeded", join_scope=ENV, app_scope=RG,
         assign=True, env_write=False, env_status="collected", group_status="collected",
         identity_status="collected"):
    assignments = [("u-alice", "User", app_scope, APP_ROLE),
                   ("u-alice", "User", join_scope if environment else RG, JOIN_ROLE)]
    if assign:
        assignments.append(("u-alice", "User", UAI, ROLE_ID))
    if env_write:
        assignments.append(("u-alice", "User", RG, ENV_ROLE))
    roles = {ROLE_ID: ([ASSIGN], []), APP_ROLE: ([APP_WRITE], []),
             JOIN_ROLE: ([JOIN], []), ENV_ROLE: ([ENV_WRITE], [])}
    env = {"id": ENV, "type": "Microsoft.App/managedEnvironments", "location": "eastus",
           "properties": {"provisioningState": env_state}}
    identity = {"id": UAI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {"principalId": "mi-worker", "clientId": "worker-client"}}
    snap = az(assignments, roles=roles,
              graph=[env] if environment and env_status == "collected" else [],
              extra=[("resource_group", SUB, [{"id": RG}] if group_status == "collected" else [], group_status),
                     ("managed_identity", SUB, [identity] if identity_status == "collected" else [], identity_status)])
    graph = next(c for c in snap["collections"] if c["type"] == "resource_graph")
    if env_status != "collected":
        graph["status"] = env_status
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_existing_joinable_environment_and_new_environment_paths():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-worker": "conditional"}
    assert reached(_run(environment=False, env_status="empty", env_write=True), "u-alice", TID) == {
        "mi-worker": "conditional"}


def test_all_three_permissions_must_apply_to_one_creation_path():
    assert reached(_run(assign=False), "u-alice", TID) == {}
    assert reached(_run(join_scope=OTHER_ENV), "u-alice", TID) == {}
    assert reached(_run(app_scope=EXISTING_APP), "u-alice", TID) == {}
    assert reached(_run(environment=False, env_status="empty"), "u-alice", TID) == {}
    assert reached(_run(env_state="Failed"), "u-alice", TID) == {}


def test_missing_environment_group_or_identity_inventory_is_unresolved():
    for case in ({"env_status": "not_collected"}, {"group_status": "not_collected"},
                 {"identity_status": "not_collected"}, {"env_state": None}):
        result = reached(_run(**case), "u-alice", TID)
        assert result and set(result.values()) == {"unknown"}
