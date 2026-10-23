"""ACI UAMI attachment needs an exact identity assignment and a usable ACI write scope."""
from peaso import privesc
from peaso.privesc.effective_permissions.azure import AzureModel
from peaso.privesc.evaluator import Evaluator


SUB = "/subscriptions/00000000-0000-0000-0000-00000000aaaa"
RG = SUB + "/resourceGroups/workloads"
OTHER = SUB + "/resourceGroups/identities"
GROUP = RG + "/providers/Microsoft.ContainerInstance/containerGroups/workload"
UAMI = OTHER + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/privileged"
SOURCE = "source-user"
TARGET = "target-uami"
WRITE_ROLE = "11111111-1111-1111-1111-111111111111"
ASSIGN_ROLE = "22222222-2222-2222-2222-222222222222"
TECHNIQUE = "azure-aci-assign-user-assigned-identity"
EXEC_TECHNIQUE = "azure-aci-container-exec"
EXISTING_WRITE_TECHNIQUE = "azure-aci-containergroup-write-existing"


def snapshot(*, write_scope=RG, assign=True, groups=True, resource_groups=True,
             group_status="collected", rg_status="collected"):
    def row(kind, scope, values, status="collected"):
        return {"type": kind, "scope": scope, "service": kind,
                "status": status, "items": values, "error": None}
    roles = [(WRITE_ROLE, ["Microsoft.ContainerInstance/containerGroups/write"]),
             (ASSIGN_ROLE, ["Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"])]
    definitions = [{"id": SUB + "/providers/Microsoft.Authorization/roleDefinitions/" + ident,
                    "properties": {"roleName": ident, "type": "CustomRole", "assignableScopes": [SUB],
                                   "permissions": [{"actions": actions, "dataActions": []}]}}
                   for ident, actions in roles]
    assignments = [{"id": write_scope + "/providers/Microsoft.Authorization/roleAssignments/write",
                    "properties": {"principalId": SOURCE, "principalType": "User", "scope": write_scope,
                                   "roleDefinitionId": definitions[0]["id"]}}]
    if assign:
        assignments.append({"id": UAMI + "/providers/Microsoft.Authorization/roleAssignments/assign",
                            "properties": {"principalId": SOURCE, "principalType": "User", "scope": UAMI,
                                           "roleDefinitionId": definitions[1]["id"]}})
    return {"schema_version": 1, "provider": "azure", "scopes": [SUB],
            "metadata": {"tenant_id": "tenant"}, "collections": [
                row("subscription", "/tenants/tenant", [{"id": SUB}]),
                row("directory_user", "/tenants/tenant", [{"id": SOURCE, "userPrincipalName": "source@example.com"}]),
                row("managed_identity", SUB, [{"id": UAMI,
                    "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                    "properties": {"principalId": TARGET, "clientId": "client"}}]),
                row("role_definition", SUB, definitions),
                row("role_assignment", SUB, assignments),
                row("deny_assignment", SUB, [], "empty"),
                row("container_group", SUB, [{"id": GROUP,
                    "type": "Microsoft.ContainerInstance/containerGroups"}] if groups else [], group_status),
                row("resource_group", SUB, [{"id": RG}] if resource_groups else [], rg_status),
            ]}


def targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(AzureModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()}


def exec_snapshot(*, group_state="Running", container_states=("Running",),
                  write_scope=GROUP, native_status="collected"):
    snap = snapshot(write_scope=write_scope, assign=False, resource_groups=False)
    role = next(c for c in snap["collections"] if c["type"] == "role_definition")["items"][0]
    role["properties"]["permissions"][0]["actions"] = [
        "Microsoft.ContainerInstance/containerGroups/containers/exec/action"]
    group = next(c for c in snap["collections"] if c["type"] == "container_group")
    group["status"] = native_status
    group["items"][0]["identity"] = {"type": "UserAssigned",
        "userAssignedIdentities": {UAMI: {"principalId": TARGET}}}
    group["items"][0]["properties"] = {"instanceView": {"state": group_state},
        "containers": [{"name": "c" + str(i), "properties": {
            "instanceView": {"currentState": {"state": state}}}}
            for i, state in enumerate(container_states)]}
    return snap


def exec_targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == EXEC_TECHNIQUE]
    reaches = Evaluator(AzureModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()}


def existing_write_targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == EXISTING_WRITE_TECHNIQUE]
    reaches = Evaluator(AzureModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()}


def write_snapshot(*, state="Running", write_scope=GROUP, native_status="collected"):
    snap = exec_snapshot(group_state=state, write_scope=write_scope, native_status=native_status)
    role = next(c for c in snap["collections"] if c["type"] == "role_definition")["items"][0]
    role["properties"]["permissions"][0]["actions"] = ["Microsoft.ContainerInstance/containerGroups/write"]
    return snap


def test_existing_group_or_known_resource_group_can_receive_assignable_identity():
    assert targets(snapshot()) == {TARGET: "conditional"}
    assert targets(snapshot(groups=False)) == {TARGET: "conditional"}
    assert targets(snapshot(resource_groups=False, write_scope=GROUP)) == {TARGET: "conditional"}


def test_write_on_unrelated_resource_or_missing_assignment_cannot_reach_identity():
    assert not targets(snapshot(write_scope=OTHER + "/providers/Microsoft.Storage/storageAccounts/other"))
    assert not targets(snapshot(assign=False))
    assert not targets(snapshot(groups=False, resource_groups=False))


def test_missing_aci_inventory_is_unresolved():
    snap = snapshot(groups=False, resource_groups=False, group_status="denied", rg_status="denied")
    assert TARGET not in targets(snap)
    assert any(target.startswith(("unknown:", "unresolved:")) for target in targets(snap))


def test_missing_identity_inventory_is_unresolved():
    snap = snapshot()
    identity = next(c for c in snap["collections"] if c["type"] == "managed_identity")
    identity["status"] = "denied"
    identity["items"] = []
    assert TARGET not in targets(snap)
    assert any(target.startswith(("unknown:", "unresolved:")) for target in targets(snap))


def test_wrong_resource_types_are_not_treated_as_container_groups():
    snap = snapshot(resource_groups=False)
    group = next(c for c in snap["collections"] if c["type"] == "container_group")
    group["items"][0]["type"] = "Microsoft.Storage/storageAccounts"
    assert not targets(snap)


def test_exec_reaches_native_group_identity_with_running_container():
    assert exec_targets(exec_snapshot()) == {TARGET: "conditional"}
    assert exec_targets(exec_snapshot(container_states=("Terminated", "Running"))) == {
        TARGET: "conditional"}


def test_exec_can_reach_system_identity_on_exact_group():
    snap = exec_snapshot()
    group = next(c for c in snap["collections"] if c["type"] == "container_group")
    group["items"][0]["identity"] = {"type": "SystemAssigned", "principalId": "system-uami"}
    assert exec_targets(snap) == {"system-uami": "conditional"}


def test_exec_does_not_claim_stopped_or_waiting_container_or_unrelated_permission():
    assert TARGET not in exec_targets(exec_snapshot(group_state="Stopped"))
    assert TARGET not in exec_targets(exec_snapshot(container_states=("Waiting",)))
    unrelated = RG + "/providers/Microsoft.ContainerInstance/containerGroups/other"
    assert TARGET not in exec_targets(exec_snapshot(write_scope=unrelated))


def test_exec_missing_runtime_state_is_unresolved():
    snap = exec_snapshot()
    group = next(c for c in snap["collections"] if c["type"] == "container_group")
    del group["items"][0]["properties"]["instanceView"]
    result = exec_targets(snap)
    assert TARGET not in result
    assert any(target.startswith(("unknown:", "unresolved:")) for target in result)


def test_exec_native_group_without_target_identity_cannot_claim_access():
    snap = exec_snapshot()
    group = next(c for c in snap["collections"] if c["type"] == "container_group")
    group["items"][0]["identity"] = {"type": "UserAssigned",
        "userAssignedIdentities": {UAMI: {"principalId": "other-identity"}}}
    assert TARGET not in exec_targets(snap)


def test_exec_missing_native_inventory_is_unresolved():
    snap = exec_snapshot(native_status="denied")
    group = next(c for c in snap["collections"] if c["type"] == "container_group")
    group["items"] = []
    result = exec_targets(snap)
    assert TARGET not in result
    assert any(target.startswith(("unknown:", "unresolved:")) for target in result)


def test_existing_group_write_reaches_attached_uami_or_system_identity():
    assert existing_write_targets(write_snapshot()) == {TARGET: "conditional"}
    snap = write_snapshot()
    group = next(c for c in snap["collections"] if c["type"] == "container_group")
    group["items"][0]["identity"] = {"type": "SystemAssigned", "principalId": "system-uami"}
    assert existing_write_targets(snap) == {"system-uami": "conditional"}


def test_existing_group_write_rejects_terminated_or_unrelated_group():
    assert TARGET not in existing_write_targets(write_snapshot(state="Succeeded"))
    assert TARGET not in existing_write_targets(write_snapshot(state="Failed"))
    unrelated = RG + "/providers/Microsoft.ContainerInstance/containerGroups/other"
    assert TARGET not in existing_write_targets(write_snapshot(write_scope=unrelated))
    snap = write_snapshot()
    group = next(c for c in snap["collections"] if c["type"] == "container_group")
    group["items"][0]["identity"]["userAssignedIdentities"][UAMI]["principalId"] = "other-uami"
    assert TARGET not in existing_write_targets(snap)


def test_existing_group_write_stopped_or_missing_state_is_unresolved():
    for state in ("Stopped", "Pending", ""):
        result = existing_write_targets(write_snapshot(state=state))
        assert TARGET not in result
        assert any(target.startswith(("unknown:", "unresolved:")) for target in result)


def test_existing_group_write_missing_group_inventory_is_unresolved():
    snap = write_snapshot(native_status="denied")
    group = next(c for c in snap["collections"] if c["type"] == "container_group")
    group["items"] = []
    result = existing_write_targets(snap)
    assert TARGET not in result
    assert any(target.startswith(("unknown:", "unresolved:")) for target in result)
