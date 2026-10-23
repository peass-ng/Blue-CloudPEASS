"""Azure / Entra schema extensions: pivot-linked hosts (AVD session hosts, hybrid workers, DevTest lab VMs), workload
consumers of a pivot, identities reached through an intermediate identity, AVD assigned users, Entra Domain Services
joined VMs, custom-security-attribute ABAC conditions, Fabric workspace roles / identities, PIM for Groups, entitlement
catalogs and auto-assignment policies, Intune, group-membership requirements, and principal-specific fact requirements."""
from __future__ import annotations

import pytest

from peaso import privesc
from peaso.privesc.effective_permissions.azure import AzureModel
from tests.test_peaso_privesc_schema_ext import entry, errors_of, reached, snapshot

SUB = "/subscriptions/00000000-0000-0000-0000-00000000aaaa"
RG = f"{SUB}/resourceGroups/rg"
T = "/tenants/t"
ROLE_ID = "11111111-1111-1111-1111-111111111111"
AVD_USER = "1d18fff3-a72a-46b5-b4a9-0b38a3cd7e63"


def _vm(name, principal, extensions=None):
    item = {"id": f"{RG}/providers/Microsoft.Compute/virtualMachines/{name}", "name": name,
            "type": "Microsoft.Compute/virtualMachines", "identity": {"principalId": principal}}
    if extensions is not None:
        item["resources"] = extensions
    return item


def _uami(name, principal):
    return {"id": f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}", "name": name,
            "type": "Microsoft.ManagedIdentity/userAssignedIdentities", "properties": {"principalId": principal, "clientId": name}}


def az(assignments=(), roles=None, users=("u-alice",), sps=(), groups=(), members=None, vms=(), graph=(), extra=()):
    """assignments: (principalId, principalType, scope, roleId[, condition])."""
    roles = roles or {ROLE_ID: (["Microsoft.Authorization/roleAssignments/write"], [])}
    defs = [{"id": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{rid}",
             "properties": {"roleName": name if isinstance(name, str) else f"role-{rid[:4]}", "type": "CustomRole",
                            "assignableScopes": [SUB], "permissions": [{"actions": acts, "dataActions": data}]}}
            for rid, (acts, data, *name) in ((r, (*v[:2], *(v[2:] or [None]))) for r, v in roles.items())]
    for d, (rid, spec) in zip(defs, roles.items()):
        if len(spec) > 2:
            d["properties"]["roleName"] = spec[2]
    ras = []
    for i, a in enumerate(assignments):
        props = {"principalId": a[0], "principalType": a[1], "scope": a[2],
                 "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{a[3]}"}
        if len(a) > 4:
            props.update(condition=a[4], conditionVersion="2.0")
        ras.append({"id": f"{a[2]}/providers/Microsoft.Authorization/roleAssignments/{i}", "properties": props})
    cols = [("subscription", T, [{"id": SUB, "subscriptionId": SUB.rsplit("/", 1)[-1]}]),
            ("role_definition", SUB, defs), ("role_assignment", SUB, ras), ("deny_assignment", SUB, [], "empty"),
            ("directory_user", T, [{"id": u, "userPrincipalName": f"{u}@t.com", "userType": "Member"} for u in users]),
            ("directory_service_principal", T, [{"id": s, "displayName": s, "servicePrincipalType": "Application"} for s in sps]),
            ("directory_group", T, [{"id": g, "displayName": name, "securityEnabled": True} for g, name in groups]),
            ("directory_role_assignment", T, [], "empty"), ("directory_role_definition", T, [], "empty"),
            ("vm", SUB, list(vms), "collected" if vms else "empty"),
            ("resource_graph", SUB, list(graph), "collected" if graph else "empty")]
    if members is not None:
        for gid, ids in members.items():
            cols.append(("directory_membership", f"{T}/groups/{gid}", [{"id": m} for m in ids], "collected" if ids else "empty"))
    cols += list(extra)
    snap = snapshot("azure", cols)
    snap["metadata"] = {"tenant_id": "t"}
    return snap


def run(snap, *entries, **kw):
    return privesc.analyze(snap, entries=list(entries), **kw)


def unresolved(result, source):
    return {t: c for t, c in reached(result, source).items() if t.startswith(("unresolved:", "unknown:"))}


def members(result, source):
    return {t: c for t, c in reached(result, source).items() if not t.startswith(("unresolved:", "unknown:"))}


MI_TARGET = {"kind": "azure_managed_identity", "scope": "any"}


# --------------------------------------------------------- principal-specific fact requirements (regression)
def test_graph_app_permission_requirement_reaches_and_is_not_shared_between_equal_principals():
    graph_items = [{"id": "x", "principalId": "sp-a", "appRoleValue": "User.ReadWrite.All",
                    "appRoleEnabled": True, "resourceId": "graph-sp"}]
    snap = az(sps=("sp-a", "sp-b"), users=("u-v",), extra=[("directory_app_role_assignment", T, graph_items)])
    for collection in snap["collections"]:
        if collection["type"] == "directory_service_principal":
            collection["items"].append({"id": "graph-sp", "appId": "00000003-0000-0000-c000-000000000000",
                                        "servicePrincipalType": "Application"})
    e = entry("azure-t-graph", "azure", {"all_of": [{"graph_app_permission": "User.ReadWrite.All"}]},
              {"kind": "azure_user", "selector": {"any_principal_in_scope": True}, "scope": "tenant"})
    result = run(snap, e)
    # sp-a and sp-b hold identical (empty) RBAC / directory roles: the fact still belongs to sp-a only.
    assert reached(result, "sp-a") == {"u-v": "derived"}
    assert reached(result, "sp-b") == {}


# --------------------------------------------------------- azure_host_linked_to_pivot
APP_GROUP = f"{RG}/providers/Microsoft.DesktopVirtualization/applicationGroups/ag"
HOST_POOL = f"{RG}/providers/Microsoft.DesktopVirtualization/hostPools/hp"
AVD_WRITE = "Microsoft.DesktopVirtualization/applicationgroups/applications/write"


def _avd_entry():
    return entry("azure-t-avd", "azure", {"all_of": [{"action": AVD_WRITE, "scope": "{pivot}"}]},
                 {**MI_TARGET, "selector": {"attached_to_service": "Microsoft.Compute/virtualMachines",
                                            "azure_host_linked_to_pivot": "avd_session_host"}},
                 pivot_resource_type="Microsoft.DesktopVirtualization/applicationGroups")


def _avd_snap(session_hosts):
    graph = [{"id": APP_GROUP, "type": "Microsoft.DesktopVirtualization/applicationGroups", "name": "ag",
              "properties": {"hostPoolArmPath": HOST_POOL}},
             {"id": HOST_POOL, "type": "Microsoft.DesktopVirtualization/hostPools", "name": "hp", "properties": {}}]
    extra = [] if session_hosts is None else [("avd_session_host", HOST_POOL, session_hosts, "collected")]
    return az([("u-alice", "User", RG, ROLE_ID)], roles={ROLE_ID: ([AVD_WRITE], [])},
              vms=[_vm("host1", "mi-host1"), _vm("other", "mi-other")], graph=graph, extra=extra)


def test_avd_session_host_link_resolves_session_host_identities():
    hosts = [{"id": f"{HOST_POOL}/sessionHosts/host1.contoso.local",
              "properties": {"resourceId": f"{RG}/providers/Microsoft.Compute/virtualMachines/host1"}}]
    result = run(_avd_snap(hosts), _avd_entry())
    assert members(result, "u-alice") == {"mi-host1": "conditional"}  # {pivot} entries: pivot_resource_may_need_creation
    assert unresolved(result, "u-alice") == {}                           # the host pool listing is complete


def test_avd_session_host_link_not_collected_is_unresolved_not_member():
    result = run(_avd_snap(None), _avd_entry(), include_unknown=True)
    assert members(result, "u-alice") == {}
    assert set(unresolved(result, "u-alice").values()) == {"unknown"}


def test_host_link_with_no_parent_under_pivot_reaches_nothing():
    snap = az([("u-alice", "User", RG, ROLE_ID)], roles={ROLE_ID: ([AVD_WRITE], [])},
              vms=[_vm("host1", "mi-host1")], graph=[{"id": f"{RG}/providers/Microsoft.Network/virtualNetworks/v",
                                                      "type": "Microsoft.Network/virtualNetworks", "name": "v"}])
    assert reached(run(snap, _avd_entry()), "u-alice") == {}


def test_automation_hybrid_worker_and_devtest_links():
    account = f"{RG}/providers/Microsoft.Automation/automationAccounts/aa"
    workers = [{"id": f"{account}/hybridRunbookWorkerGroups/g/hybridRunbookWorkers/w",
                "properties": {"vmResourceId": f"{RG}/providers/Microsoft.Compute/virtualMachines/host1"}}]
    graph = [{"id": account, "type": "Microsoft.Automation/automationAccounts", "name": "aa"}]
    write = "Microsoft.Automation/automationAccounts/runbooks/write"
    snap = az([("u-alice", "User", RG, ROLE_ID)], roles={ROLE_ID: ([write], [])},
              vms=[_vm("host1", "mi-host1"), _vm("other", "mi-other")], graph=graph,
              extra=[("automation_hybrid_worker", account, workers, "collected")])
    e = entry("azure-t-hw", "azure", {"all_of": [{"action": write, "scope": "{pivot}"}]},
              {**MI_TARGET, "selector": {"azure_host_linked_to_pivot": "automation_hybrid_worker"}})
    assert members(run(snap, e), "u-alice") == {"mi-host1": "conditional"}
    lab = f"{RG}/providers/Microsoft.DevTestLab/labs/lab"
    graph = [{"id": lab, "type": "Microsoft.DevTestLab/labs", "name": "lab"},
             {"id": f"{lab}/virtualMachines/l1", "type": "Microsoft.DevTestLab/labs/virtualMachines", "name": "l1",
              "properties": {"computeId": f"{RG}/providers/Microsoft.Compute/virtualMachines/host1"}}]
    write = "Microsoft.DevTestLab/labs/virtualMachines/applyArtifacts/action"
    snap = az([("u-alice", "User", RG, ROLE_ID)], roles={ROLE_ID: ([write], [])},
              vms=[_vm("host1", "mi-host1"), _vm("other", "mi-other")], graph=graph)
    e = entry("azure-t-dtl", "azure", {"all_of": [{"action": write, "scope": "{pivot}"}]},
              {**MI_TARGET, "selector": {"azure_host_linked_to_pivot": "devtest_lab_compute_vm"}})
    result = run(snap, e, include_unknown=True)
    assert members(result, "u-alice") == {"mi-host1": "conditional"}  # {pivot} entries: pivot_resource_may_need_creation
    assert set(unresolved(result, "u-alice").values()) == {"unknown"}   # lab VM listing not authoritative


# --------------------------------------------------------- azure_consumer_of_pivot
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/kv"
SET_SECRET = "Microsoft.KeyVault/vaults/secrets/setSecret/action"
GET_SECRET = "Microsoft.KeyVault/vaults/secrets/getSecret/action"
READER_ROLE = "22222222-2222-2222-2222-222222222222"


def test_consumer_of_pivot_reader_identities_are_conditional_others_unresolved():
    snap = az([("u-alice", "User", RG, ROLE_ID), ("mi-reader", "ServicePrincipal", VAULT, READER_ROLE)],
              roles={ROLE_ID: ([], [SET_SECRET]), READER_ROLE: ([], [GET_SECRET])},
              vms=[_vm("app", "mi-reader"), _vm("other", "mi-other")],
              graph=[{"id": VAULT, "type": "Microsoft.KeyVault/vaults", "name": "kv"}])
    e = entry("azure-t-kv", "azure", {"all_of": [{"action": SET_SECRET, "data_action": True, "scope": "{pivot}"}]},
              {**MI_TARGET, "selector": {"azure_consumer_of_pivot": "key_vault_reference"}})
    result = run(snap, e, include_unknown=True)
    assert members(result, "u-alice") == {"mi-reader": "conditional"}
    assert set(unresolved(result, "u-alice").values()) == {"unknown"}


# --------------------------------------------------------- azure_assignable_via_identity_holding
def test_identity_reached_through_an_intermediate_assignable_identity():
    assign = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
    tmpl = _uami("tmpl", "mi-tmpl")["id"]
    snap = az([("u-alice", "User", tmpl, ROLE_ID), ("mi-tmpl", "ServicePrincipal", _uami("build", "mi-build")["id"], ROLE_ID)],
              roles={ROLE_ID: ([assign], [])},
              graph=[_uami("tmpl", "mi-tmpl"), _uami("build", "mi-build"), _uami("far", "mi-far")])
    e = entry("azure-t-ib", "azure", {"all_of": [{"action": "Microsoft.VirtualMachineImages/imageTemplates/write"}]},
              {**MI_TARGET, "selector": {"managed_identity_type": "user_assigned",
                                         "azure_assignable_via_identity_holding": assign}})
    snap["collections"][1]["items"][0]["properties"]["permissions"][0]["actions"].append(
        "Microsoft.VirtualMachineImages/imageTemplates/write")
    result = run(snap, e)
    assert members(result, "u-alice") == {"mi-build": "derived"}
    edge = next(x for x in result["graph"]["edges"] if x["source"] == "u-alice")
    assert any("via_intermediate_identity:tmpl" in str(c) for d in edge["technique_details"] for c in d.get("conditions", []))


# --------------------------------------------------------- AVD assigned users
def test_avd_users_assigned_to_pivot():
    snap = az([("u-alice", "User", RG, ROLE_ID), ("u-bob", "User", APP_GROUP, AVD_USER), ("g-1", "Group", APP_GROUP, AVD_USER)],
              roles={ROLE_ID: ([AVD_WRITE], []), AVD_USER: ([], [], "Desktop Virtualization User")},
              users=("u-alice", "u-bob", "u-carol", "u-dan"), groups=[("g-1", "avd users")], members={"g-1": ["u-carol"]},
              graph=[{"id": APP_GROUP, "type": "Microsoft.DesktopVirtualization/applicationGroups", "name": "ag",
                      "properties": {"hostPoolArmPath": HOST_POOL}}])
    e = entry("azure-t-avdu", "azure", {"all_of": [{"action": AVD_WRITE, "scope": "{pivot}"}]},
              {"kind": "azure_user", "selector": {"azure_users_assigned_to_pivot": True}, "scope": "tenant",
               "outcome": "credentials"})
    assert members(run(snap, e), "u-alice") == {"u-bob": "conditional", "u-carol": "conditional"}


# --------------------------------------------------------- Entra Domain Services joined VMs + group membership requirement
def _ds_snap(membership=True, ds=True):
    join = [{"properties": {"type": "JsonADDomainExtension", "settings": {"Name": "aadds.contoso.com"}}}]
    graph = [{"id": f"{RG}/providers/Microsoft.AAD/domainServices/aadds.contoso.com", "type": "Microsoft.AAD/domainServices",
              "name": "aadds", "properties": {"domainName": "aadds.contoso.com"}}] if ds else []
    return az(groups=[("g-dc", "AAD DC Administrators")], members={"g-dc": ["u-alice"]} if membership else None,
              vms=[_vm("joined", "mi-joined", join), _vm("plain", "mi-plain", [])], graph=graph)


DS_ENTRY = entry("azure-t-ds", "azure", {"all_of": [{"entra_group_member": "AAD DC Administrators"}]},
                 {**MI_TARGET, "selector": {"attached_to_vm_joined_to_entra_domain_services": True}})


def test_aad_dc_administrators_reach_domain_joined_vm_identities():
    result = run(_ds_snap(), DS_ENTRY, include_unknown=True)
    assert members(result, "u-alice") == {"mi-joined": "conditional"}
    assert set(unresolved(result, "u-alice").values()) == {"unknown"}   # mi-plain may be joined without the extension
    assert reached(run(_ds_snap(ds=False), DS_ENTRY), "u-alice") == {}   # no managed domain inventoried anywhere


def test_group_member_requirement_unknown_when_membership_not_collected():
    model = AzureModel(_ds_snap(membership=False))
    assert model.global_unknown({"entra_group_member": "AAD DC Administrators"})
    model = AzureModel(_ds_snap())
    alice = model.principals["u-alice"]
    assert model.check(alice, {"entra_group_member": "aad dc administrators"}, None).confidence == "derived"


# --------------------------------------------------------- custom security attributes in ABAC conditions
CSA = ("((!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'})) OR "
       "(@Principal[Microsoft.Directory/CustomSecurityAttributes/Id:Eng_Project] StringEquals 'cascade'))")


def test_condition_on_principal_custom_security_attribute():
    account = f"{RG}/providers/Microsoft.Storage/storageAccounts/sa"
    blob = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    snap = az([("u-alice", "User", RG, READER_ROLE, CSA)], roles={READER_ROLE: ([], [blob])},
              graph=[{"id": account, "type": "Microsoft.Storage/storageAccounts", "name": "sa"}],
              extra=[("directory_role_assignment", T, [{"id": "ra", "principalId": "u-alice", "directoryScopeId": "/",
                                                        "roleDefinitionId": "aaaa"}], "collected"),
                     ("directory_role_definition", T, [{"id": "aaaa", "templateId": "aaaa",
                                                        "displayName": "Attribute Assignment Administrator"}], "collected")])
    snap["collections"] = [c for c in snap["collections"] if not (c["type"].startswith("directory_role_") and not c["items"])]
    e = entry("azure-t-csa", "azure", {"all_of": [{"entra_role": "Attribute Assignment Administrator"}]},
              {"kind": "azure_dataplane_admin", "selector": {"azure_assignment_condition_uses_principal_attribute": True},
               "scope": "any", "outcome": "permission_grant"})
    assert members(run(snap, e), "u-alice") == {f"azure_dataplane_admin:{account.lower()}": "conditional"}


# --------------------------------------------------------- Fabric
def _fabric_snap(role="Contributor", collected=True):
    extra = [("fabric_workspace", T, [{"id": "WS1", "workspaceIdentity": {"servicePrincipalId": "sp-ws1"}},
                                      {"id": "WS2", "workspaceIdentity": {"servicePrincipalId": "sp-ws2"}}])]
    if collected:
        extra.append(("fabric_workspace_role_assignment", T,
                      [{"id": "r1", "workspaceId": "WS1", "principal": {"id": "u-alice", "type": "User"}, "role": role}]))
    return az(sps=("sp-ws1", "sp-ws2", "sp-app"), extra=extra)


FABRIC_ENTRY = entry("azure-t-fabric", "azure",
                     {"all_of": [{"fabric_workspace_role": "Contributor", "fabric_workspace": "{target.host_resource}"}]},
                     {"kind": "azure_service_principal", "selector": {"fabric_workspace_identity": True}, "scope": "any",
                      "outcome": "workload_execution"})


@pytest.mark.parametrize("role,expected", [("Admin", {"sp-ws1": "derived"}), ("Contributor", {"sp-ws1": "derived"}),
                                           ("Viewer", {})])
def test_fabric_workspace_role_on_the_identity_workspace(role, expected):
    assert members(run(_fabric_snap(role), FABRIC_ENTRY), "u-alice") == expected


def test_fabric_role_assignments_not_collected_is_unknown():
    model = AzureModel(_fabric_snap(collected=False))
    assert "fabric_workspace_role_assignment" in model.global_unknown({"fabric_workspace_role": "Contributor"})


# --------------------------------------------------------- PIM for Groups
def test_pim_group_eligibility_selector():
    sched = [{"id": "e1", "principalId": "u-alice", "groupId": "g-priv", "accessId": "member", "status": "Provisioned"},
             {"id": "e2", "principalId": "u-alice", "groupId": "g-own", "accessId": "owner", "status": "Revoked"}]
    snap = az(groups=[("g-priv", "priv"), ("g-own", "own"), ("g-x", "x")], members={},
              extra=[("directory_group_eligibility_schedule", T, sched)])
    for collection in snap["collections"]:
        if collection["type"] == "directory_group":
            for group in collection["items"]:
                group.update({"groupTypes": [], "mailEnabled": False, "onPremisesSyncEnabled": False})
    e = entry("azure-t-pimg", "azure", {}, {"kind": "entra_group", "selector": {"entra_pim_group_eligible_for_source": True},
                                            "scope": "tenant"}, source_kind="azure_user")
    assert members(run(snap, e), "u-alice") == {"g-priv": "conditional"}
    snap = az(groups=[("g-priv", "priv")], members={})
    assert members(run(snap, e), "u-alice") == {}                         # not collected: unresolved only


# --------------------------------------------------------- entitlement management catalogs / auto-assignment
def _catalog_snap(role="Catalog owner", scope="/AccessPackageCatalog/cat1"):
    extra = [("entitlement_role_assignment", T, [{"id": "a1", "principalId": "u-alice", "roleDefinitionId": "rd",
                                                  "roleDefinition": {"displayName": role}, "appScopeId": scope}]),
             ("entitlement_catalog_resource", T, [{"catalogId": "cat1", "originId": "g-in", "originSystem": "AadGroup"},
                                                   {"catalogId": "cat2", "originId": "g-other", "originSystem": "AadGroup"}])]
    return az(groups=[("g-in", "in"), ("g-other", "other"), ("g-none", "none")], members={}, extra=extra)


CATALOG_ENTRY = entry("azure-t-cat", "azure", {"all_of": [{"entra_catalog_role": "Catalog owner", "catalog": "{target.catalog}"}]},
                      {"kind": "entra_group", "selector": {"entra_resource_in_catalog": True}, "scope": "tenant"},
                      blockers=["access_package_approval_by_other_principal"])


def test_catalog_role_reaches_resources_of_that_catalog_only():
    assert members(run(_catalog_snap(), CATALOG_ENTRY), "u-alice") == {"g-in": "derived"}
    assert members(run(_catalog_snap(scope="/"), CATALOG_ENTRY), "u-alice") == {"g-in": "derived", "g-other": "derived"}
    assert members(run(_catalog_snap(role="Catalog reader"), CATALOG_ENTRY), "u-alice") == {}


def test_access_package_auto_assignment_open_to_guest():
    policies = [{"accessPackageId": "ap1", "allowedTargetScope": "specificDirectoryUsers",
                 "automaticRequestSettings": {"requestAccessForAllowedTargets": True},
                 "specificAllowedTargets": [{"membershipRule": 'user.department -eq "Sales"'}]},
                {"accessPackageId": "ap2", "allowedTargetScope": "specificDirectoryUsers",
                 "automaticRequestSettings": {"requestAccessForAllowedTargets": True},
                 "specificAllowedTargets": [{"membershipRule": 'user.userType -eq "Member"'}]}]
    resources = [{"accessPackageId": "ap1", "originId": "g-open"}, {"accessPackageId": "ap2", "originId": "g-members"}]
    snap = az(groups=[("g-open", "o"), ("g-members", "m")], members={},
              extra=[("entitlement_assignment_policy", T, policies), ("entitlement_access_package_resource", T, resources),
                     ("directory_authorization_policy", T, [{"id": "p", "allowInvitesFrom": "everyone"}])])
    e = entry("azure-t-auto", "azure", {"all_of": [{"entra_tenant_setting": "guest_invites_allowed_for_source"}]},
              {"kind": "entra_group", "selector": {"entra_access_package_auto_assignment_open_to_guest": True}, "scope": "tenant"})
    assert members(run(snap, e), "u-alice") == {"g-open": "conditional"}


# --------------------------------------------------------- Intune
def test_intune_permission_and_managed_device_users():
    assignments = [{"id": "ia", "members": ["g-intune"], "roleDefinition": {"displayName": "Script admin", "rolePermissions": [
        {"resourceActions": [{"allowedResourceActions": ["Microsoft.Intune_DeviceConfigurations_Assign"]}]}]}}]
    snap = az(users=("u-alice", "u-bob", "u-carol"), groups=[("g-intune", "intune ops")], members={"g-intune": ["u-alice"]},
              extra=[("intune_role_assignment", T, assignments),
                     ("intune_managed_device", T, [{"id": "d1", "userId": "u-bob", "operatingSystem": "Windows"}])])
    e = entry("azure-t-intune", "azure", {"all_of": [{"intune_permission": "Microsoft.Intune_DeviceConfigurations_Assign"}]},
              {"kind": "azure_user", "selector": {"intune_managed_device_user": True}, "scope": "tenant", "outcome": "credentials"},
              blockers=["intune_multi_admin_approval_required"])
    result = run(snap, e)
    assert members(result, "u-alice") == {"u-bob": "conditional"}
    assert reached(result, "u-carol") == {}


# --------------------------------------------------------- validation
@pytest.mark.parametrize("requires,target,message", [
    ({"all_of": [{"fabric_workspace_role": "Owner"}]}, FABRIC_ENTRY["target"], "fabric_workspace_role must be one of"),
    ({"all_of": [{"entra_group_member": "g", "fabric_workspace": "x"}]}, MI_TARGET, "fabric_workspace is only valid"),
    ({"all_of": [{"entra_catalog_role": "Catalog owner", "catalog": ""}]}, CATALOG_ENTRY["target"], "catalog must be"),
    ({"all_of": [{"action": "a/b"}]}, {**MI_TARGET, "selector": {"azure_host_linked_to_pivot": "nope"}}, "must be one of"),
    ({"all_of": [{"action": "a/b"}]}, {**MI_TARGET, "selector": {"azure_consumer_of_pivot": ["key_vault_reference", "x"]}},
     "must be one or a list of"),
    ({"all_of": [{"action": "a/b"}]}, {"kind": "entra_group", "selector": {"entra_pim_group_eligible_for_source": "admin"}},
     "must be true or one of"),
    ({"all_of": [{"action": "a/b"}]}, {"kind": "azure_user", "selector": {"fabric_workspace_identity": True}},
     "needs target kind azure_service_principal"),
    ({"all_of": [{"action": "a/b"}]}, {"kind": "entra_group", "selector": {"azure_users_assigned_to_pivot": True}},
     "needs target kind azure_user"),
])
def test_validation(requires, target, message):
    errs = errors_of(entry("azure-t-bad", "azure", requires, target))
    assert any(message in e for e in errs), errs


def test_valid_entries_pass_validation():
    for e in (FABRIC_ENTRY, CATALOG_ENTRY, DS_ENTRY, _avd_entry()):
        assert errors_of(e) == [], errors_of(e)
