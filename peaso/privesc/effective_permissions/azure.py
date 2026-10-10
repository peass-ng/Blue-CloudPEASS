"""Azure RBAC + Entra ID effective permissions.

RBAC: role assignments x role definitions (Actions/NotActions, DataActions/
NotDataActions) with scope inheritance root -> management groups ->
subscription -> resource group -> resource, group membership (transitive),
ABAC conditions -> conditional, deny assignments remove permissions (not
collected -> conditional).

Entra: directory role assignments (directoryScopeId '/', '/<objectId>' or
'/administrativeUnits/<id>') x directory role definitions
(rolePermissions.allowedResourceActions). Graph application permissions, owners,
PIM eligibility, AUs and tenant settings are only evaluated when their
collections exist; otherwise the requirement is reported as globally unknown
(coverage + aggregated unknown edges).
"""
from __future__ import annotations

import re

from . import ANY, Grant, Model, Node, as_list, downgrade, glob_match, inventory_status, items, unavailable

OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
UAA = "18d7d88d-d35e-4fb5-a5c3-7773c4a72d9d"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
EVERYONE = "00000000-0000-0000-0000-000000000000"
BUILTIN_ROLES = {
    OWNER: ("Owner", [{"actions": ["*"]}]),
    CONTRIBUTOR: ("Contributor", [{"actions": ["*"], "notActions": [
        "Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/elevateAccess/Action",
        "Microsoft.Blueprint/blueprintAssignments/write", "Microsoft.Blueprint/blueprintAssignments/delete",
        "Microsoft.Compute/galleries/share/action", "Microsoft.Purview/consents/write", "Microsoft.Purview/consents/delete",
        "Microsoft.Resources/deploymentStacks/manageDenySetting/action", "Microsoft.Subscription/cancel/action",
        "Microsoft.Subscription/enable/action"]}]),
    UAA: ("User Access Administrator", [{"actions": ["*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"]}]),
    READER: ("Reader", [{"actions": ["*/read"]}]),
}
# Microsoft "who can reset passwords" matrix: roles a target may hold for each column.
RESET_MATRIX = {
    "non_admin_only": set(),
    "password_admin": {"directory readers", "guest inviter", "password administrator"},
    "helpdesk_admin": {"directory readers", "global reader", "guest inviter", "helpdesk administrator", "message center reader",
                       "password administrator", "reports reader", "usage summary reports reader"},
    "authentication_admin": {"authentication administrator", "directory readers", "global reader", "guest inviter",
                             "helpdesk administrator", "message center reader", "password administrator", "reports reader",
                             "usage summary reports reader"},
    "user_admin": {"directory readers", "global reader", "guest inviter", "helpdesk administrator", "message center reader",
                   "password administrator", "reports reader", "user administrator", "usage summary reports reader"},
    "privileged_auth_admin": None,  # every user
}
FACT_COLLECTIONS = {
    "graph_app_permission": "directory_app_role_assignment",
    "entra_owner_of": "directory_owner",
    "entra_pim_eligible_role": "directory_role_eligibility_schedule",
    "entra_tenant_setting": "directory_authorization_policy",
}


CONTROLLED_USER = ("source.controlled_user", "target.user")


def _low(value):
    return str(value or "").lower()


def _guid(rid):
    return _low(rid).rstrip("/").rsplit("/", 1)[-1]


class RoleDef:
    __slots__ = ("id", "name", "actions", "not_actions", "data", "not_data", "custom", "scopes")

    def __init__(self, rid, name, permissions, custom=False, scopes=()):
        self.id, self.name, self.custom, self.scopes = rid, name, custom, tuple(_low(s) for s in scopes)
        self.actions, self.not_actions, self.data, self.not_data = [], [], [], []
        for p in as_list(permissions):
            if not isinstance(p, dict):
                continue
            self.actions += [_low(a) for a in as_list(p.get("actions"))]
            self.not_actions += [_low(a) for a in as_list(p.get("notActions"))]
            self.data += [_low(a) for a in as_list(p.get("dataActions"))]
            self.not_data += [_low(a) for a in as_list(p.get("notDataActions"))]

    def allows(self, action, data=False):
        allow, deny = (self.data, self.not_data) if data else (self.actions, self.not_actions)
        return any(glob_match(a, action) for a in allow) and not any(glob_match(a, action) for a in deny)


class AzureModel(Model):
    provider = "azure"

    def __init__(self, snapshot, catalog_keys=()):
        super().__init__(snapshot, catalog_keys)
        self.roles, self.assignments, self.denies = {}, {}, []
        self.parents = {}
        self.scopes = set()
        self.members_of = {}         # object id -> set(group ids) (direct)
        self.dir_roles, self.dir_assignments = {}, {}
        self.dir_objects = {}
        self.resources = {}          # arm id (lower) -> item (type lower, kind, identity)
        self.mi_by_principal = {}
        self.deny_status = {}
        self.tenant = str((snapshot.get("metadata") or {}).get("tenant_id") or "tenant")
        self.app_ids = None
        self._load()
        self.require_collections(("role_assignment", "role_definition"), {
            "role_assignment": "Azure RBAC grants are unknown for this scope",
            "role_definition": "Custom role permissions are unknown (built-in Owner/Contributor/UAA/Reader are known)"})
        for kind, impact in (("directory_role_assignment", "Entra directory role grants are unknown"),
                             ("directory_role_definition", "Entra directory role permissions are unknown"),
                             ("directory_membership", "Group-inherited RBAC/Entra grants are unknown")):
            if not inventory_status(snapshot, kind):
                self.add_coverage("collection", "*", "not_collected", f"{kind} not in snapshot", impact)
        for kind, collection in FACT_COLLECTIONS.items():
            if not inventory_status(snapshot, collection):
                self.add_coverage("collection", f"/tenants/{self.tenant}", "not_collected", f"{collection} not in snapshot",
                                  f"Requirements of type {kind} are unknown")
        if not inventory_status(snapshot, "deny_assignment"):
            self.add_coverage("guardrail", "*", "not_collected", "deny_assignment not in snapshot",
                              "Edges are conditional: deny assignments may block them")
        for scope, status in unavailable(inventory_status(snapshot, "deny_assignment")).items():
            self.add_coverage("guardrail", scope, status, f"deny_assignment collection {status}",
                              "Edges under this scope are conditional: deny assignments may block them")

    # ----------------------------------------------------------------- load
    def _load(self):
        snap = self.snapshot
        for rid, (name, perms) in BUILTIN_ROLES.items():
            self.roles[rid] = RoleDef(rid, name, perms)
        for scope, item in items(snap, "role_definition"):
            props = item.get("properties") or {}
            rid = _guid(item.get("id") or item.get("name"))
            self.roles[rid] = RoleDef(rid, props.get("roleName", rid), props.get("permissions"),
                                      custom=props.get("type") == "CustomRole", scopes=props.get("assignableScopes") or [])
        for scope, item in items(snap, "management_group"):
            self._mg_tree(item.get("id"), (item.get("properties") or {}).get("children"))
            parent = ((item.get("properties") or {}).get("details") or {}).get("parent") or {}
            if parent.get("id") and item.get("id"):
                self.parents.setdefault(_low(item["id"]), _low(parent["id"]))
        for scope, item in items(snap, "subscription"):
            sid = _low(item.get("id") or f"/subscriptions/{item.get('subscriptionId')}")
            self.scopes.add(sid)
        for scope, item in items(snap, "resource_group"):
            if item.get("id"):
                self.scopes.add(_low(item["id"]))
        for kind in ("directory_user", "directory_service_principal", "directory_group"):
            for scope, item in items(snap, kind):
                if item.get("id"):
                    self._directory_principal(kind, item)
        for scope, item in items(snap, "directory_application"):
            self.app_ids = self.app_ids or {}
            if item.get("appId"):
                self.app_ids[_low(item["appId"])] = item
        for scope, item in items(snap, "directory_membership"):
            group = scope.rstrip("/").rsplit("/", 1)[-1]
            if item.get("id"):
                self.members_of.setdefault(item["id"], set()).add(group)
        self.membership_status = {s.rsplit("/", 1)[-1]: st for s, st in inventory_status(snap, "directory_membership").items()}
        for scope, item in items(snap, "directory_role_definition"):
            template = _low(item.get("templateId") or item.get("id"))
            actions = [_low(a) for p in as_list(item.get("rolePermissions")) for a in as_list((p or {}).get("allowedResourceActions"))]
            self.dir_roles[template] = {"id": template, "name": item.get("displayName", template), "actions": actions,
                                        "builtin": item.get("isBuiltIn", True), "def_id": _low(item.get("id"))}
            self.dir_roles.setdefault(_low(item.get("id")), self.dir_roles[template])
        for scope, item in items(snap, "directory_role_assignment"):
            pid = item.get("principalId")
            if pid:
                self.dir_assignments.setdefault(pid, []).append(
                    (_low(item.get("roleDefinitionId")), item.get("directoryScopeId") or "/", item.get("id")))
        # Resources and their managed identities.
        for kind in ("vm", "app_service", "aks_cluster", "storage_account", "vault", "sql_server", "resource_graph"):
            for scope, item in items(snap, kind):
                rid = _low(item.get("id"))
                if not rid:
                    continue
                entry = self.resources.setdefault(rid, {"id": item.get("id"), "type": _low(item.get("type")),
                                                        "kind": _low(item.get("kind")), "typed": False, "name": item.get("name")})
                if kind != "resource_graph":
                    entry["typed"] = True
                    entry["kind"] = _low(item.get("kind")) or entry["kind"]
                self._identity(item, entry)
                if entry["type"] == "microsoft.managedidentity/userassignedidentities":
                    props = item.get("properties") or {}
                    if props.get("principalId"):
                        mi = self._mi(props["principalId"], "user_assigned", item.get("id"))
                        mi.attrs["client_id"] = props.get("clientId")
        self.typed_types = {r["type"] for r in self.resources.values() if r["typed"]}
        for scope, item in items(snap, "role_assignment"):
            props = item.get("properties") or {}
            pid = props.get("principalId")
            if not pid:
                continue
            scope_id = _low(props.get("scope") or scope)
            self.scopes.add(scope_id)
            self.assignments.setdefault(pid, []).append({
                "role": _guid(props.get("roleDefinitionId")), "scope": scope_id, "condition": bool(props.get("condition")),
                "id": item.get("id"), "principal_type": props.get("principalType")})
            if pid not in self.principals:
                kind = {"User": "azure_user", "Group": "entra_group", "ServicePrincipal": "azure_service_principal"}.get(
                    props.get("principalType"), "azure_service_principal")
                node = Node(pid, kind, "azure", f"/tenants/{self.tenant}", pid, attrs={"object_id": pid, "directory": False})
                node.incomplete.append("principal not in directory inventory")
                self.principals[pid] = node
        for scope, status in inventory_status(snap, "deny_assignment").items():
            self.deny_status[_low(scope)] = status
        for scope, item in items(snap, "deny_assignment"):
            props = item.get("properties") or {}
            self.denies.append({"scope": _low(props.get("scope") or scope), "perms": RoleDef("deny", "deny", props.get("permissions")),
                                "principals": {p.get("id") for p in as_list(props.get("principals")) if isinstance(p, dict)},
                                "exclude": {p.get("id") for p in as_list(props.get("excludePrincipals")) if isinstance(p, dict)},
                                "id": item.get("id")})
        # Transitive group closure and permission keys.
        for node in self.principals.values():
            groups = self._groups(node.id)
            node.attrs["groups"] = sorted(groups)
            rbac = tuple(sorted((a["role"], a["scope"], a["condition"]) for pid in [node.id, *groups] for a in self.assignments.get(pid, [])))
            entra = tuple(sorted((r, s) for pid in [node.id, *groups] for r, s, _ in self.dir_assignments.get(pid, [])))
            node.perm_key = (rbac, entra, node.id if self.denies else None)
            if node.kind != "entra_group" and self.membership_status and not self.members_of.get(node.id) and \
                    any(st not in ("collected", "empty") for st in self.membership_status.values()):
                node.incomplete.append("group membership partially collected")

    def _mg_tree(self, parent, children):
        for child in as_list(children):
            if isinstance(child, dict) and child.get("id"):
                self.parents.setdefault(_low(child["id"]), _low(parent))
                self.scopes.add(_low(child["id"]))
                self._mg_tree(child["id"], child.get("children"))
        if parent:
            self.scopes.add(_low(parent))

    def _directory_principal(self, kind, item):
        oid = item["id"]
        self.dir_objects[oid] = item
        if kind == "directory_user":
            node_kind = "azure_user"
        elif kind == "directory_group":
            node_kind = "entra_group"
        elif item.get("servicePrincipalType") == "ManagedIdentity":
            node_kind = "azure_managed_identity"
        else:
            node_kind = "azure_service_principal"
        label = item.get("userPrincipalName") or item.get("displayName") or oid
        node = self.principals.get(oid) or Node(oid, node_kind, "azure", f"/tenants/{self.tenant}", label)
        node.kind, node.label = node_kind, label
        node.attrs.update(object_id=oid, directory=True, upn=item.get("userPrincipalName"), app_id=item.get("appId"),
                          sp_type=item.get("servicePrincipalType"), group_types=item.get("groupTypes"),
                          security_enabled=item.get("securityEnabled"), assignable_to_role=item.get("isAssignableToRole"),
                          membership_rule=item.get("membershipRule"), user_type=item.get("userType"),
                          app_owner_org=_low(item.get("appOwnerOrganizationId")))
        node.attrs.setdefault("hosts", [])
        self.principals[oid] = node

    def _mi(self, principal_id, mi_type, uai=None):
        node = self.principals.get(principal_id)
        if node is None:
            node = Node(principal_id, "azure_managed_identity", "azure", f"/tenants/{self.tenant}", principal_id,
                        attrs={"object_id": principal_id, "directory": False, "hosts": []})
            self.principals[principal_id] = node
        node.kind = "azure_managed_identity"
        node.attrs.setdefault("hosts", [])
        node.attrs["mi_type"] = mi_type
        if uai:
            node.attrs["uai_resource"] = _low(uai)
            node.label = uai.rstrip("/").rsplit("/", 1)[-1]
            node.scope = _subscription(uai) or node.scope
        return node

    def _identity(self, item, entry):
        identity = item.get("identity") or {}
        if not isinstance(identity, dict):
            return
        if identity.get("principalId"):
            mi = self._mi(identity["principalId"], "system_assigned")
            mi.attrs["hosts"].append(_low(item["id"]))
            mi.label = f"{item.get('name')} (system-assigned)"
            mi.scope = _subscription(item["id"]) or mi.scope
        for uai, detail in (identity.get("userAssignedIdentities") or {}).items():
            pid = (detail or {}).get("principalId")
            if pid:
                mi = self._mi(pid, "user_assigned", uai)
                if _low(item["id"]) not in mi.attrs["hosts"]:
                    mi.attrs["hosts"].append(_low(item["id"]))

    def _groups(self, oid):
        seen, stack = set(), list(self.members_of.get(oid, ()))
        while stack:
            group = stack.pop()
            if group in seen:
                continue
            seen.add(group)
            stack.extend(self.members_of.get(group, ()))
        return seen

    # ------------------------------------------------------------- hierarchy
    def ancestors(self, ref):
        ref = _low(ref).rstrip("/") or "/"
        chain = []
        parts = ref.split("/")
        # /subscriptions/s/resourcegroups/rg/providers/ns/type/name[/sub/name...]
        for i in range(len(parts), 1, -1):
            prefix = "/".join(parts[:i])
            if prefix and not prefix.endswith(("/providers", "/resourcegroups", "/subscriptions")):
                chain.append(prefix)
        node = _subscription(ref) or ref
        seen = set(chain)
        while node and node in self.parents and self.parents[node] not in seen:
            node = self.parents[node]
            chain.append(node)
            seen.add(node)
        chain.append("/")
        return chain

    def covers(self, outer, ref):
        """(covered, confidence) for an assignment scope over a ref."""
        outer = _low(outer).rstrip("/") or "/"
        if outer == "/":
            return True, "derived"
        chain = self.ancestors(ref)
        if outer in chain:
            return True, "derived"
        if "/managementgroups/" in outer and _subscription(ref) and not any("/managementgroups/" in c for c in chain):
            return True, "conditional"  # hierarchy not collected
        return False, None

    # ------------------------------------------------------------- interface
    def requirement_key(self, req):
        if "action" in req:
            return ("data:" if req.get("data_action") else "rbac:") + _low(req["action"])
        if "entra_permission" in req:
            return "entra_perm:" + _low(req["entra_permission"])
        if "entra_role" in req:
            return "entra_role:" + _low(req["entra_role"])
        if "graph_app_permission" in req:
            return "graph:" + _low(req["graph_app_permission"])
        if "entra_owner_of" in req:
            return "owner:" + _low(req.get("object_type"))
        if "entra_pim_eligible_role" in req:
            return "pim"
        if "entra_tenant_setting" in req:
            return "tenant:" + _low(req["entra_tenant_setting"])
        return "?"

    def requirement_template(self, req):
        if "entra_owner_of" in req:
            return req["entra_owner_of"]
        if "entra_pim_eligible_role" in req:
            return req["entra_pim_eligible_role"]
        value = req.get("scope", req.get("directory_scope"))
        return None if value in (None, "*") else value

    def localizable(self, req):
        return "action" in req and self.requirement_template(req) is None

    def global_unknown(self, req):
        for kind, collection in FACT_COLLECTIONS.items():
            if kind in req and not inventory_status(self.snapshot, collection):
                from ..schema import FACTS_NEEDED
                return FACTS_NEEDED.get(kind, collection)
        return None

    def unknown_holders(self, req):
        if "graph_app_permission" in req:
            return {n.id for n in self.principals.values() if n.kind in ("azure_service_principal", "azure_managed_identity")}
        if "entra_tenant_setting" in req:
            return {n.id for n in self.principals.values() if n.kind == "azure_user"}
        return {n.id for n in self.principals.values() if n.kind != "entra_group"} if "entra_owner_of" not in req else \
            {n.id for n in self.principals.values() if n.kind in ("azure_user", "azure_service_principal", "azure_managed_identity")}

    def sources(self):
        return [n for n in self.principals.values()]

    def possible(self, principal):
        key = ("possible", principal.perm_key)
        if key in self._check_cache:
            return self._check_cache[key]
        keys, universal = set(), False
        rbac_keys = [k for k in self.catalog_keys if isinstance(k, str) and k.startswith(("rbac:", "data:"))]
        for role, scope, cond in principal.perm_key[0]:
            definition = self.roles.get(role)
            if definition is None:
                continue
            for k in rbac_keys:
                if definition.allows(k[5:], k.startswith("data:")):
                    keys.add(k)
        for role, scope in principal.perm_key[1]:
            info = self.dir_roles.get(role)
            if info is None:
                continue
            keys.add("entra_role:" + _low(info["name"]))
            keys.add("entra_role:" + info["id"])
            for k in self.catalog_keys:
                if isinstance(k, str) and k.startswith("entra_perm:") and any(glob_match(a, k[11:]) for a in info["actions"]):
                    keys.add(k)
        self._check_cache[key] = (frozenset(keys), universal)
        return self._check_cache[key]

    def _rbac(self, principal, action, data, ref):
        best_grant = None
        for pid in [principal.id, *principal.attrs.get("groups", [])]:
            for a in self.assignments.get(pid, []):
                definition = self.roles.get(a["role"])
                if definition is None or not definition.allows(action, data):
                    continue
                if ref is ANY:
                    ok, conf = True, "derived"
                else:
                    ok, conf = self.covers(a["scope"], ref)
                if not ok:
                    continue
                conditions = []
                if a["condition"]:
                    conf, conditions = "conditional", ["role_assignment_condition"]
                if conf == "conditional" and not conditions:
                    conditions = ["management_group_hierarchy_not_collected"]
                if pid != principal.id:
                    conditions.append("via_group_membership")
                grant = Grant(conf, [{"assignment": a["id"], "role": definition.name, "scope": a["scope"], "via": pid}], conditions)
                if best_grant is None or (best_grant.confidence != "derived" and conf == "derived"):
                    best_grant = grant
        if best_grant is None:
            return None
        return self._deny(principal, action, data, ref, best_grant)

    def _deny(self, principal, action, data, ref, grant):
        ids = {principal.id, EVERYONE, *principal.attrs.get("groups", [])}
        for deny in self.denies:
            if not (deny["principals"] & ids) or principal.id in deny["exclude"]:
                continue
            if not deny["perms"].allows(action, data):
                continue
            if ref is ANY:
                grant = downgrade(grant, "conditional", "deny_assignment_may_apply")
                continue
            if self.covers(deny["scope"], ref)[0]:
                return None
        if not self.deny_status:
            return downgrade(grant, "conditional", "deny_assignments_not_collected")
        if ref is not ANY:
            chain = self.ancestors(ref)
            if any(self.deny_status.get(s) not in (None, "collected", "empty") for s in chain):
                grant = downgrade(grant, "conditional", "deny_assignments_not_collected")
        return grant

    def _entra(self, principal, req, ref):
        key = self.requirement_key(req)
        best_grant = None
        for pid in [principal.id, *principal.attrs.get("groups", [])]:
            for role, scope, aid in self.dir_assignments.get(pid, []):
                info = self.dir_roles.get(role)
                if info is None:
                    continue
                if key.startswith("entra_role:"):
                    wanted = key[11:]
                    if wanted not in (_low(info["name"]), info["id"]):
                        continue
                else:
                    perm = key[11:]
                    if not any(glob_match(a, perm) for a in info["actions"]):
                        continue
                    if ref not in (ANY, None) and not self._group_kind_ok(perm, ref):
                        continue
                conf, conditions = self._dir_scope(scope, ref)
                if conf is None:
                    continue
                if pid != principal.id:
                    conditions = conditions + ["via_role_assignable_group"]
                grant = Grant(conf, [{"directory_role_assignment": aid, "role": info["name"], "directory_scope": scope, "via": pid}], conditions)
                if best_grant is None or (best_grant.confidence != "derived" and conf == "derived"):
                    best_grant = grant
        return best_grant

    def _group_kind_ok(self, perm, ref):
        target = self.dir_objects.get(str(ref)[4:]) if isinstance(ref, str) and ref.startswith("dir:") else None
        if target is None:
            return True
        unified = "Unified" in as_list(target.get("groupTypes"))
        if "groups.unified/" in perm:
            return unified
        if "groups.security/" in perm:
            return bool(target.get("securityEnabled")) and not unified
        return True

    def _dir_scope(self, scope, ref):
        if ref is ANY or ref is None:
            return "derived", []
        scope = scope or "/"
        if ref == "dir:/":
            return ("derived", []) if scope == "/" else (None, [])
        if scope == "/":
            return "derived", []
        target = str(ref)[4:]
        if scope.lstrip("/") == target:
            return "derived", []
        if scope.startswith("/administrativeUnits/"):
            members = self._au_members().get(scope.split("/")[2])
            if members is None:
                return "unknown", ["administrative_unit_membership_not_collected"]
            return ("derived", []) if target in members else (None, [])
        return None, []

    def _au_members(self):
        cache = self.__dict__.get("_au_cache")
        if cache is None:
            cache = self._au_cache = {}
            for scope, item in items(self.snapshot, "directory_administrative_unit"):
                if item.get("id") and "memberIds" in item:
                    cache[item["id"]] = set(as_list(item.get("memberIds")))
        return cache

    def check(self, principal, req, ref):
        if "action" in req:
            return self._rbac(principal, _low(req["action"]), bool(req.get("data_action")), ref)
        if "entra_permission" in req or "entra_role" in req:
            return self._entra(principal, req, ref)
        reason = self.global_unknown(req)
        if reason:
            return Grant("unknown", [], [f"facts_not_collected:{reason}"])
        return self._fact_requirement(principal, req, ref)

    def _fact_requirement(self, principal, req, ref):
        """Requirements backed by optional collections (evaluated when present)."""
        if "graph_app_permission" in req:
            wanted = _low(req["graph_app_permission"])
            for scope, item in items(self.snapshot, "directory_app_role_assignment"):
                if item.get("principalId") == principal.id and _low(item.get("appRoleValue") or item.get("permission")) == wanted:
                    return Grant("derived", [{"app_role_assignment": item.get("id"), "permission": req["graph_app_permission"]}])
            return None
        if "entra_owner_of" in req:
            target = str(ref)[4:] if isinstance(ref, str) and ref.startswith("dir:") else None
            for scope, item in items(self.snapshot, "directory_owner"):
                if principal.id in as_list(item.get("ownerIds")) and (target is None or item.get("objectId") == target) and \
                        _low(item.get("objectType")) == _low(req.get("object_type")):
                    return Grant("derived", [{"owner_of": item.get("objectId")}])
            return None
        if "entra_pim_eligible_role" in req:
            target = str(ref)[4:] if isinstance(ref, str) and ref.startswith("dir:") else None
            for scope, item in items(self.snapshot, "directory_role_eligibility_schedule"):
                if item.get("principalId") in (principal.id, *principal.attrs.get("groups", [])) and \
                        (target is None or _low(item.get("roleDefinitionId")) in (target, _low(target))):
                    return Grant("conditional", [{"eligibility": item.get("id")}], ["pim_activation_required"])
            return None
        if "entra_tenant_setting" in req:
            for scope, item in items(self.snapshot, "directory_authorization_policy"):
                allowed = _low(item.get("allowInvitesFrom"))
                if allowed in ("everyone", "adminsguestinvitersandallmembers") and principal.attrs.get("user_type") != "Guest":
                    return Grant("derived", [{"authorization_policy": item.get("id"), "allowInvitesFrom": allowed}])
                if allowed == "everyone":
                    return Grant("derived", [{"authorization_policy": item.get("id")}])
            return None
        return None

    def check_targets(self, principal, req, template, candidates, localized=False):
        result = {}
        for target in candidates:
            if localized:
                refs, floor = self.localize_refs(target), None
            else:
                refs, floor = self.resolve(template, principal, target)
            grant = None
            for ref in refs:
                got = self.cached_check(principal, req, ref)
                if got is not None and (grant is None or got.confidence == "derived"):
                    grant = got
            if grant is not None:
                result[target.id] = downgrade(grant, floor[0], floor[1]) if floor else grant
        return result

    def localize_refs(self, target):
        if target.entity:
            return [target.scope]
        hosts = list(target.attrs.get("hosts") or [])
        if target.attrs.get("uai_resource"):
            hosts.append(target.attrs["uai_resource"])
        return hosts or [ANY]

    def placeholder_values(self, name, source, target, pivot=None):
        if name == "pivot":
            return [pivot["pivot"]] if pivot and pivot.get("pivot") else None
        owner, _, attr = name.partition(".")
        if not attr:
            owner, attr = "source", owner
        node = target if owner == "target" else source
        if node is None:
            return None
        if attr == "host_resource":
            hosts = node.attrs.get("hosts")
            if hosts:
                return list(hosts)
            return [] if node.attrs.get("uai_resource") else None
        if attr.startswith("host_resource."):
            return None
        if attr == "scope":
            if node.entity:
                return [node.scope]
            return ["dir:" + node.id]
        if attr == "id":
            if node.entity:
                return ["dir:" + node.attrs["template_id"]] if node.attrs.get("template_id") else [node.scope]
            if node.kind == "azure_managed_identity":
                return [node.attrs["uai_resource"]] if node.attrs.get("uai_resource") else []
            return ["dir:" + node.id]
        if attr == "application_id":
            app = (self.app_ids or {}).get(_low(node.attrs.get("app_id")))
            return ["dir:" + app["id"]] if app and app.get("id") else None
        if attr in ("name",):
            return [node.label]
        return None

    def resolve(self, template, source, target, pivot=None):
        if template is None:
            return [ANY], None
        if template == "/":
            return ["/"], None
        names = re.findall(r"(?<!\$)\{([^{}]+)\}", template)
        if not names:
            return [_low(template)], None
        refs = [template]
        for name in names:
            if name in CONTROLLED_USER:
                # The user object the source modifies: itself when it is a user; otherwise a user it controls,
                # which the snapshot does not identify (any scope holding the permission, conditional).
                if source is None or source.kind != "azure_user":
                    return [ANY], ("conditional", "controlled_user_not_identified")
                refs = [r.replace("{" + name + "}", "dir:" + source.id) for r in refs]
                continue
            got = self.placeholder_values(name, source, target, pivot)
            if got is None:
                if name == "pivot":
                    return [ANY], ("conditional", "pivot_resource_not_verified")
                return [ANY], ("unknown", f"placeholder_{name}_not_in_snapshot")
            refs = [r.replace("{" + name + "}", v) for r in refs for v in got]
        return [r if r.startswith("dir:") else _low(r) for r in refs], None

    def pivot_candidates(self, source):
        scopes = {a["scope"] for pid in [source.id, *source.attrs.get("groups", [])] for a in self.assignments.get(pid, [])}
        return [{"pivot": s} for s in sorted(scopes)]

    # --------------------------------------------------------------- targets
    def service_managed(self, node):
        """Microsoft first-party service principals (application owned by a Microsoft tenant) are not customer
        controlled; entries that model them explicitly (blocker microsoft_first_party_sp) keep them."""
        if node.kind != "azure_service_principal":
            return False
        return node.attrs.get("app_owner_org") in MICROSOFT_TENANTS

    def include_service_managed(self, compiled):
        return super().include_service_managed(compiled) or "microsoft_first_party_sp" in (
            [b if isinstance(b, str) else (b or {}).get("id") for b in (compiled.get("entry") or {}).get("blockers") or []])

    def targets(self, kind):
        if kind in ("azure_user", "azure_service_principal", "azure_managed_identity", "entra_group"):
            return [n for n in self.principals.values() if n.kind == kind]
        if kind == "azure_scope_owner":
            scopes = set(self.scopes) | {"/"}
            for rid in self.resources:
                sub = _subscription(rid)
                if sub:
                    scopes.add(sub)
                rg = _resource_group(rid)
                if rg:
                    scopes.add(rg)
            return [self.entity(kind, s) for s in sorted(scopes) if s == "/" or s.count("/") <= 4 or "/managementgroups/" in s]
        if kind in ("azure_dataplane_admin", "k8s_cluster_admin"):
            return [self.entity(kind, rid, r) for rid, r in sorted(self.resources.items())]
        if kind == "entra_role":
            seen, out = set(), []
            for info in self.dir_roles.values():
                if info["id"] in seen:
                    continue
                seen.add(info["id"])
                out.append(self.entity(kind, info["id"], {"name": info["name"]}))
            if not out:
                out.append(self.entity(kind, GLOBAL_ADMIN, {"name": "Global Administrator"}))
            return out
        return []

    def entity(self, kind, scope, extra=None):
        cache = self.__dict__.setdefault("_entities", {})
        key = (kind, scope)
        if key not in cache:
            extra = extra or {}
            if kind == "azure_scope_owner":
                label = "Owner of " + ("tenant root (/)" if scope == "/" else scope)
            elif kind == "entra_role":
                label = f"Entra role {extra.get('name', scope)}"
            elif kind == "k8s_cluster_admin":
                label = f"cluster-admin of {extra.get('name') or scope}"
            else:
                label = f"Data-plane admin of {extra.get('name') or scope}"
            cache[key] = Node(f"{kind}:{scope}", kind, "azure", scope if kind != "entra_role" else f"/tenants/{self.tenant}",
                              label, attrs={"scope": scope, "type": extra.get("type"), "template_id": scope if kind == "entra_role" else None,
                                            "name": extra.get("name")}, entity=True)
        return cache[key]

    def unknown_target_scopes(self, kind):
        if kind in ("azure_user", "azure_service_principal", "entra_group"):
            collection = {"azure_user": "directory_user", "azure_service_principal": "directory_service_principal",
                          "entra_group": "directory_group"}[kind]
            status = inventory_status(self.snapshot, collection)
            return unavailable(status) if status else {f"/tenants/{self.tenant}": "not_collected"}
        return {}

    def allowed_scopes(self, rule, source):
        return None

    def selector(self, key, value, candidates, source, pivot=None):
        if key == "_resource_type_from_action":
            action = _low(value)
            types = {r["type"] for r in self.resources.values()}
            match = max((t for t in types if action.startswith(t + "/")), key=len, default=None)
            return {tid: None for tid, n in candidates.items() if match and n.attrs.get("type") == match}
        if key == "any_principal_in_scope":
            return dict.fromkeys(candidates)
        if key == "same_as_source":
            return {source.id: None} if source.id in candidates else {}
        if key == "managed_identity_type":
            out = {}
            for tid, n in candidates.items():
                mi_type = n.attrs.get("mi_type")
                if mi_type is None:
                    out[tid] = ("unknown", "managed_identity_type_unknown")
                elif mi_type == value:
                    out[tid] = None
            return out
        if key == "attached_to_service":
            wanted = [_low(v) for v in as_list(value)]
            out = {}
            for tid, n in candidates.items():
                hosts = [self.resources.get(h, {}).get("type", "") for h in n.attrs.get("hosts", [])]
                if any(any(h == w or h.startswith(w + "/") or w.startswith(h + "/") for w in wanted) for h in hosts):
                    out[tid] = None
                elif n.attrs.get("mi_type") == "system_assigned" and hosts:
                    continue
                elif any(w not in self.typed_types for w in wanted):
                    out[tid] = ("unknown", "resource_identity_inventory_not_collected")
            return out
        if key == "azure_site_kind":
            wanted = [_low(v) for v in as_list(value)]
            out = {}
            for tid, n in candidates.items():
                kinds = [self.resources.get(h, {}).get("kind", "") for h in n.attrs.get("hosts", [])
                         if self.resources.get(h, {}).get("type") == "microsoft.web/sites"]
                if any(w in k for k in kinds for w in wanted):
                    out[tid] = None
                elif not kinds and n.attrs.get("mi_type") != "system_assigned":
                    out[tid] = ("unknown", "site_kind_unknown")
            return out
        if key == "custom_role_assigned_to_source":
            scopes = [a["scope"] for pid in [source.id, *source.attrs.get("groups", [])] for a in self.assignments.get(pid, [])
                      if self.roles.get(a["role"]) is not None and self.roles[a["role"]].custom]
            return {tid: None for tid, n in candidates.items() if any(self.covers(s, n.scope)[0] for s in scopes)}
        if key == "entra_role_assignable":
            wanted = {_low(v) for v in as_list(value)}
            if wanted & {"any", "*"}:
                return dict.fromkeys(candidates)
            return {tid: None for tid, n in candidates.items() if _low(n.attrs.get("name")) in wanted or _low(n.attrs.get("template_id")) in wanted}
        if key == "entra_role_assignment_scope_covers_target":
            return dict.fromkeys(candidates)  # enforced by the requirement's directory scope check
        if key == "entra_reset_matrix_column":
            return self._reset_matrix(value, candidates)
        if key == "entra_target_not_in_restricted_au":
            if inventory_status(self.snapshot, "directory_administrative_unit"):
                restricted = set()
                for scope, item in items(self.snapshot, "directory_administrative_unit"):
                    if item.get("isMemberManagementRestricted"):
                        restricted |= set(as_list(item.get("memberIds")))
                return {tid: None for tid in candidates if tid not in restricted}
            return {tid: ("conditional", "restricted_au_membership_not_collected") for tid in candidates}
        if key == "entra_sp_type_in":
            wanted = set(as_list(value))
            return {tid: (None if n.attrs.get("sp_type") else ("unknown", "sp_type_unknown"))
                    for tid, n in candidates.items() if n.attrs.get("sp_type") in wanted or not n.attrs.get("sp_type")}
        if key == "entra_sp_has_tenant_application":
            if self.app_ids is None:
                return None
            return {tid: None for tid, n in candidates.items() if _low(n.attrs.get("app_id")) in self.app_ids}
        if key == "entra_app_sign_in_audience":
            if self.app_ids is None or not any("signInAudience" in a for a in self.app_ids.values()):
                return None
            wanted = set(as_list(value))
            return {tid: None for tid, n in candidates.items()
                    if (self.app_ids.get(_low(n.attrs.get("app_id"))) or {}).get("signInAudience") in wanted}
        if key == "entra_group_membership_type":
            out = {}
            for tid, n in candidates.items():
                types = n.attrs.get("group_types")
                if types is None:
                    out[tid] = ("unknown", "group_types_not_collected")
                elif ("DynamicMembership" in types) == (value == "dynamic"):
                    out[tid] = None
            return out
        if key == "entra_group_role_assignable":
            out = {}
            for tid, n in candidates.items():
                flag = n.attrs.get("assignable_to_role")
                if flag is None:
                    out[tid] = ("unknown", "isAssignableToRole_not_collected")
                elif bool(flag) == bool(value):
                    out[tid] = None
            return out
        if key == "entra_group_type_covered_by_permission":
            return dict.fromkeys(candidates)  # enforced in the entra_permission check (groups.security / groups.unified)
        if key == "entra_user_upn_on_federatable_custom_domain":
            out = {}
            for tid, n in candidates.items():
                upn = _low(n.attrs.get("upn"))
                if not upn:
                    out[tid] = ("unknown", "upn_not_collected")
                elif not upn.endswith(".onmicrosoft.com") and "#ext#" not in upn:
                    out[tid] = ("conditional", "domain_federation_facts_not_collected")
            return out
        if key in ("entra_dynamic_rule_attributes_writable_by_source", "entra_dynamic_rule_satisfiable_by_invited_guest"):
            if not any(n.attrs.get("membership_rule") for n in candidates.values()):
                return None
            return {tid: ("conditional", "membership_rule_semantics_approximated") for tid, n in candidates.items() if n.attrs.get("membership_rule")}
        return None

    def _reset_matrix(self, column, candidates):
        if not inventory_status(self.snapshot, "directory_role_assignment"):
            return {tid: ("unknown", "target_directory_roles_not_collected") for tid in candidates}
        allowed = RESET_MATRIX.get(column, set())
        out = {}
        for tid, n in candidates.items():
            roles = set()
            via_group = False
            for pid in [n.id, *n.attrs.get("groups", [])]:
                for role, scope, aid in self.dir_assignments.get(pid, []):
                    info = self.dir_roles.get(role)
                    roles.add(_low(info["name"]) if info else role)
                    via_group = via_group or pid != n.id
            if allowed is not None and not roles <= allowed:
                continue
            if via_group and column != "privileged_auth_admin":
                continue  # members of role-assignable groups are protected
            groups = [self.principals.get(g) for g in n.attrs.get("groups", [])]
            if column != "privileged_auth_admin" and any(g is not None and g.attrs.get("assignable_to_role") is None for g in groups):
                out[tid] = ("conditional", "role_assignable_group_membership_unknown")
            else:
                out[tid] = None
        return out

    def admin_targets(self, principal):
        out = []
        found = {}
        for pid in [principal.id, *principal.attrs.get("groups", [])]:
            for a in self.assignments.get(pid, []):
                definition = self.roles.get(a["role"])
                if definition is None or not definition.allows("microsoft.authorization/roleassignments/write"):
                    continue
                grant = self._rbac(principal, "microsoft.authorization/roleassignments/write", False, a["scope"])
                if grant is not None:
                    found[a["scope"]] = grant
        for scope, grant in sorted(found.items()):
            if any(other != scope and self.covers(other, scope)[0] for other in found):
                continue
            out.append((self.entity("azure_scope_owner", scope), grant))
        for pid in [principal.id, *principal.attrs.get("groups", [])]:
            for role, scope, aid in self.dir_assignments.get(pid, []):
                info = self.dir_roles.get(role)
                template = info["id"] if info else role
                if (template == GLOBAL_ADMIN or (info and info["name"] == "Global Administrator")) and (scope or "/") == "/":
                    grant = Grant("derived", [{"directory_role_assignment": aid, "role": "Global Administrator"}],
                                  ["via_role_assignable_group"] if pid != principal.id else [])
                    out.append((self.entity("entra_role", GLOBAL_ADMIN if not info else info["id"], {"name": "Global Administrator"}), grant))
        return out

    def scope_within(self, inner, outer):
        return self.covers(outer, inner)[0] if inner.startswith("/") else inner == outer


# Tenants owning Microsoft first-party applications (Microsoft Services, Microsoft corp).
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}


def _subscription(rid):
    match = re.match(r"(/subscriptions/[^/]+)", _low(rid))
    return match.group(1) if match else None


def _resource_group(rid):
    match = re.match(r"(/subscriptions/[^/]+/resourcegroups/[^/]+)", _low(rid))
    return match.group(1) if match else None
