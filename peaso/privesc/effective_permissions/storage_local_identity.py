"""Azure Storage local SFTP users are service identities, never Entra users."""
import re

from . import Node, items

KIND = "azure_storage_local_user"
SELECTOR = "azure_storage_local_credential"
MODES = {"reset_password", "write_credential"}
LOCAL_ID = re.compile(r"^(/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.storage/storageaccounts/[^/]+)/localusers/([^/]+)$", re.I)


def status(model, kind, resource):
    """Use the closest collection scope; duplicate or failed reads stay unknown."""
    resource = resource.lower().rstrip("/")
    found = [(str(c.get("scope", "")).lower().rstrip("/"), c.get("status"))
             for c in model.snapshot.get("collections", []) if c.get("type") == kind
             and isinstance(c.get("scope"), str)
             and c["scope"].lower().rstrip("/").startswith("/subscriptions/")
             and (resource == c["scope"].lower().rstrip("/")
                  or resource.startswith(c["scope"].lower().rstrip("/") + "/"))]
    if not found:
        return "not_collected"
    longest = max(len(scope) for scope, _ in found)
    states = [state for scope, state in found if len(scope) == longest]
    return "collected" if len(states) == 1 and states[0] == "collected" else "unknown"


def targets(model):
    cache = model.__dict__.get("_storage_local_users")
    if cache is not None:
        return cache
    users, accounts = {}, {}
    for _, row in items(model.snapshot, "storage_account"):
        if isinstance(row.get("id"), str):
            accounts.setdefault(row["id"].lower().rstrip("/"), []).append(row)
    for _, row in items(model.snapshot, "storage_local_user"):
        rid = row.get("id")
        match = LOCAL_ID.fullmatch(rid) if isinstance(rid, str) else None
        if not match:
            continue
        users.setdefault(rid.lower(), []).append(row)
    cache = []
    for rid, rows in sorted(users.items()):
        account, name = LOCAL_ID.fullmatch(rid).groups()
        account_rows = accounts.get(account, [])
        props = rows[0].get("properties")
        cache.append(Node(f"{KIND}:{rid}", KIND, "azure", rid,
                          f"Storage SFTP user {account.rsplit('/', 1)[-1]}.{name}",
                          attrs={"name": name, "storage_account": account, "resource": rid,
                                 "local_properties": props if isinstance(props, dict) else {},
                                 "account_properties": account_rows[0].get("properties", {}) if len(account_rows) == 1 else {},
                                 "ambiguous": len(rows) != 1 or len(account_rows) != 1}))
    model._storage_local_users = cache
    return cache


def select(model, mode, candidates):
    if mode not in MODES:
        return None
    result = {}
    for ident, node in candidates.items():
        if node.kind != KIND:
            continue
        account = node.attrs["storage_account"]
        props, parent = node.attrs["local_properties"], node.attrs["account_properties"]
        if not isinstance(parent, dict):
            parent = {}
        if parent.get("isSftpEnabled") is False or parent.get("isLocalUserEnabled") is False:
            continue
        if (node.attrs["ambiguous"] or parent.get("isSftpEnabled") is not True
                or parent.get("isLocalUserEnabled") is not True
                or status(model, "storage_account", account) != "collected"
                or status(model, "storage_local_user", node.scope) != "collected"):
            result[ident] = ("unknown", "storage_local_user_inventory_or_sftp_settings_incomplete")
            continue
        if mode == "reset_password" and props.get("hasSshPassword") is False:
            continue
        if mode == "reset_password" and props.get("hasSshPassword") is not True:
            result[ident] = ("unknown", "storage_local_user_password_auth_not_collected")
            continue
        scopes = props.get("permissionScopes")
        if not isinstance(scopes, list) or any(not isinstance(scope, dict) for scope in scopes):
            result[ident] = ("unknown", "storage_local_user_permissions_not_collected")
            continue
        if not scopes:
            if props.get("allowAclAuthorization") is not False:
                result[ident] = ("unknown", "storage_local_user_acl_authority_not_collected")
            continue
        rights, malformed = [], False
        for scope in scopes:
            service, container, permissions = (scope.get(key) for key in ("service", "resourceName", "permissions"))
            if service != "blob":
                malformed = True
                continue
            if (not isinstance(container, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", container)
                    or not isinstance(permissions, str) or not re.fullmatch(r"[racwdlop]+", permissions)
                    or len(permissions) != len(set(permissions))):
                malformed = True
                continue
            container_id = account + "/blobservices/default/containers/" + container
            present = [row for _, row in items(model.snapshot, "storage_container")
                       if isinstance(row.get("id"), str) and row["id"].lower() == container_id]
            if status(model, "storage_container", container_id) != "collected" or len(present) != 1:
                malformed = True
                continue
            rights.append({"container": container_id, "permissions": permissions})
        if malformed or not rights:
            result[ident] = ("unknown", "storage_local_user_container_or_permission_scope_unverified")
            continue
        node.attrs["effective_rights"] = rights
        result[ident] = ("conditional", "storage_sftp_network_and_credential_operation_required")
    return result
