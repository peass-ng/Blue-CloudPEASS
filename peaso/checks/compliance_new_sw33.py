"""Signed Azure second-wave predicates over scoped snapshot evidence."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from ipaddress import ip_network
from urllib.parse import urlsplit
import re
import uuid

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects

_META = {'azure.other.database_backup_alert': {'kind': 'sql_server',
                                       'category': 'monitoring',
                                       'severity': 'medium',
                                       'title': 'Database backup failures generate alerts',
                                       'remediation': 'Instrument backup state and job failures, '
                                                      'configure alerts for disabled, paused and '
                                                      'missed/failed scheduled backups, and verify '
                                                      'logged delivery with a test event.',
                                       'sha': '793375250b421117213f42b3c118732b96f4ac388c95d9bf413cc7f7c47cbf77'},
 'azure.other.message_namespace_cmk': {'kind': 'eventhub_namespace',
                                       'category': 'encryption',
                                       'severity': 'medium',
                                       'title': 'Messaging namespaces use a customer-managed Key Vault '
                                                'key',
                                       'remediation': 'Configure a supported namespace tier with a '
                                                      'usable Key Vault customer-managed key, then '
                                                      'verify that publishing without the required key '
                                                      'is rejected.',
                                       'sha': '0965998ceb110c76c5d3925afa3a59dcd6d830f91c99900d786cb0133594a17e'},
 'azure.other.change_approval_trace': {'kind': 'azure_activity_log',
                                       'category': 'hardening',
                                       'severity': 'medium',
                                       'title': 'Azure changes have approval trace',
                                       'remediation': 'Configure change tooling to record approved '
                                                      'ticket, approver, scope and correlation ID '
                                                      'before deployment; investigate unmatched '
                                                      'successful ARM write/delete events.',
                                       'sha': 'ac682e32da92d4ebf45d0694e78a706c6c23d25a21725f7cd994c3b2c6fa4193'},
 'azure_route_table_network_http_internet_access_restricted_5cd2484': {'kind': 'route_table',
                                                                       'category': 'network',
                                                                       'severity': 'high',
                                                                       'title': 'Default user routes '
                                                                                'use approved next hops',
                                                                       'remediation': 'Azure portal > '
                                                                                      'Route table > '
                                                                                      'Routes: replace '
                                                                                      'Internet default '
                                                                                      'routes with '
                                                                                      'approved '
                                                                                      'virtual-appliance '
                                                                                      'next hops and '
                                                                                      'associate the '
                                                                                      'table with '
                                                                                      'intended '
                                                                                      'subnets.',
                                                                       'sha': 'fafe749939ef93479165991a022b74db3f41baba9b406483c79254ac626e681b'},
 'azure_azure_resource_1_3_1_46_b70e2c8': {'kind': 'virtual_network_gateway',
                                           'category': 'hardening',
                                           'severity': 'medium',
                                           'title': 'Both expected site-to-site VPN tunnels are '
                                                    'connected',
                                           'remediation': 'In Virtual network gateway > Connections, '
                                                          'inspect both IPsec tunnels for the expected '
                                                          'connection, repair each disconnected tunnel, '
                                                          'and verify both tunnel health entries report '
                                                          'Connected.',
                                           'sha': 'b7ff1b07fcdb6a75025284067481f7b1685498cfeb3df5dca810160270da5de4'},
 'azure_application_gateway_app_http_logs_enabled_2de0361': {'kind': 'application_gateway_and_load_balancer',
                                                             'category': 'logging',
                                                             'severity': 'medium',
                                                             'title': 'Application Gateway and Load '
                                                                      'Balancer export diagnostic logs',
                                                             'remediation': 'Enable a supported access '
                                                                            'or operational log '
                                                                            'category on each gateway '
                                                                            'and load balancer and send '
                                                                            'it to Azure Monitor Logs '
                                                                            'or an Azure Storage '
                                                                            'account.',
                                                             'sha': '7703231d14c659ba2e9b6212246fd2b241c70829ba0a2930a6bed06d6eed10e0'},
 'azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb': {'kind': 'aks_pod',
                                                        'category': 'hardening',
                                                        'severity': 'medium',
                                                        'title': 'Kubernetes containers use read-only '
                                                                 'root filesystems',
                                                        'remediation': 'In the Pod or controller '
                                                                       'manifest set '
                                                                       'securityContext.readOnlyRootFilesystem: '
                                                                       'true for every container, init '
                                                                       'container and ephemeral '
                                                                       'container; use writable volumes '
                                                                       'only where needed.',
                                                        'sha': 'ba9e1dae6a6ff7e92db25174d9051f6f876c72101c599755a1c6c922c02ac2ec'},
 'azure_storage_file_share_10_3_3_18_d67ab34': {'kind': 'storage_file_share_and_netapp_volume',
                                                'category': 'recovery',
                                                'severity': 'medium',
                                                'title': 'Azure Files and NetApp volumes have backup '
                                                         'protection',
                                                'remediation': 'For each Azure File Share, configure '
                                                               'Backup in a Recovery Services vault and '
                                                               'confirm Protected state; for each '
                                                               'NetApp volume, assign an Azure NetApp '
                                                               'Files backup policy and confirm backup '
                                                               'is active.',
                                                'sha': 'a13a2fbdc6fd41186a04a51a88b154b335c5a97e1b431cd404c4aedad8211bd2'},
 'azure_directory_user_10_6_3_21_d013932': {'kind': 'directory_user_and_group',
                                            'category': 'hardening',
                                            'severity': 'medium',
                                            'title': 'Enabled Entra users belong to at least one group',
                                            'remediation': 'Add users without group membership to an '
                                                           'appropriate Azure AD group; review any '
                                                           'explicit scope exclusions.',
                                            'sha': '9617237b6d18cca0605c079acb89b8df5bbeb1cee6ba27b3cb835f242b762475'},
 'azure_storage_file_share_3_5_1_15_17dc7f4': {'kind': 'storage_file_share',
                                               'category': 'encryption',
                                               'severity': 'medium',
                                               'title': 'Azure Files accounts use an approved customer '
                                                        'key',
                                               'remediation': 'Enable Azure Files encryption with a '
                                                              'customer-managed key and select the '
                                                              'approved Key Vault key ID for the '
                                                              'storage account.',
                                               'sha': 'fbfc414dedfaca4109ecb5d1b539f40bc4ed33d0825b36c3da6c9cd1a5e87cf9'},
 'azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9': {'kind': 'sql_server_and_managed_instance',
                                                                        'category': 'hardening',
                                                                        'severity': 'medium',
                                                                        'title': 'SQL Database and '
                                                                                 'Managed Instance '
                                                                                 'support Microsoft '
                                                                                 'Entra authentication',
                                                                        'remediation': 'Set a Microsoft '
                                                                                       'Entra '
                                                                                       'administrator '
                                                                                       'on each SQL '
                                                                                       'server or '
                                                                                       'Managed '
                                                                                       'Instance and '
                                                                                       'verify the '
                                                                                       'administrator '
                                                                                       'object ID; '
                                                                                       'enable '
                                                                                       'Entra-only '
                                                                                       'authentication '
                                                                                       'only where '
                                                                                       'policy '
                                                                                       'separately '
                                                                                       'requires it.',
                                                                        'sha': '85c2c8a911cb04a3a66fb714091ef0db34e1d1d3a0e3e0de2d153e1fc304de34'},
 'azure_c5_am_09_01b': {'kind': 'resource_graph',
                        'category': 'hardening',
                        'severity': 'medium',
                        'title': 'Tag classified Azure resources',
                        'remediation': 'Classify assets against the approved data categories and apply '
                                       'the corresponding label or tag wherever the asset supports it.',
                        'sha': 'ee0da7991b455549cffd6601fc933258ad5a65d0d24b1dffa027b4aad4955938'},
 'azure_c5_cry_08_01b': {'kind': 'key_vault_certificate_policy',
                         'category': 'hardening',
                         'severity': 'medium',
                         'title': 'Key Vault certificates use approved issuers and key types',
                         'remediation': 'Reissue noncompliant certificates with an approved issuer and '
                                        'key policy; document and operate identity verification, secure '
                                        'issuance and trusted-CA validation procedures, retaining dated '
                                        'evidence.',
                         'sha': '255da612742001bcf48b4fc7f9f6039b6af1812006971245e53ef25797a1c1d5'},
 'azure.cis.auto_provision_vulnerability_assessment_machines': {'kind': 'server_vulnerability_assessment_setting',
                                                                'category': 'vulnerability',
                                                                'severity': 'high',
                                                                'title': 'Ensure that Auto provisioning '
                                                                         "of 'Vulnerability assessment "
                                                                         "for machines' is Set to 'On'",
                                                                'remediation': 'In Defender for Cloud > '
                                                                               'Environment settings > '
                                                                               'Defender plans, enable '
                                                                               'Defender for Servers '
                                                                               'and set Vulnerability '
                                                                               'assessment to Microsoft '
                                                                               'Defender Vulnerability '
                                                                               'Management (MdeTvm).',
                                                                'sha': 'd242d411ff4da8b8d319058fd52ee46def50e749512f4b6153bc3c3659dc6f72'},
 'azure.cis.unity_catalog_configured_databricks': {'kind': 'databricks_workspace',
                                                   'category': 'logging',
                                                   'severity': 'medium',
                                                   'title': 'Assign Unity Catalog metastores to '
                                                            'Databricks workspaces',
                                                   'remediation': 'Databricks account console > Catalog '
                                                                  '> Metastores: assign an appropriate '
                                                                  'metastore to the affected workspace.',
                                                   'sha': 'bad95cc71ef790b5aa09817e2850ae2ca6a9ee39c6e4f91299814d4ff87441bb'}}
IDS = tuple(_META)


def _signed(check_id, dependencies, *, target="resource"):
    meta = _META[check_id]
    native = meta["category"] if meta["category"] in {
        "hardening", "exposure", "least_privilege", "iam_graph", "network"} else "hardening"
    def decorate(function):
        @register(check_id, "azure", native, meta["kind"], meta["title"],
                  meta["severity"], "CM-6", meta["remediation"],
                  dependencies=dependencies, target=target)
        def evaluate(item, index):
            return function(item, index)
        if native != meta["category"]:
            CHECKS[-1] = replace(CHECKS[-1], category=meta["category"])
        return evaluate
    return decorate


def _scope(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("foreign provider")
    scope = get(context, "scope", str)
    if not scope or scope == "/" or "//" in scope:
        raise Unavailable("unresolved Azure scope")
    return scope.rstrip("/").casefold()


def _rows(index, kind):
    scope = _scope(index)
    envelopes = get(get(index, "collections", dict), kind, list)
    if not envelopes:
        raise Unavailable("missing complete collection: " + kind)
    rows = complete_items(index, kind)
    for envelope in envelopes:
        if not isinstance(envelope, dict) or get(envelope, "status", str) not in ("collected", "empty"):
            raise Unavailable("incomplete collection: " + kind)
        owner = get(envelope, "scope", str).rstrip("/").casefold()
        if owner != scope and not owner.startswith(scope + "/"):
            raise Unavailable("foreign collection scope: " + kind)
        items = list_of_objects(get(envelope, "items", list))
        if envelope["status"] == "empty" and items:
            raise Unavailable("empty collection contains resources")
    seen = set()
    for row in rows:
        identity = get(row, "id", str)
        if not identity or identity.casefold() in seen:
            raise Unavailable("missing or duplicate identity: " + kind)
        seen.add(identity.casefold())
        if identity.startswith("/subscriptions/") and identity.casefold() != scope and not identity.casefold().startswith(scope + "/"):
            raise Unavailable("foreign resource: " + kind)
    expected = [item for envelope in envelopes for item in envelope["items"]]
    if len(expected) != len(rows) or {get(x, "id", str).casefold(): x for x in expected} != {get(x, "id", str).casefold(): x for x in rows}:
        raise Unavailable("inventory wrappers differ from collection")
    return rows


def _current(index, kind, item):
    identity = get(item, "id", str)
    matches = [row for row in _rows(index, kind) if get(row, "id", str).casefold() == identity.casefold()]
    if len(matches) != 1 or matches[0] != item:
        raise Unavailable("resource not in complete scoped inventory")
    return matches[0]


def _policy(index, key):
    policy = get(index, "context.metadata.compliance_policy.sw33", dict)
    if get(policy, "status", str) != "collected" or get(policy, "scope", str).rstrip("/").casefold() != _scope(index):
        raise Unavailable("policy missing or foreign scope")
    return get(policy, key, dict)


def _arm_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/.+", value, re.I):
        raise Unavailable("malformed ARM resource ID")
    return value.casefold()


def _timestamp(value):
    if not isinstance(value, str):
        raise Unavailable("missing timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("malformed timestamp") from exc
    if result.tzinfo is None:
        raise Unavailable("timestamp lacks timezone")
    return result.astimezone(timezone.utc)


def _objects(row, path):
    return list_of_objects(get(row, path, list))


@_signed("azure_route_table_network_http_internet_access_restricted_5cd2484", ["route_table"])
def route_destinations(item, index):
    _current(index, "route_table", item)
    policy = _policy(index, "routeDestinations")
    scoped = get(policy, "routeTableIds", list)
    if not all(isinstance(x, str) for x in scoped):
        raise Unavailable("malformed route-table policy scope")
    if get(item, "id", str).casefold() not in {x.casefold() for x in scoped}:
        return "NOT_APPLICABLE", {"reason": "route table outside approved policy scope"}
    allowed = get(policy, "allowedDestinationCidrs", list)
    if not allowed or not all(isinstance(x, str) for x in allowed):
        raise Unavailable("allowed destination policy missing")
    try:
        networks = [ip_network(x, strict=False) for x in allowed]
    except ValueError as exc:
        raise Unavailable("malformed destination policy") from exc
    routes = _objects(item, "properties.routes")
    bad = []
    for route in routes:
        rid = get(route, "id", str)
        if not rid.casefold().startswith(get(item, "id", str).casefold() + "/routes/"):
            raise Unavailable("foreign route identity")
        dest = get(route, "properties.addressPrefix", str)
        try:
            target = ip_network(dest, strict=False)
        except ValueError as exc:
            raise Unavailable("unrecognized route destination") from exc
        if dest in ("0.0.0.0/0", "::/0") or not any(
                target.version == permitted.version and target.subnet_of(permitted)
                for permitted in networks):
            bad.append(rid)
    return result(bool(bad), disallowed_routes=bad, semantics="declared user routes only")


@_signed("azure_storage_file_share_3_5_1_15_17dc7f4", ["storage_account"], target="scope")
def files_cmk(item, index):
    policy = _policy(index, "azureFilesKeys")
    approved = get(policy, "approvedKeyIds", list)
    if not approved or not all(isinstance(x, str) and x for x in approved):
        raise Unavailable("approved full key IDs unavailable")
    bad = []
    for account in _rows(index, "storage_account"):
        encryption = get(account, "properties.encryption", dict)
        service = get(encryption, "services.file", dict)
        enabled = get(service, "enabled", bool)
        if not enabled:
            bad.append(get(account, "id", str))
            continue
        source = get(encryption, "keySource", str)
        if source == "Microsoft.Storage":
            bad.append(get(account, "id", str))
            continue
        if source != "Microsoft.Keyvault":
            raise Unavailable("unrecognized storage key source")
        vault = get(encryption, "keyVaultProperties", dict)
        versioned = get(vault, "currentVersionedKeyIdentifier", str)
        parsed = urlsplit(versioned)
        if parsed.scheme != "https" or not parsed.hostname or not re.fullmatch(r"/keys/[^/]+/[^/]+", parsed.path):
            raise Unavailable("unresolved versioned Key Vault key ID")
        expected = get(vault, "keyVaultUri", str).rstrip("/") + "/keys/" + get(vault, "keyName", str) + "/" + get(vault, "keyVersion", str)
        if versioned.casefold() != expected.casefold():
            raise Unavailable("key ID does not match vault URI, name and version")
        if versioned.casefold() not in {x.casefold() for x in approved}:
            bad.append(get(account, "id", str))
    return result(bool(bad), accounts_without_approved_files_key=bad)


@_signed("azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb",
         ["aks_pod", "aks_deployment", "aks_statefulset", "aks_daemonset", "aks_job", "aks_cronjob"], target="scope")
def read_only_root_filesystems(item, index):
    findings = []
    for kind in ("aks_pod", "aks_deployment", "aks_statefulset", "aks_daemonset", "aks_job", "aks_cronjob"):
        for workload in _rows(index, kind):
            path = "spec" if kind == "aks_pod" else "spec.jobTemplate.spec.template.spec" if kind == "aks_cronjob" else "spec.template.spec"
            spec = get(workload, path, dict)
            containers = list(_objects(spec, "containers"))
            if not containers:
                raise Unavailable("workload has no regular containers")
            for field in ("initContainers", "ephemeralContainers") if kind == "aks_pod" else ("initContainers",):
                containers += _objects(spec, field)
            names = set()
            for container in containers:
                name = get(container, "name", str)
                if not name or name in names:
                    raise Unavailable("duplicate or missing container name")
                names.add(name)
                security = container.get("securityContext", {})
                if not isinstance(security, dict):
                    raise Unavailable("malformed security context")
                value = security.get("readOnlyRootFilesystem", False)
                if type(value) is not bool:
                    raise Unavailable("malformed readOnlyRootFilesystem")
                if not value:
                    findings.append((get(workload, "id", str), name))
    return result(bool(findings), writable_root_containers=findings)


@_signed("azure_directory_user_10_6_3_21_d013932", ["directory_user", "directory_user_group_membership"], target="scope")
def user_group_membership(item, index):
    users = _rows(index, "directory_user")
    memberships = _rows(index, "directory_user_group_membership")
    by_user = {}
    for row in memberships:
        uid = get(row, "userId", str).casefold()
        if uid in by_user or get(row, "id", str).casefold() != uid:
            raise Unavailable("ambiguous membership join")
        by_user[uid] = row
    missing = []
    for user in users:
        uid = get(user, "id", str).casefold()
        if uid not in by_user:
            raise Unavailable("user membership list absent")
        groups = _objects(by_user[uid], "groups")
        if any(not re.fullmatch(r"[0-9a-fA-F-]{36}", get(g, "id", str)) for g in groups):
            raise Unavailable("malformed group identity")
        if len({g["id"].casefold() for g in groups}) != len(groups):
            raise Unavailable("duplicate transitive group")
        if not groups:
            missing.append(uid)
    if set(by_user) != {get(u, "id", str).casefold() for u in users}:
        raise Unavailable("foreign user membership")
    return result(bool(missing), users_without_groups=missing)


@_signed("azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9",
         ["sql_database", "sql_server", "mssql_managed_instance", "sql_managed_instance_administrator"], target="scope")
def sql_entra_administrator(item, index):
    databases = _rows(index, "sql_database")
    servers = {get(row, "id", str).casefold(): row for row in _rows(index, "sql_server")}
    instances = _rows(index, "mssql_managed_instance")
    instance_admins = {get(row, "id", str).casefold(): row for row in _rows(index, "sql_managed_instance_administrator")}
    if len(instance_admins) != len(instances):
        raise Unavailable("managed instance administrator inventory mismatch")
    targets = {}
    for db in databases:
        dbid = get(db, "id", str).casefold()
        parent = dbid.split("/databases/")[0]
        if parent == dbid or parent not in servers:
            raise Unavailable("SQL database parent server unresolved")
        targets[parent] = _objects(servers[parent], "serverAdministrators")
    for instance in instances:
        iid = get(instance, "id", str).casefold()
        admin = instance_admins.get(iid)
        if admin is None:
            raise Unavailable("managed instance administrator read missing")
        targets[iid] = _objects(admin, "administrators")
    bad = []
    for parent, admins in targets.items():
        valid = False
        for admin in admins:
            aid = get(admin, "id", str).casefold()
            if not aid.startswith(parent + "/administrators/"):
                raise Unavailable("foreign SQL administrator")
            props = get(admin, "properties", dict)
            kind = get(props, "administratorType", str)
            if kind != "ActiveDirectory":
                continue
            try:
                uuid.UUID(get(props, "sid", str))
            except ValueError as exc:
                raise Unavailable("invalid Entra administrator sid") from exc
            valid = True
        if not valid:
            bad.append(parent)
    return result(bool(bad), missing_entra_administrator=bad)


@_signed("azure_storage_file_share_10_3_3_18_d67ab34",
         ["storage_file_share", "netapp_volume", "backup_protected_item", "backup_policy", "recovery_vault", "netapp_backup_policy", "netapp_backup_vault"], target="scope")
def files_and_netapp_backup(item, index):
    shares = _rows(index, "storage_file_share")
    volumes = _rows(index, "netapp_volume")
    protected = _rows(index, "backup_protected_item")
    policies = {get(x, "id", str).casefold() for x in _rows(index, "backup_policy")}
    _rows(index, "recovery_vault")
    netapp_policies = {get(x, "id", str).casefold() for x in _rows(index, "netapp_backup_policy")}
    netapp_vaults = {get(x, "id", str).casefold() for x in _rows(index, "netapp_backup_vault")}
    matched = {}
    for protection in protected:
        props = get(protection, "properties", dict)
        if get(props, "protectedItemType", str) != "AzureFileShareProtectedItem":
            continue
        key = (_arm_id(get(props, "sourceResourceId", str)), get(props, "friendlyName", str).casefold())
        matched.setdefault(key, []).append(protection)
    bad = []
    for share in shares:
        sid = _arm_id(get(share, "id", str))
        match = re.fullmatch(r"(.+)/fileServices/[^/]+/shares/([^/]+)", sid, re.I)
        if not match:
            raise Unavailable("malformed Azure Files share ID")
        candidates = matched.get((match.group(1), match.group(2)), [])
        if len(candidates) > 1:
            raise Unavailable("ambiguous Azure Files backup join")
        if not candidates:
            bad.append(sid)
            continue
        props = get(candidates[0], "properties", dict)
        state = get(props, "protectionState", str)
        policy_id = _arm_id(get(props, "policyId", str))
        if state == "Protected" and policy_id in policies:
            continue
        if state in ("NotProtected", "ProtectionStopped", "IRPending", "ProtectionPaused") or policy_id not in policies:
            bad.append(sid)
        else:
            raise Unavailable("unrecognized Azure Files protection state")
    for volume in volumes:
        vid = _arm_id(get(volume, "id", str))
        proof = volume.get('_provenance', {})
        native_full = (isinstance(proof, dict) and proof.get('read_only') is True and
                       proof.get('representation') == 'full' and proof.get('source_operation') == 'Volumes_List' and
                       proof.get('api_version') == '2026-01-01')
        if native_full:
            props = get(volume, 'properties', dict)
            protection = props.get('dataProtection')
            if protection is None or isinstance(protection, dict) and protection.get('backup') is None:
                bad.append(vid)
                continue
            if isinstance(protection, dict) and isinstance(protection.get('backup'), dict) and protection['backup'].get('policyEnforced') is False:
                bad.append(vid)
                continue
        backup = get(volume, "properties.dataProtection.backup", dict)
        policy_id = _arm_id(get(backup, "backupPolicyId", str))
        vault_id = _arm_id(get(backup, "backupVaultId", str))
        enforced = get(backup, "policyEnforced", bool)
        if not enforced or policy_id not in netapp_policies or vault_id not in netapp_vaults:
            bad.append(vid)
    return result(bool(bad), unprotected_resources=bad)


@_signed("azure_azure_resource_1_3_1_46_b70e2c8", ["virtual_network_gateway", "virtual_network_gateway_connection"], target="scope")
def vpn_tunnels(item, index):
    gateways = {get(x, "id", str).casefold() for x in _rows(index, "virtual_network_gateway")}
    connections = {get(x, "id", str).casefold(): x for x in _rows(index, "virtual_network_gateway_connection")}
    policy = _policy(index, "vpnTunnels")
    gateway = _arm_id(get(policy, "gatewayId", str))
    expected = get(policy, "expectedTunnels", list)
    if gateway not in gateways or len(expected) != 2:
        raise Unavailable("expected gateway or two tunnel identities unavailable")
    seen = set()
    bad = []
    for declaration in expected:
        connection_id = _arm_id(get(declaration, "connectionId", str))
        tunnel_id = get(declaration, "tunnel", str)
        identity = (connection_id, tunnel_id)
        if not tunnel_id or identity in seen:
            raise Unavailable("ambiguous expected tunnel")
        seen.add(identity)
        connection = connections.get(connection_id)
        if connection is None:
            raise Unavailable("selected VPN connection missing")
        props = get(connection, "properties", dict)
        first = _arm_id(get(props, "virtualNetworkGateway1.id", str))
        second = props.get("virtualNetworkGateway2")
        second_id = _arm_id(get(second, "id", str)) if isinstance(second, dict) else None
        if gateway not in (first, second_id):
            raise Unavailable("VPN connection belongs to another gateway")
        tunnels = _objects(props, "tunnelConnectionStatus")
        if len({get(t, "tunnel", str) for t in tunnels}) != len(tunnels):
            raise Unavailable("duplicate tunnel identity")
        match = [t for t in tunnels if get(t, "tunnel", str) == tunnel_id]
        if not match:
            bad.append(identity)
            continue
        state = get(match[0], "connectionStatus", str)
        if state == "Disconnected":
            bad.append(identity)
        elif state != "Connected":
            raise Unavailable("unsupported tunnel health")
    for connection_id in {connection_id for connection_id, _ in seen}:
        observed = {(connection_id, get(tunnel, "tunnel", str))
                    for tunnel in _objects(get(connections[connection_id], "properties", dict), "tunnelConnectionStatus")}
        if observed - seen:
            raise Unavailable("unexpected tunnel identity on selected connection")
    return result(bool(bad), disconnected_or_missing_tunnels=bad)


@_signed("azure_application_gateway_app_http_logs_enabled_2de0361",
         ["application_gateway", "load_balancer", "diagnostic_setting", "diagnostic_category", "log_analytics_workspace", "storage_account"], target="scope")
def gateway_and_balancer_logs(item, index):
    resources = _rows(index, "application_gateway") + _rows(index, "load_balancer")
    settings = _rows(index, "diagnostic_setting")
    categories = _rows(index, "diagnostic_category")
    destinations = {get(x, "id", str).casefold() for kind in ("log_analytics_workspace", "storage_account") for x in _rows(index, kind)}
    by_resource = {}
    for category in categories:
        parent = _arm_id(get(category, "resourceId", str))
        by_resource.setdefault(parent, []).append(category)
    bad = []
    for resource in resources:
        rid = _arm_id(get(resource, "id", str))
        supported = set()
        for category in by_resource.get(rid, []):
            name = get(category, "name", str)
            if get(category, "categoryType", str) == "Logs" and ("access" in name.casefold() or "operational" in name.casefold()):
                supported.add(name)
        if not supported:
            raise Unavailable("resource log category support unresolved")
        good = False
        for setting in settings:
            sid = get(setting, "id", str).casefold()
            if not sid.startswith(rid + "/providers/microsoft.insights/diagnosticsettings/"):
                continue
            props = get(setting, "properties", dict)
            destination_ids = []
            for field in ("workspaceId", "storageAccountId"):
                if field in props:
                    destination_ids.append(_arm_id(get(props, field, str)))
            enabled = {get(x, "category", str) for x in _objects(props, "logs") if get(x, "enabled", bool)}
            if supported & enabled and any(x in destinations for x in destination_ids):
                good = True
        if not good:
            bad.append(rid)
    return result(bool(bad), resources_without_export=bad)


@_signed("azure_c5_am_09_01b", ["resource_graph"] , target="scope")
def classified_asset_labels(item, index):
    assets = _rows(index, "resource_graph")
    policy = _policy(index, "classification")
    tag_key = get(policy, "tagKey", str)
    entries = _objects(policy, "assets")
    expected = {}
    for entry in entries:
        eid = _arm_id(get(entry, "id", str))
        if eid in expected:
            raise Unavailable("duplicate classification authority")
        expected[eid] = entry
    bad = []
    for asset in assets:
        rid = _arm_id(get(asset, "id", str))
        get(asset, "type", str)
        entry = expected.get(rid)
        if entry is None:
            raise Unavailable("asset classification applicability unresolved")
        if not get(entry, "applicable", bool):
            continue
        if not get(entry, "tagSuitable", bool):
            raise Unavailable("tag suitability unresolved")
        label = get(entry, "approvedLabel", str)
        if not label:
            raise Unavailable("asset classification absent")
        tags = get(asset, "tags", dict)
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in tags.items()):
            raise Unavailable("malformed resource tags")
        if tags.get(tag_key) != label:
            bad.append(rid)
    if set(expected) != {_arm_id(get(asset, "id", str)) for asset in assets}:
        raise Unavailable("classification evidence includes foreign assets")
    return result(bool(bad), absent_or_mismatched_labels=bad)


@_signed("azure_c5_cry_08_01b", ["key_vault_certificate_current"], target="scope")
def certificate_issuance(item, index):
    policy = _policy(index, "certificateIssuance")
    issuers = get(policy, "approvedIssuers", list)
    types = get(policy, "approvedKeyTypes", list)
    curves = get(policy, "approvedEcCurves", list)
    minimum_rsa = get(policy, "minimumRsaBits", int)
    if not issuers or not types or minimum_rsa < 2048 or not all(isinstance(x, str) for x in issuers + types + curves):
        raise Unavailable("certificate policy incomplete")
    bad = []
    for certificate in _rows(index, "key_vault_certificate_current"):
        cid = _arm_id(get(certificate, "id", str))
        if get(certificate, "isCurrentVersion", bool) is not True:
            raise Unavailable("certificate current version unresolved")
        props = get(certificate, "policy", dict)
        issuer = get(props, "issuer.name", str)
        key_type = get(props, "key_props.kty", str)
        if issuer not in issuers or key_type not in types:
            bad.append(cid)
            continue
        if key_type in ("RSA", "RSA-HSM"):
            if get(props, "key_props.key_size", int) < minimum_rsa:
                bad.append(cid)
        elif key_type in ("EC", "EC-HSM"):
            if get(props, "key_props.curve", str) not in curves:
                bad.append(cid)
        else:
            raise Unavailable("unsupported certificate key type")
    if bad:
        return result(True, certificates_violating_policy=bad)
    process = _rows(index, "certificate_issuance_evidence")
    if len(process) != 1 or get(process[0], "id", str).casefold() != _scope(index):
        raise Unavailable("issuance process evidence missing or foreign")
    start = _timestamp(get(process[0], "periodStart", str))
    end = _timestamp(get(process[0], "periodEnd", str))
    assessed = _timestamp(get(policy, "assessedAt", str))
    if not start <= assessed <= end:
        raise Unavailable("issuance process evidence does not cover assessment")
    fields = ("procedureCurrent", "identityVerified", "secureIssuance", "trustedCaVerified")
    values = {field: get(process[0], field, bool) for field in fields}
    if not all(values.values()):
        return result(True, violated_process_requirements=[k for k, v in values.items() if not v])
    return result(False, assessed_at=assessed.isoformat())


@_signed("azure.cis.auto_provision_vulnerability_assessment_machines",
         ["security_pricing", "server_vulnerability_assessment_setting", "arc_machine", "arc_vulnerability_assessment_evidence"], target="scope")
def machine_vulnerability_assessment(item, index):
    pricings = _rows(index, "security_pricing")
    pricing = [x for x in pricings if get(x, "name", str) == "VirtualMachines"]
    if len(pricing) != 1:
        raise Unavailable("Defender VM pricing unresolved")
    bad = []
    tier = get(pricing[0], "properties.pricingTier", str)
    if tier == "Free":
        bad.append("VirtualMachines pricing")
    elif tier != "Standard":
        raise Unavailable("unrecognized VM pricing tier")
    try:
        setting_rows = _rows(index, "server_vulnerability_assessment_setting")
        if len(setting_rows) != 1:
            raise Unavailable("Azure server vulnerability setting unresolved")
        setting = setting_rows[0]
        if setting.get("status") == "not_found" and get(setting, "httpStatus", int) == 404:
            bad.append("Azure server vulnerability setting absent after 404")
        else:
            kind = get(setting, "kind", str)
            provider = get(setting, "properties.selectedProvider", str)
            if kind != "AzureServersSetting" or provider != "MdeTvm":
                if kind in ("AzureServersSetting", "Disabled") and provider in ("MdeTvm", "None"):
                    bad.append("Azure server vulnerability setting disabled")
                else:
                    raise Unavailable("unrecognized server vulnerability setting")
        machines = _rows(index, "arc_machine")
        evidence = {get(x, "machineId", str).casefold(): x for x in _rows(index, "arc_vulnerability_assessment_evidence")}
        for machine in machines:
            mid = get(machine, "id", str).casefold()
            row = evidence.get(mid)
            if row is None:
                raise Unavailable("Arc machine integration evidence absent")
            if not get(row, "autoProvisioned", bool):
                bad.append(mid)
        if set(evidence) != {get(machine, "id", str).casefold() for machine in machines}:
            raise Unavailable("foreign Arc assessment evidence")
    except Unavailable:
        if not bad:
            raise
    return result(bool(bad), gaps=bad)


@_signed("azure.cis.unity_catalog_configured_databricks", ["databricks_account_workspace"], target="scope")
def unity_catalog_assignment(item, index):
    policy = _policy(index, "databricksAccount")
    account = get(policy, "accountId", str)
    if not account:
        raise Unavailable("Databricks account ID absent")
    bad = []
    for workspace in _rows(index, "databricks_account_workspace"):
        if get(workspace, "accountId", str) != account:
            raise Unavailable("foreign Databricks account workspace")
        wid = get(workspace, "workspaceId", int)
        if wid < 0:
            raise Unavailable("malformed workspace ID")
        state = get(workspace, "state", str)
        if state not in ("ACTIVE", "DELETED"):
            raise Unavailable("unrecognized workspace state")
        if state == "DELETED":
            continue
        metastore = get(workspace, "metastore", dict)
        if metastore.get("httpStatus") == 404 and metastore.get("documentedNoAssignment") is True:
            bad.append(wid)
            continue
        if get(metastore, "httpStatus", int) != 200:
            raise Unavailable("metastore assignment read unavailable")
        assignment = get(metastore, "metastore_assignment", dict)
        if get(assignment, "workspace_id", int) != wid or not get(assignment, "metastore_id", str):
            raise Unavailable("inconsistent Databricks metastore assignment")
    return result(bool(bad), workspaces_without_metastore=bad)


def _backup_alert_capture_authority(index, policy, proof):
    """Require a scoped, attributed capture before accepting any signal result."""
    context = get(index, "context", dict)
    metadata = get(context, "metadata", dict)
    captured = _timestamp(get(context, "created_at", str))
    credential = get(metadata, "credential_context_id", str)
    customer = get(metadata, "customer_context_id", str)
    if not credential.strip() or not customer.strip():
        raise Unavailable("backup alert capture identity absent")
    authorized = get(policy, "authorizedObservationDocumentIds", list)
    if (not authorized or any(not isinstance(x, str) or not x.strip() for x in authorized)):
        raise Unavailable("backup alert observation authorization unresolved")
    origin = get(proof, "_provenance", dict)
    if (get(origin, "authorizationDocumentId", str) not in authorized or
            get(origin, "scope", str).rstrip("/").casefold() != _scope(index) or
            get(origin, "credential_context_id", str) != credential or
            get(origin, "customer_context_id", str) != customer or
            get(origin, "readOnly", bool) is not True or
            _timestamp(get(origin, "capturedAt", str)) != captured):
        raise Unavailable("backup alert proof capture unresolved")
    return origin


def _backup_alert_external(index, policy, proof, sid, name, signal, groups, window):
    """Validate externally supplied read-only trigger and complete receiver search."""
    context = get(index, "context", dict)
    metadata = get(context, "metadata", dict)
    captured = _timestamp(get(context, "created_at", str))
    credential = get(metadata, "credential_context_id", str)
    customer = get(metadata, "customer_context_id", str)
    if not credential.strip() or not customer.strip():
        raise Unavailable("backup alert capture identity absent")
    start = _timestamp(get(policy, "windowStart", str))
    end = _timestamp(get(policy, "windowEnd", str))
    if not start < end <= captured:
        raise Unavailable("backup alert observation window unresolved")
    action = _arm_id(get(signal, "actionGroupId", str))
    approved_actions = {_arm_id(x) for x in get(policy, "approvedActionGroupIds", list)}
    receivers = get(policy, "approvedReceiverIds", list)
    if (not approved_actions or action not in approved_actions or action not in groups or
            not isinstance(receivers, list) or not receivers or
            any(not isinstance(x, str) or not x.strip() for x in receivers)):
        raise Unavailable("backup alert destination approval unresolved")
    authorized = get(policy, "authorizedObservationDocumentIds", list)
    if (not isinstance(authorized, list) or not authorized or
            any(not isinstance(x, str) or not x.strip() for x in authorized)):
        raise Unavailable("backup alert observation authorization unresolved")
    trigger_source = get(policy, "triggerSourceId", str)
    delivery_source = get(policy, "deliverySourceId", str)
    if not trigger_source.strip() or not delivery_source.strip() or trigger_source == delivery_source:
        raise Unavailable("independent backup alert sources unresolved")
    origin = get(proof, "_provenance", dict)
    if (get(origin, "scope", str).rstrip("/").casefold() != _scope(index) or
            get(origin, "credential_context_id", str) != credential or
            get(origin, "customer_context_id", str) != customer or
            get(origin, "readOnly", bool) is not True or
            get(origin, "authorizationDocumentId", str) not in authorized or
            _timestamp(get(origin, "capturedAt", str)) != captured):
        raise Unavailable("backup alert proof capture unresolved")
    trigger = get(signal, "triggerObservation", dict)
    delivery = get(signal, "deliveryObservation", dict)
    for observation, source in ((trigger, trigger_source), (delivery, delivery_source)):
        if (get(observation, "serviceId", str).casefold() != sid or
                get(observation, "signal", str) != name or
                get(observation, "sourceId", str) != source or
                get(observation, "scope", str).rstrip("/").casefold() != _scope(index) or
                get(observation, "credential_context_id", str) != credential or
                get(observation, "customer_context_id", str) != customer or
                _timestamp(get(observation, "capturedAt", str)) != captured or
                not get(observation, "observer", str).strip() or
                get(observation, "authorizationDocumentId", str) not in authorized or
                get(observation, "readOnly", bool) is not True):
            raise Unavailable("backup alert independent observation unresolved")
    if get(trigger, "observer", str) == get(delivery, "observer", str):
        raise Unavailable("backup alert observations are not independent")
    event = get(trigger, "eventId", str)
    if not event.strip() or get(delivery, "eventId", str) != event:
        raise Unavailable("backup alert trigger identity unresolved")
    occurred = _timestamp(get(trigger, "eventAt", str))
    if not start <= occurred < end:
        raise Unavailable("backup alert trigger outside approved window")
    if get(delivery, "complete", bool) is not True:
        raise Unavailable("backup alert receiver search incomplete")
    from datetime import timedelta
    deadline = occurred + timedelta(minutes=window)
    if (_timestamp(get(delivery, "windowStart", str)) > occurred or
            _timestamp(get(delivery, "windowEnd", str)) < deadline or
            _timestamp(get(delivery, "windowEnd", str)) > captured):
        raise Unavailable("backup alert receiver window unresolved")
    matches = get(delivery, "deliveries", list)
    if not isinstance(matches, list):
        raise Unavailable("malformed backup alert receiver records")
    if not matches:
        return False
    timely = False
    seen = set()
    for row in matches:
        if not isinstance(row, dict):
            raise Unavailable("malformed backup alert receiver record")
        identity = get(row, "alertLogId", str)
        if not identity.strip() or identity in seen:
            raise Unavailable("ambiguous backup alert receiver record")
        seen.add(identity)
        if (get(row, "serviceId", str).casefold() != sid or
                get(row, "signal", str) != name or
                get(row, "eventId", str) != event):
            raise Unavailable("foreign backup alert receiver record")
        delivered = _timestamp(get(row, "deliveredAt", str))
        if delivered < occurred or delivered > captured:
            raise Unavailable("backup alert receiver time contradiction")
        receiver = get(row, "receiverId", str)
        if (_arm_id(get(row, "actionGroupId", str)) == action and
                receiver in receivers and delivered <= deadline):
            timely = True
    return timely


@_signed("azure.other.database_backup_alert",
         ["database_backup_service", "database_backup_alert_evidence", "monitor_action_group"], target="scope")
def database_backup_alert(item, index):
    services = _rows(index, "database_backup_service")
    proof_rows = _rows(index, "database_backup_alert_evidence")
    evidence = {}
    for proof in proof_rows:
        service_id = _arm_id(get(proof, "serviceId", str))
        if service_id in evidence:
            raise Unavailable("duplicate backup alert service evidence")
        evidence[service_id] = proof
    groups = {get(x, "id", str).casefold() for x in _rows(index, "monitor_action_group")}
    policy = _policy(index, "backupAlerts")
    window = get(policy, "responseWindowMinutes", int)
    if window <= 0:
        raise Unavailable("backup alert response window invalid")
    service_ids = [_arm_id(get(service, "id", str)) for service in services]
    if set(evidence) - set(service_ids):
        raise Unavailable("foreign backup alert evidence")
    if not service_ids:
        return unknown("backup alert service universe empty")
    bad = []
    unresolved_services = []
    unresolved_signals = []
    for sid in service_ids:
        proof = evidence.get(sid)
        if proof is None:
            unresolved_services.append(sid)
            continue
        try:
            _backup_alert_capture_authority(index, policy, proof)
            signals = get(proof, "signals", dict)
        except Unavailable:
            unresolved_services.append(sid)
            continue
        for name in ("disabled", "paused", "scheduledFailure"):
            try:
                signal = get(signals, name, dict)
                observable = get(signal, "observable", bool)
                if not observable:
                    bad.append((sid, name, "signal absent"))
                    continue
                state = get(signal, "testStatus", str)
                if state == "failed":
                    bad.append((sid, name, "alert test failed"))
                    continue
                if state != "passed":
                    unresolved_signals.append((sid, name))
                    continue
                if not _backup_alert_external(index, policy, proof, sid, name, signal, groups, window):
                    bad.append((sid, name, "alert window or delivery failed"))
            except Unavailable:
                unresolved_signals.append((sid, name))
    if bad:
        return result(True, failed_signals=bad, unresolved_services=unresolved_services,
                      unresolved_signals=unresolved_signals)
    if unresolved_services or unresolved_signals:
        return unknown("backup alert evidence unresolved", unresolved_services=unresolved_services,
                       unresolved_signals=unresolved_signals)
    return result(False, failed_signals=bad)


@_signed("azure.other.message_namespace_cmk",
         ["eventhub_namespace", "servicebus_namespace"], target="scope")
def messaging_cmk(item, index):
    namespaces = _rows(index, "eventhub_namespace") + _rows(index, "servicebus_namespace")
    observed_service_keys = []
    for namespace in namespaces:
        nid = _arm_id(get(namespace, "id", str))
        if get(namespace, "sku.tier", str) not in ("Premium", "Dedicated"):
            continue
        source = get(namespace, "properties.encryption.keySource", str)
        if source in ("Microsoft.Storage", "Microsoft.ServiceBus", "Microsoft.EventHub", "ServiceManaged"):
            observed_service_keys.append((nid, "service-managed key"))
    if observed_service_keys:
        return result(True, failures=observed_service_keys)
    tests = {get(x, "namespaceId", str).casefold(): x for x in _rows(index, "message_cmk_negative_test")}
    policy = _policy(index, "messagingCmk")
    approved = {get(x, "id", str).casefold() for x in _objects(policy, "approvedKeys")}
    if not approved:
        raise Unavailable("approved messaging key set absent")
    failures = []
    unresolved = []
    for namespace in namespaces:
        nid = _arm_id(get(namespace, "id", str))
        tier = get(namespace, "sku.tier", str)
        if tier not in ("Premium", "Dedicated"):
            unresolved.append(nid)
            continue
        encryption = get(namespace, "properties.encryption", dict)
        source = get(encryption, "keySource", str)
        if source in ("Microsoft.Storage", "Microsoft.ServiceBus", "Microsoft.EventHub", "ServiceManaged"):
            failures.append((nid, "service-managed key"))
            continue
        if source != "Microsoft.KeyVault":
            unresolved.append(nid)
            continue
        keys = _objects(encryption, "keyVaultProperties")
        if len(keys) != 1:
            unresolved.append(nid)
            continue
        key_id = get(keys[0], "keyVaultKeyUrl", str).casefold()
        if key_id not in approved:
            failures.append((nid, "unapproved key"))
            continue
        test = tests.get(nid)
        if test is None:
            unresolved.append(nid)
            continue
        if not get(test, "keyUsable", bool):
            unresolved.append(nid)
            continue
        if not get(test, "withoutCmkRejected", bool):
            failures.append((nid, "publish accepted without CMK"))
    if failures:
        return result(True, failures=failures)
    if unresolved or set(tests) != {_arm_id(get(n, "id", str)) for n in namespaces}:
        return unknown("namespace tier, key access or negative-test evidence unresolved", namespaces=unresolved)
    return result(False, namespace_count=len(namespaces))


@_signed("azure.other.change_approval_trace", ["activity_log", "activity_log_coverage", "change_approval_record"], target="scope")
def change_approval_trace(item, index):
    policy = _policy(index, "changeApproval")
    start = _timestamp(get(policy, "windowStart", str))
    end = _timestamp(get(policy, "windowEnd", str))
    if start >= end:
        raise Unavailable("invalid change review window")
    from peaso.collectors.azure_wave_change_native import (
        ActivityCoverageError, validate_native_activity_if_present,
    )
    try:
        validate_native_activity_if_present(
            index, _scope(index), policy["windowStart"], policy["windowEnd"], end_inclusive=True
        )
    except ActivityCoverageError as exc:
        raise Unavailable(str(exc)) from exc
    coverage = _rows(index, "activity_log_coverage")
    if len(coverage) != 1 or get(coverage[0], "id", str).casefold() != _scope(index):
        raise Unavailable("activity log coverage missing")
    if _timestamp(get(coverage[0], "retainedFrom", str)) > start or _timestamp(get(coverage[0], "collectedThrough", str)) < end:
        raise Unavailable("activity log retention or paging does not cover window")
    events = _rows(index, "activity_log")
    approvals = _rows(index, "change_approval_record")
    by_correlation = {}
    unjoinable_resources = set()
    for approval in approvals:
        key = get(approval, "correlationId", str).casefold()
        resource = _arm_id(get(approval, "resourceId", str))
        if not resource.startswith(_scope(index) + "/"):
            raise Unavailable("foreign change approval resource")
        if not key.strip():
            unjoinable_resources.add(resource)
            continue
        by_correlation.setdefault(key, []).append((resource, approval))
    relevant = []
    unresolved = []
    for event in events:
        when = _timestamp(get(event, "eventTimestamp", str))
        if not start <= when <= end:
            continue
        operation = get(event, "operationName.value", str).casefold()
        status = get(event, "status.value", str)
        if status not in ("Succeeded", "Failed", "Started", "Accepted"):
            raise Unavailable("unrecognized Activity Log status")
        if status != "Succeeded" or not operation.endswith(("/write", "/delete")):
            continue
        resource = _arm_id(get(event, "resourceId", str))
        if not resource.startswith(_scope(index) + "/"):
            raise Unavailable("foreign change event resource")
        get(event, "caller", str)
        correlation = get(event, "correlationId", str).casefold()
        if not correlation.strip():
            unresolved.append(get(event, "id", str))
            continue
        candidates = [approval for approved_resource, approval in by_correlation.get(correlation, [])
                      if approved_resource == resource]
        if not candidates and resource in unjoinable_resources:
            unresolved.append(get(event, "id", str))
            continue
        if len(candidates) > 1:
            raise Unavailable("ambiguous change approval join")
        relevant.append((get(event, "id", str), when, candidates[0] if candidates else None))
    bad = []
    for event_id, when, approval in relevant:
        if approval is None:
            bad.append(event_id)
            continue
        try:
            if not get(approval, "ticketId", str).strip() or not get(approval, "approver", str).strip():
                unresolved.append(event_id)
                continue
            state = get(approval, "status", str)
            approved_at = _timestamp(get(approval, "approvedAt", str))
        except Unavailable:
            unresolved.append(event_id)
            continue
        if state != "Approved":
            if state in ("Rejected", "Cancelled"):
                bad.append(event_id)
            else:
                unresolved.append(event_id)
            continue
        if approved_at > when:
            bad.append(event_id)
    details = {"changes_without_predating_approval": bad, "unresolved_changes": unresolved,
               "semantics": "traceability signal; organizational process assessed separately"}
    if bad:
        return result(True, **details)
    if unresolved:
        return unknown("ticket lifecycle or approver unresolved", **details)
    return result(False, **details)


# Use the actual credential-bound membership collection for tenant dispatch.
user_group_membership.evaluation_scope = "tenant"
user_group_membership.evaluation_scope_kind = "directory_user_group_membership"
