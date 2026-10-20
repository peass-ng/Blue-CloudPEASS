"""Reviewed service-level GCP metadata predicates, independent of live APIs."""
from __future__ import annotations
import copy
from . import register, result, unknown, CHECKS
from .facts import get, guard, Unavailable, list_of_objects, optional
from .fixtures import CASES, nest

IDS, REFERENCE_SPECS, SQL_SPECS = [], {}, {}


def scalar(query, kind, path, good, bad, title, *, canonical=None):
    if canonical:
        REFERENCE_SPECS[query] = canonical
        return
    cid = "gcp.ports." + query
    IDS.append(cid)
    expected = type(good)
    @register(cid, "gcp", "hardening", kind, title, "medium", "CM-6",
        "Review the explicit native service setting and its version/workload applicability before changing configuration.")
    def evaluate(item, index):
        if query == "sql_instance_mysql_binary_log_enabled":
            import re
            version = get(item, "databaseVersion", str)
            if re.fullmatch(r"(?:POSTGRES_[0-9]+(?:_[0-9]+)?|SQLSERVER_[0-9]+_(?:STANDARD|ENTERPRISE|EXPRESS|WEB))", version):
                return "NOT_APPLICABLE", {"reason": "binaryLogEnabled is a MySQL-only configuration field", "database_version": version}
            if not re.fullmatch(r"MYSQL_[0-9]+(?:_[0-9]+)*", version):
                return unknown("unrecognized Cloud SQL engine/version for binary log configuration")
        value = get(item, path, expected)
        if expected is str and value not in (good, bad):
            return unknown("unrecognized native service setting", field=path)
        return result(value != good, field=path, configured=value, semantics="Configuration declaration, not runtime or effective-access proof")
    CASES[cid] = {"pass": nest(path, good), "fail": nest(path, bad), "missing": {}, "malformed": None}
    REFERENCE_SPECS[query] = cid


scalar("kubernetes_cluster_private_cluster_config_enabled", "gke_cluster", "privateClusterConfig.enablePrivateEndpoint", True, False,
       "GKE explicitly enables private control-plane endpoint", canonical="gcp.gke.private_endpoint")
scalar("kubernetes_cluster_legacy_abac_enabled", "gke_cluster", "legacyAbac.enabled", False, True,
       "GKE explicitly disables legacy ABAC", canonical="gcp.gke.no_legacy_abac")
scalar("kubernetes_cluster_private_nodes_configured", "gke_cluster", "privateClusterConfig.enablePrivateNodes", True, False,
       "GKE explicitly configures private nodes", canonical="gcp.gke.private_nodes")
scalar("kubernetes_cluster_master_authorized_networks_config_enabled", "gke_cluster", "masterAuthorizedNetworksConfig.enabled", True, False,
       "GKE explicitly enables authorized networks", canonical="gcp.gke.authorized_networks")
scalar("kubernetes_cluster_shielded_nodes_enabled", "gke_cluster", "shieldedNodes.enabled", True, False,
       "GKE explicitly enables shielded nodes", canonical="gcp.gke.shielded_nodes")
scalar("kubernetes_cluster_database_encryption_enabled", "gke_cluster", "databaseEncryption.state", "ENCRYPTED", "DECRYPTED",
       "GKE explicitly configures database encryption", canonical="gcp.gke.secrets_encryption")
scalar("kubernetes_cluster_network_policy_installed", "gke_cluster", "networkPolicy.enabled", True, False,
       "GKE explicitly enables NetworkPolicy", canonical="gcp.gke.network_policy")
scalar("compute_subnetwork_private_ip_google_access", "subnetwork", "privateIpGoogleAccess", True, False,
       "Subnet explicitly enables Private Google Access", canonical="gcp.subnetwork.private_google_access")
scalar("compute_subnetwork_flow_log_enabled", "subnetwork", "logConfig.enable", True, False,
       "Subnet explicitly enables Flow Logs", canonical="gcp.reviewed.network.flow_logs")
scalar("storage_bucket_uniform_access_enabled", "bucket", "iamConfiguration.uniformBucketLevelAccess.enabled", True, False,
       "Bucket explicitly enables uniform access", canonical="gcp.storage.uniform_access")
scalar("sql_instance_automated_backups_enabled", "sql_instance", "settings.backupConfiguration.enabled", True, False,
       "SQL instance explicitly enables automated backups", canonical="gcp.sql.backups")
IDS.append("gcp.ports.app_engine_application_iap_enabled")
REFERENCE_SPECS["app_engine_application_iap_enabled"] = "gcp.ports.app_engine_application_iap_enabled"


@register("gcp.ports.app_engine_application_iap_enabled", "gcp", "hardening", "app_engine_application",
    "App Engine application enables IAP", "medium", "CM-6",
    "Review the explicit native service setting and its version/workload applicability before changing configuration.")
def app_engine_iap(item, index):
    # apps.get returns the full Application; IdentityAwareProxy.enabled is a
    # proto3 bool ("Whether the serving infrastructure will authenticate and
    # authorize all incoming requests"), so ProtoJSON omits it when false and
    # omits the whole iap message when nothing is set. Only on an identified
    # application (id + name apps/<id>) is that omission read as disabled.
    app_id = get(item, "id", str)
    if get(item, "name", str) != "apps/" + app_id:
        return unknown("App Engine application identity unavailable")
    iap = optional(item, "iap", {}, dict)
    enabled = optional(iap, "enabled", False, bool)
    return result(not enabled, field="iap.enabled", configured=enabled, declared="iap.enabled" in item.get("iap", {}),
        semantics="Application-level IAP declaration, not per-service access or ingress proof")
CASES["gcp.ports.app_engine_application_iap_enabled"] = {
    "pass": {"id": "a", "name": "apps/a", "iap": {"enabled": True, "oauth2ClientId": "c"}},
    "fail": {"id": "a", "name": "apps/a", "defaultHostname": "a.uc.r.appspot.com"},
    "unknown": {"id": "a", "name": "apps/b"}, "missing": {}, "malformed": None}
scalar("sql_instance_mysql_binary_log_enabled", "sql_instance", "settings.backupConfiguration.binaryLogEnabled", True, False,
       "MySQL explicitly enables binary log backups")


def pool_scalar(query, path, good, bad, title, *, absent=None):
    """Evaluate `path` under every nodePools[].config, not only the cluster's
    default-pool nodeConfig. `absent` is the documented default of an omitted
    field; None keeps an omitted field UNKNOWN."""
    cid = "gcp.ports." + query
    IDS.append(cid)
    expected = type(good)
    @register(cid, "gcp", "hardening", "gke_cluster", title, "medium", "CM-6",
        "Review every node pool's configuration and recreate or update non-compliant pools.")
    def evaluate(item, index):
        get(item, "name", str)
        pools = list_of_objects(get(item, "nodePools", list))
        if not pools:
            return unknown("node-pool inventory absent; Autopilot configuration requires separate evidence")
        values, failing = {}, []
        for pool in pools:
            name = get(pool, "name", str)
            value = get(pool, "config", dict)
            parts = path.split(".")
            for part in parts[:-1]:
                value = get(value, part, dict) if absent is None else optional(value, part, {}, dict)
            value = get(value, parts[-1], expected) if absent is None else optional(value, parts[-1], absent, expected)
            if value not in (good, bad):
                return unknown("unrecognized node-pool setting", node_pool=name, field=path)
            values[name] = value
            if value != good:
                failing.append(name)
        return result(bool(failing), field="nodePools[].config." + path, node_pools=values, failing_node_pools=failing,
            semantics="Every node pool's declared configuration" + ("" if absent is None else "; an omitted field is the documented default " + repr(absent)))
    def pools(*values):
        return {"name": "c", "nodePools": [{"name": "p%d" % i, "config": nest(path, value)} for i, value in enumerate(values)]}
    CASES[cid] = {"pass": pools(good, good), "fail": pools(good, bad), "missing": {}, "malformed": None,
        "unknown": {"name": "c", "nodePools": [{"name": "p0", "config": nest(path, {"unexpected": True})}]}}
    REFERENCE_SPECS[query] = cid


pool_scalar("kubernetes_cluster_legacy_endpoints_disabled", "metadata.disable-legacy-endpoints", "true", "false",
       "Every GKE node pool explicitly disables legacy metadata endpoints")
pool_scalar("kubernetes_cluster_node_config_image_cos_containerd", "imageType", "COS_CONTAINERD", "UBUNTU_CONTAINERD",
       "Every GKE node pool selects COS with containerd")
# GKE: "Integrity monitoring is a node pool setting that's enabled by default";
# "Secure boot is disabled by default on node pools" (Shielded GKE nodes how-to).
pool_scalar("kubernetes_cluster_shielded_instance_integrity_monitoring_enabled", "shieldedInstanceConfig.enableIntegrityMonitoring", True, False,
       "Every GKE node pool enables integrity monitoring", absent=True)
pool_scalar("kubernetes_cluster_shielded_node_secure_boot_enabled", "shieldedInstanceConfig.enableSecureBoot", True, False,
       "Every GKE node pool enables Shielded VM secure boot", absent=False)


@register("gcp.ports.kubernetes_cluster_use_ip_aliases", "gcp", "hardening", "gke_cluster", "GKE uses alias IP ranges (VPC-native)", "medium", "CM-6",
    "Create VPC-native clusters (alias IP ranges) instead of routes-based clusters.")
def use_ip_aliases(item, index):
    # The API makes these mode selectors mutually exclusive. Both false
    # delegates mode selection to the server; it is not evidence of routes.
    get(item, "name", str)
    policy = get(item, "ipAllocationPolicy", dict)
    aliases = optional(policy, "useIpAliases", None, bool)
    routes = optional(policy, "useRoutes", None, bool)
    if aliases is True and routes is True:
        return unknown("contradictory IP allocation modes: aliases and routes are both true")
    if aliases is True:
        return result(False, field="ipAllocationPolicy.useIpAliases", configured=True, use_routes=routes,
                      semantics="Explicit nonconflicting alias selection; no server default inferred")
    if routes is True:
        return result(True, field="ipAllocationPolicy.useIpAliases", configured=False, use_routes=True,
                      semantics="Explicit route selection excludes alias IPs")
    raise Unavailable("IP allocation mode unresolved: server-chosen default without a selected mode")
IDS.append("gcp.ports.kubernetes_cluster_use_ip_aliases")
REFERENCE_SPECS["kubernetes_cluster_use_ip_aliases"] = "gcp.ports.kubernetes_cluster_use_ip_aliases"
CASES["gcp.ports.kubernetes_cluster_use_ip_aliases"] = {"pass": {"name": "c", "ipAllocationPolicy": {"useIpAliases": True}},
    "fail": {"name": "c", "ipAllocationPolicy": {"useRoutes": True}}, "missing": {}, "malformed": None,
    "unknown": {"name": "c", "ipAllocationPolicy": {}}}


@register("gcp.ports.kubernetes_cluster_intra_node_visibility_enabled", "gcp", "hardening", "gke_cluster", "GKE enables intra-node visibility", "medium", "CM-6",
    "Enable intra-node visibility so same-node pod-to-pod traffic is visible to VPC flow logs and firewall rules.")
def intra_node_visibility(item, index):
    # NetworkConfig.enableIntraNodeVisibility: "Whether Intra-node visibility is
    # enabled for this cluster"; a false proto3 boolean is omitted.
    get(item, "name", str)
    network = optional(item, "networkConfig", {}, dict)
    enabled = optional(network, "enableIntraNodeVisibility", False, bool)
    return result(not enabled, field="networkConfig.enableIntraNodeVisibility", configured=enabled,
        semantics="Absent enableIntraNodeVisibility is the proto3 false default")
IDS.append("gcp.ports.kubernetes_cluster_intra_node_visibility_enabled")
REFERENCE_SPECS["kubernetes_cluster_intra_node_visibility_enabled"] = "gcp.ports.kubernetes_cluster_intra_node_visibility_enabled"
CASES["gcp.ports.kubernetes_cluster_intra_node_visibility_enabled"] = {"pass": {"name": "c", "networkConfig": {"enableIntraNodeVisibility": True}},
    "fail": {"name": "c", "networkConfig": {"network": "n"}}, "missing": {}, "malformed": None,
    "unknown": {"name": "c", "_coverage": {"networkConfig": {"status": "denied"}}}}


def sql_flag(query, engine, flag, allowed, rejected, *, canonical=None, presence=False, forbidden=False):
    if canonical:
        REFERENCE_SPECS[query] = canonical
        return
    cid = "gcp.ports." + query
    IDS.append(cid)
    SQL_SPECS[cid] = {"engine": engine, "flag": flag, "allowed": tuple(allowed), "presence": presence, "forbidden": forbidden}
    @register(cid, "gcp", "hardening", "sql_instance", "Cloud SQL reviews explicit " + flag + " configuration", "medium", "CM-6",
        "Review the database engine/version and configure the named flag according to the intended logging or security policy.")
    def evaluate(item, index):
        version = get(item, "databaseVersion", str)
        if not version.startswith(("MYSQL", "POSTGRES", "SQLSERVER")):
            return unknown("unrecognized database engine")
        if not version.startswith(engine):
            return "NOT_APPLICABLE", {"reason": "Different database engine", "database_version": version}
        flags = {}
        for row in list_of_objects(get(item, "settings.databaseFlags", list)):
            name, value = get(row, "name", str), get(row, "value", str)
            # The native 3625 name includes its documented trace-flag suffix;
            # old imported fixtures used the short name. Reject two aliases.
            if flag == "3625" and name == "3625 (trace flag)":
                name = flag
            if flag == "3625" and name == flag and value not in ("on", "off"):
                return unknown("unrecognized trace flag value", flag=flag)
            if name in flags:
                return unknown("duplicate database flag")
            flags[name] = value
        if forbidden:
            failed = flag in flags
        elif presence:
            failed = flag not in flags
        else:
            failed = flags.get(flag) not in allowed
        return result(failed, flag=flag, configured=flags.get(flag), database_version=version,
            semantics="Explicit flag declaration; version-specific default behavior is not inferred")
    def fixture(value, exists=True):
        return {"databaseVersion": engine + "_16", "settings": {"databaseFlags": [{"name": flag, "value": value}] if exists else []}}
    CASES[cid] = {"pass": fixture(allowed[0] if allowed else "0", not forbidden),
        "fail": fixture(rejected, forbidden or not presence), "missing": {}, "malformed": None}
    REFERENCE_SPECS[query] = cid


sql_flag("sql_instance_mysql_local_infile_database_flag_off", "MYSQL", "local_infile", ["off"], "on", canonical="gcp.reviewed.sql.mysql_local_infile")
sql_flag("sql_instance_mysql_skip_show_database_flag_on", "MYSQL", "skip_show_database", ["on"], "off", canonical="gcp.reviewed.sql.mysql_skip_show_database")
sql_flag("sql_instance_postgresql_cloudsql_pgaudit_database_flag_enabled", "POSTGRES", "cloudsql.enable_pgaudit", ["on"], "off", canonical="gcp.reviewed.sql.postgres_pgaudit")
sql_flag("sql_instance_postgresql_log_connections_database_flag_on", "POSTGRES", "log_connections", ["on"], "off", canonical="gcp.reviewed.sql.postgres_log_connections")
sql_flag("sql_instance_postgresql_log_disconnections_database_flag_on", "POSTGRES", "log_disconnections", ["on"], "off", canonical="gcp.reviewed.sql.postgres_log_disconnections")
sql_flag("sql_instance_postgresql_log_statement_database_flag_ddl", "POSTGRES", "log_statement", ["ddl"], "none", canonical="gcp.reviewed.sql.postgres_log_statement")
for _flag in ("log_checkpoints", "log_duration", "log_hostname", "log_lock_waits"):
    suffix = "configured" if _flag == "log_hostname" else "on"
    sql_flag(f"sql_instance_postgresql_{_flag}_database_flag_{suffix}", "POSTGRES", _flag, ["on"], "off")
for _flag in ("log_executor_stats", "log_parser_stats", "log_planner_stats", "log_statement_stats"):
    sql_flag(f"sql_instance_postgresql_{_flag}_database_flag_off", "POSTGRES", _flag, ["off"], "on")
sql_flag("sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter", "POSTGRES", "log_error_verbosity", ["default", "verbose"], "terse")
sql_flag("sql_instance_postgresql_log_min_duration_statement_database_flag_disabled", "POSTGRES", "log_min_duration_statement", ["-1"], "0")
sql_flag("sql_instance_postgresql_log_min_error_statement_database_flag_configured", "POSTGRES", "log_min_error_statement", [], "", presence=True)
sql_flag("sql_instance_postgresql_log_min_messages_database_flag_error", "POSTGRES", "log_min_messages", ["error", "warning"], "debug1")
sql_flag("sql_instance_postgresql_log_temp_files_database_flag_0", "POSTGRES", "log_temp_files", ["0"], "-1")
for _flag in ("contained database authentication", "cross db ownership chaining", "external scripts enabled", "remote access"):
    sql_flag("sql_instance_sql_" + _flag.replace(" ", "_") + "_database_flag_off", "SQLSERVER", _flag, ["off"], "on")
sql_flag("sql_instance_sql_3625_trace_database_flag_on", "SQLSERVER", "3625", ["on"], "off")
# The source's 3625=off variant is rejected as anti-hardening, not registered as
# an automatic policy. Its replacement retains the reviewed ON predicate.
REFERENCE_SPECS["sql_instance_sql_3625_trace_database_flag_off"] = REFERENCE_SPECS["sql_instance_sql_3625_trace_database_flag_on"]
sql_flag("sql_instance_sql_user_connections_database_flag_configured", "SQLSERVER", "user connections", [], "", presence=True)
sql_flag("sql_instance_sql_user_options_database_flag_not_configured", "SQLSERVER", "user options", [], "1", forbidden=True)


def node_pool(query, field):
    cid = "gcp.ports." + query
    IDS.append(cid)
    @register(cid, "gcp", "hardening", "gke_cluster", "GKE node pools explicitly enable " + field, "medium", "CM-6",
        "Review node-pool operational requirements and enable the appropriate managed maintenance setting.")
    def evaluate(item, index):
        pools = list_of_objects(get(item, "nodePools", list))
        if not pools:
            return unknown("node-pool inventory absent; Autopilot configuration requires separate evidence")
        # NodeManagement.autoUpgrade/autoRepair: "A flag that specifies whether
        # node auto-upgrade/auto-repair is enabled for the node pool"; an omitted
        # flag inside a returned management message is false. A pool without a
        # management message stays UNKNOWN.
        failed = [get(pool, "name", str) for pool in pools
                  if not optional(get(pool, "management", dict), field, False, bool)]
        return result(bool(failed), node_pools_needing_review=failed)
    CASES[cid] = {"pass": {"nodePools": [{"name": "p", "management": {field: True}}]},
        "fail": {"nodePools": [{"name": "p", "management": {field: True}}, {"name": "q", "management": {}}]}, "missing": {}, "malformed": None,
        "unknown": {"nodePools": [{"name": "p", "_coverage": {"management": {"status": "denied"}}}]}}
    REFERENCE_SPECS[query] = cid


node_pool("kubernetes_cluster_auto_repair_enabled", "autoRepair")
node_pool("kubernetes_cluster_auto_upgrade_enabled", "autoUpgrade")
