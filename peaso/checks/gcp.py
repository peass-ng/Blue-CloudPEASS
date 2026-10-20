"""GCP checks consume native REST fields; inherited defaults stay unknown."""
import re

from . import alias_check, register, result, unknown, gcp_public
from .facts import Unavailable, field_check, get, guard, list_of_objects, optional
from .fixtures import CASES

for args in [
    ("gcp.compute.shielded_vtpm", "instance", "shieldedInstanceConfig.enableVtpm", True, False, "Compute instance enables Shielded VM vTPM"),
    ("gcp.compute.integrity_monitoring", "instance", "shieldedInstanceConfig.enableIntegrityMonitoring", True, False, "Compute instance enables Shielded VM integrity monitoring"),
    ("gcp.compute.secure_boot", "instance", "shieldedInstanceConfig.enableSecureBoot", True, False, "Compute instance enables Shielded VM Secure Boot"),
    ("gcp.sql.backups", "sql_instance", "settings.backupConfiguration.enabled", True, False, "Cloud SQL instance has automated backups enabled"),
    ("gcp.sql.no_public_ip", "sql_instance", "settings.ipConfiguration.ipv4Enabled", False, True, "Cloud SQL avoids a public IPv4 endpoint"),
    ("gcp.gke.secrets_encryption", "gke_cluster", "databaseEncryption.state", "ENCRYPTED", "DECRYPTED", "GKE application-layer secrets encryption is enabled"),
    ("gcp.network.custom_subnets", "network", "autoCreateSubnetworks", False, True, "VPC network uses explicit subnet management"),
]:
    cid, kind, path, good, bad, title = args
    field_check(cid, "gcp", kind, path, good, bad, title, expected=type(good))


@register("gcp.storage.no_public_iam", "gcp", "exposure", "bucket", "Bucket IAM has no unconditional public binding", "high", "AC-3", "Remove unintended allUsers/allAuthenticatedUsers grants and enforce public access prevention.")
def bucket_public(item, index):
    policy = get(item, "iamPolicy", dict)
    status, evidence = gcp_public(policy, index)
    if status == "FAIL":
        try:
            prevention = get(item, "iamConfiguration.publicAccessPrevention", str)
        except Unavailable:
            prevention = None
        if prevention == "enforced":
            return "MANUAL", {**evidence, "reason": "Public binding declared but bucket public access prevention is enforced"}
    return status, {**evidence, "semantics": "Bucket policy declaration; inherited policies, object ACLs and public prevention affect effective access"}
CASES["gcp.storage.no_public_iam"] = {"pass": {"iamPolicy": {"bindings": []}}, "fail": {"iamPolicy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}}}


@register("gcp.iam.no_user_managed_sa_keys", "gcp", "hardening", "service_account_key", "Service account avoids a user-managed persistent key", "high", "IA-5", "Replace user-managed service account keys with short-lived credentials or workload identity federation.")
def sa_keys(item, index):
    key_type = get(item, "keyType", str)
    if key_type not in ("USER_MANAGED", "SYSTEM_MANAGED"):
        return unknown("unrecognized service account key type")
    return result(key_type == "USER_MANAGED", key_type=key_type, disabled=item.get("disabled"), semantics="Persistent key existence, not proof of current usage or secret compromise")
CASES["gcp.iam.no_user_managed_sa_keys"] = {"pass": {"keyType": "SYSTEM_MANAGED"}, "fail": {"keyType": "USER_MANAGED"}}


# gcp.compute.os_login was an exact duplicate of gcp.ports.compute_oslogin_metadata_precedence (both return
# gcp_instance_oslogin(item, index)); retired as an alias of the mapped survivor.
alias_check("gcp.compute.os_login", "gcp.ports.compute_oslogin_metadata_precedence")


@register("gcp.sql.restrict_authorized_networks", "gcp", "hardening", "sql_instance", "Cloud SQL authorized networks avoid global IPv4 access", "high", "SC-7", "Remove 0.0.0.0/0 authorized networks and use narrow private connectivity.")
def sql_networks(item, index):
    config = get(item, "settings.ipConfiguration", dict)
    rows = list_of_objects(get(config, "authorizedNetworks", list))
    broad = [row for row in rows if get(row, "value", str) in ("0.0.0.0/0", "::/0")]
    return result(bool(broad), broad_authorized_networks=broad, semantics="Declared allowlist; IP assignment and TLS affect connectivity")
CASES["gcp.sql.restrict_authorized_networks"] = {"pass": {"settings": {"ipConfiguration": {"authorizedNetworks": []}}}, "fail": {"settings": {"ipConfiguration": {"authorizedNetworks": [{"value": "0.0.0.0/0"}]}}}}


# gcp.sql.require_tls was an exact duplicate of gcp.ports.sql_instance_require_ssl_enabled (same sslMode enum
# predicate; missing/unrecognized/non-string modes are UNKNOWN in both); retired as an alias of the mapped survivor.
alias_check("gcp.sql.require_tls", "gcp.ports.sql_instance_require_ssl_enabled")


@register("gcp.subnetwork.private_google_access", "gcp", "hardening", "subnetwork", "Subnetwork enables Private Google Access", "low", "CM-6",
    "Enable Private Google Access on subnets whose VMs without external IPs must reach Google APIs; review per VPC network.")
def private_google_access(item, index):
    # Defense-in-depth/reachability hygiene, not an exposure: low severity and
    # grouped by VPC network in evidence so per-subnet rows stay reviewable.
    # Compute omits purpose for a default PRIVATE subnet. An explicit or
    # unreadable purpose must still be verified before excluding the subnet.
    guard(item)
    coverage = item.get("_coverage", {})
    purpose_marker = coverage.get("purpose")
    if "purpose" not in item and ("purpose" not in coverage or
            isinstance(purpose_marker, dict) and purpose_marker.get("status") == "empty"):
        purpose = "PRIVATE"
    else:
        purpose = get(item, "purpose", str)
    enabled = get(item, "privateIpGoogleAccess", bool)
    context = {"field": "privateIpGoogleAccess", "configured": enabled, "network": item.get("network"), "region": item.get("region")}
    if purpose in ("REGIONAL_MANAGED_PROXY", "GLOBAL_MANAGED_PROXY", "INTERNAL_HTTPS_LOAD_BALANCER",
                   "PRIVATE_SERVICE_CONNECT", "PRIVATE_NAT", "PEER_MIGRATION"):
        return "NOT_APPLICABLE", {**context, "purpose": purpose, "reason": "Proxy/PSC/NAT subnets do not host VMs that use Private Google Access"}
    if purpose not in ("PRIVATE", "PRIVATE_RFC_1918"):
        return unknown("unrecognized subnetwork purpose", **context, purpose=purpose)
    return result(not enabled, **context)
CASES["gcp.subnetwork.private_google_access"] = {"pass": {"privateIpGoogleAccess": True}, "fail": {"privateIpGoogleAccess": False},
    "missing": {}, "malformed": {"privateIpGoogleAccess": {"unexpected": True}}}


DATA_LOG_TYPES = frozenset(("DATA_READ", "DATA_WRITE"))


def all_service_log_types(configs, required=DATA_LOG_TYPES):
    """allServices log types and exemptions across a list of auditConfigs."""
    types, exempted = set(), []
    for config in list_of_objects(configs):
        if get(config, "service", str) != "allServices":
            continue
        for row in list_of_objects(optional(config, "auditLogConfigs", [], list)):
            log_type = get(row, "logType", str)
            types.add(log_type)
            if log_type in required:
                exempted.extend(optional(row, "exemptedMembers", [], list))
    return types, exempted


def effective_audit(item, required=DATA_LOG_TYPES):
    """Union of the resource's and its ancestors' auditConfigs (Cloud Audit
    Logs semantics), as materialized by the collector. Returns
    (status, evidence) or raises Unavailable."""
    entries = list_of_objects(get(item, "effectiveAuditConfigs", list))
    coverage = item.get("_coverage", {}).get("effectiveAuditConfigs")
    if (not isinstance(coverage, dict) or coverage.get("status") != "collected"
            or coverage.get("missing_scopes") != [] or coverage.get("malformed_scopes", []) != []
            or coverage.get("ancestry_known", True) is not True):
        raise Unavailable("effective (inherited) audit configuration incomplete")
    root = get(item, "name", str)
    if not re.fullmatch(r"(?:projects/[A-Za-z0-9_-]+|(?:folders|organizations)/[0-9]+)", root):
        raise Unavailable("malformed effective audit hierarchy root")
    scopes = [get(entry, "scope", str) for entry in entries]
    if (not scopes or scopes[0] != root or len(scopes) != len(set(scopes))
            or any(not re.fullmatch(r"(?:folders|organizations)/[0-9]+", scope) for scope in scopes[1:])
            or any(scope.startswith("organizations/") for scope in scopes[:-1])):
        raise Unavailable("effective audit chain missing, foreign, or ambiguous")
    types, exempted, sources = set(), [], []
    for entry in entries:
        entry_types, entry_exempted = all_service_log_types(optional(entry, "auditConfigs", [], list), required)
        types |= entry_types
        exempted += entry_exempted
        if entry_types & required:
            sources.append({"scope": get(entry, "scope", str), "log_types": sorted(entry_types)})
    evidence = {"configured_types": sorted(types), "configured_at": sources,
        "evaluated_scopes": [entry.get("scope") for entry in entries], "missing_scopes": coverage.get("missing_scopes", [])}
    if required <= types:
        if exempted:
            return "MANUAL", {**evidence, "exempted_members": sorted(set(map(str, exempted)))}
        return result(False, **evidence, semantics="Effective all-service audit configuration across the resource hierarchy")
    if coverage.get("status") != "collected":
        return unknown("inherited audit configuration incomplete: an uncollected ancestor may enable it", **evidence)
    return result(True, **evidence, semantics="No collected hierarchy level (organization, folders, resource) enables these all-service log types")


@register("gcp.iam.data_access_audit", "gcp", "hardening", "iam_policy", "Project IAM configures all-service data access audit logs", "medium", "AU-2", "Enable DATA_READ and DATA_WRITE logging for all services and review exemptions and inherited configuration.")
def audit(item, index):
    name = get(item, "name", str)
    if not name.startswith(("projects/", "folders/", "organizations/")) or name.count("/") != 1:
        return "NOT_APPLICABLE", {"policy": name, "reason": "Resource-level IAM policy; audit configuration is set on the resource hierarchy"}
    return effective_audit(item)
CASES["gcp.iam.data_access_audit"] = {
    "pass": {"name": "projects/p", "effectiveAuditConfigs": [{"scope": "projects/p", "auditConfigs": []},
        {"scope": "organizations/1", "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]}],
        "_coverage": {"effectiveAuditConfigs": {"status": "collected", "missing_scopes": []}}},
    "fail": {"name": "projects/p", "effectiveAuditConfigs": [{"scope": "projects/p", "auditConfigs": []}, {"scope": "organizations/1", "auditConfigs": []}],
        "_coverage": {"effectiveAuditConfigs": {"status": "collected", "missing_scopes": []}}},
    "unknown": {"name": "projects/p", "effectiveAuditConfigs": [{"scope": "projects/p", "auditConfigs": []}],
        "_coverage": {"effectiveAuditConfigs": {"status": "partial", "missing_scopes": ["organizations/1"]}}}}


# GKE clusters.list/get return the Cluster resource in proto3 JSON, where false
# booleans and empty messages are omitted (the live read returns `legacyAbac: {}`).
# The predicates below read an absent boolean as false, like the gcp.claude.gke.*
# siblings, but only on an identified cluster object (a nameless object stays
# UNKNOWN) and never through a denied/partial `_coverage` entry.
def gke_cluster(item):
    get(item, "name", str)
    return item


def gke_flag(item, path):
    value = gke_cluster(item)
    parts = path.split(".")
    for part in parts[:-1]:
        value = optional(value, part, {}, dict)
    return optional(value, parts[-1], False, bool)


@register("gcp.gke.no_legacy_abac", "gcp", "hardening", "gke_cluster", "GKE cluster disables legacy ABAC", "medium", "CM-6",
    "Disable legacy ABAC (gcloud container clusters update --no-enable-legacy-authorization) and rely on RBAC/IAM.")
def gke_legacy_abac(item, index):
    # LegacyAbac.enabled: "Whether the ABAC authorizer is enabled for this cluster."
    enabled = gke_flag(item, "legacyAbac.enabled")
    return result(enabled, legacy_abac_enabled=enabled, semantics="Absent legacyAbac.enabled is the proto3 false default")
CASES["gcp.gke.no_legacy_abac"] = {"pass": {"name": "c", "legacyAbac": {}}, "fail": {"name": "c", "legacyAbac": {"enabled": True}},
    "unknown": {"name": "c", "_coverage": {"legacyAbac": {"status": "denied"}}}, "malformed": {"name": "c", "legacyAbac": {"enabled": "true"}}}


@register("gcp.gke.private_endpoint", "gcp", "network", "gke_cluster", "GKE cluster uses a private control-plane endpoint", "medium", "SC-7",
    "Disable the public control-plane endpoint (controlPlaneEndpointsConfig.ipEndpointsConfig.enablePublicEndpoint=false).")
def gke_private_endpoint(item, index):
    # PrivateClusterConfig.enablePrivateEndpoint (deprecated): "Whether the
    # master's internal IP address is used as the cluster endpoint ... Use
    # IPEndpointsConfig.enable_public_endpoint instead ... the value of
    # enablePublicEndpoint is reversed". IPEndpointsConfig.enablePublicEndpoint:
    # "Controls whether the control plane allows access through a public IP."
    gke_cluster(item)
    legacy = optional(optional(item, "privateClusterConfig", {}, dict), "enablePrivateEndpoint", None, bool)
    endpoints = optional(optional(item, "controlPlaneEndpointsConfig", {}, dict), "ipEndpointsConfig", None, dict)
    if endpoints is not None:
        public = optional(endpoints, "enablePublicEndpoint", False, bool)
        if legacy is not None and legacy == public:
            return unknown("conflicting legacy and current public-endpoint declarations")
        return result(public, enable_private_endpoint=bool(legacy), enable_public_endpoint=public)
    return result(not legacy, enable_private_endpoint=bool(legacy), semantics="Legacy privateClusterConfig only; omitted boolean is false")
CASES["gcp.gke.private_endpoint"] = {"pass": {"name": "c", "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enabled": True}}},
    "fail": {"name": "c", "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enablePublicEndpoint": True}}, "privateClusterConfig": {}},
    "unknown": {"name": "c", "_coverage": {"privateClusterConfig": {"status": "denied"}}},
    "malformed": {"name": "c", "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enablePublicEndpoint": "yes"}}}}


@register("gcp.gke.shielded_nodes", "gcp", "hardening", "gke_cluster", "GKE cluster enables Shielded GKE nodes", "medium", "CM-6",
    "Enable Shielded GKE nodes (gcloud container clusters update --enable-shielded-nodes).")
def gke_shielded_nodes(item, index):
    # ShieldedNodes.enabled: "Whether Shielded Nodes features are enabled on all nodes in this cluster."
    enabled = gke_flag(item, "shieldedNodes.enabled")
    return result(not enabled, shielded_nodes_enabled=enabled, semantics="Omitted shieldedNodes.enabled is the proto3 false default")
CASES["gcp.gke.shielded_nodes"] = {"pass": {"name": "c", "shieldedNodes": {"enabled": True}}, "fail": {"name": "c", "shieldedNodes": {}},
    "unknown": {"name": "c", "_coverage": {"shieldedNodes": {"status": "denied"}}}, "malformed": {"name": "c", "shieldedNodes": {"enabled": 1}}}


@register("gcp.gke.private_nodes", "gcp", "network", "gke_cluster", "GKE cluster uses private nodes", "medium", "SC-7",
    "Enable private nodes (networkConfig.defaultEnablePrivateNodes, or the deprecated privateClusterConfig.enablePrivateNodes).")
def gke_private_nodes_native(item, index):
    # privateClusterConfig.enablePrivateNodes is deprecated in favor of
    # NetworkConfig.default_enable_private_nodes; either explicit true counts.
    gke_cluster(item)
    legacy = optional(optional(item, "privateClusterConfig", {}, dict), "enablePrivateNodes", None, bool)
    default = optional(optional(item, "networkConfig", {}, dict), "defaultEnablePrivateNodes", None, bool)
    if legacy is not None and default is not None and legacy != default:
        return unknown("conflicting legacy and current private-node defaults")
    return result(not (legacy or default), private_cluster_config_private_nodes=bool(legacy), network_config_default_private_nodes=bool(default),
        semantics="Cluster default; individual node pools can override with networkConfig.enablePrivateNodes")
CASES["gcp.gke.private_nodes"] = {"pass": {"name": "c", "networkConfig": {"defaultEnablePrivateNodes": True}},
    "fail": {"name": "c", "privateClusterConfig": {"privateEndpoint": "10.0.0.2"}, "networkConfig": {}},
    "unknown": {"name": "c", "_coverage": {"privateClusterConfig": {"status": "denied"}}}, "malformed": {"name": "c", "privateClusterConfig": {"enablePrivateNodes": "yes"}}}


@register("gcp.gke.authorized_networks", "gcp", "network", "gke_cluster", "GKE cluster enables control-plane authorized networks", "medium", "SC-7",
    "Enable control-plane authorized networks (controlPlaneEndpointsConfig.ipEndpointsConfig.authorizedNetworksConfig) with narrow CIDR blocks.")
def gke_authorized_networks_native(item, index):
    # masterAuthorizedNetworksConfig is deprecated in favor of
    # ControlPlaneEndpointsConfig.IPEndpointsConfig.authorized_networks_config.
    gke_cluster(item)
    previous = optional(item, "masterAuthorizedNetworksConfig", None, dict)
    endpoints = optional(optional(item, "controlPlaneEndpointsConfig", {}, dict), "ipEndpointsConfig", {}, dict)
    modern = optional(endpoints, "authorizedNetworksConfig", None, dict)
    legacy = optional(previous, "enabled", False, bool) if previous is not None else None
    current = optional(modern, "enabled", False, bool) if modern is not None else None
    if legacy is not None and current is not None and legacy != current:
        return unknown("conflicting legacy and current authorized-network declarations")
    return result(not (legacy or current), master_authorized_networks_enabled=bool(legacy), ip_endpoints_authorized_networks_enabled=bool(current),
        semantics="Feature enablement only; CIDR breadth is evaluated by gcp.claude.gke.master_authorized_networks_restricted")
CASES["gcp.gke.authorized_networks"] = {"pass": {"name": "c", "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"authorizedNetworksConfig": {"enabled": True}}}},
    "fail": {"name": "c", "masterAuthorizedNetworksConfig": {}, "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"authorizedNetworksConfig": {}}}},
    "unknown": {"name": "c", "_coverage": {"masterAuthorizedNetworksConfig": {"status": "denied"}}},
    "malformed": {"name": "c", "masterAuthorizedNetworksConfig": {"enabled": 1}}}


@register("gcp.gke.network_policy", "gcp", "hardening", "gke_cluster", "GKE configures a NetworkPolicy enforcement engine", "medium", "SC-7", "Use GKE Dataplane V2, Autopilot or supported Calico network policy enforcement and review workload policies.")
def network_policy(item, index):
    network = optional(item, "networkConfig", {}, dict)
    autopilot = optional(item, "autopilot", {}, dict)
    provider = optional(network, "datapathProvider", "DATAPATH_PROVIDER_UNSPECIFIED", str)
    if provider not in ("DATAPATH_PROVIDER_UNSPECIFIED", "LEGACY_DATAPATH", "ADVANCED_DATAPATH"):
        raise Unavailable("unrecognized GKE datapath provider")
    if provider == "ADVANCED_DATAPATH" or optional(autopilot, "enabled", False, bool):
        return result(False, semantics="Dataplane V2/Autopilot includes network policy enforcement; policy coverage is separate")
    policy = optional(item, "networkPolicy", None, dict)
    if policy is None or "enabled" not in policy:
        # NetworkPolicyConfig.disabled tracks the master add-on. An omitted
        # networkPolicy.enabled is decided only when the add-on is explicitly off.
        addon = optional(optional(item, "addonsConfig", {}, dict), "networkPolicyConfig", {}, dict)
        if optional(addon, "disabled", False, bool):
            return result(True, network_policy_enabled=False, network_policy_addon_disabled=True,
                semantics="networkPolicy.enabled omitted (proto3 false) and the NetworkPolicy add-on is disabled")
        raise Unavailable("missing fact: networkPolicy.enabled")
    enabled = get(policy, "enabled", bool)
    return result(not enabled, network_policy_enabled=enabled, semantics="Configured policy engine only, not workload policy coverage")
CASES["gcp.gke.network_policy"] = {"pass": {"networkPolicy": {"enabled": True}}, "fail": {"networkPolicy": {"enabled": False}},
    "unknown": {"name": "c", "addonsConfig": {"networkPolicyConfig": {}}}}


def gke_autopilot(item):
    return optional(optional(item, "autopilot", {}, dict), "enabled", False, bool)


@register("gcp.gke.workload_identity", "gcp", "least_privilege", "gke_cluster", "GKE cluster enables Workload Identity Federation for GKE", "high", "IA-2",
    "Enable Workload Identity Federation for GKE (--workload-pool=PROJECT_ID.svc.id.goog) and migrate node pools to the GKE metadata server.")
def gke_workload_identity(item, index):
    gke_cluster(item)
    # "In Autopilot, Workload Identity Federation for GKE is always enabled."
    if gke_autopilot(item):
        return result(False, autopilot=True, semantics="Autopilot always enables Workload Identity Federation for GKE")
    pool = optional(optional(item, "workloadIdentityConfig", {}, dict), "workloadPool", "", str)
    return result(not pool, workload_pool=pool or None,
        semantics="Cluster workloadIdentityConfig.workloadPool declaration; per-pool metadata mode is gcp.gke.node_pools_gke_metadata")
CASES["gcp.gke.workload_identity"] = {"pass": {"name": "c", "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"}},
    "fail": {"name": "c", "workloadIdentityConfig": {}}, "unknown": {"name": "c", "_coverage": {"workloadIdentityConfig": {"status": "denied"}}},
    "malformed": {"name": "c", "workloadIdentityConfig": {"workloadPool": 7}}}


@register("gcp.gke.node_pools_gke_metadata", "gcp", "least_privilege", "gke_cluster", "Every GKE node pool runs the GKE metadata server (GKE_METADATA)", "high", "AC-6",
    "Set --workload-metadata=GKE_METADATA on every node pool so pods cannot read the node's Compute Engine metadata and credentials.")
def gke_pools_metadata(item, index):
    gke_cluster(item)
    if gke_autopilot(item):
        return result(False, autopilot=True, semantics="Autopilot always runs the GKE metadata server")
    pools = list_of_objects(get(item, "nodePools", list))
    if not pools:
        return unknown("node-pool inventory absent")
    workload_pool = optional(optional(item, "workloadIdentityConfig", {}, dict), "workloadPool", "", str)
    failing, unresolved = [], []
    for pool in pools:
        name = get(pool, "name", str)
        mode = optional(optional(optional(pool, "config", {}, dict), "workloadMetadataConfig", {}, dict), "mode", "MODE_UNSPECIFIED", str)
        if mode == "GKE_METADATA":
            continue
        if mode == "GCE_METADATA":
            failing.append({"node_pool": name, "mode": mode})
        elif mode == "MODE_UNSPECIFIED" and not workload_pool:
            # GKE_METADATA "can only be enabled if Workload Identity is enabled at
            # the cluster level", so without a workload pool no pool can use it.
            failing.append({"node_pool": name, "mode": mode, "cluster_workload_identity": False})
        else:
            unresolved.append({"node_pool": name, "mode": mode})
    if failing:
        return result(True, node_pools_exposing_compute_metadata=failing, unresolved_node_pools=unresolved)
    if unresolved:
        return unknown("node-pool workload metadata mode unset or unrecognized", node_pools=unresolved)
    return result(False, node_pools=[get(pool, "name", str) for pool in pools])
_pool = lambda name, mode: {"name": name, "config": {"workloadMetadataConfig": {"mode": mode}}}
CASES["gcp.gke.node_pools_gke_metadata"] = {"pass": {"name": "c", "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"},
        "nodePools": [_pool("a", "GKE_METADATA"), _pool("b", "GKE_METADATA")]},
    "fail": {"name": "c", "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"}, "nodePools": [_pool("a", "GKE_METADATA"), _pool("b", "GCE_METADATA")]},
    "unknown": {"name": "c", "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"}, "nodePools": [{"name": "a", "config": {}}]},
    "malformed": {"name": "c", "nodePools": [{"name": "a", "config": {"workloadMetadataConfig": {"mode": 1}}}]}}
