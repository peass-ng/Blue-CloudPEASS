"""GCP checks consume native REST fields; inherited defaults stay unknown."""
from . import register, result, unknown, gcp_public
from .facts import field_check, get, list_of_objects
from .fixtures import CASES

for args in [
    ("gcp.compute.shielded_vtpm", "instance", "shieldedInstanceConfig.enableVtpm", True, False, "Compute instance enables Shielded VM vTPM"),
    ("gcp.compute.integrity_monitoring", "instance", "shieldedInstanceConfig.enableIntegrityMonitoring", True, False, "Compute instance enables Shielded VM integrity monitoring"),
    ("gcp.compute.secure_boot", "instance", "shieldedInstanceConfig.enableSecureBoot", True, False, "Compute instance enables Shielded VM Secure Boot"),
    ("gcp.sql.backups", "sql_instance", "settings.backupConfiguration.enabled", True, False, "Cloud SQL instance has automated backups enabled"),
    ("gcp.sql.no_public_ip", "sql_instance", "settings.ipConfiguration.ipv4Enabled", False, True, "Cloud SQL avoids a public IPv4 endpoint"),
    ("gcp.gke.private_nodes", "gke_cluster", "privateClusterConfig.enablePrivateNodes", True, False, "GKE cluster uses private nodes"),
    ("gcp.gke.private_endpoint", "gke_cluster", "privateClusterConfig.enablePrivateEndpoint", True, False, "GKE cluster uses a private control-plane endpoint"),
    ("gcp.gke.shielded_nodes", "gke_cluster", "shieldedNodes.enabled", True, False, "GKE cluster enables Shielded GKE nodes"),
    ("gcp.gke.no_legacy_abac", "gke_cluster", "legacyAbac.enabled", False, True, "GKE cluster disables legacy ABAC"),
    ("gcp.gke.authorized_networks", "gke_cluster", "masterAuthorizedNetworksConfig.enabled", True, False, "GKE cluster enables control-plane authorized networks"),
    ("gcp.gke.secrets_encryption", "gke_cluster", "databaseEncryption.state", "ENCRYPTED", "DECRYPTED", "GKE application-layer secrets encryption is enabled"),
    ("gcp.network.custom_subnets", "network", "autoCreateSubnetworks", False, True, "VPC network uses explicit subnet management"),
    ("gcp.subnetwork.private_google_access", "subnetwork", "privateIpGoogleAccess", True, False, "Subnetwork enables Private Google Access"),
]:
    cid, kind, path, good, bad, title = args
    field_check(cid, "gcp", kind, path, good, bad, title, expected=type(good))


@register("gcp.storage.no_public_iam", "gcp", "exposure", "bucket", "Bucket IAM has no unconditional public binding", "high", "AC-3", "Remove unintended allUsers/allAuthenticatedUsers grants and enforce public access prevention.")
def bucket_public(item, index):
    policy = get(item, "iamPolicy", dict)
    status, evidence = gcp_public(policy, index)
    if status == "FAIL":
        prevention = item.get("iamConfiguration", {}).get("publicAccessPrevention")
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


@register("gcp.compute.os_login", "gcp", "hardening", "instance", "Compute instance explicitly enables OS Login", "medium", "AC-2", "Enable OS Login through reviewed instance or project metadata and IAM controls.")
def oslogin(item, index):
    rows = list_of_objects(get(item, "metadata.items", list))
    settings = {get(row, "key", str): row.get("value") for row in rows}
    if "enable-oslogin" not in settings:
        return unknown("OS Login not set on instance; project and organization inheritance unavailable")
    flag = settings["enable-oslogin"]
    if not isinstance(flag, str) or flag.upper() not in ("TRUE", "FALSE"):
        return unknown("malformed OS Login metadata")
    return result(flag.upper() != "TRUE", instance_enable_oslogin=flag)
CASES["gcp.compute.os_login"] = {"pass": {"metadata": {"items": [{"key": "enable-oslogin", "value": "TRUE"}]}}, "fail": {"metadata": {"items": [{"key": "enable-oslogin", "value": "FALSE"}]}}}


@register("gcp.sql.restrict_authorized_networks", "gcp", "hardening", "sql_instance", "Cloud SQL authorized networks avoid global IPv4 access", "high", "SC-7", "Remove 0.0.0.0/0 authorized networks and use narrow private connectivity.")
def sql_networks(item, index):
    config = get(item, "settings.ipConfiguration", dict)
    rows = list_of_objects(get(config, "authorizedNetworks", list))
    broad = [row for row in rows if get(row, "value", str) in ("0.0.0.0/0", "::/0")]
    return result(bool(broad), broad_authorized_networks=broad, semantics="Declared allowlist; IP assignment and TLS affect connectivity")
CASES["gcp.sql.restrict_authorized_networks"] = {"pass": {"settings": {"ipConfiguration": {"authorizedNetworks": []}}}, "fail": {"settings": {"ipConfiguration": {"authorizedNetworks": [{"value": "0.0.0.0/0"}]}}}}


@register("gcp.sql.require_tls", "gcp", "hardening", "sql_instance", "Cloud SQL requires encrypted client connections", "high", "SC-8", "Set sslMode to ENCRYPTED_ONLY or TRUSTED_CLIENT_CERTIFICATE_REQUIRED for supported engines.")
def sql_tls(item, index):
    config = get(item, "settings.ipConfiguration", dict)
    mode = config.get("sslMode")
    if mode in ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"):
        return result(False, ssl_mode=mode)
    if mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED":
        return result(True, ssl_mode=mode)
    if mode is not None:
        return unknown("unrecognized Cloud SQL sslMode")
    # Legacy requireSsl does not capture all engine-specific SSL modes.
    return unknown("Cloud SQL sslMode unavailable; legacy requireSsl alone is insufficient")
CASES["gcp.sql.require_tls"] = {"pass": {"settings": {"ipConfiguration": {"sslMode": "ENCRYPTED_ONLY"}}}, "fail": {"settings": {"ipConfiguration": {"sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}}}}


@register("gcp.iam.data_access_audit", "gcp", "hardening", "iam_policy", "Project IAM configures all-service data access audit logs", "medium", "AU-2", "Enable DATA_READ and DATA_WRITE logging for all services and review exemptions and inherited configuration.")
def audit(item, index):
    configs = list_of_objects(get(item, "auditConfigs", list))
    types = set()
    exempted = []
    for config in configs:
        if get(config, "service", str) != "allServices":
            continue
        for row in list_of_objects(get(config, "auditLogConfigs", list)):
            types.add(get(row, "logType", str))
            exempted.extend(row.get("exemptedMembers", []))
    if not {"DATA_READ", "DATA_WRITE"}.issubset(types):
        return unknown("project all-service data audit logging is not complete; inherited audit configuration unavailable", configured_types=sorted(types))
    if exempted:
        return "MANUAL", {"exempted_members": exempted, "configured_types": sorted(types)}
    return result(False, configured_types=sorted(types), semantics="Project all-service configuration; inherited grants may add audit logging")
CASES["gcp.iam.data_access_audit"] = {"pass": {"auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]}, "unknown": {"auditConfigs": []}}


@register("gcp.gke.network_policy", "gcp", "hardening", "gke_cluster", "GKE configures a NetworkPolicy enforcement engine", "medium", "SC-7", "Use GKE Dataplane V2, Autopilot or supported Calico network policy enforcement and review workload policies.")
def network_policy(item, index):
    network = get(item, "networkConfig", dict) if "networkConfig" in item else {}
    autopilot = get(item, "autopilot", dict) if "autopilot" in item else {}
    if network.get("datapathProvider") == "ADVANCED_DATAPATH" or autopilot.get("enabled") is True:
        return result(False, semantics="Dataplane V2/Autopilot includes network policy enforcement; policy coverage is separate")
    enabled = get(item, "networkPolicy.enabled", bool)
    return result(not enabled, network_policy_enabled=enabled, semantics="Configured policy engine only, not workload policy coverage")
CASES["gcp.gke.network_policy"] = {"pass": {"networkPolicy": {"enabled": True}}, "fail": {"networkPolicy": {"enabled": False}}}
