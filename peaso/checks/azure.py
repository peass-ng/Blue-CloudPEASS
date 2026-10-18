"""Azure ARM checks retain property casing and make configuration claims only."""
from . import register, result, unknown
from .facts import field_check, get
from .fixtures import CASES

for args in [
    ("azure.storage.no_shared_key", "storage_account", "properties.allowSharedKeyAccess", False, True, "Storage account disables Shared Key authorization"),
    ("azure.storage.default_oauth", "storage_account", "properties.defaultToOAuthAuthentication", True, False, "Storage account defaults to Microsoft Entra authorization"),
    ("azure.storage.no_public_network", "storage_account", "properties.publicNetworkAccess", "Disabled", "Enabled", "Storage account disables public network access"),
    ("azure.vault.soft_delete", "vault", "properties.enableSoftDelete", True, False, "Key Vault enables soft delete"),
    ("azure.vault.purge_protection", "vault", "properties.enablePurgeProtection", True, False, "Key Vault enables purge protection"),
    ("azure.vault.rbac", "vault", "properties.enableRbacAuthorization", True, False, "Key Vault uses Azure RBAC authorization"),
    ("azure.vault.no_public_network", "vault", "properties.publicNetworkAccess", "Disabled", "Enabled", "Key Vault disables public network access"),
    ("azure.vault.default_deny", "vault", "properties.networkAcls.defaultAction", "Deny", "Allow", "Key Vault network ACL default is deny"),
    ("azure.aks.rbac", "aks_cluster", "properties.enableRBAC", True, False, "AKS enables Kubernetes RBAC"),
    ("azure.aks.no_local_accounts", "aks_cluster", "properties.disableLocalAccounts", True, False, "AKS disables local cluster accounts"),
    ("azure.aks.private_cluster", "aks_cluster", "properties.apiServerAccessProfile.enablePrivateCluster", True, False, "AKS uses a private API endpoint"),
    ("azure.aks.azure_rbac", "aks_cluster", "properties.aadProfile.enableAzureRBAC", True, False, "AKS enables Azure RBAC for Kubernetes authorization"),
    ("azure.sql.minimum_tls", "sql_server", "properties.minimalTlsVersion", "1.2", "1.0", "Azure SQL server requires TLS 1.2"),
    ("azure.sql.no_public_network", "sql_server", "properties.publicNetworkAccess", "Disabled", "Enabled", "Azure SQL server disables public network access"),
    ("azure.sql.auditing", "sql_audit", "properties.state", "Enabled", "Disabled", "Azure SQL auditing is enabled"),
    ("azure.sql.threat_detection", "sql_security", "properties.state", "Enabled", "Disabled", "Azure SQL threat detection is enabled"),
    ("azure.storage.default_deny", "storage_account", "properties.networkAcls.defaultAction", "Deny", "Allow", "Storage network ACL default action is deny"),
]:
    cid, kind, path, good, bad, title = args
    # TLS 1.1 is a recognized insecure variant too.
    field_check(cid, "azure", kind, path, good, bad, title, expected=type(good))


@register("azure.sql.restrict_firewall", "azure", "hardening", "sql_firewall_rule", "Azure SQL firewall avoids a global address range", "high", "SC-7", "Replace broad firewall ranges and review the separate Allow Azure services setting.")
def sql_firewall(item, index):
    import ipaddress
    start = ipaddress.ip_address(get(item, "properties.startIpAddress", str))
    end = ipaddress.ip_address(get(item, "properties.endIpAddress", str))
    if start.version != 4 or end.version != 4 or int(start) > int(end):
        return unknown("malformed Azure SQL firewall range")
    if str(start) == str(end) == "0.0.0.0":
        return "MANUAL", {"reason": "Allow Azure services is broad Azure tenant access, not all internet addresses"}
    return result(str(start) == "0.0.0.0" and str(end) == "255.255.255.255", start_ip=str(start), end_ip=str(end))
CASES["azure.sql.restrict_firewall"] = {"pass": {"properties": {"startIpAddress": "10.0.0.1", "endIpAddress": "10.0.0.1"}}, "fail": {"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}}}


@register("azure.aks.network_policy", "azure", "hardening", "aks_cluster", "AKS specifies a network policy implementation", "medium", "SC-7", "Configure a supported network policy engine and policies appropriate for the cluster network plugin.")
def aks_policy(item, index):
    profile = get(item, "properties.networkProfile", dict)
    if profile.get("networkDataplane") == "cilium":
        return result(False, network_dataplane="cilium", semantics="Cilium policy engine configured; workload coverage requires separate review")
    policy = get(item, "properties.networkProfile.networkPolicy", str)
    if policy not in ("azure", "calico", "cilium", "none", ""):
        return unknown("unrecognized AKS network policy engine")
    return result(policy in ("none", ""), network_policy=policy, semantics="Configured engine only; workload policy coverage is separate")
CASES["azure.aks.network_policy"] = {"pass": {"properties": {"networkProfile": {"networkPolicy": "calico"}}}, "fail": {"properties": {"networkProfile": {"networkPolicy": "none"}}}}
