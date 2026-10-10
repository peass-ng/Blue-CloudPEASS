"""Strict offline Azure configuration checks; runtime/effective access stays unknown."""
from . import register as _register, result, unknown
from .facts import field_check, get, list_of_objects
from .fixtures import CASES, nest

CHECK_IDS = []


def register(*args):
    CHECK_IDS.append(args[0])
    return _register(*args)


for cid, kind, path, good, bad, title, control in [
    ("azure.storage.cross_tenant_replication", "storage_account", "properties.allowCrossTenantReplication", False, True, "Storage disables cross-tenant object replication", "AC-4"),
    ("azure.storage.infrastructure_encryption", "storage_account", "properties.encryption.requireInfrastructureEncryption", True, False, "Storage enables infrastructure encryption", "SC-28"),
    ("azure.vm.encryption_at_host", "vm", "properties.securityProfile.encryptionAtHost", True, False, "VM enables encryption at host", "SC-28"),
    ("azure.disk.entra_export_auth", "disk", "properties.dataAccessAuthMode", "AzureActiveDirectory", "None", "Disk export requires Microsoft Entra authentication", "AC-3"),
    ("azure.network.load_balancer_standard", "load_balancer", "sku.name", "Standard", "Basic", "Load balancer uses Standard SKU", "SC-7"),
    ("azure.network.public_ip_standard", "public_ip", "sku.name", "Standard", "Basic", "Public IP uses Standard SKU", "SC-7"),
    ("azure.network.nic_no_ip_forwarding", "nic", "properties.enableIPForwarding", False, True, "Network interface disables IP forwarding", "SC-7"),
    ("azure.network.ddos_configured", "vnet", "properties.enableDdosProtection", True, False, "Virtual network configures DDoS protection", "SC-5"),
    ("azure.aks.defender_monitoring", "aks_cluster", "properties.securityProfile.defender.securityMonitoring.enabled", True, False, "AKS configures Defender security monitoring", "SI-4"),
    ("azure.app.https_only", "app_service", "properties.httpsOnly", True, False, "App Service requires HTTPS", "SC-8"),
    ("azure.app.http2", "app_service_config", "properties.http20Enabled", True, False, "App Service enables HTTP/2", "SC-8"),
    ("azure.app.request_logging", "app_service_config", "properties.httpLoggingEnabled", True, False, "App Service configures HTTP request logging", "AU-12"),
    ("azure.app.remote_debugging_off", "app_service_config", "properties.remoteDebuggingEnabled", False, True, "App Service disables remote debugging", "CM-7"),
]:
    CHECK_IDS.append(cid)
    field_check(cid, "azure", kind, path, good, bad, title, control=control, expected=type(good))


@register("azure.disk.private_export", "azure", "hardening", "disk", "Disk export disables public networking and restricts network access", "medium", "SC-7", "Disable public network access and use AllowPrivate or DenyAll for disk export networking.")
def disk_private_export(item, index):
    public = get(item, "properties.publicNetworkAccess", str)
    policy = get(item, "properties.networkAccessPolicy", str)
    if public not in ("Enabled", "Disabled") or policy not in ("AllowAll", "AllowPrivate", "DenyAll"):
        return unknown("unrecognized disk network setting")
    return result(public != "Disabled" or policy == "AllowAll", public_network_access=public, network_access_policy=policy, semantics="Export configuration; no SAS or disk content was read")
CASES["azure.disk.private_export"] = {"pass": {"properties": {"publicNetworkAccess": "Disabled", "networkAccessPolicy": "AllowPrivate"}}, "fail": {"properties": {"publicNetworkAccess": "Enabled", "networkAccessPolicy": "AllowAll"}}}


def _blob(item):
    resource_type = get(item, "type", str).lower()
    if resource_type not in ("microsoft.storage/storageaccounts/blobservices", "microsoft.storage/storageaccounts/fileservices", "microsoft.storage/storageaccounts/queueservices", "microsoft.storage/storageaccounts/tableservices"):
        raise ValueError("unrecognized storage service type")
    return resource_type.endswith("/blobservices")


@register("azure.storage.blob_versioning", "azure", "hardening", "storage_service", "Blob service enables object versioning", "medium", "CP-9", "Enable blob versioning where supported and define lifecycle retention separately.")
def blob_versioning(item, index):
    if not _blob(item):
        return "NOT_APPLICABLE", {"reason": "This is not a blob service"}
    return result(not get(item, "properties.isVersioningEnabled", bool), semantics="Versioning configuration; retained backup quality is not verified")
CASES["azure.storage.blob_versioning"] = {"pass": {"type": "Microsoft.Storage/storageAccounts/blobServices", "properties": {"isVersioningEnabled": True}}, "fail": {"type": "Microsoft.Storage/storageAccounts/blobServices", "properties": {"isVersioningEnabled": False}}}


@register("azure.storage.blob_soft_delete_retention", "azure", "hardening", "storage_service", "Blob soft delete is enabled with 7–365 day retention", "medium", "CP-9", "Enable blob soft delete and select a retention period between 7 and 365 days.")
def blob_retention(item, index):
    if not _blob(item):
        return "NOT_APPLICABLE", {"reason": "This is not a blob service"}
    enabled = get(item, "properties.deleteRetentionPolicy.enabled", bool)
    if not enabled:
        return result(True, enabled=False)
    days = get(item, "properties.deleteRetentionPolicy.days", int)
    return result(not 7 <= days <= 365, enabled=enabled, retention_days=days)
CASES["azure.storage.blob_soft_delete_retention"] = {"pass": {"type": "Microsoft.Storage/storageAccounts/blobServices", "properties": {"deleteRetentionPolicy": {"enabled": True, "days": 7}}}, "fail": {"type": "Microsoft.Storage/storageAccounts/blobServices", "properties": {"deleteRetentionPolicy": {"enabled": True, "days": 1}}}}


@register("azure.storage.container_soft_delete", "azure", "hardening", "storage_service", "Blob container soft delete is enabled", "medium", "CP-9", "Enable container soft delete and review its retention period for recovery requirements.")
def container_soft_delete(item, index):
    if not _blob(item):
        return "NOT_APPLICABLE", {"reason": "This is not a blob service"}
    return result(not get(item, "properties.containerDeleteRetentionPolicy.enabled", bool), semantics="Container soft delete configured; retention adequacy is separate")
CASES["azure.storage.container_soft_delete"] = {"pass": {"type": "Microsoft.Storage/storageAccounts/blobServices", "properties": {"containerDeleteRetentionPolicy": {"enabled": True}}}, "fail": {"type": "Microsoft.Storage/storageAccounts/blobServices", "properties": {"containerDeleteRetentionPolicy": {"enabled": False}}}}


@register("azure.vm.linux_ssh_keys", "azure", "hardening", "vm", "Linux VM disables password authentication for SSH", "high", "IA-5", "Disable password authentication for Linux SSH and use approved key or Entra authentication.")
def linux_ssh(item, index):
    os_type = get(item, "properties.storageProfile.osDisk.osType", str)
    if os_type == "Windows":
        return "NOT_APPLICABLE", {"os_type": os_type}
    if os_type != "Linux":
        return unknown("unrecognized VM operating system")
    disabled = get(item, "properties.osProfile.linuxConfiguration.disablePasswordAuthentication", bool)
    return result(not disabled, password_authentication_disabled=disabled, semantics="ARM configuration; guest sshd runtime is not verified")
CASES["azure.vm.linux_ssh_keys"] = {"pass": {"properties": {"storageProfile": {"osDisk": {"osType": "Linux"}}, "osProfile": {"linuxConfiguration": {"disablePasswordAuthentication": True}}}}, "fail": {"properties": {"storageProfile": {"osDisk": {"osType": "Linux"}}, "osProfile": {"linuxConfiguration": {"disablePasswordAuthentication": False}}}}}


@register("azure.vm.trusted_launch", "azure", "hardening", "vm", "VM configures Trusted Launch with Secure Boot and vTPM", "medium", "SI-7", "For supported VM images and sizes, configure Trusted Launch, Secure Boot and vTPM; review alternative confidential-computing protections separately.")
def trusted_launch(item, index):
    security_type = get(item, "properties.securityProfile.securityType", str)
    if security_type not in ("TrustedLaunch", "ConfidentialVM", "Standard"):
        return unknown("unrecognized VM security type")
    if security_type != "TrustedLaunch":
        return result(True, security_type=security_type, semantics="Trusted Launch baseline specifically; other protections are separate")
    boot = get(item, "properties.securityProfile.uefiSettings.secureBootEnabled", bool)
    tpm = get(item, "properties.securityProfile.uefiSettings.vTpmEnabled", bool)
    return result(not (boot and tpm), security_type=security_type, secure_boot=boot, virtual_tpm=tpm)
CASES["azure.vm.trusted_launch"] = {"pass": {"properties": {"securityProfile": {"securityType": "TrustedLaunch", "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True}}}}, "fail": {"properties": {"securityProfile": {"securityType": "TrustedLaunch", "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": False}}}}}


@register("azure.vm.managed_disks", "azure", "hardening", "vm", "VM OS and data disks use managed disks", "medium", "CM-6", "Use managed disks for the OS and persistent data disks; ephemeral OS disk applicability requires separate review.")
def managed_disks(item, index):
    os_disk = get(item, "properties.storageProfile.osDisk", dict)
    if "diffDiskSettings" in os_disk:
        diff = get(item, "properties.storageProfile.osDisk.diffDiskSettings", dict)
        if diff.get("option") == "Local":
            return "NOT_APPLICABLE", {"reason": "Ephemeral OS disk; managed persistent OS disk baseline does not apply"}
    disks = [os_disk] + list_of_objects(get(item, "properties.storageProfile.dataDisks", list))
    for disk in disks:
        if "managedDisk" not in disk:
            if "vhd" in disk and isinstance(disk["vhd"], dict):
                return result(True, unmanaged_disk_observed=True)
            return unknown("disk storage type was not collected")
        managed = get(disk, "managedDisk")
        if managed is None:
            return result(True, unmanaged_disk_observed=True)
        if not isinstance(managed, dict) or not managed:
            return unknown("malformed managed disk metadata")
    return result(False, disk_count=len(disks), semantics="Managed disk declarations; encryption and backup are separate")
CASES["azure.vm.managed_disks"] = {"pass": {"properties": {"storageProfile": {"osDisk": {"managedDisk": {"id": "/disk/os"}}, "dataDisks": []}}}, "fail": {"properties": {"storageProfile": {"osDisk": {"managedDisk": None}, "dataDisks": []}}}}


@register("azure.app.client_certificates", "azure", "hardening", "app_service", "App Service enables and requires client certificates", "medium", "IA-2", "Enable client certificates with Required mode where client certificate authentication is intended; optional mode does not require certificates.")
def app_client_certificates(item, index):
    enabled = get(item, "properties.clientCertEnabled", bool)
    if not enabled:
        return result(True, client_certificates_enabled=False)
    mode = get(item, "properties.clientCertMode", str)
    if mode not in ("Required", "Optional", "OptionalInteractiveUser"):
        return unknown("unrecognized client certificate mode")
    return result(mode != "Required", client_certificates_enabled=enabled, client_certificate_mode=mode, semantics="Endpoint configuration; application authorization and exclusion paths require separate review")
CASES["azure.app.client_certificates"] = {"pass": {"properties": {"clientCertEnabled": True, "clientCertMode": "Required"}}, "fail": {"properties": {"clientCertEnabled": True, "clientCertMode": "Optional"}}}


@register("azure.aks.auto_upgrade", "azure", "hardening", "aks_cluster", "AKS configures a cluster auto-upgrade channel", "medium", "SI-2", "Configure an appropriate cluster auto-upgrade channel and maintenance window.")
def aks_upgrade(item, index):
    channel = get(item, "properties.autoUpgradeProfile.upgradeChannel", str)
    if channel not in ("none", "", "rapid", "stable", "patch", "node-image"):
        return unknown("unrecognized AKS upgrade channel")
    return result(channel in ("none", ""), upgrade_channel=channel, semantics="Configured channel; patch deployment completion is not verified")
CASES["azure.aks.auto_upgrade"] = {"pass": nest("properties.autoUpgradeProfile.upgradeChannel", "stable"), "fail": nest("properties.autoUpgradeProfile.upgradeChannel", "none")}


@register("azure.sql.audit_retention", "azure", "hardening", "sql_audit", "SQL audit retention is unlimited or at least 90 days", "medium", "AU-11", "Configure SQL auditing retention of at least 90 days or unlimited; verify the destination's independent retention settings.")
def sql_retention(item, index):
    days = get(item, "properties.retentionDays", int)
    if days < 0:
        return unknown("negative SQL audit retention")
    return result(days != 0 and days < 90, retention_days=days, unlimited=days == 0, semantics="Configured auditing retention; destination lifecycle and auditing enablement are separate")
CASES["azure.sql.audit_retention"] = {"pass": nest("properties.retentionDays", 0), "fail": nest("properties.retentionDays", 30)}


@register("azure.sql.threat_alerts_all", "azure", "hardening", "sql_security", "SQL security policy disables no threat-alert categories", "medium", "SI-4", "Enable the security alert policy and retain all appropriate threat-detection categories.")
def sql_alerts(item, index):
    values = get(item, "properties.disabledAlerts", list)
    if any(not isinstance(value, str) for value in values):
        return unknown("malformed disabled-alert categories")
    return result(any(value for value in values), disabled_alerts=values, semantics="Category exclusions only; policy state and monitoring response are separate")
CASES["azure.sql.threat_alerts_all"] = {"pass": nest("properties.disabledAlerts", [""]), "fail": nest("properties.disabledAlerts", ["Sql_Injection"])}


@register("azure.sql.tde_enabled", "azure", "hardening", "sql_tde", "User SQL database enables transparent data encryption", "high", "SC-28", "Enable transparent data encryption on user databases and review key management separately.")
def sql_tde(item, index):
    parent = get(item, "parent_id", str)
    if parent.rsplit("/", 1)[-1].lower() == "master":
        return "NOT_APPLICABLE", {"reason": "System master database is outside this check"}
    state = get(item, "properties.state", str)
    if state not in ("Enabled", "Disabled"):
        return unknown("unrecognized SQL TDE state")
    return result(state != "Enabled", state=state, semantics="ARM encryption configuration; no database content was read")
CASES["azure.sql.tde_enabled"] = {"pass": {"parent_id": "/sql/databases/app", "properties": {"state": "Enabled"}}, "fail": {"parent_id": "/sql/databases/app", "properties": {"state": "Disabled"}}}


@register("azure.app.minimum_tls", "azure", "hardening", "app_service_config", "App Service minimum TLS is 1.2 or later", "high", "SC-8", "Require TLS 1.2 or TLS 1.3 for the application endpoint.")
def app_tls(item, index):
    value = get(item, "properties.minTlsVersion", str)
    if value not in ("1.0", "1.1", "1.2", "1.3"):
        return unknown("unrecognized App Service TLS version")
    return result(value in ("1.0", "1.1"), minimum_tls=value)
CASES["azure.app.minimum_tls"] = {"pass": nest("properties.minTlsVersion", "1.3"), "fail": nest("properties.minTlsVersion", "1.1")}


@register("azure.app.scm_minimum_tls", "azure", "hardening", "app_service_config", "App Service deployment endpoint minimum TLS is 1.2 or later", "high", "SC-8", "Require TLS 1.2 or TLS 1.3 for the SCM deployment endpoint.")
def scm_tls(item, index):
    value = get(item, "properties.scmMinTlsVersion", str)
    if value not in ("1.0", "1.1", "1.2", "1.3"):
        return unknown("unrecognized SCM TLS version")
    return result(value in ("1.0", "1.1"), scm_minimum_tls=value)
CASES["azure.app.scm_minimum_tls"] = {"pass": nest("properties.scmMinTlsVersion", "1.2"), "fail": nest("properties.scmMinTlsVersion", "1.0")}


@register("azure.app.ftps_only", "azure", "hardening", "app_service_config", "App Service forbids plain FTP", "high", "SC-8", "Set FTP state to FtpsOnly or Disabled; FTPS can remain enabled under this baseline.")
def app_ftps(item, index):
    value = get(item, "properties.ftpsState", str)
    if value not in ("AllAllowed", "FtpsOnly", "Disabled"):
        return unknown("unrecognized FTP state")
    return result(value == "AllAllowed", ftp_state=value, semantics="Plain FTP disallowed; this does not require all deployment methods to be disabled")
CASES["azure.app.ftps_only"] = {"pass": nest("properties.ftpsState", "FtpsOnly"), "fail": nest("properties.ftpsState", "AllAllowed")}


@register("azure.app.cors_no_wildcards", "azure", "hardening", "app_service_config", "App Service CORS omits the wildcard origin", "medium", "AC-4", "Restrict CORS origins to the web clients intended to call the application.")
def app_cors(item, index):
    origins = get(item, "properties.cors.allowedOrigins", list)
    if any(not isinstance(origin, str) for origin in origins):
        return unknown("malformed CORS origins")
    return result("*" in origins, allowed_origins=origins, semantics="Browser-origin policy configuration; not server authorization or network reachability")
CASES["azure.app.cors_no_wildcards"] = {"pass": nest("properties.cors.allowedOrigins", []), "fail": nest("properties.cors.allowedOrigins", ["*"])}


@register("azure.vault.secret_expiration", "azure", "hardening", "secret_metadata", "Enabled Key Vault secret metadata declares an expiration", "medium", "IA-5", "Set a rotation-appropriate secret expiration; review rotation separately without reading values.")
def secret_expiration(item, index):
    enabled = get(item, "properties.attributes.enabled", bool)
    if not enabled:
        return "NOT_APPLICABLE", {"reason": "Secret metadata is explicitly disabled"}
    expiry = get(item, "properties.attributes.exp")
    if expiry is None:
        return result(True, expiration_configured=False)
    if type(expiry) is not int or expiry <= 0:
        return unknown("malformed secret expiration metadata")
    return result(False, expiration_configured=True, semantics="Expiration presence only; value and rotation history were not read")
CASES["azure.vault.secret_expiration"] = {"pass": {"properties": {"attributes": {"enabled": True, "exp": 2000000000}}}, "fail": {"properties": {"attributes": {"enabled": True, "exp": None}}}}


@register("azure.vault.approved_private_endpoint", "azure", "hardening", "vault", "Key Vault denies default networking and has an approved private endpoint", "medium", "SC-7", "Set network ACL default to Deny and configure an approved private endpoint; verify DNS and route configuration separately.")
def vault_private(item, index):
    action = get(item, "properties.networkAcls.defaultAction", str)
    if action not in ("Allow", "Deny"):
        return unknown("unrecognized vault network ACL action")
    if action == "Allow":
        return result(True, default_action=action)
    endpoints = list_of_objects(get(item, "properties.privateEndpointConnections", list))
    if not endpoints:
        return result(True, approved_connections=0)
    statuses = [get(endpoint, "properties.privateLinkServiceConnectionState.status", str) for endpoint in endpoints]
    if any(status not in ("Approved", "Pending", "Rejected", "Disconnected") for status in statuses):
        return unknown("unrecognized private endpoint approval state")
    return result("Approved" not in statuses, approval_states=statuses, semantics="Configured ACL and connection approval; endpoint reachability is not verified")
CASES["azure.vault.approved_private_endpoint"] = {"pass": {"properties": {"networkAcls": {"defaultAction": "Deny"}, "privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]}}, "fail": {"properties": {"networkAcls": {"defaultAction": "Allow"}}}}


@register("azure.defender.standard_tier", "azure", "hardening", "security_pricing", "Defender plan configures Standard pricing tier", "medium", "SI-4", "Enable the intended Defender plan, accounting for licensing and service applicability; verify extensions and protection coverage separately.")
def defender_tier(item, index):
    name = get(item, "name", str)
    if name not in ("VirtualMachines", "AppServices", "SqlServers", "SqlServerVirtualMachines", "StorageAccounts", "KeyVaults", "Arm", "OpenSourceRelationalDatabases", "Containers", "CloudPosture", "Api", "CosmosDbs"):
        return "NOT_APPLICABLE", {"reason": "Plan is outside reviewed pricing names", "plan": name}
    tier = get(item, "properties.pricingTier", str)
    if tier not in ("Free", "Standard"):
        return unknown("unrecognized Defender pricing tier")
    return result(tier != "Standard", plan=name, pricing_tier=tier, semantics="Plan pricing configuration; asset coverage, exclusions and sensors are separate")
CASES["azure.defender.standard_tier"] = {"pass": {"name": "StorageAccounts", "properties": {"pricingTier": "Standard"}}, "fail": {"name": "StorageAccounts", "properties": {"pricingTier": "Free"}}}
