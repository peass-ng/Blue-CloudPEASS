"""claude2_azure DEFENDER / COMPUTE / DATA group: attack-path notifications, VM and scale-set security profiles,
SQL threat detection, storage key source, Batch and Automation.

Defender plan rows of this partition are owned by the active reviewed_azure_ports_legacy_plans shard (per-plan,
resource-aware natives) and are not re-implemented here.
"""
from __future__ import annotations
from .claude2_azure_common import *  # noqa: F401,F403
from .claude2_azure_common import CHECK_IDS
from .claude_azure_data import _contact
from .claude_azure_compute import _os_type, _vm, _assignment, COMPLIANCE

_START = len(CHECK_IDS)


# --- Attack path notifications ---------------------------------------------------------------------------------------

def _alerts_on(contact):
    props = get(contact, "properties", dict)
    legacy = props.get("alertNotifications")
    if isinstance(legacy, str):
        return legacy == "On"
    if isinstance(legacy, dict) and isinstance(legacy.get("state"), str):
        return legacy["state"] == "On"
    enabled = optional(props, "isEnabled", True, bool)
    sources = list_of_objects(get(props, "notificationsSources", list))
    return enabled and any(get(s, "sourceType", str) == "Alert" for s in sources)


@scope_check("defender_attack_path_setting_and_alert_contacts", "security_setting",
             "Defender AttackPath setting is enabled and a security contact receives alert notifications",
             dependencies=["security_setting", "security_contact"], control="IR-6",
             remediation="Enable attack-path notifications and configure a security contact with alert notifications turned on.")
def attack_path_alerts(item, index):
    settings = [s for s in scoped(index, "security_setting") if get(s, "name", str) == "AttackPath"]
    if not settings:
        return na("No AttackPath Defender setting exists in the subscription; upstream emits no row")
    enabled = all(get(s, "properties.enabled", bool) for s in settings)
    contacts = sum(1 for c in scoped(index, "security_contact") if _alerts_on(c))
    return result(not (enabled and contacts > 0), attack_path_enabled=enabled, contacts_with_alert_notifications=contacts)
_AP = {"id": SUB + "/providers/Microsoft.Security/settings/AttackPath", "name": "AttackPath", "properties": {"enabled": True}}
CASES[cid("defender_attack_path_setting_and_alert_contacts")] = {
    "pass": SCOPE, "pass_index": scope_index({"security_setting": [_AP], "security_contact": [_contact(sources=[{"sourceType": "Alert", "minimalSeverity": "High"}])]}),
    "fail": SCOPE, "fail_index": scope_index({"security_setting": [_AP], "security_contact": [_contact()]})}


# --- Virtual machines and scale sets --------------------------------------------------------------------------------

def _encryption_at_host(item, parent, proof):
    profile = omitted(item, parent, "securityProfile", proof, None)
    if profile is None:
        return False
    if not isinstance(profile, dict):
        raise Unavailable("malformed securityProfile")
    return optional(profile, "encryptionAtHost", False, bool)


@claude2("vm_encryption_at_host", "vm", "Virtual machine enables encryption at host", control="SC-28",
         remediation="Register EncryptionAtHost and enable securityProfile.encryptionAtHost on the VM (deallocate first).")
def vm_encryption_at_host(item, index):
    enabled = _encryption_at_host(item, "properties", "storageProfile")
    return result(not enabled, encryption_at_host=enabled)
CASES[cid("vm_encryption_at_host")] = {"pass": _vm(), "fail": _vm()}
CASES[cid("vm_encryption_at_host")]["pass"]["properties"]["securityProfile"] = {"encryptionAtHost": True}


@claude2("vmss_encryption_at_host", "vm_scale_set", "Virtual machine scale set enables encryption at host", control="SC-28",
         remediation="Enable virtualMachineProfile.securityProfile.encryptionAtHost on the scale set model and upgrade instances.")
def vmss_encryption_at_host(item, index):
    enabled = _encryption_at_host(item, "properties.virtualMachineProfile", "storageProfile")
    return result(not enabled, encryption_at_host=enabled)
CASES[cid("vmss_encryption_at_host")] = {
    "pass": {"properties": {"virtualMachineProfile": {"storageProfile": {}, "securityProfile": {"encryptionAtHost": True}}}},
    "fail": {"properties": {"virtualMachineProfile": {"storageProfile": {}, "securityProfile": {"encryptionAtHost": False}}}}}


@claude2("vm_linux_ssh_key_only_guest_config", "vm", "Linux VM is Compliant with the LinuxNoPasswordForSSH machine configuration",
         control="IA-5", remediation="Assign the 'Linux machines should require SSH keys' machine configuration and disable "
                                     "password authentication (disablePasswordAuthentication).")
def vm_ssh_key(item, index):
    os_type = _os_type(item)
    if os_type != "Linux":
        return na("Predicate applies to Linux virtual machines", os_type=os_type)
    statuses = []
    for row in list_of_objects(get(item, "guestConfigurationAssignments", list)):
        if get(row, "properties.guestConfiguration", dict).get("name") == "LinuxNoPasswordForSSH":
            statuses.append(enum(row, "properties.complianceStatus", COMPLIANCE))
    return result("Compliant" not in statuses, statuses=statuses)
CASES[cid("vm_linux_ssh_key_only_guest_config")] = {
    "pass": _vm("Linux", guestConfigurationAssignments=[_assignment("LinuxNoPasswordForSSH")]),
    "fail": _vm("Linux", guestConfigurationAssignments=[_assignment("LinuxNoPasswordForSSH", "NonCompliant")]),
    "na": _vm("Windows", guestConfigurationAssignments=[])}


@claude2("vm_trusted_launch_secure_boot_vtpm", "vm", "Trusted Launch VM enables Secure Boot and vTPM", control="SI-7",
         remediation="Enable Secure Boot and vTPM in the VM's Trusted Launch security profile.")
def vm_trusted_launch(item, index):
    profile = omitted(item, "properties", "securityProfile", "storageProfile", None)
    if profile is None:
        return na("VM has no security profile (not a Trusted Launch VM)")
    if not isinstance(profile, dict):
        raise Unavailable("malformed securityProfile")
    security_type = optional(profile, "securityType", None)
    if security_type != "TrustedLaunch":
        return na("VM security type is not TrustedLaunch", security_type=security_type)
    uefi = optional(profile, "uefiSettings", {}, dict)
    secure_boot = optional(uefi, "secureBootEnabled", False, bool)
    vtpm = optional(uefi, "vTpmEnabled", False, bool)
    return result(not (secure_boot and vtpm), secure_boot_enabled=secure_boot, vtpm_enabled=vtpm)
CASES[cid("vm_trusted_launch_secure_boot_vtpm")] = {"pass": _vm(), "fail": _vm(), "na": _vm()}
CASES[cid("vm_trusted_launch_secure_boot_vtpm")]["pass"]["properties"]["securityProfile"] = {
    "securityType": "TrustedLaunch", "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True}}
CASES[cid("vm_trusted_launch_secure_boot_vtpm")]["fail"]["properties"]["securityProfile"] = {
    "securityType": "TrustedLaunch", "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": False}}


# --- SQL server threat detection --------------------------------------------------------------------------------------

@claude2("sql_server_threat_detection_all_alerts", "sql_server", "SQL server Defender threat detection is enabled with no alert types disabled",
         severity="high", control="SI-4", remediation="Enable Microsoft Defender for SQL on the server and clear the disabled alert types.")
def sql_threat_all(item, index):
    policies = list_of_objects(get(item, "securityAlertPolicies", list))
    if not policies:
        raise Unavailable("server security alert policy not returned")
    bad = []
    for policy in policies:
        state = enum(policy, "properties.state", ("Enabled", "Disabled", "New"))
        disabled = optional(get(policy, "properties", dict), "disabledAlerts", [], list)
        if state != "Enabled" or disabled not in ([], [""]):
            bad.append({"policy": policy.get("name") or policy.get("id"), "state": state, "disabled_alerts": disabled})
    return result(bool(bad), policies=bad, semantics="An empty disabledAlerts list ([] or [\"\"]) means every alert type is on")
_SQLP = lambda state="Enabled", disabled=("",): {"name": "Default", "properties": {"state": state, "disabledAlerts": list(disabled)}}
CASES[cid("sql_server_threat_detection_all_alerts")] = {"pass": {"securityAlertPolicies": [_SQLP()]},
                                                      "fail": {"securityAlertPolicies": [_SQLP(disabled=("Sql_Injection",))]}}


# --- Batch -------------------------------------------------------------------------------------------------------------------

@claude2("batch_account_customer_managed_key", "batch_account", "Batch account encrypts data with a customer-managed key", control="SC-28",
         remediation="Configure the Batch account encryption keySource Microsoft.KeyVault with a Key Vault key.")
def batch_cmk(item, index):
    source = get(item, "properties.encryption.keySource", str)
    if source not in ("Microsoft.Batch", "Microsoft.KeyVault"):
        return unknown("unrecognized encryption keySource", key_source=source)
    return result(source != "Microsoft.KeyVault", key_source=source)
CASES[cid("batch_account_customer_managed_key")] = {"pass": {"properties": {"encryption": {"keySource": "Microsoft.KeyVault"}}},
                                                   "fail": {"properties": {"encryption": {"keySource": "Microsoft.Batch"}}}}


@claude2("batch_account_managed_identity", "batch_account", "Batch account has a managed identity", control="IA-2",
         remediation="Assign a system- or user-assigned managed identity to the Batch account.")
def batch_identity(item, index):
    if "identity" not in item:
        get(item, "properties", dict)
        kind = "None"
    else:
        identity = get(item, "identity")
        kind = "None" if identity is None else enum(identity, "type", ("None", "SystemAssigned", "UserAssigned"))
    return result(kind == "None", identity_type=kind)
CASES[cid("batch_account_managed_identity")] = {"pass": {"identity": {"type": "SystemAssigned"}, "properties": {}},
                                               "fail": {"identity": {"type": "None"}, "properties": {}}}


@claude2("batch_account_resource_logs", "batch_account", "Batch account sends resource logs through a diagnostic setting", control="AU-12",
         remediation="Add a diagnostic setting for the Batch account that enables its log categories.")
def batch_logging(item, index):
    hits = []
    for setting in diagnostic_settings(item):
        for log in diagnostic_logs(setting):
            if not get(log, "enabled", bool):
                continue
            retention = log.get("retentionPolicy")
            if isinstance(retention, dict) and retention.get("enabled") is True and "days" not in retention:
                continue
            hits.append(setting.get("name"))
    return result(not hits, settings=sorted({h for h in hits if h}), matching_enabled_logs=bool(hits))
CASES[cid("batch_account_resource_logs")] = {"pass": diag_case(diag_log("ServiceLog")), "fail": {"diagnosticSettings": []}}


# --- Automation -----------------------------------------------------------------------------------------------------------

@claude2("automation_variable_encrypted", "automation_variable", "Automation account variable is encrypted", control="SC-28",
         remediation="Recreate the variable as encrypted (variables cannot be encrypted in place).")
def automation_variable(item, index):
    encrypted = get(item, "properties.isEncrypted", bool)
    return result(not encrypted, is_encrypted=encrypted)
CASES[cid("automation_variable_encrypted")] = {"pass": {"properties": {"isEncrypted": True}}, "fail": {"properties": {"isEncrypted": False}}}


DEFENDER_IDS = tuple(CHECK_IDS[_START:])
