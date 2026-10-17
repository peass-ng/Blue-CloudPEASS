"""Literal compute source scopes distinguish reserved disks and Trusted Launch applicability."""
from . import register, result
from .facts import get, optional, list_of_objects, field_check, Unavailable
from .fixtures import CASES

CHECK_IDS = []
SOURCE_QUERIES = {'compute_disk_public_access_disabled': 'azure.disk.private_export', 'compute_disk_data_access_auth_mode_enabled': 'azure.disk.entra_export_auth'}
DISK_STATES = ('Attached', 'Reserved', 'Unattached', 'ActiveSAS', 'ActiveSASFrozen', 'ActiveUpload', 'ReadyToUpload', 'Frozen')
ENCRYPTION = ('EncryptionAtRestWithPlatformKey', 'EncryptionAtRestWithCustomerKey', 'EncryptionAtRestWithPlatformAndCustomerKeys')


def port(query, kind, title, control='CM-6'):
    cid = 'azure.port.' + query
    CHECK_IDS.append(cid); SOURCE_QUERIES[query] = cid
    return register(cid, 'azure', 'hardening', kind, title, 'medium', control,
                    'Review the declared metadata and source-specific applicability; no guest execution, disk export, key value or configuration change is performed.', dependencies=[kind])


def _enum(item, field, values):
    value = get(item, field, str)
    if value not in values:
        raise Unavailable('Unrecognized compute provider enum')
    return value


for _query, _attached in [('compute_os_and_data_disk_encrypted_with_cmk', True), ('compute_unattached_disk_encrypted_with_cmk', False)]:
    def _register_disk(query, attached):
        @port(query, 'disk', 'Disk state ' + ('Attached' if attached else 'other than Attached') + ' selects precisely customer-key encryption', 'SC-28')
        def evaluate(item, index):
            state = _enum(item, 'properties.diskState', DISK_STATES)
            if (state == 'Attached') != attached:
                return 'NOT_APPLICABLE', {'reason': 'Exact pinned disk-state selector excludes this disk', 'state': state}
            encryption = _enum(item, 'properties.encryption.type', ENCRYPTION)
            return result(encryption != 'EncryptionAtRestWithCustomerKey', state=state, encryption_type=encryption,
                          semantics='Literal source equality; Reserved is not Attached and double-encryption enum is a separate baseline, not merged')
        CASES[SOURCE_QUERIES[query]] = {'pass': {'properties': {'diskState': 'Attached' if attached else 'Unattached', 'encryption': {'type': 'EncryptionAtRestWithCustomerKey'}}}, 'fail': {'properties': {'diskState': 'Attached' if attached else 'Unattached', 'encryption': {'type': 'EncryptionAtRestWithPlatformKey'}}}}
    _register_disk(_query, _attached)


@port('compute_vm_utilizing_managed_disk', 'vm', 'VM OS disk declares a managed-disk identifier')
def os_disk(item, index):
    disk = get(item, 'properties.storageProfile.osDisk', dict)
    managed = optional(disk, 'managedDisk', None)
    if managed is None:
        return result(True, managed_disk_id=None, semantics='Exact source presence test; ephemeral OS disk is not silently skipped')
    if not isinstance(managed, dict):
        raise Unavailable('Malformed managed-disk metadata')
    identity = optional(managed, 'id', None)
    if identity is not None and (not isinstance(identity, str) or not identity):
        raise Unavailable('Malformed managed-disk identifier')
    return result(identity is None, managed_disk_id=identity, semantics='OS-disk identifier only; all data disks/encryption are separate')
CASES[SOURCE_QUERIES['compute_vm_utilizing_managed_disk']] = {'pass': {'properties': {'storageProfile': {'osDisk': {'managedDisk': {'id': '/subscriptions/sub/resourceGroups/g/providers/Microsoft.Compute/disks/os'}}}}}, 'fail': {'properties': {'storageProfile': {'osDisk': {'managedDisk': None}}}}}


@port('compute_vm_trust_launch_enabled', 'vm', 'VM selecting TrustedLaunch declares both Secure Boot and vTPM', 'SI-7')
def trusted(item, index):
    profile = optional(get(item, 'properties', dict), 'securityProfile', None)
    if profile is None:
        return 'NOT_APPLICABLE', {'reason': 'Known omitted/null security profile is excluded by pinned TrustedLaunch selector'}
    security = optional(profile, 'securityType', None)
    if security is None:
        return 'NOT_APPLICABLE', {'reason': 'Pinned source skips known null securityType'}
    if security not in ('TrustedLaunch', 'ConfidentialVM', 'Standard'):
        raise Unavailable('Unrecognized VM security type')
    if security != 'TrustedLaunch':
        return 'NOT_APPLICABLE', {'reason': 'Source specifically applies to TrustedLaunch', 'security_type': security}
    boot, tpm = get(profile, 'uefiSettings.secureBootEnabled', bool), get(profile, 'uefiSettings.vTpmEnabled', bool)
    return result(not (boot and tpm), secure_boot=boot, vtpm=tpm, semantics='Two declared flags; guest/runtime attestation not measured')
CASES[SOURCE_QUERIES['compute_vm_trust_launch_enabled']] = {'pass': {'properties': {'securityProfile': {'securityType': 'TrustedLaunch', 'uefiSettings': {'secureBootEnabled': True, 'vTpmEnabled': True}}}}, 'fail': {'properties': {'securityProfile': {'securityType': 'TrustedLaunch', 'uefiSettings': {'secureBootEnabled': False, 'vTpmEnabled': True}}}}}


@port('compute_vm_ssh_key_authentication_linux', 'vm', 'Linux VM guest-assignment metadata reports LinuxNoPasswordForSSH compliant', 'IA-5')
def guest_ssh(item, index):
    os_type = _enum(item, 'properties.storageProfile.osDisk.osType', ('Linux', 'Windows'))
    if os_type != 'Linux': return 'NOT_APPLICABLE', {'reason': 'Pinned guest assertion applies to Linux'}
    rid = get(item, 'id', str)
    assignments = list_of_objects(get(item, 'guestConfigurationAssignments', list))
    states = []
    for assignment in assignments:
        identity = get(assignment, 'id', str)
        if not identity.casefold().startswith((rid + '/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/').casefold()):
            raise Unavailable('Foreign guest configuration assignment')
        name = get(assignment, 'properties.guestConfiguration.name', str)
        if name != 'LinuxNoPasswordForSSH': continue
        status = get(assignment, 'properties.complianceStatus', str)
        if status not in ('Compliant', 'NonCompliant', 'Pending'):
            raise Unavailable('Unrecognized guest compliance status')
        states.append(status)
    return result('Compliant' not in states, matching_states=states, semantics='Observed assignment assertion only; report age and current sshd configuration are unverified')
_VM = '/subscriptions/sub/resourceGroups/g/providers/Microsoft.Compute/virtualMachines/vm'
CASES[SOURCE_QUERIES['compute_vm_ssh_key_authentication_linux']] = {'pass': {'id': _VM, 'properties': {'storageProfile': {'osDisk': {'osType': 'Linux'}}}, 'guestConfigurationAssignments': [{'id': _VM + '/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/ssh', 'properties': {'guestConfiguration': {'name': 'LinuxNoPasswordForSSH'}, 'complianceStatus': 'Compliant'}}]}, 'fail': {'id': _VM, 'properties': {'storageProfile': {'osDisk': {'osType': 'Linux'}}}, 'guestConfigurationAssignments': []}}


query = 'compute_vm_and_sacle_set_encryption_at_host_enabled'
vmss = 'azure.port.vmss_encryption_at_host'
CHECK_IDS.append(vmss)
field_check(vmss, 'azure', 'vm_scale_set', 'properties.virtualMachineProfile.securityProfile.encryptionAtHost', True, False, 'VM scale set declares encryption at host', control='SC-28', expected=bool)
SOURCE_QUERIES[query] = ('azure.vm.encryption_at_host', vmss)
