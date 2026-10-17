"""Native ARM storage/backup responses through the real collector and engine."""
import copy
import json
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure
from peaso.collectors.azure_storage_backup_native import DP_VERSION, NETAPP_VERSION, NATIVE_TYPES
from tests.test_peaso_azure_bulk_native import Transport, parent, routes, collect, envelope, verdict, SCOPE, BASE, STORAGE

VAULT = BASE + 'Microsoft.DataProtection/backupVaults/vault'
INSTANCE = VAULT + '/backupInstances/instance'
DISK = BASE + 'Microsoft.Compute/disks/disk'
SHARE = STORAGE + '/fileServices/default/shares/share'
NETAPP = BASE + 'Microsoft.NetApp/netAppAccounts/account'
POOL = NETAPP + '/capacityPools/pool'
VOLUME = POOL + '/volumes/volume'
POLICY = NETAPP + '/backupPolicies/policy'
NVAULT = NETAPP + '/backupVaults/vault'
DISK_CHECK = 'azure_disk_10_3_3_12_174f526'
BLOB_CHECK = 'azure_storage_account_10_3_3_24_61d5e36'
FILES_CHECK = 'azure_storage_file_share_10_3_3_18_d67ab34'


def protection_fixture(kind='disk', mode='complete'):
    resource = DISK if kind == 'disk' else STORAGE
    native_kind = 'disk' if kind == 'disk' else 'storage_account'
    mapping = routes(native_kind, resource, {})
    vault = parent(VAULT, 'Microsoft.DataProtection/backupVaults', {'provisioningState': 'Succeeded', 'description': 'private-marker'})
    mapping[SCOPE + '/providers/Microsoft.DataProtection/backupVaults'] = {'value': [vault]}
    props = {'dataSourceInfo': {'resourceID': resource, 'resourceType': 'Microsoft.Compute/disks', 'secret': 'private-marker'},
             'policyInfo': {'policyId': VAULT + '/backupPolicies/policy'}, 'currentProtectionState': 'ProtectionConfigured',
             'protectionErrorDetails': {'message': 'private-marker'}}
    if mode == 'unprotected': props['currentProtectionState'] = 'ProtectionStopped'
    if mode == 'transient': props['currentProtectionState'] = 'ConfiguringProtection'
    if mode == 'missingstate': props.pop('currentProtectionState')
    if mode == 'foreigndatasource': props['dataSourceInfo']['resourceID'] = resource.replace(SCOPE, '/subscriptions/foreign')
    if kind != 'disk':
        props['policyInfo']['policyParameters'] = {'backupDatasourceParametersList': [
            {'objectType': 'BlobBackupDatasourceParameters', 'containersList': ['container']}]}
        if mode == 'wrongcontainer': props['policyInfo']['policyParameters']['backupDatasourceParametersList'][0]['containersList'] = ['other-container']
        if mode == 'automatic': props['policyInfo']['policyParameters']['backupDatasourceParametersList'][0] = {
            'objectType': 'BlobBackupDatasourceParametersForAutoProtection', 'autoProtectionSettings': {}}
        if mode == 'emptyselection': props['policyInfo']['policyParameters']['backupDatasourceParametersList'][0]['containersList'] = []
        if mode == 'missingselection': props['policyInfo'].pop('policyParameters')
        mapping[STORAGE + '/blobServices/default/containers'] = {'value': [parent(
            STORAGE + '/blobServices/default/containers/container', 'Microsoft.Storage/storageAccounts/blobServices/containers', {})]}
    instance = parent(INSTANCE, 'Microsoft.DataProtection/backupVaults/backupInstances', props)
    if mode == 'foreignchild': instance['id'] = INSTANCE.replace('/backupVaults/vault/', '/backupVaults/foreign/')
    def children(query):
        assert query['api-version'] == [DP_VERSION]
        if mode == 'deniedchild' or mode == 'partial' and '$skiptoken' in query:
            raise azure.AzureReadError('forbidden', 403)
        if mode == 'missing': return {'value': []}
        result = {'value': [instance]}
        if mode in ('partial', 'repeated', 'limit'):
            result['nextLink'] = azure.ARM + VAULT + '/backupInstances?api-version=' + DP_VERSION + '&$skiptoken=next'
        if mode == 'unsafecontinuation': result['nextLink'] = 'https://attacker.invalid/?secret=private-marker'
        if mode == 'conflict' and '$skiptoken' in query:
            result['value'] = [copy.deepcopy(instance)]
            result['value'][0]['properties']['currentProtectionState'] = 'ProtectionStopped'
        if mode == 'conflict' and '$skiptoken' not in query:
            result['nextLink'] = azure.ARM + VAULT + '/backupInstances?api-version=' + DP_VERSION + '&$skiptoken=next'
        return result
    mapping[VAULT + '/backupInstances'] = children
    if mode == 'deniedparent': mapping[SCOPE + '/providers/Microsoft.DataProtection/backupVaults'] = azure.AzureReadError('forbidden', 403)
    if mode == 'novault': mapping[SCOPE + '/providers/Microsoft.DataProtection/backupVaults'] = {'value': []}
    return mapping


@pytest.mark.parametrize('kind,check', [('disk', DISK_CHECK), ('storage_account', BLOB_CHECK)])
@pytest.mark.parametrize('mode,expected', [('complete', 'PASS'), ('unprotected', 'FAIL'), ('missing', 'FAIL'),
    ('novault', 'FAIL'), ('transient', 'UNKNOWN'), ('missingstate', 'UNKNOWN')])
def test_native_dataprotection_actual_protection_state_and_complete_empty(kind, check, mode, expected):
    api = Transport(protection_fixture(kind, mode))
    snapshot = collect([kind, 'backup_vault', 'backup_instance'], api)
    assert verdict(snapshot, check) == expected
    assert 'private-marker' not in json.dumps(snapshot)
    native = envelope(snapshot, 'backup_instance')
    assert native['covered_parent_ids'] == ([] if mode == 'novault' else [VAULT])
    if mode == 'complete':
        assert native['items'][0]['_provenance']['representation'] == 'full'


@pytest.mark.parametrize('mode', ['deniedparent', 'deniedchild', 'partial', 'repeated', 'limit', 'unsafecontinuation',
    'foreignchild', 'foreigndatasource', 'conflict'])
def test_dataprotection_denied_partial_foreign_and_conflicting_reads_never_pass(mode):
    api = Transport(protection_fixture(mode=mode))
    snapshot = collect(['disk', 'backup_vault', 'backup_instance'], api, **({'max_pages': 1} if mode == 'limit' else {}))
    assert verdict(snapshot, DISK_CHECK) in ('UNKNOWN', 'DENIED')
    assert envelope(snapshot, 'backup_instance')['status'] not in ('collected', 'empty')
    assert all(url.startswith(azure.ARM + '/') for url in api.calls)


@pytest.mark.parametrize('mode,expected', [('wrongcontainer', 'FAIL'), ('automatic', 'UNKNOWN'),
    ('emptyselection', 'UNKNOWN'), ('missingselection', 'UNKNOWN')])
def test_blob_backup_container_selection_is_native_and_never_defaulted(mode, expected):
    api = Transport(protection_fixture('storage_account', mode))
    snapshot = collect(['storage_account', 'backup_vault', 'backup_instance'], api)
    assert verdict(snapshot, BLOB_CHECK) == expected


def netapp_fixture(mode='complete'):
    mapping = routes('storage_account', STORAGE, {})
    mapping[STORAGE + '/fileServices/default/shares'] = {'value': []}
    mapping[SCOPE + '/providers/Microsoft.NetApp/netAppAccounts'] = {'value': [parent(NETAPP, 'Microsoft.NetApp/netAppAccounts', {})]}
    mapping[NETAPP + '/capacityPools'] = {'value': [parent(POOL, 'Microsoft.NetApp/netAppAccounts/capacityPools', {})]}
    backup = {'backupPolicyId': POLICY, 'backupVaultId': NVAULT, 'policyEnforced': True}
    if mode == 'unenforced': backup['policyEnforced'] = False
    if mode == 'unjoinedpolicy': backup['backupPolicyId'] = NETAPP + '/backupPolicies/another'
    volume = parent(VOLUME, 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes', {'dataProtection': {'backup': backup}})
    if mode == 'unsetbackup': volume['properties']['dataProtection'].pop('backup')
    if mode == 'unsetprotection': volume['properties'].pop('dataProtection')
    if mode == 'unenforced_missingids': volume['properties']['dataProtection']['backup'] = {'policyEnforced': False}
    if mode == 'malformedbackup': volume['properties']['dataProtection']['backup'] = 'malformed'
    mapping[POOL + '/volumes'] = {'value': [volume]}
    mapping[NETAPP + '/backupPolicies'] = {'value': [parent(POLICY, 'Microsoft.NetApp/netAppAccounts/backupPolicies', {})]}
    mapping[NETAPP + '/backupVaults'] = {'value': [parent(NVAULT, 'Microsoft.NetApp/netAppAccounts/backupVaults', {})]}
    if mode == 'foreignvolume': volume['id'] = VOLUME.replace('/capacityPools/pool/', '/capacityPools/foreign/')
    if mode == 'deniedpool': mapping[NETAPP + '/capacityPools'] = azure.AzureReadError('forbidden', 403)
    if mode == 'deniedvolume': mapping[POOL + '/volumes'] = azure.AzureReadError('forbidden', 403)
    if mode == 'empty':
        mapping[SCOPE + '/providers/Microsoft.NetApp/netAppAccounts'] = {'value': []}
    if mode == 'share_unprotected':
        mapping[STORAGE + '/fileServices/default/shares'] = {'value': [parent(
            SHARE, 'Microsoft.Storage/storageAccounts/fileServices/shares', {'metadata': {'arbitrary': 'private-marker'}})]}
    return mapping


NETAPP_KINDS = ['storage_file_share', 'netapp_volume', 'netapp_backup_policy', 'netapp_backup_vault',
                'backup_protected_item', 'backup_policy', 'recovery_vault']


@pytest.mark.parametrize('mode,expected', [('complete', 'PASS'), ('unenforced', 'FAIL'), ('unjoinedpolicy', 'FAIL'),
    ('deniedpool', 'UNKNOWN'), ('deniedvolume', 'DENIED'), ('foreignvolume', 'UNKNOWN'), ('share_unprotected', 'FAIL'), ('empty', 'PASS'),
    ('unsetbackup', 'FAIL'), ('unsetprotection', 'FAIL'), ('unenforced_missingids', 'FAIL'), ('malformedbackup', 'UNKNOWN')])
def test_native_netapp_and_files_actual_backup_membership(mode, expected):
    api = Transport(netapp_fixture(mode))
    snapshot = collect(NETAPP_KINDS, api)
    assert verdict(snapshot, FILES_CHECK) == expected
    assert 'private-marker' not in json.dumps(snapshot)
    assert all(url.startswith(azure.ARM + '/') for url in api.calls)
    if mode == 'complete':
        assert envelope(snapshot, 'netapp_volume')['items'][0]['parent_id'] == POOL
        assert any('api-version=' + NETAPP_VERSION in url for url in api.calls)


def test_native_type_registration_and_supporting_dependency_expansion():
    assert NATIVE_TYPES <= set(azure.TYPES)
    from peaso.collectors.azure_storage_backup_native import required_types
    assert required_types({'storage_file_share'}) == {'storage_account'}
    assert required_types({'backup_instance'}) == {'backup_vault'}
    assert required_types({'netapp_volume'}) == {'netapp_account', 'netapp_capacity_pool'}


@pytest.mark.parametrize('mode', ['unsetbackup', 'unsetprotection', 'unenforced_missingids'])
def test_missing_backup_on_partial_native_volume_is_unknown(mode):
    from peaso.snapshot import seal
    api = Transport(netapp_fixture(mode))
    snapshot = collect(NETAPP_KINDS, api)
    envelope(snapshot, 'netapp_volume')['items'][0]['_provenance']['representation'] = 'partial'
    snapshot = seal(snapshot)
    assert verdict(snapshot, FILES_CHECK) == 'UNKNOWN'
