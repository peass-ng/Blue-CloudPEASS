"""Storage account predicates with complete, authoritative child-resource joins."""
import re
from datetime import datetime

from . import register, result
from .facts import get, complete_items, optional, Unavailable
from .fixtures import CASES
from .azure_ports_services import _enum

CHECK_IDS = []
SOURCE_QUERIES = {
    'storage_account_infrastructure_encryption_enabled': 'azure.storage.infrastructure_encryption',
    'storage_account_cross_tenant_replication_disabled': 'azure.storage.cross_tenant_replication',
    'storage_account_block_public_access': 'azure.storage.no_public_network',
    'storage_account_default_network_access_deny': 'azure.storage.default_deny',
}
ACCOUNT = '/subscriptions/sub/resourceGroups/group/providers/Microsoft.Storage/storageAccounts/account'


def storage_port(query, title, *, dependencies=None, control='CP-9'):
    cid = 'azure.port.' + query
    CHECK_IDS.append(cid)
    SOURCE_QUERIES[query] = cid
    return register(cid, 'azure', 'hardening', 'storage_account', title, 'medium', control,
                    'Review the declared storage configuration and recovery policy; runtime protection remains separate.',
                    dependencies=dependencies or ['storage_account'])


def _account(item):
    rid = get(item, 'id', str)
    if not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Storage/storageAccounts/[^/]+', rid, re.I):
        raise Unavailable('Malformed storage account ARM identity')
    return rid


def _service(item, index, service):
    rid = _account(item)
    target = (rid + '/' + service + '/default').lower()
    rows = [row for row in complete_items(index, 'storage_service') if get(row, 'id', str).lower() == target]
    if len(rows) != 1:
        raise Unavailable('Required storage service detail missing or ambiguous')
    expected = 'microsoft.storage/storageaccounts/' + service.lower()
    if get(rows[0], 'type', str).lower() != expected:
        raise Unavailable('Storage service type does not match ARM identity')
    return rows[0]


def _fixture(properties, service='blobServices'):
    rid = ACCOUNT + '/' + service + '/default'
    return {'storage_service': [{'data': {'id': rid, 'type': 'Microsoft.Storage/storageAccounts/' + service, 'properties': properties}}],
            'collections': {'storage_service': [{'status': 'collected', 'scope': ACCOUNT + '/' + service}]}}


def _policy(service, path, minimum):
    enabled = get(service, 'properties.' + path + '.enabled', bool)
    if not enabled:
        return False, {'enabled': False}
    days = get(service, 'properties.' + path + '.days', int)
    return minimum <= days <= 365, {'enabled': enabled, 'days': days}


@storage_port('storage_account_encryption_at_rest_using_cmk', 'Storage account selects customer-managed encryption', control='SC-28')
def cmk(item, index):
    source = _enum(item, 'properties.encryption.keySource', ('Microsoft.Storage', 'Microsoft.Keyvault', 'Microsoft.KeyVault'))
    return result(source == 'Microsoft.Storage', key_source=source, semantics='Key source declaration; platform encryption and key accessibility are separate')
CASES[SOURCE_QUERIES['storage_account_encryption_at_rest_using_cmk']] = {'pass': {'properties': {'encryption': {'keySource': 'Microsoft.Keyvault'}}}, 'fail': {'properties': {'encryption': {'keySource': 'Microsoft.Storage'}}}}


@storage_port('storage_account_geo_redundant_enabled', 'Storage uses a source-approved geo-redundant SKU')
def geo(item, index):
    value = _enum(item, 'sku.name', ('Standard_LRS', 'Standard_GRS', 'Standard_RAGRS', 'Standard_ZRS', 'Premium_LRS', 'Premium_ZRS', 'Standard_GZRS', 'Standard_RAGZRS', 'StandardV2_LRS', 'StandardV2_GRS', 'StandardV2_ZRS', 'StandardV2_GZRS', 'PremiumV2_LRS', 'PremiumV2_ZRS'))
    return result(value not in ('Standard_GRS', 'Standard_RAGRS', 'Standard_GZRS', 'Standard_RAGZRS'), sku=value, semantics='Exact pinned SKU baseline; replication success not measured')
CASES[SOURCE_QUERIES['storage_account_geo_redundant_enabled']] = {'pass': {'sku': {'name': 'Standard_GRS'}}, 'fail': {'sku': {'name': 'Standard_LRS'}}}


@storage_port('storage_account_key_rotation_reminder_enabled', 'Storage key policy sets precisely 90 days', control='IA-5')
def reminder(item, index):
    policy = optional(get(item, 'properties', dict), 'keyPolicy', None)
    if policy is None:
        return result(True, key_policy=None)
    days = get(policy, 'keyExpirationPeriodInDays', int)
    return result(days != 90, configured_days=days, semantics='Reminder only; actual regeneration evaluated separately')
CASES[SOURCE_QUERIES['storage_account_key_rotation_reminder_enabled']] = {'pass': {'properties': {'keyPolicy': {'keyExpirationPeriodInDays': 90}}}, 'fail': {'properties': {'keyPolicy': {'keyExpirationPeriodInDays': 89}}}}


@storage_port('storage_account_soft_delete_enabled', 'Blob service enables soft delete', dependencies=['storage_account', 'storage_service'])
def blob_enabled(item, index):
    enabled = get(_service(item, index, 'blobServices'), 'properties.deleteRetentionPolicy.enabled', bool)
    return result(not enabled, enabled=enabled, semantics='Enabled-only source; retention range is a distinct predicate')
CASES[SOURCE_QUERIES['storage_account_soft_delete_enabled']] = {'pass': {'id': ACCOUNT}, 'fail': {'id': ACCOUNT}, 'pass_index': _fixture({'deleteRetentionPolicy': {'enabled': True}}), 'fail_index': _fixture({'deleteRetentionPolicy': {'enabled': False}})}


for _query, _path in [('storage_account_blob_soft_delete_enabled', 'deleteRetentionPolicy'), ('storage_account_container_soft_delete_enabled', 'containerDeleteRetentionPolicy')]:
    def _register_retention(query, path):
        @storage_port(query, 'Storage ' + path + ' is enabled with 7–365 day retention', dependencies=['storage_account', 'storage_service'])
        def evaluate(item, index):
            good, evidence = _policy(_service(item, index, 'blobServices'), path, 7)
            return result(not good, policy=path, **evidence)
        CASES[SOURCE_QUERIES[query]] = {'pass': {'id': ACCOUNT}, 'fail': {'id': ACCOUNT}, 'pass_index': _fixture({path: {'enabled': True, 'days': 7}}), 'fail_index': _fixture({path: {'enabled': True, 'days': 6}})}
    _register_retention(_query, _path)


@storage_port('storage_account_blob_and_container_soft_delete_enabled', 'Storage configures blob and container soft delete with 7–365 day retention', dependencies=['storage_account', 'storage_service'])
def both(item, index):
    service = _service(item, index, 'blobServices')
    blob, blob_evidence = _policy(service, 'deleteRetentionPolicy', 7)
    container, container_evidence = _policy(service, 'containerDeleteRetentionPolicy', 7)
    return result(not (blob and container), blob=blob_evidence, container=container_evidence)
CASES[SOURCE_QUERIES['storage_account_blob_and_container_soft_delete_enabled']] = {'pass': {'id': ACCOUNT}, 'fail': {'id': ACCOUNT}, 'pass_index': _fixture({'deleteRetentionPolicy': {'enabled': True, 'days': 7}, 'containerDeleteRetentionPolicy': {'enabled': True, 'days': 365}}), 'fail_index': _fixture({'deleteRetentionPolicy': {'enabled': True, 'days': 7}, 'containerDeleteRetentionPolicy': {'enabled': False}})}


@storage_port('storage_account_blob_versioning_enabled', 'Storage blob service enables versioning', dependencies=['storage_account', 'storage_service'])
def versioning(item, index):
    enabled = get(_service(item, index, 'blobServices'), 'properties.isVersioningEnabled', bool)
    return result(not enabled, versioning_enabled=enabled)
CASES[SOURCE_QUERIES['storage_account_blob_versioning_enabled']] = {'pass': {'id': ACCOUNT}, 'fail': {'id': ACCOUNT}, 'pass_index': _fixture({'isVersioningEnabled': True}), 'fail_index': _fixture({'isVersioningEnabled': False})}


for _query, _field, _good, _bad, _allowed in [
    ('storage_account_file_share_smb_protocol_version_3_1_1', 'versions', 'SMB3.1.1;', 'SMB3.0;SMB3.1.1;', {'SMB2.1', 'SMB3.0', 'SMB3.1.1'}),
    ('storage_account_file_share_smb_channel_encryption_aes_256_gcm', 'channelEncryption', 'AES-256-GCM;', 'AES-128-GCM;AES-256-GCM;', {'AES-128-CCM', 'AES-128-GCM', 'AES-256-GCM'}),
]:
    def _register_smb(query, field, good, bad, allowed):
        @storage_port(query, 'Storage SMB declares precisely ' + good, dependencies=['storage_account', 'storage_service'], control='SC-8')
        def evaluate(item, index):
            value = get(_service(item, index, 'fileServices'), 'properties.protocolSettings.smb.' + field, str)
            parts = value.rstrip(';').split(';')
            if not value or any(part not in allowed for part in parts):
                raise Unavailable('Unrecognized SMB protocol setting')
            return result(value != good, configured=value, source_predicate='Exact provider string including trailing semicolon; multiple algorithms differ')
        CASES[SOURCE_QUERIES[query]] = {'pass': {'id': ACCOUNT}, 'fail': {'id': ACCOUNT}, 'pass_index': _fixture({'protocolSettings': {'smb': {field: good}}}, 'fileServices'), 'fail_index': _fixture({'protocolSettings': {'smb': {field: bad}}}, 'fileServices')}
    _register_smb(_query, _field, _good, _bad, _allowed)


def _utc(value):
    if not isinstance(value, str):
        raise Unavailable('Missing timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('Malformed timestamp') from exc
    if parsed.tzinfo is None:
        raise Unavailable('Timestamp lacks timezone')
    return parsed


@storage_port('storage_account_access_keys_periodically_regenerated', 'Storage key creation metadata is within 90 days of capture', control='IA-5')
def rotated(item, index):
    captured = _utc(get(index, 'context.created_at', str))
    times = get(item, 'properties.keyCreationTime', dict)
    ages = {}
    for name in ('key1', 'key2'):
        value = _utc(get(times, name, str))
        age = (captured - value).total_seconds() / 86400
        if age < 0:
            raise Unavailable('Key creation time is after snapshot capture')
        ages[name] = age
    return result(any(age > 90 for age in ages.values()), days_since_creation=ages, semantics='ARM key creation timestamps only; no ListKeys or key values read. Missing metadata remains UNKNOWN')
CASES[SOURCE_QUERIES['storage_account_access_keys_periodically_regenerated']] = {'pass': {'properties': {'keyCreationTime': {'key1': '2026-07-12T00:00:00Z', 'key2': '2026-10-10T00:00:00Z'}}}, 'fail': {'properties': {'keyCreationTime': {'key1': '2026-07-11T23:59:59Z', 'key2': '2026-10-10T00:00:00Z'}}}, 'pass_index': {'context': {'created_at': '2026-10-10T00:00:00Z'}}, 'fail_index': {'context': {'created_at': '2026-10-10T00:00:00Z'}}}
