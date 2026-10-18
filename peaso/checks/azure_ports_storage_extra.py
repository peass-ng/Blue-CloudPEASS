"""Storage source service scopes/category declarations and full-ID container joins."""
import re
from . import register, result
from .facts import get, optional, list_of_objects, complete_items, Unavailable
from .fixtures import CASES
from .azure_ports_storage import _service, _policy, _fixture, ACCOUNT

CHECK_IDS = []
SOURCE_QUERIES = {'storage_account_uses_private_link': 'azure.claude.storage_private_link_all_approved',
                  'storage_account_blob_service_classic_logging_enabled': 'azure.claude.storage_blob_classic_logging',
                  'storage_account_table_service_classic_logging_enabled': 'azure.claude.storage_table_classic_logging',
                  'storage_account_queue_service_classic_logging_enabled': 'azure.claude.storage_queue_classic_logging'}


def port(query, kind, title, deps=None):
    cid = 'azure.port.' + query
    CHECK_IDS.append(cid); SOURCE_QUERIES[query] = cid
    return register(cid, 'azure', 'hardening', kind, title, 'medium', 'AU-12' if 'logging' in query else 'CP-9',
                    'Review the declared storage metadata and coverage; collection reads no blob/file contents, account keys or delivery probes.', dependencies=deps or [kind])


for _service_name, _query in [('blob', 'storage_account_blob_service_logging_enabled'), ('table', 'storage_account_table_service_logging_enabled'), ('queue', 'storage_account_queue_services_logging_enabled')]:
    def _register_logging(service, query):
        @port(query, 'storage_account', 'Eligible storage ' + service + ' diagnostics explicitly enable StorageRead/Write/Delete')
        def evaluate(item, index):
            tier = get(item, 'sku.tier', str).lower()
            if tier not in ('standard', 'premium'):
                raise Unavailable('Unrecognized storage SKU tier')
            if tier == 'premium' and (service != 'blob' or get(item, 'kind', str) in ('StorageV2', 'FileStorage')):
                return 'NOT_APPLICABLE', {'reason': 'Exact premium service/kind scope excluded by pinned source'}
            settings = list_of_objects(get(item, 'serviceDiagnosticSettings.' + service, list))
            found = set()
            for setting in settings:
                for log in list_of_objects(get(setting, 'properties.logs', list)):
                    enabled = get(log, 'enabled', bool)
                    category = optional(log, 'category', None)
                    if category is not None and not isinstance(category, str):
                        raise Unavailable('Malformed storage diagnostic category')
                    if enabled and category in ('StorageRead', 'StorageWrite', 'StorageDelete'):
                        found.add(category)
            return result(not {'StorageRead','StorageWrite','StorageDelete'} <= found, enabled_categories=sorted(found), semantics='Exact literal categories across settings; allLogs group does not replace source selectors')
        case = {'sku': {'tier': 'Standard'}, 'kind': 'StorageV2'}
        logs = [{'category': category, 'enabled': True} for category in ('StorageRead','StorageWrite','StorageDelete')]
        CASES[SOURCE_QUERIES[query]] = {'pass': {**case, 'serviceDiagnosticSettings': {service: [{'properties': {'logs': logs}}]}}, 'fail': {**case, 'serviceDiagnosticSettings': {service: []}}}
    _register_logging(_service_name, _query)


@port('storage_account_file_share_soft_delete_enabled', 'storage_account', 'Storage account with file shares declares enabled1–365day soft delete', ['storage_account','storage_service'])
def file_soft(item, index):
    service = _service(item, index, 'fileServices')
    shares = list_of_objects(get(service, 'shares', list))
    if not shares:
        return 'NOT_APPLICABLE', {'reason': 'Complete file-share metadata is empty; source skips accounts with no shares'}
    good, evidence = _policy(service, 'shareDeleteRetentionPolicy', 1)
    return result(not good, share_count=len(shares), **evidence)
CASES[SOURCE_QUERIES['storage_account_file_share_soft_delete_enabled']] = {'pass': {'id': ACCOUNT}, 'fail': {'id': ACCOUNT}, 'pass_index': _fixture({'shareDeleteRetentionPolicy': {'enabled': True,'days':1}}, 'fileServices'), 'fail_index': _fixture({'shareDeleteRetentionPolicy': {'enabled': False}}, 'fileServices')}
for _label in ('pass','fail'):
    CASES[SOURCE_QUERIES['storage_account_file_share_soft_delete_enabled']][_label + '_index']['storage_service'][0]['data']['shares'] = [{'name':'share'}]


@port('storage_account_blob_containers_public_access_disabled', 'storage_container', 'Blob container and exact parent account both exclude anonymous blob access', ['storage_container','storage_account'])
def container_public(item, index):
    cid = get(item, 'id', str)
    match = re.fullmatch(r'(/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Storage/storageAccounts/[^/]+)/blobServices/default/containers/[^/]+', cid, re.I)
    if match is None:
        raise Unavailable('Malformed container ARM identity')
    accounts = [row for row in complete_items(index, 'storage_account') if get(row, 'id', str).casefold() == match[1].casefold()]
    if len(accounts) != 1:
        raise Unavailable('Container account missing or ambiguous')
    allowed = get(accounts[0], 'properties.allowBlobPublicAccess', bool)
    access = get(item, 'properties.publicAccess', str)
    if access not in ('None','Blob','Container'):
        raise Unavailable('Unrecognized container public-access mode')
    return result(allowed or access != 'None', account_allows_public=allowed, container_public_access=access, semantics='Exact conjunction; effective endpoints, ACL authorization and public-network mode are separate')
_CONTAINER = ACCOUNT + '/blobServices/default/containers/container'
CASES[SOURCE_QUERIES['storage_account_blob_containers_public_access_disabled']] = {'pass': {'id':_CONTAINER,'properties':{'publicAccess':'None'}},'fail':{'id':_CONTAINER,'properties':{'publicAccess':'Blob'}},'pass_index':_fixture({}),'fail_index':_fixture({})}
for _label in ('pass','fail'):
    CASES[SOURCE_QUERIES['storage_account_blob_containers_public_access_disabled']][_label+'_index']={'storage_account':[{'data':{'id':ACCOUNT,'properties':{'allowBlobPublicAccess':False}}}],'collections':{'storage_account':[{'status':'collected','scope':'/subscriptions/sub'}]}}
