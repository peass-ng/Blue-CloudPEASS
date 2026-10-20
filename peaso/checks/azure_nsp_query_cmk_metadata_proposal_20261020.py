"""Two pure unregistered configuration criteria; no framework equivalence."""
from peaso.collectors import azure_nsp_query_cmk_metadata_proposal_20261020 as native

NSP_CHECK = 'azure.review.network.perimeter_association_enforced'
QUERY_CHECK = 'azure.review.log_analytics.query_storage_cmk_declared'
DECLARATIONS = [
    {'id': NSP_CHECK, 'provider': 'azure', 'category': 'hardening', 'kind': native.NSP_KIND,
     'group': 'Network', 'severity': 'medium', 'dependencies': [native.NSP_KIND],
     'title': 'Storage resource declares an enforced network perimeter association',
     'remediation': 'Review the associated perimeter profile and move the supported Storage association to Enforced after validating its access rules.',
     'scope': 'Native Storage association declaration only; no packet, access-rule suitability or effective-routing assertion.',
     'requirements': [], 'registered': False},
    {'id': QUERY_CHECK, 'provider': 'azure', 'category': 'hardening', 'kind': native.QUERY_KIND,
     'group': 'Encryption', 'severity': 'medium', 'dependencies': [native.QUERY_KIND],
     'title': 'Query-linked workspace storage declares customer-managed Table encryption',
     'remediation': 'Review customer-managed encryption on the existing Query-linked storage accounts. Validate key permissions and usability separately.',
     'scope': 'Existing Query-linked Storage declaration only; no requirement to enable Query links and no effective cryptography or key-usability assertion.',
     'requirements': [], 'registered': False},
]


def _bound(item, index, kind):
    context = index['context']
    scope = native.scope_id(context['scope'])
    metadata = context['metadata']
    if context['provider'] != 'azure' or metadata.get('proposal_schema') != native.SCHEMA:
        raise ValueError('native proposal context unavailable')
    credential = metadata['credential_context_id']
    marker = item['_capture']
    if (marker['schema'] != native.SCHEMA or marker['scope'].casefold() != scope.casefold()
            or marker['credential_context_id'] != credential
            or not isinstance(credential, str) or not native.re.fullmatch('[0-9a-f]{32}', credential)):
        raise ValueError('native capture mismatch')
    collections = index['collections'][kind]
    if len(collections) != 1 or collections[0]['status'] != 'collected' or collections[0]['scope'] != scope:
        raise ValueError('complete unique native inventory unavailable')
    rows = collections[0]['items']
    if (len({row['id'].casefold() for row in rows}) != len(rows)
            or sum(row['id'].casefold() == item['id'].casefold() for row in rows) != 1):
        raise ValueError('native resource not uniquely owned')
    reads = marker['reads']
    if not isinstance(reads, list) or not reads or len(reads) > 128:
        raise ValueError('native source receipts unavailable')
    for receipt in reads:
        if (receipt['credential_context_id'] != credential or receipt['scope'] != scope
                or receipt['method'] != 'GET' or not isinstance(receipt['path'], str)):
            raise ValueError('native read context mismatch')
    return scope, reads


def _require(reads, operation, path, version):
    if not any(receipt.get('operation') == operation and receipt.get('path', '').casefold() == path.casefold()
               and receipt.get('api_version') == version for receipt in reads):
        raise ValueError('decisive native operation missing')


def nsp(item, index):
    try:
        scope, reads = _bound(item, index, native.NSP_KIND)
        parent = native.resource_id(item['nsp_id'], scope, native.NSP)
        rid = native.child_id(item['id'], parent, 'resourceAssociations')
        profile = native.child_id(item['profile_id'], parent, 'profiles')
        protected = native.resource_id(item['protected_resource_id'], scope, native.STORAGE)
        if item['type'].casefold() != (native.NSP + '/resourceAssociations').casefold():
            raise ValueError('native association type mismatch')
        for operation, path, version in (
                ('NetworkSecurityPerimeters_ListBySubscription', scope + '/providers/' + native.NSP, native.NSP_VERSION),
                ('NetworkSecurityPerimeterAssociations_List', parent + '/resourceAssociations', native.NSP_VERSION),
                ('NetworkSecurityPerimeterAssociations_Get', rid, native.NSP_VERSION),
                ('NetworkSecurityPerimeterProfiles_Get', profile, native.NSP_VERSION),
                ('StorageAccounts_GetProperties', protected, native.STORAGE_VERSION)):
            _require(reads, operation, path, version)
        if (item['provisioned'] is not True or item['provisioning_issues_absent'] is not True
                or item['protected_provisioned'] is not True or item['access_mode'] not in ('Enforced', 'Learning', 'Audit')):
            raise ValueError('association declaration unresolved')
        mode = item['access_mode']
        return ('PASS' if mode == 'Enforced' else 'FAIL'), {
            'observed': f'The Storage association declares {mode} access mode. Effective traffic and access-rule suitability were not tested.',
            'access_mode': mode, 'configuration_only': True}
    except (KeyError, ValueError, TypeError, AttributeError):
        return 'UNKNOWN', {'observed': 'The native association, profile, Storage identity or provisioning declaration could not be established.', 'configuration_only': True}


def query(item, index):
    try:
        scope, reads = _bound(item, index, native.QUERY_KIND)
        rid = native.resource_id(item['id'], scope, native.WORKSPACE)
        if item['type'].casefold() != native.WORKSPACE.casefold():
            raise ValueError('native workspace type mismatch')
        _require(reads, 'Workspaces_ListBySubscription', scope + '/providers/' + native.WORKSPACE, native.WORKSPACE_VERSION)
        _require(reads, 'Workspaces_Get', rid, native.WORKSPACE_VERSION)
        _require(reads, 'LinkedStorageAccounts_ListByWorkspace', rid + '/linkedStorageAccounts', native.LINK_VERSION)
        accounts = item['accounts']
        if not isinstance(accounts, list):
            raise ValueError('native accounts unavailable')
        link = item['query_link_id']
        if link is None:
            if accounts:
                raise ValueError('contradictory absent Query link')
            return 'NOT_APPLICABLE', {'observed': 'The complete native list contains no Query-linked storage. There is no Query-linked store to assess.', 'configuration_only': True}
        if native.child_id(link, rid, 'linkedStorageAccounts').rsplit('/', 1)[-1] != 'Query' or not accounts:
            raise ValueError('Query link has no resolved stores')
        seen, provider, unresolved = set(), 0, False
        for account in accounts:
            account_id = native.resource_id(account['id'], scope, native.STORAGE)
            if account_id.casefold() in seen:
                raise ValueError('duplicate native account')
            seen.add(account_id.casefold())
            _require(reads, 'StorageAccounts_GetProperties', account_id, native.STORAGE_VERSION)
            if account['provisioned'] is not True:
                unresolved = True
            if account['key_source'] == 'microsoft.storage':
                provider += 1
            elif account['key_source'] != 'microsoft.keyvault' or account['cmk_reference_valid'] is not True:
                unresolved = True
            elif account['table_key_type'] == 'Service':
                provider += 1
            elif account['table_key_type'] != 'Account':
                unresolved = True
        # An unresolved account cannot be silently omitted from a clean result.
        if unresolved:
            raise ValueError('encryption declaration unresolved')
        return ('FAIL' if provider else 'PASS'), {
            'observed': ('Query-linked storage declares a provider-managed account or Table key.' if provider else
                         'Every Query-linked storage account declares a customer-managed key reference and account-scoped Table encryption.') + ' Key usability and effective cryptography were not tested.',
            'account_count': len(accounts), 'provider_managed_count': provider, 'configuration_only': True}
    except (KeyError, ValueError, TypeError, AttributeError):
        return 'UNKNOWN', {'observed': 'The native Query list, owned storage joins or encryption declarations could not be established.', 'configuration_only': True}
