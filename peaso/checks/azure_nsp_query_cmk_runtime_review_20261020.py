"""Unregistered parent/item/envelope-bound successors to immutable predicates."""
from copy import deepcopy
import json
import re

from peaso.collectors import azure_nsp_query_cmk_runtime_20261020 as runtime
from peaso.collectors import azure_nsp_query_cmk_metadata_proposal_20261020 as native
from . import azure_nsp_query_cmk_metadata_proposal_20261020 as original

IDS = (original.NSP_CHECK, original.QUERY_CHECK)
DECLARATIONS = deepcopy(original.DECLARATIONS)
for _declaration in DECLARATIONS:
    _declaration['dependencies'] = [*_declaration['dependencies'], 'subscription']


def _same(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def _binding(value, parent, scope, kind=None):
    expected = {'schema', 'adapter', 'scope', 'capture_id', 'transport_context_id', 'read_only',
                'credential_context_id', 'customer_context_id', 'tenant_id', 'tenant_verified', 'context_binding'}
    if kind is not None:
        expected.add('kind')
    if (not isinstance(value, dict) or set(value) != expected or value['schema'] != runtime.SCHEMA
            or value['adapter'] != runtime.ADAPTER or value['scope'] != scope or value['read_only'] is not True
            or kind is not None and value['kind'] != kind
            or any(not _same(value[key], member) for key, member in parent.items())
            or any(not isinstance(value[key], str) or not re.fullmatch('[0-9a-f]{32}', value[key])
                   for key in ('capture_id', 'transport_context_id'))):
        raise ValueError('native runtime capture binding unavailable')
    return value


def _source_read(receipt, scope):
    if (not isinstance(receipt, dict) or set(receipt) != {'operation', 'method', 'path', 'api_version', 'credential_context_id', 'scope'}
            or receipt['method'] != 'GET' or receipt['scope'] != scope):
        raise ValueError('native runtime source receipt malformed')
    operation, path, version = receipt['operation'], receipt['path'], receipt['api_version']
    if operation == 'NetworkSecurityPerimeters_ListBySubscription':
        valid = path == scope + '/providers/' + native.NSP and version == native.NSP_VERSION
    elif operation in ('NetworkSecurityPerimeterAssociations_List', 'NetworkSecurityPerimeterAssociations_Get', 'NetworkSecurityPerimeterProfiles_Get'):
        collection = '/profiles/' if operation == 'NetworkSecurityPerimeterProfiles_Get' else '/resourceAssociations'
        if not isinstance(path, str) or collection not in path:
            raise ValueError('native runtime NSP source path unavailable')
        parent, suffix = path.split(collection, 1)
        native.resource_id(parent, scope, native.NSP)
        valid = version == native.NSP_VERSION and (suffix == '' if operation.endswith('_List') else
                bool(re.fullmatch('/?' + native.SEGMENT, suffix)))
    elif operation == 'StorageAccounts_GetProperties':
        native.resource_id(path, scope, native.STORAGE)
        valid = version == native.STORAGE_VERSION
    elif operation == 'Workspaces_ListBySubscription':
        valid = path == scope + '/providers/' + native.WORKSPACE and version == native.WORKSPACE_VERSION
    elif operation == 'Workspaces_Get':
        native.resource_id(path, scope, native.WORKSPACE)
        valid = version == native.WORKSPACE_VERSION
    elif operation == 'LinkedStorageAccounts_ListByWorkspace':
        if not isinstance(path, str) or not path.endswith('/linkedStorageAccounts'):
            raise ValueError('native runtime Query source path unavailable')
        native.resource_id(path[:-len('/linkedStorageAccounts')], scope, native.WORKSPACE)
        valid = version == native.LINK_VERSION
    else:
        valid = False
    if not valid:
        raise ValueError('native runtime source operation unavailable')


def _delegated_index(item, index, kind):
    context = index['context']
    if context['provider'] != 'azure':
        raise ValueError('native runtime provider mismatch')
    scope = native.scope_id(context['scope'])
    metadata = context['metadata']
    parent = runtime.parent_context(metadata, scope)
    subscriptions = index['collections'].get('subscription')
    if (not isinstance(subscriptions, list) or len(subscriptions) != 1
            or subscriptions[0].get('type') != 'subscription' or subscriptions[0].get('scope') != scope
            or subscriptions[0].get('service') != 'Microsoft.Resources'
            or subscriptions[0].get('status') != 'collected' or len(subscriptions[0].get('items', [])) != 1):
        raise ValueError('native selected subscription dependency unavailable')
    subscription = subscriptions[0]['items'][0]
    if (subscription.get('id') != scope or not isinstance(subscription.get('subscriptionId'), str)
            or subscription['subscriptionId'].casefold() != scope.rsplit('/', 1)[-1].casefold()
            or not isinstance(subscription.get('tenantId'), str) or subscription['tenantId'].casefold() != parent['tenant_id']
            or subscription.get('state') != 'Enabled'):
        raise ValueError('native selected subscription identity/state differs')
    for row in (subscriptions[0], subscription):
        provenance = row.get('_provenance')
        if (not isinstance(provenance, dict) or any(provenance.get(key) != parent[key]
                for key in ('credential_context_id', 'customer_context_id'))):
            raise ValueError('native selected subscription capture differs')
    namespace = metadata[runtime.METADATA_KEY]
    if (not isinstance(namespace, dict) or set(namespace) != {'schema', 'bindings'}
            or namespace['schema'] != runtime.SCHEMA or not isinstance(namespace['bindings'], list)):
        raise ValueError('native runtime namespace unavailable')
    seen, scope_captures = set(), {}
    for declared in namespace['bindings']:
        if not isinstance(declared, dict) or declared.get('kind') not in native.KINDS:
            raise ValueError('native runtime namespace contains foreign kind')
        declared_scope = native.scope_id(declared['scope'])
        _binding(declared, runtime.parent_context(metadata, declared_scope), declared_scope, declared['kind'])
        key = (declared['kind'], declared_scope)
        capture = (declared['capture_id'], declared['transport_context_id'])
        if key in seen or scope_captures.get(declared_scope, capture) != capture:
            raise ValueError('native runtime namespace contains conflicting capture')
        seen.add(key);scope_captures[declared_scope] = capture
    selected = [binding for binding in namespace['bindings'] if isinstance(binding, dict)
                and binding.get('kind') == kind and binding.get('scope') == scope]
    if len(selected) != 1:
        raise ValueError('native runtime namespace ambiguous')
    binding = _binding(selected[0], parent, scope, kind)
    subscription_source = runtime.subscription_receipt(subscription, scope, parent['credential_context_id'],
        parent['customer_context_id'], parent['tenant_id'])
    if subscription_source['transport_context_id'] != binding['transport_context_id']:
        raise ValueError('native subscription and metadata transport differ')
    envelopes = index['collections'][kind]
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or envelopes[0]['type'] != kind
            or envelopes[0]['scope'] != scope or envelopes[0]['status'] != 'collected'
            or envelopes[0]['service'] != ('Microsoft.Network' if kind == native.NSP_KIND else 'Microsoft.OperationalInsights')
            or not _same(envelopes[0]['_provenance'], binding)):
        raise ValueError('native runtime envelope unavailable')
    rows = envelopes[0]['items']
    if (not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows)
            or sum(_same(row, item) for row in rows) != 1
            or any(not _same(row.get('_provenance'), binding) for row in rows)):
        raise ValueError('native runtime item not owned by envelope')
    if not _same(item['_provenance'], binding):
        raise ValueError('native runtime item capture differs')
    marker = item['_capture']
    common = {key: value for key, value in binding.items() if key != 'kind'}
    if (marker.get('schema') != native.SCHEMA or marker.get('scope') != scope
            or marker.get('credential_context_id') != parent['credential_context_id']
            or not _same(_binding(marker['runtime'], parent, scope), common)
            or not isinstance(marker['reads'], list) or not marker['reads']):
        raise ValueError('native runtime deciding capture differs')
    for receipt in marker['reads']:
        _source_read(receipt, scope)
        if receipt['credential_context_id'] != parent['credential_context_id']:
            raise ValueError('native runtime source credential differs')
    if metadata.get('proposal_schema', native.SCHEMA) != native.SCHEMA:
        raise ValueError('conflicting original proposal schema')
    # The original predicate only needs its schema selector added to a COPY.
    # Parent credential/customer/tenant and completed source receipts are intact.
    delegated = dict(index)
    delegated['context'] = {**context, 'metadata': {**metadata, 'proposal_schema': native.SCHEMA}}
    return delegated


def nsp(item, index):
    try:
        return original.nsp(item, _delegated_index(item, index, native.NSP_KIND))
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return 'UNKNOWN', {'observed': 'The parent scan context, native Storage association or capture provenance could not be established.', 'configuration_only': True}


def query(item, index):
    try:
        return original.query(item, _delegated_index(item, index, native.QUERY_KIND))
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return 'UNKNOWN', {'observed': 'The parent scan context, Query-linked Table encryption declaration or capture provenance could not be established.', 'configuration_only': True}
