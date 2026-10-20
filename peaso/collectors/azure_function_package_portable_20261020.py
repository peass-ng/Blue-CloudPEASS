"""Same-process export adapter for the original unregistered native collector.

Never re-sign an input, reconstruct the old seal or admit a saved native envelope.
Call only at a trusted collector boundary before process-local keys disappear.
No fetching, auth, pre-auth wiring or shared snapshot/engine hooks live here.
"""
from copy import deepcopy
from datetime import datetime, timezone

from peaso import azure_function_package_portable_20261020 as contract
from peaso.secret_scanning import _fingerprint, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from . import azure_function_package_source_20261020 as source
from . import azure_selected_storage_secret_indicators as storage


def build_expected_context(targets, scopes, *, capture, customer_context_id,
                           credential_context_id, tenant_id, principal_id):
    """Derive locators from caller-owned selection/identity, never envelope metadata.

    This validates structure, not permission to collect. Future engine integration
    must retain real pre-auth authorization and supply trusted run context. The
    capture ID is retained by the caller from its controlled collector invocation.
    """
    targets = source.preflight({'content_secret_scans': True, source.OPTION: targets}, scopes, [source.CHECK])
    contract.require(isinstance(tenant_id, str) and isinstance(principal_id, str)
                     and contract.match(contract.GUID, tenant_id.lower()) and contract.match(contract.GUID, principal_id.lower())
                     and all(s == s.lower() for s in scopes))
    context = {'provider': 'azure', 'scopes': [s.lower() for s in scopes], 'capture': capture,
               'customer_context_id': customer_context_id, 'credential_context_id': credential_context_id,
               'tenant_id': tenant_id.lower(), 'principal': 'storage-source-principal:' + _fingerprint(tenant_id.lower() + '\n' + principal_id.lower()),
               'selection': {s.lower(): [] for s in scopes}, 'target_order': [], 'targets': {}}
    for target in targets:
        ident, blob = source.identity(target), target['blob']
        scope = storage.parse(blob)[1].lower()
        site = target['site_resource_id']
        host, route = storage.data_route(blob)
        requests = []
        for operation in source.OPERATIONS:
            if operation.startswith(('site_', 'settings_')):
                method = 'POST' if operation.startswith('settings_') else 'GET'
                path = site + ('/config/appsettings/list' if method == 'POST' else '') + '?api-version=' + source.SITE_VERSION
                request = 'package-web-request:' + _fingerprint(method + '\n' + path)
            else:
                method = 'HEAD' if operation.startswith('properties_') else 'GET'
                origin = 'management.azure.com' if operation in ('subscription', 'account') else host
                path = (storage.parse(blob)[1] + '?api-version=' + storage.SUB_VERSION if operation == 'subscription' else
                        blob['resource_id'] + '?api-version=' + storage.ARM_VERSION if operation == 'account' else route)
                request = 'storage-source-request:' + _fingerprint(method + '\n' + origin + '\n' + path)
            requests.append(request)
        context['target_order'].append(ident)
        context['selection'][scope].append(ident)
        context['targets'][ident] = {'scope': scope, 'object_identity': storage.identity(blob),
                                    'selection_mode': 'versioned' if 'version' in blob else 'current', 'requests': requests}
    contract.validate_context(context)
    return context


def export_native_projection(envelope, *, expected_index_context):
    """Validate sealed native facts before constructing a plain portable snapshot.

    Invalid/tampered input raises a fixed Invalid error, never a favorable row.
    Valid denied/partial captures retain their native UNKNOWN/incomplete facts.
    This exports an isolated snapshot only; mixed metadata union redaction and
    normal trusted index admission remain future owner-controlled integration.
    """
    try:
        contract.bounded(envelope)
        native = deepcopy(envelope)
        contract.require(source.authentic(native))
        contract.validate_context(expected_index_context)
        contract.require(set(native) == {'schema', 'authorized', 'capture', 'customer_context_id', 'credential_context_id', 'selection', 'results', 'receipts', 'seal'}
                         and native['schema'] == source.SCHEMA == contract.NATIVE_SCHEMA
                         and native['authorized'] is True and source.KIND == contract.NATIVE_KIND
                         and source.OPERATIONS == contract.OPERATIONS
                         and contract.VERSIONS == {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION})
        for field in ('capture', 'customer_context_id', 'credential_context_id', 'selection'):
            contract.require(native[field] == expected_index_context[field])
        contract.validate_facts(native['results'], native['receipts'], expected_index_context)
        # No provider fact is filled in or repaired. Only the outer ordinary
        # snapshot and explicit export-boundary assertion are constructed here.
        collections = []
        for scope in expected_index_context['scopes']:
            rows = [r for r in native['results'] if r['scope'] == scope]
            collections.append({'type': contract.KIND, 'scope': scope, 'service': 'Microsoft.Web',
                                'status': 'empty' if not rows else 'collected' if all(r['complete'] for r in rows) else 'partial',
                                'items': rows})
        snapshot = {'schema_version': '1.0', 'provider': 'azure', 'scopes': deepcopy(expected_index_context['scopes']),
                    'created_at': datetime.now(timezone.utc).isoformat(), 'collections': collections,
                    'metadata': {contract.KIND: {'schema': contract.SCHEMA, 'trust_boundary': contract.TRUST,
                        'native_projection_verified_at_export': True, 'index_context': deepcopy(expected_index_context),
                        'receipts': native['receipts']}}}
        snapshot['snapshot_id'] = contract.digest(snapshot)
        contract.require(len(contract.canonical(snapshot).encode()) <= contract.MAX_JSON_BYTES)
        contract.validate_snapshot(snapshot, expected_index_context)
        return snapshot
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, UnicodeError, OverflowError):
        raise contract.Invalid('native_package_export_rejected') from None
