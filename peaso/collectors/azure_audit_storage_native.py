"""Native audit-storage logging absence; no delivery or secure-sink PASS claim."""
from datetime import datetime, timezone
from copy import deepcopy
import hashlib
import json
import re

ARM = 'https://management.azure.com'
VERSION = '2021-05-01-preview'
NAMESPACE = 'azure_audit_storage'
KIND = 'audit_storage_access_evidence'
NATIVE_TYPES = {KIND}
CONTRACT = 'native-audit-storage-logging-absence-v1'
CID = 'azure.other.audit_storage_access_logging'
SUB = r'/subscriptions/[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
ACCOUNT = SUB + r'/resourceGroups/[^/?#%\\\s]+/providers/Microsoft.Storage/storageAccounts/[a-z0-9]{3,24}'
OPERATIONS = ('read', 'write', 'delete')
CATEGORIES = {'StorageRead', 'StorageWrite', 'StorageDelete'}
MAX_CATEGORY_PAGES = 16


def required_types(wanted):
    return {'storage_account'} if KIND in wanted else set()


def _object(value):
    if not isinstance(value, dict): raise ValueError('native audit metadata unavailable')
    return value


def _text(value):
    if not isinstance(value, str) or not value or len(value) > 2048 or value != value.strip() or any(ord(c) < 32 for c in value):
        raise ValueError('audit review identity invalid')
    return value


def _date(value):
    result = datetime.fromisoformat(_text(value).replace('Z', '+00:00'))
    if result.utcoffset() is None: raise ValueError('audit review timezone required')
    return result


def normalize(options):
    params = _object(options.get('compliance_parameters', {}))
    if NAMESPACE not in params: return None
    review = _object(params[NAMESPACE])
    from peaso.server.native_policy_validation import bounded
    bounded(review)
    fields = {'status', 'scope', 'authorized_by', 'document_id', 'observed_at', 'expires_at', 'audit_account_ids'}
    if set(review) != fields or review['status'] != 'collected' or not isinstance(review['scope'], str) or re.fullmatch(SUB, review['scope']) is None:
        raise ValueError('exact audit account classification scope required')
    for field in ('authorized_by', 'document_id'): _text(review[field])
    if _date(review['observed_at']) >= _date(review['expires_at']): raise ValueError('audit review expiry must follow approval')
    accounts = review['audit_account_ids']
    if (not isinstance(accounts, list) or not 1 <= len(accounts) <= 128
            or any(not isinstance(a, str) or re.fullmatch(ACCOUNT, a, re.I) is None
                or not a.casefold().startswith(review['scope'].casefold() + '/')
                or any(p in ('.', '..') for p in a.split('/')) for a in accounts)
            or len({a.casefold() for a in accounts}) != len(accounts)):
        raise ValueError('audit account classification identities invalid or ambiguous')
    return review


def _parents(collections, scope):
    matches = [c for c in collections if c.get('type') == 'storage_account' and str(c.get('scope', '')).casefold() == scope.casefold()]
    if len(matches) != 1 or matches[0].get('status') not in ('collected', 'empty'): raise ValueError('audit parent inventory incomplete')
    items = matches[0].get('items')
    if not isinstance(items, list) or (matches[0]['status'] == 'empty') != (not items): raise ValueError('audit parent inventory inconsistent')
    parents = {}
    for item in items:
        rid = _object(item).get('id')
        if (not isinstance(rid, str) or re.fullmatch(ACCOUNT, rid, re.I) is None
                or not rid.casefold().startswith(scope.casefold() + '/') or rid.casefold() in parents
                or str(item.get('type', '')).casefold() != 'microsoft.storage/storageaccounts'):
            raise ValueError('audit account parent identity invalid')
        parents[rid.casefold()] = item
    return parents


def projection(account):
    proof = _object(account.get('_provenance'))
    return {'id': account.get('id'), 'serviceDiagnosticSettings': account.get('serviceDiagnosticSettings'),
        'serviceAnalyticsLogging': account.get('serviceAnalyticsLogging'),
        '_provenance': {k: proof.get(k) for k in ('representation', 'source_operation', 'read_only', 'api_version')}}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _category_groups(category):
    # Optional native metadata: absence is unavailable, never inferred membership.
    from peaso.checks.facts import optional
    absent = object()
    groups = optional(category, 'categoryGroups', absent)
    if groups is absent:
        return None
    if (not isinstance(groups, list) or len(groups) > 16
            or any(not isinstance(g, str) or re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}', g) is None for g in groups)
            or len({g.casefold() for g in groups}) != len(groups)):
        raise ValueError('native category group membership malformed or duplicate')
    return sorted(groups)


def _categories(reader, request, account):
    parent = account + '/blobServices/default'
    base = parent + '/providers/Microsoft.Insights/diagnosticSettingsCategories/'
    result, ids, names = [], set(), set()
    for number, page in enumerate(reader.pages(request, ARM + base.rstrip('/') + '?api-version=' + VERSION), 1):
        if number >= MAX_CATEGORY_PAGES: raise ValueError('Blob category page budget exceeded')
        for raw in page:
            raw = _object(raw)
            rid, name, props = raw.get('id'), raw.get('name'), _object(raw.get('properties'))
            kind = props.get('categoryType')
            if (not isinstance(rid, str) or not isinstance(name, str) or re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,127}', name) is None
                    or rid.casefold() != (base + name).casefold() or rid.casefold() in ids or name.casefold() in names
                    or kind not in ('Logs', 'Metrics')):
                raise ValueError('Blob logging category identity/type malformed or duplicate')
            ids.add(rid.casefold()); names.add(name.casefold())
            groups = _category_groups(props)
            result.append({'id': rid, 'name': name, 'categoryType': kind,
                           **({'categoryGroups': groups} if groups is not None else {})})
            if len(result) > 256: raise ValueError('Blob logging category budget exceeded')
    return result


def collect(reader, request, scopes, wanted, options):
    if KIND not in wanted: return
    review = normalize(options)
    if review is not None and review['scope'].casefold() not in {s.casefold() for s in scopes}:
        raise ValueError('audit classification subscription outside selected scopes')
    for scope in scopes:
        def rows(scope=scope):
            if review is None or review['scope'].casefold() != scope.casefold():
                from .azure import AzureReadError
                raise AzureReadError('audit_classification_unavailable')
            now = datetime.now(timezone.utc)
            if not _date(review['observed_at']) <= now < _date(review['expires_at']):
                from .azure import AzureReadError
                raise AzureReadError('audit_classification_not_current')
            parents = _parents(reader.collections, scope)
            for identity in review['audit_account_ids']:
                account = parents.get(identity.casefold())
                if account is None: raise ValueError('classified audit account missing from native inventory')
                categories = _categories(reader, request, account['id'])
                yield [{'id': account['id'] + '/complianceEvidence/nativeAuditLogging', 'parent_id': account['id'],
                    '_metadata_projection': CONTRACT, 'payload': {'account_configuration_sha256': digest(projection(account)),
                        'categories': categories}, '_provenance': {'schema_version': 1, 'read_only': True,
                        'source_operation': 'BlobDiagnosticSettingsCategories_List+native_storage_logging_metadata',
                        'api_version': VERSION, 'category_pages_complete': True,
                        'operator_classification': deepcopy(review),
                        'captured_at': 'pending_native_snapshot_binding'}}]
        reader.run([(KIND, scope, 'Microsoft.Storage', rows)])


def snapshot_instant(collections, wanted, instant=None):
    if KIND not in wanted: return instant
    instant = instant or datetime.now(timezone.utc).isoformat()
    for env in collections:
        if env.get('type') == KIND:
            for row in env['items']: row['_provenance']['captured_at'] = instant
    return instant


def has_native(item, index):
    return any(isinstance(w.get('data'), dict) and str(w['data'].get('parent_id', '')).casefold() == str(item.get('id', '')).casefold()
        and '_metadata_projection' in w['data'] for w in index.get(KIND, []) if isinstance(w, dict))


def assess(parent, context, evidence, parents):
    from peaso.checks.facts import get, optional, Unavailable

    unknown = ('UNKNOWN', {'reason': 'native audit classification, logging configuration or actual delivery unresolved'})
    try:
        if parent not in parents: return unknown
        matches = []
        for row in evidence.values():
            pid = get(row, 'parent_id', str)
            if pid.casefold() not in parents or get(row, 'id', str).casefold() != (pid + '/complianceEvidence/nativeAuditLogging').casefold(): return unknown
            if pid.casefold() == parent: matches.append(row)
        if len(matches) != 1: return unknown
        row = matches[0]; proof = get(row, '_provenance', dict); payload = get(row, 'payload', dict)
        review = normalize({'compliance_parameters': {NAMESPACE: get(proof, 'operator_classification', dict)}})
        if review is None or review['scope'].casefold() != context.get('scope', '').casefold(): return unknown
        if not _date(review['observed_at']) <= _date(context.get('created_at')) < _date(review['expires_at']): return unknown
        if parent not in {a.casefold() for a in review['audit_account_ids']}: return unknown
        if (get(row, '_metadata_projection') != CONTRACT or get(proof, 'schema_version', int) != 1
                or get(proof, 'read_only', bool) is not True or get(proof, 'category_pages_complete', bool) is not True
                or get(proof, 'source_operation') != 'BlobDiagnosticSettingsCategories_List+native_storage_logging_metadata'
                or get(proof, 'api_version') != VERSION or get(proof, 'captured_at') != context.get('created_at')): return unknown
        account = parents[parent]
        if get(payload, 'account_configuration_sha256') != digest(projection(account)): return unknown
        native = get(account, '_provenance', dict)
        if (get(native, 'read_only', bool) is not True or get(native, 'representation') != 'full'
                or get(native, 'source_operation') != 'get'): return unknown
        get(native, 'api_version', str)
        account_id = get(account, 'id', str)
        if account_id.casefold() != parent: return unknown
        categories = get(payload, 'categories', list)
        seen, logs = set(), set()
        group_members, membership_known = {}, set()
        base = account_id + '/blobServices/default/providers/Microsoft.Insights/diagnosticSettingsCategories/'
        for category in categories:
            name = get(category, 'name', str)
            if name.casefold() in seen or get(category, 'id', str).casefold() != (base + name).casefold(): return unknown
            seen.add(name.casefold())
            kind = get(category, 'categoryType', str)
            if kind == 'Logs':
                logs.add(name)
                groups = _category_groups(category)
                if groups is not None:
                    membership_known.add(name)
                    for group in groups:
                        group_members.setdefault(group, set()).add(name)
            elif kind != 'Metrics': return unknown
        if not CATEGORIES <= logs: return unknown
        diagnostics = get(account, 'serviceDiagnosticSettings', dict)
        status = get(get(get(diagnostics, '_coverage', dict), 'blob', dict), 'status')
        settings = get(diagnostics, 'blob', list)
        if (status not in ('empty', 'collected') or not isinstance(settings, list)
                or (status == 'empty') != (not settings) or len(settings) > 128): return unknown
        # Overapproximate possible configured logging. A configured category
        # does not prove delivery, but it prevents an absence finding for it.
        potentially_logged, setting_ids = set(), set()
        base = account_id + '/blobServices/default/providers/Microsoft.Insights/diagnosticSettings/'
        for setting in settings:
            setting = _object(setting)
            sid = get(setting, 'id', str)
            if (not isinstance(sid, str) or not sid.casefold().startswith(base.casefold())
                    or re.fullmatch(r'[^/?#%\\\s]+', sid[len(base):]) is None
                    or sid.casefold() in setting_ids): return unknown
            setting_ids.add(sid.casefold())
            entries = get(get(setting, 'properties', dict), 'logs', list)
            if not isinstance(entries, list) or len(entries) > 256: return unknown
            selectors = set()
            for entry in entries:
                entry = _object(entry)
                category, group = optional(entry, 'category', None), optional(entry, 'categoryGroup', None)
                enabled = get(entry, 'enabled', bool)
                if (type(entry.get('enabled')) is not bool
                        or (bool(category) == bool(group))
                        or (category is not None and category not in logs)
                        or (group is not None and group not in ('allLogs', 'audit'))): return unknown
                # Only the resource's complete native category membership can
                # establish what its audit group includes. allLogs retains its
                # documented universal meaning and the existing proof path.
                if group == 'audit' and (not CATEGORIES <= membership_known or not group_members.get('audit')):
                    return unknown
                selector = category or group
                if selector in selectors: return unknown
                selectors.add(selector)
                if enabled:
                    if group == 'allLogs':
                        potentially_logged.update(CATEGORIES)
                    elif group == 'audit':
                        potentially_logged.update(CATEGORIES & group_members['audit'])
                    else:
                        potentially_logged.add(category)
        analytics = get(account, 'serviceAnalyticsLogging', dict)
        if get(get(get(analytics, '_coverage', dict), 'blob', dict), 'status') != 'collected': return unknown
        state = get(analytics, 'blob', dict)
        if any(type(state.get(op)) is not bool for op in OPERATIONS): return unknown
        missing, unresolved = [], []
        for op in OPERATIONS:
            try:
                enabled = get(state, op, bool)
            except Unavailable:
                unresolved.append(op)
                continue
            if not enabled and 'Storage' + op.title() not in potentially_logged:
                missing.append(op)
        if not missing: return unknown
        return 'FAIL', {'audit_account_id': account_id, 'missing_blob_access_log_operations': missing,
            'unresolved_legacy_operations': unresolved,
            'semantics': 'Available native Blob diagnostics and legacy Analytics prove no configured logging for the listed operations; actual event delivery and sink security unassessed'}
    except (Unavailable, ValueError, TypeError, KeyError, AttributeError):
        return unknown
