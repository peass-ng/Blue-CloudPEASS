"""Functions v2 resolved archive references -> audited selected GCS archive reader.

Root must call capture_response before caching the original successful response,
then collection_pages only after native function/project/bucket jobs complete.
Opaque projections are persistent; raw object targets live only in a bounded,
private pending plan and are consumed/cleared by the dependent job.
"""
from copy import deepcopy
from datetime import datetime
import hashlib
import re
import time
import threading
from types import SimpleNamespace

from . import gcp_selected_archive_secret_indicators as archives
from . import gcp_selected_object_secret_indicators as objects
from .gcp_function_secret_indicators import _request, _bound

KIND = 'function_source_archive'
SCHEMA = 'gcp-function-source-archive-secrets-v1'
REFERENCE = 'FunctionSourceArchiveReference'
MARKER = 'FunctionSourceArchiveSecretIndicators'
MAX_FUNCTIONS = 10
MAX_PLAN_BYTES = 32768
MAX_SECONDS = 30


def enabled(options):
    kinds = options.get('_content_secret_scan_kinds')
    return options.get('content_secret_scans') is True and isinstance(kinds, list) and KIND in kinds


def selection_metadata(collector):
    return {'function_source_archive_authorized': enabled(collector.options)}


def _hash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _target(row, scope):
    """Never substitute a mutable reference, URL, repo or inferred package age."""
    if (not isinstance(row, dict) or not _bound(row.get('name'), scope, '-', None)
            or row.get('_coverage') or row.get('collection_status', 'collected') != 'collected'
            or row.get('environment') != 'GEN_2' or row.get('state') != 'ACTIVE'):
        raise ValueError('native function unavailable')
    updated = row['updateTime']
    if (not isinstance(updated, str) or not re.fullmatch(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', updated)):
        raise ValueError('native update time')
    datetime.fromisoformat(updated.replace('Z', '+00:00'))
    build = row['buildConfig']
    if not isinstance(build, dict) or build.get('_coverage'):
        raise ValueError('native build unavailable')
    source, provenance = build['source'], build['sourceProvenance']
    if (not isinstance(source, dict) or set(source) != {'storageSource'}
            or not isinstance(provenance, dict) or set(provenance) != {'resolvedStorageSource'}):
        raise ValueError('only resolved storage source supported')
    configured, resolved = source['storageSource'], provenance['resolvedStorageSource']
    if (not isinstance(configured, dict) or not isinstance(resolved, dict)
            or set(configured) - {'bucket', 'object', 'generation'}
            or set(resolved) != {'bucket', 'object', 'generation'}
            or configured.get('bucket') != resolved['bucket'] or configured.get('object') != resolved['object']
            or 'generation' in configured and configured['generation'] not in ('0', resolved['generation'])):
        raise ValueError('source and provenance mismatch')
    target = {'project_scope': scope, **resolved}
    objects.selected_targets({'content_secret_scans': True, '_content_secret_scan_kinds': [objects.KIND],
                              objects.OPTION: [target]}, [scope])
    if int(target['generation']) > 9223372036854775807:
        raise ValueError('native int64 generation')
    name = target['object'].lower()
    format_name = next((f for suffix, f in (('.tar.gz', 'tar.gz'), ('.tgz', 'tar.gz'),
                       ('.zip', 'zip'), ('.tar', 'tar')) if name.endswith(suffix)), None)
    if format_name is None:
        raise ValueError('unsupported referenced archive')
    target['format'] = format_name
    return target


def _reference(row, scope, target):
    return {'schema': SCHEMA, 'status': 'bound', 'scope': scope, 'function': row['name'],
            'relationship': 'buildConfig.sourceProvenance.resolvedStorageSource',
            'archive_id': archives.identity(target),
            'object_id': objects.identity({k: v for k, v in target.items() if k != 'format'}),
            'bucket_sha256': _hash(target['bucket']), 'generation': target['generation'],
            'format': target['format'], 'function_update_time': row['updateTime']}


def _safe_source_projection(response, scope):
    """Omit native source alternatives even when optional source planning fails."""
    from peaso.secret_scanning import omit_free_text_metadata
    safe = deepcopy(response)
    if isinstance(safe, dict):
        rows = safe.get('functions') if 'functions' in safe else [safe]
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                row.pop(REFERENCE, None)
                row.pop(MARKER, None)
                row[REFERENCE] = {'schema': SCHEMA, 'status': 'incomplete', 'scope': scope,
                                  'function': row.get('name')}
                if isinstance(row.get('buildConfig'), dict):
                    build = row['buildConfig']
                    for field in ('source', 'sourceProvenance'):
                        if field in build:
                            build.pop(field)
                            coverage = build.setdefault('_coverage', {})
                            if isinstance(coverage, dict):
                                coverage[field] = {'status': 'unknown', 'reason': 'function_source_reference_not_retained'}
    return omit_free_text_metadata(safe)


def capture_response(transport, response, *, method, url, scope, params=None, body=None):
    """Pre-cache source projection; optional source limits never poison metadata.

    Valid ordinary native inventory/environment projection keeps working even if
    this optional bounded source plan is incomplete. No content or tool calls.
    """
    if not enabled(transport.options):
        return response
    safe = _safe_source_projection(response, scope)
    try:
        location, function = _request(method, url, scope, params, body)
        if not isinstance(response, dict):
            raise ValueError('native response')
        rows = response.get('functions') if 'functions' in response else [response]
        if not isinstance(rows, list):
            raise ValueError('native rows')
        with transport.lock:
            if not hasattr(transport, '_function_source_pending'):
                transport._function_source_pending = {'started': time.monotonic(), 'bytes': 0,
                                                      'rows': {}, 'count': 0, 'blocked': False}
            state = transport._function_source_pending
            transport.check_cancelled()
            safe_rows = safe.get('functions') if 'functions' in safe else [safe]
            if (time.monotonic() - state['started'] >= MAX_SECONDS
                    or len(rows) > MAX_FUNCTIONS or state['count'] + len(rows) > MAX_FUNCTIONS):
                state['rows'].clear()
                state['blocked'] = True
            if state['blocked']:
                return safe
            for raw, projected in zip(rows, safe_rows):
                if not isinstance(raw, dict) or not _bound(raw.get('name'), scope, location, function):
                    state['rows'].clear()
                    state['blocked'] = True
                    return _safe_source_projection(response, scope)
                name = raw['name']
                if (scope, name) in state['rows']:
                    state['rows'].clear()
                    state['blocked'] = True
                    return _safe_source_projection(response, scope)
                state['count'] += 1
                reference = projected[REFERENCE]
                target = None
                try:
                    if response.get('unreachable') or response.get('unreachables') or response.get('warning'):
                        raise ValueError('partial response')
                    target = _target(raw, scope)
                    state['bytes'] += sum(len(str(v).encode('utf-8')) for v in target.values())
                    if state['bytes'] > MAX_PLAN_BYTES:
                        raise ValueError('source plan bytes')
                    reference = _reference(raw, scope, target)
                except Exception:
                    target = None
                state['rows'][(scope, name)] = {'target': target, 'reference': deepcopy(reference)}
                projected[REFERENCE] = reference
            return safe
    except Exception:
        clear_pending(transport)
        return safe


def clear_pending(transport):
    """Root teardown hook: discard sensitive private plan even before dependency jobs."""
    if getattr(transport, '_function_source_pending', None) is None:
        return
    with transport.lock:
        state = getattr(transport, '_function_source_pending', None)
        if state is not None:
            state['rows'].clear()
            delattr(transport, '_function_source_pending')


def native_source_receipts(refs, evidence, scope, name):
    by_id = {r.get('id'): r for r in evidence}
    valid = []
    for ref in refs:
        receipt = by_id.get(ref, {})
        url = receipt.get('url', '')
        if (receipt.get('scope') == scope and receipt.get('method') == 'GET'
                and receipt.get('status') == 'collected' and receipt.get('http_status') == 200
                and (re.fullmatch('https://cloudfunctions.googleapis.com/v2/' + re.escape(scope)
                     + r'/locations/(?:-|[a-z][a-z0-9-]{0,62})/functions', url)
                     or url == 'https://cloudfunctions.googleapis.com/v2/' + name)
                and not set(receipt.get('query', {})) - {'pageSize'}):
            valid.append(ref)
    return valid


def _source(collector, scope):
    env = collector.collections.get(('function', scope), {})
    rows = env.get('items')
    if (env.get('coverage_status') != 'collected' or not isinstance(rows, list)
            or not 1 <= len(rows) <= MAX_FUNCTIONS
            or any(not isinstance(r, dict) or not _bound(r.get('name'), scope, '-', None) for r in rows)
            or len({r['name'] for r in rows}) != len(rows)):
        raise ValueError('incomplete source collection')
    return rows


def collection_pages(collector, scope):
    """Trusted, private selection facade; never changes caller options or kinds."""
    if not enabled(collector.options):
        return
    transport = collector.transport
    pending = {}
    try:
        with transport.lock:
            state = getattr(transport, '_function_source_pending', None)
            if state is not None:
                pending = {name: state['rows'].pop((s, name)) for s, name in list(state['rows']) if s == scope}
                if time.monotonic() - state['started'] >= MAX_SECONDS:
                    pending = {}
                if not state['rows']:
                    delattr(transport, '_function_source_pending')
        source_rows = _source(collector, scope)
        if state is not None:
            # Same state/lock and counters as selected text/archive inventories.
            with transport.lock:
                if not hasattr(transport, '_selected_object_secret_state'):
                    transport._selected_object_secret_state = {'started': state['started'], 'bytes': 0,
                        'calls': 0, 'lock': threading.Lock(), 'items': {}}
                else:
                    transport._selected_object_secret_state['started'] = min(
                        transport._selected_object_secret_state['started'], state['started'])
        for function in source_rows:
            name = function['name']
            reference = function.get(REFERENCE, {})
            refs = native_source_receipts(function.get('_provenance', {}).get('source_requests', []),
                transport.evidence, scope, name)
            marker = {'schema': SCHEMA, 'complete': False, 'verification': 'not_attempted',
                      'source_requests': refs, 'archive_source_requests': [], 'archive': {}}
            row = {'name': name, REFERENCE: deepcopy(reference), MARKER: marker}
            plan = pending.pop(name, None)
            try:
                transport.check_cancelled()
                if (plan is None or plan['target'] is None or reference != plan['reference']
                        or reference.get('status') != 'bound' or not refs
                        or function.get('_coverage', {}).get(REFERENCE, {}).get('status', 'collected') != 'collected'):
                    raise ValueError('source relationship unavailable')
                # Validate native ownership before creating a privately authorized selection.
                objects._bound_bucket(collector, scope, plan['target']['bucket'])
                facade = SimpleNamespace(options={'content_secret_scans': True,
                    '_content_secret_scan_kinds': [archives.KIND], archives.OPTION: [plan['target']]},
                    scopes=[scope], transport=transport, collections=collector.collections)
                archive_rows, archive_refs = [], []
                for page, request_id in archives.collection_pages(facade, scope):
                    archive_rows.extend(page)
                    archive_refs.append(request_id)
                archive, = archive_rows
                if archive['name'] != reference['archive_id']:
                    raise ValueError('archive relationship')
                marker.update(archive=archive, archive_source_requests=sorted(set(archive_refs)),
                              complete=archive[archives.MARKER]['complete'] is True)
            except Exception:
                marker['complete'] = False
            all_refs = sorted(set(refs + marker['archive_source_requests']))
            row['_coverage'] = {MARKER: {'status': 'collected' if marker['complete'] else 'unknown',
                                         'source_requests': all_refs}}
            for request_id in all_refs[:-1]:
                yield [], request_id
            yield [row], all_refs[-1] if all_refs else 'local:function_source_unavailable'
    except Exception:
        # Let the normal native envelope encode static UNKNOWN collection coverage.
        from .gcp import ReadError
        raise ReadError('unavailable', 'function_source_collection_unavailable') from None
    finally:
        pending.clear()  # Never retain raw object targets after this dependent job.
