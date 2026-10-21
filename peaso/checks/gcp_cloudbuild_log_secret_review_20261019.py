"""Pure review of a selected Build's observed stored GCS log generation."""
from copy import deepcopy
import hashlib
import re
from types import SimpleNamespace

from peaso.collectors import gcp_cloudbuild_log_secret_indicators as source
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.collectors import gcp_cloudbuild_logging_entries as logging_entries
from peaso.secret_scanning import KINGFISHER_VERSION, TRUFFLEHOG_VERSION, merge_leaks
from . import gcp_selected_object_secret_review_20261019 as object_check

KIND, MARKER, SCHEMA = source.KIND, source.MARKER, source.SCHEMA
CHECK_ID = 'gcp.review.cloudbuild.stored_log_secret_indicators'
DECLARATION = {
    'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'requirements': [],
    'dependencies': ['project', 'bucket', KIND],
    'title': 'Observed Cloud Build stored log generation has no detected secrets',
    'remediation': 'Remove credential literals from build output, rotate confirmed exposed credentials, and use secret references with controlled log output.',
    'evidence_sentences': ['A likely secret was detected in an observed Cloud Build stored log generation.',
                           'The value is hidden; offline detection did not validate the credential.'],
}


def _envelope(index, kind, scope):
    rows = index['collections'][kind]
    matches = [e for e in rows if isinstance(e, dict) and e.get('scope') == scope]
    if (len(matches) != 1 or matches[0].get('status') != 'collected'
            or matches[0].get('coverage_status', 'collected') != 'collected'
            or not isinstance(matches[0].get('items'), list)):
        raise ValueError('incomplete native collection')
    return matches[0]


def evaluate(item, index):
    try:
        scope = index['context']['scope']
        if (index['context']['provider'] != 'gcp'
                or index['context']['metadata']['cloudbuild_log_source_authorized'] is not True):
            raise ValueError('authorization')
        own = _envelope(index, KIND, scope)
        marker = item[MARKER]
        if isinstance(marker, dict) and marker.get('mode') == 'cloud_logging_entries':
            return _evaluate_logging(item, index, own, marker, scope)
        if (set(marker) != {'schema', 'complete', 'scope', 'build_name', 'build', 'bucket_sha256',
                            'generation', 'object', 'native_requests', 'read_receipts',
                            'source_requests', 'reason', 'verification'}
                or marker['schema'] != SCHEMA or marker['scope'] != scope
                or marker['complete'] is not True or marker['reason'] != 'complete'
                or marker['verification'] != 'not_attempted'
                or not isinstance(marker['build_name'], str)
                or source.BUILD_NAME.fullmatch(marker['build_name']) is None
                or item['name'] != source.identity(marker['build_name'])
                or item not in own['items']
                or sum(r.get('name') == item['name'] for r in own['items']) != 1):
            raise ValueError('binding')
        project = _envelope(index, 'project', scope)
        buckets = _envelope(index, 'bucket', scope)
        if len(project['items']) != 1 or set(project['items'][0].get('_coverage', {})) & {'name', 'projectId', 'projectNumber', '*'}:
            raise ValueError('project')
        matching = [b for b in buckets['items'] if isinstance(b.get('name'), str)
                    and hashlib.sha256(b['name'].encode()).hexdigest() == marker['bucket_sha256']]
        if len(matching) != 1:
            raise ValueError('bucket')
        bucket = matching[0]
        if set(bucket.get('_coverage', {})) & {'name', 'projectNumber', '*'}:
            raise ValueError('bucket field coverage')
        facade = SimpleNamespace(collections={('project', scope): project, ('bucket', scope): buckets})
        objects._bound_bucket(facade, scope, bucket['name'])
        if '/'.join(marker['build_name'].split('/')[:2]) != scope:
            raise ValueError('scope')
        build = deepcopy(marker['build'])
        if 'logsBucket' in build:
            raise ValueError('raw bucket reference')
        build['logsBucket'] = 'gs://' + bucket['name']
        _, name = source.build_binding(build, marker['build_name'], project['items'][0])
        generation = marker['generation']
        if not isinstance(generation, str) or not objects._DECIMAL.fullmatch(generation):
            raise ValueError('generation')
        target = {'project_scope': scope, 'bucket': bucket['name'], 'object': name, 'generation': generation}
        selected = marker['object']
        if selected['name'] != objects.identity(target):
            raise ValueError('foreign object generation')
        refs, native, receipts = marker['source_requests'], marker['native_requests'], marker['read_receipts']
        if (not isinstance(refs, list) or len(refs) != 6 or len(set(refs)) != 6
                or any(not isinstance(r, str) or not re.fullmatch(r'request-[1-9][0-9]*', r) for r in refs)
                or not set(refs) <= set(own.get('source_requests', []))
                or not isinstance(native, list) or len(native) != 2 or len(set(native)) != 2
                or not isinstance(receipts, list) or len(receipts) != 4):
            raise ValueError('provenance')
        for row, env in ((project['items'][0], project), (bucket, buckets)):
            if len(set(native) & set(row.get('_provenance', {}).get('source_requests', []))
                   & set(env.get('source_requests', []))) != 1:
                raise ValueError('native source')
        expected = {('cloudbuild.builds.get.log_source', item['name']),
                    ('storage.objects.get.cloudbuild_log_generation', item['name']),
                    ('storage.objects.get.metadata', selected['name']),
                    ('storage.objects.get.media', selected['name'])}
        pairs, ids = set(), []
        for receipt in receipts:
            if (set(receipt) != {'id', 'scope', 'method', 'operation', 'resource_id', 'status', 'http_status'}
                    or receipt['scope'] != scope or receipt['method'] != 'GET'
                    or receipt['status'] != 'collected' or receipt['http_status'] != 200):
                raise ValueError('receipt')
            pairs.add((receipt['operation'], receipt['resource_id']))
            ids.append(receipt['id'])
        if (pairs != expected or len(set(ids)) != 4 or set(ids) & set(native)
                or set(refs) != set(ids) | set(native)):
            raise ValueError('receipt completeness')
        inner = {'context': index['context'], 'collections': {objects.KIND: [{
            'scope': scope, 'status': 'collected', 'items': [selected]}]}}
        status, evidence = object_check.evaluate(selected, inner)
        if status not in ('PASS', 'FAIL'):
            raise ValueError('incomplete content inspection')
        evidence.update(build_name=marker['build_name'], generation=generation,
            source_requests=list(refs), coverage='observed_object_generation_only',
            historical_build_log_completion='not_established')
        evidence['observed'] = (
            'A likely secret was detected in an observed Cloud Build stored log generation. The value is hidden; offline detection did not validate the credential.'
            if status == 'FAIL' else
            'Both offline detectors completed without detecting a supported secret in the observed stored log generation. This does not establish complete historical build log coverage.')
        return status, evidence
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, source.Incomplete):
        return 'UNKNOWN', {'observed': 'Cloud Build stored log inspection is disabled, unsupported, incomplete or unbound; secret absence could not be assessed.'}


def _evaluate_logging(item, index, own, marker, scope):
    try:
        required = {'schema', 'complete', 'scope', 'build_name', 'build', 'bucket_sha256',
                    'generation', 'object', 'native_requests', 'read_receipts',
                    'source_requests', 'reason', 'verification', 'mode', 'logging'}
        if (set(marker) != required or marker['schema'] != SCHEMA or marker['scope'] != scope
                or type(marker['complete']) is not bool
                or marker['verification'] != 'not_attempted' or marker['mode'] != 'cloud_logging_entries'
                or marker['bucket_sha256'] != '' or marker['generation'] != '' or marker['object'] != {}
                or not isinstance(marker['build_name'], str)
                or source.BUILD_NAME.fullmatch(marker['build_name']) is None
                or item['name'] != source.identity(marker['build_name']) or item not in own['items']
                or sum(r.get('name') == item['name'] for r in own['items']) != 1):
            raise ValueError('binding')
        project = _envelope(index, 'project', scope)
        if len(project['items']) != 1 or set(project['items'][0].get('_coverage', {})) & {'name', 'projectId', 'projectNumber', '*'}:
            raise ValueError('project')
        build = marker['build']
        source.logging_binding(build, marker['build_name'], project['items'][0])
        if '/'.join(marker['build_name'].split('/')[:2]) != scope:
            raise ValueError('scope')
        info = marker['logging']
        if (not isinstance(info, dict) or set(info) != {'schema', 'complete', 'reason', 'window_start', 'window_end',
                'entries', 'pages', 'bytes', 'engines', 'leaks', 'verification', 'filter_sha256'}
                or info['schema'] != logging_entries.SCHEMA or type(info['complete']) is not bool
                or marker['complete'] != info['complete'] or marker['reason'] != info['reason']
                or info['verification'] != 'not_attempted'
                or (info['complete'] and info['reason'] != 'complete')
                or (not info['complete'] and info['reason'] not in {
                    'logging_denied', 'logging_unavailable', 'logging_encoding_or_limit',
                    'logging_byte_limit', 'truncated_logging_response', 'malformed_logging_response',
                    'content_deadline', 'call_limit', 'detector_unavailable', 'logging_page_limit',
                    'metadata_denied', 'metadata_unavailable', 'metadata_encoding_or_limit',
                    'metadata_byte_limit', 'truncated_metadata'})
                or type(info['entries']) is not int or not 1 <= info['entries'] <= logging_entries.MAX_ENTRIES
                or type(info['pages']) is not int or not 1 <= info['pages'] <= logging_entries.MAX_PAGES
                or type(info['bytes']) is not int or not 0 <= info['bytes'] <= logging_entries.MAX_TOTAL_BYTES):
            raise ValueError('logging coverage')
        from datetime import timedelta
        lower = (source._time(build['createTime']) - timedelta(minutes=5)).isoformat().replace('+00:00', 'Z')
        upper = (source._time(build['finishTime']) + timedelta(minutes=5)).isoformat().replace('+00:00', 'Z')
        pid, bid = project['items'][0]['projectId'], build['id']
        log_name = 'projects/' + pid + '/logs/cloudbuild'
        literal = logging_entries._literal
        filt = ('resource.type="build" AND resource.labels.project_id=' + literal(pid)
                + ' AND resource.labels.build_id=' + literal(bid) + ' AND logName=' + literal(log_name)
                + ' AND timestamp>=' + literal(lower) + ' AND timestamp<=' + literal(upper))
        if (info['window_start'] != lower or info['window_end'] != upper
                or info['filter_sha256'] != hashlib.sha256(filt.encode()).hexdigest()):
            raise ValueError('window')
        refs, native, receipts = marker['source_requests'], marker['native_requests'], marker['read_receipts']
        if (not isinstance(refs, list) or not isinstance(native, list) or len(native) != 1
                or not isinstance(receipts, list)
                or len(refs) != len(receipts) + 1 or len(set(refs)) != len(refs)
                or set(refs) != set(native) | {r.get('id') for r in receipts}
                or not set(refs) <= set(own.get('source_requests', []))
                or not set(native) <= set(project['items'][0].get('_provenance', {}).get('source_requests', []))
                or not set(native) <= set(project.get('source_requests', []))):
            raise ValueError('provenance')
        expected = ([('GET', 'cloudbuild.builds.get.log_source')]
                    + [('POST', 'logging.entries.list.cloudbuild')] * info['pages'])
        if info['complete']:
            expected.append(('GET', 'cloudbuild.builds.get.log_source_after'))
        if len(receipts) not in (len(expected), len(expected) + (not info['complete'])):
            raise ValueError('receipt count')
        if info['complete'] and len(receipts) != len(expected):
            raise ValueError('receipt count')
        for receipt, (method, operation) in zip(receipts[:len(expected)], expected):
            if (set(receipt) != {'id', 'scope', 'method', 'operation', 'resource_id', 'status', 'http_status'}
                    or not re.fullmatch(r'request-[1-9][0-9]*', receipt['id'])
                    or receipt['scope'] != scope or receipt['method'] != method
                    or receipt['operation'] != operation or receipt['resource_id'] != item['name']
                    or receipt['status'] != 'collected' or receipt['http_status'] != 200):
                raise ValueError('receipt')
        if not info['complete'] and len(receipts) == len(expected) + 1:
            last = receipts[-1]
            postread = info['reason'].startswith('metadata_') or info['reason'] == 'truncated_metadata'
            if (not isinstance(last, dict) or not {'id', 'scope', 'method', 'operation', 'resource_id', 'status'} <= set(last)
                    or set(last) - {'id', 'scope', 'method', 'operation', 'resource_id', 'status', 'http_status'}
                    or not re.fullmatch(r'request-[1-9][0-9]*', last['id'])
                    or last['scope'] != scope or last['resource_id'] != item['name']
                    or last['method'] != ('GET' if postread else 'POST')
                    or last['operation'] != ('cloudbuild.builds.get.log_source_after' if postread
                                            else 'logging.entries.list.cloudbuild')
                    or last['status'] == 'collected'):
                raise ValueError('failed receipt')
            if (postread and info['reason'] not in {'metadata_denied', 'metadata_unavailable',
                    'metadata_encoding_or_limit', 'metadata_byte_limit', 'truncated_metadata'}
                    or not postread and info['reason'] not in {'logging_denied', 'logging_unavailable',
                    'logging_encoding_or_limit', 'logging_byte_limit', 'truncated_logging_response',
                    'malformed_logging_response'}
                    or info['reason'].endswith('_denied') and last.get('http_status') not in (401, 403)):
                raise ValueError('failure reason')
        elif not info['complete'] and info['reason'] in {'logging_denied', 'logging_unavailable',
                'logging_encoding_or_limit', 'truncated_logging_response', 'malformed_logging_response',
                'metadata_denied', 'metadata_unavailable', 'metadata_encoding_or_limit',
                'metadata_byte_limit', 'truncated_metadata'}:
            raise ValueError('missing failed receipt')
        if not info['complete'] and not info['leaks']:
            raise ValueError('partial negative')
        expected_engines = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        engines = info['engines']
        if (not isinstance(engines, list) or len(engines) != 2
                or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                       or e.get('engine') not in expected_engines or e.get('version') != expected_engines.get(e.get('engine'))
                       or e.get('status') not in ('complete', 'unavailable') for e in engines)
                or {e['engine'] for e in engines} != set(expected_engines)
                or info['complete'] and any(e['status'] != 'complete' for e in engines)
                or not any(e['status'] == 'complete' for e in engines)):
            raise ValueError('engines')
        if not isinstance(info['leaks'], list) or len(info['leaks']) > objects.MAX_LEAKS:
            raise ValueError('leaks')
        leaks = merge_leaks(info['leaks'])
        if (sum(len(x['locations']) for x in leaks) > objects.MAX_LOCATIONS
                or any(loc['path'] != 'logging.entry' or set(loc) - {'path', 'line'}
                       for leak in leaks for loc in leak['locations'])):
            raise ValueError('locations')
        complete_engines = {e['engine'] for e in engines if e['status'] == 'complete'}
        if any(d['engine'] not in complete_engines for leak in leaks for d in leak['detectors']):
            raise ValueError('unbound detector')
        status = 'FAIL' if leaks else 'PASS'
        return status, {'observed': (
            'The selected build\'s retrieved Cloud Logging entries contain a likely secret.\n'
            'A person with log access may use it.\n'
            'That could expose related data.\n'
            'The credential was not validated.'
            if leaks else
            'The selected build sent these entries to Cloud Logging in the recorded time window.\n'
            'Both offline detectors completed on the retrieved entries.\n'
            'No supported secret was found in those entries.\n'
            'Other entries and later activity remain unclear.'),
            'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
            'complete': info['complete'], 'bytes': info['bytes'], 'entries': info['entries'],
            'engines': deepcopy(engines), 'coverage': ('selected_build_logging_window_only' if info['complete']
                else 'observed_selected_build_entries_partial'),
            'source_requests': list(refs)}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, source.Incomplete):
        return 'UNKNOWN', {'observed': 'The selected build lacks a complete bound Cloud Logging window. Its log content and possible secret exposure remain unclear.'}


def install():
    """Explicit, idempotent installation; root owns catalog admission."""
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    register(CHECK_ID, 'gcp', 'hardening', KIND, DECLARATION['title'], 'high',
             'security_configuration', DECLARATION['remediation'],
             dependencies=DECLARATION['dependencies'])(evaluate)
    CASES[CHECK_ID] = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_cloudbuild_log_secret_review_20261019_fixtures.json.gz').read_bytes()))
