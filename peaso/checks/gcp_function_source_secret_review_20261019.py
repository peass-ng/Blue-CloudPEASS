"""Pure predicate for an observed Function's immutable resolved source archive.

No claim of deployed image equivalence, live revision contents or all code.
"""
from copy import deepcopy
from datetime import datetime
import re
from types import SimpleNamespace

from .facts import get, Unavailable
from . import gcp_selected_archive_secret_review_20261019 as archive_check
from peaso.collectors import gcp_selected_archive_secret_indicators as archives
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.collectors.gcp_function_source_secret_indicators import KIND, SCHEMA, MARKER, REFERENCE, _hash, native_source_receipts
from peaso.collectors.gcp_function_secret_indicators import _bound

CHECK_ID = 'gcp.review.function.resolved_source_archive_secret_indicators'
DECLARATION = {'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'dependencies': ['function', 'project', 'bucket', KIND],
    'requirements': [], 'title': 'Function resolved source archive has no detected secrets',
    'remediation': 'Remove credential literals from the function source archive and rotate confirmed exposed credentials. Use authorized runtime secret references instead of embedding credentials.',
    'evidence_sentences': ['A likely secret was detected in the function’s resolved source archive.',
        'The value is hidden; offline detection did not validate the credential or inspect deployed code.']}


def _envelope(index, kind, scope):
    rows = get(index, 'collections.' + kind, list)
    matching = [e for e in rows if isinstance(e, dict) and e.get('scope') == scope]
    if len(matching) != 1 or matching[0].get('status') != 'collected' or matching[0].get('coverage_status', 'collected') != 'collected':
        raise Unavailable('incomplete dependency')
    return matching[0]


def evaluate(item, index):
    try:
        scope = get(index, 'context.scope', str)
        if (get(index, 'context.provider', str) != 'gcp'
                or get(index, 'context.metadata.function_source_archive_authorized', bool) is not True):
            raise Unavailable('authorization')
        name = get(item, 'name', str)
        if not _bound(name, scope, '-', None):
            raise Unavailable('function identity')
        own = _envelope(index, KIND, scope)
        source = _envelope(index, 'function', scope)
        if item not in own['items'] or sum(r.get('name') == name for r in own['items']) != 1:
            raise Unavailable('foreign item')
        matching = [r for r in source['items'] if r.get('name') == name]
        if len(matching) != 1:
            raise Unavailable('function source')
        reference = get(item, REFERENCE, dict)
        if (set(reference) != {'schema', 'status', 'scope', 'function', 'relationship', 'archive_id',
                             'object_id', 'bucket_sha256', 'generation', 'format', 'function_update_time'}
                or reference != get(matching[0], REFERENCE, dict) or reference['schema'] != SCHEMA
                or reference['status'] != 'bound' or reference['scope'] != scope or reference['function'] != name
                or reference['relationship'] != 'buildConfig.sourceProvenance.resolvedStorageSource'
                or reference['format'] not in archives.MIME_TYPES
                or not re.fullmatch(r'gcs-selected-archive:[0-9a-f]{64}', reference['archive_id'])
                or not re.fullmatch(r'gcs-selected-object:[0-9a-f]{64}', reference['object_id'])
                or not re.fullmatch(r'[0-9a-f]{64}', reference['bucket_sha256'])
                or not objects._DECIMAL.fullmatch(reference['generation'])
                or int(reference['generation']) > 9223372036854775807):
            raise Unavailable('native resolved reference')
        if (get(matching[0], 'environment', str) != 'GEN_2' or get(matching[0], 'state', str) != 'ACTIVE'
                or get(matching[0], 'updateTime', str) != reference['function_update_time']):
            raise Unavailable('native function observation')
        updated = reference['function_update_time']
        if (not isinstance(updated, str) or not re.fullmatch(
                r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', updated)):
            raise Unavailable('native update time')
        datetime.fromisoformat(updated.replace('Z', '+00:00'))
        project, buckets = _envelope(index, 'project', scope), _envelope(index, 'bucket', scope)
        bound = [b for b in buckets['items'] if isinstance(b.get('name'), str)
                 and _hash(b['name']) == reference['bucket_sha256']]
        if len(bound) != 1:
            raise Unavailable('native bucket ownership')
        facade = SimpleNamespace(collections={('project', scope): project, ('bucket', scope): buckets})
        objects._bound_bucket(facade, scope, bound[0]['name'])
        marker = get(item, MARKER, dict)
        if (set(marker) != {'schema', 'complete', 'verification', 'source_requests', 'archive_source_requests', 'archive'}
                or marker['schema'] != SCHEMA or marker['complete'] is not True
                or marker['verification'] != 'not_attempted'):
            raise Unavailable('incomplete content')
        requests = get(index, 'context.metadata.source_requests', list)
        if len({r.get('id') for r in requests}) != len(requests):
            raise Unavailable('ambiguous request')
        by_id = {r['id']: r for r in requests}
        # Native ownership facts must also be attached to actual successful API reads.
        for envelope, endpoint in ((project, 'https://cloudresourcemanager.googleapis.com/v3/' + scope),
                                   (buckets, 'https://storage.googleapis.com/storage/v1/b')):
            candidates = [by_id.get(ref, {}) for ref in envelope['source_requests']]
            if not any(r.get('scope') == scope and r.get('status') == 'collected'
                       and r.get('http_status') == 200 and r.get('method') == 'GET'
                       and r.get('url') == endpoint
                       and (envelope is project or r.get('query', {}).get('project') == scope.split('/', 1)[1])
                       for r in candidates):
                raise Unavailable('ownership source receipt')
        refs = marker['source_requests']
        native_refs = native_source_receipts(matching[0]['_provenance']['source_requests'], requests, scope, name)
        if (not isinstance(refs, list) or not refs or len(set(refs)) != len(refs)
                or refs != native_refs or not set(refs) <= set(source['source_requests'])
                or not set(refs) <= set(own['source_requests'])):
            raise Unavailable('native source receipt')
        function_read = False
        for ref in refs:
            receipt = by_id[ref]
            if receipt.get('scope') != scope or receipt.get('status') != 'collected' or receipt.get('method') != 'GET':
                raise Unavailable('source receipt status')
            url = receipt.get('url', '')
            if re.fullmatch('https://cloudfunctions.googleapis.com/v2/' + re.escape(scope)
                            + r'/locations/(?:-|[a-z][a-z0-9-]{0,62})/functions', url) or url == 'https://cloudfunctions.googleapis.com/v2/' + name:
                if set(receipt.get('query', {})) - {'pageSize'}:
                    raise Unavailable('masked source')
                function_read = True
        if not function_read:
            raise Unavailable('native source read missing')
        archive_refs = marker['archive_source_requests']
        if not isinstance(archive_refs, list) or len(archive_refs) != 2 or len(set(archive_refs)) != 2:
            raise Unavailable('archive receipts')
        operations = set()
        for ref in archive_refs:
            receipt = by_id[ref]
            if (receipt.get('scope') != scope or receipt.get('method') != 'GET' or receipt.get('status') != 'collected'
                    or receipt.get('http_status') != 200 or receipt.get('resource_id') != reference['object_id']
                    or ref not in own['source_requests']):
                raise Unavailable('archive native read')
            operations.add(receipt.get('operation'))
        if operations != {'storage.objects.get.metadata', 'storage.objects.get.media'}:
            raise Unavailable('archive native operations')
        archive = marker['archive']
        if archive['name'] != reference['archive_id'] or archive[archives.MARKER]['format'] != reference['format']:
            raise Unavailable('wrong archive')
        outcome, evidence = archive_check.evaluate(archive, {'context': {'provider': 'gcp', 'scope': scope},
            'collections': {archives.KIND: [{'scope': scope, 'status': 'collected', 'items': [archive]}]}})
        if outcome not in ('PASS', 'FAIL'):
            raise Unavailable('archive assessment')
        evidence.update(function=name, resolved_archive=reference['archive_id'],
                        generation=reference['generation'], function_update_time=updated,
                        source_relationship=reference['relationship'], deployed_code_assessed=False)
        evidence['observed'] = (' '.join(DECLARATION['evidence_sentences']) if outcome == 'FAIL' else
            'Both offline detectors found no supported secret in the complete supported text of the function’s immutable resolved source archive. Deployed images, running revisions and runtime values were not assessed.')
        return outcome, evidence
    except (Unavailable, objects.Incomplete, KeyError, ValueError, TypeError, AttributeError):
        return 'UNKNOWN', {'observed': 'The function’s resolved source archive is unavailable, unbound, incomplete or unsupported; secret absence could not be assessed.'}


def install():
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    cases = json.loads(gzip.decompress(Path(__file__).with_name('gcp_function_source_secret_fixtures.json.gz').read_bytes()))
    register(CHECK_ID, 'gcp', 'hardening', KIND, DECLARATION['title'], 'high', 'security_configuration',
             DECLARATION['remediation'], dependencies=DECLARATION['dependencies'])(evaluate)
    CASES[CHECK_ID] = cases
