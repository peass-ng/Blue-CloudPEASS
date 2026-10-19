"""Pure review of a selected Build's observed stored GCS log generation."""
from copy import deepcopy
import hashlib
import re
from types import SimpleNamespace

from peaso.collectors import gcp_cloudbuild_log_secret_indicators as source
from peaso.collectors import gcp_selected_object_secret_indicators as objects
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
