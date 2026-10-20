"""Uninstalled consumer for selected Release source observations, not deployment proof."""
from copy import deepcopy
import re
from types import SimpleNamespace

from peaso.collectors import gcp_clouddeploy_source_secret_indicators as source
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.collectors import gcp_selected_archive_secret_indicators as archives
from . import gcp_selected_archive_secret_review_20261019 as archive_check
from .gcp_cloudbuild_log_secret_review_20261019 import _envelope

KIND, MARKER, SCHEMA = source.KIND, source.MARKER, source.SCHEMA
CHECK_ID = 'gcp.review.clouddeploy.release_source_secret_indicators'
DECLARATION = {'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'requirements': [],
    'dependencies': ['project', 'bucket', KIND],
    'title': 'Observed Cloud Deploy release source archive has no detected secrets',
    'remediation': 'Remove credential literals from release source configuration and rotate confirmed exposed credentials. Use controlled secret references.',
    'evidence_sentences': ['A likely secret was detected in an observed Cloud Deploy release source archive.',
        'The value is hidden; offline detection did not validate credentials or establish historical release bytes.']}


def evaluate(item, index):
    try:
        context = index['context']
        scope, metadata = context['scope'], context['metadata']
        if (context['provider'] != 'gcp' or metadata['clouddeploy_release_source_authorized'] is not True
                or item['name'] not in metadata['selected_clouddeploy_release_ids']):
            raise ValueError('authorization')
        own = _envelope(index, KIND, scope)
        marker = item[MARKER]
        if (set(marker) != {'schema', 'complete', 'scope', 'release_name', 'binding', 'archive',
                            'native_requests', 'read_receipts', 'source_requests', 'reason', 'verification'}
                or marker['schema'] != SCHEMA or marker['scope'] != scope
                or marker['complete'] is not True or marker['reason'] != 'complete'
                or marker['verification'] != 'not_attempted'
                or not source.RELEASE_NAME.fullmatch(marker['release_name'])
                or '/'.join(marker['release_name'].split('/')[:2]) != scope
                or source.identity(marker['release_name']) != item['name']
                or item not in own['items'] or sum(r.get('name') == item['name'] for r in own['items']) != 1
                or item['_coverage'][MARKER]['status'] != 'collected'):
            raise ValueError('source binding')
        binding = marker['binding']
        if (set(binding) != {'bucket_sha256', 'object_sha256', 'generation', 'object_id', 'archive_id',
                             'format', 'relationship', 'coverage'}
                or binding['format'] != 'tar.gz' or binding['relationship'] != 'skaffoldConfigUri'
                or binding['coverage'] != 'observed_object_generation_only'
                or not objects._DECIMAL.fullmatch(binding['generation'])
                or not re.fullmatch(r'gcs-selected-object:[0-9a-f]{64}', binding['object_id'])
                or not re.fullmatch(r'gcs-selected-archive:[0-9a-f]{64}', binding['archive_id'])
                or any(not re.fullmatch(r'[0-9a-f]{64}', binding[k]) for k in ('bucket_sha256', 'object_sha256'))):
            raise ValueError('generation binding')
        project, buckets = _envelope(index, 'project', scope), _envelope(index, 'bucket', scope)
        matching = [b for b in buckets['items'] if isinstance(b.get('name'), str)
                    and source.digest(b['name']) == binding['bucket_sha256']]
        if len(matching) != 1 or len(project['items']) != 1:
            raise ValueError('ownership')
        bucket, project_row = matching[0], project['items'][0]
        if (set(bucket.get('_coverage', {})) & {'name', 'projectNumber', '*'}
                or set(project_row.get('_coverage', {})) & {'name', 'projectId', 'projectNumber', '*'}):
            raise ValueError('partial ownership')
        objects._bound_bucket(SimpleNamespace(collections={('project', scope): project, ('bucket', scope): buckets}), scope, bucket['name'])
        evidence_rows = metadata['source_requests']
        by_id = {r['id']: r for r in evidence_rows}
        if len(by_id) != len(evidence_rows):
            raise ValueError('duplicate receipts')
        refs, native, receipts = marker['source_requests'], marker['native_requests'], marker['read_receipts']
        if (not isinstance(refs, list) or len(refs) != 6 or len(set(refs)) != 6
                or not set(refs) <= set(own['source_requests'])
                or not set(refs) <= set(item['_coverage'][MARKER]['source_requests'])
                or len(native) != 2 or len(set(native)) != 2 or len(receipts) != 4):
            raise ValueError('missing receipts')
        for env, row, endpoint in ((project, project_row, 'https://cloudresourcemanager.googleapis.com/v3/' + scope),
                                  (buckets, bucket, 'https://storage.googleapis.com/storage/v1/b')):
            ids = set(native) & set(env['source_requests']) & set(row['_provenance']['source_requests'])
            if len(ids) != 1:
                raise ValueError('ownership provenance')
            receipt = by_id[ids.pop()]
            if (receipt.get('url') != endpoint or receipt.get('method') != 'GET'
                    or receipt.get('scope') != scope or receipt.get('status') != 'collected'
                    or receipt.get('http_status') != 200 or receipt.get('query', {}).get('fields')
                    or env is buckets and (receipt.get('query', {}).get('project') != scope.split('/')[1]
                                           or receipt.get('query', {}).get('projection') != 'full')):
                raise ValueError('ownership request')
        expected = {('clouddeploy.releases.get.source', item['name']),
                    ('storage.objects.get.clouddeploy_source_generation', item['name']),
                    ('storage.objects.get.metadata', binding['object_id']),
                    ('storage.objects.get.media', binding['object_id'])}
        pairs, ids = set(), []
        for receipt in receipts:
            if (receipt != by_id.get(receipt['id']) or receipt.get('scope') != scope
                    or receipt.get('method') != 'GET' or receipt.get('status') != 'collected'
                    or receipt.get('http_status') != 200 or 'url' in receipt):
                raise ValueError('content provenance')
            if receipt['operation'] in ('clouddeploy.releases.get.source', 'storage.objects.get.clouddeploy_source_generation') and receipt.get('binding') != binding:
                raise ValueError('native binding contradiction')
            pairs.add((receipt['operation'], receipt['resource_id']))
            ids.append(receipt['id'])
        if pairs != expected or len(set(ids)) != 4 or set(ids) & set(native) or set(refs) != set(ids) | set(native):
            raise ValueError('incomplete source receipts')
        archive = marker['archive']
        if archive['name'] != binding['archive_id'] or archive[archives.MARKER]['format'] != binding['format']:
            raise ValueError('foreign archive')
        status, evidence = archive_check.evaluate(archive, {'context': context, 'collections': {archives.KIND: [{
            'scope': scope, 'status': 'collected', 'items': [archive]}]}})
        if status not in ('PASS', 'FAIL'):
            raise ValueError('detectors incomplete')
        evidence.update(release_name=marker['release_name'], generation=binding['generation'],
                        coverage=binding['coverage'], historical_release_bytes='not_established',
                        source_requests=list(refs))
        evidence['observed'] = (' '.join(DECLARATION['evidence_sentences']) if status == 'FAIL' else
            'Both offline detectors found no supported secret in the complete supported text of the observed release source archive. Historical release bytes and deployed configuration were not established.')
        return status, evidence
    except (KeyError, TypeError, ValueError, AttributeError, objects.Incomplete):
        return 'UNKNOWN', {'observed': 'Cloud Deploy release source inspection is disabled, unsupported, incomplete or unbound; secret absence could not be assessed.'}


def install():
    """Explicit idempotent installation; shared admission belongs to the coordinator."""
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    cases = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_clouddeploy_source_secret_review_20261019_fixtures.json.gz').read_bytes()))
    register(CHECK_ID, 'gcp', 'hardening', KIND, DECLARATION['title'], 'high',
             'security_configuration', DECLARATION['remediation'], dependencies=DECLARATION['dependencies'])(evaluate)
    CASES[CHECK_ID] = cases
