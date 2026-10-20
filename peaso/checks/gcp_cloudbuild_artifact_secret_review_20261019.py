"""Pure uninstalled consumer of bounded native produced-artifact receipts."""
from collections import Counter
from copy import deepcopy
import hashlib
import re
from types import SimpleNamespace

from peaso.collectors import gcp_cloudbuild_artifact_secret_indicators as source
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.collectors import gcp_selected_archive_secret_indicators as archives
from . import gcp_selected_object_secret_review_20261019 as object_check
from . import gcp_selected_archive_secret_review_20261019 as archive_check
from .gcp_cloudbuild_log_secret_review_20261019 import _envelope
from peaso.secret_scanning import merge_leaks

KIND, MARKER, SCHEMA = source.KIND, source.MARKER, source.SCHEMA
CHECK_ID = 'gcp.review.cloudbuild.artifact_secret_indicators'
DECLARATION = {'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'requirements': [],
    'dependencies': ['project', 'bucket', KIND],
    'title': 'Observed Cloud Build output artifacts have no detected secrets',
    'remediation': 'Remove exposed credentials from produced artifacts and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in an observed Cloud Build output artifact.',
                           'The value is hidden; offline detection did not validate the credential.']}


def _requests(value):
    if (not isinstance(value, list) or not value or len(value) > 64
            or any(not isinstance(r, str) or not re.fullmatch(r'request-[1-9][0-9]*', r) for r in value)
            or len(set(value)) != len(value)):
        raise ValueError('request identities')
    return set(value)


def _descriptor(row, extra=()):
    if (not isinstance(row, dict) or set(row) != {'identity', 'generation', 'bucket_sha256'} | set(extra)
            or not isinstance(row['identity'], str) or not re.fullmatch(r'gcs-selected-object:[0-9a-f]{64}', row['identity'])
            or not isinstance(row['bucket_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', row['bucket_sha256'])
            or not isinstance(row['generation'], str) or not objects._DECIMAL.fullmatch(row['generation'])
            or int(row['generation']) > 9223372036854775807):
        raise ValueError('descriptor')


def evaluate(item, index):
    try:
        scope = index['context']['scope']
        if (index['context']['provider'] != 'gcp' or not isinstance(scope, str)
                or not objects._SCOPE.fullmatch(scope)
                or index['context']['metadata']['cloudbuild_artifact_source_authorized'] is not True):
            raise ValueError('authorization')
        own, project, buckets = (_envelope(index, k, scope) for k in (KIND, 'project', 'bucket'))
        m = item[MARKER]
        if (set(m) != {'schema', 'scope', 'build_name', 'build', 'manifest', 'artifacts', 'complete', 'reason',
                       'native_requests', 'read_receipts', 'source_requests', 'verification', 'coverage', 'historical_build_bytes'}
                or m['schema'] != SCHEMA or m['scope'] != scope or m['complete'] is not True
                or m['reason'] != 'complete' or m['verification'] != 'not_attempted'
                or m['coverage'] != 'observed_manifest_generations_only' or m['historical_build_bytes'] != 'not_established'
                or not isinstance(m['build_name'], str) or not source.BUILD_NAME.fullmatch(m['build_name'])
                or '/'.join(m['build_name'].split('/')[:2]) != scope
                or item['name'] != source.identity(m['build_name']) or item not in own['items']
                or sum(isinstance(r, dict) and r.get('name') == item['name'] for r in own['items']) != 1
                or len(project['items']) != 1 or not isinstance(project['items'][0], dict)):
            raise ValueError('source binding')
        refs, native = _requests(m['source_requests']), _requests(m['native_requests'])
        coverage = item['_coverage'][MARKER]
        if (coverage['status'] != 'collected' or _requests(coverage['source_requests']) != refs
                or not refs <= _requests(own['source_requests'])
                or not refs <= _requests(item['_provenance']['source_requests'])):
            raise ValueError('source provenance')
        descriptors = [m['manifest']] + m['artifacts'] if isinstance(m['artifacts'], list) else []
        if not 2 <= len(descriptors) <= source.MAX_ARTIFACTS + 1:
            raise ValueError('artifact count')
        _descriptor(descriptors[0])
        for d in descriptors[1:]:
            _descriptor(d, ('format', 'selected', 'reader_identity'))
        if len({d['identity'] for d in descriptors}) != len(descriptors):
            raise ValueError('ambiguous targets')
        facade = SimpleNamespace(collections={('project', scope): project, ('bucket', scope): buckets})
        bound, native_rows = {}, [project['items'][0]]
        for d in descriptors:
            matches = [b for b in buckets['items'] if isinstance(b, dict) and isinstance(b.get('name'), str)
                       and hashlib.sha256(b['name'].encode()).hexdigest() == d['bucket_sha256']]
            if len(matches) != 1:
                raise ValueError('bucket binding')
            bucket = matches[0]
            objects._bound_bucket(facade, scope, bucket['name'])
            bound[d['identity']] = bucket
            if bucket not in native_rows:
                native_rows.append(bucket)
        native_observed = set()
        for row in native_rows:
            if set(row.get('_coverage', {})) & {'name', 'projectId', 'projectNumber', '*'}:
                raise ValueError('native coverage')
            env = project if row is project['items'][0] else buckets
            intersection = native & _requests(row['_provenance']['source_requests']) & _requests(env['source_requests'])
            if len(intersection) != 1:
                raise ValueError('native provenance')
            native_observed |= intersection
        if native_observed != native:
            raise ValueError('extra native receipt')
        # Revalidate the persisted native Build identity and terminal times;
        # its content-bearing pointer is omitted from persisted evidence.
        if not isinstance(m['build'], dict) or 'results' in m['build']:
            raise ValueError('build summary')
        build = {**m['build'], 'results': {'artifactManifest': 'gs://' + bound[descriptors[0]['identity']]['name'] + '/manifest'}}
        source.build_binding(build, m['build_name'], project['items'][0])
        expected = Counter({('cloudbuild.builds.get.artifact_source', item['name']): 1,
            ('storage.objects.get.cloudbuild_manifest_generation', item['name']): 1,
            ('storage.objects.get.media', descriptors[0]['identity']): 1})
        statuses, content_evidence, combined_leaks = [], [], []
        for artifact in m['artifacts']:
            fmt, selected = artifact['format'], artifact['selected']
            if fmt != 'utf8' and fmt not in archives.MIME_TYPES:
                raise ValueError('unsupported artifact type')
            reader, check = (objects, object_check) if fmt == 'utf8' else (archives, archive_check)
            if (not isinstance(artifact['reader_identity'], str) or selected['name'] != artifact['reader_identity']
                    or fmt == 'utf8' and selected['name'] != artifact['identity']
                    or fmt != 'utf8' and selected[archives.MARKER]['format'] != fmt):
                raise ValueError('selected source identity')
            inner = {'context': index['context'], 'collections': {reader.KIND: [{
                'scope': scope, 'status': 'collected', 'items': [selected]}]}}
            status, evidence = check.evaluate(selected, inner)
            if status not in ('PASS', 'FAIL'):
                raise ValueError('incomplete artifact')
            statuses.append(status)
            for leak in deepcopy(evidence['secret_leaks']):
                for loc in leak['locations']:
                    loc['path'] = 'artifact.' + artifact['identity'].split(':')[1] + '/' + loc['path']
                combined_leaks.append(leak)
            content_evidence.append({'identity': artifact['identity'], 'generation': artifact['generation'],
                                     'format': fmt, 'inspection': {k: v for k, v in evidence.items() if k != 'observed'}})
            for operation in ('storage.objects.get.cloudbuild_artifact_type', 'storage.objects.get.metadata', 'storage.objects.get.media'):
                expected[(operation, artifact['identity'])] += 1
        receipts, observed, ids = m['read_receipts'], Counter(), set()
        if not isinstance(receipts, list) or len(receipts) != 3 + 3 * len(m['artifacts']):
            raise ValueError('receipt count')
        for receipt in receipts:
            binding = None
            if isinstance(receipt, dict):
                if receipt.get('operation') == 'storage.objects.get.cloudbuild_manifest_generation' or receipt.get('resource_id') == descriptors[0]['identity']:
                    binding = descriptors[0]
                elif receipt.get('resource_id') in {d['identity'] for d in descriptors[1:]}:
                    d = next(d for d in descriptors[1:] if d['identity'] == receipt['resource_id'])
                    binding = {k: d[k] for k in ('identity', 'generation', 'bucket_sha256', 'reader_identity')}
            if (not isinstance(receipt, dict) or set(receipt) != {'id', 'scope', 'method', 'operation', 'resource_id', 'status', 'http_status'} | ({'binding'} if binding else set())
                    or binding is not None and receipt.get('binding') != binding
                    or receipt['scope'] != scope or receipt['method'] != 'GET'
                    or receipt['status'] != 'collected' or type(receipt['http_status']) is not int or receipt['http_status'] != 200):
                raise ValueError('receipt')
            rid, = _requests([receipt['id']])
            if rid in ids or rid in native:
                raise ValueError('duplicate receipt')
            ids.add(rid)
            observed[(receipt['operation'], receipt['resource_id'])] += 1
        if observed != expected or refs != native | ids:
            raise ValueError('receipt completeness')
        leaks = merge_leaks(combined_leaks)
        if len(leaks) > objects.MAX_LEAKS or sum(len(l['locations']) for l in leaks) > objects.MAX_LOCATIONS:
            raise ValueError('aggregate finding limit')
        status = 'FAIL' if 'FAIL' in statuses else 'PASS'
        evidence = {'secret_leaks': leaks, 'artifacts': deepcopy(content_evidence), 'source_requests': sorted(refs),
            'coverage': m['coverage'], 'historical_build_bytes': 'not_established', 'credential_validation': 'not_attempted'}
        evidence['observed'] = ('A likely secret was detected in an observed Cloud Build output artifact. The value is hidden; offline detection did not validate the credential.'
            if status == 'FAIL' else 'Both offline detectors completed on every supported artifact in the observed manifest without detecting a supported secret. Historical build bytes and artifacts outside this manifest were not established.')
        return status, evidence
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, source.Incomplete):
        return 'UNKNOWN', {'observed': 'Cloud Build artifact inspection is disabled, unsupported, incomplete or unbound; secret absence could not be assessed.'}


def install():
    """Explicit idempotent installation; root owns admission and planner hooks."""
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    fixture = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_cloudbuild_artifact_secret_review_20261019_fixtures.json.gz').read_bytes()))
    register(CHECK_ID, 'gcp', 'hardening', KIND, DECLARATION['title'], 'high', 'security_configuration',
             DECLARATION['remediation'], dependencies=DECLARATION['dependencies'])(evaluate)
    CASES[CHECK_ID] = fixture
