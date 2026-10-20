"""Pure, opt-in consumer of complete hash-bound deployment.files observations."""
from copy import deepcopy
import hashlib
import re
from types import SimpleNamespace

from peaso.collectors import gcp_appengine_source_secret_indicators as source
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from . import gcp_selected_object_secret_review_20261019 as object_check
from .gcp_cloudbuild_log_secret_review_20261019 import _envelope

KIND, SCHEMA, MARKER = source.KIND, source.SCHEMA, source.MARKER
CHECK_ID = 'gcp.review.appengine.deployment_source_secret_indicators'
DECLARATION = {'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'requirements': [],
    'dependencies': ['project', 'bucket', KIND],
    'title': 'Selected App Engine deployment source files have no detected secrets',
    'remediation': 'Remove credential literals from deployment source files and rotate confirmed exposed credentials. Use runtime secret references instead.',
    'evidence_sentences': ['A likely secret was detected in hash-matched App Engine deployment source.',
                           'The value is hidden; offline detection did not validate the credential.']}


def evaluate(item, index):
    try:
        scope = index['context']['scope']
        if (index['context']['provider'] != 'gcp'
                or index['context']['metadata']['appengine_deployment_source_authorized'] is not True):
            raise ValueError('authorization')
        own = _envelope(index, KIND, scope)
        marker = item[MARKER]
        name = marker['version_name']
        m = source.VERSION_NAME.fullmatch(name)
        if (m is None or item['name'] != source.identity(name) or item not in own['items']
                or sum(r.get('name') == item['name'] for r in own['items']) != 1
                or set(marker) != {'schema', 'scope', 'version_name', 'complete', 'verification', 'files',
                    'manifest_count', 'native_requests', 'read_receipts', 'source_requests', 'reason'}
                or marker['schema'] != SCHEMA or marker['scope'] != scope or marker['complete'] is not True
                or marker['verification'] != 'not_attempted' or marker['reason'] != 'complete'
                or type(marker['manifest_count']) is not int or not 1 <= marker['manifest_count'] <= source.MAX_FILES
                or not isinstance(marker['files'], list) or len(marker['files']) != marker['manifest_count']):
            raise ValueError('manifest completeness')
        source.selected_versions({'content_secret_scans': True, '_content_secret_scan_kinds': [KIND], source.OPTION: [name]}, [scope])
        project, buckets = _envelope(index, 'project', scope), _envelope(index, 'bucket', scope)
        if (len(project['items']) != 1 or project['items'][0].get('projectId') != m[1]
                or set(project['items'][0].get('_coverage', {})) & {'name', 'projectId', 'projectNumber', '*'}):
            raise ValueError('project')
        native, receipts, refs = marker['native_requests'], marker['read_receipts'], marker['source_requests']
        if (not isinstance(native, list) or not native or len(set(native)) != len(native)
                or not isinstance(refs, list) or len(set(refs)) != len(refs)
                or any(not isinstance(r, str) or not re.fullmatch(r'request-[1-9][0-9]*', r) for r in refs)
                or not set(refs) <= set(own.get('source_requests', []))
                or not isinstance(receipts, list) or len(receipts) != 2 + 3 * len(marker['files'])):
            raise ValueError('provenance')
        used_native = set()
        def native_binding(row, env):
            attached = set(native) & set(row.get('_provenance', {}).get('source_requests', [])) & set(env.get('source_requests', []))
            if not attached:
                raise ValueError('native source ownership')
            used_native.update(attached)
        native_binding(project['items'][0], project)
        expected = [('appengine.apps.get.source', item['name']), ('appengine.versions.get.source', item['name'])]
        outcomes, evidence_rows, object_ids, total = [], [], set(), 0
        for file in marker['files']:
            if (set(file) != {'bucket_sha256', 'object_sha256', 'generation', 'sha1', 'hash_matches', 'object'}
                    or not re.fullmatch('[0-9a-f]{64}', file['object_sha256']) or file['hash_matches'] is not True or not re.fullmatch('[0-9a-f]{40}', file['sha1'])
                    or not isinstance(file['generation'], str) or not objects._DECIMAL.fullmatch(file['generation'])
                    or int(file['generation']) > 9223372036854775807):
                raise ValueError('hash or generation binding')
            matching = [b for b in buckets['items'] if isinstance(b.get('name'), str)
                        and hashlib.sha256(b['name'].encode()).hexdigest() == file['bucket_sha256']]
            if len(matching) != 1 or set(matching[0].get('_coverage', {})) & {'name', 'projectNumber', '*'}:
                raise ValueError('bucket')
            objects._bound_bucket(SimpleNamespace(collections={('project', scope): project, ('bucket', scope): buckets}), scope, matching[0]['name'])
            native_binding(matching[0], buckets)
            selected = file['object']
            oid = selected['name']
            if oid in object_ids:
                raise ValueError('duplicate object')
            object_ids.add(oid)
            expected += [('storage.objects.get.appengine_generation', item['name']),
                         ('storage.objects.get.metadata', oid), ('storage.objects.get.media', oid)]
            status, evidence = object_check.evaluate(selected, {'context': {'provider': 'gcp', 'scope': scope},
                'collections': {objects.KIND: [{'scope': scope, 'status': 'collected', 'items': [selected]}]}})
            if status not in ('PASS', 'FAIL'):
                raise ValueError('incomplete content')
            total += evidence['bytes']
            outcomes.append(status)
            evidence_rows.append(evidence)
        if total > source.MAX_BYTES:
            raise ValueError('byte limit')
        expected_manifest = [{'bucket_sha256': f['bucket_sha256'], 'object_sha256': f['object_sha256'], 'sha1': f['sha1']} for f in marker['files']]
        expected_bindings = [{'bucket_sha256': f['bucket_sha256'], 'object_sha256': f['object_sha256'], 'generation': f['generation']} for f in marker['files']]
        actual, ids, discoveries = [], [], []
        for receipt in receipts:
            if (set(receipt) != {'id', 'scope', 'method', 'operation', 'resource_id', 'status', 'http_status', 'projection'}
                    or receipt['scope'] != scope or receipt['method'] != 'GET'
                    or receipt['status'] != 'collected' or receipt['http_status'] != 200):
                raise ValueError('source receipt')
            operation, projection = receipt['operation'], receipt['projection']
            if operation == 'appengine.apps.get.source':
                if projection != {'name': 'apps/' + m[1], 'id': m[1]}:
                    raise ValueError('app projection')
            elif operation == 'appengine.versions.get.source':
                if projection != {'name': name, 'files': expected_manifest}:
                    raise ValueError('native manifest projection')
            elif operation == 'storage.objects.get.appengine_generation':
                discoveries.append(projection)
            else:
                owner_file = next(f for f in marker['files'] if f['object']['name'] == receipt['resource_id'])
                if projection != {k: owner_file[k] for k in ('bucket_sha256', 'object_sha256', 'generation')}:
                    raise ValueError('generation receipt binding')
            actual.append((receipt['operation'], receipt['resource_id']))
            ids.append(receipt['id'])
        if (discoveries != expected_bindings or sorted(actual) != sorted(expected) or len(set(ids)) != len(ids) or set(ids) & set(native)
                or used_native != set(native) or set(refs) != set(ids) | set(native)):
            raise ValueError('source request ownership')
        leaks = [leak for e in evidence_rows for leak in e['secret_leaks']]
        failed = 'FAIL' in outcomes
        return ('FAIL' if failed else 'PASS'), {'observed': ' '.join(DECLARATION['evidence_sentences']) if failed else
            'Both offline detectors found no supported secret in the complete hash-matched deployment file manifest. Runtime contents and generated build artifacts were not assessed.',
            'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted', 'version_name': name,
            'coverage': 'complete_native_deployment_files_manifest_only', 'files': len(outcomes),
            'bytes': total, 'source_requests': list(refs)}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, objects.Incomplete, StopIteration):
        return 'UNKNOWN', {'observed': 'App Engine deployment source inspection is disabled, unsupported, incomplete or unbound; secret absence could not be assessed.'}


def install():
    """Root alone calls this idempotent catalog admission hook."""
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    cases = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_appengine_source_secret_review_20261019_fixtures.json.gz').read_bytes()))
    register(CHECK_ID, 'gcp', 'hardening', KIND, DECLARATION['title'], 'high', 'security_configuration',
             DECLARATION['remediation'], dependencies=DECLARATION['dependencies'])(evaluate)
    CASES[CHECK_ID] = cases
