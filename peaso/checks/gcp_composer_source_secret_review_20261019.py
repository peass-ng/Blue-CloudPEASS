"""Native Composer DAG source desired-state check; installation is root-owned."""
from copy import deepcopy
import re
from urllib.parse import urlsplit
from peaso.collectors.gcp_composer_source_secret_indicators import (
    KIND, MARKER, SCHEMA, MAX_FILES, MAX_LEAKS, MAX_LOCATIONS, identity,
)
from peaso.collectors.gcp_selected_object_secret_indicators import MAX_TOTAL_BYTES
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID = 'gcp.review.composer.dag_source_secret_indicators'
DECLARATION = {
    'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'title': 'Observed Composer DAG source files have no detected secrets',
    'severity': 'high', 'dependencies': ['project', 'bucket', 'composer_environment', KIND],
    'requirements': [], 'remediation': 'Remove exposed credentials from DAG source and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in a native Composer DAG source file.',
                           'The value is hidden; neither offline detector validated the credential.'],
}


def evaluate(item, index):
    try:
        scope, name = index['context']['scope'], item['name']
        if index['context']['provider'] != 'gcp':
            raise ValueError('provider')
        marker = item[MARKER]
        partial = (marker.get('complete') is False and marker.get('status') == 'incomplete'
                   and marker.get('reason') not in ('complete', 'source_unavailable')
                   and isinstance(marker.get('leaks'), list) and bool(marker['leaks']))
        if (not isinstance(scope, str) or not isinstance(name, str)
                or not re.fullmatch(r'composer-dag-source:[a-f0-9]{64}', name)
                or set(marker) != {'schema', 'identity', 'owner', 'scope', 'complete', 'status', 'reason',
                                   'verification', 'source_requests', 'native_requests', 'read_receipts', 'files', 'engines', 'leaks', 'bytes'}
                or marker['schema'] != SCHEMA or marker['identity'] != name or marker['scope'] != scope
                or not (partial or marker['complete'] is True and marker['status'] == 'collected'
                        and marker['reason'] == 'complete') or marker['verification'] != 'not_attempted'
                or not isinstance(marker['owner'], str) or identity(marker['owner']) != name
                or not re.fullmatch(r'projects/(?:[a-z][a-z0-9-]{0,62}|[1-9][0-9]{0,19})/locations/[a-z][a-z0-9-]{0,62}/environments/[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?', marker['owner'])
                or type(marker['bytes']) is not int or not 0 <= marker['bytes'] <= MAX_TOTAL_BYTES):
            raise ValueError('binding')
        project_envelopes = [e for e in index['collections']['project'] if e.get('scope') == scope and e.get('status') == 'collected' and len(e.get('items', [])) == 1]
        if len(project_envelopes) != 1:
            raise ValueError('project')
        project = project_envelopes[0]['items'][0]
        aliases = {project.get('name'), 'projects/' + str(project.get('projectId', ''))}
        if scope not in aliases or '/'.join(marker['owner'].split('/')[:2]) not in aliases:
            raise ValueError('project alias')
        envelopes = [e for e in index['collections'][KIND] if e.get('scope') == scope
                     and e.get('status') == 'collected' and item in e.get('items', [])
                     and sum(r.get('name') == name for r in e['items']) == 1]
        refs, files = marker['source_requests'], marker['files']
        if (len(envelopes) != 1 or not isinstance(refs, list) or len(refs) < 6 or len(set(refs)) != len(refs)
                or any(not isinstance(r, str) or not re.fullmatch(r'request-[1-9][0-9]*', r) for r in refs)
                or not set(refs) <= set(envelopes[0].get('source_requests', []))
                or not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES or len(set(files)) != len(files)
                or any(not isinstance(f, str) or not re.fullmatch(r'gcs-selected-object:[a-f0-9]{64}', f) for f in files)):
            raise ValueError('provenance')
        native_refs, receipts = marker['native_requests'], marker['read_receipts']
        if (not isinstance(native_refs, list) or len(native_refs) != 3 or len(set(native_refs)) != 3
                or not isinstance(receipts, list) or not 1 <= len(receipts) <= 3 + 2 * MAX_FILES):
            raise ValueError('receipt shape')
        env_rows = [r for e in index['collections']['composer_environment'] if e.get('scope') == scope and e.get('status') == 'collected'
                    for r in e.get('items', []) if r.get('name') == marker['owner']]
        if len(env_rows) != 1:
            raise ValueError('owner source')
        bucket = urlsplit(env_rows[0]['config']['dagGcsPrefix']).netloc
        bucket_rows = [r for e in index['collections']['bucket'] if e.get('scope') == scope and e.get('status') == 'collected'
                       for r in e.get('items', []) if r.get('name') == bucket and r.get('projectNumber') == project['name'].split('/')[1]]
        if len(bucket_rows) != 1:
            raise ValueError('bucket source')
        for native_row in [project, env_rows[0], bucket_rows[0]]:
            if len(set(native_refs) & set(native_row.get('_provenance', {}).get('source_requests', []))) != 1:
                raise ValueError('native source receipts')
        ids, counts = [], {}
        for receipt in receipts:
            if (not isinstance(receipt, dict) or set(receipt) != {'id', 'scope', 'operation', 'resource_id', 'status'}
                    or receipt['scope'] != scope or receipt['status'] not in ('collected', 'unavailable')):
                raise ValueError('foreign receipt')
            operation, resource = receipt['operation'], receipt['resource_id']
            if operation == 'storage.objects.list.composer_dags':
                if resource != name or receipt['status'] != 'collected':
                    raise ValueError('foreign list owner')
            elif (operation not in ('storage.objects.get.metadata', 'storage.objects.get.media')
                  or not re.fullmatch(r'gcs-selected-object:[a-f0-9]{64}', resource)
                  or not partial and resource not in files
                  or resource in files and receipt['status'] != 'collected'):
                raise ValueError('foreign file owner')
            ids.append(receipt['id'])
            counts[(operation, resource)] = counts.get((operation, resource), 0) + 1
        unscanned = [r for r in receipts if r['operation'] != 'storage.objects.list.composer_dags'
                     and r['resource_id'] not in files]
        if unscanned and (not partial or marker['reason'] == 'detector_unavailable'
                          or len({r['resource_id'] for r in unscanned}) != 1
                          or len(unscanned) > 2
                          or not (any(r['status'] == 'unavailable' for r in unscanned)
                                  or marker['reason'] == 'metadata_changed'
                                  and len(unscanned) == 1
                                  and unscanned[0]['operation'] == 'storage.objects.get.metadata'
                                  and unscanned[0]['status'] == 'collected')):
            raise ValueError('unscanned receipt')
        if (len(set(ids)) != len(ids) or set(ids) & set(native_refs) or set(refs) != set(ids) | set(native_refs)
                or not 1 <= counts.get(('storage.objects.list.composer_dags', name), 0) <= 3
                or any(counts.get((operation, f)) != 1 for f in files
                       for operation in ('storage.objects.get.metadata', 'storage.objects.get.media'))):
            raise ValueError('receipt completeness')
        expected = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        engines = marker['engines']
        if (not isinstance(engines, list) or len(engines) != 2
                or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                       or e.get('version') != expected.get(e.get('engine'))
                       or e.get('status') not in (('complete', 'unavailable') if partial else ('complete',)) for e in engines)
                or {e['engine'] for e in engines} != set(expected)):
            raise ValueError('engines')
        if not isinstance(marker['leaks'], list) or len(marker['leaks']) > MAX_LEAKS:
            raise ValueError('leaks')
        leaks = merge_leaks(marker['leaks'])
        if (sum(len(x['locations']) for x in leaks) > MAX_LOCATIONS
                or any(loc.get('path') not in {'composer.dag.content/' + f.split(':', 1)[1] for f in files} or set(loc) - {'path', 'line'}
                       for leak in leaks for loc in leak['locations'])
                or partial and any(d['engine'] not in {e['engine'] for e in engines if e['status'] == 'complete'}
                                   for leak in leaks for d in leak['detectors'])):
            raise ValueError('locations')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
            'owner': marker['owner'], 'files': list(files), 'source_requests': list(refs),
            'bytes': marker['bytes'], 'engines': deepcopy(engines), 'coverage': 'observed_prefix_generations_only'}
        if leaks:
            if partial:
                evidence.update(coverage='partial_observed_prefix_generations_only', complete=False,
                                reason=marker['reason'])
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in a native Composer DAG source file. The value is hidden; neither offline detector validated the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed without detecting a supported secret in the observed DAG file generations. This bounded prefix observation does not establish secret absence throughout the environment or across concurrent changes.'}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return 'UNKNOWN', {'observed': 'Composer DAG source inspection is disabled, unsupported, incomplete or unbound; secret absence could not be assessed.'}


def install():
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    register(CHECK_ID, 'gcp', 'hardening', KIND, DECLARATION['title'], 'high',
             'security_configuration', DECLARATION['remediation'], dependencies=DECLARATION['dependencies'])(evaluate)
    CASES[CHECK_ID] = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_composer_source_secret_fixtures.json.gz').read_bytes()))
