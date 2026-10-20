"""Pure job-configuration checks with explicit idempotent registry installer."""
from copy import deepcopy
import re

from peaso.collectors.gcp_job_literal_secret_indicators import (
    SCHEMA, MARKER, IDENTITY, DATAFLOW, BATCH, CLUSTER, DATAPROC,
    MAX_ROW_BYTES, MAX_LEAKS, MAX_LEAK_LOCATIONS,
)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

SERVICES = {DATAFLOW: 'Dataflow job', BATCH: 'Batch job', CLUSTER: 'Dataproc cluster', DATAPROC: 'Dataproc job'}
FIELDS = {DATAFLOW: {'environment'},
          BATCH: {'taskGroups.literal_configuration'},
          CLUSTER: {'config.softwareConfig.properties', 'config.gceClusterConfig.metadata'}}
JOB_VARIANTS = ('hadoopJob', 'sparkJob', 'pysparkJob', 'hiveJob', 'pigJob', 'sparkRJob',
                'sparkSqlJob', 'prestoJob', 'trinoJob', 'flinkJob')
ACTIONS = {
    DATAFLOW: 'Remove credentials from pipeline options and worker configuration, retrieve secrets in authorized pipeline code, and rotate exposed credentials.',
    BATCH: 'Replace literal task credentials with Batch secretVariables or authorized runtime retrieval and rotate exposed credentials.',
    CLUSTER: 'Remove credentials from cluster properties and VM metadata, retrieve secrets in authorized workload code, and rotate exposed credentials.',
    DATAPROC: 'Remove credentials from job arguments, properties and queries, retrieve secrets in authorized job code, and rotate exposed credentials.',
}
DECLARATIONS = {kind: {'id': 'gcp.review.' + kind + '.literal_configuration_secret_indicators',
    'provider': 'gcp', 'category': 'hardening', 'kind': kind, 'finding_type': 'secrets',
    'title': service + ' literal configuration has no detected secrets', 'severity': 'high',
    'dependencies': ['project', kind], 'requirements': [],
    'remediation': ACTIONS[kind],
    'evidence_sentences': ['A likely secret was detected in the ' + service.lower() + ' literal configuration.',
                           'The value is hidden; detection did not validate the credential.']}
    for kind, service in SERVICES.items()}


def evaluate(item, index, kind):
    try:
        scope = index['context']['scope']; ident = item[IDENTITY]
        if index['context']['provider'] != 'gcp' or kind not in SERVICES or not isinstance(scope, str) or not re.fullmatch(r'gcp-job-literal:[0-9a-f]{64}', ident):
            raise ValueError('identity')
        matching = [e for e in index['collections'][kind] if isinstance(e, dict) and e.get('scope') == scope
                    and e.get('status') == 'collected' and isinstance(e.get('items'), list) and item in e['items']
                    and sum(isinstance(r, dict) and r.get(IDENTITY) == ident for r in e['items']) == 1]
        if len(matching) != 1: raise ValueError('collection')
        coverage = item['_coverage'][MARKER]
        refs = coverage['source_requests']
        if (coverage.get('status') != 'collected' or not isinstance(refs, list)
                or len(refs) != (2 if kind == DATAFLOW else 1) or len(set(refs)) != len(refs)
                or any(not isinstance(ref, str) or not re.fullmatch(r'request-[1-9][0-9]*', ref) for ref in refs)
                or not set(refs) <= set(matching[0].get('source_requests', []))
                or not set(refs) <= set(item.get('_provenance', {}).get('source_requests', []))):
            raise ValueError('native request provenance')
        marker = item[MARKER]
        if (set(marker) != {'schema', 'identity', 'scope', 'kind', 'region', 'complete', 'bytes', 'fields', 'engines', 'leaks', 'verification'}
                or marker['schema'] != SCHEMA or marker['identity'] != ident or marker['scope'] != scope
                or marker['kind'] != kind or marker['complete'] is not True or marker['verification'] != 'not_attempted'
                or not isinstance(marker['region'], str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', marker['region'])
                or type(marker['bytes']) is not int or not 1 <= marker['bytes'] <= MAX_ROW_BYTES):
            raise ValueError('producer')
        fields = marker['fields']
        if not isinstance(fields, list) or any(not isinstance(f, str) for f in fields): raise ValueError('fields')
        if kind == DATAPROC:
            if len(fields) != 1 or fields[0] not in {v + '.literal_configuration' for v in JOB_VARIANTS}: raise ValueError('variant')
        elif set(fields) != FIELDS[kind] or len(fields) != len(FIELDS[kind]): raise ValueError('field coverage')
        engines = marker['engines']; expected = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        if (not isinstance(engines, list) or len(engines) != 2 or any(not isinstance(e, dict)
                or set(e) != {'engine', 'version', 'status'} or e.get('engine') not in expected
                or e.get('version') != expected.get(e.get('engine')) or e.get('status') != 'complete' for e in engines)
                or {e['engine'] for e in engines} != set(expected)):
            raise ValueError('engines')
        if not isinstance(marker['leaks'], list) or len(marker['leaks']) > MAX_LEAKS: raise ValueError('leaks')
        leaks = merge_leaks(marker['leaks'])
        if sum(len(l['locations']) for l in leaks) > MAX_LEAK_LOCATIONS or any(
                loc['path'] != kind + '.literal_configuration' or set(loc) - {'path', 'line'}
                for leak in leaks for loc in leak['locations']): raise ValueError('locations')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
                    'complete': True, 'fields': fields[:], 'bytes': marker['bytes'], 'engines': deepcopy(engines)}
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in the ' + SERVICES[kind].lower() + ' literal configuration. The value is hidden; detection did not validate the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed without finding a supported secret in the returned ' + SERVICES[kind].lower() + ' literal configuration; referenced files and managed secret values were not assessed.'}
    except (KeyError, ValueError, TypeError, AttributeError):
        return 'UNKNOWN', {'observed': 'Literal configuration scanning is disabled, incomplete, unreadable or unsupported; secret absence could not be assessed.'}


CALLBACKS = {kind: (lambda item, index, kind=kind: evaluate(item, index, kind)) for kind in SERVICES}


def install():
    """Root invokes explicitly; fixtures are native-produced redacted cases."""
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    fixtures = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_job_literal_secret_fixtures.json.gz').read_bytes()))
    for kind, declaration in DECLARATIONS.items():
        check_id = declaration['id']
        if any(c.id == check_id for c in CHECKS):
            continue
        register(check_id, 'gcp', 'hardening', kind, declaration['title'], 'high',
                 'security_configuration', declaration['remediation'],
                 dependencies=declaration['dependencies'])(CALLBACKS[kind])
        CASES[check_id] = fixtures[check_id]
