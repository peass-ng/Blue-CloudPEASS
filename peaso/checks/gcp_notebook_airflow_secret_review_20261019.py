"""Pure native Composer/Workbench literal checks and explicit registry hook."""
from copy import deepcopy
import re
from peaso.collectors.gcp_notebook_airflow_secret_indicators import (
    SCHEMA, MARKER, KINDS, COMPOSER, WORKBENCH, FIELDS, MAX_ROW_BYTES, MAX_LEAKS, MAX_LOCATIONS, bound,
)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

SERVICES = {COMPOSER: 'Cloud Composer', WORKBENCH: 'Workbench'}
ACTIONS = {
    COMPOSER: 'Remove credentials from Composer configuration, retrieve secrets at runtime through authorized Airflow or application code, and rotate exposed credentials.',
    WORKBENCH: 'Remove credentials from notebook metadata and startup scripts, retrieve secrets at runtime using the notebook service account, and rotate exposed credentials.',
}
DECLARATIONS = {kind: {
    'id': 'gcp.review.' + kind + '.literal_configuration_secret_indicators',
    'kind': kind, 'provider': 'gcp', 'category': 'hardening', 'finding_type': 'secrets',
    'title': service + ' literal configuration has no detected secrets', 'severity': 'high',
    'dependencies': [kind], 'requirements': [],
    'remediation': ACTIONS[kind],
} for kind, service in SERVICES.items()}


def evaluate(item, index, kind):
    try:
        scope = index['context']['scope']; name = item['name']
        if index['context']['provider'] != 'gcp' or not bound(name, scope, kind): raise ValueError('identity')
        matching = [e for e in index['collections'][kind] if isinstance(e, dict) and e.get('scope') == scope
                    and e.get('status') == 'collected' and isinstance(e.get('items'), list) and item in e['items']
                    and sum(isinstance(r, dict) and r.get('name') == name for r in e['items']) == 1]
        if len(matching) != 1: raise ValueError('incomplete collection')
        m = item[MARKER]
        if (set(m) != {'schema', 'scope', 'kind', 'identity', 'complete', 'bytes', 'fields', 'engines', 'leaks', 'verification'}
                or m['schema'] != SCHEMA or m['scope'] != scope or m['kind'] != kind or m['identity'] != name
                or m['complete'] is not True or type(m['bytes']) is not int or not 1 <= m['bytes'] <= MAX_ROW_BYTES
                or m['fields'] != list(FIELDS[kind]) or m['verification'] != 'not_attempted'):
            raise ValueError('coverage')
        expected = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        engines = m['engines']
        if (not isinstance(engines, list) or len(engines) != 2 or any(not isinstance(e, dict)
                or set(e) != {'engine', 'version', 'status'} or e.get('engine') not in expected
                or e.get('version') != expected.get(e.get('engine')) or e.get('status') != 'complete' for e in engines)
                or {e['engine'] for e in engines} != set(expected)):
            raise ValueError('engines')
        if not isinstance(m['leaks'], list) or len(m['leaks']) > MAX_LEAKS: raise ValueError('leaks')
        leaks = merge_leaks(m['leaks'])
        if sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS or any(
            set(loc) - {'path', 'line'} or loc['path'] != kind + '.literal_configuration'
            for leak in leaks for loc in leak['locations']): raise ValueError('locations')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
                    'complete': True, 'fields': m['fields'][:], 'bytes': m['bytes'], 'engines': deepcopy(engines)}
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in the returned ' + SERVICES[kind] + ' literal configuration. The value is hidden; detection did not validate the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed without finding a supported secret in the returned ' + SERVICES[kind] + ' literal configuration; referenced code, files and managed secret values were not assessed.'}
    except (KeyError, TypeError, ValueError, AttributeError):
        return 'UNKNOWN', {'observed': 'Literal configuration scanning is disabled, incomplete, unreadable or unsupported; secret absence could not be assessed.'}


CALLBACKS = {k: (lambda item, index, kind=k: evaluate(item, index, kind)) for k in KINDS}


def install():
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    fixtures = json.loads(gzip.decompress(Path(__file__).with_name('gcp_notebook_airflow_secret_fixtures.json.gz').read_bytes()))
    for kind, d in DECLARATIONS.items():
        if any(c.id == d['id'] for c in CHECKS): continue
        register(d['id'], 'gcp', 'hardening', kind, d['title'], 'high', 'security_configuration',
                 d['remediation'], dependencies=d['dependencies'])(CALLBACKS[kind])
        CASES[d['id']] = fixtures[d['id']]
