"""Pure, unregistered selected-object check; root owns installation/admission."""
from copy import deepcopy
import re

from peaso.collectors.gcp_selected_object_secret_indicators import (
    SCHEMA, MARKER, KIND, MAX_OBJECT_BYTES, MAX_LEAKS, MAX_LOCATIONS,
)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID = 'gcp.review.storage.selected_object_secret_indicators'
DECLARATION = {
    'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'title': 'Selected Cloud Storage text object has no detected secrets',
    'severity': 'high', 'dependencies': ['project', 'bucket', KIND], 'requirements': [],
    'remediation': 'Remove exposed credentials from object content and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in an explicitly selected Cloud Storage text object.',
                           'The value is hidden; detection did not validate the credential.'],
}


def evaluate(item, index):
    try:
        scope = index['context']['scope']
        name = item['name']
        if (index['context']['provider'] != 'gcp' or not isinstance(scope, str)
                or not re.fullmatch(r'gcs-selected-object:[0-9a-f]{64}', name)):
            raise ValueError('unbound object')
        envelopes = index['collections'][KIND]
        matching = [e for e in envelopes if isinstance(e, dict) and e.get('scope') == scope
                    and e.get('status') == 'collected' and isinstance(e.get('items'), list)
                    and sum(isinstance(r, dict) and r.get('name') == name for r in e['items']) == 1
                    and item in e['items']]
        if len(matching) != 1:
            raise ValueError('collection unavailable or ambiguous')
        marker = item[MARKER]
        if (set(marker) != {'schema', 'identity', 'scope', 'status', 'complete', 'bytes',
                            'engines', 'leaks', 'verification', 'reason'}
                or marker['schema'] != SCHEMA or marker['identity'] != name or marker['scope'] != scope
                or marker['status'] != 'collected' or marker['complete'] is not True
                or marker['reason'] != 'complete' or marker['verification'] != 'not_attempted'
                or type(marker['bytes']) is not int or not 0 <= marker['bytes'] <= MAX_OBJECT_BYTES):
            raise ValueError('incomplete or unbound evidence')
        expected = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        engines = marker['engines']
        if (not isinstance(engines, list) or len(engines) != 2
                or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                       or e.get('engine') not in expected or e.get('version') != expected.get(e.get('engine'))
                       or e.get('status') != 'complete' for e in engines)
                or {e['engine'] for e in engines} != set(expected)):
            raise ValueError('incomplete engines')
        if not isinstance(marker['leaks'], list) or len(marker['leaks']) > MAX_LEAKS:
            raise ValueError('finding limit')
        leaks = merge_leaks(marker['leaks'])
        if (sum(len(x['locations']) for x in leaks) > MAX_LOCATIONS
                or any(loc['path'] != 'object.content' or set(loc) - {'path', 'line'}
                       for leak in leaks for loc in leak['locations'])):
            raise ValueError('foreign source position')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
                    'complete': True, 'bytes': marker['bytes'], 'engines': deepcopy(engines)}
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in an explicitly selected Cloud Storage text object. The value is hidden; detection did not validate the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed without finding a supported secret in the complete selected text object.'}
    except (KeyError, TypeError, ValueError, AttributeError):
        return 'UNKNOWN', {'observed': 'Selected object scanning is disabled, incomplete, unreadable or unbound; secret absence could not be assessed.'}


def install():
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
        'gcp_selected_object_secret_fixtures.json.gz').read_bytes()))
    CASES[CHECK_ID].update(missing={}, malformed=None)
