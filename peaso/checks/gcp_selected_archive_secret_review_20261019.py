"""Pure unregistered check for complete, explicitly selected archive text."""
from copy import deepcopy
import re

from peaso.collectors.gcp_selected_archive_secret_indicators import (
    SCHEMA, MARKER, KIND, MIME_TYPES, MAX_EXPANDED_BYTES, MAX_MEMBER_BYTES, MAX_MEMBERS,
)
from peaso.collectors.gcp_selected_object_secret_indicators import MAX_OBJECT_BYTES, MAX_LEAKS, MAX_LOCATIONS
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID = 'gcp.review.storage.selected_archive_secret_indicators'
DECLARATION = {
    'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'title': 'Selected Cloud Storage archive has no detected secrets',
    'severity': 'high', 'dependencies': ['project', 'bucket', KIND], 'requirements': [],
    'remediation': 'Remove exposed credentials from the selected archive and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in a text member of an explicitly selected Cloud Storage archive.',
                           'The value is hidden; detection did not validate the credential.'],
}


def evaluate(item, index):
    try:
        scope, name = index['context']['scope'], item['name']
        if (index['context']['provider'] != 'gcp' or not isinstance(scope, str)
                or not re.fullmatch(r'gcs-selected-archive:[0-9a-f]{64}', name)):
            raise ValueError('foreign archive')
        matching = [e for e in index['collections'][KIND] if isinstance(e, dict)
                    and e.get('scope') == scope and e.get('status') == 'collected'
                    and isinstance(e.get('items'), list) and item in e['items']
                    and sum(isinstance(r, dict) and r.get('name') == name for r in e['items']) == 1]
        if len(matching) != 1:
            raise ValueError('unavailable collection')
        marker = item[MARKER]
        if (set(marker) != {'schema', 'identity', 'scope', 'format', 'status', 'complete', 'compressed_bytes',
                            'expanded_bytes', 'members', 'files', 'leaks', 'verification', 'reason'}
                or marker['schema'] != SCHEMA or marker['identity'] != name or marker['scope'] != scope
                or marker['format'] not in MIME_TYPES or marker['status'] != 'collected'
                or marker['complete'] is not True or marker['verification'] != 'not_attempted'
                or marker['reason'] != 'complete'):
            raise ValueError('incomplete producer')
        for field, cap in (('compressed_bytes', MAX_OBJECT_BYTES), ('expanded_bytes', MAX_EXPANDED_BYTES),
                           ('members', MAX_MEMBERS)):
            if type(marker[field]) is not int or not (0 if field == 'expanded_bytes' else 1) <= marker[field] <= cap:
                raise ValueError('invalid coverage bound')
        files = marker['files']
        if not isinstance(files, list) or not 1 <= len(files) <= marker['members']:
            raise ValueError('missing regular text coverage')
        expected = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        for i, file in enumerate(files, 1):
            if (not isinstance(file, dict) or set(file) != {'path', 'bytes', 'engines'}
                    or file['path'] != 'archive.member-' + str(i)
                    or type(file['bytes']) is not int or not 0 <= file['bytes'] <= MAX_MEMBER_BYTES):
                raise ValueError('invalid member coverage')
            engines = file['engines']
            if (not isinstance(engines, list) or len(engines) != 2
                    or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                           or e.get('engine') not in expected or e.get('version') != expected.get(e.get('engine'))
                           or e.get('status') != 'complete' for e in engines)
                    or {e['engine'] for e in engines} != set(expected)):
                raise ValueError('both detectors required for every member')
        if sum(f['bytes'] for f in files) > marker['expanded_bytes']:
            raise ValueError('contradictory expansion')
        if not isinstance(marker['leaks'], list) or len(marker['leaks']) > MAX_LEAKS:
            raise ValueError('finding limit')
        leaks = merge_leaks(marker['leaks'])
        paths = {f['path'] for f in files}
        if (sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS
                or any(loc['path'] not in paths or set(loc) - {'path', 'line'}
                       for leak in leaks for loc in leak['locations'])):
            raise ValueError('foreign member source')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
                    'complete': True, 'format': marker['format'], 'files': deepcopy(files),
                    'compressed_bytes': marker['compressed_bytes'], 'expanded_bytes': marker['expanded_bytes']}
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in a text member of an explicitly selected Cloud Storage archive. The value is hidden; detection did not validate the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed on every regular text member of the complete selected archive without finding a supported secret.'}
    except (KeyError, TypeError, ValueError, AttributeError):
        return 'UNKNOWN', {'observed': 'Selected archive scanning is disabled, incomplete, unreadable or unsupported; secret absence could not be assessed.'}


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
        'gcp_selected_archive_secret_fixtures.json.gz').read_bytes()))
    CASES[CHECK_ID].update(missing={}, malformed=None)
