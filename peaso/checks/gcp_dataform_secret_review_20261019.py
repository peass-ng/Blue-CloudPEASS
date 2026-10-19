"""Pure unregistered selected Dataform file declaration and predicate."""
from copy import deepcopy
from datetime import datetime
import re

from peaso.collectors.gcp_dataform_secret_indicators import (
    SCHEMA, MARKER, KIND, MAX_FILE_BYTES, MAX_LEAKS, MAX_LOCATIONS,
)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID = 'gcp.review.dataform.selected_file_secret_indicators'
DECLARATION = {
    'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'title': 'Selected Dataform file has no detected secrets',
    'severity': 'high', 'dependencies': ['project', KIND], 'requirements': [],
    'remediation': 'Remove credentials from the selected Dataform file and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in the explicitly selected Dataform file.',
                           'The value is hidden; detection did not validate the credential.'],
}


def evaluate(item, index):
    try:
        scope, name = index['context']['scope'], item['name']
        if (index['context']['provider'] != 'gcp' or not isinstance(scope, str)
                or not re.fullmatch(r'dataform-selected-file:[0-9a-f]{64}', name)):
            raise ValueError('unbound file')
        envelopes = [e for e in index['collections'][KIND] if isinstance(e, dict)
                     and e.get('scope') == scope and e.get('status') == 'collected'
                     and isinstance(e.get('items'), list) and item in e['items']
                     and sum(isinstance(r, dict) and r.get('name') == name for r in e['items']) == 1]
        if len(envelopes) != 1:
            raise ValueError('unbound collection')
        marker = item[MARKER]
        if (set(marker) != {'schema', 'identity', 'scope', 'status', 'complete', 'bytes',
                            'engines', 'leaks', 'reason', 'verification', 'source_requests',
                            'read_mode', 'revision', 'observed_at'}
                or marker['schema'] != SCHEMA or marker['identity'] != name or marker['scope'] != scope
                or marker['status'] != 'collected' or marker['complete'] is not True
                or marker['reason'] != 'complete' or marker['verification'] != 'not_attempted'
                or type(marker['bytes']) is not int or not 0 <= marker['bytes'] <= MAX_FILE_BYTES):
            raise ValueError('incomplete evidence')
        mode, revision = marker['read_mode'], marker['revision']
        if mode not in ('commit_sha', 'revision_sha', 'observed_workspace'):
            raise ValueError('unsupported revision')
        if ((mode == 'observed_workspace' and revision is not None)
                or (mode != 'observed_workspace' and (not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{40}', revision)))):
            raise ValueError('unbound revision')
        observed = datetime.fromisoformat(marker['observed_at'])
        if observed.tzinfo is None:
            raise ValueError('unbound observation')
        refs = marker['source_requests']
        required = 2 if mode == 'commit_sha' else 3
        if (not isinstance(refs, list) or len(refs) != required or len(set(refs)) != required
                or any(not isinstance(r, str) or not re.fullmatch(r'request-[1-9][0-9]*', r) for r in refs)
                or not set(refs) <= set(envelopes[0].get('source_requests', []))):
            raise ValueError('unbound read provenance')
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
                or any(loc['path'] != 'dataform.selected_file.content' or set(loc) - {'path', 'line'}
                       for leak in leaks for loc in leak['locations'])):
            raise ValueError('foreign content position')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
                    'complete': True, 'bytes': marker['bytes'], 'engines': deepcopy(engines),
                    'read_mode': mode, 'revision': revision, 'observed_at': marker['observed_at'],
                    'source_requests': list(refs), 'coverage': 'selected_file_only'}
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in the explicitly selected Dataform file. The value is hidden; detection did not validate the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed without finding a supported secret in this complete selected file read. This observation covers only the selected file and does not establish repository-wide or workspace-wide secret absence.'}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return 'UNKNOWN', {'observed': 'Selected Dataform file scanning is disabled, incomplete, unreadable or unbound; secret absence could not be assessed.'}


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
        'gcp_dataform_secret_fixtures.json.gz').read_bytes()))
