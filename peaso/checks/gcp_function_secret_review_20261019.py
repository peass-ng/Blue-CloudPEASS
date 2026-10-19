"""Optional offline inspection of literal Cloud Functions environment values."""
from copy import deepcopy

from .facts import Unavailable, get
from peaso.collectors.gcp_function_secret_indicators import (
    SCHEMA, MARKER, SURFACES, MAX_PAIRS, MAX_FUNCTION_BYTES, MAX_LEAKS, MAX_LOCATIONS, _bound,
)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID = 'gcp.review.function.literal_environment_secret_indicators'
DECLARATION = {
    'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': 'function',
    'finding_type': 'secrets', 'title': 'Cloud Function literal environment has no detected secrets',
    'severity': 'high', 'dependencies': ['function'], 'requirements': [],
    'remediation': 'Move literal credentials to Secret Manager references and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in the function’s literal environment values.',
                           'The value is hidden; detection did not validate the credential.'],
}


def evaluate(item, index):
    try:
        scope = get(index, 'context.scope', str)
        if get(index, 'context.provider', str) != 'gcp':
            raise Unavailable('foreign provider')
        name = get(item, 'name', str)
        if not _bound(name, scope, '-', None):
            raise Unavailable('foreign function')
        envelopes = get(index, 'collections.function', list)
        matching = [row for row in envelopes if isinstance(row, dict) and row.get('scope') == scope
                    and row.get('status') == 'collected' and isinstance(row.get('items'), list)
                    and sum(isinstance(native, dict) and native.get('name') == name for native in row['items']) == 1
                    and item in row['items']]
        if len(matching) != 1:
            raise Unavailable('function collection incomplete or ambiguous')
        marker = get(item, MARKER, dict)
        if (set(marker) != {'schema', 'status', 'identity', 'scope', 'complete', 'surfaces', 'leaks', 'verification'}
                or marker['schema'] != SCHEMA or marker['status'] not in ('collected', 'incomplete')
                or marker['identity'] != name or marker['scope'] != scope
                or type(marker['complete']) is not bool or marker['verification'] != 'not_attempted'):
            raise Unavailable('unbound or unavailable scanner projection')
        surfaces = marker['surfaces']
        if not isinstance(surfaces, list) or [s.get('surface') for s in surfaces if isinstance(s, dict)] != list(SURFACES):
            raise Unavailable('both environment surfaces required')
        all_complete = True
        for surface in surfaces:
            if (set(surface) != {'surface', 'pairs', 'bytes', 'complete', 'engines'}
                    or type(surface['pairs']) is not int or not 0 <= surface['pairs'] <= MAX_PAIRS
                    or type(surface['bytes']) is not int or not 1 <= surface['bytes'] <= MAX_FUNCTION_BYTES
                    or type(surface['complete']) is not bool or not isinstance(surface['engines'], list)):
                raise Unavailable('malformed detector coverage')
            engines = surface['engines']
            expected = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
            if (len(engines) != 2 or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                    or e.get('engine') not in expected or e.get('version') != expected.get(e.get('engine'))
                    or e.get('status') not in ('complete', 'unavailable') for e in engines)
                    or {e['engine'] for e in engines} != set(expected)):
                raise Unavailable('both detector identities required')
            complete = all(e['status'] == 'complete' for e in engines)
            if surface['complete'] != complete:
                raise Unavailable('contradictory surface completeness')
            all_complete &= complete
        if marker['complete'] != all_complete or (marker['status'] == 'collected') != all_complete:
            raise Unavailable('contradictory complete scan status')
        if not isinstance(marker['leaks'], list) or len(marker['leaks']) > MAX_LEAKS:
            raise Unavailable('invalid leak evidence')
        leaks = merge_leaks(marker['leaks'])
        if sum(len(leak['locations']) for leak in leaks) > MAX_LOCATIONS:
            raise Unavailable('leak location bound')
        for leak in leaks:
            for loc in leak['locations']:
                if loc['path'] not in {s + '.environmentVariables' for s in SURFACES}:
                    raise Unavailable('foreign content location')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
                    'complete': all_complete, 'surfaces': deepcopy(surfaces)}
        if not all_complete:
            raise Unavailable('incomplete detector coverage')
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in the function’s literal environment values. The value is hidden; detection did not validate the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed without finding a supported secret in the returned runtime and build environment values.'}
    except (Unavailable, KeyError, TypeError, ValueError, AttributeError):
        return 'UNKNOWN', {'observed': 'Literal environment scanning is disabled, incomplete, unreadable or unbound; secret absence could not be assessed.'}


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    register(CHECK_ID, 'gcp', 'hardening', 'function', DECLARATION['title'],
             'high', 'security_configuration', DECLARATION['remediation'])(evaluate)
    scope = 'projects/review'
    name = scope + '/locations/us-central1/functions/worker'
    good = {'name': name, MARKER: {'schema': SCHEMA, 'status': 'collected',
        'identity': name, 'scope': scope, 'complete': True, 'verification': 'not_attempted',
        'leaks': [], 'surfaces': [{'surface': surface, 'pairs': 0, 'bytes': 1,
            'complete': True, 'engines': [
                {'engine': 'kingfisher', 'version': KINGFISHER_VERSION, 'status': 'complete'},
                {'engine': 'trufflehog', 'version': TRUFFLEHOG_VERSION, 'status': 'complete'}]}
            for surface in SURFACES]}}
    bad = deepcopy(good)
    bad[MARKER]['leaks'] = [{'fingerprint': 'a' * 64,
        'detectors': [{'engine': 'kingfisher', 'rule': 'synthetic'}],
        'locations': [{'path': 'serviceConfig.environmentVariables', 'line': 1}]}]
    def context(row):
        return {'context': {'provider': 'gcp', 'scope': scope}, 'collections': {
            'function': [{'scope': scope, 'status': 'collected', 'items': [row]}]}}
    CASES[CHECK_ID] = {'pass': good, 'fail': bad, 'missing': {}, 'malformed': None,
                      'pass_index': context(good), 'fail_index': context(bad)}
