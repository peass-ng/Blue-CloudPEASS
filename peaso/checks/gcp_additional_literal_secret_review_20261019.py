"""Pure unregistered callbacks for exact optional native literal surfaces."""
from copy import deepcopy
from .facts import get, Unavailable
from peaso.collectors.gcp_additional_literal_secret_indicators import (
    SCHEMA, MARKER, SCHEDULER, APPENGINE, WORKFLOW, REVISION, SCOPE, _bound,
    MAX_ROW_BYTES, MAX_LEAKS, MAX_LEAK_LOCATIONS,
)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_IDS = {
    SCHEDULER: 'gcp.review.scheduler_job.literal_target_secret_indicators',
    APPENGINE: 'gcp.review.app_engine_version.literal_environment_secret_indicators',
    WORKFLOW: 'gcp.review.workflow.deployed_source_secret_indicators',
}
LABELS = {SCHEDULER: 'Scheduler target literals', APPENGINE: 'App Engine version environment literals',
          WORKFLOW: 'Workflows deployed source'}
REMEDIATIONS = {
    SCHEDULER: 'Remove credentials from literal Scheduler headers, payloads and attributes, and rotate confirmed exposed credentials. Use native OIDC/OAuth for compatible HTTP targets, or send the job to a workload that reads secrets at runtime.',
    APPENGINE: 'Remove credentials from literal runtime and build environment maps, and rotate confirmed exposed credentials. Retrieve required secrets in application code or authorized build tooling through Secret Manager using a narrowly scoped identity.',
    WORKFLOW: 'Remove credential literals from workflow source and rotate confirmed exposed credentials. Retrieve required secrets through Secret Manager at runtime using the workflow service account with narrowly scoped access.',
}
DECLARATIONS = {kind: {'id': check_id, 'provider': 'gcp', 'category': 'hardening', 'kind': kind,
    'finding_type': 'secrets', 'severity': 'high', 'dependencies': [kind], 'requirements': [],
    'title': LABELS[kind] + (' has no detected secrets' if kind == WORKFLOW else ' have no detected secrets'),
    'remediation': REMEDIATIONS[kind],
    'evidence_sentences': ['A likely secret was detected in the returned ' + LABELS[kind].lower() + '.',
                           'The value is hidden; offline detection did not validate the credential.']}
    for kind, check_id in CHECK_IDS.items()}


def evaluate(item, index, kind):
    try:
        scope = get(index, 'context.scope', str)
        name = get(item, 'name', str)
        if get(index, 'context.provider', str) != 'gcp' or not SCOPE.fullmatch(scope) or not _bound(name, scope, kind):
            raise Unavailable('subject')
        collections = get(index, 'collections.' + kind, list)
        matching = [c for c in collections if isinstance(c, dict) and c.get('scope') == scope]
        if (len(matching) != 1 or matching[0].get('status') != 'collected'
                or not isinstance(matching[0].get('items'), list)
                or sum(isinstance(r, dict) and r.get('name') == name for r in matching[0]['items']) != 1
                or item not in matching[0]['items']):
            raise Unavailable('inventory')
        marker = get(item, MARKER, dict)
        if (set(marker) != {'schema', 'identity', 'scope', 'kind', 'complete', 'surfaces', 'leaks', 'verification', 'revision'}
                or marker['schema'] != SCHEMA or marker['identity'] != name or marker['scope'] != scope
                or marker['kind'] != kind or marker['complete'] is not True or marker['verification'] != 'not_attempted'):
            raise Unavailable('projection')
        if kind == WORKFLOW:
            if (not isinstance(marker['revision'], str) or not REVISION.fullmatch(marker['revision'])
                    or get(item, 'revisionId', str) != marker['revision']):
                raise Unavailable('revision')
            expected_paths = ['sourceContents']
        elif kind == APPENGINE:
            if marker['revision'] is not None:
                raise Unavailable('revision')
            expected_paths = ['envVariables', 'buildEnvVariables']
        else:
            targets = set(item) & {'httpTarget', 'appEngineHttpTarget', 'pubsubTarget'}
            if len(targets) != 1 or marker['revision'] is not None:
                raise Unavailable('target')
            target = next(iter(targets))
            expected_paths = [target + '.' + p for p in (('attributes', 'data') if target == 'pubsubTarget' else ('headers', 'body'))]
        surfaces = marker['surfaces']
        if (not isinstance(surfaces, list) or [s.get('surface') for s in surfaces if isinstance(s, dict)] != expected_paths):
            raise Unavailable('surfaces')
        engines = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        total = 0
        for surface in surfaces:
            if (set(surface) != {'surface', 'bytes', 'complete', 'engines'} or surface['complete'] is not True
                    or type(surface['bytes']) is not int or not 0 <= surface['bytes'] <= MAX_ROW_BYTES
                    or not isinstance(surface['engines'], list) or len(surface['engines']) != 2):
                raise Unavailable('coverage')
            total += surface['bytes']
            pair = surface['engines']
            if (any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                    or e.get('version') != engines.get(e.get('engine')) or e.get('status') != 'complete' for e in pair)
                    or {e['engine'] for e in pair} != set(engines)):
                raise Unavailable('pinned pair')
        if total > MAX_ROW_BYTES:
            raise Unavailable('bytes')
        if not isinstance(marker['leaks'], list) or len(marker['leaks']) > MAX_LEAKS:
            raise Unavailable('leak bound')
        leaks = merge_leaks(marker['leaks'])
        if sum(len(x['locations']) for x in leaks) > MAX_LEAK_LOCATIONS:
            raise Unavailable('location bound')
        for leak in leaks:
            if any(set(loc) - {'path', 'line'} or loc['path'] not in expected_paths for loc in leak['locations']):
                raise Unavailable('location')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
            'surfaces': deepcopy(surfaces), 'native_subject': name, 'revision': marker['revision']}
        if leaks:
            return 'FAIL', {**evidence, 'observed': ' '.join(DECLARATIONS[kind]['evidence_sentences'])}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors found no supported secret in the returned ' + LABELS[kind].lower() + '. Other configuration and managed secret values were not assessed.'}
    except (Unavailable, KeyError, ValueError, TypeError, AttributeError):
        return 'UNKNOWN', {'observed': 'Literal scanning is disabled, incomplete, unreadable or unbound; secret absence could not be assessed.'}


def scheduler(item, index):
    return evaluate(item, index, SCHEDULER)


def appengine(item, index):
    return evaluate(item, index, APPENGINE)


def workflow(item, index):
    return evaluate(item, index, WORKFLOW)


CALLBACKS = {SCHEDULER: scheduler, APPENGINE: appengine, WORKFLOW: workflow}


def install():
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    fixtures = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_additional_literal_secret_fixtures.json.gz').read_bytes()))
    evaluators = {SCHEDULER: scheduler, APPENGINE: appengine, WORKFLOW: workflow}
    existing = {c.id for c in CHECKS}
    for kind, declaration in DECLARATIONS.items():
        if declaration['id'] in existing:
            continue
        register(declaration['id'], 'gcp', 'hardening', kind, declaration['title'], 'high',
                 'security_configuration', declaration['remediation'],
                 dependencies=declaration['dependencies'])(evaluators[kind])
        CASES[declaration['id']] = deepcopy(fixtures[declaration['id']])
