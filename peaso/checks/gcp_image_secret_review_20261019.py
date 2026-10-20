"""Selected immutable-image content predicate with optional native Run bindings."""
from copy import deepcopy

from .facts import get, guard, Unavailable
from peaso.collectors.gcp_image_secret_indicators import (
    CHECK_ID, MARKER, SCHEMA, bind_image, DIGEST, MAX_LAYERS, MAX_EXPANDED, MAX_MEMBERS,
    MAX_LEAKS, MAX_LOCATIONS, MAX_CONFIG, MAX_LAYER, MAX_IMAGE, CONFIG_TYPES, TAR_TYPES,
)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

DECLARATION = {'id': CHECK_ID, 'provider': 'gcp', 'kind': 'artifact_image', 'category': 'hardening',
    'finding_type': 'secrets', 'title': 'Selected Artifact Registry image has no detected secrets',
    'severity': 'high', 'dependencies': ['artifact_image', 'artifact_repository', 'project'], 'requirements': [],
    'remediation': 'Remove literal secrets from image configuration and layers, rebuild the image, and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in the selected immutable image configuration or a layer.',
                           'The value is hidden; credentials were not validated.']}


def evaluate(item, index):
    try:
        scope = get(index, 'context.scope', str)
        if get(index, 'context.provider', str) != 'gcp': raise Unavailable('foreign provider')
        def rows(kind):
            envelopes = get(index, 'collections.' + kind, list)
            matching = [e for e in envelopes if isinstance(e, dict) and e.get('scope') == scope]
            if len(matching) != 1 or matching[0].get('status') != 'collected' or not isinstance(matching[0].get('items'), list):
                raise Unavailable('native collection incomplete')
            return matching[0]['items']
        images, repositories, projects = rows('artifact_image'), rows('artifact_repository'), rows('project')
        if item not in images or sum(row.get('uri') == item.get('uri') for row in images) != 1:
            raise Unavailable('native image membership ambiguous')
        uri, repo, digest = bind_image(item, scope, repositories, projects)
        from peaso.collectors.gcp_cloudrun_image_inspection import MARKER as RUN_MARKER, validate_proof
        run_paths = validate_proof(item, index, images, repositories, projects) if RUN_MARKER in item else None
        candidate = item.get(MARKER) if isinstance(item, dict) else None
        if isinstance(candidate, dict) and candidate.get('status') == 'partial':
            guard(item)
            coverage = item.get('_coverage', {}).get(MARKER)
            if coverage is not None and (not isinstance(coverage, dict)
                    or coverage.get('status') != 'partial'):
                raise Unavailable('partial marker coverage differs')
            marker = candidate
        else:
            marker = get(item, MARKER, dict)
        expected = {'schema', 'status', 'complete', 'uri', 'repository', 'manifest_digest', 'descriptors', 'layers_scanned',
                    'expanded_bytes', 'members', 'regular_files', 'engines', 'leaks', 'verification'}
        partial = marker.get('status') == 'partial' and marker.get('complete') is False
        if (set(marker) != (expected | {'inspected_digests', 'source_reports'} if partial else expected)
                or marker['schema'] != SCHEMA
                or not (partial or marker['status'] == 'collected' and marker['complete'] is True)
                or marker['uri'] != uri or marker['repository'] != repo
                or marker['manifest_digest'] != digest or marker['verification'] != 'not_attempted'
                or type(marker['expanded_bytes']) is not int or not 0 < marker['expanded_bytes'] <= MAX_EXPANDED
                or type(marker['members']) is not int or not 0 <= marker['members'] <= MAX_MEMBERS
                or type(marker['regular_files']) is not int or not 0 <= marker['regular_files'] <= marker['members']):
            raise Unavailable('immutable image coverage absent')
        descriptors = marker['descriptors']
        if not isinstance(descriptors, list) or not 2 <= len(descriptors) <= MAX_LAYERS + 1:
            raise Unavailable('image descriptors absent')
        for ordinal, descriptor in enumerate(descriptors):
            if (not isinstance(descriptor, dict) or set(descriptor) != {'digest', 'size', 'mediaType'} or descriptor.get('mediaType') not in (CONFIG_TYPES if ordinal == 0 else TAR_TYPES)
                    or not isinstance(descriptor.get('digest'), str) or not DIGEST.fullmatch(descriptor['digest'])
                    or type(descriptor.get('size')) is not int or not 0 < descriptor['size'] <= (MAX_CONFIG if ordinal == 0 else MAX_LAYER)):
                raise Unavailable('invalid image descriptor')
        if sum(d['size'] for d in descriptors) > MAX_IMAGE:
            raise Unavailable('image compressed coverage bound')
        layer_digests = [d['digest'] for d in descriptors[1:]]
        scanned = marker['layers_scanned']
        if (not isinstance(scanned, list) or scanned != layer_digests[:len(scanned)]
                or (not partial and scanned != layer_digests)):
            raise Unavailable('image layer coverage differs')
        if partial:
            inspected = marker['inspected_digests']
            expected_inspected = [descriptors[0]['digest']] + scanned
            if (not isinstance(inspected, list) or inspected not in
                    (expected_inspected, expected_inspected + layer_digests[len(scanned):len(scanned)+1])):
                raise Unavailable('partial observation lacks verified blob identity')
        else:
            inspected = [d['digest'] for d in descriptors]
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        engines = marker['engines']
        if (not isinstance(engines, list) or len(engines) != 2 or any(not isinstance(e, dict)
                or set(e) != {'engine', 'version', 'status'} or e.get('version') != versions.get(e.get('engine'))
                or e.get('status') not in (('complete', 'unavailable') if partial else ('complete',))
                for e in engines) or {e['engine'] for e in engines} != set(versions)):
            raise Unavailable('both offline detectors required')
        if not isinstance(marker['leaks'], list) or len(marker['leaks']) > MAX_LEAKS:
            raise Unavailable('leak result bound')
        leaks = merge_leaks(marker['leaks'])
        if sum(len(leak['locations']) for leak in leaks) > MAX_LOCATIONS:
            raise Unavailable('leak location bound')
        if any(location.get('layer') not in inspected for leak in leaks for location in leak['locations']):
            raise Unavailable('foreign layer observation')
        if partial and not leaks:
            raise Unavailable('incomplete negative cannot establish absence')
        if partial:
            reports = marker['source_reports']
            if not isinstance(reports, list) or not 1 <= len(reports) <= MAX_LOCATIONS:
                raise Unavailable('partial source reports absent or unbounded')
            engine_status = {engine['engine']: engine['status'] for engine in engines}
            expected_sources = {}
            for leak in leaks:
                for location in leak['locations']:
                    key = (location['layer'], location['path'], leak['fingerprint'])
                    expected_sources[key] = {detector['engine'] for detector in leak['detectors']}
            reported = set()
            for report in reports:
                if not isinstance(report, dict) or set(report) != {'layer', 'path', 'fingerprint', 'engines'}:
                    raise Unavailable('malformed partial source report')
                key = (report['layer'], report['path'], report['fingerprint'])
                if key in reported or key not in expected_sources:
                    raise Unavailable('foreign or repeated partial source report')
                reported.add(key)
                reporters = report['engines']
                if (not isinstance(reporters, list) or not 1 <= len(reporters) <= 2
                        or any(not isinstance(engine, dict) or set(engine) != {'engine', 'status'}
                            or engine.get('engine') not in versions or engine.get('status') != 'complete'
                            for engine in reporters)):
                    raise Unavailable('partial source lacks completed reporting detector')
                names = {engine['engine'] for engine in reporters}
                if len(names) != len(reporters) or not names <= expected_sources[key]:
                    raise Unavailable('partial report contradicts leak detectors')
                if key[0] == descriptors[0]['digest']:
                    if any(engine_status[name] != 'complete' for name in names):
                        raise Unavailable('config report contradicts config detector status')
                elif any(status != 'complete' for status in engine_status.values()):
                    # The collector does not enter a layer unless both config
                    # detectors completed; layer reports come from scan_tar's
                    # completed reporting detector, not a global layer ledger.
                    raise Unavailable('layer report contradicts config scan')
            if reported != set(expected_sources):
                raise Unavailable('partial source observation unreported')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted', 'image_uri': uri,
                    'complete': not partial, 'layers_scanned': len(scanned), 'regular_files': marker['regular_files']}
        if run_paths is not None:
            evidence['cloudrun_deployment_paths'] = run_paths
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in the selected immutable image configuration or a verified layer. The value is hidden; credentials were not validated.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed without finding a supported secret in the selected immutable image configuration and all supported layers.'}
    except (Unavailable, KeyError, TypeError, ValueError, AttributeError):
        return 'UNKNOWN', {'observed': 'Selected image content scanning is disabled, incomplete, unsupported or unbound; secret absence could not be assessed.'}


def install():
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    register(CHECK_ID, 'gcp', 'hardening', 'artifact_image', DECLARATION['title'], 'high',
             'security_configuration', DECLARATION['remediation'],
             dependencies=DECLARATION['dependencies'])(evaluate)
    case = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_image_secret_fixtures.json.gz').read_bytes()))['cases'][CHECK_ID]
    CASES[CHECK_ID] = {'missing': {}, 'malformed': None}
    for branch in ('pass', 'fail', 'unknown'):
        CASES[CHECK_ID][branch] = deepcopy(case[branch]['item'])
        CASES[CHECK_ID][branch + '_index'] = deepcopy(case[branch]['index'])
