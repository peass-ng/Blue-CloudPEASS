"""Pure check for complete digest-pinned explicitly selected native files."""
from copy import deepcopy
import re
from peaso.collectors import gcp_artifact_file_secret_indicators as a
from peaso.collectors import gcp_selected_archive_secret_indicators as archives
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID = 'gcp.review.artifactregistry.selected_file_secret_indicators'
DECLARATION = {'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': a.KIND,
    'finding_type': 'secrets', 'title': 'Selected Artifact Registry file has no detected secrets', 'severity': 'high',
    'dependencies': ['project', 'artifact_repository', a.KIND], 'requirements': [],
    'remediation': 'Remove exposed credentials from the selected file and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in an explicitly selected Artifact Registry file.',
                           'The value is hidden; detection did not validate the credential.']}


def evaluate(item, index):
    try:
        name, scope = item['name'], index['context']['scope']
        if (index['context']['provider'] != 'gcp' or not isinstance(scope, str) or not isinstance(name, str)
                or not re.fullmatch(r'artifact-selected-file:[0-9a-f]{64}', name)): raise ValueError('identity')
        matching = [e for e in index['collections'][a.KIND] if isinstance(e, dict) and e.get('scope') == scope
                    and e.get('status') == 'collected' and isinstance(e.get('items'), list) and item in e['items']
                    and sum(isinstance(r, dict) and r.get('name') == name for r in e['items']) == 1]
        if len(matching) != 1: raise ValueError('collection')
        coverage = item['_coverage'][a.MARKER]; refs = coverage['source_requests']
        if (coverage.get('status') not in ('collected', 'incomplete') or not isinstance(refs, list) or len(refs) != 2 or len(set(refs)) != 2
                or any(not isinstance(r, str) or not re.fullmatch(r'request-[1-9][0-9]*', r) for r in refs)
                or not set(refs) <= set(matching[0].get('source_requests', []))
                or not set(refs) <= set(item.get('_provenance', {}).get('source_requests', []))): raise ValueError('receipts')
        m = item[a.MARKER]
        if (set(m) != {'schema', 'identity', 'scope', 'format', 'complete', 'digest_verified', 'bytes', 'expanded_bytes',
                       'members', 'files', 'leaks', 'verification'}
                or m['schema'] != a.SCHEMA or m['identity'] != name or m['scope'] != scope or m['format'] not in a.FORMATS
                or type(m['complete']) is not bool or m['digest_verified'] is not True or m['verification'] != 'not_attempted'
                or type(m['bytes']) is not int or not 0 <= m['bytes'] <= a.MAX_FILE_BYTES
                or type(m['expanded_bytes']) is not int or not 0 <= m['expanded_bytes'] <= archives.MAX_EXPANDED_BYTES
                or type(m['members']) is not int or not 1 <= m['members'] <= archives.MAX_MEMBERS): raise ValueError('producer')
        if coverage['status'] != ('collected' if m['complete'] else 'incomplete'): raise ValueError('coverage')
        files = m['files']; expected = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        if not isinstance(files, list) or not 1 <= len(files) <= m['members']: raise ValueError('files')
        for i, f in enumerate(files, 1):
            path = 'artifact.content' if m['format'] == 'utf8' else 'archive.member-' + str(i)
            if (not isinstance(f, dict) or set(f) != {'path', 'bytes', 'engines'} or f['path'] != path
                    or type(f['bytes']) is not int or not 0 <= f['bytes'] <= archives.MAX_MEMBER_BYTES): raise ValueError('file')
            engines = f['engines']
            if (not isinstance(engines, list) or len(engines) != 2 or any(not isinstance(e, dict)
                    or set(e) != {'engine', 'version', 'status'} or e.get('engine') not in expected
                    or e.get('version') != expected.get(e.get('engine'))
                    or e.get('status') not in ('complete', 'unavailable') for e in engines)
                    or {e['engine'] for e in engines} != set(expected)): raise ValueError('engines')
        if sum(f['bytes'] for f in files) > m['expanded_bytes']: raise ValueError('expansion')
        if m['format'] == 'utf8' and (len(files) != 1 or m['members'] != 1 or m['expanded_bytes'] != m['bytes'] or files[0]['bytes'] != m['bytes']):
            raise ValueError('text coverage')
        if not isinstance(m['leaks'], list) or len(m['leaks']) > 256: raise ValueError('leaks')
        leaks = merge_leaks(m['leaks']); paths = {f['path'] for f in files}
        if sum(len(l['locations']) for l in leaks) > 512 or any(set(loc) - {'path', 'line'} or loc['path'] not in paths for l in leaks for loc in l['locations']):
            raise ValueError('locations')
        if not m['complete']:
            if not leaks: raise ValueError('partial negative')
            for f in files:
                if not any(e['status'] == 'complete' for e in f['engines']):
                    raise ValueError('no completed detector')
            for leak in leaks:
                for detector in leak['detectors']:
                    if not any(f['path'] == loc['path'] and any(e['engine'] == detector['engine'] and e['status'] == 'complete' for e in f['engines'])
                               for loc in leak['locations'] for f in files):
                        raise ValueError('unproven detector')
        elif any(e['status'] != 'complete' for f in files for e in f['engines']):
            raise ValueError('incomplete detector')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted', 'complete': m['complete'],
                    'digest_verified': True, 'format': m['format'], 'bytes': m['bytes'], 'files': deepcopy(files)}
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in an explicitly selected Artifact Registry file. The value is hidden; detection did not validate the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed on the full digest-verified selected file or all its supported text members without finding a supported secret.'}
    except (KeyError, TypeError, ValueError, AttributeError):
        return 'UNKNOWN', {'observed': 'Selected file scanning is disabled, incomplete, unreadable or unsupported; secret absence could not be assessed.'}


def install():
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS): return
    fixture = json.loads(gzip.decompress(Path(__file__).with_name('gcp_artifact_file_secret_fixtures.json.gz').read_bytes()))
    register(CHECK_ID, 'gcp', 'hardening', a.KIND, DECLARATION['title'], 'high', 'security_configuration',
             DECLARATION['remediation'], dependencies=DECLARATION['dependencies'])(evaluate)
    CASES[CHECK_ID] = fixture
