"""Independent pure CSR selected-file consumer; explicit idempotent install only."""
from copy import deepcopy
import hashlib
import json
import re

from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.gcp_sourcerepo_secret_indicators import KIND, MARKER, SCHEMA

CHECK_ID = 'gcp.review.sourcerepo.selected_file_secret_indicators'
DECLARATION = {
    'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'requirements': [],
    'dependencies': ['project', KIND],
    'title': 'Selected Source Repository files have no detected secrets',
    'remediation': 'Remove credential literals from selected repository files and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in an explicitly selected repository file.',
                           'The value is hidden; offline detection did not validate the credential.'],
}


def _envelope(index, kind, scope):
    rows = [e for e in index['collections'][kind] if isinstance(e, dict) and e.get('scope') == scope]
    if (len(rows) != 1 or rows[0].get('status') != 'collected'
            or rows[0].get('coverage_status') != 'collected' or not isinstance(rows[0].get('items'), list)):
        raise ValueError('collection')
    return rows[0]


def _sha(value, count):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(count) + '}', value) is not None


def evaluate(item, index):
    try:
        ctx = index['context']
        scope = ctx['scope']
        if (ctx['provider'] != 'gcp' or not isinstance(scope, str)
                or not re.fullmatch(r'projects/[a-z][a-z0-9-]{4,28}[a-z0-9]', scope)
                or ctx['metadata']['source_repository_file_authorized'] is not True):
            raise ValueError('authorization')
        own, project = _envelope(index, KIND, scope), _envelope(index, 'project', scope)
        m = item[MARKER]
        if (set(m) != {'schema', 'complete', 'scope', 'selection', 'repository', 'files', 'leaks',
                       'native_requests', 'read_receipts', 'source_requests', 'reason', 'verification', 'content_accounting'}
                or m['schema'] != SCHEMA or m['scope'] != scope or type(m['complete']) is not bool
                or (m['reason'] != 'complete' if m['complete'] else m['reason'] not in {
                    'detectors_incomplete', 'content_deadline', 'unsupported_text', 'unsupported_binary',
                    'finding_limit', 'source_unavailable'}) or m['verification'] != 'not_attempted'
                or len(own['items']) != 1 or own['items'][0] != item):
            raise ValueError('incomplete')
        selected = m['selection']
        if not isinstance(selected, dict) or set(selected) != {'repository', 'commit', 'paths_sha256'}:
            raise ValueError('selection')
        repo = selected['repository']
        match = re.fullmatch(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/repos/([A-Za-z0-9_.-]{1,100})', repo)
        if (match is None or 'projects/' + match[1] != scope or match[2] in ('.', '..')
                or not _sha(selected['commit'], 40) or selected['commit'] == '0' * 40
                or not isinstance(selected['paths_sha256'], list) or not 1 <= len(selected['paths_sha256']) <= 8
                or any(not _sha(h, 64) for h in selected['paths_sha256'])
                or len(set(selected['paths_sha256'])) != len(selected['paths_sha256'])
                or ctx['metadata']['source_repository_file_selection'] != selected):
            raise ValueError('selector binding')
        expected_name = 'sourcerepo-selected-files:' + hashlib.sha256(json.dumps(selected,
            sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        if item['name'] != expected_name:
            raise ValueError('selector identity')
        if m['repository'] != {'name': repo, 'url': 'https://source.developers.google.com/p/' + match[1] + '/r/' + match[2]}:
            raise ValueError('native repository')
        if len(project['items']) != 1:
            raise ValueError('project count')
        p = project['items'][0]
        if (p.get('projectId') != match[1] or not isinstance(p.get('name'), str)
                or not re.fullmatch(r'projects/[1-9][0-9]{0,19}', p['name'])
                or 'projectNumber' in p and p['projectNumber'] != p['name'].split('/')[1]
                or set(p.get('_coverage', {})) & {'name', 'projectId', 'projectNumber', '*'}):
            raise ValueError('native project')
        native, refs, receipts = m['native_requests'], m['source_requests'], m['read_receipts']
        if (not isinstance(refs, list) or len(refs) != 4 or len(set(refs)) != 4
                or any(not isinstance(r, str) or not re.fullmatch(r'request-[1-9][0-9]*', r) for r in refs)
                or set(own.get('source_requests', [])) != set(refs)
                or not isinstance(native, list) or len(native) != 1
                or native[0] not in p.get('_provenance', {}).get('source_requests', [])
                or native[0] not in project.get('source_requests', [])
                or p.get('_provenance', {}).get('scope') != scope
                or not isinstance(receipts, list) or len(receipts) != 3):
            raise ValueError('provenance')
        if (set(item.get('_provenance', {}).get('source_requests', [])) != set(refs)
                or item.get('_provenance', {}).get('scope') != scope
                or item.get('_coverage', {}).get(MARKER) != {'status': 'collected' if m['complete'] else 'unknown', 'source_requests': refs}):
            raise ValueError('item provenance')
        git_owner = 'sourcerepo-content:' + hashlib.sha256((repo + ':' + selected['commit']).encode()).hexdigest()
        expected = [('GET', 'sourcerepo.repos.get.selected_files', expected_name, 16384, 'csr_native_repo_name_url_v1'),
                    ('GET', 'sourcerepo.git.advertise', git_owner, 262144, 'csr_git_advertisement_v0'),
                    ('POST', 'sourcerepo.git.upload_pack', git_owner, 8388608 - 262144, 'csr_git_upload_pack_v0')]
        ids = []
        for receipt, (method, operation, owner, limit, route) in zip(receipts, expected):
            if (set(receipt) != {'id', 'scope', 'method', 'operation', 'resource_id', 'status', 'http_status', 'bytes', 'route', 'final_route_verified'}
                    or receipt['scope'] != scope or receipt['method'] != method or receipt['operation'] != operation
                    or receipt['route'] != route or receipt['final_route_verified'] is not True
                    or receipt['resource_id'] != owner or receipt['status'] != 'collected'
                    or type(receipt['http_status']) is not int or receipt['http_status'] != 200
                    or type(receipt['bytes']) is not int or not 1 <= receipt['bytes'] <= limit):
                raise ValueError('receipt')
            ids.append(receipt['id'])
        if len(set(ids)) != 3 or set(ids) & set(native) or set(ids) | set(native) != set(refs):
            raise ValueError('receipt ownership')
        files = m['files']
        if (not isinstance(files, list) or not 1 <= len(files) <= len(selected['paths_sha256'])
                or m['complete'] and len(files) != len(selected['paths_sha256'])):
            raise ValueError('files')
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        total = 0
        for file, path_hash in zip(files, selected['paths_sha256']):
            if (set(file) != {'path_sha256', 'blob_sha1', 'bytes', 'complete', 'engines', 'identity'}
                    or file['path_sha256'] != path_hash or not _sha(file['blob_sha1'], 40)
                    or file['blob_sha1'] == '0' * 40 or type(file['complete']) is not bool
                    or m['complete'] and file['complete'] is not True
                    or type(file['bytes']) is not int or not 0 <= file['bytes'] <= 262144):
                raise ValueError('blob binding')
            blob_id = 'sourcerepo-selected-blob:' + hashlib.sha256(json.dumps(
                [repo, selected['commit'], path_hash, file['blob_sha1'], file['bytes']],
                separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
            if file['identity'] != blob_id:
                raise ValueError('blob identity')
            total += file['bytes']
            engines = file['engines']
            if (not isinstance(engines, list) or len(engines) != 2
                    or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                           or e.get('engine') not in versions or e.get('version') != versions.get(e.get('engine'))
                           or e.get('status') not in ('complete', 'unavailable') for e in engines)
                    or {e['engine'] for e in engines} != set(versions)):
                raise ValueError('detectors')
            if file['complete'] != all(engine['status'] == 'complete' for engine in engines):
                raise ValueError('detector completeness')
        if total > 2097152 or not isinstance(m['leaks'], list) or len(m['leaks']) > 256:
            raise ValueError('budget')
        accounting = m['content_accounting']
        if (set(accounting) != {'commit_sha', 'object_count', 'inflated_bytes', 'wire_bytes', 'selected_bytes'}
                or accounting['commit_sha'] != selected['commit']
                or (accounting['selected_bytes'] != total if m['complete'] else
                    not total <= accounting['selected_bytes'] <= 2097152)
                or any(type(accounting[k]) is not int for k in ('object_count', 'inflated_bytes', 'wire_bytes', 'selected_bytes'))
                or not 1 <= accounting['object_count'] <= 4096
                or not total <= accounting['inflated_bytes'] <= 16777216
                or not 32 <= accounting['wire_bytes'] <= 8388608
                or receipts[2]['bytes'] != accounting['wire_bytes'] + 8):
            raise ValueError('parser accounting')
        leaks = merge_leaks(m['leaks'])
        valid_paths = {'sourcerepo.selected_file.' + file['path_sha256'] for file in files}
        if (leaks != m['leaks'] or sum(len(l['locations']) for l in leaks) > 512
                or any(set(loc) - {'path', 'line'} or loc['path'] not in valid_paths
                       for leak in leaks for loc in leak['locations'])):
            raise ValueError('finding binding')
        # Each reported location needs a completed detector that actually
        # participated in this leak's detector union. Never infer a positive
        # from the unavailable engine or an uninspected selected path.
        completed = {'sourcerepo.selected_file.' + file['path_sha256']:
                     {engine['engine'] for engine in file['engines'] if engine['status'] == 'complete'}
                     for file in files}
        if any(not completed[loc['path']].intersection(detector['engine'] for detector in leak['detectors'])
               for leak in leaks for loc in leak['locations']):
            raise ValueError('positive detector binding')
        if not m['complete'] and not leaks:
            raise ValueError('incomplete negative')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
                    'complete': m['complete'], 'coverage': 'selected_files_at_advertised_commit_only',
                    'commit': selected['commit'], 'files': deepcopy(files), 'source_requests': list(refs)}
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in an explicitly selected repository file. The value is hidden; offline detection did not validate the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed without detecting a supported secret in the exact selected text files at the advertised commit. This does not establish repository or history secret absence.'}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return 'UNKNOWN', {'observed': 'Selected repository file inspection is disabled, unsupported, incomplete or unbound; secret absence could not be assessed.'}


def install():
    """Explicit, idempotent registration; no import-time installation."""
    import gzip
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    register(CHECK_ID, 'gcp', 'hardening', KIND, DECLARATION['title'], 'high',
             'security_configuration', DECLARATION['remediation'],
             dependencies=DECLARATION['dependencies'])(evaluate)
    CASES[CHECK_ID] = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_sourcerepo_secret_review_20261019_fixtures.json.gz').read_bytes()))
