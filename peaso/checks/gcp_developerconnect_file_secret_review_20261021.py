"""Pure selected Developer Connect file evidence consumer."""
from copy import deepcopy
import hashlib
import json
import re

from peaso.collectors import gcp_developerconnect_file_native_20261021 as source
from peaso.secret_scanning import KINGFISHER_VERSION, TRUFFLEHOG_VERSION, merge_leaks

CHECK_ID, KIND = source.CHECK_ID, source.KIND


def need(ok):
    if not ok: raise ValueError('unbound selected file evidence')


def evaluate(item, index):
    try:
        context = index['context']
        scope = context['scope']
        need(context['provider'] == 'gcp' and source.PROJECT.fullmatch(scope))
        proof = item[source.MARKER]
        row = proof['row']
        target = row['target']
        need(proof['schema'] == source.SCHEMA and proof['scope'] == scope and target in context['metadata'][source.OPTION])
        name = 'developerconnect-selected-file:' + hashlib.sha256(json.dumps(target, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        need(name == row['resource_id'] == item['name'] == item['_resource_id'] == item['native_id'])
        need(target['link_name'].startswith(scope + '/') and source.LINK.fullmatch(target['link_name']))
        need(re.fullmatch('[0-9a-f]{64}', target['path_sha256']) and source.HEX40.fullmatch(target['blob_sha']))
        collection = [c for c in index['collections'][KIND] if c['scope'] == scope]
        need(len(collection) == 1 and item in collection[0]['items'])
        ids = row['source_requests']
        ledger = {r['id']: r for r in context['metadata']['source_requests']}
        need(len(ledger) == len(context['metadata']['source_requests']) and len(ids) == len(set(ids)) and set(ids) <= set(ledger)
             and ids == proof['source_requests'] == item['_provenance']['source_requests'])
        if row['association_revalidated'] is not True:
            need(row['status'] == 'UNKNOWN')
            return 'UNKNOWN', {'observed':
                'The selected repository file could not be associated with a stable project and repository link.'}
        need(len(ids) == (8 if target['provider'] == 'bitbucket' else 7) and len(row['native_captures']) == 2 and row['native_captures'][0] == row['native_captures'][1])
        link, project = row['native_captures'][0]
        source.bind_native(target, scope, link, project)
        for rid, body in zip(ids[:2]+ids[-2:], row['native_captures'][0]+row['native_captures'][1]):
            canonical = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
            need(ledger[rid].get('body_sha256') == source.sha256(canonical))
        need(link['name'] == target['link_name'] and link['uid'] == target['link_uid'] and link['cloneUri'] == target['clone_uri'] and link['reconciling'] is False)
        need(project['projectId'] == scope.split('/')[1] and project['state'] == 'ACTIVE' and re.fullmatch(r'projects/[0-9]+', project['name']))
        source.origin(target['clone_uri'])
        expected = [
            ('link', 'GET', 'developerconnect.googleapis.com', 'https://developerconnect.googleapis.com/v1/'+target['link_name']),
            ('project', 'GET', 'cloudresourcemanager.googleapis.com', 'https://cloudresourcemanager.googleapis.com/v3/'+scope),
            ('token', 'POST', 'developerconnect.googleapis.com', 'https://developerconnect.googleapis.com/v1/'+target['link_name']+':fetchReadToken'),
            ('commit', 'GET', {'github':'api.github.com','gitlab':'gitlab.com','bitbucket':'api.bitbucket.org'}[target['provider']], None),
            ('file', 'GET', {'github':'api.github.com','gitlab':'gitlab.com','bitbucket':'api.bitbucket.org'}[target['provider']], None),
            ('link', 'GET', 'developerconnect.googleapis.com', 'https://developerconnect.googleapis.com/v1/'+target['link_name']),
            ('project', 'GET', 'cloudresourcemanager.googleapis.com', 'https://cloudresourcemanager.googleapis.com/v3/'+scope),
        ]
        if target['provider'] == 'bitbucket':
            expected.insert(4, ('file_meta', 'GET', 'api.bitbucket.org', None))
            need(row.get('file_meta') == {'type':'commit_file', 'path_sha256':target['path_sha256'], 'size':row['content'].get('size')})
        for rid, (phase, method, host, url) in zip(ids, expected):
            receipt = ledger[rid]
            route_hash = target['commit_route_sha256'] if phase == 'commit' else target['file_route_sha256'] if phase in ('file','file_meta') else source.sha256(url.encode())
            need(receipt['operation'] == 'developerconnect_selected_'+phase and receipt['method'] == method and receipt['host'] == host
                 and receipt['scope'] == scope and receipt['route_sha256'] == route_hash and receipt['status'] == 'collected'
                 and receipt['http_status'] == 200 and receipt['http_attempts'] == 1)
            expected_query = {'fields':source.LINK_FIELDS} if phase == 'link' else {'fields':source.PROJECT_FIELDS} if phase == 'project' else {'format':'meta'} if phase == 'file_meta' else {'ref':target['commit_sha']} if phase == 'file' and target['provider'] in ('github','gitlab') else {}
            need(receipt['query'] == expected_query)
            if phase in ('token','file'): need('body_sha256' not in receipt)
        content = row['content']
        leaks = merge_leaks(content['leaks'])
        need(leaks == content['leaks'] and len(leaks) <= source.MAX_LEAKS and sum(len(x['locations']) for x in leaks) <= source.MAX_LOCATIONS)
        need(all(type(x.get('fingerprint')) is str and re.fullmatch('[0-9a-f]{64}', x['fingerprint']) and 'value' not in x and 'raw' not in x for x in leaks))
        need(content['blob_sha'] == target['blob_sha'] and type(content['size']) is int and 0 <= content['size'] <= source.MAX_FILE
             and re.fullmatch('[0-9a-f]{64}', content['bytes_sha256']))
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        engines = content['engines']
        need(type(engines) is list and len(engines) == 2 and {e['engine'] for e in engines} == set(versions)
             and all(e['version'] == versions[e['engine']] and e['status'] in ('complete','unavailable') for e in engines))
        if content['complete']: need(all(e['status'] == 'complete' for e in engines))
        status = 'FAIL' if leaks else 'PASS' if content['complete'] else 'UNKNOWN'
        need(status == row['status'] == content['status'] and row['complete'] == content['complete'])
        observed = {
            'FAIL': 'A likely secret was found in the selected repository file at its pinned commit. Its value is hidden.',
            'PASS': 'Both detectors found no supported secret in the selected file at its pinned Git blob.',
            'UNKNOWN': 'The selected file matched its pinned Git blob, but its contents could not be fully inspected.',
        }[status]
        return status, {'observed': observed, 'secret_leaks': deepcopy(leaks), 'source_requests': deepcopy(ids),
            'blob_sha': target['blob_sha'], 'path_sha256': target['path_sha256'], 'complete': status == 'PASS'}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return 'UNKNOWN', {'observed':
            'The selected repository file could not be associated with a verified link, commit and Git blob.'}


def install():
    from . import CHECKS, register
    if any(check.id == CHECK_ID for check in CHECKS): return
    from .fixtures import CASES
    from pathlib import Path
    import json
    native_cases = json.loads(Path(__file__).with_name('gcp_developerconnect_file_secret_review_20261021_cases.json').read_text())
    if set(native_cases) != {CHECK_ID} or CHECK_ID in CASES:
        raise RuntimeError('Selected native fixture collision or absence')
    CASES[CHECK_ID] = native_cases[CHECK_ID]
    register(CHECK_ID, 'gcp', 'hardening', KIND,
        'Selected Developer Connect repository file has no detected secrets', 'high', 'security_configuration',
        'Remove embedded secrets from the selected repository file and rotate affected credentials.',
        dependencies=[KIND], allow_incomplete_failure=True)(evaluate)
