"""Selected Cloud Run worker pool revision declarations and immutable OCI bytes."""
from copy import deepcopy
import hashlib
import json
import re
import time
from urllib.parse import quote

from . import gcp_image_secret_indicators as native
from .gcp_image_stream_inspection_20261021 import inspect_image, _interrupt
from .gcp_image_stream_reader_20261021 import Reader

SCHEMA = 'gcp-worker-pool-selected-image-native-v1'
POOL_FIELDS = 'name,uid,generation,observedGeneration,reconciling,deleteTime,terminalCondition(state),latestReadyRevision,latestCreatedRevision,etag,instanceSplitStatuses(type,revision,percent)'
REV_FIELDS = 'name,uid,generation,observedGeneration,reconciling,deleteTime,service,conditions(type,state),containers(image)'
REPO_FIELDS = 'name,format,mode,updateTime'
IMAGE_FIELDS = 'name,uri,mediaType,updateTime'
PROJECT_FIELDS = 'name,projectId,state'
MAX_BODY = 32768
MAX_CALLS = 40
MAX_SECONDS = 180
POOL = re.compile(r'projects/([a-z][a-z0-9-]{0,62})/locations/([a-z][a-z0-9-]{0,62})/workerPools/([a-z][a-z0-9-]{0,62})')


def _session():
    import requests
    session = requests.Session()
    session.trust_env, session.auth = False, None
    return session


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def selections(values, scope):
    need(type(scope) is str and re.fullmatch(r'projects/[a-z][a-z0-9-]{0,62}', scope), 'exact project required')
    need(type(values) is list and 1 <= len(values) <= 4, 'one to four selections required')
    out, seen = [], set()
    for v in values:
        need(type(v) is dict and set(v) == {'pool_name', 'pool_uid', 'revision_name', 'revision_uid', 'container_index', 'immutable_reference'}, 'closed selection required')
        pool = v['pool_name']
        need(type(pool) is str and len(pool) <= 512 and POOL.fullmatch(pool) and pool.startswith(scope + '/'), 'foreign pool')
        need(type(v['pool_uid']) is str and re.fullmatch(r'[0-9a-f-]{36}', v['pool_uid']), 'pool UID required')
        need(type(v['revision_uid']) is str and re.fullmatch(r'[0-9a-f-]{36}', v['revision_uid']), 'revision UID required')
        need(type(v['revision_name']) is str and len(v['revision_name']) <= 512 and re.fullmatch(re.escape(pool) + r'/revisions/[a-z][a-z0-9-]{0,62}', v['revision_name']), 'foreign revision')
        need(type(v['container_index']) is int and 0 <= v['container_index'] < 10, 'container index bound')
        need(type(v['immutable_reference']) is str and len(v['immutable_reference']) <= 512 and not v['immutable_reference'].startswith('https://'), 'literal digest required')
        uri, repo, digest, image_name = native.parse_image_uri(v['immutable_reference'])
        need(repo.startswith(scope + '/') and v['immutable_reference'] == v['immutable_reference'].lower(), 'foreign image repository')
        key = pool, v['revision_name'], v['container_index']
        need(key not in seen, 'duplicate selection')
        seen.add(key)
        out.append(deepcopy(v))
    return out


def requests_for(v, scope):
    uri, repo, digest, image_name = native.parse_image_uri(v['immutable_reference'])
    return [('https://run.googleapis.com/v2/' + v['pool_name'], POOL_FIELDS),
            ('https://run.googleapis.com/v2/' + v['revision_name'], REV_FIELDS),
            ('https://cloudresourcemanager.googleapis.com/v3/' + scope, PROJECT_FIELDS),
            ('https://artifactregistry.googleapis.com/v1/' + repo, REPO_FIELDS),
            ('https://artifactregistry.googleapis.com/v1/' + repo + '/dockerImages/' + quote(image_name, safe=''), IMAGE_FIELDS)]


def bind(v, scope, bodies):
    pool, revision, project, repository, image = bodies
    need(type(pool) is dict and pool.get('name') == v['pool_name'] and pool.get('uid') == v['pool_uid'], 'pool identity changed')
    need(not pool.get('deleteTime') and pool.get('reconciling', False) is False and pool.get('generation') == pool.get('observedGeneration') and pool.get('generation'), 'pool not reconciled')
    need(pool.get('terminalCondition', {}).get('state') == 'CONDITION_SUCCEEDED' and pool.get('latestReadyRevision') == pool.get('latestCreatedRevision'), 'pool terminal condition incomplete')
    need(type(pool.get('instanceSplitStatuses')) is list and 1 <= len(pool['instanceSplitStatuses']) <= 16, 'observed splits unavailable')
    total, selected, seen_revisions = 0, None, set()
    for split in pool['instanceSplitStatuses']:
        need(type(split) is dict and split.get('type') in ('INSTANCE_SPLIT_ALLOCATION_TYPE_LATEST', 'INSTANCE_SPLIT_ALLOCATION_TYPE_REVISION') and type(split.get('percent')) is int and 0 <= split['percent'] <= 100, 'invalid observed split')
        total += split['percent']
        if split['percent']:
            revision_name = split.get('revision')
            need(type(revision_name) is str and re.fullmatch(re.escape(v['pool_name']) + r'/revisions/[a-z][a-z0-9-]*', revision_name) and revision_name not in seen_revisions, 'foreign or duplicate observed revision')
            seen_revisions.add(revision_name)
            if split['type'] == 'INSTANCE_SPLIT_ALLOCATION_TYPE_LATEST':
                need(revision_name == pool['latestReadyRevision'], 'latest observed revision differs')
        if split['percent'] and split.get('revision') == v['revision_name']:
            need(selected is None, 'duplicate revision split')
            selected = split['percent']
            if split['type'] == 'INSTANCE_SPLIT_ALLOCATION_TYPE_LATEST':
                need(pool.get('latestReadyRevision') == v['revision_name'], 'latest revision changed')
    need(total == 100 and selected is not None, 'selected revision absent from observed positive splits')
    need(type(revision) is dict and revision.get('name') == v['revision_name'] and revision.get('uid') == v['revision_uid'] and revision.get('service') in (None, v['pool_name']), 'revision owner changed')
    need(not revision.get('deleteTime') and revision.get('reconciling', False) is False and revision.get('generation') == revision.get('observedGeneration') and revision.get('generation'), 'revision not reconciled')
    need(any(c.get('type') == 'Ready' and c.get('state') == 'CONDITION_SUCCEEDED' for c in revision.get('conditions', []) if type(c) is dict), 'revision not ready')
    containers = revision.get('containers')
    need(type(containers) is list and 1 <= len(containers) <= 10 and v['container_index'] < len(containers), 'container absent')
    need(type(containers[v['container_index']]) is dict and containers[v['container_index']].get('image') == v['immutable_reference'], 'container digest differs')
    need(type(project) is dict and project.get('projectId') == scope.split('/')[1] and project.get('state') == 'ACTIVE' and re.fullmatch(r'projects/[0-9]+', project.get('name', '')), 'project identity differs')
    from peaso import oci_index_20261021 as oci_index
    need(type(repository) is dict and repository.get('mode') in (None, 'STANDARD_REPOSITORY') and type(image) is dict and image.get('uri') == v['immutable_reference'] and image.get('mediaType') in oci_index.ALL_MANIFEST_TYPES, 'registry metadata missing or differs')
    uri, repo, digest = native.bind_image({**image, 'repository': repository.get('name'), 'digest': native.parse_image_uri(v['immutable_reference'])[2]}, scope, [repository], [project])
    need(uri == native.parse_image_uri(v['immutable_reference'])[0], 'image metadata differs')
    return {'worker_pool': v['pool_name'], 'pool_uid': v['pool_uid'], 'revision': v['revision_name'], 'revision_uid': v['revision_uid'], 'container_index': v['container_index'], 'observed_split_percent': selected, 'immutable_reference': v['immutable_reference'], 'runtime_image_proven': False}, {**image, 'repository': repo, 'digest': digest}


class Capture:
    def __init__(self, transport, session, scope):
        self.transport, self.session, self.scope = transport, session, scope
        self.end = time.monotonic() + MAX_SECONDS
        self.records, self.captures = [], []

    def get(self, url, fields):
        self.transport.check_cancelled()
        need(len(self.records) < MAX_CALLS and time.monotonic() < self.end, 'metadata bounds')
        need(url.startswith(('https://run.googleapis.com/v2/', 'https://cloudresourcemanager.googleapis.com/v3/', 'https://artifactregistry.googleapis.com/v1/')) and url.count('://') == 1, 'foreign metadata host')
        receipt = {'method': 'GET', 'url': url, 'scope': self.scope, 'query': {'fields': fields}, 'operation': 'cloudrun_worker_pool_selected_image_metadata_get', 'status': 'unavailable', 'http_attempts': 0}
        response = None
        try:
            with self.transport.lock:
                self.transport.check_cancelled()
                need(self.transport.max_calls is None or self.transport.calls < self.transport.max_calls, 'native call budget')
                self.transport.calls += 1
            auth = self.transport.credentials.headers().get('Authorization')
            need(type(auth) is str and re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', auth), 'access token unavailable')
            if hasattr(self.session, 'cookies'):
                self.session.cookies.clear()
            receipt['http_attempts'] = 1
            response = self.session.request('GET', url, params={'fields': fields}, headers={'Authorization': auth, 'Accept': 'application/json', 'Accept-Encoding': 'identity'}, stream=True, allow_redirects=False, timeout=min(10, self.transport.timeout, max(.001, self.end-time.monotonic())))
            import requests
            expected = requests.Request('GET', url, params={'fields': fields}).prepare().url
            receipt['http_status'] = response.status_code
            need(response.status_code == 200 and response.url == expected and not response.history and response.headers.get('Content-Encoding', 'identity') == 'identity' and response.headers.get('WWW-Authenticate') is None, 'metadata response denied or redirected')
            length = response.headers.get('Content-Length')
            need(length is None or type(length) is str and length.isdecimal() and int(length) <= MAX_BODY, 'metadata length bound')
            raw = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                self.transport.check_cancelled()
                need(type(chunk) is bytes and len(raw)+len(chunk) <= MAX_BODY, 'metadata truncated or oversized')
                raw.extend(chunk)
            need(length is None or len(raw) == int(length), 'metadata truncated')
            body = native._json(bytes(raw))
            need(type(body) is dict, 'native object required')
            receipt.update(status='collected', bytes=len(raw), body_sha256=hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
            self.captures.append({'url': url, 'fields': fields, 'body': deepcopy(body), 'body_sha256': receipt['body_sha256']})
            return body
        finally:
            if response is not None:
                if response.status_code in (401, 403): receipt['status'] = 'denied'
                response.close()
            with self.transport.lock:
                if not hasattr(self.transport, 'evidence'): self.transport.evidence = []
                receipt['id'] = 'request-' + str(len(self.transport.evidence)+1)
                self.transport.evidence.append(receipt)
                self.records.append(deepcopy(receipt))


def collect_native(transport, *, scope, selectors, enabled=False, metadata_session=None, image_session=None,
                   match_callback=None):
    result = {'schema': SCHEMA, 'scope': scope, 'status': 'UNKNOWN', 'complete': False, 'rows': [], 'source_requests': [], 'metadata_captures': []}
    if enabled is not True: return result
    targets = selections(selectors, scope)  # before credentials or sessions
    metadata_session = metadata_session or _session()
    image_session = image_session or _session()
    capture = Capture(transport, metadata_session, scope)
    reader = Reader(transport, session=image_session)
    reader.end = min(reader.end, capture.end)
    try:
        for target in targets:
            row = {'selection': target, 'status': 'UNKNOWN', 'complete': False, 'association_revalidated': False, 'content': {'complete': False, 'leaks': []}, 'source_requests': []}
            result['rows'].append(row)
            start, image_start, capture_start = len(capture.records), len(reader.request_ids), len(capture.captures)
            try:
                reqs = requests_for(target, scope)
                before = [capture.get(*req) for req in reqs]
                declaration, image = bind(target, scope, before)
                row['declaration'] = declaration
                row['content'] = inspect_image(image, scope, [before[3]], [before[2]], reader,
                                               match_callback=match_callback,
                                               capture_resource_id=target['revision_name'] + '#container=' + str(target['container_index']))
                after = [capture.get(*req) for req in reqs]
                bind(target, scope, after)
                need(before == after, 'source metadata drift')
                row['association_revalidated'] = True
                row['complete'] = row['content']['complete']
                row['status'] = 'FAIL' if row['content']['leaks'] else 'PASS' if row['complete'] else 'UNKNOWN'
            except Exception as exc:
                if _interrupt(exc):
                    raise
                pass
            finally:
                row['source_requests'] = [r['id'] for r in capture.records[start:]] + reader.request_ids[image_start:]
                row['metadata_captures'] = deepcopy(capture.captures[capture_start:])
        result['complete'] = all(r['complete'] for r in result['rows'])
        result['status'] = 'FAIL' if any(r['status'] == 'FAIL' for r in result['rows']) else 'PASS' if result['complete'] else 'UNKNOWN'
    finally:
        result['metadata_captures'] = deepcopy(capture.captures)
        result['source_requests'] = deepcopy(capture.records) + [deepcopy(r) for r in getattr(transport, 'evidence', []) if r.get('id') in reader.request_ids]
        for session in (metadata_session, image_session):
            try: session.close()
            except Exception:
                result['complete'] = False
                if result['status'] != 'FAIL': result['status'] = 'UNKNOWN'
    return result
