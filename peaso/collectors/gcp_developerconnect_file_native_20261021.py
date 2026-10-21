"""Explicit Developer Connect link to immutable public-provider Git blob bytes.

The only token mint is the documented read-token authorization RPC. Tokens and
raw file bytes stay in local variables and never enter receipts or snapshots.
"""
from copy import deepcopy
from datetime import datetime, timezone
import base64
import hashlib
import http.client
import json
import logging
import re
import time
from urllib.parse import quote

from peaso.secret_evidence import alias_path, scan_with_source, source_context
from peaso.secret_scanning import scan_content, merge_leaks

CHECK_ID = 'gcp.review.developerconnect.selected_repository_file_secret_indicators'
KIND = 'developerconnect_selected_file'
OPTION = 'selected_developerconnect_files'
MARKER = 'DeveloperConnectSelectedFileInspection'
SCHEMA = 'gcp-developerconnect-selected-file-v1'
MAX_TARGETS = 4
MAX_FILE = 1024 * 1024
MAX_HTTP = 2 * 1024 * 1024
MAX_CALLS = 32
MAX_SECONDS = 120
MAX_LEAKS = 256
MAX_LOCATIONS = 512
LINK_FIELDS = 'name,cloneUri,etag,reconciling,uid,deleteTime'
PROJECT_FIELDS = 'name,projectId,state'
PROJECT = re.compile(r'projects/([a-z][a-z0-9-]{0,62})\Z')
LINK = re.compile(r'projects/([a-z][a-z0-9-]{0,62})/locations/([a-z][a-z0-9-]{0,62})/connections/([A-Za-z][A-Za-z0-9_-]{0,62})/gitRepositoryLinks/([A-Za-z][A-Za-z0-9_-]{0,62})\Z')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
SEGMENT = re.compile(r'[A-Za-z0-9_.-]{1,100}\Z')
PATH = re.compile(r'[A-Za-z0-9_./-]{1,256}\Z')


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_blob_sha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def origin(clone_uri):
    need(type(clone_uri) is str and len(clone_uri) <= 512, 'clone URI bound')
    patterns = (
        ('github', r'https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?\Z'),
        ('gitlab', r'https://gitlab\.com/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)/([A-Za-z0-9_.-]+?)(?:\.git)?\Z'),
        ('bitbucket', r'https://bitbucket\.org/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?\Z'),
    )
    for provider, pattern in patterns:
        match = re.fullmatch(pattern, clone_uri)
        if match:
            owner, repo = match.groups()
            need(all(SEGMENT.fullmatch(part) and part not in ('.', '..') for part in owner.split('/') + [repo]), 'unsafe repository path')
            return provider, owner, repo
    raise ValueError('unsupported public repository origin')


def selections(values, scope):
    need(type(scope) is str and PROJECT.fullmatch(scope), 'one exact project required')
    need(type(values) is list and 1 <= len(values) <= MAX_TARGETS, 'one to four targets required')
    result, seen = [], set()
    keys = {'link_name', 'link_uid', 'clone_uri', 'provider', 'commit_sha', 'path', 'blob_sha'}
    for value in values:
        need(type(value) is dict and set(value) == keys, 'closed file selector required')
        link = value['link_name']
        need(type(link) is str and len(link) <= 512 and LINK.fullmatch(link) and link.startswith(scope + '/'), 'foreign link')
        need(type(value['link_uid']) is str and re.fullmatch(r'[0-9a-f-]{36}', value['link_uid']), 'link UID required')
        if value['provider'] == 'enterprise':
            from urllib.parse import urlsplit
            parsed = urlsplit(value['clone_uri']) if type(value['clone_uri']) is str else None
            need(parsed is not None and parsed.scheme == 'https' and parsed.hostname and parsed.port is None and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment
                 and re.fullmatch(r'[a-z0-9.-]{3,253}', parsed.hostname) and parsed.hostname not in ('github.com','gitlab.com','bitbucket.org')
                 and re.fullmatch(r'/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+(?:\.git)?', parsed.path), 'unsafe enterprise origin')
        else:
            provider, owner, repo = origin(value['clone_uri'])
            need(provider == value['provider'], 'provider origin mismatch')
        need(type(value['commit_sha']) is str and (HEX40.fullmatch(value['commit_sha']) and value['commit_sha'] != '0'*40
             or re.fullmatch(r'[A-Za-z][A-Za-z0-9._/-]{0,63}', value['commit_sha']) and '..' not in value['commit_sha'].split('/')), 'commit or unsupported branch required')
        need(type(value['blob_sha']) is str and HEX40.fullmatch(value['blob_sha']) and value['blob_sha'] != '0'*40, 'immutable blob required')
        path = value['path']
        need(type(path) is str and PATH.fullmatch(path) and all(part not in ('', '.', '..') for part in path.split('/')), 'unsafe selected path')
        key = link, value['commit_sha'], path
        need(key not in seen, 'duplicate target')
        seen.add(key)
        result.append(deepcopy(value))
    return result


def public_target(target):
    if target['provider'] == 'enterprise':
        commit_hash = file_hash = None
    else:
        commit_url, file_url, _, _ = routes(target)
        commit_hash, file_hash = sha256(commit_url.encode()), sha256(file_url.encode())
    return {key: target[key] for key in ('link_name', 'link_uid', 'clone_uri', 'provider', 'commit_sha', 'blob_sha')} | {'path_sha256': sha256(target['path'].encode()), 'commit_route_sha256': commit_hash, 'file_route_sha256': file_hash}


def resource_id(target):
    return 'developerconnect-selected-file:' + sha256(json.dumps(public_target(target), sort_keys=True, separators=(',', ':')).encode())


def routes(target):
    provider, owner, repo = origin(target['clone_uri'])
    commit, path = target['commit_sha'], target['path']
    if provider == 'github':
        base = 'https://api.github.com/repos/' + owner + '/' + repo
        return base + '/git/commits/' + commit, base + '/contents/' + quote(path, safe='/'), {'ref': commit}, 'api.github.com'
    if provider == 'gitlab':
        base = 'https://gitlab.com/api/v4/projects/' + quote(owner + '/' + repo, safe='')
        return base + '/repository/commits/' + commit, base + '/repository/files/' + quote(path, safe=''), {'ref': commit}, 'gitlab.com'
    base = 'https://api.bitbucket.org/2.0/repositories/' + owner + '/' + repo
    return base + '/commit/' + commit, base + '/src/' + commit + '/' + quote(path, safe='/'), {}, 'api.bitbucket.org'


def session():
    import requests
    current = requests.Session()
    current.trust_env = False
    current.auth = None
    return current


def safe_http_diagnostics():
    from urllib3.connection import HTTPSConnection
    need(not (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel or HTTPSConnection.debuglevel or logging.getLogger('urllib3.connectionpool').isEnabledFor(logging.DEBUG)), 'unsafe HTTP diagnostics')


class Capture:
    def __init__(self, transport, cloud_session, remote_session, scope):
        self.transport, self.cloud_session, self.remote_session, self.scope = transport, cloud_session, remote_session, scope
        self.end = time.monotonic() + MAX_SECONDS
        self.records, self.captures = [], []

    def check(self):
        self.transport.check_cancelled()
        need(time.monotonic() < self.end, 'content deadline')

    def request(self, *, phase, method, url, params=None, data=None, headers=None, cap=MAX_HTTP, secret_response=False):
        self.check()
        safe_http_diagnostics()
        need(len(self.records) < MAX_CALLS and type(url) is str, 'call bound')
        cloud = phase in ('project', 'link', 'token')
        if phase == 'project': need(url == 'https://cloudresourcemanager.googleapis.com/v3/' + self.scope and method == 'GET', 'project route')
        elif phase in ('link', 'token'):
            need(url.startswith('https://developerconnect.googleapis.com/v1/' + self.scope + '/') and method == ('POST' if phase == 'token' else 'GET'), 'link route')
        else:
            need(method == 'GET' and phase in ('commit', 'file', 'file_meta') and url.startswith(('https://api.github.com/', 'https://gitlab.com/api/v4/', 'https://api.bitbucket.org/2.0/')), 'remote route')
        receipt = {'method': method, 'operation': 'developerconnect_selected_' + phase, 'scope': self.scope,
            'route_sha256': sha256(url.encode()), 'host': url.split('/')[2], 'query': deepcopy(params or {}), 'status': 'unavailable', 'http_attempts': 0}
        response = None
        try:
            with self.transport.lock:
                self.transport.check_cancelled()
                need(self.transport.max_calls is None or self.transport.calls < self.transport.max_calls, 'global call bound')
                self.transport.calls += 1
            self.check()
            request_headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}
            if cloud:
                auth = self.transport.credentials.headers().get('Authorization')
                need(type(auth) is str and re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', auth), 'cloud authorization unavailable')
                request_headers['Authorization'] = auth
            else:
                need(type(headers) is dict and set(headers) in ({'Authorization'}, {'PRIVATE-TOKEN'}) and all(type(v) is str and 0 < len(v) <= 2048 for v in headers.values()), 'remote read token unavailable')
                request_headers.update(headers)
            if method == 'POST': request_headers['Content-Type'] = 'application/json'
            chosen = self.cloud_session if cloud else self.remote_session
            if hasattr(chosen, 'cookies'): chosen.cookies.clear()
            receipt['http_attempts'] = 1
            response = chosen.request(method, url, params=params, data=data, headers=request_headers, stream=True, allow_redirects=False,
                timeout=min(10, self.transport.timeout, max(.001, self.end-time.monotonic())))
            import requests
            expected = requests.Request(method, url, params=params).prepare().url
            receipt['http_status'] = response.status_code
            need(response.status_code == 200 and response.url == expected and not response.history and response.headers.get('Content-Encoding', 'identity') == 'identity' and response.headers.get('WWW-Authenticate') is None and response.headers.get('Content-Range') is None, 'untrusted or denied response')
            length = response.headers.get('Content-Length')
            need(length is None or type(length) is str and length.isdecimal() and int(length) <= cap, 'content length bound')
            raw = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                self.check()
                need(type(chunk) is bytes and len(chunk) <= 8192 and len(raw)+len(chunk) <= cap, 'content byte bound')
                raw.extend(chunk)
            need(length is None or len(raw) == int(length), 'truncated content')
            if phase not in ('file',) or receipt['host'] != 'api.bitbucket.org':
                need(response.headers.get('Content-Type', 'application/json').split(';')[0].lower() == 'application/json', 'JSON response required')
            receipt.update(status='collected', bytes=len(raw))
            if not secret_response:
                body = parse_json(bytes(raw))
                receipt['body_sha256'] = sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode())
            return bytes(raw)
        finally:
            if response is not None:
                if response.status_code in (401, 403): receipt['status'] = 'denied'
                response.close()
            with self.transport.lock:
                if not hasattr(self.transport, 'evidence'): self.transport.evidence = []
                receipt['id'] = 'request-' + str(len(self.transport.evidence)+1)
                self.transport.evidence.append(deepcopy(receipt))
                self.records.append(deepcopy(receipt))


def parse_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    data = json.loads(raw, object_pairs_hook=unique)
    need(type(data) is dict, 'native object required')
    return data


def bind_native(target, scope, link, project):
    need(type(link) is dict and set(link) <= {'name', 'cloneUri', 'etag', 'reconciling', 'uid', 'deleteTime'} and link.get('name') == target['link_name'] and link.get('uid') == target['link_uid'] and link.get('cloneUri') == target['clone_uri'] and not link.get('deleteTime') and link.get('reconciling', False) is False, 'link identity mismatch')
    need(type(project) is dict and set(project) <= {'name', 'projectId', 'state'} and project.get('projectId') == scope.split('/')[1] and project.get('state') == 'ACTIVE' and re.fullmatch(r'projects/[0-9]+', project.get('name', '')), 'project identity mismatch')
    origin(link['cloneUri'])
    return {'name': link['name'], 'uid': link['uid'], 'cloneUri': link['cloneUri'], 'etag': link.get('etag'), 'reconciling': False}, {'name': project['name'], 'projectId': project['projectId'], 'state': project['state']}


def token_response(raw):
    body = parse_json(raw)
    need(set(body) <= {'token', 'expirationTime', 'gitUsername'} and type(body.get('token')) is str and re.fullmatch(r'[A-Za-z0-9._~+/-]{16,2048}=*', body['token']), 'read token unavailable')
    expiry = body.get('expirationTime')
    need(type(expiry) is str and expiry, 'short-lived token expiry required')
    try: when = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
    except ValueError: raise ValueError('token expiry invalid') from None
    now = datetime.now(timezone.utc)
    need(when.tzinfo is not None and 30 <= (when-now).total_seconds() <= 3600, 'short-lived token required')
    return body['token']


def remote_headers(provider, token):
    if provider == 'gitlab': return {'PRIVATE-TOKEN': token}
    return {'Authorization': 'Bearer ' + token}


def bound_file(target, commit_body, file_raw, provider):
    commit = parse_json(commit_body)
    need(commit.get('sha' if provider == 'github' else 'id' if provider == 'gitlab' else 'hash') == target['commit_sha'], 'commit changed')
    if provider == 'bitbucket':
        payload = file_raw
    else:
        file = parse_json(file_raw)
        if provider == 'github':
            need(file.get('type') == 'file' and file.get('path') == target['path'] and file.get('sha') == target['blob_sha'] and file.get('encoding') == 'base64', 'GitHub file identity mismatch')
        else:
            need(file.get('file_path') == target['path'] and file.get('ref') == target['commit_sha'] and file.get('blob_id') == target['blob_sha'] and file.get('encoding') == 'base64', 'GitLab file identity mismatch')
        encoded = file.get('content')
        need(type(encoded) is str and len(encoded) <= 2*MAX_FILE, 'encoded file bound')
        try: payload = base64.b64decode(encoded.replace('\n', '').replace('\r', ''), validate=True)
        except Exception: raise ValueError('invalid base64 file') from None
        need(file.get('size') == len(payload), 'file size mismatch')
    need(type(payload) is bytes and len(payload) <= MAX_FILE and git_blob_sha(payload) == target['blob_sha'], 'immutable blob mismatch')
    return payload


def scan(target, scope, payload, *, match_callback=None):
    with source_context(resource_id=resource_id(target), scope=scope, location_kind='repository_file'):
        alias_path('selected-file', target['path'])
        outcome = scan_with_source(scan_content, payload, 'selected-file', timeout=15,
            _redact_values=match_callback,
            source={'resource_id': resource_id(target), 'scope': scope, 'location_kind': 'repository_file'})
    leaks = merge_leaks(outcome['leaks'])
    need(len(leaks) <= MAX_LEAKS and sum(len(x['locations']) for x in leaks) <= MAX_LOCATIONS, 'indicator bound')
    try:
        text = payload.decode('utf-8', errors='strict')
        binary = any(ord(char) < 32 and char not in '\t\r\n' or ord(char) == 127 for char in text)
    except UnicodeError:
        binary = True
    opaque = (binary or payload.startswith((b'PK\x03\x04', b'\x1f\x8b', b'BZh', b'\xfd7zXZ',
        b'version https://git-lfs.github.com/spec/v1')))
    complete = outcome['complete'] and not opaque
    return {'complete': complete, 'leaks': leaks, 'engines': outcome['engines'], 'blob_sha': target['blob_sha'], 'bytes_sha256': sha256(payload), 'size': len(payload), 'status': 'FAIL' if leaks else 'PASS' if complete else 'UNKNOWN'}


def collect_native(transport, *, scope, selectors, enabled=False, cloud_session=None, remote_session=None,
                   match_callback=None):
    result = {'schema': SCHEMA, 'scope': scope, 'status': 'UNKNOWN', 'complete': False, 'rows': [], 'source_requests': []}
    if enabled is not True: return result
    targets = selections(selectors, scope)  # no auth or session before this point
    own_cloud, own_remote = cloud_session is None, remote_session is None
    cloud_session = cloud_session or session()
    remote_session = remote_session or session()
    capture = Capture(transport, cloud_session, remote_session, scope)
    try:
        for target in targets:
            row = {'target': public_target(target), 'resource_id': resource_id(target), 'status': 'UNKNOWN', 'complete': False,
                'association_revalidated': False, 'content': {'complete': False, 'leaks': []}, 'source_requests': [], 'native_captures': []}
            result['rows'].append(row)
            start = len(capture.records)
            try:
                if target['provider'] == 'enterprise' or not HEX40.fullmatch(target['commit_sha']):
                    continue
                link_url = 'https://developerconnect.googleapis.com/v1/' + target['link_name']
                project_url = 'https://cloudresourcemanager.googleapis.com/v3/' + scope
                link_raw = capture.request(phase='link', method='GET', url=link_url, params={'fields': LINK_FIELDS}, cap=16384)
                project_raw = capture.request(phase='project', method='GET', url=project_url, params={'fields': PROJECT_FIELDS}, cap=16384)
                link_body, project_body = parse_json(link_raw), parse_json(project_raw)
                before = bind_native(target, scope, link_body, project_body)
                row['native_captures'].append(deepcopy([link_body, project_body]))
                token_raw = capture.request(phase='token', method='POST', url=link_url+':fetchReadToken', data=b'{}', cap=8192, secret_response=True)
                token = token_response(token_raw)
                commit_url, file_url, params, host = routes(target)
                headers = remote_headers(target['provider'], token)
                commit_raw = capture.request(phase='commit', method='GET', url=commit_url, headers=headers, cap=16384)
                if target['provider'] == 'bitbucket':
                    meta_raw = capture.request(phase='file_meta', method='GET', url=file_url, params={'format':'meta'}, headers=headers, cap=16384)
                    meta = parse_json(meta_raw)
                    need(meta.get('type') == 'commit_file' and meta.get('path') == target['path'] and type(meta.get('size')) is int and 0 <= meta['size'] <= MAX_FILE
                         and 'link' not in meta.get('attributes', []), 'Bitbucket file metadata mismatch')
                    row['file_meta'] = {'type':'commit_file', 'path_sha256': sha256(target['path'].encode()), 'size': meta['size']}
                file_raw = capture.request(phase='file', method='GET', url=file_url, params=params, headers=headers, cap=MAX_HTTP, secret_response=True)
                payload = bound_file(target, commit_raw, file_raw, target['provider'])
                if target['provider'] == 'bitbucket': need(len(payload) == row['file_meta']['size'], 'Bitbucket file size mismatch')
                row['content'] = scan(target, scope, payload, match_callback=match_callback)
                del token, token_raw, payload, file_raw
                link_after = capture.request(phase='link', method='GET', url=link_url, params={'fields': LINK_FIELDS}, cap=16384)
                project_after = capture.request(phase='project', method='GET', url=project_url, params={'fields': PROJECT_FIELDS}, cap=16384)
                link_body_after, project_body_after = parse_json(link_after), parse_json(project_after)
                after = bind_native(target, scope, link_body_after, project_body_after)
                row['native_captures'].append(deepcopy([link_body_after, project_body_after]))
                need(before == after and link_raw == link_after and project_raw == project_after, 'native link or project drift')
                row['association_revalidated'] = True
                row['complete'] = row['content']['complete']
                row['status'] = row['content']['status']
            except Exception:
                pass
            finally:
                row['source_requests'] = [r['id'] for r in capture.records[start:]]
        result['complete'] = all(r['complete'] for r in result['rows'])
        result['status'] = 'FAIL' if any(r['status'] == 'FAIL' for r in result['rows']) else 'PASS' if result['complete'] else 'UNKNOWN'
    finally:
        result['source_requests'] = deepcopy(capture.records)
        for current in (cloud_session, remote_session):
            try: current.close()
            except Exception:
                result['complete'] = False
                if result['status'] != 'FAIL': result['status'] = 'UNKNOWN'
    return result
