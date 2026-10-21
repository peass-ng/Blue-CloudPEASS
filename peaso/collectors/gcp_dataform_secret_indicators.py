"""Opted-in exact Dataform file reads, streamed outside the JSON/cache boundary.

No enumeration, checkout, remote Git fallback, managed secret access or mutation.
Only opaque selection identities and offline redacted detector results survive.
Root owns planner/collector admission; this module performs no registration.
"""

from peaso.secret_evidence import scan_with_source, target_source
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import http.client
import logging
import json
import re
import threading
import time
from urllib.parse import quote

from peaso.secret_scanning import scan_content, merge_leaks

SCHEMA = 'gcp-dataform-selected-file-secrets-v1'
MARKER = 'DataformFileSecretIndicators'
KIND = 'dataform_selected_file'
OPTION = 'selected_dataform_files'
MAX_FILES = 8
MAX_FILE_BYTES = 262144
MAX_JSON_BYTES = 4 * ((MAX_FILE_BYTES + 2) // 3) + 1024
MAX_METADATA_BYTES = 16384
MAX_TOTAL_BYTES = 2097152  # wire bytes, including metadata and JSON/base64 overhead
MAX_CALLS = 24
MAX_SECONDS = 60
MAX_LEAKS = 256
MAX_LOCATIONS = 512
_SCOPE = re.compile(r'projects/(?:[a-z][a-z0-9-]{0,62}|[1-9][0-9]{0,19})\Z')
_REPO = re.compile(r'projects/([a-z0-9-]+)/locations/([a-z][a-z0-9-]{0,62})/repositories/([A-Za-z0-9_-]{1,128})\Z')
_WORKSPACE = re.compile(r'workspaces/[A-Za-z0-9_-]{1,128}\Z')
_SHA = re.compile(r'[0-9a-f]{40}\Z')


class Incomplete(Exception):
    """Only static reason codes, never provider/body/credential error strings."""


def identity(target):
    # Hash only the selector, never file content; resource and file names can leak.
    return 'dataform-selected-file:' + hashlib.sha256(json.dumps(target, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def selected_targets(options, scopes):
    if (options.get('content_secret_scans') is not True
            or KIND not in options.get('_content_secret_scan_kinds', [])):
        return []
    rows = options.get(OPTION)
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FILES:
        raise Incomplete('invalid_selection')
    result, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise Incomplete('invalid_selection')
        keys = set(row)
        if keys not in ({'project_scope', 'repository', 'path', 'commit_sha'},
                        {'project_scope', 'repository', 'path', 'workspace'},
                        {'project_scope', 'repository', 'path', 'workspace', 'revision'}):
            raise Incomplete('invalid_selection')
        scope, repo, path = (row[k] for k in ('project_scope', 'repository', 'path'))
        try:
            path_size = len(path.encode('utf-8')) if isinstance(path, str) else 0
        except UnicodeError:
            raise Incomplete('invalid_selection') from None
        if (not isinstance(scope, str) or not _SCOPE.fullmatch(scope) or scope not in scopes
                or not isinstance(repo, str) or not _REPO.fullmatch(repo)
                or not repo.startswith(scope + '/')
                or not isinstance(path, str) or not path or path_size > 1024
                or '\\' in path or any(part in ('', '.', '..') for part in path.split('/'))
                or any(ord(c) < 32 or ord(c) == 127 for c in path)):
            raise Incomplete('invalid_selection')
        if 'workspace' in row:
            workspace = row['workspace']
            if (not isinstance(workspace, str) or not workspace.startswith(repo + '/')
                    or not _WORKSPACE.fullmatch(workspace[len(repo) + 1:])):
                raise Incomplete('invalid_selection')
        for key in ('commit_sha', 'revision'):
            if key in row and (not isinstance(row[key], str) or not _SHA.fullmatch(row[key])):
                raise Incomplete('immutable_sha_required')
        ident = identity(row)
        if ident in seen:
            raise Incomplete('duplicate_selection')
        seen.add(ident)
        result.append(dict(row))
    return result


def _bound_project(collector, scope):
    envelope = collector.collections.get(('project', scope), {})
    rows = envelope.get('items', [])
    if envelope.get('coverage_status') != 'collected' or len(rows) != 1 or not isinstance(rows[0], dict):
        raise Incomplete('project_binding_unavailable')
    project = rows[0]
    native, pid = project.get('name'), project.get('projectId')
    if (not isinstance(native, str) or not re.fullmatch(r'projects/[1-9][0-9]{0,19}', native)
            or not isinstance(pid, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', pid)
            or scope.split('/')[1] not in (native.split('/')[1], pid)):
        raise Incomplete('project_binding_unavailable')


def _json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise Incomplete('duplicate_json_field')
            result[key] = value
        return result
    try:
        result = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('invalid_json')))
        if not isinstance(result, dict):
            raise Incomplete('invalid_json')
        return result
    except Incomplete:
        raise
    except Exception:
        raise Incomplete('invalid_json') from None


class Reader:
    """Fixed native HTTPS only. Dedicated no-proxy/no-cookie session; no cache."""
    def __init__(self, transport, state, session=None):
        if session is None:
            import requests
            session = requests.Session()
        session.trust_env = False
        session.auth = None
        self.transport, self.state, self.session = transport, state, session

    def close(self):
        self.session.close()

    def remaining(self):
        self.transport.check_cancelled()
        remaining = MAX_SECONDS - (time.monotonic() - self.state['started'])
        if self.transport.deadline is not None:
            remaining = min(remaining, self.transport.deadline - time.time())
        if self.transport.deadline_seconds is not None:
            remaining = min(remaining, self.transport.deadline_seconds - (time.monotonic() - self.transport.started))
        if remaining <= 0:
            raise Incomplete('content_deadline')
        return min(self.transport.timeout, remaining)

    def get(self, target, operation):
        transport, state = self.transport, self.state
        ident = identity(target)
        receipt = {'scope': target['project_scope'], 'method': 'GET', 'operation': operation,
                   'resource_id': ident, 'status': 'unavailable', 'http_attempts': 0}
        response = None
        try:
            self.remaining()
            # Validate again at the credential boundary; get is not an arbitrary URL API.
            selected_targets({'content_secret_scans': True, '_content_secret_scan_kinds': [KIND],
                              OPTION: [target]}, [target['project_scope']])
            if operation == 'dataform.repositories.get':
                name, params = target['repository'], {'fields': 'name,gitRemoteSettings(url)'}
            elif operation == 'dataform.workspaces.get' and 'workspace' in target:
                name, params = target['workspace'], {'fields': 'name'}
            elif operation == 'dataform.repositories.readFile' and 'commit_sha' in target:
                name, params = target['repository'] + ':readFile', {'path': target['path'], 'commitSha': target['commit_sha']}
            elif operation == 'dataform.workspaces.readFile' and 'workspace' in target:
                name, params = target['workspace'] + ':readFile', {'path': target['path']}
                if 'revision' in target:
                    params['revision'] = target['revision']
            else:
                raise Incomplete('invalid_operation')
            url = 'https://dataform.googleapis.com/v1/' + quote(name, safe='/:')
            with transport.lock:
                if (state['calls'] >= MAX_CALLS or
                        transport.max_calls is not None and transport.calls >= transport.max_calls):
                    raise Incomplete('call_limit')
                state['calls'] += 1
                transport.calls += 1
            # urllib3 DEBUG and stdlib HTTP debugging can persist query names
            # or authorization. Refuse those diagnostics instead of changing
            # process-wide logging configuration owned by the application.
            from urllib3.connection import HTTPSConnection as UrllibHTTPSConnection
            if (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel
                    or UrllibHTTPSConnection.debuglevel
                    or logging.getLogger('urllib3.connectionpool').isEnabledFor(logging.DEBUG)):
                raise Incomplete('unsafe_http_diagnostics')
            authorization = transport.credentials.headers().get('Authorization')
            if not isinstance(authorization, str) or not re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', authorization):
                raise Incomplete('credential_unavailable')
            headers = {'Authorization': authorization, 'Accept-Encoding': 'identity', 'Accept': 'application/json'}
            if hasattr(self.session, 'cookies'):
                self.session.cookies.clear()
            timeout = self.remaining()
            receipt['http_attempts'] = 1
            response = self.session.request('GET', url, params=params, headers=headers, stream=True,
                                           allow_redirects=False, timeout=timeout)
            if type(response.status_code) is int and 100 <= response.status_code <= 599:
                receipt['http_status'] = response.status_code
            if response.status_code != 200:
                raise Incomplete('denied' if response.status_code in (401, 403) else 'http_incomplete')
            # requests adds query parameters to response.url; compare the actual prepared URL.
            import requests
            expected_url = requests.Request('GET', url, params=params).prepare().url
            if response.url != expected_url or response.history:
                raise Incomplete('response_identity_mismatch')
            hdr = {k.lower(): v for k, v in response.headers.items()}
            if (hdr.get('content-encoding', 'identity').lower() != 'identity' or 'content-range' in hdr
                    or 'www-authenticate' in hdr or hdr.get('content-type', '').split(';')[0].strip().lower() != 'application/json'):
                raise Incomplete('unsupported_response')
            cap = MAX_JSON_BYTES if operation.endswith('readFile') else MAX_METADATA_BYTES
            length = hdr.get('content-length')
            if length is None or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length):
                raise Incomplete('invalid_length')
            if int(length) > cap or state['bytes'] + int(length) > MAX_TOTAL_BYTES:
                raise Incomplete('byte_limit')
            output = bytearray()
            while True:
                remaining = self.remaining()
                sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
                if sock is not None:
                    sock.settimeout(remaining)
                chunk = response.raw.read(min(16384, cap - len(output) + 1), decode_content=False)
                self.remaining()
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise Incomplete('invalid_stream')
                output.extend(chunk)
                state['bytes'] += len(chunk)
                if len(output) > cap or state['bytes'] > MAX_TOTAL_BYTES:
                    raise Incomplete('byte_limit')
            if len(output) != int(length):
                raise Incomplete('truncated_or_overlong')
            receipt.update(status='collected', bytes=len(output))
            return bytes(output)
        except Incomplete as exc:
            receipt['reason'] = str(exc)
            raise
        except Exception:
            receipt['reason'] = 'read_unavailable'
            raise Incomplete('read_unavailable') from None
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            with transport.lock:
                receipt['id'] = 'request-' + str(len(transport.evidence) + 1)
                transport.evidence.append(receipt)
                state['refs'].setdefault(ident, []).append(receipt['id'])


def _payload(raw, workspace):
    data = _json(raw)
    field = 'fileContents' if workspace else 'contents'
    if set(data) != {field} or not isinstance(data[field], str):
        raise Incomplete('file_response_schema')
    try:
        payload = base64.b64decode(data[field], validate=True)
        if base64.b64encode(payload).decode('ascii') != data[field]:
            raise Incomplete('invalid_base64')
    except Incomplete:
        raise
    except Exception:
        raise Incomplete('invalid_base64') from None
    if len(payload) > MAX_FILE_BYTES:
        raise Incomplete('file_byte_limit')
    try:
        text = payload.decode('utf-8', errors='strict')
    except UnicodeError:
        raise Incomplete('unsupported_utf8') from None
    if any(ord(c) < 32 and c not in '\t\r\n' or ord(c) == 127 for c in text):
        raise Incomplete('unsupported_binary')
    return payload


def collect_selected_files(collector, scope, reader_factory=None):
    targets = selected_targets(collector.options, collector.scopes)
    if not targets:
        return []
    transport = collector.transport
    with transport.lock:
        if not hasattr(transport, '_dataform_secret_state'):
            transport._dataform_secret_state = {'started': time.monotonic(), 'bytes': 0,
                'calls': 0, 'lock': threading.Lock(), 'items': {}, 'refs': {}}
        state = transport._dataform_secret_state
    result = []
    with state['lock']:
        # Default-off and scopes without selected files do not even create a session.
        selected = [t for t in targets if t['project_scope'] == scope and identity(t) not in state['items']]
        reader = (reader_factory or Reader)(transport, state) if selected else None
        try:
            for target in selected:
                ident = identity(target)
                workspace = 'workspace' in target
                marker = {'schema': SCHEMA, 'identity': ident, 'scope': scope, 'status': 'incomplete',
                    'complete': False, 'bytes': 0, 'engines': [], 'leaks': [], 'reason': 'unavailable',
                    'verification': 'not_attempted', 'source_requests': [],
                    'read_mode': 'revision_sha' if 'revision' in target else 'observed_workspace' if workspace else 'commit_sha',
                    'revision': target.get('commit_sha', target.get('revision')),
                    'observed_at': None}
                try:
                    reader.remaining()
                    _bound_project(collector, scope)
                    metadata = _json(reader.get(target, 'dataform.repositories.get'))
                    if set(metadata) - {'name', 'gitRemoteSettings'} or metadata.get('name') != target['repository']:
                        raise Incomplete('repository_identity_mismatch')
                    remote = metadata.get('gitRemoteSettings', {})
                    if (not isinstance(remote, dict) or set(remote) - {'url'}
                            or 'url' in remote and not isinstance(remote['url'], str)
                            or not workspace and remote.get('url')):
                        raise Incomplete('unsupported_remote_repository')
                    if workspace:
                        metadata = _json(reader.get(target, 'dataform.workspaces.get'))
                        if set(metadata) != {'name'} or metadata.get('name') != target['workspace']:
                            raise Incomplete('workspace_identity_mismatch')
                    payload = _payload(reader.get(target, 'dataform.workspaces.readFile' if workspace else 'dataform.repositories.readFile'), workspace)
                    marker['observed_at'] = datetime.now(timezone.utc).isoformat()
                    timeout = min(10, reader.remaining() / 2)
                    outcome = scan_with_source(scan_content, payload, 'dataform.selected_file.content', timeout=timeout, source=target_source(target, resource_id=target['repository'], scope=scope))
                    marker['bytes'] = len(payload)
                    del payload
                    reader.remaining()
                    leaks = merge_leaks(outcome['leaks'])
                    if len(leaks) > MAX_LEAKS or sum(len(x['locations']) for x in leaks) > MAX_LOCATIONS:
                        raise Incomplete('finding_limit')
                    marker.update(engines=outcome['engines'], leaks=leaks,
                        complete=outcome['complete'], status='collected' if outcome['complete'] else 'incomplete',
                        reason='complete' if outcome['complete'] else 'detector_unavailable')
                except Incomplete as exc:
                    marker['reason'] = str(exc)
                except Exception:
                    marker['reason'] = 'unavailable'
                marker['source_requests'] = list(state['refs'].get(ident, []))
                state['items'][ident] = {'name': ident, MARKER: marker, '_coverage': {MARKER: {
                    'status': marker['status'], 'source_requests': list(marker['source_requests']),
                    'semantics': 'selected native file read only'}}}
        finally:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
        for target in targets:
            if target['project_scope'] == scope:
                result.append(deepcopy(state['items'][identity(target)]))
    return result


def collection_pages(collector, scope):
    for row in collect_selected_files(collector, scope):
        refs = row[MARKER]['source_requests']
        for ref in refs[:-1]:
            yield [], ref
        yield [row], refs[-1] if refs else 'local:dataform_selected_file'
