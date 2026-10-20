"""Explicit digest-pinned Artifact Registry File reads; no raw cache or install.

Only fixed native GET metadata/download endpoints. Repository/project inventory
must already be complete. Media is verified before UTF-8 or memory-only archive
inspection. Reuses the audited GCP archive facade with private parser bindings;
no AWS context/network helper or global scanner mutation is involved.
"""
from copy import deepcopy
import base64
import hashlib
import json
import re
import threading
import time
from urllib.parse import quote, unquote_to_bytes
import requests

from . import gcp_selected_archive_secret_indicators as archives
from . import gcp_selected_object_secret_indicators as objects
from peaso.secret_scanning import scan_content, merge_leaks

SCHEMA = 'gcp-selected-artifact-file-secrets-v1'
KIND = 'artifact_selected_file'
OPTION = 'selected_artifact_files'
MARKER = 'ArtifactFileSecretIndicators'
FORMATS = ('utf8', 'zip', 'tar', 'tar.gz')
REPO_FORMATS = ('MAVEN', 'NPM', 'APT', 'YUM', 'GOOGET', 'PYTHON', 'KFP', 'GO', 'GENERIC', 'RUBY', 'CONDA')
MAX_FILES = 8
MAX_FILE_BYTES = 1048576
MAX_TOTAL_BYTES = 8388608
MAX_METADATA_BYTES = 16384
MAX_CALLS = 16
MAX_SECONDS = 30
FIELDS = 'name,sizeBytes,hashes'
_SCOPE = r'projects/(?:[a-z][a-z0-9-]{0,62}|[1-9][0-9]{0,19})'
_PREFIX = re.compile('(' + _SCOPE + r')/locations/([a-z][a-z0-9-]{0,62})/repositories/([a-z][a-z0-9_-]{0,62})/files/([^/]+)\Z')


class Incomplete(Exception):
    pass


class PartialInspection(Incomplete):
    def __init__(self, parsed):
        super().__init__('partial_positive')
        self.parsed = parsed


def identity(target):
    return 'artifact-selected-file:' + hashlib.sha256(json.dumps(target, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def normalize_selection(options, scopes):
    kinds = options.get('_content_secret_scan_kinds')
    if options.get('content_secret_scans') is not True or not isinstance(kinds, list) or KIND not in kinds:
        return []
    selected = options.get(OPTION)
    if not isinstance(selected, list) or not 1 <= len(selected) <= MAX_FILES: raise Incomplete('invalid_selection')
    result, seen = [], set()
    for t in selected:
        if (not isinstance(t, dict) or set(t) != {'project_scope', 'name', 'sha256', 'format'}
                or not isinstance(t['project_scope'], str) or not re.fullmatch(_SCOPE, t['project_scope'])
                or t['project_scope'] not in scopes or not isinstance(t['name'], str)
                or not isinstance(t['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', t['sha256'])
                or not isinstance(t['format'], str) or t['format'] not in FORMATS):
            raise Incomplete('invalid_selection')
        m = _PREFIX.fullmatch(t['name'])
        if m is None or m[1] != t['project_scope'] or m[2] in ('global', '-'):
            raise Incomplete('invalid_selection')
        try:
            decoded = unquote_to_bytes(m[4]).decode('utf-8', errors='strict')
            if (not 1 <= len(decoded.encode()) <= 1024 or quote(decoded, safe='-._~') != m[4]
                    or re.search(r'%[0-9A-Fa-f]{2}', decoded)
                    or any(ord(c) < 32 or ord(c) == 127 for c in decoded) or '\\' in decoded
                    or any(part in ('', '.', '..') for part in decoded.split('/'))):
                raise ValueError('invalid file id')
        except Exception: raise Incomplete('invalid_selection') from None
        # Selecting the same native file twice cannot multiply calls/budget or
        # create contradictory format/digest declarations.
        if t['name'] in seen: raise Incomplete('duplicate_selection')
        seen.add(t['name']); result.append(deepcopy(t))
    return result


def _authority(collector, scope, target):
    from peaso.checks.facts import get
    project = collector.collections.get(('project', scope), {})
    repos = collector.collections.get(('artifact_repository', scope), {})
    if (project.get('coverage_status') != 'collected' or repos.get('coverage_status') != 'collected'
            or len(project.get('items', [])) != 1): raise Incomplete('authority_unavailable')
    row = project['items'][0]
    number = re.fullmatch(r'projects/([1-9][0-9]{0,19})', get(row, 'name', str))
    pid = get(row, 'projectId', str)
    if (number is None or not isinstance(pid, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', pid)
            or scope.split('/')[1] not in (pid, number[1])
            or 'projectNumber' in row and row['projectNumber'] != number[1]): raise Incomplete('authority_unavailable')
    parent = target['name'].split('/files/')[0]
    matches = [r for r in repos.get('items', []) if isinstance(r, dict) and r.get('name') == parent]
    if (len(matches) != 1 or get(matches[0], 'name', str) != parent
            or get(matches[0], 'mode', str) != 'STANDARD_REPOSITORY'
            or get(matches[0], 'format', str) not in REPO_FORMATS):
        raise Incomplete('repository_unavailable_or_unsupported')


def _check(transport, state):
    transport.check_cancelled()
    if time.monotonic() - state['started'] >= MAX_SECONDS: raise Incomplete('deadline')


def _remaining(transport, state):
    _check(transport, state)
    seconds = MAX_SECONDS - (time.monotonic() - state['started'])
    if transport.deadline is not None: seconds = min(seconds, transport.deadline - time.time())
    if transport.deadline_seconds is not None: seconds = min(seconds, transport.deadline_seconds - (time.monotonic() - transport.started))
    if seconds <= 0: raise Incomplete('deadline')
    return min(transport.timeout, seconds)


def _headers(transport):
    # Native ADC headers only; ambient proxies, netrc, auth challenge callbacks,
    # credential helpers and arbitrary caller headers are never consulted.
    supplied = transport.credentials.headers()
    candidates = [v for k, v in supplied.items() if k.lower() == 'authorization']
    if len(candidates) != 1 or not isinstance(candidates[0], str) or not re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', candidates[0]):
        raise Incomplete('credentials_unavailable')
    headers = {'Authorization': candidates[0], 'Accept-Encoding': 'identity', 'Accept': '*/*'}
    quota = transport.options.get('quota_project')
    if quota is not None:
        if not isinstance(quota, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', quota): raise Incomplete('quota_unavailable')
        headers['X-Goog-User-Project'] = quota
    return headers


class Reader:
    def __init__(self, transport, state):
        self.transport, self.state = transport, state
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.auth = lambda request: request
        self.session.cookies.clear()
        self.session.headers.clear()
        self.session.proxies.clear()

    def close(self): self.session.close()

    def read(self, target, *, size=None):
        transport, state = self.transport, self.state
        media = size is not None
        url = 'https://artifactregistry.googleapis.com/' + ('download/v1/' if media else 'v1/') + target['name'] + (':download' if media else '')
        params = {'alt': 'media'} if media else {'fields': FIELDS}
        receipt = {'scope': target['project_scope'], 'method': 'GET', 'resource_id': identity(target),
            'operation': 'artifactregistry.files.download' if media else 'artifactregistry.files.get', 'status': 'unavailable'}
        response = None
        try:
            _check(transport, state)
            with transport.lock:
                if state['calls'] >= MAX_CALLS or transport.max_calls is not None and transport.calls >= transport.max_calls:
                    raise Incomplete('call_limit')
                transport.calls += 1; state['calls'] += 1
            headers = _headers(transport)
            if not media: headers['Accept'] = 'application/json'
            _check(transport, state)
            self.session.cookies.clear()
            response = self.session.request('GET', url, params=params, headers=headers,
                stream=True, allow_redirects=False, timeout=_remaining(transport, state))
            receipt['http_status'] = response.status_code
            prepared = requests.Request('GET', url, params=params).prepare().url
            if response.status_code != 200 or response.url != prepared or response.history:
                raise Incomplete('native_read_unavailable')
            h = {k.lower(): v for k, v in response.headers.items()}
            length = h.get('content-length')
            limit = MAX_FILE_BYTES if media else MAX_METADATA_BYTES
            if (h.get('content-encoding', 'identity').lower() != 'identity' or 'content-range' in h
                    or not isinstance(length, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length)
                    or int(length) > limit or media and int(length) != size
                    or not media and h.get('content-type', '').split(';')[0].strip().lower() != 'application/json'):
                raise Incomplete('native_integrity_unavailable')
            chunks, count = [], 0
            while True:
                _check(transport, state)
                sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
                if sock is not None: sock.settimeout(_remaining(transport, state))
                chunk = response.raw.read(min(16384, limit - count + 1), decode_content=False)
                if not chunk: break
                if not isinstance(chunk, bytes): raise Incomplete('invalid_stream')
                count += len(chunk)
                if media: state['bytes'] += len(chunk)
                if count > limit or state['bytes'] > MAX_TOTAL_BYTES: raise Incomplete('byte_limit')
                chunks.append(chunk)
            if count != int(length): raise Incomplete('truncated_or_overlong')
            _check(transport, state)
            receipt.update(status='collected', bytes=count)
            return b''.join(chunks)
        except Exception:
            receipt['reason'] = 'selected_file_read_unavailable'
            raise Incomplete('selected_file_read_unavailable') from None
        finally:
            if response is not None:
                try: response.close()
                except Exception: pass
            try: self.session.cookies.clear()
            except Exception: pass
            with transport.lock:
                receipt['id'] = 'request-' + str(len(transport.evidence) + 1)
                transport.evidence.append(receipt)


def _metadata(raw, target):
    def unique(pairs):
        d = {}
        for k,v in pairs:
            if k in d: raise ValueError('duplicate key')
            d[k] = v
        return d
    try:
        data = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
        if (not isinstance(data, dict) or set(data) != {'name', 'sizeBytes', 'hashes'} or data['name'] != target['name']
                or not isinstance(data['sizeBytes'], str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', data['sizeBytes'])
                or int(data['sizeBytes']) > MAX_FILE_BYTES or not isinstance(data['hashes'], list)
                or not 1 <= len(data['hashes']) <= 4): raise ValueError('metadata')
        seen, digest = set(), None
        for h in data['hashes']:
            if not isinstance(h, dict) or set(h) != {'type', 'value'} or h['type'] not in ('SHA256', 'MD5', 'DIRSUM_SHA256') or h['type'] in seen:
                raise ValueError('hash shape')
            seen.add(h['type'])
            decoded = base64.b64decode(h['value'], validate=True)
            if len(decoded) != (16 if h['type'] == 'MD5' else 32) or base64.b64encode(decoded).decode() != h['value']:
                raise ValueError('hash encoding')
            if h['type'] == 'SHA256': digest = decoded.hex()
        if digest != target['sha256']: raise ValueError('digest mismatch')
        return int(data['sizeBytes'])
    except Exception: raise Incomplete('native_metadata_unavailable') from None


def _inspect(payload, target, transport, state):
    if target['format'] != 'utf8': return archives._parse(payload, target['format'], transport, state)
    if (state['archive_expanded'] + len(payload) > archives.MAX_TOTAL_EXPANDED_BYTES
            or state['archive_members'] >= archives.MAX_TOTAL_MEMBERS): raise Incomplete('expanded_limit')
    state['archive_expanded'] += len(payload); state['archive_members'] += 1
    objects._text(payload)
    outcome = scan_content(payload, 'artifact.content', timeout=min(5, _remaining(transport, state) / 2))
    _check(transport, state)
    leaks = merge_leaks(outcome['leaks'])
    if len(leaks) > objects.MAX_LEAKS or sum(len(l['locations']) for l in leaks) > objects.MAX_LOCATIONS: raise Incomplete('finding_limit')
    parsed = {'expanded_bytes': len(payload), 'members': 1, 'files': [
        {'path': 'artifact.content', 'bytes': len(payload), 'engines': outcome['engines']}], 'leaks': leaks}
    if not outcome['complete']:
        if leaks: raise PartialInspection(parsed)
        raise Incomplete('detectors_unavailable')
    return parsed


def collect_selected_files(collector, scope):
    targets = normalize_selection(collector.options, collector.scopes)
    if not targets: return []
    transport = collector.transport
    with transport.lock:
        if not hasattr(transport, '_artifact_file_secret_state'):
            transport._artifact_file_secret_state = {'started': time.monotonic(), 'bytes': 0, 'calls': 0,
                'lock': threading.Lock(), 'items': {}, 'archive_expanded': 0, 'archive_members': 0}
        state = transport._artifact_file_secret_state
    result, reader = [], None
    with state['lock']:
        try:
            for target in targets:
                if target['project_scope'] != scope: continue
                ident = identity(target)
                if ident not in state['items']:
                    marker = {'schema': SCHEMA, 'identity': ident, 'scope': scope, 'format': target['format'],
                        'complete': False, 'digest_verified': False, 'bytes': 0, 'expanded_bytes': 0,
                        'members': 0, 'files': [], 'leaks': [], 'verification': 'not_attempted'}
                    try:
                        _check(transport, state); _authority(collector, scope, target)
                        if reader is None: reader = Reader(transport, state)
                        size = _metadata(reader.read(target), target)
                        if state['bytes'] + size > MAX_TOTAL_BYTES: raise Incomplete('total_bytes')
                        payload = reader.read(target, size=size)
                        if hashlib.sha256(payload).hexdigest() != target['sha256']: raise Incomplete('media_digest_mismatch')
                        marker.update(bytes=size, digest_verified=True)
                        try:
                            parsed = _inspect(payload, target, transport, state)
                        except archives.PartialInspection as exc:
                            raise PartialInspection(exc.parsed) from None
                        del payload
                        _check(transport, state)
                        marker.update(parsed, bytes=size, complete=True, digest_verified=True)
                    except PartialInspection as exc:
                        marker.update(exc.parsed)
                    except Exception: pass
                    state['items'][ident] = {'name': ident, MARKER: marker}
                result.append(deepcopy(state['items'][ident]))
        finally:
            if reader is not None:
                try: reader.close()
                except Exception: pass
    return result


def collection_pages(collector, scope):
    for row in collect_selected_files(collector, scope):
        with collector.transport.lock:
            refs = [e['id'] for e in collector.transport.evidence if e.get('scope') == scope and e.get('resource_id') == row['name']
                    and e.get('operation') in ('artifactregistry.files.get', 'artifactregistry.files.download')]
        for ref in refs[:-1]: yield [], ref
        row.setdefault('_coverage', {})[MARKER] = {'status': 'collected' if row[MARKER]['complete'] else 'incomplete', 'source_requests': refs}
        yield [row], refs[-1] if refs else 'local:artifact_selected_file'
