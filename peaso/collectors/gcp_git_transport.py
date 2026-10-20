"""Uninstalled, bounded CSR Git read transport; never a generic HTTP client.

The caller must establish native project/repository authority before invoking
this helper. It neither installs a check nor claims repository content coverage.
No ref names, pack bytes, credentials or source text enter transport evidence.
"""
import base64
import hashlib
import http.client
import logging
import math
import re
import time

KIND = 'source_repository_file'
MAX_ADVERTISEMENT = 262144
MAX_PACK_RESPONSE = 8388608 - MAX_ADVERTISEMENT
MAX_REFS = 1024
SECONDS = 60
_REPOSITORY = re.compile(r'projects/([a-z][a-z0-9-]{0,62})/repos/([A-Za-z0-9_.-]{1,100})\Z')
_OID = re.compile(r'[0-9a-f]{40}\Z')


class Incomplete(ValueError):
    """Only static, non-sensitive reason codes cross the helper boundary."""


def _check(transport, deadline):
    transport.check_cancelled()
    if time.monotonic() >= deadline:
        raise Incomplete('git_deadline')


def _pkt(data, position):
    if position + 4 > len(data) or not re.fullmatch(b'[0-9a-fA-F]{4}', data[position:position + 4]):
        raise Incomplete('git_framing')
    size = int(data[position:position + 4], 16)
    if size == 0:
        return None, position + 4
    if not 4 <= size <= 65520 or position + size > len(data):
        raise Incomplete('git_framing')
    return data[position + 4:position + size], position + size


def _encode(packet):
    return ('%04x' % (4 + len(packet))).encode('ascii') + packet


def fetch_request(advertisement, commit):
    """Select an exact advertised SHA1, with no thin/side-band negotiation."""
    if (not isinstance(advertisement, bytes) or len(advertisement) > MAX_ADVERTISEMENT
            or not isinstance(commit, str) or not _OID.fullmatch(commit) or commit == '0' * 40):
        raise Incomplete('git_selection')
    packet, position = _pkt(advertisement, 0)
    if packet != b'# service=git-upload-pack\n':
        raise Incomplete('git_service')
    packet, position = _pkt(advertisement, position)
    if packet is not None:
        raise Incomplete('git_service')
    found, refs, capabilities, first, names = False, 0, set(), True, set()
    while position < len(advertisement):
        packet, position = _pkt(advertisement, position)
        if packet is None:
            if position != len(advertisement) or refs == 0:
                raise Incomplete('git_framing')
            break
        if first and packet == b'version 1\n':
            packet, position = _pkt(advertisement, position)
        if not isinstance(packet, bytes) or not packet.endswith(b'\n'):
            raise Incomplete('git_reference')
        if first:
            parts = packet[:-1].split(b'\0')
            if len(parts) != 2:
                raise Incomplete('git_capabilities')
            packet, cap = parts
            if len(cap) > 8192 or any(c < 32 or c > 126 for c in cap):
                raise Incomplete('git_capabilities')
            capabilities = set(cap.split(b' '))
            if any(c.startswith(b'object-format=') and c != b'object-format=sha1' for c in capabilities):
                raise Incomplete('git_object_format')
        else:
            packet = packet[:-1]
        first = False
        if b'\0' in packet or len(packet) > 1065:
            raise Incomplete('git_reference')
        oid, separator, name = packet.partition(b' ')
        if (not separator or not re.fullmatch(b'[0-9a-f]{40}', oid) or not name
                or any(c < 33 or c > 126 for c in name) or name in names):
            raise Incomplete('git_reference')
        refs += 1
        if refs > MAX_REFS:
            raise Incomplete('git_ref_limit')
        names.add(name)
        found |= oid == commit.encode('ascii')
    else:
        raise Incomplete('git_truncated_advertisement')
    if not found:
        raise Incomplete('git_commit_not_advertised')
    selected = [c for c in (b'ofs-delta', b'no-progress') if c in capabilities]
    want = b'want ' + commit.encode('ascii') + (b' ' + b' '.join(selected) if selected else b'') + b'\n'
    return _encode(want) + b'0000' + _encode(b'done\n')


def pack_response(data):
    if not isinstance(data, bytes) or len(data) > MAX_PACK_RESPONSE:
        raise Incomplete('git_pack_limit')
    packet, position = _pkt(data, 0)
    if packet != b'NAK\n' or not data[position:].startswith(b'PACK'):
        raise Incomplete('git_pack_framing')
    return data[position:]


def _session():
    import requests
    session = requests.Session()
    session.trust_env = False
    session.auth = lambda request: request
    session.cookies.clear()
    return session


def _read(transport, session, *, scope, owner, method, url, body, limit, content_type, deadline):
    response = None
    receipt = {'scope': scope, 'method': method, 'operation': 'sourcerepo.git.' + ('advertise' if method == 'GET' else 'upload_pack'),
               'resource_id': owner, 'status': 'unavailable',
               'route': 'csr_git_advertisement_v0' if method == 'GET' else 'csr_git_upload_pack_v0',
               'final_route_verified': False}
    try:
        _check(transport, deadline)
        if (http.client.HTTPConnection.debuglevel or
                logging.getLogger('urllib3.connectionpool').getEffectiveLevel() <= logging.DEBUG):
            raise Incomplete('git_unsafe_diagnostics')
        with transport.lock:
            if transport.max_calls is not None and transport.calls >= transport.max_calls:
                raise Incomplete('git_call_limit')
            transport.calls += 1
        headers = transport.credentials.headers()
        _check(transport, deadline)
        authorization = next((v for k, v in headers.items() if k.lower() == 'authorization'), None)
        if (not isinstance(authorization, str) or not authorization.startswith('Bearer ')
                or not authorization[7:] or len(authorization) > 16384
                or any(ord(c) < 33 or ord(c) > 126 for c in authorization[7:])):
            raise Incomplete('git_auth_unavailable')
        basic = base64.b64encode(('git-service-account:' + authorization[7:]).encode()).decode('ascii')
        session.cookies.clear()
        response = session.request(method, url, data=body, stream=True, allow_redirects=False,
            timeout=min(transport.timeout, max(0.001, deadline - time.monotonic())),
            headers={'Authorization': 'Basic ' + basic, 'Accept': content_type,
                     'Accept-Encoding': 'identity', 'Cache-Control': 'no-store',
                     **({'Content-Type': 'application/x-git-upload-pack-request'} if method == 'POST' else {})})
        receipt['http_status'] = response.status_code
        if getattr(response, 'url', None) != url or getattr(response, 'history', None) != []:
            raise Incomplete('git_final_route_mismatch')
        receipt['final_route_verified'] = True
        if response.status_code != 200:
            raise Incomplete('git_read_denied' if response.status_code in (401, 403) else 'git_read_unavailable')
        hdr = {k.lower(): v for k, v in response.headers.items()}
        length = hdr.get('content-length')
        if (hdr.get('content-type', '').split(';', 1)[0].strip().lower() != content_type
                or hdr.get('content-encoding', 'identity').lower() != 'identity' or 'content-range' in hdr
                or length is not None and (not isinstance(length, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length)
                    or int(length) > limit)):
            raise Incomplete('git_response_encoding_or_limit')
        chunks, count = [], 0
        while True:
            _check(transport, deadline)
            sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(min(transport.timeout, max(0.001, deadline - time.monotonic())))
            chunk = response.raw.read(min(16384, limit - count + 1), decode_content=False)
            if not chunk:
                break
            if not isinstance(chunk, bytes) or count + len(chunk) > limit:
                raise Incomplete('git_response_byte_limit')
            count += len(chunk)
            chunks.append(chunk)
        _check(transport, deadline)
        if length is not None and int(length) != count:
            raise Incomplete('git_response_truncated')
        receipt.update(status='collected', bytes=count)
        return b''.join(chunks)
    except Incomplete:
        raise
    except Exception:
        raise Incomplete('git_read_unavailable') from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        with transport.lock:
            receipt['id'] = 'request-' + str(len(transport.evidence) + 1)
            transport.evidence.append(receipt)


def fetch_pack(transport, scope, repository, commit, *, enabled=False, deadline=None):
    """Two reads only; caller validates native identity and enables explicitly."""
    match = _REPOSITORY.fullmatch(repository) if isinstance(repository, str) else None
    if (enabled is not True or match is None or scope != 'projects/' + match[1]
            or match[2] in ('.', '..') or not isinstance(commit, str)
            or not _OID.fullmatch(commit) or commit == '0' * 40):
        raise Incomplete('git_selection')
    now = time.monotonic()
    if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)):
        raise Incomplete('git_deadline')
    deadline = min(now + SECONDS, deadline) if deadline is not None else now + SECONDS
    if deadline <= now:
        raise Incomplete('git_deadline')
    owner = 'sourcerepo-content:' + hashlib.sha256((repository + ':' + commit).encode()).hexdigest()
    base = 'https://source.developers.google.com/p/' + match[1] + '/r/' + match[2]
    session = _session()
    try:
        advertisement = _read(transport, session, scope=scope, owner=owner, method='GET',
            url=base + '/info/refs?service=git-upload-pack', body=None, limit=MAX_ADVERTISEMENT,
            content_type='application/x-git-upload-pack-advertisement', deadline=deadline)
        body = fetch_request(advertisement, commit)
        response = _read(transport, session, scope=scope, owner=owner, method='POST',
            url=base + '/git-upload-pack', body=body, limit=MAX_PACK_RESPONSE,
            content_type='application/x-git-upload-pack-result', deadline=deadline)
        return pack_response(response)
    finally:
        session.close()
