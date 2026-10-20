"""Unregistered bounded selected S3 source content profile; raw values stay transient.

Root must explicitly delegate this profile in Requests before its ordinary value
read prohibition. This module never changes the generic AWS operation allowlist.
"""
from copy import deepcopy
import io
import json
import re
import stat
import tarfile
import time
import threading
from urllib.parse import quote, urlsplit, parse_qsl
from uuid import uuid4
import zipfile
import zlib

from .aws_content_sdk_logging import private_sdk_logs as _private_sdk_logs
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint, redact_matches

KIND = 's3_selected_source_content'
CHECK = 'aws.review.s3.selected_source_secret_indicators'
OPTION = 'selected_aws_s3_sources'
PROFILE = 'aws-selected-s3-source-content-v1'
MARKER = 'SelectedS3SourceSecretIndicators'
SCHEMA = 'aws-selected-s3-source-v1'
FORMATS = ('text', 'zip', 'tar', 'tar.gz')
PROJECTION_OPERATIONS = {('sts', 'get_caller_identity'), ('s3', 'get_bucket_location'), ('s3', 'head_object'), ('s3', 'get_object')}
MAX_TARGETS = 4
MAX_CALLS = 20
MAX_OBJECT = 2 * 1024 * 1024
MAX_WIRE_TOTAL = 8 * 1024 * 1024
MAX_EXPANDED = 4 * 1024 * 1024
MAX_EXPANDED_TOTAL = 8 * 1024 * 1024
MAX_TEXT = 256 * 1024
MAX_MEMBERS = 64
MAX_MEMBERS_TOTAL = 128
MAX_RATIO = 100
MAX_SECONDS = 120
MAX_LEAKS = 128
MAX_LOCATIONS = 512
SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')


class Incomplete(ValueError):
    pass


def enabled(options):
    return (options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'), list)
            and KIND in options['_content_secret_scan_kinds'])


def parse(target):
    if (not isinstance(target, dict) or set(target) - {'scope', 'bucket', 'key', 'version_id', 'format'}
            or not {'scope', 'bucket', 'key', 'format'} <= set(target)
            or not isinstance(target['scope'], str) or not SCOPE.fullmatch(target['scope'])
            or target['format'] not in FORMATS):
        raise Incomplete('invalid_s3_selection')
    account, region = SCOPE.fullmatch(target['scope']).groups()
    if region.startswith(('cn-', 'us-gov-')) or '-iso' in region:
        raise Incomplete('unsupported_partition')
    bucket, key = target['bucket'], target['key']
    if (not isinstance(bucket, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket)
            or '..' in bucket or '.-' in bucket or '-.' in bucket
            or re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', bucket)
            or bucket.startswith(('xn--', 'sthree-', 'amzn-s3-demo-'))
            or bucket.endswith(('-s3alias', '--ol-s3', '--x-s3', '-x-s3', '--table-s3', '.mrap'))):
        raise Incomplete('unsupported_bucket')
    if (not isinstance(key, str) or not 1 <= len(key.encode('utf-8')) <= 1024
            or any(ord(c) < 32 or ord(c) == 127 for c in key)
            or '\\' in key or key.startswith(('/', 'http:', 'https:', 's3:'))
            or any(p in ('', '.', '..') for p in key.split('/'))):
        raise Incomplete('invalid_object_key')
    version = target.get('version_id')
    if 'version_id' in target and (not isinstance(version, str) or not 1 <= len(version) <= 1024
            or any(ord(c) <= 32 or ord(c) >= 127 for c in version)):
        raise Incomplete('invalid_object_version')
    return account, region


def selected_targets(options, scopes):
    if not isinstance(options, dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
        raise Incomplete('invalid_s3_selection')
    if OPTION not in options and not enabled(options):
        return []
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
            or len(set(scopes)) != len(scopes) or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
        raise Incomplete('invalid_s3_selection')
    seen = set()
    for target in targets:
        parse(target)
        # One object/version may not acquire ambiguous competing format declarations.
        locator = target['scope'], target['bucket'], target['key'], target.get('version_id')
        if target['scope'] not in scopes or locator in seen:
            raise Incomplete('invalid_s3_selection')
        seen.add(locator)
    return deepcopy(targets)


def identity(target):
    return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True, separators=(',', ':')))


def client_config(requests):
    from botocore.config import Config
    return Config(connect_timeout=min(3, requests.connect_timeout), read_timeout=min(5, requests.timeout),
        retries={'total_max_attempts': 1, 'mode': 'standard'}, ignore_configured_endpoint_urls=True,
        use_fips_endpoint=False, use_dualstack_endpoint=False,
        request_checksum_calculation='when_required', response_checksum_validation='when_required',
        s3={'addressing_style': 'path', 'us_east_1_regional_endpoint': 'regional', 'use_accelerate_endpoint': False})


def initialize(requests, options, scopes):
    targets = selected_targets(options, scopes)
    requests.s3_source_metadata = {KIND + '_authorized': enabled(options), KIND + '_capture': 's3-source:' + uuid4().hex,
        KIND + '_selection': {scope: [identity(t) for t in targets if t['scope'] == scope] for scope in scopes},
        KIND + '_receipts': [], KIND + '_principals': {}}
    requests.s3_source_state = {'deadline': time.monotonic() + MAX_SECONDS, 'calls': 0, 'wire_bytes': 0,
        'expanded_bytes': 0, 'members': 0}
    requests.s3_source_io_lock = threading.RLock()
    requests.s3_source_sessions = {}
    requests.s3_source_heads = {}
    requests.s3_source_redactions = set()


def remaining(requests):
    requests.check_deadline()
    left = requests.s3_source_state['deadline'] - time.monotonic()
    if left <= 0:
        raise Incomplete('s3_source_deadline')
    return min(5, left)


def arguments(target, phase, head=None):
    account, _ = parse(target)
    if phase == 'caller':
        return 'sts', 'get_caller_identity', {}
    args = {'Bucket': target['bucket'], 'ExpectedBucketOwner': account}
    if phase == 'location':
        return 's3', 'get_bucket_location', args
    if phase not in ('head_before', 'get', 'head_after'):
        raise Incomplete('invalid_s3_phase')
    args['Key'] = target['key']
    if 'version_id' in target:
        args['VersionId'] = target['version_id']
    if phase in ('get', 'head_after'):
        if not isinstance(head, dict) or not isinstance(head.get('etag'), str):
            raise Incomplete('head_required')
        args['IfMatch'] = head['etag']
    return 's3', 'get_object' if phase == 'get' else 'head_object', args


def validate_request(requests, session, service, region, operation, args, context):
    if (not isinstance(context, dict) or set(context) != {'target', 'phase', 'marker'}
            or not getattr(requests, 'content_secret_scans', False)
            or requests.s3_source_metadata[KIND + '_authorized'] is not True):
        raise Incomplete('selected_s3_profile_unauthorized')
    target, phase = context['target'], context['phase']; account, selected_region = parse(target)
    ident = identity(target); scope = target['scope']
    if ident not in requests.s3_source_metadata[KIND + '_selection'].get(scope, []) or selected_region != region:
        raise Incomplete('selected_s3_profile_scope')
    expected_service, expected_operation, expected_args = arguments(target, phase, requests.s3_source_heads.get(ident))
    if (service, operation) not in PROJECTION_OPERATIONS or (service, operation, args) != (expected_service, expected_operation, expected_args):
        raise Incomplete('undeclared_selected_s3_operation')
    if phase != 'caller' and requests.s3_source_sessions.get((id(session), scope), {}).get('account') != account:
        raise Incomplete('selected_s3_caller_unbound')
    if context['marker']['identity'] != ident or context['marker']['capture'] != requests.s3_source_metadata[KIND + '_capture']:
        raise Incomplete('selected_s3_capture_unbound')


def validate_native_client(client, service, region):
    from botocore.client import BaseClient
    host = service + '.' + region + '.amazonaws.com'
    if (not isinstance(client, BaseClient) or client.meta.region_name != region
            or client.meta.service_model.service_name != service
            or client.meta.endpoint_url not in ('https://' + host, 'https://' + host + '/')
            or client._endpoint.host not in ('https://' + host, 'https://' + host + '/')):
        raise Incomplete('untrusted_selected_s3_endpoint')
    return host


def _wire_guard(request, *, service, region, args, operation, sends):
    """Before-send rejects redirects/endpoint rewriting before any network I/O."""
    sends[0] += 1
    parsed = urlsplit(request.url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    expected_path = '/' if service == 'sts' else '/' + args['Bucket']
    if 'Key' in args:
        expected_path += '/' + quote(args['Key'], safe='/~')
    expected_query = {'location': ''} if operation == 'get_bucket_location' else {}
    if 'VersionId' in args:
        expected_query['versionId'] = args['VersionId']
    method = 'POST' if service == 'sts' else 'HEAD' if operation == 'head_object' else 'GET'
    if (sends[0] != 1 or parsed.scheme != 'https' or parsed.netloc != service + '.' + region + '.amazonaws.com'
            or parsed.path != expected_path or parsed.fragment or query != expected_query
            or len(parse_qsl(parsed.query, keep_blank_values=True)) != len(expected_query) or request.method != method):
        raise Incomplete('selected_s3_wire_binding')
    if service == 's3':
        def value(name):
            raw = request.headers.get(name)
            return raw.decode() if isinstance(raw, bytes) else raw
        if any(value(name) is not None for name in ('x-amz-request-payer', 'x-amz-checksum-mode',
                'x-amz-server-side-encryption-customer-key', 'x-amz-server-side-encryption-customer-algorithm',
                'x-amz-server-side-encryption-customer-key-MD5')):
            raise Incomplete('unsupported_selected_s3_header')
        if value('x-amz-expected-bucket-owner') != args['ExpectedBucketOwner']:
            raise Incomplete('selected_s3_wire_owner')
        if 'IfMatch' in args and value('If-Match') != args['IfMatch']:
            raise Incomplete('selected_s3_wire_condition')


class _BoundedRaw:
    """Bound success and SDK error-body reads before botocore parses/caches them."""
    def __init__(self, raw, requests):
        self.raw, self.requests, self.size = raw, requests, 0
    def read(self, amt=None, **kwargs):
        remaining(self.requests)
        amount = min(amt if isinstance(amt, int) and amt > 0 else 16384, 16384,
            MAX_OBJECT - self.size + 1, MAX_WIRE_TOTAL - self.requests.s3_source_state['wire_bytes'] + 1)
        if amount <= 0:raise Incomplete('s3_wire_byte_budget')
        data = self.raw.read(amount, **kwargs)
        self.size += len(data); self.requests.s3_source_state['wire_bytes'] += len(data)
        if self.size > MAX_OBJECT or self.requests.s3_source_state['wire_bytes'] > MAX_WIRE_TOTAL:
            raise Incomplete('s3_wire_byte_budget')
        return data
    def stream(self, amt=1024, decode_content=False):
        while True:
            chunk = self.read(amt)
            if not chunk:return
            yield chunk
    def close(self):
        self.raw.close()
    def __getattr__(self, name):
        return getattr(self.raw, name)




def profile_call(requests, session, service, region, operation, *, _projection_context=None, **args):
    # Dedicated profile clients are serialized while the transient HTTP budget
    # wrapper is installed. Generic Requests clients are never touched.
    with requests.s3_source_io_lock, _private_sdk_logs():
        return _profile_call_locked(requests, session, service, region, operation,
            _projection_context=_projection_context, **args)


def _profile_call_locked(requests, session, service, region, operation, *, _projection_context=None, **args):
    """Exact proposed Requests delegation; shares budget, never caches content/args."""
    context = _projection_context
    validate_request(requests, session, service, region, operation, args, context)
    remaining(requests)
    with requests._lock:
        if requests.s3_source_state['calls'] >= MAX_CALLS or requests.max_calls is not None and requests.calls >= requests.max_calls:
            raise Incomplete('selected_s3_call_budget')
        requests.calls += 1; requests.s3_source_state['calls'] += 1
    client = requests.client(session, service, region, _metadata_profile=PROFILE)
    validate_native_client(client, service, region)
    event = 'before-send.' + client.meta.service_model.service_id.hyphenize() + '.*'
    event_id = 'selected-s3-' + uuid4().hex
    sends = [0]
    def guard(request, **kwargs):
        _wire_guard(request, service=service, region=region, args=args, operation=operation, sends=sends)
    client.meta.events.register(event, guard, unique_id=event_id)
    response = None
    raw_streams = []
    native_send = client._endpoint.http_session.send
    def bounded_send(request, **kwargs):
        response = native_send(request, **kwargs)
        stream = _BoundedRaw(response.raw, requests); raw_streams.append(stream)
        response.raw = stream
        return response
    client._endpoint.http_session.send = bounded_send
    ledger = requests.s3_source_metadata[KIND + '_receipts']
    receipt = {'id': 's3-source-read-' + str(len(ledger) + 1), 'identity': identity(context['target']),
        'scope': context['target']['scope'], 'capture': context['marker']['capture'], 'service': service,
        'operation': operation, 'phase': context['phase'], 'region': region,
        'method': 'POST' if service == 'sts' else 'HEAD' if operation == 'head_object' else 'GET',
        'host': service + '.' + region + '.amazonaws.com', 'request': _fingerprint(json.dumps(args, sort_keys=True)),
        'http_status': None, 'request_id': None, 'bound': False, 'bytes': 0}
    ledger.append(receipt); context['marker']['source_requests'].append(receipt['id'])
    try:
        response = getattr(client, operation)(**args)
        return project_response(response, service, operation, args, request_context=(requests, session, context, receipt), region=region)
    finally:
        close_failed = False
        try:
            closers = ([response['Body']] if isinstance(response, dict)
                and callable(getattr(response.get('Body'), 'close', None)) else []) + raw_streams
            for stream in closers:
                try:
                    stream.close()
                except Exception:
                    close_failed = True
        finally:
            client._endpoint.http_session.send = native_send
            client.meta.events.unregister(event, unique_id=event_id)
        if close_failed:
            raise Incomplete('selected_s3_stream_close_incomplete')


def _native_metadata(response, receipt):
    if not isinstance(response, dict) or any(k in response for k in ('Error', '_coverage', 'NextToken', 'ContinuationToken')):
        raise Incomplete('s3_native_shape')
    metadata = response.get('ResponseMetadata')
    if (not isinstance(metadata, dict) or type(metadata.get('HTTPStatusCode')) is not int or metadata['HTTPStatusCode'] != 200
            or not isinstance(metadata.get('RequestId'), str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', metadata['RequestId'])):
        raise Incomplete('s3_native_response_unbound')
    receipt.update(http_status=200, request_id=_fingerprint(metadata['RequestId']))


def _object_metadata(response, target):
    etag = response.get('ETag'); length = response.get('ContentLength'); version = response.get('VersionId')
    if (not isinstance(etag, str) or not re.fullmatch(r'"[^"\r\n]{1,128}"', etag)
            or any(ord(c) < 32 or ord(c) > 126 for c in etag)
            or type(length) is not int or not 0 <= length <= MAX_OBJECT
            or version is not None and (not isinstance(version, str) or not 1 <= len(version) <= 1024
                or any(ord(c) <= 32 or ord(c) >= 127 for c in version))
            or 'version_id' in target and version != target['version_id']
            or response.get('DeleteMarker') not in (None, False)
            or response.get('RequestCharged') is not None or response.get('SSECustomerAlgorithm') is not None
            or response.get('SSECustomerKeyMD5') is not None or response.get('ContentRange') is not None
            or response.get('ContentEncoding') not in (None, '', 'identity')):
        raise Incomplete('s3_object_metadata_unbound')
    return {'etag': etag, 'length': length, 'version': version}


def _read_body(requests, body, length, receipt):
    from botocore.response import StreamingBody
    if not isinstance(body, StreamingBody):
        raise Incomplete('native_stream_required')
    chunks = []; size = 0
    while True:
        body.set_socket_timeout(remaining(requests))
        chunk = body.read(min(16384, MAX_OBJECT - size + 1, MAX_WIRE_TOTAL - requests.s3_source_state['wire_bytes'] + 1))
        if not chunk:
            break
        size += len(chunk); receipt['bytes'] = size
        if size > MAX_OBJECT or requests.s3_source_state['wire_bytes'] > MAX_WIRE_TOTAL:
            raise Incomplete('s3_body_byte_budget')
        chunks.append(chunk)
    if size != length:
        raise Incomplete('s3_body_length_mismatch')
    return b''.join(chunks)


def _member_name(name):
    return (isinstance(name, str) and 0 < len(name.encode()) <= 1024 and not name.startswith('/')
        and not re.match(r'[A-Za-z]:', name) and '\\' not in name and not any(ord(c) < 32 for c in name)
        and all(p not in ('', '.', '..') for p in name.rstrip('/').split('/')))


def _text(data):
    if not isinstance(data, bytes) or not data or len(data) > MAX_TEXT or b'\0' in data:
        raise Incomplete('unsupported_source_text')
    text = data.decode('utf-8', errors='strict')
    if any(ord(c) < 32 and c not in '\n\r\t' for c in text):
        raise Incomplete('unsupported_source_text')
    return text


def _scan_part(requests, marker, data, name):
    text = _text(data)
    # Names are data too. Never expose native archive names or derived line numbers.
    payload = text.encode() + b'\n' + name.encode()
    location = marker['identity'] + '.text' if marker['format'] == 'text' else marker['identity'] + '.member:' + _fingerprint(name)
    outcome = scan_content(payload, location, timeout=remaining(requests) / 2,
        _redact_values=requests.s3_source_redactions.update)
    marker['parts'].append({'path': location, 'bytes': len(payload), 'complete': outcome['complete'], 'engines': deepcopy(outcome['engines'])})
    leaks = deepcopy(outcome['leaks'])
    for leak in leaks:
        leak['locations'] = [{'path': location}]
    merged = merge_leaks(marker['leaks'] + leaks)
    overflow = len(merged) > MAX_LEAKS or sum(len(l['locations']) for l in merged) > MAX_LOCATIONS
    bounded = []; left = MAX_LOCATIONS
    for leak in merged[:MAX_LEAKS]:
        if not left:break
        row = deepcopy(leak); row['locations'] = row['locations'][:left]; left -= len(row['locations']); bounded.append(row)
    marker['leaks'] = merge_leaks(bounded)
    if overflow:
        raise Incomplete('s3_finding_budget')


def _nested(name, data):
    return (name.lower().endswith(('.zip', '.tar', '.tar.gz', '.tgz')) or data.startswith((b'PK\x03\x04', b'\x1f\x8b'))
            or len(data) > 262 and data[257:262] == b'ustar')


def _expanded(requests, size, raw_size):
    state = requests.s3_source_state
    state['expanded_bytes'] += size
    if size > MAX_EXPANDED or size > max(1, raw_size) * MAX_RATIO or state['expanded_bytes'] > MAX_EXPANDED_TOTAL:
        raise Incomplete('s3_archive_expansion_budget')


def _members(requests, marker, data):
    complete = True; seen = set(); expanded = 0; count = 0
    fmt = marker['format']
    if fmt == 'text':
        _scan_part(requests, marker, data, 'selected-object')
        return True
    if fmt == 'tar.gz':
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = decoder.decompress(data, MAX_EXPANDED + 1)
        if len(raw) > MAX_EXPANDED or not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
            raise Incomplete('unsupported_gzip_stream')
        _expanded(requests, len(raw), len(data)); data = raw
    def entry(name):
        nonlocal count
        remaining(requests)
        count += 1; requests.s3_source_state['members'] += 1
        if (count > MAX_MEMBERS or requests.s3_source_state['members'] > MAX_MEMBERS_TOTAL
                or not _member_name(name) or name in seen):
            raise Incomplete('unsupported_archive_member')
        seen.add(name)
    def member(name, size, read, binary=False):
        nonlocal expanded, complete
        entry(name)
        if type(size) is not int or not 0 <= size <= MAX_TEXT:
            raise Incomplete('unsupported_archive_member')
        expanded += size
        if expanded > MAX_EXPANDED:
            raise Incomplete('s3_archive_expansion_budget')
        if binary:
            complete = False; return
        raw = read(MAX_TEXT + 1)
        if len(raw) != size or _nested(name, raw):
            complete = False; return
        try:
            _text(raw)
        except (Incomplete, UnicodeError):
            complete = False; return
        _scan_part(requests, marker, raw, name)
    if fmt == 'zip':
        # Require a plain single-disk ZIP with no appended bytes or comment.
        if (not data.startswith(b'PK\x03\x04') or len(data) < 22
                or data[-22:-18] != b'PK\x05\x06' or data[-2:] != b'\0\0'
                or any(data[-18:-14])):
            raise Incomplete('unsupported_zip_envelope')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS or archive.comment:
                raise Incomplete('unsupported_zip_metadata')
            for info in infos:
                mode = info.external_attr >> 16
                if info.is_dir():
                    entry(info.filename)
                    continue
                if (info.flag_bits & 1 or stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                        or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or info.file_size > max(1, info.compress_size) * MAX_RATIO or info.comment or info.extra):
                    raise Incomplete('unsupported_zip_member')
                with archive.open(info) as stream:
                    member(info.filename, info.file_size, stream.read)
            _expanded(requests, expanded, len(data))
    else:
        if len(data) % 512 or len(data) < 1024 or data[-1024:] != b'\0' * 1024:
            raise Incomplete('incomplete_tar_stream')
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
            for info in archive:
                if info.isdir():
                    entry(info.name)
                    continue
                if (not info.isfile() or info.issparse() or info.pax_headers):
                    raise Incomplete('unsupported_tar_member')
                stream = archive.extractfile(info)
                if stream is None:raise Incomplete('unsupported_tar_member')
                with stream:
                    member(info.name, info.size, stream.read)
            if any(data[archive.offset:]):
                raise Incomplete('trailing_tar_content')
            if fmt == 'tar':_expanded(requests, expanded, len(data))
    marker['member_count'] = count
    return complete and bool(marker['parts'])


def project_response(response, service, operation, args, *, request_context, region):
    requests, session, context, receipt = request_context
    target, marker, phase = context['target'], context['marker'], context['phase']
    account, _ = parse(target); ident = identity(target)
    _native_metadata(response, receipt); remaining(requests)
    if phase == 'caller':
        arn = response.get('Arn'); user = response.get('UserId')
        if (response.get('Account') != account or not isinstance(arn, str)
                or not re.fullmatch(r'arn:aws:(?:iam|sts)::' + account + r':[^\r\n]{1,1024}', arn)
                or not isinstance(user, str) or not 1 <= len(user) <= 1024):
            raise Incomplete('s3_native_caller_account')
        principal = 's3-source-principal:' + _fingerprint(arn + '\n' + user)
        requests.s3_source_sessions[(id(session), target['scope'])] = {'account': account, 'principal': principal}
        requests.s3_source_metadata[KIND + '_principals'][target['scope']] = principal
        marker['principal'] = principal; receipt['bound'] = True
    elif phase == 'location':
        if 'LocationConstraint' not in response:
            raise Incomplete('s3_native_bucket_region_missing')
        native_region = response.get('LocationConstraint')
        native_region = 'us-east-1' if native_region is None else 'eu-west-1' if native_region == 'EU' else native_region
        if native_region != region:
            raise Incomplete('s3_native_bucket_region')
        receipt['bound'] = True
    else:
        facts = _object_metadata(response, target)
        if phase == 'head_before':
            requests.s3_source_heads[ident] = facts
            marker['object'] = {'etag': _fingerprint(facts['etag']), 'length': facts['length'],
                'version': _fingerprint(facts['version']) if facts['version'] is not None else None,
                'explicit_version': 'version_id' in target}
            receipt['bound'] = True
        else:
            if facts != requests.s3_source_heads[ident]:
                raise Incomplete('s3_object_changed')
            if phase == 'get':
                body = _read_body(requests, response.get('Body'), facts['length'], receipt)
                # Content is bound before inspection; later gaps cannot erase a trusted hit.
                receipt['bound'] = True; marker['source_bound'] = True
                try:
                    marker['content_complete'] = _members(requests, marker, body)
                finally:
                    del body
            else:
                receipt['bound'] = True; marker['head_coherent'] = True
    return {'bound': receipt['bound']}


def collect_selected(requests, session, region, caller, options, scopes):
    """Root selected-kind dispatcher proposal; caller DTO is never source proof."""
    from .aws import ReadResult
    targets = selected_targets(options, scopes)
    if not enabled(options):return ReadResult([], 'not_collected', {'code': 'selected_s3_disabled'})
    rows = []
    for target in targets:
        account, own_region = parse(target)
        if own_region != region or not isinstance(caller, dict) or caller.get('Account') != account:
            continue
        ident = identity(target); marker = {'schema': SCHEMA, 'identity': ident, 'scope': target['scope'],
            'format': target['format'], 'capture': requests.s3_source_metadata[KIND + '_capture'], 'principal': None,
            'complete': False, 'source_bound': False, 'head_coherent': False, 'content_complete': False,
            'parts': [], 'leaks': [], 'source_requests': [], 'object': None, 'member_count': 0,
            'verification': 'not_attempted'}
        try:
            for phase in ('caller', 'location', 'head_before', 'get', 'head_after'):
                service, operation, args = arguments(target, phase, requests.s3_source_heads.get(ident))
                requests.call(session, service, region, operation, _metadata_profile=PROFILE,
                    _projection_context={'target': target, 'phase': phase, 'marker': marker}, **args)
            marker['complete'] = marker['content_complete'] and marker['head_coherent'] and bool(marker['parts']) and all(p['complete'] for p in marker['parts'])
        except Exception:
            marker['complete'] = False
        finally:
            requests.s3_source_heads.pop(ident, None)
        rows.append({'id': ident, MARKER: marker, '_provenance': {'scope': target['scope'], 'capture': marker['capture']}})
    return ReadResult(rows) if rows else ReadResult([], 'not_collected', {'code': 'selected_s3_scope_omitted'})


def finalize(requests, collections, metadata):
    """Root final handoff: union-scrub metadata, locators and all prior cache aliases."""
    values = getattr(requests, 's3_source_redactions', set())
    try:
        if values:
            with requests._lock:
                for future in requests._cache.values():
                    if not future.done() or future.exception() is not None:
                        continue
                    item = future.result(); safe = redact_matches(item, values)
                    if isinstance(item, dict):item.clear(); item.update(safe)
                    elif isinstance(item, list):item[:] = safe
            collections = redact_matches(collections, values); metadata = redact_matches(metadata, values)
        metadata.update(deepcopy(getattr(requests, 's3_source_metadata', {})))
        return collections, metadata
    finally:
        values.clear()
        getattr(requests, 's3_source_heads', {}).clear()
