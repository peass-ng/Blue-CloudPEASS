"""Opt-in, memory-only package inspection. No payloads or URLs survive projection.

Kingfisher and TruffleHog inspect bounded content offline. The three existing
resource kinds are enriched; no package is executed or extracted to disk.
"""
import base64
from copy import deepcopy
import hashlib
import io
import json
import re
import stat
import struct
import tarfile
import time
import threading
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler
import zipfile
import zlib
from .aws_user_data_secret_indicators import project as inspect_text

PROFILE = 'aws-package-content-indicators-v1'
SCHEMA = PROFILE
PROJECTION_OPERATIONS = {('lambda', 'get_function'), ('lambda', 'get_layer_version'),
                         ('ecr', 'batch_get_image'), ('ecr', 'get_download_url_for_layer')}
READ_ACTIONS = PROJECTION_OPERATIONS | {('ecr', 'describe_images')}
ZIP_LIMIT = 8 * 1024 * 1024
LAYER_LIMIT = 16 * 1024 * 1024
IMAGE_LIMIT = 32 * 1024 * 1024
EXPANDED_LIMIT = 64 * 1024 * 1024
MEMBER_LIMIT = 5000
MANIFEST_LIMIT = 1024 * 1024
OCI = 'application/vnd.oci.image.manifest.v1+json'
DOCKER = 'application/vnd.docker.distribution.manifest.v2+json'
TAR_TYPES = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip',
             'application/vnd.docker.image.rootfs.diff.tar.gzip'}
CONFIG_TYPES = {'application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'}
CATEGORIES = {'private_key', 'cloud_credential', 'password_assignment', 'secret'}


def _failure(code='package_content_unavailable'):
    from .aws import ReadFailure
    return ReadFailure('not_collected', code)


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None


def _partition(region):
    if not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]+)+-[0-9]', region):
        raise ValueError('invalid region')
    return 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'


def _arn(value, service, region):
    match = re.fullmatch(r'arn:' + _partition(region) + ':' + service + ':' + re.escape(region) + r':([0-9]{12}):(.+)', value if isinstance(value, str) else '')
    if match is None: raise ValueError('foreign resource')
    return match[1], match[2]


def _json(value):
    def unique(pairs):
        out = {}
        for key, val in pairs:
            if key in out: raise ValueError('duplicate JSON key')
            out[key] = val
        return out
    def invalid(value): raise ValueError('non-JSON constant')
    return json.loads(value, object_pairs_hook=unique, parse_constant=invalid)


def _context(context):
    if not isinstance(context, tuple) or len(context) != 2: raise ValueError('missing request context')
    requests, session = context
    if getattr(requests, 'content_secret_scans', False) is not True: raise _failure('content_secret_scans_disabled')
    requests.check_deadline()
    return requests, session


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def validate_url(url, region):
    """Only regional AWS S3 virtual-host presigned locations, never arbitrary hosts."""
    partition = _partition(region)
    if not isinstance(url, str) or len(url) > 32768 or any(ord(c) <= 32 or ord(c) >= 127 for c in url):
        raise ValueError('invalid package URL')
    parsed = urlsplit(url)
    suffix = 'amazonaws.com.cn' if partition == 'aws-cn' else 'amazonaws.com'
    # Do not accept unregional s3.amazonaws.com or arbitrary *.amazonaws.com.
    host = r'[a-z0-9][a-z0-9.-]*\.s3[.-]' + re.escape(region) + r'\.' + re.escape(suffix)
    if (parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None
            or parsed.port is not None or parsed.fragment or not re.fullmatch(host, parsed.hostname or '')
            or not parsed.path.startswith('/') or not parsed.query):
        raise ValueError('package URL outside regional AWS S3 allowlist')
    return url


def download(requests, url, region, cap, expected_size=None, budget=None):
    """Stream actual bytes under one shared call budget and a ten-second deadline."""
    try:
        validate_url(url, region)
        if budget is not None:
            cap = min(cap, budget[0])
            if cap <= 0: raise ValueError('image stream budget exhausted')
        with requests._lock:
            requests.check_deadline()
            if requests.max_calls is not None and requests.calls >= requests.max_calls: raise _failure('call_limit')
            requests.calls += 1
        end = min(time.monotonic() + 10, requests.deadline if requests.deadline is not None else float('inf'))
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        with opener.open(url, timeout=min(3, requests.timeout, max(0.001, end - time.monotonic()))) as response:
            if response.status != 200 or response.geturl() != url or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise ValueError('unexpected HTTP response')
            length = response.headers.get('Content-Length')
            if length is not None and (not length.isdecimal() or int(length) > cap or expected_size is not None and int(length) != expected_size):
                raise ValueError('invalid HTTP length')
            result = bytearray()
            while True:
                requests.check_deadline()
                if time.monotonic() >= end: raise ValueError('download deadline')
                chunk = response.read(min(65536, cap + 1 - len(result)))
                if not isinstance(chunk, bytes): raise ValueError('invalid stream')
                if not chunk: break
                if budget is not None: budget[0] = max(0, budget[0] - len(chunk))
                result.extend(chunk)
                if len(result) > cap: raise ValueError('actual stream limit')
            requests.check_deadline()
            if time.monotonic() >= end or length is not None and len(result) != int(length) or expected_size is not None and len(result) != expected_size:
                raise ValueError('truncated or expired stream')
            return bytes(result)
    except Exception:
        # Do not propagate provider/urllib exception text, URL, traceback or body.
        raise _failure('package_download_unavailable') from None


def _path(value):
    if (not isinstance(value, str) or not value or len(value) > 256 or not re.fullmatch(r'[A-Za-z0-9_./@+ -]+', value)
            or value.startswith('/') or any(piece in ('', '.', '..') for piece in value.rstrip('/').split('/'))):
        raise ValueError('unsafe archive path')
    return value.rstrip('/')


def _scan(raw, name, requests):
    from peaso.secret_scanning import scan_content
    requests.check_deadline()
    outcome = scan_content(bytes(raw), name)
    categories = inspect_text(raw.decode('latin-1'), 'unused')['MatchedCategories']
    if outcome['leaks']:
        categories = sorted(set(categories) | {'secret'})
    safe_name = outcome['leaks'][0]['locations'][0]['path'] if outcome['leaks'] else name
    refs = [{'File': safe_name, 'Categories': categories, 'Leaks': outcome['leaks']}] if categories else []
    requests.check_deadline()
    if not outcome['complete']:
        raise PartialArchive(refs, 0, 0)
    return refs


class PartialArchive(ValueError):
    """Carries safe observations only; caught before the projection boundary."""
    def __init__(self, refs, expanded, members):
        super().__init__('archive incomplete after proven observation')
        self.refs, self.expanded, self.members = refs, expanded, members


def scan_zip(raw, requests):
    """Preflight central directory and read each member in memory with actual bounds."""
    if not isinstance(raw, bytes) or not raw.startswith(b'PK\x03\x04') or len(raw) > ZIP_LIMIT: raise ValueError('ZIP size bound')
    end = raw.rfind(b'PK\x05\x06')
    if end < 0 or end + 22 > len(raw) or end + 22 + int.from_bytes(raw[end + 20:end + 22], 'little') != len(raw):
        raise ValueError('ZIP trailing or missing directory')
    disk, directory_disk, disk_count, count, directory_size, directory_offset = struct.unpack_from('<4H2I', raw, end + 4)
    if (disk or directory_disk or disk_count != count or not 1 <= count <= MEMBER_LIMIT
            or directory_offset + directory_size != end or directory_offset < 4):
        raise ValueError('unsupported ZIP directory or member bound')
    refs, total, names = [], 0, set()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        if not members or len(members) > MEMBER_LIMIT: raise ValueError('ZIP member bound')
        for member in members:
            requests.check_deadline()
            name = _path(member.filename)
            mode = member.external_attr >> 16
            if (name in names or member.flag_bits & 0x41 or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise ValueError('unsupported ZIP member')
            names.add(name)
            total += member.file_size
            if total > EXPANDED_LIMIT or member.file_size > max(1024, member.compress_size * 200): raise ValueError('ZIP expansion bound')
        actual = 0
        try:
            for member in members:
                if member.is_dir(): continue
                with archive.open(member) as source:
                    payload = bytearray()
                    while True:
                        requests.check_deadline()
                        chunk = source.read(min(65536, EXPANDED_LIMIT - actual + 1))
                        if not chunk: break
                        actual += len(chunk)
                        if actual > EXPANDED_LIMIT: raise ValueError('ZIP actual expansion bound')
                        payload.extend(chunk)
                    if len(payload) != member.file_size: raise ValueError('truncated ZIP member')
                    refs.extend(_scan(payload, _path(member.filename), requests))
                    if len(refs) > MEMBER_LIMIT: raise ValueError('too many observations')
        except Exception as exc:
            if isinstance(exc, PartialArchive): refs.extend(exc.refs)
            if refs: raise PartialArchive(refs, actual, len(members)) from None
            raise
    return refs, actual, len(members)


def scan_tar(raw, media_type, requests, budget=None):
    """Only regular files/directories; one gzip member, no links/devices/extraction."""
    expanded, count = budget or (0, 0)
    if not isinstance(raw, bytes) or len(raw) > LAYER_LIMIT or media_type not in TAR_TYPES: raise ValueError('unsupported layer')
    if media_type.endswith('gzip'):
        inflater = zlib.decompressobj(zlib.MAX_WBITS | 16)
        raw = inflater.decompress(raw, EXPANDED_LIMIT - expanded + 1)
        if len(raw) > EXPANDED_LIMIT - expanded or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
            raise ValueError('layer expansion bound')
    if len(raw) + expanded > EXPANDED_LIMIT or len(raw) % 512 or len(raw) < 1024 or raw[-1024:] != bytes(1024):
        raise ValueError('truncated or oversized tar')
    expanded += len(raw)
    refs, names, offset, ended = [], set(), 0, False
    try:
        while offset + 512 <= len(raw):
            requests.check_deadline()
            block = raw[offset:offset + 512]
            if block == bytes(512):
                if offset + 1024 > len(raw) or any(raw[offset:]): raise ValueError('invalid tar terminator')
                ended = True
                break
            member = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
            name = _path(member.name)
            count += 1
            if (count > MEMBER_LIMIT or name in names or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                    or member.size < 0 or member.isdir() and member.size != 0):
                raise ValueError('unsupported tar member')
            names.add(name)
            offset += 512
            end = offset + member.size
            next_offset = offset + ((member.size + 511) // 512) * 512
            if end > len(raw) or next_offset > len(raw): raise ValueError('truncated tar member')
            if member.isfile(): refs.extend(_scan(raw[offset:end], name, requests))
            offset = next_offset
        if not ended: raise ValueError('tar missing terminator')
    except Exception as exc:
        if isinstance(exc, PartialArchive): refs.extend(exc.refs)
        if refs: raise PartialArchive(refs, expanded, count) from None
        raise
    return refs, expanded, count


def marker(identity, account, region, operation, refs, *, complete=True, code=None):
    return {'Schema': SCHEMA, 'ResourceId': identity, 'AccountId': account, 'Region': region,
            'SourceOperation': operation, 'NativeResponseComplete': complete,
            'collection_status': 'collected' if complete else 'partial', 'References': refs,
            'HighConfidenceSecretPresent': bool(refs), 'Reason': code}


def _lambda(response, operation, arguments, requests, region):
    if operation == 'get_function':
        identity = arguments['FunctionName']
        account, resource = _arn(identity, 'lambda', region)
        configuration = response['Configuration']
        version = arguments['Qualifier']
        if (not re.fullmatch(r'function:[A-Za-z0-9_-]{1,64}', resource)
                or not isinstance(configuration, dict) or configuration.get('FunctionArn') != identity
                or configuration.get('Version') != version or not isinstance(version, str)
                or not re.fullmatch(r'(?:\$LATEST|[1-9][0-9]*)', version) or configuration.get('PackageType') != 'Zip'):
            raise ValueError('function identity/version/format mismatch')
        code, size, expected = response['Code'], configuration['CodeSize'], configuration['CodeSha256']
        if code.get('RepositoryType') != 'S3': raise ValueError('unsupported function code location')
    else:
        base, version = arguments['LayerName'], arguments['VersionNumber']
        account, resource = _arn(base, 'lambda', region)
        if not re.fullmatch(r'layer:[A-Za-z0-9_-]{1,140}', resource) or type(version) is not int or version < 1:
            raise ValueError('invalid layer identity')
        identity = base + ':' + str(version)
        if response.get('LayerVersionArn') != identity or response.get('LayerArn') != base or response.get('Version') != version:
            raise ValueError('layer identity/version mismatch')
        code = response['Content']
        size, expected = code['CodeSize'], code['CodeSha256']
    if type(size) is not int or not 0 < size <= ZIP_LIMIT or not isinstance(expected, str): raise ValueError('package size/hash missing')
    expected_digest = base64.b64decode(expected, validate=True)
    if len(expected_digest) != 32: raise ValueError('package hash malformed')
    raw = download(requests, code['Location'], region, ZIP_LIMIT, size)
    if hashlib.sha256(raw).digest() != expected_digest: raise ValueError('package hash mismatch')
    complete = True
    try:
        refs, _, _ = scan_zip(raw, requests)
    except PartialArchive as partial:
        refs, complete = partial.refs, False
    return {'PackageSecretIndicators': marker(identity, account, region, 'lambda:' + operation, refs, complete=complete,
            code=None if complete else 'package_content_incomplete'), 'SourceVersion': version}


def _ecr_arguments(arguments):
    account, repo = arguments['registryId'], arguments['repositoryName']
    if (not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account) or not isinstance(repo, str)
            or not 2 <= len(repo) <= 256 or not re.fullmatch(r'[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*', repo)):
        raise ValueError('invalid ECR identity')
    return account, repo


def _layer(response, arguments, requests, region):
    account, repo = _ecr_arguments(arguments)
    digest = arguments['layerDigest']
    if not _digest(digest) or response.get('layerDigest') != digest: raise ValueError('foreign layer digest')
    state = getattr(requests, '_package_scan_local', None)
    budget = getattr(state, 'budget', None) if state is not None else None
    raw = download(requests, response['downloadUrl'], region, LAYER_LIMIT, budget=budget)
    if 'sha256:' + hashlib.sha256(raw).hexdigest() != digest: raise ValueError('layer digest mismatch')
    # Return no layer bytes through the Future: scan both supported source shapes.
    # Manifest projection selects the exact appropriate result and checks size.
    results = {}
    for typ in ('tar', 'gzip', 'config'):
        try:
            if typ == 'config':
                document = _json(raw.decode('utf-8'))
                if not isinstance(document, dict): raise ValueError('config object required')
                config, history = document.get('config'), document.get('history')
                if not isinstance(config, dict) or not isinstance(history, list): raise ValueError('incomplete config')
                env = config.get('Env', [])
                if not isinstance(env, list) or any(not isinstance(v, str) for v in env): raise ValueError('invalid environment')
                texts = []
                for v in env:
                    key, separator, val = v.partition('=')
                    if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key): raise ValueError('invalid variable')
                    texts.append(key + '=' + json.dumps(val))
                for entry in history:
                    if not isinstance(entry, dict) or not isinstance(entry.get('created_by'), str): raise ValueError('invalid build history')
                    texts.append(entry['created_by'])
                refs = _scan('\n'.join(texts).encode('utf-8'), 'image-config', requests)
                results[typ] = {'References': refs, 'ExpandedBytes': len(raw), 'Members': 1, 'NativeResponseComplete': True}
            else:
                media = 'application/vnd.oci.image.layer.v1.tar' + ('+gzip' if typ == 'gzip' else '')
                refs, expanded, members = scan_tar(raw, media, requests)
                results[typ] = {'References': refs, 'ExpandedBytes': expanded, 'Members': members, 'NativeResponseComplete': True}
        except PartialArchive as partial:
            results[typ] = {'References': partial.refs, 'ExpandedBytes': partial.expanded, 'Members': partial.members, 'NativeResponseComplete': False}
        except Exception:
            # Each alternative is independently unsupported; discard payload errors.
            pass
    requests.check_deadline()
    return {'LayerDigest': digest, 'RegistryId': account, 'RepositoryName': repo, 'CompressedBytes': len(raw), 'Formats': results}


def _image(response, arguments, requests, session, region):
    account, repo = _ecr_arguments(arguments)
    ids = arguments['imageIds']
    if not isinstance(ids, list) or len(ids) != 1 or set(ids[0]) != {'imageDigest'} or not _digest(ids[0]['imageDigest']):
        raise ValueError('exact image digest required')
    digest = ids[0]['imageDigest']
    identity = f'arn:{_partition(region)}:ecr:{region}:{account}:repository/{repo}@{digest}'
    images = response['images']
    if response.get('failures') != [] or not isinstance(images, list) or len(images) != 1: raise ValueError('ambiguous image response')
    image = images[0]
    raw = image['imageManifest']
    if (image.get('registryId') != account or image.get('repositoryName') != repo or image.get('imageId', {}).get('imageDigest') != digest
            or not isinstance(raw, str) or len(raw.encode()) > MANIFEST_LIMIT or 'sha256:' + hashlib.sha256(raw.encode()).hexdigest() != digest):
        raise ValueError('image manifest binding mismatch')
    manifest = _json(raw)
    if (not isinstance(manifest, dict) or type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 2
            or manifest.get('mediaType') not in (OCI, DOCKER) or image.get('imageManifestMediaType') != manifest['mediaType']):
        raise ValueError('unsupported manifest or multiarch index')
    layers, config = manifest.get('layers'), manifest.get('config')
    if not isinstance(layers, list) or not layers or len(layers) > MEMBER_LIMIT or not isinstance(config, dict): raise ValueError('incomplete image')
    with requests._lock:
        if not hasattr(requests, '_package_scan_local'): requests._package_scan_local = threading.local()
    requests._package_scan_local.budget = [IMAGE_LIMIT]
    refs, complete, compressed, expanded, members, seen = [], True, 0, 0, 0, set()
    for descriptor in [config] + layers:
        requests.check_deadline()
        try:
            ld, size, typ = descriptor['digest'], descriptor['size'], descriptor['mediaType']
            if (set(descriptor) - {'digest', 'size', 'mediaType', 'annotations'} or not _digest(ld) or ld in seen
                    or type(size) is not int or not 0 < size <= LAYER_LIMIT): raise ValueError('unsupported descriptor')
            seen.add(ld)
            if descriptor is config:
                if typ not in CONFIG_TYPES: raise ValueError('unsupported image config')
                fmt = 'config'
            else:
                if typ not in TAR_TYPES: raise ValueError('unsupported image layer')
                fmt = 'gzip' if typ.endswith('gzip') else 'tar'
            compressed += size
            if compressed > IMAGE_LIMIT: raise ValueError('image compressed limit')
            safe = requests.detail(session, 'ecr', region, 'get_download_url_for_layer', _metadata_profile=PROFILE,
                                   registryId=account, repositoryName=repo, layerDigest=ld)
            if (safe.get('collection_status') != 'collected' or safe.get('LayerDigest') != ld or safe.get('RegistryId') != account
                    or safe.get('RepositoryName') != repo or safe.get('CompressedBytes') != size): raise ValueError('layer incomplete')
            result = safe['Formats'][fmt]
            if result['NativeResponseComplete'] is not True: complete = False
            expanded += result['ExpandedBytes']; members += result['Members']
            if expanded > EXPANDED_LIMIT or members > MEMBER_LIMIT: raise ValueError('image expansion/member limit')
            refs.extend({'File': r['File'], 'Categories': r['Categories'], **({'Leaks': r['Leaks']} if 'Leaks' in r else {}), 'LayerDigest': ld} for r in result['References'])
        except Exception:
            complete = False
            # Stop at bounds to prevent downloading later layers past the image budget.
            if compressed > IMAGE_LIMIT or expanded > EXPANDED_LIMIT or members > MEMBER_LIMIT or requests._package_scan_local.budget[0] <= 0: break
    requests.check_deadline()
    return {'PackageSecretIndicators': marker(identity, account, region, 'ecr:batch_get_image', refs, complete=complete,
                                               code=None if complete else 'image_content_incomplete'), 'ImageDigest': digest}


def project_response(response, service, operation, arguments, *, request_context=None, region=None):
    """Root dispatcher invokes before Future.set_result; never return raw SDK data."""
    try:
        requests, session = _context(request_context)
        if (service, operation) not in PROJECTION_OPERATIONS or not isinstance(response, dict): raise ValueError('invalid projection operation')
        _partition(region)
        own = _own_account(requests, session, region)
        candidate = (_arn(arguments.get('FunctionName') if operation == 'get_function' else arguments.get('LayerName'), 'lambda', region)[0]
                     if service == 'lambda' else arguments.get('registryId'))
        if candidate != own: raise ValueError('foreign content request')
        if service == 'lambda': return _lambda(response, operation, arguments, requests, region)
        if operation == 'get_download_url_for_layer': return _layer(response, arguments, requests, region)
        return _image(response, arguments, requests, session, region)
    except Exception:
        raise _failure('package_projection_unavailable') from None
    finally:
        # Budgets retain integers only; erase at the outer image boundary.
        if service == 'ecr' and operation == 'batch_get_image' and isinstance(request_context, tuple) and len(request_context) == 2:
            state = getattr(request_context[0], '_package_scan_local', None)
            if state is not None and hasattr(state, 'budget'): del state.budget


def _own_account(requests, session, region):
    identity = requests.detail(session, 'sts', region, 'get_caller_identity')
    account = identity.get('Account')
    partition = _partition(region)
    if (identity.get('collection_status') != 'collected' or not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account)
            or not re.fullmatch(r'arn:' + partition + r':(?:sts|iam)::' + account + r':.+', identity.get('Arn', ''))):
        raise ValueError('own account authority unavailable')
    return account


def enrich(kind, requests, session, region, items):
    enabled = getattr(requests, 'content_secret_scans', False) is True
    try: account = _own_account(requests, session, region) if enabled else None
    except Exception: account = None
    output = []
    for original in items:
        item = deepcopy(original)
        source = {'collection_status': 'not_collected', 'error': {'code': 'content_secret_scans_disabled' if not enabled else 'package_binding_unavailable'}}
        try:
            if not enabled or account is None: raise ValueError('optout or authority unavailable')
            if kind == 'lambda_function':
                identity, resource = item['FunctionArn'], item['FunctionName']
                own, native = _arn(identity, 'lambda', region)
                version = item['Version']
                if own != account or native != 'function:' + resource or not isinstance(version, str) or not re.fullmatch(r'(?:\$LATEST|[1-9][0-9]*)', version):
                    raise ValueError('foreign function')
                source = requests.detail(session, 'lambda', region, 'get_function', _metadata_profile=PROFILE, FunctionName=identity, Qualifier=version)
            elif kind == 'lambda_layer_version':
                identity, version = item['LayerVersionArn'], item['Version']
                own, native = _arn(identity, 'lambda', region)
                if own != account or type(version) is not int or version < 1 or native != 'layer:' + item['LayerName'] + ':' + str(version) or item.get('LayerArn') != identity.rsplit(':', 1)[0]:
                    raise ValueError('foreign layer')
                source = requests.detail(session, 'lambda', region, 'get_layer_version', _metadata_profile=PROFILE, LayerName=item['LayerArn'], VersionNumber=version)
            else:
                own, native = _arn(item['repositoryArn'], 'ecr', region)
                repo = item['repositoryName']
                if own != account or item.get('registryId') != account or native != 'repository/' + repo: raise ValueError('foreign repository')
                inventory = requests.pages(session, 'ecr', region, 'describe_images', 'imageDetails', registryId=account, repositoryName=repo)
                if inventory.status != 'collected' or not inventory.items or len(inventory.items) > 5000: raise ValueError('incomplete image inventory')
                images, digests = [], set()
                from datetime import datetime
                for row in inventory.items:
                    digest, pushed = row['imageDigest'], row['imagePushedAt']
                    if (not _digest(digest) or digest in digests or not isinstance(pushed, datetime) or pushed.tzinfo is None
                            or row.get('registryId') != account or row.get('repositoryName') != repo): raise ValueError('image inventory binding incomplete')
                    digests.add(digest); images.append((pushed, digest))
                images.sort()
                if len(images) > 1 and images[-1][0] == images[-2][0]: raise ValueError('ambiguous latest image')
                digest = images[-1][1]
                source = requests.detail(session, 'ecr', region, 'batch_get_image', _metadata_profile=PROFILE,
                    registryId=account, repositoryName=repo, imageIds=[{'imageDigest': digest}], acceptedMediaTypes=[OCI, DOCKER])
                source['SelectedImageDigest'] = digest
        except Exception:
            pass
        item['PackageContentSource'] = source
        output.append(item)
    return output


ENRICHERS = {kind: (lambda requests, session, region, items, k=kind: enrich(k, requests, session, region, items))
             for kind in ('lambda_function', 'lambda_layer_version', 'ecr_repository')}
