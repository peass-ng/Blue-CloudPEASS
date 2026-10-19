"""Selected immutable Artifact Registry images: bounded memory-only inspection.

No Docker daemon, extraction, credential validation, challenge exchange, redirects,
external URLs or content cache. Existing dual-detector TAR parsing is reused.
"""
import base64
from copy import deepcopy
import hashlib
import io
import re
import tarfile
import time
from urllib.parse import unquote, urlsplit
import zlib

from .gcp_sbom_native import _digest_uri
from .gcp_registry_image_uri import parse as parse_image_uri
from .aws_package_content_indicators import scan_tar, _json, _path, TAR_TYPES, CONFIG_TYPES, OCI, DOCKER
from peaso.secret_scanning import scan_content, merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID = 'gcp.review.artifact_image.content_secret_indicators'
MARKER = 'ImageSecretIndicators'
SCHEMA = 'gcp-selected-image-secrets-v1'
MAX_IMAGES = 4
MAX_LAYERS = 16
MAX_MANIFEST = 262144
MAX_CONFIG = 1048576
MAX_LAYER = 8 * 1024 * 1024
MAX_IMAGE = 16 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_MEMBERS = 2000
MAX_CALLS = 64
MAX_SECONDS = 120
MAX_LEAKS = 256
MAX_LOCATIONS = 2000
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def _sha(raw): return 'sha256:' + hashlib.sha256(raw).hexdigest()


def normalize_selected(values, scope):
    if (not isinstance(values, list) or not 1 <= len(values) <= MAX_IMAGES
            or any(not isinstance(value, str) for value in values) or len(set(values)) != len(values)):
        raise ValueError('bounded unique image selection required')
    result = []
    for value in values:
        if not isinstance(value, str) or value.startswith('https://'):
            raise ValueError('literal immutable registry image required')
        try:
            uri, repo, digest = _digest_uri(value)
        except Exception:
            raise ValueError('selected image must name an immutable Artifact Registry digest') from None
        if (repo.rsplit('/', 1)[-1] in ('.', '..') or not repo.startswith(scope + '/')
                or value != value.lower()):
            raise ValueError('selected image outside native project/registry')
        result.append(uri)
    return result


def bind_image(row, scope, repositories, projects):
    uri, repo, digest, _ = parse_image_uri(row.get('uri'))
    if (repo.rsplit('/', 1)[-1] in ('.', '..') or not repo.startswith(scope + '/') or row.get('repository') != repo or row.get('digest') != digest
            or not isinstance(row.get('name'), str) or not row['name'].startswith(repo + '/dockerImages/')
            or unquote(row['name'][len(repo + '/dockerImages/'):]) != parse_image_uri(uri)[3]):
        raise ValueError('native DockerImage binding mismatch')
    matching = [r for r in repositories if r.get('name') == repo and r.get('format') == 'DOCKER']
    matching_projects = [p for p in projects if p.get('projectId') == scope.split('/')[1] and
            (p.get('name') == scope or re.fullmatch(r'projects/[0-9]+', str(p.get('name'))))]
    if len(matching) != 1 or len(matching_projects) != 1:
        raise ValueError('native repository/project join incomplete')
    return uri, repo, digest


class Reader:
    """Dedicated streaming session; only derived fixed registry URLs get auth."""
    def __init__(self, transport, *, session=None):
        if session is None:
            import requests
            session = requests.Session()
            session.trust_env = False
            session.auth = None
        self.session, self.transport = session, transport
        self.end = time.monotonic() + MAX_SECONDS
        self.calls, self.bytes = 0, 0
        self.request_ids = []
        self.current_receipt = None

    def check(self):
        self.transport.check_cancelled()
        if time.monotonic() >= self.end: raise TimeoutError('image inspection deadline')

    def close(self): self.session.close()

    def get(self, uri, category, digest, cap, size=None):
        receipt = {'method': 'GET', 'operation': 'artifactregistry.registry_content_get',
                   'category': category if category in ('manifests', 'blobs') else None,
                   'digest': digest if isinstance(digest, str) and DIGEST.fullmatch(digest) else None,
                   'scope': None, 'status': 'unavailable', 'attempts': 0, 'http_attempts': 0}
        self.current_receipt = receipt
        try:
            _, repo, _, _ = parse_image_uri(uri)
            receipt['scope'] = '/'.join(repo.split('/')[:2])
            result = self._get(uri, category, digest, cap, size)
            receipt['status'] = 'collected'
            return result
        except Exception:
            if receipt.get('http_status') in (401, 403):
                receipt['status'] = 'denied'
            raise
        finally:
            with self.transport.lock:
                if not hasattr(self.transport, 'evidence'):
                    self.transport.evidence = []
                receipt['id'] = 'request-' + str(len(self.transport.evidence) + 1)
                self.transport.evidence.append(receipt)
                self.request_ids.append(receipt['id'])
            self.current_receipt = None

    def _get(self, uri, category, digest, cap, size=None):
        self.check()
        canonical, _, _, _ = parse_image_uri(uri)
        parsed = urlsplit(canonical)
        if any(segment in ('', '.', '..') for segment in parsed.path.lstrip('/').split('/')):
            raise ValueError('unsafe registry repository path')
        if category not in ('manifests', 'blobs') or DIGEST.fullmatch(digest) is None:
            raise ValueError('fixed registry object required')
        image_path = parsed.path.split('@', 1)[0].lstrip('/')
        url = 'https://' + parsed.netloc + '/v2/' + image_path + '/' + category + '/' + digest
        if self.calls >= MAX_CALLS: raise ValueError('registry call bound')
        with self.transport.lock:
            self.transport.check_cancelled()
            if self.transport.max_calls is not None and self.transport.calls >= self.transport.max_calls:
                raise ValueError('native call budget')
            self.transport.calls += 1
        self.calls += 1
        self.current_receipt['attempts'] = 1
        authorization = self.transport.credentials.headers().get('Authorization')
        if not isinstance(authorization, str) or not re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', authorization):
            raise ValueError('native access token unavailable')
        basic = base64.b64encode(('oauth2accesstoken:' + authorization[7:]).encode()).decode()
        headers = {'Authorization': 'Basic ' + basic, 'Accept-Encoding': 'identity',
                   'Accept': OCI + ', ' + DOCKER if category == 'manifests' else 'application/octet-stream'}
        if hasattr(self.session, 'cookies'):
            self.session.cookies.clear()
        self.current_receipt['http_attempts'] = 1
        response = self.session.request('GET', url, headers=headers, stream=True,
            allow_redirects=False, timeout=min(10, self.transport.timeout, max(.001, self.end - time.monotonic())))
        try:
            if type(response.status_code) is int and 100 <= response.status_code <= 599:
                self.current_receipt['http_status'] = response.status_code
            if (response.status_code != 200 or response.url != url or response.history
                    or response.headers.get('Content-Encoding', 'identity') != 'identity'
                    or response.headers.get('WWW-Authenticate') is not None):
                raise ValueError('registry redirect/challenge/denied/unexpected response')
            length = response.headers.get('Content-Length')
            if length is not None and (not length.isdecimal() or int(length) > cap or size is not None and int(length) != size):
                raise ValueError('registry stream size differs')
            header_digest = response.headers.get('Docker-Content-Digest')
            if header_digest is not None and header_digest != digest:
                raise ValueError('registry header digest differs')
            output = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                self.check()
                if not isinstance(chunk, bytes): raise ValueError('invalid registry stream')
                if not chunk: continue
                self.bytes += len(chunk)
                if len(output) + len(chunk) > cap or self.bytes > MAX_IMAGES * MAX_IMAGE:
                    raise ValueError('registry stream bound')
                output.extend(chunk)
            if size is not None and len(output) != size or _sha(output) != digest:
                raise ValueError('registry descriptor digest/size differs')
            return bytes(output)
        finally:
            response.close()


class Deadline:
    """The reused scanner has two fixed <=15s adapters; reserve their full bound."""
    def __init__(self, reader): self.reader = reader
    def check_deadline(self):
        self.reader.check()
        if self.reader.end - time.monotonic() < 31:
            raise TimeoutError('insufficient remaining dual-detector time')


def _descriptor(value, types, cap):
    if (not isinstance(value, dict) or set(value) - {'digest', 'size', 'mediaType', 'annotations'}
            or not isinstance(value.get('digest'), str) or not DIGEST.fullmatch(value['digest'])
            or type(value.get('size')) is not int or not 0 < value['size'] <= cap
            or value.get('mediaType') not in types):
        raise ValueError('unsupported or foreign descriptor')
    return {key: value[key] for key in ('digest', 'size', 'mediaType')}


def _tar(raw, media, expected_diff):
    if media.endswith('gzip'):
        decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
        expanded = decoder.decompress(raw, MAX_LAYER + 1)
        if len(expanded) > MAX_LAYER or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('gzip expansion/concatenation unsupported')
    else:
        expanded = raw
    if len(expanded) > MAX_LAYER or _sha(expanded) != expected_diff:
        raise ValueError('uncompressed rootfs identity/bound mismatch')
    # Preflight unsupported nested archives before calling the common scanner.
    files = 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        for ordinal, member in enumerate(archive):
            if ordinal >= MAX_MEMBERS: raise ValueError('layer file bound')
            _path(member.name)
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
                raise ValueError('links/devices/extensions unsupported')
            if member.isfile():
                files += 1
                if member.size > MAX_LAYER: raise ValueError('file bound')
                stream = archive.extractfile(member)  # memory stream only, never filesystem extraction
                head = stream.read(512)
                if (head.startswith((b'PK\x03\x04', b'\x1f\x8b', b'BZh', b'\xfd7zXZ', b'7z\xbc\xaf', b'Rar!', b'\x28\xb5\x2f\xfd'))
                        or head[257:262] == b'ustar'):
                    raise ValueError('nested archive unsupported')
    # The shared detector caches redacted locations. A filename can contain a
    # different credential from the file body, so never pass original filenames
    # to that cache. Hash verification above uses original bytes; only TAR header
    # names are pseudonymized here, preserving every file byte and layer order.
    safe, offset, ordinal, names = bytearray(expanded), 0, 0, set()
    while offset + 512 <= len(expanded):
        block = expanded[offset:offset+512]
        if block == bytes(512):
            break
        member = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
        original = _path(member.name)
        if original in names or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            raise ValueError('duplicate/unsupported original TAR member')
        names.add(original)
        ordinal += 1
        member.name = 'member-' + str(ordinal)
        safe[offset:offset+512] = member.tobuf(format=tarfile.USTAR_FORMAT)
        offset += 512 + ((member.size + 511) // 512) * 512
    return bytes(safe), files


def inspect_image(row, scope, repositories, projects, reader):
    try:
        uri, repo, digest = bind_image(row, scope, repositories, projects)
        raw = reader.get(uri, 'manifests', digest, MAX_MANIFEST)
        manifest = _json(raw)
        if (not isinstance(manifest, dict) or set(manifest) - {'schemaVersion', 'mediaType', 'config', 'layers', 'annotations'}
                or type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 2
                or manifest.get('mediaType') not in (OCI, DOCKER)):
            raise ValueError('single-platform manifest required')
        config = _descriptor(manifest['config'], CONFIG_TYPES, MAX_CONFIG)
        layers = manifest['layers']
        if not isinstance(layers, list) or not 1 <= len(layers) <= MAX_LAYERS:
            raise ValueError('all supported image layers required')
        layers = [_descriptor(layer, TAR_TYPES, MAX_LAYER) for layer in layers]
        if sum(v['size'] for v in [config] + layers) > MAX_IMAGE:
            raise ValueError('image compressed bound')
        config_raw = reader.get(uri, 'blobs', config['digest'], MAX_CONFIG, config['size'])
        decoded = _json(config_raw)
        if (not isinstance(decoded, dict) or decoded.get('os') != 'linux' or decoded.get('architecture') not in ('amd64', 'arm64')
                or not isinstance(decoded.get('rootfs'), dict) or decoded['rootfs'].get('type') != 'layers'
                or not isinstance(decoded['rootfs'].get('diff_ids'), list) or len(decoded['rootfs']['diff_ids']) != len(layers)
                or any(not isinstance(d, str) or not DIGEST.fullmatch(d) for d in decoded['rootfs']['diff_ids'])):
            raise ValueError('unsupported platform/config rootfs')
        reader.check()
        outcome = scan_content(config_raw, 'image-config.json', timeout=min(10, max(.001, (reader.end-time.monotonic())/2)))
        if not outcome['complete']: raise ValueError('config detector incomplete')
        leaks = [dict(leak, locations=[dict(loc, layer=config['digest']) for loc in leak['locations']]) for leak in outcome['leaks']]
        expanded, members, files, scanned = len(config_raw), 0, 0, []
        for layer, diff in zip(layers, decoded['rootfs']['diff_ids']):
            reader.check()
            payload = reader.get(uri, 'blobs', layer['digest'], MAX_LAYER, layer['size'])
            uncompressed, regular = _tar(payload, layer['mediaType'], diff)
            if len(uncompressed) + expanded > MAX_EXPANDED or files + regular > MAX_MEMBERS:
                raise ValueError('image expansion/member bound')
            refs, tar_expanded, members = scan_tar(uncompressed, 'application/vnd.oci.image.layer.v1.tar', Deadline(reader), (expanded, members))
            expanded, files = tar_expanded, files + regular
            if members > MAX_MEMBERS: raise ValueError('image member bound')
            for ordinal, ref in enumerate(refs):
                # A filename can itself contain a different secret from the file
                # body. Retain ordinal references, never provider-controlled paths.
                leaks.extend(dict(leak, locations=[dict(loc, path='matched-file-' + str(ordinal + 1), layer=layer['digest']) for loc in leak['locations']]) for leak in ref.get('Leaks', []))
            scanned.append(layer['digest'])
        reader.check()
        leaks = merge_leaks(leaks)
        if len(leaks) > MAX_LEAKS or sum(len(leak['locations']) for leak in leaks) > MAX_LOCATIONS:
            raise ValueError('indicator bound')
        return {'schema': SCHEMA, 'status': 'collected', 'complete': True, 'uri': uri, 'repository': repo,
            'manifest_digest': digest, 'descriptors': deepcopy([config] + layers), 'layers_scanned': scanned,
            'expanded_bytes': expanded, 'members': members, 'regular_files': files,
            'engines': outcome['engines'], 'leaks': leaks, 'verification': 'not_attempted'}
    except Exception:
        return {'schema': SCHEMA, 'status': 'unavailable', 'complete': False, 'leaks': []}


def enrich(collector, *, reader_factory=None):
    """Root calls after native SBOM/image inventory; no new inventory is invented."""
    reader_factory = Reader if reader_factory is None else reader_factory
    options = collector.options
    kinds = options.get('_content_secret_scan_kinds', [])
    if options.get('content_secret_scans') is not True or not isinstance(kinds, (list, tuple)) or 'artifact_image' not in kinds:
        return
    for scope in collector.scopes:
        images = collector.collections.get(('artifact_image', scope))
        if not isinstance(images, dict): continue
        selected_rows = []
        reader = None
        try:
            repos = collector.collections.get(('artifact_repository', scope), {})
            projects = collector.collections.get(('project', scope), {})
            if any(c.get('status') != 'collected' or not isinstance(c.get('items'), list) for c in (images, repos, projects)):
                raise ValueError('native parent inventories incomplete')
            run_proof, run_plan = None, None
            requested = list(options.get('selected_artifact_images', []))
            if 'selected_cloudrun_services' in options:
                from . import gcp_cloudrun_image_inspection as run_sources
                run_plan, run_proof = run_sources.prepare(collector, scope, images['items'],
                    repos['items'], projects['items'])
                requested = list(dict.fromkeys(requested + run_plan['selected_artifact_images']))
            selected = normalize_selected(requested, scope)
            for row in images['items']:
                if row.get('uri') in selected:
                    selected_rows.append(row)
                    bind_image(row, scope, repos['items'], projects['items'])
            if {row['uri'] for row in selected_rows} != set(selected) or len(selected_rows) != len(selected):
                raise ValueError('selected image missing or duplicated in native inventory')
            reader = reader_factory(collector.transport)
            for row in selected_rows:
                before = len(reader.request_ids)
                row[MARKER] = inspect_image(row, scope, repos['items'], projects['items'], reader)
                receipts = reader.request_ids[before:]
                provenance = row.setdefault('_provenance', {})
                provenance['source_requests'] = sorted(set(provenance.get('source_requests', [])) | set(receipts))
                provenance.setdefault('scope', scope)
                images['source_requests'] = sorted(set(images.get('source_requests', [])) | set(receipts))
                row.setdefault('_coverage', {})[MARKER] = {
                    'status': 'collected' if row[MARKER]['complete'] else 'unavailable',
                    'source_requests': receipts}
            if run_proof is not None:
                completed = run_sources.finish(collector, run_proof)
                refs = [r['source_request'] for r in completed['reads'] + completed['revalidation']]
                for row in selected_rows:
                    if row['uri'].removeprefix('https://') in run_plan['selected_artifact_images']:
                        row[run_sources.MARKER] = deepcopy(completed)
                        row['_provenance']['source_requests'] = sorted(set(row['_provenance']['source_requests']) | set(refs))
                images['source_requests'] = sorted(set(images.get('source_requests', [])) | set(refs))

        except Exception:
            for row in selected_rows: row[MARKER] = {'schema': SCHEMA, 'status': 'unavailable', 'complete': False, 'leaks': []}
            images.update(status='partial', coverage_status='partial', error={'code': 'selected_image_content_unavailable'})
        finally:
            if reader is not None: reader.close()
