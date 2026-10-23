"""Unregistered exact selected Pod -> ECR digest byte capture, with separate auth.

Factories are trusted caller-owned dependencies, never looked up from selectors.
No kubeconfig, Secret, exec, registry login, image execution or latest selection.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import http.client
import importlib.util
import json
import logging
from pathlib import Path
import re
import secrets
import ssl
import sys
import tarfile
import time
from urllib.parse import urlsplit

from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from peaso.collectors.aws_package_content_indicators import _json, OCI, DOCKER, TAR_TYPES, CONFIG_TYPES, validate_url
from peaso.collectors.gcp_image_secret_indicators import _tar, _descriptor
from peaso.collectors.aws_workload_command_source_20261020 import bounded_response, response_size

CHECK = 'k8s.review.selected_ecr_image.captured_secret_indicators'
KIND = 'k8s_selected_ecr_image_source_20261020'
SCHEMA = 'k8s-selected-ecr-image-source-v1'
OPTION = 'selected_k8s_ecr_images'
GRANTS = ['k8s-selected-pod-ecr-source-v1', 'aws-selected-ecr-image-bytes-v1']
MAX_TARGETS, MAX_CALLS, MAX_SECONDS = 2, 32, 120
MAX_POD, MAX_MANIFEST, MAX_CONFIG = 524288, 262144, 262144
MAX_LAYER, MAX_IMAGE, MAX_TOTAL = 4 * 1024**2, 8 * 1024**2, 16 * 1024**2
MAX_EXPANDED, MAX_MEMBERS, MAX_LAYERS = 8 * 1024**2, 128, 4
MAX_LEAKS, MAX_LOCATIONS = 128, 512
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
LABEL = re.compile(r'[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z')
TOKEN = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
_PLANS = {}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def reviewed_sources():
    root = Path(__file__).resolve().parents[2]
    receipt = _json((root / 'docs/check-review/k8s-selected-ecr-image-source-20261020.json').read_text())
    for name, expected in receipt['source_hashes'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('source_binding')
    return hashlib.sha256(canonical(receipt['source_hashes']).encode()).hexdigest()


def resolver():
    """Load the existing pure association file, never the checks registry."""
    name = '_k8s_ecr_existing_association_20261020'
    if name not in sys.modules:
        path = Path(__file__).resolve().parents[1] / 'checks/k8s_image_source_association_20261020.py'
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module  # dataclasses needs its own real module identity.
        spec.loader.exec_module(module)
    return sys.modules[name]


def contexts(k8s, aws):
    if (not isinstance(k8s, dict) or set(k8s) != {'customer', 'credential', 'cluster', 'namespace', 'api_server'}
            or not isinstance(aws, dict) or set(aws) != {'customer', 'credential', 'scope', 'repository'}
            or any(not isinstance(c[k], str) or not TOKEN.fullmatch(c[k]) for c, keys in (
                (k8s, ('customer', 'credential', 'cluster')), (aws, ('customer', 'credential'))) for k in keys)
            or k8s['customer'] != aws['customer'] or not isinstance(k8s['namespace'], str)
            or not LABEL.fullmatch(k8s['namespace']) or not isinstance(aws['scope'], str)
            or len(aws['scope']) > 80 or not re.fullmatch(r'[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+', aws['scope'])
            or '-iso' in aws['scope'] or not isinstance(aws['repository'], str)
            or not 2 <= len(aws['repository']) <= 128
            or not re.fullmatch(r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*', aws['repository'])):
        raise ValueError('trusted_context')
    endpoint = urlsplit(k8s['api_server']) if isinstance(k8s['api_server'], str) else None
    if (endpoint is None or len(k8s['api_server']) > 512 or endpoint.scheme != 'https'
            or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment
            or endpoint.path or not re.fullmatch(r'[a-zA-Z0-9.-]+', endpoint.hostname)
            or endpoint.port not in (None, 443, 6443)):
        raise ValueError('trusted_endpoint')
    account, region = aws['scope'].split('/')
    suffix = 'amazonaws.com.cn' if region.startswith('cn-') else 'amazonaws.com'
    return account, region, f'{account}.dkr.ecr.{region}.{suffix}'


def prepare(options, *, k8s_context, aws_context):
    """Opaque, bounded, one-use pre-auth handle; input cannot supply observations."""
    if (not isinstance(options, dict) or set(options) != {'check_id', 'content_secret_scans',
            'aws_registry_content_read', 'content_secret_scan_grants', OPTION}
            or options['check_id'] != CHECK or options['content_secret_scans'] is not True
            or options['aws_registry_content_read'] is not True or options['content_secret_scan_grants'] != GRANTS):
        raise ValueError('explicit_separate_grants_required')
    account, region, registry = contexts(k8s_context, aws_context)
    targets = options[OPTION]
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        raise ValueError('selection_bound')
    seen = set()
    for t in targets:
        if (not isinstance(t, dict) or set(t) != {'namespace', 'pod', 'uid', 'container_type', 'container', 'registry', 'repository', 'digest'}
                or t['namespace'] != k8s_context['namespace'] or t['registry'] != registry
                or t['repository'] != aws_context['repository'] or t['container_type'] not in ('regular', 'init', 'ephemeral')
                or any(not isinstance(t[k], str) or not LABEL.fullmatch(t[k]) for k in ('namespace', 'pod', 'container'))
                or not isinstance(t['uid'], str) or not TOKEN.fullmatch(t['uid'])
                or not isinstance(t['digest'], str) or not DIGEST.fullmatch(t['digest'])):
            raise ValueError('exact_selection')
        ident = _fingerprint(canonical([t[k] for k in ('namespace', 'pod', 'uid', 'container_type', 'container')]))
        if ident in seen:
            raise ValueError('duplicate_selection')
        seen.add(ident)
    binding = reviewed_sources()
    if len(_PLANS) >= 16:
        raise ValueError('pending_plan_bound')
    handle = 'ecr-plan:' + secrets.token_hex(16)
    expected = {'schema': SCHEMA, 'capture': 'ecr-capture:' + secrets.token_hex(16),
        'context': _fingerprint(canonical([k8s_context, aws_context])), 'binding': binding,
        'selection': {KIND + ':' + _fingerprint(canonical(t)): {
            'image': _fingerprint(canonical([aws_context['scope'], t['repository'], t['digest']])),
            'pod': _fingerprint(canonical([k8s_context['cluster'], t['namespace'], t['pod'], t['uid'], t['container_type'], t['container']]))}
            for t in targets}}
    _PLANS[handle] = {'targets': deepcopy(targets), 'k8s': deepcopy(k8s_context), 'aws': deepcopy(aws_context),
        'expected': expected, 'created': time.monotonic()}
    return {'plan': handle, 'seal': _fingerprint(handle)}


def expected_context(plan):
    if (not isinstance(plan, dict) or set(plan) != {'plan', 'seal'} or not isinstance(plan['plan'], str)
            or plan['seal'] != _fingerprint(plan['plan']) or plan['plan'] not in _PLANS):
        raise ValueError('plan_binding')
    body = _PLANS[plan['plan']]
    if time.monotonic() - body['created'] > 300 or body['expected']['binding'] != reviewed_sources():
        _PLANS.pop(plan['plan'], None)
        raise ValueError('expired_or_changed_plan')
    return deepcopy(body['expected'])


def discard(plan):
    expected_context(plan)
    _PLANS.pop(plan['plan'], None)


@dataclass
class KubernetesAccess:
    context: dict
    token: str
    tls: ssl.SSLContext


@dataclass
class AWSAccess:
    context: dict
    session: object


def left(state):
    remaining = state['end'] - time.monotonic()
    if remaining <= 0:
        raise ValueError('deadline')
    return remaining


def attempt(state):
    left(state)
    if state['calls'] >= MAX_CALLS:
        raise ValueError('call_bound')
    state['calls'] += 1


def body_read(response, cap, state, expected=None):
    if response.status != 200 or response.getheader('Content-Encoding', 'identity') != 'identity':
        raise ValueError('native_http')
    declared = response.getheader('Content-Length')
    if declared is not None and (not re.fullmatch(r'[0-9]{1,10}', declared)
            or int(declared) > cap or expected is not None and int(declared) != expected):
        raise ValueError('native_length')
    data = bytearray()
    limit = min(cap, MAX_TOTAL - state['bytes'])
    while True:
        left(state)
        if declared is not None and len(data) == int(declared):
            break
        remaining = limit - len(data)
        if remaining <= 0:
            raise ValueError('byte_bound')
        amount = min(65536, remaining, int(declared) - len(data) if declared is not None else remaining)
        chunk = response.read(amount)
        if not isinstance(chunk, bytes) or len(chunk) > amount:
            raise ValueError('native_chunk')
        if not chunk:
            break
        state['bytes'] += len(chunk)
        data.extend(chunk)
    if (declared is not None and len(data) != int(declared)) or expected is not None and len(data) != expected:
        raise ValueError('native_length')
    return bytes(data)


def pod_get(access, target, state):
    endpoint = urlsplit(access.context['api_server'])
    path = f"/api/v1/namespaces/{target['namespace']}/pods/{target['pod']}"
    attempt(state)
    conn = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443,
        timeout=min(3, left(state)), context=access.tls)
    response = None
    try:
        conn.request('GET', path, headers={'Authorization': 'Bearer ' + access.token,
            'Accept': 'application/json', 'Accept-Encoding': 'identity'})
        response = conn.getresponse()
        raw = body_read(response, MAX_POD, state)
        document = _json(raw)
        if not isinstance(document, dict):
            raise ValueError('native_pod')
        selector = {'cluster_id': access.context['cluster'], 'api_version': 'v1', 'kind': 'Pod',
            'namespace': target['namespace'], 'name': target['pod'], 'uid': target['uid'],
            'container_type': target['container_type'], 'container_name': target['container']}
        resolved = resolver().resolve_image_source(selector, document, cluster_id=access.context['cluster'])
        expected = target['registry'] + '/' + target['repository'] + '@' + target['digest']
        if resolved.get('status') != 'associated' or resolved.get('immutable_reference') != expected:
            raise ValueError('pod_image_unresolved')
        return {'receipt': _fingerprint(path), 'uid': _fingerprint(document['metadata']['uid']),
            'version': _fingerprint(document['metadata']['resourceVersion']),
            'association': _fingerprint(canonical(resolved)), 'http_status': 200,
            'bytes': len(raw), 'claim': 'pod_status_reported_digest'}
    finally:
        if response is not None:
            response.close()
        conn.close()


def aws_call(access, service, operation, args, state):
    from botocore.config import Config
    allowed = {'sts': {'GetCallerIdentity': 'get_caller_identity'}, 'ecr': {
        'DescribeRepositories': 'describe_repositories', 'BatchGetImage': 'batch_get_image',
        'GetDownloadUrlForLayer': 'get_download_url_for_layer'}}
    if operation not in allowed.get(service, {}):
        raise ValueError('readonly_operation')
    account, region = access.context['scope'].split('/')
    expected = deepcopy(args)
    repo_args = {'registryId': account, 'repositoryNames': [access.context['repository']]}
    if (service == 'sts' and args != {} or operation == 'DescribeRepositories' and args != repo_args
            or service == 'ecr' and operation != 'DescribeRepositories' and (
                args.get('registryId') != account or args.get('repositoryName') != access.context['repository'])):
        raise ValueError('aws_request_binding')
    if operation == 'BatchGetImage':
        ids = expected.get('imageIds')
        if (set(expected) != {'registryId', 'repositoryName', 'imageIds', 'acceptedMediaTypes'}
                or expected['acceptedMediaTypes'] != [OCI, DOCKER] or not isinstance(ids, list) or len(ids) != 1
                or not isinstance(ids[0], dict) or set(ids[0]) != {'imageDigest'}
                or not isinstance(ids[0]['imageDigest'], str) or not DIGEST.fullmatch(ids[0]['imageDigest'])):
            raise ValueError('exact_digest_required')
    if operation == 'GetDownloadUrlForLayer' and (set(expected) != {'registryId', 'repositoryName', 'layerDigest'}
            or not isinstance(expected['layerDigest'], str) or not DIGEST.fullmatch(expected['layerDigest'])):
        raise ValueError('exact_digest_required')
    suffix = 'amazonaws.com.cn' if region.startswith('cn-') else 'amazonaws.com'
    endpoint = f'https://{"api.ecr" if service == "ecr" else "sts"}.{region}.{suffix}'
    timeout = min(3, left(state) / 3)
    client = access.session.client(service, region_name=region, endpoint_url=endpoint, verify=True,
        config=Config(signature_version='v4', connect_timeout=timeout, read_timeout=timeout,
            retries={'total_max_attempts': 1}, proxies={}, ignore_configured_endpoint_urls=True,
            use_fips_endpoint=False, use_dualstack_endpoint=False))
    event, guard, original = None, None, None
    try:
        if client.meta.endpoint_url != endpoint or client.meta.region_name != region or client.meta.service_model.service_name != service:
            raise ValueError('aws_endpoint')
        def validate(request):
            left(state)
            body = request.body.decode() if isinstance(request.body, bytes) else request.body
            if request.method != 'POST' or request.url != endpoint + '/':
                raise ValueError('aws_wire')
            if service == 'sts':
                if body != 'Action=GetCallerIdentity&Version=2011-06-15':
                    raise ValueError('aws_wire')
            else:
                target = request.headers.get('X-Amz-Target')
                target = target.decode() if isinstance(target, bytes) else target
                if _json(body) != expected or target != client.meta.service_model.metadata['targetPrefix'] + '.' + operation:
                    raise ValueError('aws_wire')
        sends, events = [], []
        def guard(request, **kwargs):
            events.append(True)
            if len(events) != 1:
                raise ValueError('aws_retry')
            validate(request)
        event = 'before-send.' + client.meta.service_model.service_id.hyphenize() + '.' + operation
        client.meta.events.register_first(event, guard)
        transport = client._endpoint.http_session
        original = transport.send
        def send(request):
            validate(request)
            sends.append(True)
            if len(sends) != 1:
                raise ValueError('aws_retry')
            return bounded_response(original(request), state['end'], state['native'])
        transport.send = send
        attempt(state)
        value = getattr(client, allowed[service][operation])(**args)
        left(state)
        size = response_size(value)
        if size + state['native']['bytes'] > 4 * 1024**2:
            raise ValueError('aws_byte_bound')
        state['native']['bytes'] += size
        meta = value['ResponseMetadata']
        if type(meta['HTTPStatusCode']) is not int or meta['HTTPStatusCode'] != 200 or not isinstance(meta['RequestId'], str) or not 1 <= len(meta['RequestId']) <= 256:
            raise ValueError('aws_receipt')
        return value, {'operation': operation, 'request': _fingerprint(canonical(expected)),
            'response': _fingerprint(meta['RequestId']), 'bytes': size, 'http_status': 200}
    finally:
        if original is not None:
            client._endpoint.http_session.send = original
        if event is not None:
            client.meta.events.unregister(event, guard)
        client.close()


def blob_get(access, descriptor, state, receipts):
    account, region = access.context['scope'].split('/')
    value, receipt = aws_call(access, 'ecr', 'GetDownloadUrlForLayer', {'registryId': account,
        'repositoryName': access.context['repository'], 'layerDigest': descriptor['digest']}, state)
    receipts.append(receipt)
    if value.get('layerDigest') != descriptor['digest']:
        raise ValueError('blob_identity')
    # Only a native ECR-returned regional S3 URL, never a caller URL or auth redirect.
    url = validate_url(value['downloadUrl'], region)
    parsed = urlsplit(url)
    attempt(state)
    conn = http.client.HTTPSConnection(parsed.hostname, timeout=min(3, left(state)), context=ssl.create_default_context())
    response = None
    try:
        conn.request('GET', parsed.path + '?' + parsed.query, headers={'Accept-Encoding': 'identity'})
        response = conn.getresponse()
        raw = body_read(response, min(MAX_LAYER, descriptor['size']), state, descriptor['size'])
        if sha(raw) != descriptor['digest']:
            raise ValueError('blob_digest')
        receipts.append({'operation': 'S3PresignedGet', 'request': _fingerprint(url),
            'response': _fingerprint(descriptor['digest']), 'bytes': len(raw), 'http_status': 200})
        return raw
    finally:
        if response is not None:
            response.close()
        conn.close()


def scan_part(raw, row, label, state, matches):
    path = row['id'] + ':' + _fingerprint(label)
    outcome = scan_content(raw, path, timeout=min(15, left(state) / 3), _redact_values=matches.update)
    part = {'path': path, 'source': label.split(':', 1)[0], 'bytes': len(raw),
        'engines': outcome['engines'], 'complete': outcome['complete'], 'leaks': outcome['leaks']}
    candidates = merge_leaks(row['leaks'] + outcome['leaks'])
    if len(candidates) > MAX_LEAKS or sum(len(x['locations']) for x in candidates) > MAX_LOCATIONS:
        remaining, allowed = MAX_LOCATIONS, {}
        for leak in candidates[:MAX_LEAKS]:
            locations = leak['locations'][:remaining]
            if not locations:
                break
            remaining -= len(locations)
            allowed[leak['fingerprint']] = locations
        row['parts'].append(part)
        for retained in row['parts']:
            kept = []
            for leak in retained['leaks']:
                locations = [loc for loc in leak['locations'] if loc in allowed.get(leak['fingerprint'], [])]
                if locations:
                    kept.append({**deepcopy(leak), 'locations': locations})
            retained['leaks'] = kept
            retained['complete'] = False
        row['leaks'] = merge_leaks([leak for p in row['parts'] for leak in p['leaks']])
        raise ValueError('finding_bound')
    row['parts'].append(part)
    row['leaks'] = candidates
    left(state)


def file_ranges(raw, remaining_members):
    """Strict full TAR terminator contract after the existing diff-ID preflight.

    tarfile iteration alone can silently ignore trailing concatenated archives.
    Retain only offsets into the memory buffer; no extraction or provider names.
    """
    offset, members, files = 0, 0, []
    while offset + 512 <= len(raw):
        header = raw[offset:offset + 512]
        if header == bytes(512):
            if offset + 1024 > len(raw) or any(raw[offset:]):
                raise ValueError('tar_trailing_content')
            return files, members
        member = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        members += 1
        if (members > remaining_members or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                or not 0 <= member.size <= 1024**2 or member.isdir() and member.size != 0):
            raise ValueError('member_bound')
        start = offset + 512
        end = start + member.size
        offset = start + ((member.size + 511) // 512) * 512
        if end > len(raw) or offset > len(raw):
            raise ValueError('member_length')
        if member.isfile():
            files.append((members, start, end))
    raise ValueError('tar_missing_terminator')


def image_capture(access, target, row, state, matches):
    account, region, registry = contexts(state['k8s'], access.context)
    identity, receipt = aws_call(access, 'sts', 'GetCallerIdentity', {}, state)
    row['requests'].append(receipt)
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    if (identity.get('Account') != account or not isinstance(identity.get('UserId'), str) or not identity['UserId']
            or not re.fullmatch(r'arn:' + partition + r':(?:iam|sts)::' + account + r':(?:user|role|assumed-role|federated-user)/[^\s]{1,1024}|arn:' + partition + ':iam::' + account + ':root', identity.get('Arn', ''))):
        raise ValueError('aws_identity')
    row['aws_principal'] = _fingerprint(canonical({k: identity[k] for k in ('Account', 'Arn', 'UserId')}))
    if state.get('aws_principal') not in (None, row['aws_principal']):
        raise ValueError('aws_principal_changed')
    state['aws_principal'] = row['aws_principal']
    native, receipt = aws_call(access, 'ecr', 'DescribeRepositories', {'registryId': account, 'repositoryNames': [target['repository']]}, state)
    row['requests'].append(receipt)
    repos = native.get('repositories')
    if native.get('nextToken') not in (None, '') or not isinstance(repos, list) or len(repos) != 1:
        raise ValueError('repository_cardinality')
    repo = repos[0]
    arn = f'arn:{partition}:ecr:{region}:{account}:repository/{target["repository"]}'
    if (repo.get('registryId') != account or repo.get('repositoryName') != target['repository']
            or repo.get('repositoryArn') != arn or repo.get('repositoryUri') != registry + '/' + target['repository']):
        raise ValueError('repository_binding')
    native, receipt = aws_call(access, 'ecr', 'BatchGetImage', {'registryId': account, 'repositoryName': target['repository'],
        'imageIds': [{'imageDigest': target['digest']}], 'acceptedMediaTypes': [OCI, DOCKER]}, state)
    row['requests'].append(receipt)
    images = native.get('images')
    if native.get('failures') != [] or not isinstance(images, list) or len(images) != 1:
        raise ValueError('manifest_cardinality')
    image = images[0]
    raw = image.get('imageManifest')
    if (image.get('registryId') != account or image.get('repositoryName') != target['repository']
            or image.get('imageId', {}).get('imageDigest') != target['digest']
            or not isinstance(raw, str) or len(raw) > MAX_MANIFEST or len(raw.encode()) > MAX_MANIFEST
            or sha(raw.encode()) != target['digest']):
        raise ValueError('manifest_binding')
    manifest = _json(raw)
    if (not isinstance(manifest, dict) or set(manifest) - {'schemaVersion', 'mediaType', 'config', 'layers', 'annotations'}
            or type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 2
            or manifest.get('mediaType') not in (OCI, DOCKER) or image.get('imageManifestMediaType') != manifest['mediaType']):
        raise ValueError('manifest_shape')
    config = _descriptor(manifest['config'], CONFIG_TYPES, MAX_CONFIG)
    layers = manifest['layers']
    if not isinstance(layers, list) or not 1 <= len(layers) <= MAX_LAYERS:
        raise ValueError('layer_bound')
    layers = [_descriptor(d, TAR_TYPES, MAX_LAYER) for d in layers]
    if len({d['digest'] for d in [config] + layers}) != len(layers) + 1 or sum(d['size'] for d in [config] + layers) > MAX_IMAGE:
        raise ValueError('descriptor_bound')
    row['manifest_bound'] = True
    row['descriptor_count'] = len(layers) + 1
    scan_part(raw.encode(), row, 'manifest:0', state, matches)
    config_raw = blob_get(access, config, state, row['requests'])
    decoded = _json(config_raw)
    diffs = decoded.get('rootfs', {}).get('diff_ids') if isinstance(decoded, dict) else None
    if (not isinstance(decoded, dict) or decoded.get('os') != 'linux' or decoded.get('architecture') not in ('amd64', 'arm64')
            or decoded.get('rootfs', {}).get('type') != 'layers' or not isinstance(diffs, list)
            or len(diffs) != len(layers) or any(not isinstance(d, str) or not DIGEST.fullmatch(d) for d in diffs)):
        raise ValueError('config_platform')
    scan_part(config_raw, row, 'config:0', state, matches)
    row['blobs_verified'] += 1
    expanded, members = len(config_raw), 0
    for index, (descriptor, diff) in enumerate(zip(layers, diffs)):
        raw_layer = blob_get(access, descriptor, state, row['requests'])
        safe, _ = _tar(raw_layer, descriptor['mediaType'], diff)
        if len(safe) + expanded > MAX_EXPANDED or len(safe) % 512 or len(safe) < 1024 or safe[-1024:] != bytes(1024):
            raise ValueError('expanded_bound')
        expanded += len(safe)
        files, count = file_ranges(safe, MAX_MEMBERS - members)
        members += count
        for ordinal, start, end in files:
            left(state)
            scan_part(safe[start:end], row, f'layer:{index}:member:{ordinal}', state, matches)
        row['blobs_verified'] += 1
    row['image_complete'] = all(p['complete'] for p in row['parts'])


def collect(plan, *, k8s_factory, aws_factory, on_matches=None):
    """Factory contexts are trusted; the returned portable context is not a grant."""
    expected = expected_context(plan)
    body = _PLANS.pop(plan['plan'])
    state = {'end': time.monotonic() + MAX_SECONDS, 'calls': 0, 'bytes': 0,
        'native': {'bytes': 0, 'wire_bytes': 0}, 'k8s': body['k8s']}
    result = {'schema': SCHEMA, 'context': expected, 'items': [], 'calls': 0,
        'http_bytes': 0, 'sdk_bytes': 0, 'matched_union_delivered': False}
    matches = set()
    try:
        if http.client.HTTPConnection.debuglevel != 0 or any(
                logging.getLogger(name).isEnabledFor(logging.DEBUG)
                for name in ('botocore', 'urllib3', 'boto3', *[
                    n for n in logging.Logger.manager.loggerDict
                    if n.startswith(('botocore.', 'urllib3.', 'boto3.'))])):
            raise ValueError('wire_debug_enabled')
        for target, ident in zip(body['targets'], expected['selection']):
            row = {'id': ident, 'image': expected['selection'][ident]['image'], 'pod': expected['selection'][ident]['pod'],
                'pod_before': None, 'pod_after': None, 'association_complete': False, 'manifest_bound': False,
                'descriptor_count': 0, 'blobs_verified': 0, 'image_complete': False, 'aws_principal': None,
                'requests': [], 'parts': [], 'leaks': [], 'runtime_filesystem': False, 'verification': 'not_attempted'}
            result['items'].append(row)
            access, aws = None, None
            try:
                left(state)
                access = k8s_factory(deepcopy(body['k8s']))
                if (not isinstance(access, KubernetesAccess) or access.context != body['k8s']
                        or not isinstance(access.token, str) or not re.fullmatch(r'[A-Za-z0-9._~+/-]{1,16384}=*', access.token)
                        or not isinstance(access.tls, ssl.SSLContext) or access.tls.verify_mode != ssl.CERT_REQUIRED
                        or not access.tls.check_hostname):
                    raise ValueError('k8s_factory_binding')
                row['pod_before'] = pod_get(access, target, state)
                aws = aws_factory(deepcopy(body['aws']))
                if not isinstance(aws, AWSAccess) or aws.context != body['aws']:
                    raise ValueError('aws_factory_binding')
                image_capture(aws, target, row, state, matches)
            except Exception:
                row['image_complete'] = False
            finally:
                if access is not None and row['pod_before'] is not None:
                    try:
                        row['pod_after'] = pod_get(access, target, state)
                        row['association_complete'] = all(row['pod_before'][k] == row['pod_after'][k]
                            for k in ('receipt', 'uid', 'version', 'association'))
                    except Exception:
                        pass
                access = aws = None
        if on_matches is not None:
            if not callable(on_matches):
                raise ValueError('trusted_finalizer')
            try:
                on_matches(frozenset(matches))
            except Exception:
                raise ValueError('finalizer_failed') from None
            result['matched_union_delivered'] = True
        result.update(calls=state['calls'], http_bytes=state['bytes'], sdk_bytes=state['native']['bytes'])
        if reviewed_sources() != expected['binding']:
            raise ValueError('source_binding')
        result['content_digest'] = sha(canonical(result).encode())
        # The trusted caller must retain this context independently of input.
        return result, {**deepcopy(expected), 'content_digest': result['content_digest']}
    finally:
        matches.clear()
        body.clear()
