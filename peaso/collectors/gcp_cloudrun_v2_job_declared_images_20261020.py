"""Unregistered, default-off Cloud Run v2 Job declared-image collector proposal.

Only exact caller-selected project/Job UID/container/SHA256 declarations are
associated. No executed/resolved image claim is made. All metadata and byte
sessions are dedicated, streaming GET-only sessions using the native transport's
credentials, cancellation, global call budget and source-request evidence.
"""
from copy import deepcopy
import hashlib
import json
import re
import tarfile
import time
from urllib.parse import quote

from peaso.checks import gcp_workload_image_source_association_20261020 as association
from peaso.secret_scanning import merge_leaks, scan_content
from . import gcp_image_secret_indicators as native
from .aws_package_content_indicators import PartialArchive

SCHEMA = 'gcp-cloudrun-v2-job-declared-images-proposal-20261020-v1'
MAX_SELECTIONS = 4
MAX_METADATA_CALLS = 32
MAX_METADATA_BODY = 32768
MAX_METADATA_BYTES = MAX_METADATA_CALLS * MAX_METADATA_BODY
MAX_SECONDS = 180
JOB_FIELDS = ('name,uid,etag,generation,observedGeneration,reconciling,deleteTime,'
              'expireTime,template(template(containers(name,image)))')
REPO_FIELDS = 'name,format,mode,updateTime'
IMAGE_FIELDS = 'name,uri,mediaType,updateTime'
PROJECT_FIELDS = 'name,projectId,state'


def _require(value, reason):
    if not value:
        raise ValueError(reason)


def normalize_selection(selectors, scope):
    """Closed selectors; validate everything before sessions or credentials."""
    _require(type(scope) is str and scope.startswith('projects/'), 'exact_project_required')
    project = scope.removeprefix('projects/')
    _require(association._PROJECT.fullmatch(project), 'exact_project_id_required')
    _require(type(selectors) is list and 1 <= len(selectors) <= MAX_SELECTIONS,
             'bounded_explicit_selectors_required')
    identities, uids = set(), {}
    for item in selectors:
        _require(type(item) is dict and set(item) == association._SELECTOR_KEYS,
                 'closed_selector_required')
        _require(item['api_version'] == association.RUN_API and item['kind'] == 'Job'
                 and item['project_id'] == project, 'only_selected_project_v2_job_supported')
        name, uid, container = (item[k] for k in ('resource_name', 'resource_uid', 'container_name'))
        _require(type(name) is str and len(name) <= 512 and re.fullmatch(
            re.escape(scope) + r'/locations/[a-z][a-z0-9-]{0,62}/jobs/' + association._RESOURCE_ID,
            name), 'exact_job_name_required')
        _require(type(uid) is str and association._UUID.fullmatch(uid), 'exact_job_uuid_required')
        _require(type(container) is str and association._LABEL.fullmatch(container),
                 'exact_container_name_required')
        parsed = association._immutable(item['immutable_reference'])
        _require(parsed['project_id'] == project and item['repository'] == parsed['repository']
                 and item['digest'] == parsed['digest'], 'selector_image_scope_mismatch')
        key = name, container
        _require(key not in identities and uids.get(name, uid) == uid,
                 'duplicate_or_ambiguous_job_selection')
        identities.add(key)
        uids[name] = uid
    return deepcopy(selectors)


def _session():
    import requests
    session = requests.Session()
    session.trust_env, session.auth = False, None
    return session


def _shape(body, fields):
    """Keep only the documented field-mask shape; reject partial/foreign wrappers."""
    _require(type(body) is dict, 'native_object_required')
    allowed = {
        PROJECT_FIELDS: {'name', 'projectId', 'state'},
        REPO_FIELDS: {'name', 'format', 'mode', 'updateTime'},
        IMAGE_FIELDS: {'name', 'uri', 'mediaType', 'updateTime'},
        JOB_FIELDS: {'name', 'uid', 'etag', 'generation', 'observedGeneration',
                     'reconciling', 'deleteTime', 'expireTime', 'template'},
    }[fields]
    _require(not set(body) - allowed, 'foreign_or_partial_metadata_shape')
    if fields == JOB_FIELDS:
        node = body.get('template')
        _require(type(node) is dict and set(node) == {'template'}, 'execution_template_required')
        node = node['template']
        _require(type(node) is dict and set(node) == {'containers'}, 'task_template_required')
        rows = node['containers']
        _require(type(rows) is list and 1 <= len(rows) <= association.MAX_CONTAINERS,
                 'bounded_containers_required')
        _require(all(type(row) is dict and set(row) == {'name', 'image'} for row in rows),
                 'native_named_container_image_required')
    else:
        _require(all(type(value) is str for value in body.values()), 'native_scalar_fields_required')


class Capture:
    """No transport cache: every revalidation is a new bounded HTTP GET."""
    def __init__(self, transport, session, end, scope):
        self.transport, self.session, self.end, self.scope = transport, session, end, scope
        self.calls, self.bytes, self.records, self.captures = 0, 0, [], []

    def check(self):
        self.transport.check_cancelled()
        _require(time.monotonic() < self.end, 'proposal_deadline')

    def get(self, url, fields):
        self.check()
        _require(self.calls < MAX_METADATA_CALLS, 'metadata_call_bound')
        receipt = {'method': 'GET', 'url': url, 'scope': self.scope,
                   'query': {'fields': fields}, 'operation': 'cloudrun_v2_job_declared_image_metadata_get',
                   'status': 'unavailable', 'http_attempts': 0}
        response, body = None, None
        try:
            with self.transport.lock:
                self.transport.check_cancelled()
                _require(self.transport.max_calls is None or self.transport.calls < self.transport.max_calls,
                         'native_call_budget')
                self.transport.calls += 1
            self.calls += 1
            authorization = self.transport.credentials.headers().get('Authorization')
            _require(type(authorization) is str and re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', authorization),
                     'native_access_token_unavailable')
            if hasattr(self.session, 'cookies'):
                self.session.cookies.clear()
            receipt['http_attempts'] = 1
            response = self.session.request('GET', url, params={'fields': fields},
                headers={'Authorization': authorization, 'Accept': 'application/json',
                         'Accept-Encoding': 'identity'}, stream=True, allow_redirects=False,
                timeout=min(10, self.transport.timeout, max(.001, self.end - time.monotonic())))
            receipt['http_status'] = response.status_code
            # requests includes params in response.url; compare the exact prepared URL.
            import requests
            expected = requests.Request('GET', url, params={'fields': fields}).prepare().url
            _require(response.status_code == 200 and response.url == expected and not response.history
                     and response.headers.get('Content-Encoding', 'identity') == 'identity'
                     and response.headers.get('WWW-Authenticate') is None, 'metadata_http_unavailable')
            length = response.headers.get('Content-Length')
            _require(length is None or length.isdecimal() and int(length) <= MAX_METADATA_BODY,
                     'metadata_length_bound')
            output = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                self.check()
                _require(type(chunk) is bytes, 'invalid_metadata_stream')
                self.bytes += len(chunk)
                _require(len(output) + len(chunk) <= MAX_METADATA_BODY and self.bytes <= MAX_METADATA_BYTES,
                         'metadata_byte_bound')
                output.extend(chunk)
            _require(length is None or len(output) == int(length), 'metadata_truncation')
            body = native._json(bytes(output))
            _shape(body, fields)
            receipt.update(status='collected', bytes=len(output),
                           body_sha256=hashlib.sha256(output).hexdigest())
            return body
        finally:
            if response is not None:
                if response.status_code in (401, 403):
                    receipt['status'] = 'denied'
                response.close()
            with self.transport.lock:
                if not hasattr(self.transport, 'evidence'):
                    self.transport.evidence = []
                receipt['id'] = 'request-' + str(len(self.transport.evidence) + 1)
                self.transport.evidence.append(receipt)
                self.records.append(deepcopy(receipt))
                if receipt['status'] == 'collected':
                    self.captures.append({'source_request': receipt['id'], 'body': deepcopy(body)})


def _requests(selection, scope):
    parsed = association._immutable(selection['immutable_reference'])
    image_id = parsed['image_path'] + '@' + parsed['digest']
    return [
        ('https://run.googleapis.com/v2/' + selection['resource_name'], JOB_FIELDS),
        ('https://cloudresourcemanager.googleapis.com/v3/' + scope, PROJECT_FIELDS),
        ('https://artifactregistry.googleapis.com/v1/' + parsed['repository'], REPO_FIELDS),
        ('https://artifactregistry.googleapis.com/v1/' + parsed['repository']
         + '/dockerImages/' + quote(image_id, safe=''), IMAGE_FIELDS),
    ]


def _bind(selection, scope, bodies):
    job, project, repository, image = bodies
    declaration = association.resolve_image_source(selection, job, project_id=scope.split('/')[1])
    _require(declaration['status'] == 'ASSOCIATED_DECLARATION', 'job_declaration_unresolved')
    _require(project.get('projectId') == selection['project_id'] and project.get('state') == 'ACTIVE'
             and re.fullmatch(r'projects/[0-9]+', project.get('name', '')), 'project_identity_mismatch')
    _require(repository.get('name') == selection['repository'] and repository.get('format') == 'DOCKER'
             and repository.get('mode') in (None, 'STANDARD_REPOSITORY'), 'repository_identity_or_mode_mismatch')
    parsed = association._immutable(selection['immutable_reference'])
    image_id = parsed['image_path'] + '@' + parsed['digest']
    expected_name = selection['repository'] + '/dockerImages/'
    _require(image.get('name') in (expected_name + image_id, expected_name + quote(image_id, safe=''))
             and image.get('uri') == selection['immutable_reference']
             and image.get('mediaType') in (native.OCI, native.DOCKER), 'native_dockerimage_identity_mismatch')
    row = {**image, 'repository': selection['repository'], 'digest': selection['digest']}
    native.bind_image(row, scope, [repository], [project])
    return declaration, row


def _inspect(row, scope, repository, project, reader):
    """Reuse native OCI GET, descriptors, rootfs/TAR validation and both detectors.

    Unlike the existing complete-only projection, preserve redacted observations
    across incomplete config/layers; later bounded layers may still prove leaks.
    """
    result = {'complete': False, 'leaks': [], 'config_engines': [], 'layers_scanned': [],
              'layer_coverage': [],
              'verification': 'not_attempted', 'reason': 'image_incomplete'}
    leaks = []

    def retain(rows, layer):
        merged = merge_leaks(leaks + [dict(leak, locations=[dict(loc, layer=layer) for loc in leak['locations']])
                                     for leak in rows])
        bounded, locations = [], 0
        for leak in merged[:native.MAX_LEAKS]:
            kept = leak['locations'][:native.MAX_LOCATIONS - locations]
            if not kept:
                break
            bounded.append(dict(leak, locations=kept))
            locations += len(kept)
        leaks[:] = bounded
        result['leaks'] = deepcopy(bounded)
        _require(bounded == merged, 'indicator_bound')

    try:
        uri, _, digest = native.bind_image(row, scope, [repository], [project])
        manifest = native._json(reader.get(uri, 'manifests', digest, native.MAX_MANIFEST))
        _require(type(manifest) is dict and not set(manifest) -
                 {'schemaVersion', 'mediaType', 'config', 'layers', 'annotations'}
                 and type(manifest.get('schemaVersion')) is int and manifest['schemaVersion'] == 2
                 and manifest.get('mediaType') in (native.OCI, native.DOCKER), 'single_platform_manifest_required')
        config = native._descriptor(manifest['config'], native.CONFIG_TYPES, native.MAX_CONFIG)
        layers = manifest['layers']
        _require(type(layers) is list and 1 <= len(layers) <= native.MAX_LAYERS, 'bounded_layers_required')
        layers = [native._descriptor(layer, native.TAR_TYPES, native.MAX_LAYER) for layer in layers]
        result['descriptors'] = deepcopy([config] + layers)
        _require(sum(v['size'] for v in [config] + layers) <= native.MAX_IMAGE, 'image_byte_bound')
        raw = reader.get(uri, 'blobs', config['digest'], native.MAX_CONFIG, config['size'])
        decoded = native._json(raw)
        diffs = decoded.get('rootfs', {}).get('diff_ids')
        _require(decoded.get('os') == 'linux' and decoded.get('architecture') in ('amd64', 'arm64')
                 and decoded.get('rootfs', {}).get('type') == 'layers' and type(diffs) is list
                 and len(diffs) == len(layers) and all(type(d) is str and native.DIGEST.fullmatch(d) for d in diffs),
                 'native_platform_rootfs_required')
        native.Deadline(reader).check_deadline()
        outcome = scan_content(raw, 'image-config.json', timeout=10)
        result['config_engines'] = outcome['engines']
        retain(outcome['leaks'], config['digest'])
        complete = outcome['complete']
        expanded, members, files = len(raw), 0, 0
        for layer, diff in zip(layers, diffs):
            layer_coverage = {'digest': layer['digest'], 'status': 'unavailable',
                              'reason': 'layer_read_or_scan_incomplete'}
            result['layer_coverage'].append(layer_coverage)
            try:
                reader.check()
                payload = reader.get(uri, 'blobs', layer['digest'], native.MAX_LAYER, layer['size'])
                safe_tar, regular = native._tar(payload, layer['mediaType'], diff)
                offset, count = 0, 0
                while offset + 512 <= len(safe_tar) and any(safe_tar[offset:offset + 512]):
                    member = tarfile.TarInfo.frombuf(safe_tar[offset:offset + 512], 'utf-8', 'strict')
                    count += 1
                    offset += 512 + ((member.size + 511) // 512) * 512
                _require(expanded + len(safe_tar) <= native.MAX_EXPANDED
                         and members + count <= native.MAX_MEMBERS
                         and files + regular <= native.MAX_MEMBERS, 'image_expansion_bound')
                budget = expanded, members
                # Charge validated expansion before a detector can fail. Later
                # layers cannot evade cumulative bounds through incomplete scans.
                expanded, members = expanded + len(safe_tar), members + count
                files += regular
                refs, _, _ = native.scan_tar(safe_tar, 'application/vnd.oci.image.layer.v1.tar',
                    native.Deadline(reader), budget)
                for ref in refs:
                    retain(ref.get('Leaks', []), layer['digest'])
                result['layers_scanned'].append(layer['digest'])
                layer_coverage.update(status='complete', reason=None)
            except PartialArchive as exc:
                complete = False
                layer_coverage['reason'] = 'native_archive_scan_incomplete'
                for ref in exc.refs:
                    retain(ref.get('Leaks', []), layer['digest'])
            except Exception:
                complete = False
        reader.check()
        result.update(complete=complete, reason=None if complete else 'image_incomplete')
    except Exception:
        pass
    result['byte_status'] = 'FAIL' if result['leaks'] else 'PASS' if result['complete'] else 'UNKNOWN'
    return result


def collect_declared_images(transport, *, scope, selectors=None, enabled=False,
                            metadata_session=None, image_session=None):
    """Standalone proposal entrypoint; no registry, hook, engine or UI integration.

    Supplying enabled=True is explicit consent for this bounded reader only.
    Sessions are owned and closed on every enabled exit, including bad selectors.
    FAIL means a detector found a secret in declared image bytes; never runtime.
    """
    result = {'schema': SCHEMA, 'status': 'UNKNOWN', 'complete': False, 'reason': 'disabled',
              'scope': scope, 'association_kind': 'desired_digest_declaration',
              'runtime_association_status': 'UNKNOWN', 'observed_runtime_digest': None,
              'deployed_bytes_proven': False, 'rows': [], 'source_requests': [], 'metadata_captures': []}
    if enabled is not True:
        return result
    reader = capture = None
    try:
        selections = normalize_selection(selectors, scope)
        metadata_session = metadata_session if metadata_session is not None else _session()
        image_session = image_session if image_session is not None else _session()
        end = time.monotonic() + MAX_SECONDS
        capture = Capture(transport, metadata_session, end, scope)
        reader = native.Reader(transport, session=image_session)
        reader.end = min(reader.end, end)
        for selection in selections:
            row = {'selection': selection, 'status': 'UNKNOWN', 'complete': False,
                   'association_revalidated': False, 'content': {'complete': False, 'leaks': []},
                   'reason': 'declaration_or_metadata_unavailable', 'source_requests': []}
            result['rows'].append(row)
            metadata_start, image_start = len(capture.records), len(reader.request_ids)
            try:
                requests = _requests(selection, scope)
                before = [capture.get(*request) for request in requests]
                declaration, image = _bind(selection, scope, before)
                row['declaration'] = declaration
                row['content'] = _inspect(image, scope, before[2], before[1], reader)
                row['reason'] = 'metadata_changed_or_revalidation_unavailable'
                after = [capture.get(*request) for request in requests]
                _bind(selection, scope, after)
                _require(before == after, 'metadata_changed')
                row['association_revalidated'] = True
                row['complete'] = row['content']['complete']
                row['status'] = ('FAIL' if row['content']['leaks'] else
                                 'PASS' if row['complete'] else 'UNKNOWN')
                row['reason'] = row['content']['reason']
            except Exception:
                pass
            finally:
                row['source_requests'] = ([r['id'] for r in capture.records[metadata_start:]]
                                          + reader.request_ids[image_start:])
        result['complete'] = all(row['complete'] for row in result['rows'])
        result['status'] = ('FAIL' if any(row['status'] == 'FAIL' for row in result['rows']) else
                            'PASS' if result['complete'] else 'UNKNOWN')
        result['reason'] = None if result['complete'] else 'selected_declaration_scope_incomplete'
    except Exception:
        result['reason'] = 'invalid_selection_or_reader_unavailable'
    finally:
        if capture is not None:
            result['source_requests'] = deepcopy(capture.records)
            result['metadata_captures'] = deepcopy(capture.captures)
        if reader is not None:
            result['source_requests'].extend(deepcopy(r) for r in getattr(transport, 'evidence', [])
                                             if r.get('id') in reader.request_ids)
        for session in (metadata_session, image_session):
            if session is not None:
                try:
                    session.close()
                except Exception:
                    result['complete'] = False
                    result['reason'] = 'session_cleanup_incomplete'
                    if result['status'] != 'FAIL':
                        result['status'] = 'UNKNOWN'
    return result
