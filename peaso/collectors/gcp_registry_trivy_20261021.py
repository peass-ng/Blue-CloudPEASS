"""Explicit standalone immutable GCP registry images: native reads and offline Trivy.

No workload deployment claim. Registry project/repository/image metadata is read
before and after the bounded content download. The scanner receives no cloud
credentials. Disabled or invalid selections create no session and make no calls.
"""
from copy import deepcopy
import hashlib
import json
import re
import time
from urllib.parse import quote
from . import gcp_cloudrun_v2_job_declared_images_20261020 as metadata
from . import gcp_image_secret_indicators as native
from .gcp_registry_image_uri import parse
from .gcp_job_trivy_stream_20261021 import CaptureReader, Reader, _read_image, sha256
from peaso import container_image_archive_20261020 as archive
from peaso import trivy_container_runner_20261020 as trivy

SCHEMA = 'gcp-selected-registry-image-vulnerabilities-v1'
MAX_METADATA_CALLS = 24
MAX_METADATA_BODY = metadata.MAX_METADATA_BODY
MAX_METADATA_BYTES = MAX_METADATA_CALLS * MAX_METADATA_BODY
_shape = metadata._shape
_require = archive.require

class MetadataReader:
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
                   'query': {'fields': fields}, 'operation': 'artifactregistry_selected_image_metadata_get',
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


def normalize_selection(selectors, scope):
    archive.require(type(scope) is str and re.fullmatch(r'projects/[a-z][a-z0-9-]{4,61}[a-z0-9]', scope),
                    'exact_project_required')
    refs = native.normalize_selected(selectors, scope)
    return [uri.removeprefix('https://') for uri in refs]


def requests_for(reference, scope):
    _, repository, _, image_id = parse(reference)
    archive.require(repository.startswith(scope + '/'), 'foreign_project')
    return [
        ('https://cloudresourcemanager.googleapis.com/v3/' + scope, metadata.PROJECT_FIELDS),
        ('https://artifactregistry.googleapis.com/v1/' + repository, metadata.REPO_FIELDS),
        ('https://artifactregistry.googleapis.com/v1/' + repository + '/dockerImages/'
         + quote(image_id, safe=''), metadata.IMAGE_FIELDS),
    ]


def bind(reference, scope, bodies):
    archive.require(type(bodies) is list and len(bodies) == 3, 'native_metadata_required')
    project, repository, image = bodies
    uri, repo, digest, image_id = parse(reference)
    archive.require(project.get('projectId') == scope.split('/')[1]
                    and project.get('state') == 'ACTIVE'
                    and type(project.get('name')) is str
                    and re.fullmatch(r'projects/[0-9]+', project['name']), 'project_identity_mismatch')
    archive.require(repository.get('name') == repo and repository.get('format') == 'DOCKER'
                    and repository.get('mode') in (None, 'STANDARD_REPOSITORY'),
                    'repository_identity_mismatch')
    prefix = repo + '/dockerImages/'
    archive.require(image.get('name') in (prefix + image_id, prefix + quote(image_id, safe=''))
                    and image.get('uri') == reference
                    and image.get('mediaType') in (native.OCI, native.DOCKER),
                    'image_identity_mismatch')
    row = {**image, 'repository': repo, 'digest': digest}
    archive.require(native.bind_image(row, scope, [repository], [project]) == (uri, repo, digest),
                    'native_image_join_mismatch')
    return row


def _fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def scan_captured(reference, scope, before, after, captured, metadata_reader, *, runner,
                  db_cache=None, cli=trivy.DEFAULT_CLI, timeout=trivy.MAX_SECONDS,
                  scratch_parent=None):
    """No trust verdict cache: reconstruct bindings and rehash owned bytes per call."""
    archive.require(before == after, 'metadata_changed')
    row = bind(reference, scope, before)
    uri, _, digest = native.bind_image(row, scope, [before[1]], [before[0]])
    archive.require(captured._uri == uri, 'captured_image_mismatch')
    records, captures = metadata_reader.records, metadata_reader.captures
    expected = requests_for(reference, scope) * 2
    archive.require(len(records) == len(captures) == 6, 'all_metadata_receipts_required')
    seen = set()
    for record, capture, request, body in zip(records, captures, expected, before + after):
        archive.require(record.get('id') not in seen and type(record.get('id')) is str
                        and capture == {'source_request': record['id'], 'body': body}
                        and record.get('method') == 'GET' and record.get('url') == request[0]
                        and record.get('query') == {'fields': request[1]}
                        and record.get('operation') == 'artifactregistry_selected_image_metadata_get'
                        and record.get('scope') == scope and record.get('status') == 'collected'
                        and record.get('http_status') == 200 and record.get('http_attempts') == 1
                        and type(record.get('bytes')) is int and 0 < record['bytes'] <= MAX_METADATA_BODY
                        and type(record.get('body_sha256')) is str
                        and re.fullmatch(r'[0-9a-f]{64}', record['body_sha256']), 'metadata_receipt_mismatch')
        seen.add(record['id'])
    archive.require(all(records[i]['body_sha256'] == records[i + 3]['body_sha256']
                        and records[i]['bytes'] == records[i + 3]['bytes'] for i in range(3)),
                    'metadata_wire_changed')
    manifest = captured._blobs[('manifests', digest)]
    decoded = archive.decode(manifest)
    config_desc = archive.descriptor(decoded['config'], archive.CONFIGS, archive.MAX_CONFIG)
    layers = decoded['layers']
    archive.require(type(layers) is list and 1 <= len(layers) <= archive.MAX_LAYERS, 'all_layers_required')
    layers = [archive.descriptor(d, archive.LAYERS, archive.MAX_LAYER) for d in layers]
    config = captured._blobs[('blobs', config_desc['digest'])]
    payloads = [captured._blobs[('blobs', d['digest'])] for d in layers]
    expected_reads = [('manifests', digest), ('blobs', config_desc['digest'])] + [('blobs', d['digest']) for d in layers]
    archive.require([key for _, key in captured._reads] == expected_reads, 'image_reads_incomplete')
    ids = [rid for rid, _ in captured._reads]
    archive.require(len(set(ids)) == len(ids) and not set(ids) & seen, 'duplicate_native_receipts')
    identity = archive.identity({'provider': 'gcp', 'scope': scope,
        'immutable_reference': reference, 'manifest_digest': digest, 'config_digest': config_desc['digest']})
    archive.validate(identity, manifest, config, payloads, captured.check)
    image_ledger = {r.get('id'): r for r in captured.transport.evidence}
    image_records = {rid:deepcopy(image_ledger[rid]) for rid in ids}
    archive.require(all(r.get('scope') == scope and r.get('http_status') == 200
                        and r.get('http_attempts') == 1 for r in image_records.values()), 'image_native_receipts_required')
    expected_state = _fingerprint([before, after, records, captures, captured._reads])
    byte_state = tuple((key, sha256(value, captured.check).digest()) for key, value in captured._blobs.items())

    def verify():
        captured.check()
        archive.require(_fingerprint([before, after, records, captures, captured._reads]) == expected_state,
                        'metadata_or_sequence_changed')
        archive.require(bind(reference, scope, after) == row, 'native_binding_changed')
        archive.require(tuple((key, sha256(value, captured.check).digest())
                        for key, value in captured._blobs.items()) == byte_state, 'retained_bytes_changed')
        ledger = {r.get('id'): r for r in captured.transport.evidence}
        archive.require(all(ledger.get(r['id']) == r for r in records), 'metadata_ledger_changed')
        archive.require(all(ledger.get(rid) == image_records[rid] for rid in ids), 'image_receipt_changed')
        archive.require(all(ledger.get(rid, {}).get('status') == 'collected'
                        and ledger[rid].get('digest') == key[1]
                        and ledger[rid].get('category') == key[0]
                        and ledger[rid].get('operation') == 'artifactregistry.registry_content_get'
                        and ledger[rid].get('method') == 'GET' for rid, key in captured._reads),
                        'image_ledger_changed')
        return identity

    verify()
    outcome = runner(identity, manifest, config, payloads, native_verifier=verify,
        enabled=True, db_cache=db_cache, cli=cli, archive_format='docker', timeout=timeout,
        cancel=captured.check, scratch_parent=scratch_parent)
    archive.require(type(outcome) is dict and outcome.get('image') == identity, 'scanner_identity_mismatch')
    return {**outcome, 'schema': SCHEMA, 'association_kind': 'selected_registry_digest',
            'runtime_image_proven': False, 'source_requests': sorted(seen) + ids}


def collect_native(transport, *, scope, selectors=None, enabled=False, metadata_session=None,
                   image_session=None, db_cache=None, cli=trivy.DEFAULT_CLI,
                   timeout=trivy.MAX_SECONDS, scratch_parent=None, runner=trivy.scan_image):
    result = {'schema': SCHEMA, 'scope': scope, 'status': 'UNKNOWN', 'complete': False,
              'reason': 'disabled', 'rows': [], 'source_requests': []}
    if enabled is not True:
        return result
    try:
        selected = normalize_selection(selectors, scope)
    except Exception:
        result['reason'] = 'invalid_selection'
        return result
    reader = None
    try:
        metadata_session = metadata_session if metadata_session is not None else metadata._session()
        image_session = image_session if image_session is not None else metadata._session()
        deadline = time.monotonic() + 600
        meta = MetadataReader(transport, metadata_session, deadline, scope)
        reader = CaptureReader(Reader(transport, session=image_session))
        for reference in selected:
            reader.reset()
            meta.records, meta.captures = [], []
            row = {'immutable_reference': reference, 'status': 'UNKNOWN', 'complete': False,
                   'reason': 'native_image_unavailable', 'scan': None, 'source_requests': []}
            result['rows'].append(row)
            start = len(getattr(transport, 'evidence', []))
            try:
                requests = requests_for(reference, scope)
                before = [meta.get(*request) for request in requests]
                image = bind(reference, scope, before)
                _read_image(image, scope, [None, before[0], before[1], before[2]], reader)
                after = [meta.get(*request) for request in requests]
                scan = scan_captured(reference, scope, before, after, reader, meta, runner=runner,
                    db_cache=db_cache, cli=cli, timeout=timeout, scratch_parent=scratch_parent)
                archive.require(scan.get('status') in ('PASS', 'FAIL', 'UNKNOWN')
                                and type(scan.get('complete')) is bool, 'scanner_result_malformed')
                row.update(scan=scan, status=scan['status'],
                    complete=scan['complete'] is True and scan['status'] != 'UNKNOWN', reason=scan.get('reason'))
            except Exception:
                pass
            finally:
                row['source_requests'] = [r['id'] for r in transport.evidence[start:]]
                reader.reset()
        result['complete'] = bool(result['rows']) and all(r['complete'] for r in result['rows'])
        result['status'] = ('FAIL' if any(r['status'] == 'FAIL' for r in result['rows']) else
                            'PASS' if result['complete'] and all(r['status'] == 'PASS' for r in result['rows']) else 'UNKNOWN')
        result['reason'] = None if result['complete'] else 'selected_image_coverage_incomplete'
    except Exception:
        result['reason'] = 'native_reader_unavailable'
    finally:
        if reader is not None:
            reader.reset()
        for session in (metadata_session, image_session):
            if session is not None:
                try:
                    session.close()
                except Exception:
                    result['complete'] = False
                    if result['status'] != 'FAIL':
                        result['status'] = 'UNKNOWN'
                    result['reason'] = 'session_cleanup_incomplete'
        result['source_requests'] = deepcopy(getattr(transport, 'evidence', []))
    return result
