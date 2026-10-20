"""Engine admission and native collection for selected Job declared image bytes.

The immutable native proposal owns all metadata and OCI transport operations.
This adapter persists its real observations in the ordinary snapshot boundary.
"""
from copy import deepcopy
import hashlib
import json

from . import gcp_cloudrun_v2_job_declared_images_20261020 as source
from .gcp_cloudrun_job_image_native_20261020 import collect_native

CHECK_ID = 'gcp.review.cloudrun_job.declared_image_secret_indicators'
KIND = 'cloudrun_job_declared_image'
OPTION = 'selected_cloudrun_job_declared_images'
MARKER = 'JobDeclaredImageInspection'
SCHEMA = 'gcp-cloudrun-job-declared-image-runtime-20261020-v1'
GRANT = '_cloudrun_job_image_engine_grant'
_SEAL = object()


def validate_options(options, scopes):
    """Closed bounded exact selectors, including when content reads are disabled."""
    if 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool:
        raise ValueError('content_secret_scans must be a boolean')
    if OPTION not in options:
        return []
    if (not isinstance(scopes, list) or len(scopes) != 1 or
            any(options.get(key) for key in ('all_projects', 'discover_projects', 'all_hierarchy'))):
        raise ValueError('Job image inspection requires one exact project without discovery')
    return source.normalize_selection(options[OPTION], scopes[0])


def validate_request(connector, request):
    options = connector.get('options', {})
    named = CHECK_ID in (request.get('checks') or [])
    if OPTION in options or named:
        if connector.get('provider') != 'gcp':
            raise ValueError('Selected Job declared images require GCP')
        targets = validate_options(options, connector.get('scopes', []))
        if named and options.get('content_secret_scans') is True and not targets:
            raise ValueError('Named Job image check requires exact declared-image selectors')


def _selection_hash(targets):
    return hashlib.sha256(json.dumps(targets, sort_keys=True).encode()).hexdigest()


class _Grant:
    __slots__ = ('seal', 'scopes', 'selection')

    def __init__(self, scopes, targets):
        self.seal, self.scopes, self.selection = _SEAL, tuple(scopes), _selection_hash(targets)


def issue_engine_grant(options, scopes, named=()):
    """Only the normal engine's actual named selection can issue this token."""
    options.pop(GRANT, None)
    validate_request({'provider': 'gcp', 'options': options, 'scopes': scopes}, {'checks': list(named)})
    if CHECK_ID in named and options.get('content_secret_scans') is True:
        options[GRANT] = _Grant(scopes, validate_options(options, scopes))


def authorize_collector(options, scopes):
    """Consume admission before any credential or HTTP object is constructed."""
    token = options.pop(GRANT, None)
    targets = validate_options(options, scopes)
    permitted = (type(token) is _Grant and token.seal is _SEAL
        and token.scopes == tuple(scopes) and token.selection == _selection_hash(targets)
        and options.get('content_secret_scans') is True
        and KIND in options.get('_content_secret_scan_kinds', []))
    incoming = options.get('_content_secret_scan_kinds', [])
    options['_content_secret_scan_kinds'] = [k for k in incoming if k != KIND or permitted]
    return permitted


def collect(collector):
    if KIND not in collector.needed or not collector.job_declared_image_permitted:
        return
    scope, = collector.scopes
    result = collect_native(collector.transport, scope=scope, selectors=collector.options[OPTION])
    items = []
    for row in result['rows']:
        selection = row['selection']
        identity = selection['resource_name'] + '#container=' + selection['container_name']
        # These are the producer's own request IDs and minimal native captures.
        ids = row['source_requests']
        proof = {'schema': SCHEMA, 'scope': scope, 'row': deepcopy(row),
            'capture_reason': result['reason'],
            'metadata_captures': [deepcopy(c) for c in result['metadata_captures']
                                  if c['source_request'] in ids],
            'association_kind': result['association_kind'],
            'runtime_association_status': result['runtime_association_status'],
            'observed_runtime_digest': result['observed_runtime_digest'],
            'deployed_bytes_proven': result['deployed_bytes_proven']}
        if collector.max_items is not None and collector.total_items >= collector.max_items:
            break
        collector.total_items += 1
        items.append({'name': identity, '_resource_id': identity, 'native_id': identity,
            MARKER: proof, '_provenance': {'scope': scope, 'source_requests': deepcopy(ids),
                                          'collected_at': collector.read_time}})
    collector.collections[(KIND, scope)] = {'type': KIND, 'scope': scope, 'service': 'cloudrun',
        'status': 'collected' if items and len(items) == len(result['rows']) else 'partial' if items else 'unknown',
        'coverage_status': 'collected' if result['complete'] and len(items) == len(result['rows']) else 'partial',
        'items': items, 'source_requests': [r['id'] for r in result['source_requests']]}


def selection_metadata(collector):
    if collector.job_declared_image_permitted:
        return {OPTION: deepcopy(collector.options[OPTION])}
    return {}


def collect_connector(connector, requirements=None):
    """Reuse native collection through ordinary subclass dispatch, without clones.

    Existing GCPCollector methods and their admitted source epochs stay intact.
    The Job collector consumes its engine grant before native authentication.
    """
    from .gcp import GCPCollector
    from peaso.snapshot import seal

    class JobImageCollector(GCPCollector):
        def __init__(self):
            super().__init__(connector, requirements)
            self.job_declared_image_permitted = authorize_collector(self.options, self.scopes)
            if not self.job_declared_image_permitted:
                self.needed.discard(KIND)

        def dependent_jobs(self):
            super().dependent_jobs()
            collect(self)

        def finish(self):
            snapshot = super().finish()
            snapshot['metadata'].update(selection_metadata(self))
            return seal(snapshot)

    return JobImageCollector().collect()
