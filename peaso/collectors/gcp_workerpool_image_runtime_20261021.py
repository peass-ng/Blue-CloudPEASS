"""Normal snapshot adapter for explicitly selected worker-pool revision images."""
from copy import deepcopy
from .gcp_workerpool_image_native_20261021 import collect_native, selections

CHECK_ID = 'gcp.review.cloudrun_worker_pool.selected_revision_image_secret_indicators'
KIND = 'cloudrun_worker_pool_selected_revision_image'
OPTION = 'selected_cloudrun_worker_pool_revision_images'
MARKER = 'WorkerPoolSelectedRevisionImageInspection'


def validate_request(connector, request):
    options = connector.get('options') or {}
    named = CHECK_ID in (request.get('checks') or [])
    if OPTION in options or named:
        if connector.get('provider') != 'gcp' or len(connector.get('scopes', [])) != 1 or any(options.get(x) for x in ('all_projects', 'discover_projects', 'all_hierarchy')):
            raise ValueError('one selected GCP project required')
        targets = selections(options[OPTION], connector['scopes'][0]) if OPTION in options else []
        if named and options.get('content_secret_scans') is True and not targets:
            raise ValueError('named check requires selected worker-pool image')


def collect(collector):
    if KIND not in collector.needed or collector.options.get('content_secret_scans') is not True or KIND not in collector.options.get('_content_secret_scan_kinds', []):
        return
    scope, = collector.scopes
    result = collect_native(collector.transport, scope=scope, selectors=collector.options[OPTION],
                            enabled=True, match_callback=collector.remember_selected_image_matches)
    items = []
    for row in result['rows']:
        if collector.max_items is not None and collector.total_items >= collector.max_items: break
        target = row['selection']
        identity = target['revision_name'] + '#container=' + str(target['container_index'])
        ids = row['source_requests']
        collector.total_items += 1
        items.append({'name': identity, '_resource_id': identity, 'native_id': identity,
            MARKER: {'scope': scope, 'row': deepcopy(row), 'source_requests': deepcopy(ids),
                     'association_kind': 'immutable_revision_container_declaration', 'runtime_image_proven': False},
            '_provenance': {'scope': scope, 'source_requests': deepcopy(ids), 'collected_at': collector.read_time}})
    collector.collections[(KIND, scope)] = {'type': KIND, 'scope': scope, 'service': 'cloudrun',
        'status': 'collected' if items and len(items) == len(result['rows']) else 'partial' if items else 'unknown',
        'coverage_status': 'collected' if result['complete'] and len(items) == len(result['rows']) else 'partial',
        'items': items, 'source_requests': [r['id'] for r in result['source_requests']]}
    collector.workerpool_image_requests = result['source_requests']
    collector.workerpool_image_metadata = {OPTION: deepcopy(collector.options[OPTION])}


def collect_connector(connector, requirements=None):
    from .gcp import GCPCollector
    from peaso.snapshot import seal
    class SelectedWorkerPoolCollector(GCPCollector):
        def dependent_jobs(self):
            super().dependent_jobs()
            collect(self)
        def finish(self):
            return seal(super().finish())
    return SelectedWorkerPoolCollector(connector, requirements).collect()
