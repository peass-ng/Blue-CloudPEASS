"""Normal GCP snapshot collection for selected App Engine Flex image content."""
from copy import deepcopy
from contextlib import ExitStack

from peaso import gcp_appengine_flex_image_selection_20261021 as selection
from . import gcp_appengine_flex_image_native_20261021 as native

MARKER = 'SelectedAppEngineFlexVersionImage'
KINDS = frozenset((selection.SECRET_KIND, selection.VULN_KIND))


def _trusted_runtime_options(options):
    if any(key in options for key in ('trivy_db_cache', 'trivy_cli')):
        raise ValueError('trivy_runtime_configuration_is_not_a_request_option')


def validate_request(connector, request):
    options = connector.get('options') or {}
    _trusted_runtime_options(options)
    named = request.get('checks') or []
    if selection.OPTION in options or selection.SECRET_CHECK in named or selection.VULN_CHECK in named:
        if connector.get('provider') != 'gcp':
            raise ValueError('GCP-only Flex image selection')
        selection.selected(options, connector.get('scopes', []), named)


def collect(collector):
    options = collector.options
    _trusted_runtime_options(options)
    named = options.get('_appengine_flex_image_named_checks', [])
    targets = selection.selected(options, collector.requested_scopes, named)
    secret_on = (selection.SECRET_KIND in collector.needed and options.get(selection.ENABLE_SECRET) is True
                 and selection.SECRET_CHECK in named)
    vuln_on = (selection.VULN_KIND in collector.needed and options.get(selection.ENABLE_VULN) is True
               and selection.VULN_CHECK in named)
    if not (secret_on or vuln_on):
        return
    if collector.max_items is not None and collector.total_items + len(targets) * (int(secret_on)+int(vuln_on)) > collector.max_items:
        raise ValueError('selected_flex_image_item_limit')
    scope, = collector.requested_scopes

    def version_get(target):
        url = 'https://appengine.googleapis.com/v1/' + target['version_name']
        return collector.read(url, scope, params={'view': 'FULL', 'fields': native.VERSION_FIELDS},
                              operation='appengine_flex_selected_version_get')

    def trivy_collect(reference, exact_scope):
        if db_cache is None:
            return {'status': 'UNKNOWN', 'complete': False, 'record': None,
                'source_requests': [], 'source_ledger': []}
        from . import gcp_registry_trivy_20261021 as trivy_source
        from peaso.checks import gcp_registry_trivy_review_20261021 as trivy_review
        scan = trivy_source.collect_native(collector.transport, scope=exact_scope,
            selectors=[reference], enabled=True, db_cache=db_cache)
        row, = scan['rows']
        record = trivy_review.project(reference, exact_scope, row['scan']) if type(row.get('scan')) is dict else None
        status, _ = trivy_review.evaluate(record, {'scope': exact_scope, 'selections': [reference],
            'source_requests': scan['source_requests']}) if record is not None else ('UNKNOWN', {})
        return {'status': status, 'complete': row['complete'] is True and status != 'UNKNOWN',
            'record': record, 'source_requests': row['source_requests'],
            'source_ledger': scan['source_requests']}

    from . import selected_image_trivy_database_20261021 as database
    with ExitStack() as lease_stack:
        db_cache = database.acquire(lease_stack, enabled=vuln_on,
                                    cancel=collector.transport.check_cancelled)
        result = native.collect_native(collector.transport, scope=scope, selectors=targets,
            enabled=True, version_get=version_get, secret_enabled=secret_on,
            vuln_enabled=vuln_on, trivy_collect=trivy_collect if vuln_on else None,
            match_callback=collector.remember_selected_image_matches if secret_on else None)
    collector.appengine_flex_image_metadata = {selection.OPTION: deepcopy(targets),
        selection.SECRET_KIND + '_authorized': secret_on, selection.VULN_KIND + '_authorized': vuln_on}
    for kind, active in ((selection.SECRET_KIND, secret_on), (selection.VULN_KIND, vuln_on)):
        if not active:
            continue
        items = []
        for row in result['rows']:
            target = row['selection']; rid = native.identity(target)
            items.append({'name': rid, 'native_id': rid, '_resource_id': rid,
                MARKER: {'scope': scope, 'row': deepcopy(row), 'runtime_image_proven': False},
                '_provenance': {'scope': scope, 'source_requests': row['source_requests'][:],
                                'collected_at': collector.read_time}})
        complete = all((row['content'].get('complete') is True if kind == selection.SECRET_KIND else
                        type(row.get('vulnerability')) is dict and row['vulnerability'].get('complete') is True)
                       and row['association_revalidated'] for row in result['rows'])
        collector.collections[(kind, scope)] = {'type': kind, 'scope': scope, 'service': 'appengine',
            'status': 'collected' if items else 'unknown',
            'coverage_status': 'collected' if items and complete else 'partial',
            'items': items, 'source_requests': sorted({r for row in result['rows'] for r in row['source_requests']})}
        collector.total_items += len(items)


def collect_connector(connector, requirements=None):
    from .gcp import GCPCollector
    from peaso.snapshot import seal
    _trusted_runtime_options(connector.get('options') or {})
    selection.selected(connector.get('options') or {}, connector.get('scopes', []),
                       connector.get('options', {}).get('_appengine_flex_image_named_checks', []))
    class SelectedFlexCollector(GCPCollector):
        def dependent_jobs(self):
            super().dependent_jobs()
            collect(self)
        def finish(self):
            snapshot = super().finish()
            snapshot['metadata'].update(getattr(self, 'appengine_flex_image_metadata', {}))
            return seal(snapshot)
    return SelectedFlexCollector(connector, requirements).collect()
