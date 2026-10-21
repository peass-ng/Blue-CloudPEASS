"""Selected Developer Connect file admission and normal GCP snapshot adapter."""
from copy import deepcopy
from . import gcp_developerconnect_file_native_20261021 as source

CHECK_ID, KIND, OPTION, MARKER = source.CHECK_ID, source.KIND, source.OPTION, source.MARKER


def validate_request(connector, request):
    options = connector.get('options') or {}
    named = CHECK_ID in (request.get('checks') or [])
    if OPTION in options or named:
        if connector.get('provider') != 'gcp' or len(connector.get('scopes', [])) != 1 or any(options.get(x) for x in ('all_projects', 'discover_projects', 'all_hierarchy')):
            raise ValueError('one explicit GCP project required')
        targets = source.selections(options[OPTION], connector['scopes'][0]) if OPTION in options else []
        if named and options.get('content_secret_scans') is True and not targets:
            raise ValueError('named Developer Connect check requires exact targets')


def collect(collector):
    if KIND not in collector.needed or collector.options.get('content_secret_scans') is not True or KIND not in collector.options.get('_content_secret_scan_kinds', []):
        return
    scope, = collector.scopes
    values = collector.developerconnect_selected_redactions = set()
    collector.developerconnect_redaction_overflow = False
    def remember_matches(matches):
        if collector.developerconnect_redaction_overflow:
            return
        if (not isinstance(matches, (set, frozenset)) or
                any(not isinstance(value, str) or not value or len(value.encode('utf-8')) > 4096 for value in matches)):
            collector.developerconnect_redaction_overflow = True
            values.clear()
            return
        combined = values | matches
        if len(combined) > 256 or sum(len(value.encode('utf-8')) for value in combined) > 65536:
            collector.developerconnect_redaction_overflow = True
            values.clear()
            return
        values.update(matches)
    result = source.collect_native(collector.transport, scope=scope, selectors=collector.options[OPTION],
                                   enabled=True, match_callback=remember_matches)
    items = []
    for row in result['rows']:
        if collector.max_items is not None and collector.total_items >= collector.max_items: break
        collector.total_items += 1
        ids = row['source_requests']
        identity = row['resource_id']
        items.append({'name': identity, '_resource_id': identity, 'native_id': identity,
            MARKER: {'schema': source.SCHEMA, 'scope': scope, 'row': deepcopy(row), 'source_requests': deepcopy(ids)},
            '_provenance': {'scope': scope, 'source_requests': deepcopy(ids), 'collected_at': collector.read_time}})
    collector.collections[(KIND, scope)] = {'type': KIND, 'scope': scope, 'service': 'developerconnect',
        'status': 'collected' if items and len(items) == len(result['rows']) else 'partial' if items else 'unknown',
        'coverage_status': 'collected' if result['complete'] and len(items) == len(result['rows']) else 'partial',
        'items': items, 'source_requests': [r['id'] for r in result['source_requests']]}


def collect_connector(connector, requirements=None):
    from .gcp import GCPCollector
    from peaso.snapshot import seal
    class DeveloperConnectFileCollector(GCPCollector):
        def dependent_jobs(self):
            super().dependent_jobs()
            collect(self)
        def finish(self):
            values = getattr(self, 'developerconnect_selected_redactions', set())
            try:
                snapshot = super().finish()
                if KIND in self.needed and self.options.get('content_secret_scans') is True and KIND in self.options.get('_content_secret_scan_kinds', []):
                    snapshot['metadata'][OPTION] = [source.public_target(v) for v in source.selections(self.options[OPTION], self.scopes[0])]
                # No complete scrub set means no retained snapshot can safely
                # contain other metadata or options that repeat a matched value.
                if getattr(self, 'developerconnect_redaction_overflow', False):
                    raise ValueError('developerconnect_redaction_bound')
                if values:
                    from peaso.secret_scanning import redact_matches
                    snapshot = redact_matches(snapshot, values)
                    self.collections = redact_matches(self.collections, values)
                    self.options = redact_matches(self.options, values)
                    if self.transport is not None:
                        self.transport.cache = redact_matches(self.transport.cache, values)
                        self.transport.evidence = redact_matches(self.transport.evidence, values)
                        self.transport.options = redact_matches(self.transport.options, values)
                return seal(snapshot)
            finally:
                values.clear()
        def collect(self):
            try:
                return super().collect()
            finally:
                getattr(self, 'developerconnect_selected_redactions', set()).clear()
    return DeveloperConnectFileCollector(connector, requirements).collect()
