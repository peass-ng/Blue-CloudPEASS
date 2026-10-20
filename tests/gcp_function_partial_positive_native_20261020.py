"""Local HTTP boundary proof using the installed GCP transport and detectors.

No production source, clock, or installed transport hook is changed. Completed
detector surfaces delegate to real adapters; deliberately unavailable surfaces
fail at discovery (or first-detector availability in the asymmetric proof).
"""
from copy import deepcopy
from importlib.metadata import version
import json
from types import SimpleNamespace

from peaso import secret_scanning as scanning
from peaso.collectors import gcp

SCOPE = 'projects/review'
NAME = SCOPE + '/locations/us-central1/functions/worker'
URL = 'https://cloudfunctions.googleapis.com/v2/' + SCOPE + '/locations/-/functions'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'


def raw(runtime=None, build=None):
    return {'name': NAME, 'state': 'ACTIVE',
            'serviceConfig': {'environmentVariables': runtime or {}},
            'buildConfig': {'environmentVariables': build or {}}}


def index_for(row, envelope=None):
    return {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': {'function': [
        envelope if envelope is not None else {'scope': SCOPE, 'status': 'collected', 'items': [row]}]}}


def collect_native(monkeypatch, row, *, unavailable_second=True, enabled=True,
                   response_changes=None, http_status=200, asymmetric=False,
                   paired_projection=False):
    """Fake only successful native HTTP, plus optional missing executable.

    Kingfisher is the real installed SDK with its real rules; TruffleHog either
    uses the installed binary or its real adapter sees no discoverable binary.
    The returned receipt has no raw payload or exception content.

    Asymmetric mode completes only real Kingfisher/runtime and real
    TruffleHog/build. Optional proposed projection runs independently against
    the same fake HTTP response and is never installed in the transport hook.
    """
    assert version('kingfisher-secret-scanner') == scanning.KINGFISHER_VERSION
    scanning._RESULTS.clear()
    scanning._trufflehog.cache_clear()
    calls, detector_runs, payload_calls, proposed_rows = [], [], [], []
    native = {'functions': [deepcopy(row)], **(response_changes or {})}
    before = deepcopy(native)
    real_first, real_second = scanning._scan_kingfisher, scanning._scan_trufflehog

    def first(payload, path, timeout):
        detector_runs.append(('kingfisher', path))
        payload_calls.append(payload)
        if asymmetric and path == 'buildConfig.environmentVariables':
            raise FileNotFoundError('deliberately unavailable first detector on build surface')
        return real_first(payload, path, timeout)

    def second(payload, path, timeout):
        detector_runs.append(('trufflehog', path))
        payload_calls.append(payload)
        if asymmetric:
            scanning._trufflehog.cache_clear()
            if path == 'serviceConfig.environmentVariables':
                with monkeypatch.context() as patch:
                    real_which = scanning.shutil.which
                    patch.setattr(scanning.shutil, 'which',
                        lambda name: None if name == 'trufflehog' else real_which(name))
                    try:
                        return real_second(payload, path, timeout)
                    finally:
                        scanning._trufflehog.cache_clear()
        return real_second(payload, path, timeout)

    class Response:
        def __init__(self, data, status):
            self.data, self.status_code = data, status

        def json(self):
            return deepcopy(self.data)

    def request(method, url, **kwargs):
        calls.append((method, url))
        assert method == 'GET'
        if url == URL:
            if paired_projection:
                # Proposed producer observes the exact same fake HTTP response
                # independently. The installed transport still runs its original
                # v1 projection. This is not a proposed-hook integration test.
                from peaso.collectors.gcp_function_secret_pairs_candidate_20261020 import project_response
                projected = project_response(deepcopy(native), method=method, url=url,
                    scope=SCOPE, params=kwargs.get('params'), enabled=enabled)
                proposed_rows.extend(projected['functions'])
            return Response(native, http_status)
        assert url == 'https://cloudfunctions.googleapis.com/v2/' + NAME + ':getIamPolicy'
        return Response({'bindings': []}, 200)

    with monkeypatch.context() as patch:
        patch.setattr(scanning, '_scan_kingfisher', first)
        patch.setattr(scanning, '_scan_trufflehog', second)
        if unavailable_second and not asymmetric:
            real_which = scanning.shutil.which
            patch.setattr(scanning.shutil, 'which',
                          lambda name: None if name == 'trufflehog' else real_which(name))
        transport = gcp.Transport(SimpleNamespace(headers=lambda: {}, close=lambda: None),
            {'content_secret_scans': enabled, '_content_secret_scan_kinds': ['function'], 'retries': 0})
        patch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
        collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': {
            'inventories': ['function'], 'include_inherited': False,
            'metrics_scopes': False, 'concurrency': 1}}, requirements=['function'], transport=transport)
        snapshot = collector.collect()
        if http_status == 200:
            # The repeated read proves the cache retains the safe projection.
            transport.request('GET', URL, params={'pageSize': collector.page_size}, scope=SCOPE)
        safe = json.dumps([snapshot, [entry.get('data') for entry in transport.cache.values()],
                           transport.evidence], sort_keys=True) + repr(scanning._RESULTS)
    scanning._trufflehog.cache_clear()
    scanning._RESULTS.clear()
    assert native == before
    assert TOKEN not in safe
    envelope, = [entry for entry in snapshot['collections'] if entry['type'] == 'function']
    receipt = {'http_calls': [list(call) for call in calls],
               'detector_runs': [list(call) for call in detector_runs],
               'ordinary_inventory_status': envelope['status'],
               'ordinary_items': len(envelope['items']),
               'secret_absent_from_retained_output': TOKEN not in safe,
               'raw_source_unchanged': native == before}
    if paired_projection:
        assert TOKEN not in json.dumps(proposed_rows)
        receipt['proposed_rows'] = proposed_rows
        receipt['proposed_hook_installed'] = False
    return envelope, receipt, payload_calls
