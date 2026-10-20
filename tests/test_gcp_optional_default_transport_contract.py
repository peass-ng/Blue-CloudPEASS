"""Disabled content features preserve the ordinary request-only transport seam."""
from types import SimpleNamespace
import threading
import pytest
from peaso.collectors.gcp_additional_literal_secret_indicators import prepare_scope
from peaso.collectors.gcp_function_source_secret_indicators import clear_pending


@pytest.mark.parametrize('options', [{}, {'content_secret_scans': False},
    {'content_secret_scans': True, '_content_secret_scan_kinds': []},
    {'content_secret_scans': True, '_content_secret_scan_kinds': ['function']}])
def test_disabled_additional_content_does_not_require_private_transport_state(options):
    # Ordinary metadata transports implement request/close; private content state
    # is acquired only for an explicitly selected content operation.
    transport = SimpleNamespace()
    collector = SimpleNamespace(options=options, needed={'project', 'scheduler_job'}, transport=transport)
    prepare_scope(collector, 'projects/review')
    assert vars(transport) == {}


def test_named_additional_content_authorizes_only_the_resolved_scope():
    transport = SimpleNamespace(lock=threading.Lock())
    collector = SimpleNamespace(options={'content_secret_scans': True,
        '_content_secret_scan_kinds': ['workflow_source']}, needed={'workflow_source'},
        scopes=['projects/review'], transport=transport)
    prepare_scope(collector, 'projects/other')
    assert not hasattr(transport, '_additional_scopes')
    prepare_scope(collector, 'projects/review')
    assert transport._additional_scopes == {('projects/review', 'workflow_source')}


@pytest.mark.parametrize('transport', [SimpleNamespace(), SimpleNamespace(_function_source_pending=None)])
def test_absent_source_plan_teardown_needs_no_private_transport_lock(transport):
    clear_pending(transport)


def test_existing_source_plan_is_discarded_at_teardown():
    plan = {'rows': {('projects/review', 'function'): {'target': 'inert-object-reference'}}}
    transport = SimpleNamespace(lock=threading.Lock(), _function_source_pending=plan)
    clear_pending(transport)
    assert plan['rows'] == {} and not hasattr(transport, '_function_source_pending')


@pytest.mark.parametrize('kind', sorted(__import__('peaso.collectors.gcp', fromlist=['CONTENT_ONLY_TYPES']).CONTENT_ONLY_TYPES))
def test_disabled_content_inventory_is_unknown_without_fetching(kind):
    from peaso.collectors.gcp import GCPCollector
    collector = GCPCollector({'provider': 'gcp', 'scopes': ['projects/review'],
        'options': {}}, [kind], transport=SimpleNamespace())
    def forbidden():
        pytest.fail('disabled content inventory attempted its fetcher')
    envelope = collector.envelope(kind, 'projects/review', 'content', forbidden)
    assert envelope['status'] == 'unknown'
    assert envelope['coverage_status'] == 'unavailable'
    assert envelope['items'] == [] and envelope['source_requests'] == []
    assert envelope['error']['code'] == 'content_secret_inspection_not_enabled'
