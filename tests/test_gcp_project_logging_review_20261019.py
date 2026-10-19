"""Native producer-to-consumer review, reusing attributed offline transports.

Sink transport/planner: test_peaso_gcp_inherited_sink_native.observed.
Audit transport/entry projection: test_gcp_audit_native.collect/event.
No live cloud, attack simulation, or manufactured authentication classification.
"""
import pytest

from peaso.engine import evaluate_snapshot
from tests import test_peaso_gcp_inherited_sink_native as inherited
from tests.test_gcp_audit_native import collect, event

SINK = 'gcp.claude2.logging.sink_all_log_entries'


def sink_observed(monkeypatch, **kwargs):
    monkeypatch.setattr(inherited, 'CID', SINK)
    return inherited.observed(monkeypatch, **kwargs)


def test_native_local_sink_does_not_bypass_ancestor_interceptor(monkeypatch):
    interceptor = {**inherited.GOOD, 'destination': 'logging.googleapis.com/projects/central',
        'filter': 'severity>=ERROR', 'interceptChildren': True}
    _, finding, _ = sink_observed(monkeypatch,
        local=[{'name': 'all', 'destination': 'storage.googleapis.com/archive'}], org=[interceptor])
    assert finding['status'] == 'UNKNOWN'


@pytest.mark.parametrize('mode', ['denied', 'partial'])
def test_native_local_sink_does_not_bypass_unread_ancestor(monkeypatch, mode):
    kwargs = {mode: inherited.ORG}
    _, finding, _ = sink_observed(monkeypatch,
        local=[{'name': 'all', 'destination': 'storage.googleapis.com/archive'}], **kwargs)
    assert finding['status'] == 'UNKNOWN'


@pytest.mark.parametrize('owner,expected', [('higher', 'UNKNOWN'), ('lower', 'PASS'), ('disabled', 'PASS')])
def test_native_aggregated_sink_respects_interceptor_order(monkeypatch, owner, expected):
    interceptor = {**inherited.GOOD, 'destination': 'logging.googleapis.com/projects/central',
        'filter': 'severity>=ERROR', 'interceptChildren': True, 'disabled': owner == 'disabled'}
    options = {'folder': [inherited.GOOD], 'org': [interceptor]}
    if owner == 'lower':
        options = {'folder': [interceptor], 'org': [inherited.GOOD]}
    _, finding, _ = sink_observed(monkeypatch, **options)
    assert finding['status'] == expected


def test_native_inherited_sink_tampered_request_cannot_pass(monkeypatch):
    def mutate(project, snapshot):
        project['_coverage']['_inherited_sinks']['source_requests'] = ['foreign-request']
    _, finding, _ = sink_observed(monkeypatch, org=[inherited.GOOD], mutate=mutate)
    assert finding['status'] == 'UNKNOWN'


def test_audit_adapter_does_not_invent_authentication_from_permission_denied():
    native, transport = collect([{'entries': [event(code=7)]}])
    envelope = next(c for c in native['collections'] if c['type'] == 'audit_log')
    coverage = envelope['audit_coverage']
    assert 'complete' not in coverage and 'authentication_events' not in coverage
    assert 'authenticationEvent' not in envelope['items'][0]
    assert 'authentication' not in transport.calls[0][2]['filter'].lower()
    # Retain historical predicate regression evidence without admitting its
    # unsupported contract back into production selectors.
    from tests.archived_check_contract import evaluate_snapshot as evaluate_archived
    findings = evaluate_archived(native, checks=['gcp_logging_detect_t1110'])['findings']
    assert findings and all(row['status'] == 'UNKNOWN' for row in findings)
    assert any('complete' in str(row['evidence']) for row in findings)


@pytest.mark.parametrize('exclusions,expected', [(None, 'FAIL'), ([], 'PASS'),
    ([{'name': 'drop', 'filter': 'severity<WARNING'}], 'MANUAL')])
def test_native_complete_sink_route_preserves_claude2_exclusion_contract(monkeypatch, exclusions, expected):
    local = [] if exclusions is None else [{'name': 'all',
        'destination': 'storage.googleapis.com/archive', 'exclusions': exclusions}]
    _, finding, _ = sink_observed(monkeypatch, local=local)
    assert finding['status'] == expected


def test_native_backup_metric_has_no_synthetic_filter_truth_marker():
    from tests.test_peaso_collectors_gcp import snapshot, collection
    scope = 'projects/123'
    def response(request):
        url = request['url']
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + scope:
            return {'name': scope, 'projectId': 'fixture'}
        if url == 'https://compute.googleapis.com/compute/v1/' + scope:
            return {}
        if url.endswith('/metrics'):
            return {'metrics': [{'name': 'failed-backup', 'disabled': False,
                'filter': 'resource.type="cloudsql_database" AND severity=ERROR',
                'metricDescriptor': {'type': 'logging.googleapis.com/user/failed-backup'}}]}
        if url.endswith(':getAncestry'):
            return {'ancestor': [{'resourceId': {'type': 'project', 'id': '123'}}]}
        assert url.endswith('/alertPolicies'), url
        return {}
    native, _ = snapshot(['project', 'logging_metric', 'monitoring_alert_policy'], response, scopes=[scope], metrics_scopes=False)
    assert collection(native, 'project', scope)['status'] == 'collected', collection(native, 'project', scope)
    assert 'filterMatchesFailedCloudSqlBackupRun' not in collection(native, 'logging_metric', scope)['items'][0]
    findings = evaluate_snapshot(native, checks=['gcp_cloudsql_backup_failure_alert'])['findings']
    assert findings and all(row['status'] == 'UNKNOWN' for row in findings)
    assert any('supported native contract' in str(row['evidence']) for row in findings), findings
