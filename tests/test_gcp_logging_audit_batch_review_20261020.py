"""Offline native API -> GCPCollector -> engine proofs for 30 logging checks.

Positive fragments are independent API-shaped declarations, never CASES fixtures.
Regression assertions deliberately remain failing until the coordinator fixes runtime.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import socket
from urllib.parse import urlsplit

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import FixtureTransport, connector
from peaso.snapshot import validate

SCOPE = 'projects/review-proj'
MTYPE = 'logging.googleapis.com/user/review'
CHANNEL = SCOPE + '/notificationChannels/1'
FILTERS = {
    'audit_configuration_changes': 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*',
    'bucket_iam_changes': 'resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"',
    'compute_configuration_changes': 'protoPayload.serviceName="compute.googleapis.com"',
    'custom_role_changes': 'resource.type="iam_role" AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole")',
    'custom_role_changes_with_undelete': 'resource.type="iam_role" AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole" OR protoPayload.methodName="google.iam.admin.v1.UndeleteRole")',
    'firewall_rule_changes': 'resource.type="gce_firewall_rule" AND (protoPayload.methodName:"compute.firewalls.patch" OR protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.delete")',
    'network_changes': 'resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")',
    'network_changes_beta_methods': 'resource.type=gce_network AND (protoPayload.methodName="beta.compute.networks.insert" OR protoPayload.methodName="beta.compute.networks.patch" OR protoPayload.methodName="v1.compute.networks.delete" OR protoPayload.methodName="v1.compute.networks.removePeering" OR protoPayload.methodName="v1.compute.networks.addPeering")',
    'project_ownership_changes': '(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")',
    'route_changes': 'resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")',
    'sql_instance_configuration_changes': 'protoPayload.methodName="cloudsql.instances.update"',
}
CLAUDE = [('gcp.claude.logging.metric_alert_' + slug, slug) for slug in FILTERS]
CLAUDE2 = [('gcp.claude2.logging.metric_alert_' + slug, slug) for slug in FILTERS
           if slug not in ('compute_configuration_changes', 'network_changes_beta_methods')]
PORTS = [('gcp.ports.logging_metric_alert_' + slug + '_scoped', event) for slug, event in [
    ('audit_configuration_changes', 'audit_configuration_changes'),
    ('custom_role_changes', 'custom_role_changes'),
    ('custom_role_changes_with_iam_admin_undelete_role', 'custom_role_changes_with_undelete'),
    ('firewall_rule_changes', 'firewall_rule_changes'),
    ('network_changes', 'network_changes_beta_methods'),
]]
METRICS = CLAUDE + CLAUDE2 + PORTS
SINKS = ['gcp.claude.logging.project_sink_all_entries', 'gcp.claude2.logging.sink_all_log_entries']
DEFAULT = 'gcp.htbp.logging.default_sink_not_disabled'
TRANSPARENCY = 'gcp.logging.access_transparency_entries'
AUDIT = 'gcp.ports.audit_logging_configured_for_all_service'


@pytest.fixture(autouse=True)
def forbid_network_and_credentials(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('Offline review: sockets, DNS and cloud credentials are prohibited')
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)
    monkeypatch.setattr(socket.socket, 'sendto', blocked)
    monkeypatch.setattr(gcp, 'GoogleTransport', blocked) if hasattr(gcp, 'GoogleTransport') else None


def native_collect(kinds, payloads, *, denied=(), partial=(), parents=(), ancestry_denied=False, scope=SCOPE):
    """Finite exact method+scheme+host+path routing; no fallthrough to a network."""
    roots = [scope, *parents]
    routes = {}
    for root in roots:
        routes['https://cloudresourcemanager.googleapis.com/v3/' + root] = (
            'GET', {'name': 'projects/123', 'projectId': 'review-proj', 'state': 'ACTIVE'} if root == scope else {'name': root})
        routes['https://cloudresourcemanager.googleapis.com/v3/' + root + ':getIamPolicy'] = (
            'POST', payloads.get(('iam_policy', root), {'version': 3, 'bindings': []}))
        routes['https://logging.googleapis.com/v2/' + root + '/sinks'] = (
            'GET', {'sinks': payloads.get(('log_sink', root), [])})
    routes.update({
        'https://compute.googleapis.com/compute/v1/' + scope: ('GET', {'name': 'review-proj', 'id': '123'}),
        'https://monitoring.googleapis.com/v1/locations/global/metricsScopes:listMetricsScopesByMonitoredProject':
            ('GET', {'metricsScopes': [{'name': 'locations/global/metricsScopes/123'}]}),
        'https://cloudresourcemanager.googleapis.com/v1/' + scope + ':getAncestry':
            ('POST', {'ancestor': [{'resourceId': {'type': 'project', 'id': '123'}}] + [
                {'resourceId': {'type': p.split('/')[0][:-1], 'id': p.split('/')[1]}} for p in parents]}),
        'https://logging.googleapis.com/v2/' + scope + '/metrics':
            ('GET', {'metrics': payloads.get('logging_metric', [])}),
        'https://monitoring.googleapis.com/v3/' + scope + '/alertPolicies':
            ('GET', {'alertPolicies': payloads.get('monitoring_alert_policy', [])}),
        'https://monitoring.googleapis.com/v3/' + scope + '/notificationChannels':
            ('GET', {'notificationChannels': payloads.get('monitoring_notification_channel', [])}),
        'https://logging.googleapis.com/v2/entries:list': ('POST', {'entries': payloads.get('access_transparency_entry', [])}),
    })
    route_kinds = {'/metrics': 'logging_metric', '/alertPolicies': 'monitoring_alert_policy',
                   '/notificationChannels': 'monitoring_notification_channel', '/sinks': 'log_sink',
                   ':getIamPolicy': 'iam_policy', '/entries:list': 'access_transparency_entry'}
    before = deepcopy(payloads)

    def resolve(request):
        url = request['url']
        parsed = urlsplit(url)
        assert parsed.scheme == 'https' and not parsed.query and not parsed.fragment
        assert url in routes, 'Unexpected host/path: ' + url
        method, response = routes[url]
        assert request['method'] == method, request
        kind = next((kind for suffix, kind in route_kinds.items() if parsed.path.endswith(suffix)), None)
        masks = {'logging_metric': ('name', 'filter', 'disabled', 'bucketName', 'metricDescriptor(type'),
                 'monitoring_alert_policy': ('name', 'enabled', 'validity', 'conditions', 'notificationChannels', 'combiner'),
                 'monitoring_notification_channel': ('name', 'enabled', 'verificationStatus')}
        if kind in masks:
            mask = request['params']['fields']
            assert all(field in mask for field in masks[kind]), mask
        if parsed.path.endswith(':getAncestry'):
            assert request['body'] == {}
            if ancestry_denied: raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        if parsed.path.endswith(':getIamPolicy'):
            assert request['body'] == {'options': {'requestedPolicyVersion': 3}}
        if parsed.path.endswith('/entries:list'):
            body = request['body']
            assert body['resourceNames'] == [scope]
            assert 'timestamp>=' in body['filter'] and 'timestamp<' in body['filter']
            assert 'cloudaudit.googleapis.com%2Faccess_transparency' in body['filter']
        if kind in denied or url in denied:
            raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        cursor = (request.get('params') or {}).get('pageToken') or (request.get('body') or {}).get('pageToken')
        if kind in partial and cursor:
            assert cursor == 'review-page-2'
            raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        output = deepcopy(response)
        if kind in partial: output['nextPageToken'] = 'review-page-2'
        return output

    class ScopedTransport(FixtureTransport):
        # Match production Transport evidence (gcp.py request), including scope.
        def request(self, method, url, **kwargs):
            try:
                return super().request(method, url, **kwargs)
            finally:
                self.evidence[-1]['scope'] = kwargs['scope']

    transport = ScopedTransport(resolve)
    collected = gcp.GCPCollector(connector(kinds, scopes=[scope], include_inherited=True,
        resource_iam=False, metrics_scopes=True), transport=transport).collect()
    assert validate(collected) == collected
    assert payloads == before
    assert transport.requests and all(r['url'] in routes for r in transport.requests)
    return collected, transport


def finding(collected, cid):
    before = deepcopy(collected)
    rows = evaluate_snapshot(collected, checks=[cid])['findings']
    assert collected == before
    assert len(rows) == 1 and rows[0]['check_id'] == cid, rows
    return rows[0]


def metric_capture(cid, slug, scenario='good'):
    # API-required threshold fields are included; the collector requests all conditions.
    event_filter = FILTERS[slug]
    metric = {'name': 'review', 'filter': event_filter,
              'metricDescriptor': {'type': MTYPE, 'metricKind': 'DELTA', 'valueType': 'INT64'}}
    resource_type = {'audit_configuration_changes': 'project', 'project_ownership_changes': 'project',
        'custom_role_changes': 'iam_role', 'custom_role_changes_with_undelete': 'iam_role',
        'firewall_rule_changes': 'gce_firewall_rule', 'network_changes': 'gce_network',
        'network_changes_beta_methods': 'gce_network', 'route_changes': 'gce_route',
        'bucket_iam_changes': 'gcs_bucket', 'sql_instance_configuration_changes': 'cloudsql_database',
        'compute_configuration_changes': 'gce_instance'}[slug]
    alert = {'name': SCOPE + '/alertPolicies/1', 'displayName': 'Review', 'enabled': True, 'combiner': 'OR',
             'notificationChannels': [CHANNEL], 'conditions': [{'displayName': 'Review', 'conditionThreshold': {
                 'filter': 'metric.type="' + MTYPE + '" AND resource.type="' + resource_type + '"',
                 'comparison': 'COMPARISON_GT', 'thresholdValue': 0, 'duration': '0s',
                 'aggregations': [{'alignmentPeriod': '60s', 'perSeriesAligner': 'ALIGN_DELTA'}]}}]}
    channel = {'name': CHANNEL, 'type': 'email', 'enabled': True, 'verificationStatus': 'VERIFIED'}
    metrics, alerts, channels = [metric], [alert], [channel]
    denied, partial = (), ()
    if scenario == 'empty': metrics = []
    elif scenario == 'disabled_metric': metric['disabled'] = True
    elif scenario == 'disabled_alert': alert['enabled'] = False
    elif scenario == 'missing_enabled': alert.pop('enabled')
    elif scenario == 'denied': denied = ('logging_metric',)
    elif scenario == 'partial': partial = ('logging_metric',)
    elif scenario == 'foreign_alert': alert['name'] = 'projects/other/alertPolicies/1'
    elif scenario == 'invalid_alert': alert['validity'] = {'code': 3, 'message': 'Invalid metric condition'}
    elif scenario == 'unverified_channel': channel['verificationStatus'] = 'UNVERIFIED'
    elif scenario == 'omitted_channel_enabled': channel.pop('enabled')
    elif scenario == 'foreign_selector':
        alert['conditions'][0]['conditionThreshold']['filter'] += ' AND resource.labels.project_id="other"'
    elif scenario == 'principal_narrowing':
        metric['filter'] = '(' + event_filter + ') AND protoPayload.authenticationInfo.principalEmail="admin@example.com"'
    elif scenario == 'negated_filter': metric['filter'] = 'NOT (' + event_filter + ')'
    elif scenario == 'bucket_metric': metric['bucketName'] = SCOPE + '/locations/global/buckets/_Default'
    elif scenario == 'disabled_channel': channel['enabled'] = False
    elif scenario == 'mql':
        alert['conditions'] = [{'displayName': 'Review', 'conditionMonitoringQueryLanguage': {
            'query': "fetch global | metric '" + MTYPE + "' | condition val() > 0"}}]
    payloads = {'logging_metric': metrics, 'monitoring_alert_policy': alerts,
                'monitoring_notification_channel': channels}
    collected, transport = native_collect(['project', 'logging_metric', 'monitoring_alert_policy',
        'monitoring_notification_channel', 'log_sink'], payloads, denied=denied, partial=partial)
    # Assert production of the normalized metric identity and selected native fields.
    metric_rows = next(c for c in collected['collections'] if c['type'] == 'logging_metric')['items']
    if metric_rows:
        assert metric_rows[0]['name'] == SCOPE + '/metrics/review'
        assert metric_rows[0]['metricId'] == 'review'
        assert metric_rows[0]['filter'] == metric['filter']
    return finding(collected, cid), transport


@pytest.mark.parametrize('cid,slug', METRICS, ids=[x[0] for x in METRICS])
@pytest.mark.parametrize('scenario,expected', [('good', 'PASS'), ('empty', 'FAIL'), ('disabled_metric', 'FAIL'),
    ('disabled_alert', 'FAIL'), ('denied', 'UNKNOWN'), ('partial', 'UNKNOWN'), ('foreign_alert', 'FAIL')])
def test_every_metric_native_declaration(cid, slug, scenario, expected):
    row, _ = metric_capture(cid, slug, scenario)
    assert row['status'] == expected, row


@pytest.mark.parametrize('cid,slug', CLAUDE, ids=[x[0] for x in CLAUDE])
@pytest.mark.parametrize('scenario,expected', [('missing_enabled', 'UNKNOWN'), ('invalid_alert', 'FAIL'),
    ('foreign_selector', 'FAIL'), ('principal_narrowing', 'UNKNOWN'), ('bucket_metric', 'UNKNOWN'), ('mql', 'UNKNOWN')])
def test_shared_matcher_conservative_scope_and_filter_guards(cid, slug, scenario, expected):
    row, _ = metric_capture(cid, slug, scenario)
    assert row['status'] == expected, row


@pytest.mark.parametrize('cid,slug', CLAUDE2, ids=[x[0] for x in CLAUDE2])
@pytest.mark.parametrize('scenario,expected', [('omitted_channel_enabled', 'UNKNOWN'), ('disabled_channel', 'FAIL'),
                                            ('bucket_metric', 'MANUAL'), ('mql', 'MANUAL')])
def test_semantic_metric_channel_and_uncertainty_guards(cid, slug, scenario, expected):
    row, _ = metric_capture(cid, slug, scenario)
    assert row['status'] == expected, row


@pytest.mark.parametrize('cid,slug', CLAUDE2, ids=[x[0] for x in CLAUDE2])
@pytest.mark.parametrize('scenario', ['principal_narrowing', 'invalid_alert', 'unverified_channel', 'foreign_selector'])
def test_regression_semantic_metric_must_not_certify_counterexample(cid, slug, scenario):
    row, _ = metric_capture(cid, slug, scenario)
    assert row['status'] != 'PASS', {'native_counterexample': scenario, **row}


@pytest.mark.parametrize('cid,slug', PORTS, ids=[x[0] for x in PORTS])
@pytest.mark.parametrize('scenario', ['negated_filter', 'foreign_selector', 'bucket_metric', 'invalid_alert'])
def test_regression_scoped_template_must_not_certify_counterexample(cid, slug, scenario):
    row, _ = metric_capture(cid, slug, scenario)
    assert row['status'] != 'PASS', {'native_counterexample': scenario, **row}


@pytest.mark.parametrize('cid', SINKS)
@pytest.mark.parametrize('scenario,expected', [('local', 'PASS'), ('empty', 'FAIL'), ('disabled', 'FAIL'),
    ('filtered', 'FAIL'), ('denied', 'UNKNOWN'), ('partial', 'UNKNOWN'), ('ancestry_denied', 'UNKNOWN'),
    ('aggregated', 'PASS'), ('ancestor_no_children', 'FAIL'), ('ancestor_denied', 'UNKNOWN'),
    ('intercepted_local', 'UNKNOWN'), ('higher_interceptor', 'UNKNOWN'), ('disabled_exclusion', 'PASS')])
def test_native_sink_ancestry_routing(cid, scenario, expected):
    sink = {'name': 'review', 'destination': 'storage.googleapis.com/log-archive'}
    parents, denied, partial = [], (), ()
    local = [sink]
    payloads = {}
    if scenario == 'empty': local = []
    elif scenario == 'disabled': sink['disabled'] = True
    elif scenario == 'filtered': sink['filter'] = 'severity>=ERROR'
    elif scenario == 'denied': denied = ('log_sink',)
    elif scenario == 'partial': partial = ('log_sink',)
    elif scenario == 'disabled_exclusion': sink['exclusions'] = [{'name': 'off', 'filter': 'severity<ERROR', 'disabled': True}]
    elif scenario in ('aggregated', 'ancestor_no_children', 'ancestor_denied', 'intercepted_local', 'higher_interceptor'):
        parents = ['folders/7', 'organizations/9']
        local = [sink] if scenario == 'intercepted_local' else []
        payloads[('log_sink', 'folders/7')] = [{**sink, 'includeChildren': scenario != 'ancestor_no_children'}]
        if scenario in ('intercepted_local', 'higher_interceptor'):
            payloads[('log_sink', 'organizations/9')] = [{'name': 'intercept', 'includeChildren': True,
                'interceptChildren': True, 'filter': 'severity>=ERROR', 'destination': 'logging.googleapis.com/projects/central'}]
        if scenario == 'ancestor_denied': denied = ('https://logging.googleapis.com/v2/folders/7/sinks',)
    payloads[('log_sink', SCOPE)] = local
    collected, _ = native_collect(['project', 'log_sink'], payloads, parents=parents, denied=denied,
                                  partial=partial, ancestry_denied=scenario == 'ancestry_denied')
    row = finding(collected, cid)
    assert row['status'] == expected, row


@pytest.mark.parametrize('name,disabled,expected', [('_Default', None, 'PASS'), ('_Default', True, 'FAIL'),
    ('_Default', False, 'PASS'), ('_Required', None, 'NOT_APPLICABLE'), ('custom', False, 'NOT_APPLICABLE'),
    ('_Default', 'false', 'UNKNOWN')])
def test_default_sink_native_omission_and_applicability(name, disabled, expected):
    sink = {'name': name, 'destination': 'logging.googleapis.com/' + SCOPE + '/locations/global/buckets/_Default'}
    if disabled is not None: sink['disabled'] = disabled
    collected, _ = native_collect(['log_sink'], {('log_sink', SCOPE): [sink]})
    assert finding(collected, DEFAULT)['status'] == expected


@pytest.mark.parametrize('project_scope', [SCOPE, 'projects/123'], ids=['project_id', 'project_number'])
@pytest.mark.parametrize('scenario,expected', [('recent', 'PASS'), ('empty', 'UNKNOWN'), ('old', 'UNKNOWN'),
    ('future', 'UNKNOWN'), ('foreign_log', 'UNKNOWN'), ('missing_identity', 'UNKNOWN'),
    ('malformed_time', 'UNKNOWN'), ('denied', 'UNKNOWN'), ('partial', 'UNKNOWN')])
def test_access_transparency_native_event_window_and_identity(scenario, expected, project_scope):
    stamp = datetime.now(timezone.utc) - timedelta(days=1)
    if scenario == 'old': stamp -= timedelta(days=40)
    elif scenario == 'future': stamp += timedelta(days=3)
    entry = {'insertId': 'event/one', 'timestamp': stamp.isoformat(),
             'logName': project_scope + '/logs/cloudaudit.googleapis.com%2Faccess_transparency'}
    if scenario == 'foreign_log': entry['logName'] = 'projects/other/logs/cloudaudit.googleapis.com%2Faccess_transparency'
    elif scenario == 'missing_identity': entry.pop('insertId')
    elif scenario == 'malformed_time': entry['timestamp'] = 'not-a-time'
    collected, _ = native_collect(['project', 'access_transparency_entry'],
        {'access_transparency_entry': [] if scenario == 'empty' else [entry]},
        denied=('access_transparency_entry',) if scenario == 'denied' else (),
        partial=('access_transparency_entry',) if scenario == 'partial' else (), scope=project_scope)
    assert finding(collected, TRANSPARENCY)['status'] == expected


@pytest.mark.parametrize('scenario,expected', [('local', 'PASS'), ('inherited', 'PASS'), ('empty', 'FAIL'),
    ('missing_category', 'FAIL'), ('exemption', 'FAIL'), ('service_only', 'FAIL'),
    ('denied', 'DENIED'), ('ancestor_denied', 'UNKNOWN'), ('ancestry_denied', 'UNKNOWN')])
def test_all_service_audit_native_policy_union(scenario, expected):
    logs = [{'logType': k} for k in ('ADMIN_READ', 'DATA_READ', 'DATA_WRITE')]
    configs = [{'service': 'allServices', 'auditLogConfigs': logs}]
    parents, denied = [], ()
    payloads = {('iam_policy', SCOPE): {'version': 3, 'auditConfigs': configs}}
    if scenario == 'empty': payloads[('iam_policy', SCOPE)] = {'version': 3}
    elif scenario == 'missing_category': logs.pop()
    elif scenario == 'exemption': logs[0]['exemptedMembers'] = ['user:exempt@example.com']
    elif scenario == 'service_only': configs[0]['service'] = 'storage.googleapis.com'
    elif scenario in ('inherited', 'ancestor_denied'):
        parents = ['organizations/9']
        payloads[('iam_policy', SCOPE)] = {'version': 3}
        payloads[('iam_policy', 'organizations/9')] = {'version': 3, 'auditConfigs': configs}
        if scenario == 'ancestor_denied':
            denied = ('https://cloudresourcemanager.googleapis.com/v3/organizations/9:getIamPolicy',)
    elif scenario == 'denied': denied = ('iam_policy',)
    collected, _ = native_collect(['project', 'iam_policy'], payloads, parents=parents, denied=denied,
                                  ancestry_denied=scenario == 'ancestry_denied')
    assert finding(collected, AUDIT)['status'] == expected


@pytest.mark.parametrize('cid,slug', METRICS, ids=[x[0] for x in METRICS])
def test_every_metric_incomplete_alert_inventory_stays_unknown(cid, slug):
    # The readable matching policy on page one cannot attest complete dependency reads.
    metric = {'name': 'review', 'filter': FILTERS[slug], 'metricDescriptor': {'type': MTYPE}}
    collected, transport = native_collect(['project', 'logging_metric', 'monitoring_alert_policy'],
        {'logging_metric': [metric], 'monitoring_alert_policy': []}, partial=('monitoring_alert_policy',))
    assert finding(collected, cid)['status'] == 'UNKNOWN'
    assert any((r.get('params') or {}).get('pageToken') == 'review-page-2' for r in transport.requests)


@pytest.mark.parametrize('cid', SINKS)
@pytest.mark.parametrize('scenario', ['wrong_receipt_scope', 'wrong_ancestor_chain', 'foreign_inherited_sink'])
def test_inherited_sink_tampering_cannot_manufacture_a_route(cid, scenario):
    collected, _ = native_collect(['project', 'log_sink'], {('log_sink', 'organizations/9'): [
        {'name': 'all', 'includeChildren': True, 'destination': 'storage.googleapis.com/archive'}]},
        parents=['organizations/9'])
    project = next(c for c in collected['collections'] if c['type'] == 'project')['items'][0]
    if scenario == 'wrong_receipt_scope':
        for receipt in collected['metadata']['source_requests']:
            if receipt['url'].endswith('/organizations/9/sinks'): receipt['scope'] = 'organizations/8'
    elif scenario == 'wrong_ancestor_chain': project['_coverage']['_inherited_sinks']['ancestors'] = ['organizations/8']
    else: project['_inherited_sinks'][0]['ancestor'] = 'organizations/8'
    collected.pop('snapshot_id', None)
    assert finding(collected, cid)['status'] == 'UNKNOWN'


@pytest.mark.parametrize('cid,expected', [(SINKS[0], 'FAIL'), (SINKS[1], 'MANUAL')])
def test_active_sink_exclusions_preserve_each_source_contract(cid, expected):
    collected, _ = native_collect(['project', 'log_sink'], {('log_sink', SCOPE): [
        {'name': 'all', 'destination': 'storage.googleapis.com/archive', 'exclusions': [
            {'name': 'omit', 'filter': 'severity>=ERROR'}]}]})
    assert finding(collected, cid)['status'] == expected
