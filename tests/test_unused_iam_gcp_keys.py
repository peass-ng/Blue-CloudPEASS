from copy import deepcopy
from datetime import timedelta
import json
import pytest

from peaso import unused_iam_gcp_keys as subject
from peaso.gcp_key_usage_contract import API, HMAC, PARENTS, METRICS, RESOURCES, parameters, WINDOW_DAYS, LAG
from peaso.gcp_iam_usage_contract import timestamp

NOW = '2026-10-21T12:00:00Z'
OWNER = 'projects/usage-project'
OTHER = 'projects/bucket-project'


def proof(scope, refs):
    return {'scope': scope, 'collected_at': NOW, 'source_requests': refs}


def read(ref, url, scope, query=None, status='collected'):
    return {'id': ref, 'scope': scope, 'url': url, 'method': 'GET', 'status': status,
            'http_status': 200 if status == 'collected' else 403, 'query': query or {}}


def series(kind, ident, project='usage-project', recent=False, success=True):
    labels = {'response_code_class': '2xx' if success else '4xx'} if kind == API else {
        'access_id': ident, 'authentication_method': 'HMAC', 'response_code': '200' if success else '403'}
    resource = {'project_id': project}
    if kind == API: resource['credential_id'] = 'apikey:'+ident
    return {'metric': {'type': METRICS[kind], 'labels': labels}, 'resource': {'type': RESOURCES[kind], 'labels': resource},
        'metricKind': 'DELTA', 'valueType': 'INT64', 'points': [{'interval': {
            'startTime': '2026-10-19T00:00:00Z' if recent else '2026-01-01T00:00:00Z',
            'endTime': '2026-10-20T00:00:00Z' if recent else '2026-01-02T00:00:00Z'}, 'value': {'int64Value': '2'}}]}


def fixture(hmac=False, recent=False, cross=False):
    kind = HMAC if hmac else API
    ident = 'GOOG1syntheticPublicAccessId' if hmac else 'synthetic-key-uid'
    item = {'accessId': ident, 'projectId': 'usage-project', 'serviceAccountEmail': 'worker@usage-project.iam.gserviceaccount.com',
            'state': 'ACTIVE', 'timeCreated': '2024-01-01T00:00:00Z'} if hmac else {
            'name': OWNER+'/locations/global/keys/synthetic', 'uid': ident, 'createTime': '2024-01-01T00:00:00Z'}
    native_url = 'https://storage.googleapis.com/storage/v1/'+OWNER+'/hmacKeys' if hmac else 'https://apikeys.googleapis.com/v2/'+OWNER+'/locations/global/keys'
    item['_provenance'] = proof(OWNER, ['credential-read'])
    start, end = timestamp(NOW)-LAG-timedelta(days=WINDOW_DAYS), timestamp(NOW)-LAG
    selected = [OWNER, OTHER] if cross else [OWNER]
    record = {'name': OWNER+'/'+kind+'/'+ident, 'credential_id': ident,
        'credential_name': ident if hmac else item['name'], 'owner_scope': OWNER,
        'observation_start': start.isoformat(), 'observation_end': end.isoformat(),
        'selected_project_scopes': selected, 'views': []}
    ledger = [read('credential-read', native_url, OWNER)]
    bindings = {}
    for i, scope in enumerate(selected):
        project = scope.split('/')[1]
        number = str(123456789012+i)
        ref, crm = f'metric-{i}', f'crm-{i}'
        query = parameters(kind, project, ident, start.isoformat(), end.isoformat())
        bindings[scope] = {'status': 'collected', 'scope': scope, 'project_id': project,
                          'project_number': number, 'source_requests': [crm]}
        ledger.append(read(crm, 'https://cloudresourcemanager.googleapis.com/v3/'+scope, scope))
        if kind == API and scope != OWNER: continue
        record['views'].append({'scope': scope, 'status': 'collected', 'project_id': project, 'project_number': number,
            'source_requests': [ref], 'query': query, 'series': [series(kind, ident, project, recent and (not cross or scope == OTHER))]})
        ledger.append(read(ref, 'https://monitoring.googleapis.com/v3/'+scope+'/timeSeries', scope, query))
    refs = [ref for view in record['views'] for ref in view['source_requests']]
    record.update(metric_source_requests=refs, _provenance=proof(OWNER, [refs[-1]]))
    index = {'context': {'provider': 'gcp', 'scope': OWNER, 'created_at': NOW,
        'metadata': {'asset_read_time': NOW, 'source_requests': ledger, 'resolved_scopes': selected, 'data_service_project_bindings': bindings}}, 'collections': {}}
    for typ, rows, service in [(PARENTS[kind], [item], 'storage' if hmac else 'apikeys'), (kind, [record], 'monitoring')]:
        index[typ] = [{'type': typ, 'scope': OWNER, 'data': row} for row in rows]
        index['collections'][typ] = [{'type': typ, 'scope': OWNER, 'service': service, 'status': 'collected', 'items': rows}]
    return item, index


def observation(index, hmac=False): return index[HMAC if hmac else API][0]['data']


@pytest.mark.parametrize('hmac', [False, True])
def test_old_recorded_successful_requests_fail_and_recent_positive_passes(hmac):
    evaluate = subject.evaluate_hmac if hmac else subject.evaluate_api
    for recent, expected in [(False, 'FAIL'), (True, 'PASS')]:
        item, index = fixture(hmac, recent)
        before = deepcopy(index)
        status, evidence = evaluate(item, index)
        assert status == expected, evidence
        assert evidence['universal_inactivity_established'] is False
        assert evidence['latest_recorded_successful_interval']
        assert index == before


@pytest.mark.parametrize('hmac', [False, True])
@pytest.mark.parametrize('mutation', ['empty', 'failed_only', 'negative', 'overflow', 'future', 'before_creation', 'duplicate', 'foreign_metric', 'foreign_key', 'foreign_project', 'query', 'query_receipt', 'read_receipt', 'stale', 'short', 'missing_view', 'unselected', 'missing_binding', 'denied'])
def test_missing_or_foreign_telemetry_never_fabricates_unused_credentials(hmac, mutation):
    item, index = fixture(hmac)
    record = observation(index, hmac)
    view = record['views'][0]
    row = view['series'][0]
    point = row['points'][0]
    expected = 'UNKNOWN'
    if mutation == 'empty': view['series'] = []
    elif mutation == 'failed_only': row['metric']['labels']['response_code' if hmac else 'response_code_class'] = '403' if hmac else '4xx'
    elif mutation == 'negative': point['value']['int64Value'] = '-1'
    elif mutation == 'overflow': point['value']['int64Value'] = str(2**63)
    elif mutation == 'future': point['interval']['endTime'] = '2027-01-01T00:00:00Z'
    elif mutation == 'before_creation': item['timeCreated' if hmac else 'createTime'] = '2026-02-01T00:00:00Z'
    elif mutation == 'duplicate': row['points'].append(deepcopy(point))
    elif mutation == 'foreign_metric': row['metric']['type'] = 'other.googleapis.com/metric'
    elif mutation == 'foreign_key': (row['metric']['labels'] if hmac else row['resource']['labels'])['access_id' if hmac else 'credential_id'] = 'foreign'
    elif mutation == 'foreign_project': row['resource']['labels']['project_id'] = 'foreign-project'
    elif mutation == 'query': view['query'] = {**view['query'], 'filter': 'wrong'}
    elif mutation == 'query_receipt': index['context']['metadata']['source_requests'][-1]['query'] = {'filter': 'wrong'}
    elif mutation == 'read_receipt': index['context']['metadata']['source_requests'][-1]['method'] = 'POST'
    elif mutation == 'stale': record['observation_end'] = '2026-01-01T00:00:00Z'
    elif mutation == 'short': record['observation_start'] = '2026-10-01T00:00:00Z'
    elif mutation == 'missing_view': record['views'] = []
    elif mutation == 'unselected': record['selected_project_scopes'] = ['projects/foreign']
    elif mutation == 'missing_binding': index['context']['metadata']['data_service_project_bindings'] = {}
    elif mutation == 'denied': view.update(status='denied', series=[]); expected = 'DENIED'
    evaluate = subject.evaluate_hmac if hmac else subject.evaluate_api
    assert evaluate(item, index)[0] == expected


def test_hmac_recent_success_in_another_selected_bucket_project_is_not_unused():
    item, index = fixture(True, True, True)
    status, evidence = subject.evaluate_hmac(item, index)
    assert status == 'PASS', evidence
    assert evidence['latest_recorded_successful_interval']['project_scope'] == OTHER


def test_hmac_denied_view_cannot_hide_independent_recent_success():
    item, index = fixture(True, True, True)
    observation(index, True)['views'][0].update(status='denied', series=[])
    assert subject.evaluate_hmac(item, index)[0] == 'PASS'
    item, index = fixture(True, False, True)
    observation(index, True)['views'][0].update(status='denied', series=[])
    assert subject.evaluate_hmac(item, index)[0] == 'DENIED'


@pytest.mark.parametrize('hmac', [False, True])
def test_new_and_inactive_credentials_have_explicit_applicability(hmac):
    item, index = fixture(hmac)
    item['timeCreated' if hmac else 'createTime'] = '2026-10-20T12:00:00Z'
    evaluate = subject.evaluate_hmac if hmac else subject.evaluate_api
    assert evaluate(item, index)[0] == 'PASS'
    if hmac: item['state'] = 'INACTIVE'
    else: item['deleteTime'] = '2026-10-21T11:00:00Z'
    assert evaluate(item, index)[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('hmac', [False, True])
def test_daily_count_overlapping_90_day_threshold_is_unresolved(hmac):
    item, index = fixture(hmac)
    cutoff = timestamp(NOW)-timedelta(days=90)
    point = observation(index, hmac)['views'][0]['series'][0]['points'][0]
    point['interval'] = {'startTime': (cutoff-timedelta(hours=12)).isoformat(), 'endTime': (cutoff+timedelta(hours=12)).isoformat()}
    evaluate = subject.evaluate_hmac if hmac else subject.evaluate_api
    assert evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid,hmac', [(subject.API_CHECK, False), (subject.HMAC_CHECK, True)])
def test_registered_key_controls_have_hardening_json_and_compliance_membership(cid, hmac):
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.snapshot import make_snapshot
    check = next(row for row in CHECKS if row.id == cid)
    assert check.category == 'hardening'
    for status in ('PASS', 'FAIL'):
        key = status.lower();case = CASES[cid]
        assert check.evaluate(case[key], case[key+'_index'])[0] == status
    item, index = fixture(hmac)
    collections = [deepcopy(row) for rows in index['collections'].values() for row in rows]
    snapshot = make_snapshot('gcp', [OWNER], collections, created_at=NOW, metadata=index['context']['metadata'])
    finding = hydrate_frameworks(evaluate_snapshot(snapshot, categories=['hardening'], checks=[cid]))['findings'][0]
    assert finding['status'] == 'FAIL', finding['evidence']
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    assert any(name != 'HackTricks Cloud Best Practices' for name in finding['frameworks'])
    assert json.loads(json.dumps(finding))['evidence']['universal_inactivity_established'] is False
