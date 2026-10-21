from peaso.collectors.gcp_unused_iam_directory_completion_20261021 import bind_project, collect_users
from peaso.collectors.gcp_unused_iam_federation_completion_20261021 import read_provider_exchanges
from peaso.unused_iam_gcp_federation_completion_20261021 import evaluate_provider_use
from peaso.unused_iam_k8s_external_completion_20261021 import evaluate_subject_use
from copy import deepcopy

from peaso.collectors import gcp
from peaso.gcp_directory_usage_contract import KIND, USERS, FIELDS
from peaso.unused_iam_gcp_directory import USER
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate


NOW = '2026-10-21T12:00:00Z'
PROVIDER = 'projects/123456789/locations/global/workloadIdentityPools/pool/providers/oidc'


class DirectoryReader:
    def __init__(self):
        self.scopes = ['projects/alpha-project', 'projects/beta-project']
        self.needed = {'workspace_user'}
        self.options = {}
        self.added = {}

    def read(self, url, scope):
        current = url.rsplit('/v3/', 1)[1]
        customer = 'Calpha' if scope.endswith('alpha-project') else 'Cbeta'
        if current.startswith('projects/'):
            return {'name': 'projects/' + ('111' if customer == 'Calpha' else '222'),
                    'projectId': scope.split('/')[1], 'parent': 'organizations/' + ('1' if customer == 'Calpha' else '2')}, scope + '-project'
        return {'name': current, 'directoryCustomerId': customer}, scope + '-organization'

    def pages(self, url, scope, **kwargs):
        customer = kwargs['params']['customer']
        yield [{'id': 'user-1', 'customerId': customer, 'primaryEmail': 'user@example.test'}], scope + '-users'

    def add(self, kind, scope, service, rows):
        self.added[scope] = list(rows())


def test_directory_binding_is_per_project_and_customer():
    reader = DirectoryReader()
    collect_users(reader)
    assert set(reader.added) == set(reader.scopes)
    alpha = reader.added['projects/alpha-project'][0][0][0]
    beta = reader.added['projects/beta-project'][0][0][0]
    assert alpha['directoryCustomer'] == 'Calpha'
    assert beta['directoryCustomer'] == 'Cbeta'
    assert alpha['_directoryBinding']['scope'] == 'projects/alpha-project'
    assert beta['_directoryBinding']['chain'][-1]['directoryCustomerId'] == 'Cbeta'


def test_unbound_and_foreign_customer_cannot_collect_user():
    reader = DirectoryReader()
    reader.options = {'workspace_customers': ['Calpha']}
    reader.scopes = ['projects/beta-project']
    try:
        collect_users(reader)
    except Exception as exc:
        assert getattr(exc, 'error', {}).get('code') == 'project_directory_customer_not_selected'
    else:
        raise AssertionError('foreign customer was accepted')
    reader = DirectoryReader()
    reader.read = lambda url, scope: ({'name': 'projects/123', 'projectId': 'other', 'parent': 'organizations/1'}, 'bad')
    assert bind_project(reader, 'projects/alpha-project')['status'] == 'malformed'


def test_federation_logging_pages_and_positive_only():
    class Reader:
        def __init__(self): self.calls = []
        def read(self, url, scope, **kwargs):
            self.calls.append((url, scope, kwargs))
            if len(self.calls) == 1:
                return {'entries': [], 'nextPageToken': 'page-2'}, 'first'
            return {'entries': [{'timestamp': '2026-10-20T12:00:00Z',
                'logName': 'projects/test/logs/cloudaudit.googleapis.com%2Fdata_access',
                'protoPayload': {'resourceName': PROVIDER,
                    'methodName': 'google.identity.sts.v1.SecurityTokenService.ExchangeToken',
                    'status': {}}}]}, 'second'
    reader = Reader()
    result = read_provider_exchanges(reader, PROVIDER, 'projects/test',
                                     start='2026-10-01T00:00:00Z', end=NOW)
    assert result['status'] == 'collected' and result['source_requests'] == ['first', 'second']
    assert reader.calls[1][2]['body']['pageToken'] == 'page-2'
    assert evaluate_provider_use(PROVIDER, result['entries'], read_status=result['status'],
                                 captured_at=NOW, source_requests=result['source_requests'],
                                 scope='projects/test')[0] == 'PASS'
    assert evaluate_provider_use(PROVIDER, result['entries'], read_status='partial',
                                 captured_at=NOW, source_requests=result['source_requests'],
                                 scope='projects/test')[0] == 'PASS'
    assert evaluate_provider_use(PROVIDER, [], read_status='empty', captured_at=NOW,
                                 source_requests=['first'], scope='projects/test')[0] == 'UNKNOWN'


def test_k8s_external_audit_observes_subject_but_not_binding_usage():
    event = {'apiVersion': 'audit.k8s.io/v1', 'stage': 'ResponseComplete',
             'stageTimestamp': '2026-10-20T12:00:00Z', 'user': {'username': 'someone', 'groups': ['external-devs']},
             'responseStatus': {'code': 200}}
    kwargs = {'cluster_id': 'cluster-a', 'source_cluster_id': 'cluster-a', 'captured_at': NOW,
              'source_status': 'collected', 'source_requests': ['audit-file-1']}
    status, evidence = evaluate_subject_use({'kind': 'Group', 'name': 'external-devs'}, [event], **kwargs)
    assert status == 'PASS' and 'does not identify which RBAC binding' in evidence['summary']
    assert evaluate_subject_use({'kind': 'Group', 'name': 'external-devs'}, [event],
                                **{**kwargs, 'source_status': 'partial'})[0] == 'PASS'
    assert evaluate_subject_use({'kind': 'Group', 'name': 'external-devs'}, [], **kwargs)[0] == 'UNKNOWN'
    assert evaluate_subject_use({'kind': 'Group', 'name': 'external-devs'}, [event],
                                **{**kwargs, 'source_cluster_id': 'other'})[0] == 'UNKNOWN'
    assert evaluate_subject_use({'kind': 'Group', 'name': 'external-devs'},
                                [{**event, 'impersonatedUser': {'username': 'someone'}}], **kwargs)[0] == 'UNKNOWN'


class NativeDirectoryTransport:
    """Real GCPCollector transport contract with scope-bound read receipts."""
    def __init__(self, *, deny_detail=None, deny_project=None):
        self.evidence, self.requests, self.calls = [], [], 0
        self.deny_detail, self.deny_project = deny_detail, deny_project

    def request(self, method, url, **kwargs):
        self.calls += 1
        ref = f'directory-request-{self.calls}'
        scope = kwargs['scope']
        row = {'id': ref, 'method': method, 'url': url, 'scope': scope,
               'query': deepcopy(kwargs.get('params') or {}), 'status': 'collected', 'http_status': 200}
        self.requests.append({'method': method, 'url': url, **deepcopy(kwargs)})
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + scope:
            if scope == self.deny_project:
                row.update(status='denied', http_status=403)
                self.evidence.append(row)
                error = gcp.ReadError('denied', 'directory_project_denied', http_status=403)
                error.request_id = ref
                raise error
            project = scope.split('/', 1)[1]
            data = {'name': 'projects/' + ('111' if project == 'alpha-project' else '222'),
                    'projectId': project, 'parent': 'organizations/' + ('1' if project == 'alpha-project' else '2')}
        elif url.startswith('https://cloudresourcemanager.googleapis.com/v3/organizations/'):
            data = {'name': url.rsplit('/v3/', 1)[1],
                    'directoryCustomerId': 'Calpha' if scope == 'projects/alpha-project' else 'Cbeta'}
        elif url == USERS:
            customer = kwargs['params']['customer']
            data = {'users': [{'id': 'uid-' + customer, 'customerId': customer,
                               'primaryEmail': 'user@' + customer.lower() + '.test',
                               'suspended': False, 'archived': False}]}
        elif url.startswith(USERS + '/'):
            if scope == self.deny_detail:
                row.update(status='denied', http_status=403)
                self.evidence.append(row)
                error = gcp.ReadError('denied', 'directory_user_denied', http_status=403)
                error.request_id = ref
                raise error
            customer = 'Calpha' if scope == 'projects/alpha-project' else 'Cbeta'
            assert kwargs['params']['fields'] == FIELDS
            data = {'id': 'uid-' + customer, 'customerId': customer,
                    'primaryEmail': 'user@' + customer.lower() + '.test',
                    'suspended': False, 'archived': False,
                    'creationTime': '2024-01-01T00:00:00Z',
                    'lastLoginTime': '2025-01-01T00:00:00Z'}
        else:
            raise AssertionError('unexpected read: ' + url)
        self.evidence.append(row)
        return deepcopy(data), ref


def _native_directory_scan(*, deny_detail=None, deny_project=None):
    scopes = ['projects/alpha-project', 'projects/beta-project']
    transport = NativeDirectoryTransport(deny_detail=deny_detail, deny_project=deny_project)
    connector = {'provider': 'gcp', 'scopes': scopes,
                 'options': {'inventories': ['workspace_user', KIND],
                             'workspace_customers': ['Calpha', 'Cbeta'],
                             'include_inherited': False, 'concurrency': 1}}
    snapshot = gcp.GCPCollector(connector, transport=transport).collect()
    assert validate(snapshot) == snapshot
    return snapshot, transport


def test_native_collector_to_snapshot_to_evaluator_binds_two_customers():
    snapshot, transport = _native_directory_scan()
    users = {(c['scope'], c['items'][0]['directoryCustomer'])
             for c in snapshot['collections'] if c['type'] == 'workspace_user'}
    assert users == {('projects/alpha-project', 'Calpha'),
                     ('projects/beta-project', 'Cbeta')}
    reports = evaluate_snapshot(snapshot, categories=['hardening'], checks=[USER])
    findings = [row for row in reports['findings'] if row['check_id'] == USER]
    assert len(findings) == 2
    assert {row['status'] for row in findings} == {'FAIL'}
    assert {row['evidence']['directory_customer'] for row in findings} == {'Calpha', 'Cbeta'}
    assert {r['params']['customer'] for r in transport.requests if r['url'] == USERS} == {'Calpha', 'Cbeta'}
    assert len([r for r in transport.requests if r['url'].startswith(USERS + '/')]) == 2


def test_denied_second_project_keeps_first_project_positive():
    snapshot, _ = _native_directory_scan(deny_detail='projects/beta-project')
    findings = [row for row in evaluate_snapshot(snapshot, categories=['hardening'], checks=[USER])['findings']
                if row['check_id'] == USER]
    assert {row['status'] for row in findings} == {'FAIL', 'DENIED'}
    assert next(row for row in findings if row['status'] == 'FAIL')['evidence']['directory_customer'] == 'Calpha'
    snapshot, transport = _native_directory_scan(deny_project='projects/beta-project')
    collections = {(row['type'], row['scope']): row for row in snapshot['collections']}
    assert collections[('workspace_user', 'projects/beta-project')]['status'] == 'denied'
    assert collections[('workspace_user', 'projects/alpha-project')]['status'] == 'collected'
    assert not any(r['url'] == USERS and r['scope'] == 'projects/beta-project' for r in transport.requests)
