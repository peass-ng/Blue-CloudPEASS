"""Native GCP IAM ancestry responses through collector and registered engine."""
import copy
import pytest
from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CHECK = 'gcp.claude.project.audit_logs_configured'
SCOPE = 'projects/p-one'

class Transport:
    def __init__(self, *, inherited=True, denied=False, malformed=False, direct=False):
        self.calls = []
        self.evidence = []
        self.inherited, self.denied, self.malformed, self.direct = inherited, denied, malformed, direct

    def request(self, method, url, **kwargs):
        request_id = f'request-{len(self.calls)+1}'
        self.calls.append((method, url, copy.deepcopy(kwargs)))
        if url.endswith(':getAncestry'):
            result = {'ancestor': [{'resourceId': {'type': 'project', 'id': 'p-one'}},
                {'resourceId': {'type': 'folder', 'id': '12'}},
                {'resourceId': {'type': 'organization', 'id': '34'}}]}
        elif url.endswith('organizations/34:getIamPolicy'):
            if self.denied:
                exc = gcp.ReadError('denied', 'api_error', http_status=403)
                exc.request_id = request_id
                self.evidence.append({'id': request_id, 'url': url, 'method': method,
                                      'status': exc.status, 'error': exc.error})
                raise exc
            result = {'version': 3, 'auditConfigs': [{'service': 7 if self.malformed else 'allServices'}]} if self.inherited else {'version': 3, 'bindings': []}
        elif url.endswith(':getIamPolicy'):
            result = {'version': 1, 'bindings': []}
            if self.direct and url.endswith('projects/p-one:getIamPolicy'):
                result['auditConfigs'] = [{'service': 'allServices'}]
        else:
            result = {'results': []}
        self.evidence.append({'id': request_id, 'url': url, 'method': method, 'status': 'collected'})
        return copy.deepcopy(result), request_id


def collect(*, inherited=True, denied=False, malformed=False, direct=False):
    transport = Transport(inherited=inherited, denied=denied, malformed=malformed, direct=direct)
    connector = {'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'inventories': ['iam_policy'], 'include_inherited': True, 'concurrency': 1,
        'max_calls': 20}}
    snapshot = gcp.GCPCollector(connector, transport=transport).collect()
    assert transport.calls and all(method in ('GET', 'POST') for method, _, _ in transport.calls)
    return snapshot


def status(snapshot):
    report = evaluate_snapshot(snapshot, checks=[CHECK])
    rows = [r for r in report['findings'] if r['check_id'] == CHECK and r['resource_id'] != 'inventory:iam_policy']
    project = [r for r in rows if r.get('scope') == SCOPE]
    assert len(project) == 1, [(r.get('scope'), r['status']) for r in rows]
    return project[0]['status']


@pytest.mark.parametrize('inherited,expected', [(True, 'PASS'), (False, 'FAIL')])
def test_complete_native_ancestor_chain(inherited, expected):
    assert status(collect(inherited=inherited)) == expected


@pytest.mark.parametrize('denied,malformed', [(True, False), (False, True)])
def test_unavailable_ancestor_never_proves_positive(denied, malformed):
    assert status(collect(denied=denied, malformed=malformed)) == 'UNKNOWN'


def test_direct_native_declaration_keeps_existing_positive_branch():
    assert status(collect(direct=True)) == 'PASS'


@pytest.mark.parametrize('change', ['foreign_ancestry', 'partial_coverage', 'missing_source_requests',
    'missing_ancestor_entry', 'foreign_request', 'denied_request', 'foreign_ancestry_request',
    'missing_native_annotation'])
def test_corrupted_inherited_proof_is_unknown(change):
    snapshot = collect()
    collections = copy.deepcopy(snapshot['collections'])
    metadata = copy.deepcopy(snapshot['metadata'])
    if change == 'foreign_ancestry':
        metadata['inherited_scopes'] = []
    else:
        project = next(item for c in collections if c['type'] == 'iam_policy' and c['scope'] == SCOPE
                       for item in c['items'] if item.get('name') == SCOPE)
        if change == 'partial_coverage':
            project['_coverage']['effectiveAuditConfigs']['status'] = 'partial'
        elif change == 'missing_source_requests':
            project['_coverage']['effectiveAuditConfigs']['source_requests'] = []
        elif change == 'missing_ancestor_entry':
            project['effectiveAuditConfigs'].pop(1)
        elif change == 'foreign_request':
            ref = project['effectiveAuditConfigs'][2]['source_requests'][0]
            next(request for request in metadata['source_requests'] if request['id'] == ref)['url'] = (
                'https://cloudresourcemanager.googleapis.com/v3/organizations/99:getIamPolicy')
        elif change == 'denied_request':
            ref = project['effectiveAuditConfigs'][2]['source_requests'][0]
            next(request for request in metadata['source_requests'] if request['id'] == ref)['status'] = 'denied'
        elif change == 'foreign_ancestry_request':
            ref = project['_coverage']['effectiveAuditConfigs']['ancestry_source_requests'][0]
            next(request for request in metadata['source_requests'] if request['id'] == ref)['url'] = (
                'https://cloudresourcemanager.googleapis.com/v1/projects/foreign:getAncestry')
        else:
            project.pop('effectiveAuditConfigs')
            project['_coverage'].pop('effectiveAuditConfigs')
    modified = make_snapshot('gcp', snapshot['scopes'], collections, metadata=metadata)
    assert status(modified) == 'UNKNOWN'


def test_nonroot_cai_alias_cannot_claim_direct_project_audit_config():
    snapshot = collect()
    collections = copy.deepcopy(snapshot['collections'])
    project = next(item for c in collections if c['type'] == 'iam_policy' and c['scope'] == SCOPE
                   for item in c['items'] if item.get('name') == SCOPE)
    project['_provenance']['representation'] = 'partial'
    project['auditConfigs'] = [{'service': 'allServices'}]
    modified = make_snapshot('gcp', snapshot['scopes'], collections, metadata=snapshot['metadata'])
    assert status(modified) == 'NOT_APPLICABLE'
