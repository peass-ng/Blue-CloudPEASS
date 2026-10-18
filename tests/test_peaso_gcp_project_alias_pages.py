"""Every CAI page, including an empty final page, supplies completeness."""
import copy
import pytest
from peaso.collectors import gcp
from peaso.checks.gcp_data_access import CHECK_SERVICES
from peaso.gcp_data_access_policy import OPTION
from tests.test_peaso_gcp_project_alias_pipeline import (
    Session, Response, InertTransport, SCOPE, CRM, CAI, PRINCIPAL,
    complete_case, remake, direct_finding)

class PagedSession(Session):
    def request(self, method, url, **kwargs):
        if url == f'{CAI}/v1/{SCOPE}:searchAllIamPolicies':
            if kwargs['params'].get('pageToken') == 'final-empty-page':
                self.calls.append((method, url, copy.deepcopy(kwargs['params']), copy.deepcopy(kwargs['json'])))
                return Response({'results': []})
            response = super().request(method, url, **kwargs)
            response.data['nextPageToken'] = 'final-empty-page'
            return response
        return super().request(method, url, **kwargs)

def paged_snapshot(*, supporting_only=False):
    case = complete_case()
    session = PagedSession(case)
    transport = InertTransport(session)
    inventories = ['iam_policy'] if supporting_only else ['project', 'iam_policy']
    options = {'inventories': inventories, 'concurrency': 1,
               'hydration_concurrency': 1, 'metrics_scopes': False, 'resource_iam': True,
               OPTION: [{'status': 'approved', 'scope': SCOPE, 'service': service,
                         'source_ref': 'reviewed-page-fixture', 'principals': [PRINCIPAL]}
                        for service in CHECK_SERVICES.values()]}
    collector = gcp.GCPCollector({'auth': {}, 'scopes': [SCOPE], 'options': options},
                                 inventories, transport=transport)
    snapshot = collector.collect()
    iam = next(c for c in snapshot['collections'] if c['type'] == 'iam_policy')
    pages = [r for r in snapshot['metadata']['source_requests']
             if r['url'] == f'{CAI}/v1/{SCOPE}:searchAllIamPolicies']
    assert len(pages) == 2
    final = pages[-1]['id']
    assert final in iam['source_requests']
    assert all(final not in row['_provenance']['source_requests'] for row in iam['items'])
    return snapshot, final, session.calls

@pytest.mark.parametrize('check', tuple(CHECK_SERVICES))
def test_successful_empty_final_page_is_bound_and_preserved(check):
    snapshot, final, _ = paged_snapshot()
    finding = direct_finding(snapshot, check)
    assert finding['status'] == 'PASS'
    assert final in finding['evidence']['project_alias_requests']

@pytest.mark.parametrize('case', ['denied', 'missing', 'filtered', 'foreign_scope',
                                  'duplicate_record', 'denied_field', 'different_page_size',
                                  'denied_metadata_ledger'])
@pytest.mark.parametrize('check', tuple(CHECK_SERVICES))
def test_unbound_or_unreadable_empty_page_prevents_project_pass(case, check):
    snapshot, final, _ = paged_snapshot()
    metadata = copy.deepcopy(snapshot['metadata'])
    records = metadata['source_requests']
    row = next(r for r in records if r['id'] == final)
    if case == 'denied':
        row.update(status='denied', http_status=403)
    elif case == 'missing':
        metadata['source_requests'] = [r for r in records if r['id'] != final]
    elif case == 'filtered':
        row['query']['query'] = 'policy.role:roles/viewer'
    elif case == 'foreign_scope':
        row['scope'] = 'projects/other-project'
    elif case == 'duplicate_record':
        records.append(copy.deepcopy(row))
    elif case == 'denied_field':
        row['_coverage'] = {'status': {'status': 'denied'}}
    elif case == 'different_page_size':
        row['query']['pageSize'] = 17
    elif case == 'denied_metadata_ledger':
        metadata['_coverage'] = {'source_requests': {'status': 'denied'}}
    assert direct_finding(remake(snapshot, metadata=metadata), check)['status'] == 'UNKNOWN'

@pytest.mark.parametrize('check', tuple(CHECK_SERVICES))
def test_supporting_identity_does_not_collect_unrequested_compute_or_monitoring(check):
    snapshot, _, calls = paged_snapshot(supporting_only=True)
    assert direct_finding(snapshot, check)['status'] == 'PASS'
    assert any(url == f'{CRM}/v3/{SCOPE}' for _, url, _, _ in calls)
    assert all('compute.googleapis.com' not in url and 'monitoring.googleapis.com' not in url
               for _, url, _, _ in calls)
    assert len(calls) == 5  # direct policy, two CAI pages, identity GET, ancestry.
