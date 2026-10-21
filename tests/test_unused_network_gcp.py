from copy import deepcopy
import json
from pathlib import Path

import pytest

from peaso import unused_network_gcp as subject


CASES = json.loads((Path(__file__).parents[1] / 'peaso/checks/unused_network_gcp_cases.json').read_text())


@pytest.mark.parametrize('cid', [subject.ADDRESS, subject.POLICY, subject.NEG])
def test_native_resource_status_and_source_guards(cid):
    evaluator = dict((row[0], row[3]) for row in subject.DECLARATIONS)[cid]
    case = CASES[cid]
    for name, expected in [('pass', 'PASS'), ('fail', 'FAIL')]:
        assert evaluator(case[name], case[name+'_index'])[0] == expected
    from peaso.checks import CHECKS
    if not any(row.id == cid for row in CHECKS):
        subject.install(__import__('peaso.checks', fromlist=['register']))
    check = next(row for row in CHECKS if row.id == cid)
    assert check.category == 'hardening'
    assert check.evaluate(case['missing'], case['missing_index'])[0] == 'UNKNOWN'
    assert check.evaluate(case['malformed'], case['malformed_index'])[0] == 'UNKNOWN'
    for mutation in ('missing_receipt', 'foreign_scope', 'filtered', 'denied', 'partial_representation'):
        item, index = deepcopy(case['fail']), deepcopy(case['fail_index'])
        if mutation == 'missing_receipt': index['context']['metadata']['source_requests'] = []
        elif mutation == 'foreign_scope': item['_provenance']['scope'] = 'projects/foreign-project'
        elif mutation == 'filtered': index['context']['metadata']['source_requests'][0]['query']['filter'] = 'name=x'
        elif mutation == 'denied': index['context']['metadata']['source_requests'][0]['status'] = 'denied'
        else: item['_provenance']['representation'] = 'partial'
        assert check.evaluate(item, index)[0] == 'UNKNOWN', mutation
    item, index = deepcopy(case['pass']), deepcopy(case['pass_index'])
    index['collections'][check.kind][0]['status'] = 'partial'
    assert check.evaluate(item, index)[0] == 'PASS'


def test_address_omission_and_state_contradiction():
    case = CASES[subject.ADDRESS]
    item, index = deepcopy(case['fail']), deepcopy(case['fail_index'])
    del item['users']
    assert subject.evaluate_address(item, index)[0] == 'FAIL'
    item, index = deepcopy(case['fail']), deepcopy(case['fail_index'])
    item['users'] = ['https://www.googleapis.com/compute/v1/projects/usage-project/zones/us-central1-a/instances/vm']
    from peaso.checks.facts import Unavailable
    with pytest.raises(Unavailable): subject.evaluate_address(item, index)
    item, index = deepcopy(case['fail']), deepcopy(case['fail_index'])
    index['context']['metadata']['source_requests'][0]['url'] += '/wrong'
    with pytest.raises(Unavailable): subject.evaluate_address(item, index)


def test_managed_neg_endpoint_count_not_applicable():
    case = CASES[subject.NEG]
    item = deepcopy(case['fail'])
    item['networkEndpointType'] = 'SERVERLESS'
    assert subject.evaluate_neg(item, case['fail_index'])[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('cid', [subject.ADDRESS, subject.POLICY, subject.NEG])
def test_real_engine_snapshot(cid):
    from peaso.checks import CHECKS
    if not any(row.id == cid for row in CHECKS):
        subject.install(__import__('peaso.checks', fromlist=['register']))
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    case = CASES[cid]
    index = case['fail_index']
    scope = index['context']['scope']
    collections = deepcopy(list(index['collections'].values())[0])
    snapshot = make_snapshot('gcp', [scope], collections, created_at='2026-10-21T12:00:00Z',
                             metadata=index['context']['metadata'])
    report = evaluate_snapshot(snapshot, categories=['hardening'], checks=[cid])
    finding = next(row for row in report['findings'] if row['check_id'] == cid)
    assert finding['status'] == 'FAIL', finding
    assert finding['native_resource_id'] == case['fail']['selfLink']
    assert len(finding['evidence']['summary'].splitlines()) == 3


@pytest.mark.parametrize('cid', [subject.HTTP_PROXY, subject.HTTPS_PROXY])
def test_proxy_requires_both_forwarding_lists_and_exact_reference(cid):
    case = CASES[cid]
    assert subject.evaluate_proxy(case['pass'], case['pass_index'])[0] == 'PASS'
    assert subject.evaluate_proxy(case['fail'], case['fail_index'])[0] == 'UNKNOWN'
    item, index = deepcopy(case['pass']), deepcopy(case['pass_index'])
    index['collections']['forwarding_rule'][0]['source_requests'] = ['regional-list']
    from peaso.checks.facts import Unavailable
    with pytest.raises(Unavailable):
        subject.evaluate_proxy(item, index)
    item, index = deepcopy(case['pass']), deepcopy(case['pass_index'])
    index['forwarding_rule'][0]['data']['target'] = 'https://www.googleapis.com/compute/v1/projects/foreign-project/global/targetHttpProxies/proxy'
    with pytest.raises(Unavailable):
        subject.evaluate_proxy(item, index)


def test_backend_membership_and_service_bindings():
    case = CASES[subject.BACKEND]
    assert subject.evaluate_backend(case['pass'], case['pass_index'])[0] == 'PASS'
    assert subject.evaluate_backend(case['fail'], case['fail_index'])[0] == 'FAIL'
    item = deepcopy(case['fail'])
    del item['backends']
    assert subject.evaluate_backend(item, case['fail_index'])[0] == 'FAIL'
    item['_provenance']['representation'] = 'partial'
    from peaso.checks.facts import Unavailable
    with pytest.raises(Unavailable):
        subject.evaluate_backend(item, case['fail_index'])


def test_completion_engine_and_protocol_applicability():
    from peaso.checks import CHECKS
    if not any(row.id == subject.BACKEND for row in CHECKS):
        subject.install(__import__('peaso.checks', fromlist=['register']))
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    case = CASES[subject.HTTP_PROXY]
    index = case['pass_index']
    snapshot = make_snapshot('gcp', ['projects/usage-project'],
                             deepcopy([*index['collections']['target_proxy'], *index['collections']['forwarding_rule']]),
                             created_at='2026-10-21T12:00:00Z', metadata=index['context']['metadata'])
    report = evaluate_snapshot(snapshot, categories=['hardening'], checks=[subject.HTTP_PROXY, subject.HTTPS_PROXY])
    statuses = {row['check_id']: row['status'] for row in report['findings']}
    assert statuses[subject.HTTP_PROXY] == 'PASS'
    assert statuses[subject.HTTPS_PROXY] == 'NOT_APPLICABLE'
    case = CASES[subject.BACKEND]
    snapshot = make_snapshot('gcp', ['projects/usage-project'],
                             deepcopy(case['fail_index']['collections']['backend_service']),
                             created_at='2026-10-21T12:00:00Z', metadata=case['fail_index']['context']['metadata'])
    report = evaluate_snapshot(snapshot, categories=['hardening'], checks=[subject.BACKEND])
    assert next(row for row in report['findings'] if row['check_id'] == subject.BACKEND)['status'] == 'FAIL'


def test_global_forwarding_rule_helper_uses_native_bounded_reader():
    from peaso.collectors.gcp_network_forwarding_completion_20261021 import collect
    class Collector:
        needed = {'forwarding_rule'}
        scopes = ['projects/usage-project', 'organizations/123456789012']
        def __init__(self):
            self.calls = []
        def pages(self, url, scope, **options):
            self.calls.append((url, scope, options))
            item = {'selfLink': 'https://www.googleapis.com/compute/v1/projects/usage-project/global/forwardingRules/f'}
            yield [options['transform'](item)], 'global-list'
        def add(self, kind, scope, service, fetch):
            assert (kind, scope, service) == ('forwarding_rule', 'projects/usage-project', 'compute')
            self.result = list(fetch())
    collector = Collector()
    collect(collector)
    assert len(collector.calls) == 1
    url, scope, options = collector.calls[0]
    assert url == 'https://compute.googleapis.com/compute/v1/projects/usage-project/global/forwardingRules'
    assert scope == 'projects/usage-project'
    assert options['page_size_key'] == 'maxResults'
    assert collector.result[0][0][0]['_representation'] == 'full'
