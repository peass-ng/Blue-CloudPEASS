"""Verify both real forwarding-rule readers survive into a native finding."""
from copy import deepcopy

from peaso.collectors.gcp import GCPCollector
from peaso.engine import evaluate_snapshot
from peaso import unused_network_gcp as subject
from peaso.checks import CHECKS


def test_native_global_and_regional_forwarding_rules_reach_proxy_finding():
    project = 'projects/usage-project'
    base = 'https://www.googleapis.com/compute/v1/' + project
    proxy = base + '/global/targetHttpProxies/proxy'
    class Transport:
        def __init__(self):
            self.evidence = []
            self.requests = []
        def request(self, method, url, **kwargs):
            self.requests.append(url)
            ref = 'native-' + str(len(self.requests))
            self.evidence.append({'id': ref, 'method': method, 'url': url, 'scope': kwargs['scope'],
                'query': deepcopy(kwargs.get('params') or {}), 'status': 'collected', 'http_status': 200})
            if url.endswith('/aggregated/targetHttpProxies'):
                data = {'items': {'global': {'targetHttpProxies': [{'name': 'proxy', 'selfLink': proxy}]}}}
            elif url.endswith('/global/forwardingRules'):
                data = {'items': [{'name': 'front', 'selfLink': base + '/global/forwardingRules/front', 'target': proxy}]}
            elif '/aggregated/' in url:
                data = {'items': {}}
            elif '/global/' in url:
                data = {'items': []}
            elif 'cloudresourcemanager.googleapis.com/v3/projects/' in url:
                data = {'name': 'projects/123456789012', 'projectId': 'usage-project'}
            else:
                raise AssertionError('unexpected native read: ' + url)
            return data, ref
    check = next(c for c in CHECKS if c.id == subject.HTTP_PROXY)
    assert 'forwarding_rule' in check.dependencies
    transport = Transport()
    connector = {'provider': 'gcp', 'scopes': [project],
                 'options': {'inventories': list(check.dependencies), 'include_inherited': False, 'concurrency': 1}}
    snapshot = GCPCollector(connector, transport=transport).collect()
    report = evaluate_snapshot(snapshot, categories=['hardening'], checks=[subject.HTTP_PROXY])
    finding = next(f for f in report['findings'] if f['check_id'] == subject.HTTP_PROXY)
    assert finding['status'] == 'PASS', finding
    assert any(u.endswith('/aggregated/forwardingRules') for u in transport.requests)
    assert any(u.endswith('/global/forwardingRules') for u in transport.requests)
