"""An uncertain ancestor inventory cannot certify project audit logging."""
import copy
import pytest
from peaso.collectors.gcp import GCPCollector
from peaso.checks.gcp_data_access import _native, CHECK_SERVICES
from peaso.gcp_data_access_policy import OPTION, normalize_owner_policy
from tests.test_peaso_gcp_data_access import PROJECT, ORG, config, policy, owner

@pytest.mark.parametrize('check', tuple(CHECK_SERVICES))
@pytest.mark.parametrize('case', ['none', 'known_peer', 'unknown_peer', 'denied_name',
                                  'denied_assetType', 'denied_provenance',
                                  'denied_items', 'denied_status', 'partial_inventory', 'duplicate_root'])
def test_ancestor_authority_is_required_before_project_verdict(check, case):
    service = CHECK_SERVICES[check]
    collector = GCPCollector.__new__(GCPCollector)
    collector.needed = {'iam_policy'}
    collector.ancestry = {PROJECT: [
        {'resourceId': {'type': 'project', 'id': PROJECT.split('/')[1]}},
        {'resourceId': {'type': 'organization', 'id': ORG.split('/')[1]}}]}
    project = policy(PROJECT, [])
    organization = policy(ORG, [config(service, 'DATA_READ'), config(service, 'DATA_WRITE')])
    peers = []
    if case in ('known_peer', 'unknown_peer', 'denied_name', 'denied_assetType', 'denied_provenance'):
        peer = {'name': '//storage.googleapis.com/projects/_/buckets/example',
                'assetType': 'storage.googleapis.com/Bucket',
                '_provenance': {'source_requests': ['peer'], 'representation': 'partial'}}
        if case == 'unknown_peer':
            peer.update(name='//mystery.googleapis.com/organizations/34/opaque', assetType='unknown/Root')
        if case.startswith('denied_'):
            field = {'denied_name': 'name', 'denied_assetType': 'assetType',
                     'denied_provenance': '_provenance'}[case]
            peer['_coverage'] = {field: {'status': 'denied'}}
        peers.append(peer)
    if case == 'duplicate_root':
        peers.append(copy.deepcopy(organization))
    def envelope(scope, items):
        return {'type': 'iam_policy', 'scope': scope, 'status': 'collected',
                'coverage_status': 'collected', 'items': items}
    ancestor = envelope(ORG, [organization, *peers])
    if case in ('denied_items', 'denied_status'):
        ancestor['_coverage'] = {case.removeprefix('denied_'): {'status': 'denied'}}
    if case == 'partial_inventory':
        ancestor['coverage_status'] = 'partial'
    collector.collections = {('iam_policy', PROJECT): envelope(PROJECT, [project]),
                             ('iam_policy', ORG): ancestor}
    collector.annotate_effective_audit()
    index = {'context': {'scope': PROJECT, 'metadata': {
                OPTION: normalize_owner_policy([owner(service)], [PROJECT])}},
             'collections': {'iam_policy': [collector.collections[('iam_policy', PROJECT)]]}}
    expected = 'PASS' if case in ('none', 'known_peer') else 'UNKNOWN'
    assert _native(project, index, check)[0] == expected
    assert project['_coverage']['effectiveAuditConfigs']['status'] == (
        'collected' if expected == 'PASS' else 'partial')
