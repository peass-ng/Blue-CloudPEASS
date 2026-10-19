"""Directed native-response review; native regression tests for reproduced defects.

Reuse the collector transport/snapshot harness from test_peaso_collectors_gcp;
consumer assertions use the production engine, never registration fixtures.
"""
import pytest

from peaso.collectors.gcp import ReadError
from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot, collection


def verdict(native, cid):
    findings = evaluate_snapshot(native, checks=[cid], include_not_applicable=True)['findings']
    assert len(findings) == 1
    return findings[0]['status']


def test_native_template_external_ipv6_is_exposure():
    native, _ = snapshot(['instance_template'], lambda r: {'items': {'global': {'instanceTemplates': [{
        'name': 'ipv6-template', 'properties': {'networkInterfaces': [{
            'stackType': 'IPV4_IPV6', 'ipv6AccessConfigs': [{'type': 'DIRECT_IPV6', 'networkTier': 'PREMIUM'}]}]}}]}}})
    assert collection(native, 'instance_template')['items'][0]['_provenance']['representation'] == 'full'
    assert verdict(native, 'gcp_pci_instance_template_2e26bed500fc') == 'FAIL'


@pytest.mark.parametrize('selector', ['sourceTags', 'sourceServiceAccounts'])
@pytest.mark.parametrize('suffix,cidr', [('http_lb', '35.191.0.0/16'), ('iap_tcp', '35.235.240.0/20')])
def test_native_proxy_source_selector_expands_allowed_population(suffix, cidr, selector):
    native, _ = snapshot(['firewall'], lambda r: {'items': [{'name': 'proxy', 'direction': 'INGRESS',
        'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}], 'sourceRanges': [cidr], selector: ['other-vms']}]})
    assert verdict(native, 'gcp.ports.firewall_' + suffix + '_proxy_source_restriction') == 'FAIL'


def test_native_gke_modern_authorized_networks_are_consumed():
    native, _ = snapshot(['gke_cluster'], lambda r: {'clusters': [{'name': 'cluster',
        'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'enabled': True, 'enablePublicEndpoint': True,
            'authorizedNetworksConfig': {'enabled': True, 'cidrBlocks': [{'cidrBlock': '10.0.0.0/8'}]}}}}]})
    assert verdict(native, 'gcp.claude.gke.master_authorized_networks_restricted') == 'PASS'


def test_native_template_no_access_config_and_explicit_denial():
    native, _ = snapshot(['instance_template'], lambda r: {'items': {'global': {'instanceTemplates': [{
        'name': 'private', 'properties': {'networkInterfaces': [{'network': 'projects/p-one/global/networks/private'}]}}]}}})
    assert verdict(native, 'gcp_pci_instance_template_2e26bed500fc') == 'PASS'
    item = collection(native, 'instance_template')['items'][0]
    item['properties']['networkInterfaces'][0]['_coverage'] = {'accessConfigs': {'status': 'denied'}}
    native.pop('snapshot_id')
    assert verdict(native, 'gcp_pci_instance_template_2e26bed500fc') == 'UNKNOWN'


def test_native_partial_firewall_list_cannot_certify_clean_first_page():
    def response(request):
        if request['params'].get('pageToken'):
            raise ReadError('denied', 'PERMISSION_DENIED', http_status=403)
        return {'items': [{'name': 'narrow', 'direction': 'INGRESS',
            'sourceRanges': ['10.0.0.0/8'], 'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}]}], 'nextPageToken': 'next'}
    native, _ = snapshot(['firewall'], response)
    assert collection(native, 'firewall')['status'] == 'partial'
    findings = evaluate_snapshot(native, checks=['gcp.ports.compute_firewall_rule_ssh_access_restricted'])['findings']
    assert any(f['status'] in ('UNKNOWN', 'DENIED') for f in findings)
    assert any(f['status'] == 'PASS' for f in findings)  # observed rule remains locally decidable


def test_native_gke_unreachable_zone_cannot_certify_cluster():
    native, _ = snapshot(['gke_cluster'], lambda r: {'clusters': [{'name': 'cluster',
        'legacyAbac': {'enabled': False}}], 'missingZones': ['us-central1-a']})
    assert collection(native, 'gke_cluster')['status'] == 'partial'
    findings = evaluate_snapshot(native, checks=['gcp.gke.no_legacy_abac'])['findings']
    assert any(f['status'] in ('UNKNOWN', 'DENIED') for f in findings)
    assert any(f['status'] == 'PASS' for f in findings)  # returned cluster is a distinct known object


@pytest.mark.parametrize('selector', ['sourceTags', 'sourceServiceAccounts'])
def test_proxy_source_unreadable_selector_stays_unknown(selector):
    native, _ = snapshot(['firewall'], lambda r: {'items': [{'name': 'proxy', 'direction': 'INGRESS',
        'allowed': [{'IPProtocol': 'tcp'}], 'sourceRanges': ['35.235.240.0/20'],
        '_coverage': {selector: {'status': 'denied'}}}]})
    assert verdict(native, 'gcp.ports.firewall_iap_tcp_proxy_source_restriction') == 'UNKNOWN'


def test_template_unreadable_ipv6_is_not_omitted_default():
    native, _ = snapshot(['instance_template'], lambda r: {'items': {'global': {'instanceTemplates': [{
        'name': 'unreadable', 'properties': {'networkInterfaces': [{
            '_coverage': {'ipv6AccessConfigs': {'status': 'denied'}}}]}}]}}})
    assert verdict(native, 'gcp_pci_instance_template_2e26bed500fc') == 'UNKNOWN'


@pytest.mark.parametrize('config,expected', [
    ({'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'enabled': False}}}, 'NOT_APPLICABLE'),
    ({'masterAuthorizedNetworksConfig': {'enabled': True, 'cidrBlocks': [{'cidrBlock': '10.0.0.0/8'}]},
      'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'authorizedNetworksConfig': {'enabled': False}}}}, 'UNKNOWN'),
    ({'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'authorizedNetworksConfig': {
        'enabled': True, 'cidrBlocks': [{'cidrBlock': 'bad-cidr'}]}}}}, 'UNKNOWN'),
    ({'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'authorizedNetworksConfig': {
        'enabled': True, 'cidrBlocks': [{'cidrBlock': '::/0'}]}}}}, 'FAIL'),
    ({'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'_coverage': {
        'authorizedNetworksConfig': {'status': 'denied'}}}}}, 'UNKNOWN'),
])
def test_native_gke_current_authorized_network_contract(config, expected):
    native, _ = snapshot(['gke_cluster'], lambda r: {'clusters': [{'name': 'cluster', **config}]})
    assert verdict(native, 'gcp.claude.gke.master_authorized_networks_restricted') == expected
