"""Native proof for four bounded Compute fixes and exact project URL joins."""
from copy import deepcopy
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from tests import test_gcp_compute_second_batch_review_20261020 as batch
from tests.test_gcp_compute_second_batch_review_20261020 import no_network_or_credentials, write_receipts

# Isolate post-fix receipts from the historical review's artifacts.
batch.ROOT = Path('/tmp/peasso-gcp-review-20261020/compute-second/fixes')


@pytest.mark.parametrize('reference', [
    batch.BACKEND,
    batch.BACKEND.replace('compute.googleapis.com', 'www.googleapis.com'),
    'compute/v1/projects/p-one/global/backendServices/review',
    '/compute/v1/projects/p-one/global/backendServices/review',
    'projects/p-one/global/backendServices/review',
    'global/backendServices/review',
])
def test_documented_compute_backend_url_forms(reference):
    case = batch.find('compute_url_map_backend_logging')
    collected, transport = batch.capture(case, 'good', lambda row, routes: row.update(defaultService=reference))
    batch.verdict(case, 'fixed:backend_form:' + reference, collected, transport, 'PASS')


@pytest.mark.parametrize('reference', [
    'https://evil.invalid/compute/v1/projects/p-one/global/backendServices/review',
    'https://compute.googleapis.com.evil.invalid/compute/v1/projects/p-one/global/backendServices/review',
    'https://user@compute.googleapis.com/compute/v1/projects/p-one/global/backendServices/review',
    'http://compute.googleapis.com/compute/v1/projects/p-one/global/backendServices/review',
    'https://compute.googleapis.com:443/compute/v1/projects/p-one/global/backendServices/review',
    'https://compute.googleapis.com/compute/v1/projects/p-one/global/backendServices/review?alt=json',
    'https://compute.googleapis.com/compute/v1/projects/p-one/global/backendServices/review#section',
    'projects/p-two/global/backendServices/review',
    'projects/p-one/global/../backendServices/review',
    'projects/p-one/global/backendServices/review%2fother',
    'projects/p-one/regions/us-east1/backendServices/review',
    'projects/p-one/global/networks/review',
])
def test_backend_url_authority_scope_and_path_are_not_suffix_joins(reference):
    case = batch.find('compute_url_map_backend_logging')
    collected, transport = batch.capture(case, 'good', lambda row, routes: row.update(defaultService=reference))
    batch.verdict(case, 'fixed:reject_backend_reference:' + reference, collected, transport, 'UNKNOWN')


@pytest.mark.parametrize('scenario', ['foreign_native_map', 'foreign_native_backend', 'alias_duplicate'])
def test_backend_native_identity_must_match_scope_and_be_unique(scenario):
    case = batch.find('compute_url_map_backend_logging')
    def mutate(row, routes):
        backends = routes[batch.C + '/aggregated/backendServices']['data']['items']['global']['backendServices']
        if scenario == 'foreign_native_map': row['selfLink'] = row['selfLink'].replace('p-one', 'p-two')
        elif scenario == 'foreign_native_backend': backends[0]['selfLink'] = backends[0]['selfLink'].replace('p-one', 'p-two')
        else:
            duplicate = deepcopy(backends[0])
            duplicate['selfLink'] = duplicate['selfLink'].replace('compute.googleapis.com', 'www.googleapis.com')
            backends.append(duplicate)
    collected, transport = batch.capture(case, 'good', mutate)
    batch.verdict(case, 'fixed:backend_identity:' + scenario, collected, transport, 'UNKNOWN')


def test_regional_backend_keeps_exact_location_binding():
    case = batch.find('compute_url_map_backend_logging')
    def mutate(row, routes):
        row['selfLink'] = batch.C + '/regions/us-central1/urlMaps/review'
        row['region'] = batch.C + '/regions/us-central1'
        row['defaultService'] = 'regions/us-central1/backendServices/review'
        urls = routes[batch.C + '/aggregated/urlMaps']['data']['items']
        urls['regions/us-central1'] = urls.pop('global')
        services = routes[batch.C + '/aggregated/backendServices']['data']['items']
        services['regions/us-central1'] = services.pop('global')
        services['regions/us-central1']['backendServices'][0]['selfLink'] = batch.C + '/regions/us-central1/backendServices/review'
    collected, transport = batch.capture(case, 'good', mutate)
    batch.verdict(case, 'fixed:regional_backend_reference', collected, transport, 'PASS')


@pytest.mark.parametrize('profile,minimum,expected', [
    ('RESTRICTED', 'TLS_1_3', 'PASS'), ('RESTRICTED', 'TLS_1_2', 'PASS'),
    ('MODERN', 'TLS_1_2', 'PASS'), ('FIPS_202205', 'TLS_1_2', 'PASS'),
    ('COMPATIBLE', 'TLS_1_0', 'FAIL'), ('MODERN', 'TLS_1_1', 'FAIL'),
    ('MODERN', 'TLS_1_3', 'UNKNOWN'), ('CUSTOM', 'TLS_1_3', 'UNKNOWN'),
    ('RESTRICTED', 'TLS_FUTURE', 'UNKNOWN'), ('FUTURE', 'TLS_1_3', 'UNKNOWN'),
])
def test_tls_minimum_and_profile_contract(profile, minimum, expected):
    case = batch.find('compute_ssl_policy_strict_declaration')
    def mutate(row, routes):
        policy = routes[batch.C + '/aggregated/sslPolicies']['data']['items']['global']['sslPolicies'][0]
        policy.update(profile=profile, minTlsVersion=minimum)
    collected, transport = batch.capture(case, 'good', mutate)
    batch.verdict(case, 'fixed:tls_pair:' + profile + ':' + minimum, collected, transport, expected)


@pytest.mark.parametrize('scenario,expected', [('relative', 'PASS'), ('google_alias', 'PASS'), ('foreign', 'UNKNOWN'), ('duplicate_alias', 'UNKNOWN')])
def test_ssl_policy_reference_is_scoped_and_unambiguous(scenario, expected):
    case = batch.find('compute_ssl_policy_strict_declaration')
    def mutate(row, routes):
        if scenario == 'relative': row['sslPolicy'] = 'global/sslPolicies/review'
        elif scenario == 'google_alias': row['sslPolicy'] = batch.POLICY.replace('compute.googleapis.com', 'www.googleapis.com')
        elif scenario == 'foreign': row['sslPolicy'] = batch.POLICY.replace('p-one', 'p-two')
        else:
            policies = routes[batch.C + '/aggregated/sslPolicies']['data']['items']['global']['sslPolicies']
            duplicate = deepcopy(policies[0]); duplicate['selfLink'] = duplicate['selfLink'].replace('compute.googleapis.com', 'www.googleapis.com')
            policies.append(duplicate)
    collected, transport = batch.capture(case, 'good', mutate)
    batch.verdict(case, 'fixed:ssl_reference:' + scenario, collected, transport, expected)


@pytest.mark.parametrize('suffix', ['compute_ssl_policy_strict_declaration', 'compute_url_map_backend_logging'])
@pytest.mark.parametrize('context', [None, {'provider': 'aws', 'scope': batch.P}, {'provider': 'gcp', 'scope': 'projects/p-two'}])
def test_unscoped_or_wrong_provider_indices_cannot_supply_a_safe_join(suffix, context):
    case = batch.find(suffix)
    collected, transport = batch.capture(case, 'good')
    # This direct guard test starts from real collected native facts, then removes
    # the engine's context authority to verify the predicate cannot infer it.
    # Build a resource index from the public snapshot representation.
    index = {'collections': {}, 'context': context}
    for collection in collected['collections']:
        kind = collection['type']
        index['collections'][kind] = [collection]
        index[kind] = [{'data': row} for row in collection['items']]
    item = next(c for c in collected['collections'] if c['type'] == case['kind'])['items'][0]
    check = next(c for c in CHECKS if c.id == case['id'])
    before = deepcopy((item, index))
    assert check.evaluate(item, index)[0] == 'UNKNOWN'
    assert (item, index) == before


@pytest.mark.parametrize('scenario,expected', [
    ('missing_state', 'PASS'), ('unspecified_state', 'PASS'), ('disabled_partial', 'UNKNOWN'),
    ('filtered_partial', 'UNKNOWN'), ('malformed_state', 'UNKNOWN'), ('denied_state', 'UNKNOWN'),
    ('foreign_host', 'UNKNOWN'), ('conflicting_targets', 'UNKNOWN'), ('foreign_project', 'FAIL'),
])
def test_flow_log_alternative_readability_and_partial_coverage(scenario, expected):
    case = batch.find('gcp.reviewed.network.flow_logs')
    def mutate(row, routes):
        config = {'name': batch.P + '/locations/global/vpcFlowLogsConfigs/logging', 'network': batch.NETWORK}
        if scenario == 'unspecified_state': config['state'] = 'STATE_UNSPECIFIED'
        elif scenario == 'disabled_partial': config['state'] = 'DISABLED'
        elif scenario == 'filtered_partial': config['filterExpr'] = 'src_ip == "10.0.0.1"'
        elif scenario == 'malformed_state': config['state'] = {'invalid': True}
        elif scenario == 'foreign_host': config['network'] = batch.NETWORK.replace('compute.googleapis.com', 'evil.invalid')
        elif scenario == 'conflicting_targets': config['subnet'] = batch.SUBNET
        elif scenario == 'foreign_project': config['network'] = batch.NETWORK.replace('p-one', 'p-two')
        routes[batch.FLOW]['data']['vpcFlowLogsConfigs'] = [config]
    denied = batch.FLOW + ':queryOrgVpcFlowLogsConfigs' if scenario.endswith('_partial') else None
    collected, transport = batch.capture(case, 'bad', mutate, denied_url=denied)
    if scenario == 'denied_state':
        config = next(c for c in collected['collections'] if c['type'] == 'vpc_flow_logs_config')['items'][0]
        config['_coverage'] = {'state': {'status': 'denied'}}
        collected.pop('snapshot_id', None)
    batch.verdict(case, 'fixed:flow_config:' + scenario, collected, transport, expected)


@pytest.mark.parametrize('login,two_factor,expected', [
    ('true', 'true', 'PASS'), ('false', 'true', 'FAIL'), ('true', 'false', 'FAIL'),
    ('false', 'false', 'FAIL'), (None, 'true', 'UNKNOWN'), (None, None, 'FAIL'),
    ('true', None, 'FAIL'), ('invalid', 'true', 'UNKNOWN'), ('true', 'invalid', 'UNKNOWN'),
])
def test_oslogin_and_2fa_flags_are_evaluated_together(login, two_factor, expected):
    case = batch.find('gcp.reviewed.project.os_login_2fa')
    def mutate(row, routes):
        fields = [('enable-oslogin', login), ('enable-oslogin-2fa', two_factor)]
        routes[batch.C]['data']['commonInstanceMetadata']['items'] = [{'key': key, 'value': value} for key, value in fields if value is not None]
    collected, transport = batch.capture(case, 'good', mutate)
    batch.verdict(case, 'fixed:2fa_flags:' + str((login, two_factor)), collected, transport, expected)


@pytest.mark.parametrize('enforce,expected', [(True, 'PASS'), (False, 'FAIL')])
def test_2fa_with_unset_login_needs_observed_effective_policy(enforce, expected):
    case = deepcopy(batch.find('gcp.reviewed.project.os_login_2fa'))
    case['dependencies'] = ['org_policy_effective']
    def mutate(row, routes):
        routes[batch.C]['data']['commonInstanceMetadata']['items'] = [{'key': 'enable-oslogin-2fa', 'value': 'true'}]
        policy = routes['https://orgpolicy.googleapis.com/v2/' + batch.P + '/policies/compute.requireOsLogin:getEffectivePolicy']['data']
        policy['spec']['rules'][0]['enforce'] = enforce
    collected, transport = batch.capture(case, 'good', mutate)
    batch.verdict(case, 'fixed:2fa_effective_policy:' + str(enforce), collected, transport, expected)


def test_selected_oslogin_2fa_plan_collects_its_effective_policy_dependency():
    from peaso.engine import plan_collection
    kinds = plan_collection({'connector': {'provider': 'gcp', 'scopes': ['projects/p-one']},
                             'checks': ['gcp.reviewed.project.os_login_2fa']})
    assert set(kinds) == {'project', 'org_policy_effective'}


@pytest.mark.parametrize('profile,minimum,observable', [
    ('COMPATIBLE', 'TLS_1_2', True), ('MODERN', 'TLS_1_0', True),
    ('MODERN', 'TLS_1_2', False), ('RESTRICTED', 'TLS_1_0', False),
    ('RESTRICTED', 'TLS_1_3', False), ('FIPS_202205', 'TLS_1_2', False),
    ('CUSTOM', 'TLS_1_2', False), ('CUSTOM', 'TLS_1_0', True),
])
def test_ssl_failure_copy_never_invents_weak_custom_ciphers(profile, minimum, observable):
    from peaso.checks.gcp_remaining_finding_summary import evidence_summary
    finding = {'provider': 'gcp', 'check_id': 'gcp.ports.compute_ssl_policy_strict_declaration',
               'status': 'FAIL', 'evidence': {'profile': profile, 'min_tls_version': minimum}}
    assert bool(evidence_summary(finding)) is observable
