"""Geographic decisions bind current operator review to exact native configuration."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.collectors import azure_geo_consideration_native as native

TENANT = '22222222-2222-2222-2222-222222222222'
POLICY = '33333333-3333-3333-3333-333333333333'
LOCATION = '44444444-4444-4444-4444-444444444444'
SCOPE = '/tenants/' + TENANT


def case(decision='block'):
    def proof(endpoint):
        return {'endpoint': endpoint, 'read_only': True, 'tenant_verified': True, 'tenant_id': TENANT}
    rule = {'id': POLICY, 'state': 'enabled', 'conditions': {
        'users': {'includeUsers': ['All'], 'excludeUsers': []},
        'applications': {'includeApplications': ['All'], 'excludeApplications': []},
        'clientAppTypes': ['all'], 'locations': {'includeLocations': [LOCATION], 'excludeLocations': []}},
        'grantControls': {'operator': 'OR', 'builtInControls': ['block']},
        '_provenance': proof(native.POLICIES)}
    location = {'id': LOCATION, '@odata.type': '#microsoft.graph.countryNamedLocation',
        'countriesAndRegions': ['CN', 'RU'], '_provenance': proof(native.LOCATIONS)}
    config = {'userScope': 'all', 'requiredApplications': ['All'], 'requiredClientAppTypes': ['all'],
        'consideration': {'decision': decision, 'rationale': 'Reviewed business and regulatory requirements'}}
    if decision == 'block':
        config['consideration'].update(prohibitedCountries=['CN', 'RU'],
            reviewedPolicies=[{'policyId': POLICY, 'configurationSha256': native.policy_digest(rule)}],
            reviewedLocations=[{'locationId': LOCATION, 'configurationSha256': native.location_digest(location)}])
    now = datetime.now(timezone.utc)
    context = {'provider': 'azure', 'scope': SCOPE, 'created_at': now.isoformat(), 'metadata': {
        'compliance_policy': {'sw13': {'status': 'collected', 'scope': SCOPE,
            'authorized_by': 'risk-reviewer', 'document_id': 'geo-review',
            'observed_at': (now - timedelta(hours=1)).isoformat(),
            'expires_at': (now + timedelta(days=1)).isoformat(), 'checks': {native.KEY: config}}}}}
    return rule, location, config, context


@pytest.mark.parametrize('decision', ['block', 'noBlockRequired'])
def test_current_explicit_decision_has_supported_native_positive_path(decision):
    rule, location, config, context = case(decision)
    before = deepcopy((rule, location, config, context))
    result = native.native_result(rule, context, [rule], [location], config)
    assert result[0] == 'PASS' and result[1]['decision'] == decision
    assert (rule, location, config, context) == before


def test_native_policy_and_location_display_names_do_not_invalidate_semantic_approval():
    rule, location, config, context = case()
    rule['displayName'] = 'renamed rule'; location['displayName'] = 'renamed country group'
    assert native.native_result(rule, context, [rule], [location], config)[0] == 'PASS'


def test_reviewed_policies_can_cover_distinct_prohibited_countries():
    rule, location, config, context = case()
    other_rule, other_location = deepcopy(rule), deepcopy(location)
    other_rule['id'] = '55555555-5555-5555-5555-555555555555'
    other_location['id'] = '66666666-6666-6666-6666-666666666666'
    rule['conditions']['locations']['includeLocations'] = [LOCATION]
    location['countriesAndRegions'] = ['CN']; other_location['countriesAndRegions'] = ['RU']
    other_rule['conditions']['locations']['includeLocations'] = [other_location['id']]
    config['consideration']['reviewedPolicies'] = [{'policyId': row['id'], 'configurationSha256': native.policy_digest(row)}
        for row in (rule, other_rule)]
    config['consideration']['reviewedLocations'] = [{'locationId': row['id'], 'configurationSha256': native.location_digest(row)}
        for row in (location, other_location)]
    assert native.native_result(rule, context, [rule, other_rule], [location, other_location], config)[0] == 'PASS'


@pytest.mark.parametrize('mutation', ['changed_country', 'changed_rule', 'unverified', 'foreign_tenant',
    'expired', 'future', 'duplicate_policy', 'duplicate_location', 'missing_location',
    'ip_location', 'gps_approved', 'exclude_approved', 'unknown_condition_approved',
    'unknown_root_approved', 'report_only_approved', 'wrong_flow_approved', 'gap_approved'])
def test_stale_or_unmodeled_evidence_does_not_certify_a_country_block(mutation):
    rule, location, config, context = case()
    rules, locations = [rule], [location]
    review = context['metadata']['compliance_policy']['sw13']
    if mutation == 'changed_country': location['countriesAndRegions'] = ['CN']
    elif mutation == 'changed_rule': rule['state'] = 'disabled'
    elif mutation == 'unverified': rule['_provenance']['tenant_verified'] = False
    elif mutation == 'foreign_tenant': location['_provenance']['tenant_id'] = '77777777-7777-7777-7777-777777777777'
    elif mutation == 'expired': review['expires_at'] = review['observed_at']
    elif mutation == 'future': review['observed_at'] = review['expires_at']
    elif mutation == 'duplicate_policy': rules.append(deepcopy(rule))
    elif mutation == 'duplicate_location': locations.append(deepcopy(location))
    elif mutation == 'missing_location': locations = []
    elif mutation == 'ip_location': location['@odata.type'] = '#microsoft.graph.ipNamedLocation'
    elif mutation == 'gps_approved': location['countryLookupMethod'] = 'authenticatorAppGps'
    elif mutation == 'exclude_approved': rule['conditions']['users']['excludeUsers'] = ['77777777-7777-7777-7777-777777777777']
    elif mutation == 'unknown_condition_approved': rule['conditions']['futureConstraint'] = {'condition': True}
    elif mutation == 'unknown_root_approved': rule['futureEnforcementMode'] = {'subset': True}
    elif mutation == 'report_only_approved': rule['state'] = 'enabledForReportingButNotEnforced'
    elif mutation == 'wrong_flow_approved': rule['conditions']['authenticationFlows'] = {'transferMethods': 'deviceCodeFlow'}
    else: location['countriesAndRegions'] = ['CN']
    if mutation.endswith('_approved'):
        config['consideration']['reviewedPolicies'][0]['configurationSha256'] = native.policy_digest(rule)
        config['consideration']['reviewedLocations'][0]['configurationSha256'] = native.location_digest(location)
    assert native.native_result(rule, context, rules, locations, config) is None


@pytest.mark.parametrize('mutation', ['observed_outcome', 'scope_complete', 'bad_country', 'duplicate_country',
    'missing_rationale', 'extra_endpoint', 'bad_hash', 'wrong_user_scope', 'duplicate_binding'])
def test_normative_input_rejects_outcomes_and_ambiguous_review(mutation):
    _, _, config, _ = case()
    decision = config['consideration']
    if mutation == 'observed_outcome': decision['enforced'] = True
    elif mutation == 'scope_complete': decision['scopeComplete'] = True
    elif mutation == 'bad_country': decision['prohibitedCountries'] = ['China']
    elif mutation == 'duplicate_country': decision['prohibitedCountries'] = ['CN', 'CN']
    elif mutation == 'missing_rationale': decision.pop('rationale')
    elif mutation == 'extra_endpoint': config['endpoint'] = 'https://unreviewed.example'
    elif mutation == 'bad_hash': decision['reviewedPolicies'][0]['configurationSha256'] = 'invalid'
    elif mutation == 'wrong_user_scope': config['userScope'] = 'designated'
    else: decision['reviewedLocations'].append(deepcopy(decision['reviewedLocations'][0]))
    with pytest.raises(ValueError): native.validate_config(config)


@pytest.mark.parametrize('mode,expected', [('block', 'PASS'), ('no_block', 'PASS'),
    ('changed_country', 'UNKNOWN'), ('duplicate_location', 'UNKNOWN'), ('duplicate_policy', 'UNKNOWN'),
    ('denied_locations', 'UNKNOWN'), ('no_block_denied_locations', 'PASS')])
def test_public_hosted_native_country_review(monkeypatch, mode, expected):
    from types import SimpleNamespace
    from urllib.parse import urlsplit
    from peaso.collectors import azure, collect_live
    from peaso.engine import evaluate_snapshot, plan_collection
    from peaso.server.validation import validate_connector
    from tests.test_peaso_collectors_azurek8s import FakeAzure
    rule, location, config, context = case('noBlockRequired' if mode.startswith('no_block') else 'block')
    policy = deepcopy(context['metadata']['compliance_policy'])
    rule.pop('_provenance'); location.pop('_provenance')
    if mode == 'changed_country': location['countriesAndRegions'] = ['CN']
    calls = []
    def response(url, body, audience):
        assert body is None and audience == azure.GRAPH
        path = urlsplit(url).path
        calls.append(path)
        if path == native.POLICIES:
            return {'value': [deepcopy(rule)] * (2 if mode == 'duplicate_policy' else 1)}
        if path == native.LOCATIONS:
            if mode in {'denied_locations', 'no_block_denied_locations'}:
                raise azure.AzureReadError('fixture_location_denied', 403)
            return {'value': [deepcopy(location)] * (2 if mode == 'duplicate_location' else 1)}
        if path == '/v1.0/users':
            return {'value': [{'id': '77777777-7777-7777-7777-777777777777', 'accountEnabled': True}]}
        if path == '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy':
            return {'id': '88888888-8888-8888-8888-888888888888', 'isEnabled': False}
        assert path == '/v1.0/policies/authenticationStrengthPolicies'
        return {'value': []}
    transport = FakeAzure(response); transport.tenant = transport.verified_tenant = TENANT
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda connector, kinds: original(connector, kinds, transport=transport))
    auth = {'method': 'token', 'arm_token': 'inert', 'graph_token': 'inert'}
    options = {'retries': 1, 'compliance_policy': policy}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'azure', 'scopes': ['/subscriptions/11111111-1111-1111-1111-111111111111'],
                 'auth': auth, 'options': options}
    selected = plan_collection({'connector': connector, 'checks': [native.CID]})
    snapshot = collect_live(connector, selected)
    results = evaluate_snapshot(snapshot, checks=[native.CID])['findings']
    assert results and {row['status'] for row in results} == {expected}, results
    assert all(row['scope'] == SCOPE for row in results)
    assert calls and set(calls) <= {native.POLICIES, native.LOCATIONS, '/v1.0/users',
        '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy', '/v1.0/policies/authenticationStrengthPolicies'}
    assert all(not c['items'] and c['status'] == 'not_collected' for c in snapshot['collections']
        if c['type'] in {'azure_compliance_review', 'conditional_access_principal', 'conditional_access_partition'})
    if mode.startswith('duplicate_'):
        kind = 'named_location' if mode == 'duplicate_location' else 'conditional_access_policy'
        source = next(c for c in snapshot['collections'] if c['type'] == kind)
        assert source['status'] == 'partial'


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('decision', ['block', 'noBlockRequired'])
def test_typed_hosted_and_local_geographic_review_intake(mode, decision):
    from types import SimpleNamespace
    from peaso.server.validation import validate_connector
    _, _, _, context = case(decision)
    policy = deepcopy(context['metadata']['compliance_policy'])
    before = deepcopy(policy)
    validate_connector('azure', {'method': 'token', 'arm_token': 'inert'},
        {'compliance_policy': policy}, SimpleNamespace(auth_mode=mode))
    assert policy == before


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('field,value', [('enforced', True), ('scopeComplete', True), ('outcome', 'PASS')])
def test_observed_country_results_cannot_be_supplied_as_normative_approval(mode, field, value):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from peaso.server.validation import validate_connector
    _, _, config, context = case()
    config['consideration'][field] = value
    with pytest.raises(HTTPException) as error:
        validate_connector('azure', {'method': 'token', 'arm_token': 'inert'},
            {'compliance_policy': context['metadata']['compliance_policy']}, SimpleNamespace(auth_mode=mode))
    assert error.value.status_code == 422


@pytest.mark.parametrize('native_review', [False, True])
def test_existing_local_legacy_device_criteria_can_coexist_with_native_geographic_review(native_review):
    from types import SimpleNamespace
    from peaso.server.validation import validate_connector
    _, _, _, context = case()
    review = deepcopy(context['metadata']['compliance_policy']['sw13'])
    if not native_review: review['checks'] = {}
    review['checks']['azure|cis|exclusionary_device_code_flow_policy_considered'] = {
        'userScope': 'all', 'requiredApplications': ['All'], 'requiredClientAppTypes': ['all']}
    validate_connector('azure', {'method': 'token', 'arm_token': 'inert'},
        {'compliance_policy': {'sw13': review}}, SimpleNamespace(auth_mode='local'))
