"""Actual risk-policy metadata and per-user P2 entitlement through native routes."""
import copy
from urllib.parse import urlsplit, parse_qs

from peaso.collectors import azure
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate
import tests.test_peaso_mfa_native_group_consumer as group_fixtures
from tests.test_peaso_mfa_native_group_consumer import GroupsAPI, P1, P2, G1, group_row
from tests.test_peaso_mfa_native_direct_user_partitions import U1, U2, DISABLED, CHECKS, row

RISK = 'azure.cis.multifactor_authentication_risky_sign_ins'
KIND = 'conditional_access_risk_entitlement'
P2_PLAN = 'eec0eb4f-6444-4f95-aba0-50c24d67f998'
SKU = 'eeeeeeee-aaaa-bbbb-cccc-123456789012'


def risk_row(pid=P1, levels=('medium', 'high'), include=('All',), **changes):
    pid, value = row(pid, list(include), **changes)
    value['conditions']['signInRiskLevels'] = list(levels)
    return pid, value


class RiskAPI(GroupsAPI):
    def __init__(self, rows, mode='complete', groups=None):
        super().__init__(rows, groups=groups)
        self.license_mode = mode

    def request(self, url, *, body=None, audience=azure.ARM):
        path, query = urlsplit(url).path, parse_qs(urlsplit(url).query)
        assigned = path == '/v1.0/users' and 'assignedPlans' in query.get('$select', [''])[0]
        if assigned or path == '/v1.0/subscribedSkus':
            self.calls.append((url, audience, body))
            mode = self.license_mode
            if mode == 'denied' or (mode == 'partial' and '$skiptoken' in query):
                raise azure.AzureReadError('inert_license_read_denied', 403)
            if not assigned:
                return {'value': [{'id': 'sku-row', 'skuId': SKU, 'appliesTo': 'User',
                    'capabilityStatus': 'Suspended' if mode == 'sku-suspended' else 'Enabled',
                    'servicePlans': [{'servicePlanId': P2_PLAN, 'servicePlanName': 'AAD_PREMIUM_P2',
                                      'provisioningStatus': 'Success'}]}]}
            users = []
            for uid, enabled in [(U1, True), (U2, True), (DISABLED, False)]:
                plans = [{'servicePlanId': P2_PLAN,
                          'capabilityStatus': 'Suspended' if mode == 'user-suspended' and uid == U2 else 'Enabled'}]
                if not enabled or mode == 'sku-only' or (mode == 'only-u2' and uid == U1) or (mode == 'unassigned-u2' and uid == U2):
                    plans = []
                users.append({'id': uid, 'accountEnabled': enabled, 'assignedPlans': plans})
            result = {'value': users}
            if mode == 'partial':
                result['@odata.nextLink'] = azure.GRAPH + '/v1.0/users?$select=id,accountEnabled,assignedPlans&$skiptoken=next'
            return result
        return super().request(url, body=body, audience=audience)


def collected(monkeypatch, rows, mode='complete', groups=None):
    api = RiskAPI(rows, mode, groups)
    monkeypatch.setattr(group_fixtures, 'GroupsAPI', lambda *args, **kwargs: api)
    snap, _ = group_fixtures.collected(monkeypatch, rows, groups=groups)
    assert all(body is None for url, audience, body in api.calls)
    return snap, api


def assert_risk(snap, expected='PASS', ordinary='UNKNOWN'):
    report = evaluate_snapshot(snap, checks=CHECKS, include_not_applicable=True)
    actual = {cid: {f['status'] for f in report['findings'] if f['check_id'] == cid} for cid in CHECKS}
    assert actual == {cid: {expected if cid == RISK else ordinary} for cid in CHECKS}, actual
    if expected == 'PASS':
        import json
        for finding in report['findings']:
            if finding['check_id'] == RISK:
                text = json.dumps(finding['evidence'])
                assert U1 not in text and U2 not in text and DISABLED not in text


def test_native_medium_high_mfa_with_per_user_p2_entitlement(monkeypatch):
    snap, api = collected(monkeypatch, [risk_row()])
    assert_risk(snap)
    assert any('/subscribedSkus' in url for url, _, _ in api.calls)
    from peaso.checks import CHECKS as registered
    lookup = {c.id: c for c in registered}
    assert KIND in lookup[RISK].dependencies
    assert all(KIND not in lookup[cid].dependencies for cid in CHECKS if cid != RISK)


def test_separate_medium_high_policies_both_cover_native_universe(monkeypatch):
    snap, _ = collected(monkeypatch, [risk_row(P1, ['medium']), risk_row(P2, ['high'])])
    assert_risk(snap)


def test_unconditional_group_user_needs_no_p2_when_risk_user_is_licensed(monkeypatch):
    snap, _ = collected(monkeypatch, [group_row(P1, include=[G1]), risk_row(P2, include=[U2])],
                        mode='only-u2', groups={G1: [U1]})
    assert_risk(snap)


def test_missing_high_risk_coverage_stays_unknown(monkeypatch):
    snap, _ = collected(monkeypatch, [risk_row(levels=['medium'])])
    assert_risk(snap, 'UNKNOWN')


def test_denied_partial_or_missing_entitlement_cannot_prove_coverage(monkeypatch):
    for mode in ('denied', 'partial', 'missing'):
        snap, _ = collected(monkeypatch, [risk_row()], mode='complete' if mode == 'missing' else mode)
        if mode == 'missing':
            snap['collections'] = [e for e in snap['collections'] if e['type'] != KIND]
            snap.pop('snapshot_id'); snap = validate(snap)
        assert_risk(snap, 'UNKNOWN')


def test_tenant_sku_pool_or_unassigned_suspended_user_is_not_p2_entitlement(monkeypatch):
    for mode in ('sku-only', 'unassigned-u2', 'user-suspended', 'sku-suspended'):
        snap, _ = collected(monkeypatch, [risk_row()], mode=mode)
        assert_risk(snap, 'UNKNOWN')


def test_entitlement_foreign_capture_userstate_and_plan_consistency_fail_closed(monkeypatch):
    for change in ('foreign', 'capture', 'customer', 'user-state', 'duplicate', 'inactive-p2', 'unknown-p2', 'endpoint'):
        snap, _ = collected(monkeypatch, [risk_row()])
        env = next(e for e in snap['collections'] if e['type'] == KIND)
        user = env['items'][0]
        if change == 'foreign': user['_provenance']['tenant_id'] = U1
        elif change == 'capture': env['_provenance']['credential_context_id'] = 'earlier-capture'
        elif change == 'customer': user['_provenance']['customer_context_id'] = 'another-customer'
        elif change == 'user-state': user['account_enabled'] = not user['account_enabled']
        elif change == 'duplicate': env['items'].append(copy.deepcopy(user))
        elif change == 'inactive-p2': user['active_service_plan_ids'] = []
        elif change == 'unknown-p2':
            user['active_service_plan_ids'] = [SKU]; user['risk_p2_service_plan_ids'] = [SKU]
        else: user['_provenance']['skus_endpoint'] = '/v1.0/other'
        snap.pop('snapshot_id'); assert_risk(validate(snap), 'UNKNOWN')


def test_risk_mfa_or_device_bypass_is_not_enforced_mfa(monkeypatch):
    controls = {'operator': 'OR', 'builtInControls': ['mfa', 'compliantDevice'],
        'authenticationStrength': None, 'customAuthenticationFactors': [], 'termsOfUse': []}
    snap, _ = collected(monkeypatch, [risk_row(grantControls=controls)])
    assert_risk(snap, 'UNKNOWN')


def test_unknown_risk_and_other_restrictions_never_prove_both_risk_states(monkeypatch):
    variants = [risk_row(levels=['medium', 'high', 'futureRisk'])]
    for key, value in [('userRiskLevels', ['high']), ('platforms', {'includePlatforms': ['windows']}),
                       ('authenticationFlows', {'transferMethods': 'deviceCodeFlow'})]:
        pid, value_row = risk_row(); value_row['conditions'][key] = value; variants.append((pid, value_row))
    for variant in variants:
        snap, _ = collected(monkeypatch, [variant]); assert_risk(snap, 'UNKNOWN')


def test_independent_unconditional_all_rule_ignores_unavailable_license_source(monkeypatch):
    snap, _ = collected(monkeypatch, [risk_row(P1), row(P2, ['All'])], mode='denied')
    assert_risk(snap, 'PASS', ordinary='PASS')
