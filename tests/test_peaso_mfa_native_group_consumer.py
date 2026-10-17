"""Opt-in group membership through hosted plan, Graph stub, snapshot and engine."""
import copy
from urllib.parse import urlsplit, parse_qs

from peaso.collectors import azure, collect_live
from peaso.engine import plan_collection
from peaso.snapshot import validate
from tests.test_peaso_mfa_native_direct_user_partitions import (
    PartitionAPI, U1, U2, collect as direct_collect, assert_status, selector, row, CHECKS)

GROUP_KIND = 'conditional_access_group_membership'
G1 = '11111111-aaaa-bbbb-cccc-111111111111'
G2 = '22222222-aaaa-bbbb-cccc-222222222222'
P1 = '11111111-dddd-eeee-ffff-111111111111'
P2 = '22222222-dddd-eeee-ffff-222222222222'
TENANT = '22222222-2222-2222-2222-222222222222'


def group_row(pid, include=(), exclude=(), direct=(), exclude_direct=()):
    conditions = selector(list(direct), exclude_direct)
    conditions['users']['includeGroups'] = list(include)
    conditions['users']['excludeGroups'] = list(exclude)
    return pid, {'conditions': conditions}


class GroupsAPI(PartitionAPI):
    def __init__(self, rows, groups=None, failures=None, metadata_mode=None):
        super().__init__(rows)
        self.groups = groups or {}
        self.failures = failures or {}
        self.metadata_mode = metadata_mode or {}

    def request(self, url, *, body=None, audience=azure.ARM):
        path = urlsplit(url).path
        if path.startswith('/v1.0/groups/'):
            self.calls.append((url, audience, body))
            gid = path.split('/')[3]
            failure = self.failures.get(gid)
            if failure == 'missing' or failure == 'denied':
                raise azure.AzureReadError('inert_group_unavailable', 404 if failure == 'missing' else 403)
            if path.endswith('/transitiveMembers'):
                if failure == 'partial' and '$skiptoken' in parse_qs(urlsplit(url).query):
                    raise azure.AzureReadError('inert_second_page_denied', 403)
                members = self.groups.get(gid, [])
                result = {'value': [dict(member) if isinstance(member, dict) else
                    {'id': member, '@odata.type': '#microsoft.graph.user'} for member in members]}
                if failure == 'partial':
                    result['@odata.nextLink'] = azure.GRAPH + path + '?$skiptoken=next'
                return result
            mode = self.metadata_mode.get(gid)
            return {'id': gid, 'visibility': 'HiddenMembership' if mode == 'hidden' else 'Private',
                'groupTypes': ['DynamicMembership'] if mode == 'dynamic' else [],
                'membershipRuleProcessingState': 'On'}
        return super().request(url, body=body, audience=audience)


def collected(monkeypatch, rows, groups=None, failures=None, metadata_mode=None):
    api = GroupsAPI(rows, groups, failures, metadata_mode)
    # Reuse the approved owner obligation and actual hosted collection helper,
    # replacing only its inert HTTP transport factory, not collection/evaluation.
    import tests.test_peaso_mfa_native_direct_user_partitions as fixtures
    monkeypatch.setattr(fixtures, 'PartitionAPI', lambda unused_rows, unused_mode: api)
    snap = direct_collect(monkeypatch, rows)
    assert all(body is None for url, audience, body in api.calls)
    return snap, api


def group_calls(api):
    return [url for url, audience, body in api.calls if '/v1.0/groups/' in url]


def test_complete_native_transitive_group_covers_enabled_user_universe(monkeypatch):
    snap, api = collected(monkeypatch, [group_row(P1, include=[G1])], {G1: [U1, U2]})
    assert_status(snap, 'PASS', [P1])
    assert GROUP_KIND in snap['metadata']['requested_types'] if 'requested_types' in snap['metadata'] else any(
        env['type'] == GROUP_KIND for env in snap['collections'])
    assert any('/' + G1 + '/transitiveMembers' in url for url in group_calls(api))


def test_native_group_and_direct_user_policy_union_cover_universe(monkeypatch):
    rows = [group_row(P1, include=[G1]), row(P2, [U2])]
    snap, api = collected(monkeypatch, rows, {G1: [U1]})
    assert_status(snap, 'PASS', [P1, P2])
    assert len(group_calls(api)) == 2


def test_excluded_native_group_is_recovered_by_second_mfa_rule(monkeypatch):
    rows = [group_row(P1, exclude=[G2], direct=['All']), group_row(P2, include=[G2])]
    snap, api = collected(monkeypatch, rows, {G2: [U2]})
    assert_status(snap, 'PASS', [P1, P2])
    assert len(group_calls(api)) == 2


def test_excluded_group_without_other_mfa_evidence_leaves_unknown_gap(monkeypatch):
    snap, _ = collected(monkeypatch, [group_row(P1, exclude=[G2], direct=['All'])], {G2: [U2]})
    assert_status(snap, 'UNKNOWN')


def test_unavailable_exclusion_group_is_never_treated_as_empty(monkeypatch):
    for failure in ('denied', 'partial', 'missing'):
        snap, _ = collected(monkeypatch, [group_row(P1, exclude=[G2], direct=['All'])],
            {G2: [U2]}, {G2: failure})
        assert_status(snap, 'UNKNOWN')


def test_duplicate_foreign_or_wrong_binding_group_evidence_is_unknown(monkeypatch):
    for mutation in ('duplicate', 'foreign', 'endpoint', 'requested-group', 'scope'):
        snap, _ = collected(monkeypatch, [group_row(P1, include=[G1])], {G1: [U1, U2]})
        env = next(e for e in snap['collections'] if e['type'] == GROUP_KIND)
        member = env['items'][0]
        if mutation == 'duplicate': env['items'].append(copy.deepcopy(member))
        elif mutation == 'foreign': member['_provenance']['tenant_id'] = U1
        elif mutation == 'endpoint': member['_provenance']['endpoint'] = '/v1.0/groups/'+G2+'/transitiveMembers'
        elif mutation == 'requested-group': member['_provenance']['requested_group_id'] = G2
        else: env['scope'] = '/tenants/'+TENANT+'/groups/'+G2
        snap.pop('snapshot_id')
        assert_status(validate(snap), 'UNKNOWN')


def test_nonuser_transitive_members_cannot_cover_enabled_directory_user(monkeypatch):
    nonuser = {'id': U2, '@odata.type': '#microsoft.graph.group'}
    snap, _ = collected(monkeypatch, [group_row(P1, include=[G1])], {G1: [U1, nonuser]})
    assert_status(snap, 'UNKNOWN')


def test_hidden_or_dynamic_group_remains_unavailable_without_member_calls(monkeypatch):
    for mode in ('hidden', 'dynamic'):
        snap, api = collected(monkeypatch, [group_row(P1, include=[G1])],
            {G1: [U1, U2]}, metadata_mode={G1: mode})
        assert_status(snap, 'UNKNOWN')
        assert all('/transitiveMembers' not in url for url in group_calls(api))


def test_direct_user_rules_have_no_group_http_calls_and_no_device_geo_dependency(monkeypatch):
    from peaso.checks import CHECKS as registered
    rows = [row(P1, [U1]), row(P2, [U2])]
    snap, api = collected(monkeypatch, rows)
    assert_status(snap, 'PASS', [P1, P2])
    assert group_calls(api) == []
    lookup = {c.id: c for c in registered}
    assert all(GROUP_KIND in lookup[cid].dependencies for cid in CHECKS)
    for cid in ('azure.cis.exclusionary_device_code_flow_policy_considered',
                'azure.cis.exclusionary_geographic_access_policy_considered'):
        assert GROUP_KIND not in lookup[cid].dependencies


def test_independent_all_users_proof_ignores_unavailable_unrelated_group(monkeypatch):
    rows = [group_row(P1, include=[G1]), row(P2, ['All'])]
    snap, _ = collected(monkeypatch, rows, failures={G1: 'denied'})
    assert_status(snap, 'PASS')


def test_complete_independent_group_proof_survives_unrelated_group_denial(monkeypatch):
    rows = [group_row(P1, include=[G1]), group_row(P2, include=[G2])]
    snap, _ = collected(monkeypatch, rows, {G1: [U1, U2]}, failures={G2: 'denied'})
    assert_status(snap, 'PASS', [P1])
