"""Directed raw Graph membership traversal bounds for the CA group producer."""
from peaso.collectors import azure_conditional_access_native as native
from tests.test_peaso_azure_ca_group_membership_20261016 import (
    G1, G2, USER, DEVICE, KIND, Transport, collect, groups, policy, routes,
)


def members(*ids):
    return {'value': [{'id': rid, '@odata.type': '#microsoft.graph.user'
                       if rid != DEVICE else '#microsoft.graph.device'} for rid in ids]}


def test_per_group_cap_counts_nonusers_and_refuses_incomplete_row(monkeypatch):
    monkeypatch.setattr(native, 'MAX_MEMBERS_PER_GROUP', 2, raising=False)
    monkeypatch.setattr(native, 'MAX_TOTAL_GROUP_MEMBERS', 10, raising=False)
    third = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    api = Transport(routes(policies=[policy(excludes=[])], group1=members(USER, DEVICE, third)))
    got = groups(collect(api))
    assert len(got) == 1 and got[0]['status'] not in ('collected', 'empty')
    assert got[0]['items'] == []
    assert got[0]['error']['code'] == 'group_member_limit'


def test_exact_per_group_limit_accepts_complete_user_and_nonuser(monkeypatch):
    monkeypatch.setattr(native, 'MAX_MEMBERS_PER_GROUP', 2, raising=False)
    monkeypatch.setattr(native, 'MAX_TOTAL_GROUP_MEMBERS', 2, raising=False)
    api = Transport(routes(policies=[policy(excludes=[])], group1=members(USER, DEVICE)))
    got = groups(collect(api))
    assert len(got) == 1 and got[0]['status'] == 'collected'
    assert got[0]['items'][0]['user_ids'] == [USER]


def test_shared_total_cap_is_enforced_across_concurrent_groups(monkeypatch):
    monkeypatch.setattr(native, 'MAX_MEMBERS_PER_GROUP', 2, raising=False)
    monkeypatch.setattr(native, 'MAX_TOTAL_GROUP_MEMBERS', 2, raising=False)
    api = Transport(routes(group1=members(USER, DEVICE), group2=members(USER, DEVICE)))
    got = groups(collect(api))
    assert len(got) == 2
    assert sum(row['status'] == 'collected' for row in got) == 1
    assert sum(row.get('error', {}).get('code') == 'group_member_total_limit' for row in got) == 1
    assert sum(len(row['items'][0]['user_ids']) for row in got if row['items']) == 1


def test_no_group_inventory_request_still_makes_no_group_calls(monkeypatch):
    monkeypatch.setattr(native, 'MAX_MEMBERS_PER_GROUP', 0, raising=False)
    monkeypatch.setattr(native, 'MAX_TOTAL_GROUP_MEMBERS', 0, raising=False)
    api = Transport(routes())
    collect(api, wanted=['conditional_access_policy'])
    assert not any('/groups/' in call for call in api.calls)
