"""Caller-only CIDR regression through native API response, collector and engine."""
from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.engine import evaluate_snapshot
from tests.test_gcp_metadata_final_batch_review_20261020 import (
    BASE, merge, native, forbid_network_auth,
)

CID = 'gcp.ports.iam_api_key_restricts_websites_hosts_apps'
CHECK = next(check for check in CHECKS if check.id == CID)
IP_CASES = [
    ('expanded-ipv6-universal', ['0:0:0:0:0:0:0:0/0'], 'FAIL'),
    ('compressed-ipv6-universal', ['::/0'], 'FAIL'),
    ('ipv6-hostbits-universal', ['2001:db8::1/0'], 'FAIL'),
    ('ipv4-universal', ['0.0.0.0/0'], 'FAIL'),
    ('ipv4-hostbits-universal', ['192.0.2.1/0'], 'FAIL'),
    ('ipv6-subnet', ['2001:db8::/64'], 'PASS'),
    ('expanded-ipv6-subnet', ['2001:0db8:0000:0000:0000:0000:0000:0000/64'], 'PASS'),
    ('ipv6-single-address', ['2001:db8::7'], 'PASS'),
    ('ipv4-subnet', ['192.0.2.0/24'], 'PASS'),
    ('ipv4-single-address', ['192.0.2.1'], 'PASS'),
    ('mixed-restricted-families', ['192.0.2.0/24', '2001:db8::/64'], 'PASS'),
    ('mixed-universal-last', ['192.0.2.0/24', '0:0:0:0:0:0:0:0/0'], 'FAIL'),
    ('mixed-universal-first', ['0:0:0:0:0:0:0:0/0', '2001:db8::/64'], 'FAIL'),
    ('native-empty-list', [], 'FAIL'),
    ('null-list', None, 'UNKNOWN'),
    ('scalar-not-list', '2001:db8::/64', 'UNKNOWN'),
    ('bad-ip', ['not-an-ip'], 'UNKNOWN'),
    ('ip-hostname', ['server.example.com'], 'UNKNOWN'),
    ('bad-ipv6-prefix', ['2001:db8::/129'], 'UNKNOWN'),
    ('bad-ipv4-prefix', ['192.0.2.1/33'], 'UNKNOWN'),
    ('invalid-entry-object', [{'cidr': '::/0'}], 'UNKNOWN'),
    ('invalid-entry-integer', [1], 'UNKNOWN'),
    ('mixed-valid-invalid', ['2001:db8::/64', 'bad'], 'UNKNOWN'),
    ('mixed-universal-invalid', ['::/0', 'bad'], 'UNKNOWN'),
    ('mixed-invalid-universal', ['bad', '::/0'], 'UNKNOWN'),
    ('legacy-bare-zero-ipv4', ['0.0.0.0'], 'FAIL'),
    ('legacy-bare-zero-ipv6', ['::0'], 'FAIL'),
]


def observe(restrictions=None, *, denied=False, partial=False, omitted=False):
    item = deepcopy(BASE['api_key'])
    if not omitted: item['restrictions'] = deepcopy(restrictions)
    before = deepcopy(item)
    captured, api = native('api_key', item, denied=denied, partial=partial)
    assert item == before
    frozen = deepcopy(captured)
    rows = evaluate_snapshot(captured, checks=[CID])['findings']
    assert captured == frozen
    resource_rows = [row for row in rows if 'native_resource_id' in row]
    return captured, api, resource_rows, rows


@pytest.mark.parametrize('label,allowed,expected', IP_CASES, ids=[row[0] for row in IP_CASES])
def test_native_server_caller_prefix(label, allowed, expected):
    restrictions = {'serverKeyRestrictions': {'allowedIps': allowed}}
    captured, api, resources, rows = observe(restrictions)
    assert len(resources) == 1 and resources[0]['status'] == expected, rows
    assert captured['collections'][0]['items'][0]['restrictions'] == restrictions
    assert len(api.requests) == 1
    request = api.requests[0]
    assert request['params']['fields'] == 'keys(name,uid,displayName,createTime,updateTime,deleteTime,restrictions),nextPageToken'
    assert 'keyString' not in request['params']['fields']


@pytest.mark.parametrize('label,allowed,expected', IP_CASES, ids=[row[0] for row in IP_CASES])
def test_direct_typed_caller_grammar(label, allowed, expected):
    item = {'restrictions': {'serverKeyRestrictions': {'allowedIps': deepcopy(allowed)}}}
    before = deepcopy(item)
    status, evidence = CHECK.evaluate(item, {})
    assert status == expected, evidence
    assert item == before


@pytest.mark.parametrize('fragment', [
    {}, {'restrictions': None}, {'restrictions': {'serverKeyRestrictions': None}},
    {'restrictions': {'serverKeyRestrictions': {}}},
    {'restrictions': {'serverKeyRestrictions': {'allowedIps': ['2001:db8::/64'], '_coverage': {'allowedIps': {'status': 'denied'}}}}},
    {'restrictions': {'serverKeyRestrictions': {'allowedIps': ['2001:db8::/64']}, '_coverage': {'serverKeyRestrictions': {'status': 'denied'}}}},
    {'restrictions': {'serverKeyRestrictions': {'allowedIps': ['2001:db8::/64']}}, '_coverage': {'restrictions': {'status': 'denied'}}},
])
def test_unproven_missing_or_denied_fields_are_unknown(fragment):
    assert CHECK.evaluate(deepcopy(fragment), {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('scenario', ['denied', 'omitted-restrictions', 'denied-ips', 'denied-mode', 'partial'])
def test_native_denial_omission_and_partial_coverage(scenario):
    restrictions = {'serverKeyRestrictions': {'allowedIps': ['2001:db8::/64']}}
    if scenario == 'denied-ips': restrictions['serverKeyRestrictions']['_coverage'] = {'allowedIps': {'status': 'denied'}}
    if scenario == 'denied-mode': restrictions['_coverage'] = {'serverKeyRestrictions': {'status': 'denied'}}
    captured, api, resources, rows = observe(restrictions, denied=scenario == 'denied', partial=scenario == 'partial', omitted=scenario == 'omitted-restrictions')
    if scenario == 'denied': assert not resources and [row['status'] for row in rows] == ['DENIED']
    elif scenario == 'partial':
        assert resources[0]['status'] == 'PASS'
        assert any(row['status'] == 'UNKNOWN' and row['evidence'].get('collection_status') == 'partial' for row in rows)
    else: assert len(resources) == 1 and resources[0]['status'] == 'UNKNOWN', rows


def test_native_known_omitted_repeated_list_is_empty_not_unread():
    captured, api, resources, rows = observe({'serverKeyRestrictions': {}})
    body = captured['collections'][0]['items'][0]['restrictions']['serverKeyRestrictions']
    assert body['allowedIps'] == [] and body['_coverage']['allowedIps']['status'] == 'empty'
    assert resources[0]['status'] == 'FAIL'


@pytest.mark.parametrize('restrictions,expected', [
    ({'browserKeyRestrictions': {'allowedReferrers': ['example.com/*']}}, 'PASS'),
    ({'browserKeyRestrictions': {'allowedReferrers': ['*']}}, 'FAIL'),
    ({'browserKeyRestrictions': {'allowedReferrers': []}}, 'FAIL'),
    ({'androidKeyRestrictions': {'allowedApplications': [{'packageName': 'com.example.app', 'sha1Fingerprint': '00' * 20}]}}, 'PASS'),
    ({'androidKeyRestrictions': {'allowedApplications': []}}, 'FAIL'),
    ({'iosKeyRestrictions': {'allowedBundleIds': ['com.example.app']}}, 'PASS'),
    ({'iosKeyRestrictions': {'allowedBundleIds': []}}, 'FAIL'),
    ({'apiTargets': [{'service': 'storage.googleapis.com'}]}, 'FAIL'),
])
def test_nonserver_semantics_are_preserved(restrictions, expected):
    captured, api, resources, rows = observe(restrictions)
    assert resources[0]['status'] == expected, rows
    assert captured['collections'][0]['items'][0]['restrictions'] == restrictions
