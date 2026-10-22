"""AppStream DescribeFleets optional fields through SDK, collection and engine."""
from __future__ import annotations

from copy import deepcopy

import boto3
import pytest
from botocore.exceptions import EndpointConnectionError
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = f'{ACCOUNT}/{REGION}'
ARN = f'arn:aws:appstream:{REGION}:{ACCOUNT}:fleet/sample'
CHECKS = (
    'aws.c2b.appstream.no_default_internet',
    'aws.c2b.appstream.max_user_duration_under_10h',
    'aws.c2b.appstream.disconnect_timeout_5m',
    'aws.c2b.appstream.idle_disconnect_10m',
)


def collect(monkeypatch, **fields):
    session = boto3.Session(aws_access_key_id='INERT', aws_secret_access_key='INERT', region_name=REGION)
    sts, appstream = session.client('sts'), session.client('appstream')
    fleet = {'Arn': ARN, 'Name': 'sample', 'InstanceType': 'stream.standard.small',
             'ComputeCapacityStatus': {'Desired': 1}, 'State': 'RUNNING', **fields}
    with Stubber(sts) as sts_stub, Stubber(appstream) as stream_stub:
        sts_stub.add_response('get_caller_identity', {'Account': ACCOUNT,
            'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'AIDAREVIEWER'}, {})
        stream_stub.add_response('describe_fleets', {'Fleets': [fleet]}, {})
        clients = {('sts', REGION): sts, ('appstream', REGION): appstream}
        monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture'))
        monkeypatch.setattr(aws.Requests, 'client',
            lambda self, _session, service, region: clients[(service, region)])
        snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
            'auth': {'profile': 'fixture'}, 'options': {'regions': [REGION],
            'service_concurrency': 1, 'scope_concurrency': 1}}, ['appstream_fleet'])
        sts_stub.assert_no_pending_responses()
        stream_stub.assert_no_pending_responses()
    return snapshot


def fleet_collection(snapshot):
    rows = [c for c in snapshot['collections'] if c['type'] == 'appstream_fleet' and c['scope'] == SCOPE]
    assert len(rows) == 1
    return rows[0]


def statuses(snapshot):
    findings = evaluate_snapshot(snapshot, checks=list(CHECKS))['findings']
    return {finding['check_id']: finding['status'] for finding in findings
            if finding['check_id'] in CHECKS and finding.get('native_resource_id') == ARN}


def test_sdk_omissions_do_not_create_internet_pass(monkeypatch):
    snapshot = collect(monkeypatch)
    inventory = fleet_collection(snapshot)
    assert inventory['status'] == 'collected' and len(inventory['items']) == 1
    assert 'EnableDefaultInternetAccess' not in inventory['items'][0]
    assert statuses(snapshot) == {
        CHECKS[0]: 'UNKNOWN', CHECKS[1]: 'UNKNOWN',
        CHECKS[2]: 'UNKNOWN', CHECKS[3]: 'FAIL',
    }


def test_explicit_fleet_settings(monkeypatch):
    safe = collect(monkeypatch, EnableDefaultInternetAccess=False,
        MaxUserDurationInSeconds=35999, DisconnectTimeoutInSeconds=300,
        IdleDisconnectTimeoutInSeconds=600)
    assert statuses(safe) == dict.fromkeys(CHECKS, 'PASS')
    unsafe = collect(monkeypatch, EnableDefaultInternetAccess=True,
        MaxUserDurationInSeconds=36000, DisconnectTimeoutInSeconds=301,
        IdleDisconnectTimeoutInSeconds=0)
    assert statuses(unsafe) == dict.fromkeys(CHECKS, 'FAIL')


def test_partial_inventory_does_not_turn_omission_into_pass(monkeypatch):
    snapshot = collect(monkeypatch)
    partial = deepcopy(snapshot)
    fleet_collection(partial)['status'] = 'partial'
    partial.pop('snapshot_id', None)
    assert statuses(partial) == {
        CHECKS[0]: 'UNKNOWN', CHECKS[1]: 'UNKNOWN',
        CHECKS[2]: 'UNKNOWN', CHECKS[3]: 'FAIL',
    }


@pytest.mark.parametrize('region', ['us-west-1', 'eu-north-1'])
def test_unsupported_region_is_not_applicable(monkeypatch, region):
    session = boto3.Session(aws_access_key_id='INERT', aws_secret_access_key='INERT',
                            region_name=region)
    assert region not in session.get_available_regions('appstream')
    sts = session.client('sts', region_name=region)
    appstream = session.client('appstream', region_name=region)
    calls = []
    with Stubber(sts) as stub:
        stub.add_response('get_caller_identity', {'Account': ACCOUNT,
            'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'AIDAREVIEWER'}, {})
        monkeypatch.setattr(aws, '_session', lambda auth, requested_region: (session, 'fixture'))
        def client(self, _session, service, requested_region):
            calls.append((service, requested_region))
            assert requested_region == region
            if service == 'sts':
                return sts
            assert service == 'appstream'
            class Unsupported:
                def __getattr__(self, name):
                    return getattr(appstream, name)
                def describe_fleets(self, **kwargs):
                    calls.append(('describe_fleets', region))
                    raise EndpointConnectionError(endpoint_url=f'https://appstream.{region}.amazonaws.com')
            return Unsupported()
        monkeypatch.setattr(aws.Requests, 'client', client)
        snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
            'auth': {'profile': 'fixture'}, 'options': {'regions': [region],
            'service_concurrency': 1, 'scope_concurrency': 1}}, ['appstream_fleet'])
        stub.assert_no_pending_responses()
    rows = [c for c in snapshot['collections'] if c['type'] == 'appstream_fleet'
            and c['scope'] == f'{ACCOUNT}/{region}']
    assert len(rows) == 1
    assert rows[0]['status'] == 'not_collected' and rows[0]['items'] == [], (rows, calls)
    assert ('describe_fleets', region) in calls
    assert rows[0]['error']['code'] == 'unsupported_region_service'
    findings = evaluate_snapshot(snapshot, checks=list(CHECKS))['findings']
    inventory = [f for f in findings if f['check_id'] in CHECKS
                 and f['resource_id'] == 'inventory:appstream_fleet']
    assert {f['check_id']: f['status'] for f in inventory} == dict.fromkeys(CHECKS, 'NOT_APPLICABLE')
    assert all(f['evidence']['reason'] == 'service is unavailable in this AWS Region'
               for f in inventory)
