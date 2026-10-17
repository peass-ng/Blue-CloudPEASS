"""SDK-shaped WAF IP set reads and end-to-end compliance decisions."""
import copy
import json
import pytest
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT
from peaso.collectors import aws, aws_bulk_inventory as facts
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGION = 'eu-west-1'
UUID = '12345678-1234-1234-1234-123456789012'
CHECK = 'aws_wafv2_global_allow_block_lists'


def ipset(name='allow', scope='REGIONAL', region=REGION):
    prefix = 'regional' if scope == 'REGIONAL' else 'global'
    return {'Name': name, 'Id': UUID,
            'ARN': f'arn:aws:wafv2:{region}:{ACCOUNT}:{prefix}/ipset/{name}/{UUID}',
            'IPAddressVersion': 'IPV4', 'Addresses': ['192.0.2.0/24'],
            'Description': 'private-description-marker'}


def summary(row):
    return {key: row[key] for key in ('Name', 'Id', 'ARN', 'Description')}


def decision(read, expected_priority=2, metadata=True, through_connector=False):
    scope = ACCOUNT + '/' + REGION
    acl_arn = f'arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/qa/{UUID}'
    rules = [{'Name': name, 'Priority': priority, 'Action': {action: {}},
              'Statement': {'IPSetReferenceStatement': {'ARN': ipset(name)['ARN']}}}
             for name, priority, action in [('allow', 1, 'Allow'), ('block', expected_priority, 'Block')]]
    acl = {'ARN': acl_arn, 'Id': UUID, 'Scope': 'REGIONAL',
           'WebACL': {'ARN': acl_arn, 'Id': UUID, 'Rules': rules}}
    policy = {'approved_allow_cidrs': ['192.0.2.0/24'], 'approved_block_cidrs': ['192.0.2.0/24'],
              'approved_allow_priority': 1, 'approved_block_priority': 2} if metadata else {}
    snapshot = make_snapshot('aws', [scope], [
        {'type': 'wafv2_web_acl', 'scope': scope, 'status': 'collected', 'items': [acl]},
        {'type': 'wafv2_ip_set', 'scope': scope, 'status': read.status, 'items': read.items}], metadata=policy)
    if through_connector:
        from types import SimpleNamespace
        from peaso.collectors.bulk_evidence import collect
        module = SimpleNamespace(AWS_TYPES={'wafv2_web_acl', 'wafv2_ip_set'},
                                 collect=lambda connector, requirements: make_snapshot('aws', [scope], snapshot['collections']))
        snapshot = collect(module, {'provider': 'aws', 'options': {'compliance_parameters': policy}},
                           ['wafv2_web_acl', 'wafv2_ip_set'])
    return evaluate_snapshot(snapshot, checks=[CHECK])['findings'][0]['status']


@pytest.mark.parametrize('mode', ['complete', 'empty', 'denied_parent', 'denied_child',
    'missing_child', 'foreign_account', 'foreign_region', 'wrong_partition', 'wrong_scope',
    'wrong_id', 'duplicate', 'paginated', 'limited', 'foreign_detail', 'missing_detail',
    'bad_cidr', 'host_bits', 'wrong_family', 'duplicate_cidr', 'empty_addresses', 'ipv6'])
def test_native_ip_set_integrity_pagination_and_failures(sdk, mode):
    session, add = sdk
    stub = add('wafv2')
    row = ipset()
    options = {'retries': 0}
    if mode == 'foreign_account': row['ARN'] = row['ARN'].replace(ACCOUNT, '999999999999')
    if mode == 'foreign_region': row['ARN'] = row['ARN'].replace(REGION, 'eu-west-2')
    if mode == 'wrong_partition': row['ARN'] = row['ARN'].replace('arn:aws:', 'arn:aws-cn:')
    if mode == 'wrong_scope': row['ARN'] = row['ARN'].replace(':regional/', ':global/')
    if mode == 'wrong_id': row['Id'] = 'invalid'
    args = {'Scope': 'REGIONAL', 'Limit': 100}
    if mode == 'denied_parent':
        stub.add_client_error('list_ip_sets', 'AccessDeniedException', expected_params=args)
    else:
        response = {'IPSets': [] if mode == 'empty' else [summary(row)] * (2 if mode == 'duplicate' else 1)}
        if mode in ('paginated', 'limited'): response['NextMarker'] = 'cursor'
        stub.add_response('list_ip_sets', response, args)
        if mode == 'paginated': stub.add_response('list_ip_sets', {'IPSets': []}, {**args, 'NextMarker': 'cursor'})
        if mode == 'limited': options['max_pages'] = 1
    if mode not in ('empty', 'denied_parent', 'foreign_account', 'foreign_region', 'wrong_partition', 'wrong_scope', 'wrong_id'):
        args = {'Name': row['Name'], 'Id': row['Id'], 'Scope': 'REGIONAL'}
        if mode in ('denied_child', 'missing_child'):
            stub.add_client_error('get_ip_set', 'AccessDeniedException' if mode == 'denied_child' else 'WAFNonexistentItemException', expected_params=args)
        else:
            detail = copy.deepcopy(row)
            if mode == 'foreign_detail': detail['ARN'] = detail['ARN'].replace(ACCOUNT, '999999999999')
            if mode == 'bad_cidr': detail['Addresses'] = ['not-a-network']
            if mode == 'host_bits': detail['Addresses'] = ['192.0.2.1/24']
            if mode == 'wrong_family': detail['IPAddressVersion'] = 'IPV6'
            if mode == 'duplicate_cidr': detail['Addresses'] *= 2
            if mode == 'empty_addresses': detail['Addresses'] = []
            if mode == 'ipv6': detail.update(IPAddressVersion='IPV6', Addresses=['2001:db8::/32'])
            stub.add_response('get_ip_set', {} if mode == 'missing_detail' else {'IPSet': detail, 'LockToken': UUID}, args)
    read = facts.FETCHERS['wafv2_ip_set'](aws.Requests(options), session, REGION, ACCOUNT)
    if mode in ('complete', 'paginated', 'empty_addresses', 'ipv6'):
        assert read.status == 'collected'
        assert 'private-description-marker' not in json.dumps(read.items)
        assert 'LockToken' not in json.dumps(read.items)
        assert read.items[0]['_provenance']['read_only'] is True
    elif mode == 'empty': assert read.status == 'empty'
    else:
        assert read.status not in ('collected', 'empty')
        assert decision(read) == 'UNKNOWN'
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('region,scope,prefix', [('us-east-1', 'CLOUDFRONT', 'global'),
    ('us-east-1', 'REGIONAL', 'regional'), ('cn-north-1', 'REGIONAL', 'regional'),
    ('us-gov-west-1', 'REGIONAL', 'regional')])
def test_cloudfront_is_read_only_at_its_endpoint_and_partition_bound(sdk, region, scope, prefix):
    session, add = sdk
    stub = add('wafv2')
    row = ipset(scope=scope, region=region)
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    row['ARN'] = row['ARN'].replace('arn:aws:', 'arn:' + partition + ':')
    for observed in ['REGIONAL'] + (['CLOUDFRONT'] if region == 'us-east-1' else []):
        stub.add_response('list_ip_sets', {'IPSets': [summary(row)] if observed == scope else []}, {'Scope': observed, 'Limit': 100})
        if observed == scope: stub.add_response('get_ip_set', {'IPSet': row, 'LockToken': UUID}, {'Name': row['Name'], 'Id': UUID, 'Scope': scope})
    read = facts.FETCHERS['wafv2_ip_set'](aws.Requests({}), session, region, ACCOUNT)
    assert read.status == 'collected' and read.items[0]['Scope'] == scope
    assert ':' + prefix + '/ipset/' in read.items[0]['ARN']
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('through_connector', [False, True])
@pytest.mark.parametrize('priority,policy,expected', [(2, True, 'PASS'), (4, True, 'FAIL'), (2, False, 'UNKNOWN')])
def test_real_native_rows_drive_check_without_synthetic_positive_evidence(sdk, priority, policy, expected, through_connector):
    session, add = sdk
    stub = add('wafv2')
    rows = [ipset('allow'), ipset('block')]
    stub.add_response('list_ip_sets', {'IPSets': [summary(row) for row in rows]}, {'Scope': 'REGIONAL', 'Limit': 100})
    for row in rows: stub.add_response('get_ip_set', {'IPSet': row, 'LockToken': UUID}, {'Name': row['Name'], 'Id': row['Id'], 'Scope': 'REGIONAL'})
    requests = aws.Requests({})
    read = facts.FETCHERS['wafv2_ip_set'](requests, session, REGION, ACCOUNT)
    assert decision(read, priority, policy, through_connector) == expected
    assert facts.FETCHERS['wafv2_ip_set'](requests, session, REGION, ACCOUNT).items == read.items
    assert requests.calls == 3
    assert 'wafv2_ip_set' in aws.AWS_TYPES
    assert ('wafv2', 'get_ip_set') in aws.READ_ACTIONS
    stub.assert_no_pending_responses()
