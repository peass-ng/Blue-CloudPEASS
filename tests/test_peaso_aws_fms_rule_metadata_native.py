"""FMS native ACL metadata through SDK, without fabricating policy ownership."""
from copy import deepcopy
import json
from types import SimpleNamespace
import pytest

from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live, aws_fms_rule_metadata_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from peaso.snapshot import make_snapshot

CHECK = 'aws.pci.fms.web_acl_rule_priority'
UID = '12345678-1234-1234-1234-123456789012'
POLICY = '87654321-4321-4321-4321-210987654321'
NAME = 'FMS_Managed_Example'
PRIVATE = 'NEVER_STORE_FMS_PRIVATE_HEADER_BODY'
VISIBILITY = {'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True, 'MetricName': 'NativeMetric'}


def acl(scope='REGIONAL', region=REGION):
    location = 'regional' if scope == 'REGIONAL' else 'global'
    arn = f'arn:aws:wafv2:{region}:{ACCOUNT}:{location}/webacl/{NAME}/{UID}'
    def group(name, priority):
        return {'Name': name, 'Priority': priority,
            'FirewallManagerStatement': {'RuleGroupReferenceStatement': {
                'ARN': f'arn:aws:wafv2:{region}:{ACCOUNT}:{location}/rulegroup/{PRIVATE}/{UID}'}},
            'OverrideAction': {'None': {}}, 'VisibilityConfig': deepcopy(VISIBILITY)}
    return {'Name': NAME, 'Id': UID, 'ARN': arn, 'ManagedByFirewallManager': True,
        'DefaultAction': {'Allow': {'CustomRequestHandling': {'InsertHeaders': [{'Name': 'x-private', 'Value': PRIVATE}]}}},
        'VisibilityConfig': deepcopy(VISIBILITY), 'Description': PRIVATE,
        'CustomResponseBodies': {'private': {'ContentType': 'TEXT_PLAIN', 'Content': PRIVATE}},
        'PreProcessFirewallManagerRuleGroups': [group('Pre', 1)],
        'PostProcessFirewallManagerRuleGroups': [group('Post', 2)]}


def policy_row():
    return {'PolicyId': POLICY, 'PolicyArn': f'arn:aws:fms:{REGION}:{ACCOUNT}:policy/{POLICY}',
        'PolicyName': 'NativePolicy', 'SecurityServiceType': 'WAFV2'}


def queue(sdk, mode, *, public=False):
    session, add = sdk; waf = add('wafv2'); stubs = [waf]; count = [0]
    call_region = 'eu-west-1' if mode == 'other_region' else REGION
    def response(stub, operation, value, arguments):
        stub.add_response(operation, value, arguments); count[0] += 1
    def denied(operation, arguments):
        waf.add_client_error(operation, 'AccessDeniedException', expected_params=arguments); count[0] += 1
    if public:
        sts, fms = add('sts'), add('fms'); stubs += [sts, fms]
        response(sts, 'get_caller_identity', {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
        response(fms, 'list_policies', {'PolicyList': [policy_row()]}, {})
        response(fms, 'list_compliance_status', {'PolicyComplianceStatusList': []}, {'PolicyId': POLICY})
    for scope in ('REGIONAL', 'CLOUDFRONT') if call_region == REGION else ('REGIONAL',):
        args = {'Scope': scope, 'Limit': 100}
        if mode == 'list_denied': denied('list_web_acls', args); break
        body = acl(scope, call_region)
        if mode == 'retrofit': body['ManagedByFirewallManager'] = False; body['RetrofittedByFirewallManager'] = True
        if mode == 'both_flags': body['RetrofittedByFirewallManager'] = True
        if mode == 'equal_across_sets': body['PostProcessFirewallManagerRuleGroups'][0]['Priority'] = 1
        if mode == 'unmanaged': body['ManagedByFirewallManager'] = False
        if mode == 'missing_flags': body.pop('ManagedByFirewallManager')
        if mode == 'omitted_arrays':
            for field in native.ARRAYS: body.pop(field)
        if mode in ('duplicate_name', 'duplicate_priority'):
            other = deepcopy(body[native.ARRAYS[0]][0])
            other['Name'] = 'Other' if mode == 'duplicate_priority' else 'Pre'
            other['Priority'] = 1 if mode == 'duplicate_priority' else 3
            body[native.ARRAYS[0]].append(other)
        summary = {key: body[key] for key in ('Name', 'Id', 'ARN')}
        summary.update(Description=PRIVATE, LockToken=UID)
        include = mode != 'empty' and (scope == ('CLOUDFRONT' if mode == 'cloudfront' else 'REGIONAL'))
        rows = [summary] if include else []
        if mode == 'foreign_account' and include: rows[0]['ARN'] = rows[0]['ARN'].replace(ACCOUNT, '999999999999')
        if mode == 'duplicate' and include: rows.append(deepcopy(summary))
        result = {'WebACLs': rows, **({'NextMarker': 'more'} if mode == 'partial' else {})}
        response(waf, 'list_web_acls', result, args)
        if mode in ('partial', 'foreign_account'): break
        if not include: continue
        detail_args = {'Name': NAME, 'Id': UID, 'Scope': scope}
        if mode == 'detail_denied': denied('get_web_acl', detail_args); break
        if mode == 'wrong_detail': body['ARN'] = body['ARN'].replace(ACCOUNT, '999999999999')
        response(waf, 'get_web_acl', {'WebACL': body, 'LockToken': UID}, detail_args)
        if mode in ('duplicate', 'wrong_detail', 'duplicate_name', 'duplicate_priority'): break
    return session, stubs, count[0], call_region


def verdict(read, region):
    scope = ACCOUNT + '/' + region
    snapshot = make_snapshot('aws', [scope], [{'type': 'fms_policy', 'scope': scope,
        'status': 'collected', 'items': [policy_row()]}, {'type': native.KIND, 'scope': scope,
        'status': read.status, 'items': read.items, **({'error': read.error} if read.error else {})}], metadata={
            'parameters': {'approved_fms_rule_priorities': {POLICY: [{'Name': 'Pre', 'Priority': 1}, {'Name': 'Post', 'Priority': 2}]}}})
    return evaluate_snapshot(snapshot, checks=[CHECK])['findings']


@pytest.mark.parametrize('mode,status,count', [('managed', 'collected', 1), ('retrofit', 'collected', 1),
    ('both_flags', 'collected', 1), ('equal_across_sets', 'collected', 1), ('unmanaged', 'not_collected', 0),
    ('missing_flags', 'not_collected', 0), ('empty', 'not_collected', 0), ('list_denied', 'denied', 0),
    ('detail_denied', 'denied', 0), ('partial', 'partial', 0), ('duplicate', 'partial', 1),
    ('foreign_account', 'malformed', 0), ('wrong_detail', 'malformed', 0), ('omitted_arrays', 'collected', 1),
    ('cloudfront', 'collected', 1), ('other_region', 'collected', 1),
    ('duplicate_name', 'malformed', 0), ('duplicate_priority', 'malformed', 0)])
def test_sdk_native_only_dispatch_metadata_and_no_policy_association(sdk, mode, status, count):
    session, stubs, calls, region = queue(sdk, mode)
    reader = aws.Requests({'service_concurrency': 1, 'retry_attempts': 1,
        **({'max_pages': 1} if mode == 'partial' else {})})
    observed = []
    original = reader.call
    def dispatch(session, service, region, operation, **arguments):
        observed.append((service, operation))
        return original(session, service, region, operation, **arguments)
    reader.call = dispatch
    read = native.collect(reader, session, region, ACCOUNT)
    assert read.status == status and len(read.items) == count
    assert reader.calls == calls
    assert set(observed) <= native.PROJECTION_OPERATIONS
    if mode == 'other_region': assert reader.calls == 2
    for row in read.items:
        assert row['complete'] is False and row['RulesInventoryStatus'] == 'collected'
        assert 'PolicyId' not in row and row['_coverage']['PolicyId']['status'] == 'not_collected'
        assert 'Rules' not in row
        if mode == 'equal_across_sets':
            assert row[native.ARRAYS[0]][0]['Priority'] == row[native.ARRAYS[1]][0]['Priority']
        if mode == 'omitted_arrays':
            assert all(field not in row and row['_coverage'][field]['status'] == 'not_collected' for field in native.ARRAYS)
    findings = verdict(read, region)
    assert findings and all(f['status'] in {'UNKNOWN', 'DENIED'} for f in findings)
    for future in reader._cache.values():
        if future.exception() is None:
            value = json.dumps(future.result(), default=str)
            assert PRIVATE not in value and 'FirewallManagerStatement' not in value and 'LockToken' not in value
        else: assert future.exception().__traceback__ is None and future.exception().__context__ is None
    for stub in stubs: stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['managed', 'retrofit', 'equal_across_sets'])
def test_normal_hosted_frozen_control_remains_unknown_without_native_policy_binding(monkeypatch, sdk, mode):
    session, stubs, calls, region = queue(sdk, mode, public=True)
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'inert-sdk-fixture'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1, 'compliance_parameters': {
        'approved_fms_rule_priorities': {POLICY: [{'Name': 'Pre', 'Priority': 1}, {'Name': 'Post', 'Priority': 2}]}}}
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + region], 'auth': auth, 'options': options}
    required = plan_collection({'connector': connector, 'checks': [CHECK]})
    assert set(required) == {'fms_policy', native.KIND}
    snapshot = collect_live(connector, required)
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    assert findings and all(f['status'] == 'UNKNOWN' for f in findings)
    collection = next(c for c in snapshot['collections'] if c['type'] == native.KIND)
    assert collection['status'] == 'collected' and len(collection['items']) == 1
    assert PRIVATE not in json.dumps(snapshot)
    assert snapshot['metadata']['calls'] == calls
    for stub in stubs: stub.assert_no_pending_responses()
