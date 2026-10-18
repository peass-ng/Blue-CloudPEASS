"""Native tag compliance through the hosted path, with tag values omitted."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from peaso.collectors import aws, collect_live, aws_resource_tag_compliance_native as native
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from peaso.snapshot import make_snapshot
from peaso.checks.aws_resource_tag_compliance import CHECK_ID
from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION

SCOPE = ACCOUNT + '/' + REGION
RESOURCE = 'arn:aws:ec2:' + REGION + ':' + ACCOUNT + ':instance/i-0123456789abcdef0'
PRIVATE = 'tag-value-private-marker-must-never-enter-cache'


def mapping(compliant=True):
    return {'ResourceARN': RESOURCE, 'Tags': [{'Key': 'Password', 'Value': PRIVATE}],
            'ComplianceDetails': {'ComplianceStatus': compliant,
                                  'NoncompliantKeys': [] if compliant else ['Environment'],
                                  'KeysWithNoncompliantValues': []}}


@pytest.mark.parametrize('mode,expected', [('compliant', 'PASS'), ('noncompliant', 'FAIL'),
                                         ('missing_assessment', 'UNKNOWN'), ('contradiction', 'UNKNOWN'),
                                         ('foreign_resource', 'UNKNOWN'), ('foreign_partition', 'UNKNOWN'),
                                         ('foreign_region', 'UNKNOWN'), ('denied', 'DENIED'),
                                         ('empty', 'EMPTY'), ('partial', 'UNKNOWN')])
def test_hosted_native_tag_policy_assessment(monkeypatch, sdk, mode, expected):
    session, add = sdk
    sts, tagging = add('sts'), add('resourcegroupstaggingapi')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': 'arn:aws:iam::' + ACCOUNT + ':user/reviewer', 'UserId': 'reviewer'}, {})
    row = mapping(mode != 'noncompliant')
    if mode == 'missing_assessment': row.pop('ComplianceDetails')
    if mode == 'contradiction': row['ComplianceDetails']['NoncompliantKeys'] = ['Environment']
    if mode == 'foreign_resource': row['ResourceARN'] = RESOURCE.replace(ACCOUNT, '999999999999')
    if mode == 'foreign_partition': row['ResourceARN'] = RESOURCE.replace('arn:aws:', 'arn:aws-cn:')
    if mode == 'foreign_region': row['ResourceARN'] = RESOURCE.replace(REGION, 'eu-west-2')
    if mode == 'denied':
        tagging.add_client_error('get_resources', 'AccessDeniedException', expected_params=native.QUERY)
    else:
        tagging.add_response('get_resources', {'ResourceTagMappingList': [] if mode == 'empty' else [row],
            **({'PaginationToken': 'second-page'} if mode == 'partial' else {})}, native.QUERY)
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1}
    if mode == 'partial': options['max_pages'] = 1
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [SCOPE], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CHECK_ID]})
    assert requirements == [native.KIND] or set(requirements) == {native.KIND}
    snapshot = collect_live(connector, requirements)
    findings = [finding for finding in evaluate_snapshot(snapshot, checks=[CHECK_ID])['findings']
                if finding['check_id'] == CHECK_ID]
    assert findings and {finding['status'] for finding in findings} == {expected}
    assert PRIVATE not in str(snapshot)
    sts.assert_no_pending_responses()
    tagging.assert_no_pending_responses()


def test_sdk_pagination_metadata_cache_never_keeps_tag_values(sdk):
    session, add = sdk
    tagging = add('resourcegroupstaggingapi')
    first, second = mapping(False), mapping(True)
    second['ResourceARN'] += '-another'
    tagging.add_response('get_resources', {'ResourceTagMappingList': [first], 'PaginationToken': 'second'}, native.QUERY)
    tagging.add_response('get_resources', {'ResourceTagMappingList': [second]}, {**native.QUERY, 'PaginationToken': 'second'})
    requests = aws.Requests({})
    read = native.fetch(requests, session, REGION, ACCOUNT)
    assert read.status == 'collected' and len(read.items) == 2 and requests.calls == 2
    cached = [future.result() for future in requests._cache.values()]
    assert PRIVATE not in str(cached) and 'Tags' not in str(cached)
    snapshot = make_snapshot('aws', [SCOPE], [{'type': native.KIND, 'scope': SCOPE,
                                             'status': read.status, 'items': read.items}])
    assert {f['status'] for f in evaluate_snapshot(snapshot, checks=[CHECK_ID])['findings']} == {'PASS', 'FAIL'}
    tagging.assert_no_pending_responses()


@pytest.mark.parametrize('mutation', ['wrong_type', 'duplicate', 'invalid_keys'])
def test_invalid_native_compliance_responses_fail_closed_without_mutating_input(mutation):
    row = mapping()
    if mutation == 'wrong_type': row['ComplianceDetails']['ComplianceStatus'] = 'true'
    if mutation == 'invalid_keys': row['ComplianceDetails']['NoncompliantKeys'] = [None]
    raw = {'ResourceTagMappingList': [row, deepcopy(row)] if mutation == 'duplicate' else [row]}
    before = deepcopy(raw)
    with pytest.raises(ValueError): native.project_response(raw)
    assert raw == before


def test_duplicate_across_native_pages_never_certifies_compliance(sdk):
    session, add = sdk
    tagging = add('resourcegroupstaggingapi')
    tagging.add_response('get_resources', {'ResourceTagMappingList': [mapping()], 'PaginationToken': 'second'}, native.QUERY)
    tagging.add_response('get_resources', {'ResourceTagMappingList': [mapping(False)]}, {**native.QUERY, 'PaginationToken': 'second'})
    read = native.fetch(aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == 'partial'
    snapshot = make_snapshot('aws', [SCOPE], [{'type': native.KIND, 'scope': SCOPE,
        'status': read.status, 'items': read.items}])
    assert {f['status'] for f in evaluate_snapshot(snapshot, checks=[CHECK_ID])['findings']} == {'UNKNOWN'}
    tagging.assert_no_pending_responses()


def test_imported_assessment_with_foreign_partition_is_unknown():
    from peaso.checks import evaluate_check
    from peaso.checks.aws_resource_tag_compliance import _fixture
    row, index = _fixture(True)
    row['ResourceARN'] = row['ResourceARN'].replace('arn:aws:', 'arn:aws-cn:')
    index['collections'][native.KIND][0]['items'] = [deepcopy(row)]
    index[native.KIND][0]['data'] = deepcopy(row)
    assert evaluate_check(CHECK_ID, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mutation', ['global_alias', 'wrong_type', 'foreign_wrapper', 'missing_wrapper'])
def test_imported_assessment_requires_regional_envelope_and_matching_wrapper(mutation):
    from peaso.checks import evaluate_check
    from peaso.checks.aws_resource_tag_compliance import _fixture
    row, index = _fixture(True)
    envelope = index['collections'][native.KIND][0]
    if mutation == 'global_alias':
        envelope.update(scope=ACCOUNT + '/global')
        envelope['global'] = True
        envelope['account_id'] = ACCOUNT
    elif mutation == 'wrong_type': envelope['type'] = 'unrelated_inventory'
    elif mutation == 'foreign_wrapper': index[native.KIND][0]['scope'] = ACCOUNT + '/eu-west-2'
    else: index[native.KIND] = []
    assert evaluate_check(CHECK_ID, row, index)[0] == 'UNKNOWN'


def test_large_resource_batch_validates_shared_inventory_once(monkeypatch):
    from peaso.checks import aws_resource_tag_compliance as check
    from peaso.checks.aws_resource_tag_compliance import _fixture
    row, _ = _fixture(True)
    rows = []
    for number in range(500):
        resource = deepcopy(row)
        resource['ResourceARN'] = RESOURCE + '-' + str(number)
        resource['ComplianceDetails']['ComplianceStatus'] = number % 2 == 0
        rows.append(resource)
    calls = []
    original = check.complete_items
    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(check, 'complete_items', counted)
    snapshot = make_snapshot('aws', [SCOPE], [{'type': native.KIND, 'scope': SCOPE,
        'status': 'collected', 'items': rows}])
    findings = evaluate_snapshot(snapshot, checks=[CHECK_ID])['findings']
    assert len(findings) == 500
    assert sum(f['status'] == 'PASS' for f in findings) == 250
    assert sum(f['status'] == 'FAIL' for f in findings) == 250
    assert len(calls) == 1


def test_ad_hoc_index_is_not_cached_after_inventory_changes():
    from peaso.checks import evaluate_check
    from peaso.checks.aws_resource_tag_compliance import _fixture
    row, index = _fixture(True)
    assert evaluate_check(CHECK_ID, row, index)[0] == 'PASS'
    index['collections'][native.KIND][0]['items'][0]['ComplianceDetails']['ComplianceStatus'] = False
    assert evaluate_check(CHECK_ID, row, index)[0] == 'UNKNOWN'


def test_duplicate_wrappers_do_not_hide_another_resource_assessment():
    from peaso.checks import evaluate_check
    from peaso.checks.aws_resource_tag_compliance import _fixture
    row, index = _fixture(True)
    other = deepcopy(row)
    other['ResourceARN'] += '-other'
    other['ComplianceDetails']['ComplianceStatus'] = False
    index['collections'][native.KIND][0]['items'].append(other)
    index[native.KIND].append(deepcopy(index[native.KIND][0]))
    assert evaluate_check(CHECK_ID, row, index)[0] == 'UNKNOWN'
