"""Native EKS/Shield status truth tables and existing SDK producer shapes."""
from copy import deepcopy

import pytest

from peaso.checks import aws_service_status_review_20261019 as checks
from peaso.collectors import aws
from tests.test_peaso_collectors_aws import sdk

ACCOUNT, REGION = '123456789012', 'us-east-1'


def cases(cid):
    return deepcopy(checks.RUNTIME_CASES[cid])


@pytest.mark.parametrize('status,expected', [('STANDARD_SUPPORT', 'PASS'), ('EXTENDED_SUPPORT', 'PASS'),
    ('UNSUPPORTED', 'FAIL'), ('standard-support', 'UNKNOWN'), ('FUTURE', 'UNKNOWN'), (None, 'UNKNOWN')])
def test_eks_exact_native_status_enum(status, expected):
    case = cases(checks.EKS_ID)
    case['pass_index']['collections']['eks_version_catalog'][0]['items'][0]['versions'][0]['versionStatus'] = status
    original = deepcopy(case)
    outcome, evidence = checks.eks_version_supported(case['pass'], case['pass_index'])
    assert outcome == expected and case == original and len(evidence['observed']) <= 150


@pytest.mark.parametrize('kind', ['eks_cluster', 'eks_version_catalog'])
@pytest.mark.parametrize('status', ['partial', 'denied', 'unknown', 'not_collected', 'malformed'])
def test_eks_incomplete_dependencies_cannot_pass(kind, status):
    case = cases(checks.EKS_ID)
    case['pass_index']['collections'][kind][0]['status'] = status
    assert checks.eks_version_supported(case['pass'], case['pass_index'])[0] == 'UNKNOWN'


def test_eks_foreign_duplicate_missing_and_unproved_catalogs_stay_unknown():
    for mutation in ('foreign_cluster', 'duplicate_version', 'missing_version', 'partial_provenance', 'denied_status_field'):
        case = cases(checks.EKS_ID)
        scoped = case['pass_index']
        catalog = scoped['collections']['eks_version_catalog'][0]['items'][0]
        if mutation == 'foreign_cluster':
            case['pass']['Cluster']['cluster']['arn'] = 'arn:aws:eks:eu-west-1:999999999999:cluster/example'
        elif mutation == 'duplicate_version': catalog['versions'] *= 2
        elif mutation == 'missing_version': catalog['versions'] = []
        elif mutation == 'partial_provenance': catalog['_provenance']['includeAll'] = False
        else: catalog['versions'][0]['_coverage'] = {'versionStatus': {'status': 'denied'}}
        assert checks.eks_version_supported(case['pass'], scoped)[0] == 'UNKNOWN', mutation


@pytest.mark.parametrize('role,expected', [(f'arn:aws:iam::{ACCOUNT}:role/DRT', 'PASS'), ('', 'FAIL'),
    ('arn:aws:iam::999999999999:role/DRT', 'UNKNOWN'), ('malformed', 'UNKNOWN')])
def test_shield_configured_role_native_truths(role, expected):
    case = cases(checks.SHIELD_ID)
    scoped = case['pass_index']
    scoped['collections']['shield_drt_access'][0]['items'][0]['RoleArn'] = role
    status, evidence = checks.shield_drt_role_configured(case['pass'], scoped)
    assert status == expected and len(evidence['observed']) <= 150
    if status == 'PASS':
        assert 'DRT role DRT' in evidence['observed']


def test_inactive_shield_does_not_require_a_drt_role_and_unknown_enum_is_unresolved():
    case = cases(checks.SHIELD_ID)
    case['pass']['SubscriptionState'] = 'INACTIVE'
    case['pass_index']['collections']['shield_subscription'][0]['items'] = [case['pass']]
    del case['pass_index']['collections']['shield_drt_access']
    assert checks.shield_drt_role_configured(case['pass'], case['pass_index'])[0] == 'NOT_APPLICABLE'
    case['pass']['SubscriptionState'] = 'Future'
    assert checks.shield_drt_role_configured(case['pass'], case['pass_index'])[0] == 'UNKNOWN'


@pytest.mark.parametrize('status', ['partial', 'denied', 'unknown', 'not_collected', 'malformed'])
def test_shield_drt_incomplete_inventory_cannot_pass(status):
    case = cases(checks.SHIELD_ID)
    case['pass_index']['collections']['shield_drt_access'][0]['status'] = status
    assert checks.shield_drt_role_configured(case['pass'], case['pass_index'])[0] == 'UNKNOWN'


def test_existing_sdk_eks_producers_feed_new_predicate(sdk):
    from peaso.collectors.aws_bulk_inventory import _eks_versions
    session, add, _ = sdk
    stub = add('eks')
    stub.add_response('describe_cluster', {'cluster': {'name': 'example',
        'arn': f'arn:aws:eks:{REGION}:{ACCOUNT}:cluster/example', 'version': '1.35'}}, {'name': 'example'})
    stub.add_response('describe_cluster_versions', {'clusterVersions': [
        {'clusterVersion': '1.35', 'versionStatus': 'STANDARD_SUPPORT'}]}, {'includeAll': True})
    requests = aws.Requests({})
    cluster = aws._enrich(requests, session, REGION, 'eks_cluster', ['example'])[0]
    catalog = _eks_versions(requests, session, REGION, ACCOUNT)
    case = cases(checks.EKS_ID)
    scoped = case['pass_index']
    scoped['collections']['eks_cluster'][0]['items'] = [cluster]
    scoped['collections']['eks_version_catalog'][0]['items'] = catalog.items
    assert checks.eks_version_supported(cluster, scoped)[0] == 'PASS'


def test_public_global_shield_collector_reads_once_across_selected_regions(sdk):
    from peaso.snapshot import validate
    _session, add, _ = sdk
    add('sts').add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'AIDAREVIEWER'}, {})
    stub = add('shield')
    stub.add_response('describe_drt_access', {'RoleArn': f'arn:aws:iam::{ACCOUNT}:role/DRT'}, {})
    stub.add_response('get_subscription_state', {'SubscriptionState': 'ACTIVE'}, {})
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'auth': {'profile': 'chosen'},
        'options': {'regions': [REGION, 'eu-west-1'], 'service_concurrency': 1}},
        ['shield_subscription', 'shield_drt_access'])
    assert validate(snapshot) == snapshot
    selected = {kind: [row for row in snapshot['collections'] if row['type'] == kind] for kind in
                ['shield_subscription', 'shield_drt_access']}
    assert all(len(rows) == 1 for rows in selected.values())
    assert snapshot['metadata']['calls'] == 3
    item = selected['shield_subscription'][0]['items'][0]
    scoped = {'context': {'provider': 'aws', 'scope': ACCOUNT + '/global'}, 'collections': selected}
    assert checks.shield_drt_role_configured(item, scoped)[0] == 'PASS'
