"""Narrow service-reported status alternatives to owner-policy controls.

No registration or provider calls occur here. The coordinator admits metadata
and cases; the predicates consume existing complete native collector envelopes.
"""
from __future__ import annotations

from copy import deepcopy
from functools import wraps
import re

from . import result, unknown
from .facts import Unavailable, get, guard, list_of_objects

EKS_ID = 'aws.review.eks.native_version_supported'
SHIELD_ID = 'aws.review.shield.drt_role_configured'


def _safe(function):
    @wraps(function)
    def evaluate(item, index):
        try:
            guard(item)
            return function(item, index)
        except (Unavailable, ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
            return unknown('Native service status evidence unavailable or malformed', error_type=type(exc).__name__,
                           observed='Required native service status or identity evidence is unavailable or malformed.')
    return evaluate


def _context(index, *, global_scope=False):
    scope = get(index, 'context.scope', str)
    if get(index, 'context.provider', str) != 'aws':
        raise Unavailable('AWS provider context required')
    match = re.fullmatch(r'([0-9]{12})/(global|[a-z]{2}(?:-[a-z]+)+-[0-9])', scope)
    if match is None or (match[2] == 'global') != global_scope:
        raise Unavailable('native account/Region context unavailable')
    return scope, match[1], match[2]


def _rows(index, kind, scope, account, *, global_scope=False):
    envelopes = get(index, 'collections.' + kind, list)
    if len(envelopes) != 1:
        raise Unavailable('native inventory missing or ambiguous')
    envelope = envelopes[0]
    if (get(envelope, 'scope', str) != scope or envelope.get('account_id', account) != account or
            get(envelope, 'status', str) not in {'collected', 'empty'}):
        raise Unavailable('native inventory scope or coverage unavailable')
    if global_scope and (get(envelope, 'global', bool) is not True or get(envelope, 'account_id', str) != account):
        raise Unavailable('global account coverage not verified')
    if not global_scope and envelope.get('global') is True:
        raise Unavailable('regional inventory was incorrectly marked global')
    rows = list_of_objects(get(envelope, 'items', list))
    if envelope['status'] == 'empty' and rows:
        raise Unavailable('empty status contradicts retained rows')
    for row in rows:
        guard(row)
    return rows


@_safe
def eks_version_supported(item, index):
    scope, account, region = _context(index)
    name = get(item, 'name', str)
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,99}', name) is None:
        raise Unavailable('malformed EKS cluster name')
    representation = get(item, 'Cluster', dict)
    if get(representation, 'collection_status', str) != 'collected':
        raise Unavailable('DescribeCluster unavailable')
    cluster = get(representation, 'cluster', dict)
    arn = get(cluster, 'arn', str)
    match = re.fullmatch(r'arn:(aws(?:-[a-z0-9-]+)?):eks:([^:]+):([0-9]{12}):cluster/(.+)', arn)
    if match is None or match[2] != region or match[3] != account or match[4] != name or get(cluster, 'name', str) != name:
        raise Unavailable('cluster native identity does not match audited scope')
    version = get(cluster, 'version', str)
    if re.fullmatch(r'[0-9]+\.[0-9]+', version) is None:
        raise Unavailable('malformed native Kubernetes version')
    clusters = _rows(index, 'eks_cluster', scope, account)
    matches = [row for row in clusters if get(row, 'name', str) == name]
    if len(matches) != 1 or matches[0] != item:
        raise Unavailable('cluster missing or ambiguous in complete scoped inventory')
    catalogs = _rows(index, 'eks_version_catalog', scope, account)
    if len(catalogs) != 1 or get(catalogs[0], 'region', str) != region:
        raise Unavailable('native EKS catalog missing or foreign')
    catalog = catalogs[0]
    provenance = get(catalog, '_provenance', dict)
    if (get(provenance, 'source_operation', str) != 'DescribeClusterVersions' or
            get(provenance, 'read_only', bool) is not True or get(provenance, 'includeAll', bool) is not True):
        raise Unavailable('complete native EKS version enumeration not proven')
    statuses = {}
    for row in list_of_objects(get(catalog, 'versions', list)):
        native_version = get(row, 'clusterVersion', str)
        status = get(row, 'versionStatus', str)
        if (re.fullmatch(r'[0-9]+\.[0-9]+', native_version) is None or native_version in statuses or
                status not in {'STANDARD_SUPPORT', 'EXTENDED_SUPPORT', 'UNSUPPORTED'}):
            raise Unavailable('native version status malformed, duplicated or unrecognized')
        statuses[native_version] = status
    if version not in statuses:
        raise Unavailable('cluster version absent from native catalog')
    status = statuses[version]
    return result(status == 'UNSUPPORTED', cluster_arn=arn, cluster_name=name, version=version, version_status=status,
                  observed=f'EKS cluster {name[:24]} version {version[:12]} is reported as {status} by AWS.',
                  semantics='Native EKS support status only; no owner-approved minimum version or extended-support spending policy')


@_safe
def shield_drt_role_configured(item, index):
    scope, account, _region = _context(index, global_scope=True)
    if get(item, 'id', str) != 'shield-subscription/' + account or get(item, 'AccountId', str) != account:
        raise Unavailable('Shield subscription account identity mismatch')
    subscriptions = _rows(index, 'shield_subscription', scope, account, global_scope=True)
    if len(subscriptions) != 1 or subscriptions[0] != item:
        raise Unavailable('Shield subscription missing or ambiguous')
    status = get(item, 'SubscriptionState', str)
    if status == 'INACTIVE':
        return 'NOT_APPLICABLE', {'reason': 'Shield Advanced subscription is inactive', 'account_id': account,
                                  'observed': 'Shield Advanced subscription is inactive; DRT role configuration is outside this check.'}
    if status != 'ACTIVE':
        raise Unavailable('unrecognized Shield subscription status')
    rows = _rows(index, 'shield_drt_access', scope, account, global_scope=True)
    if len(rows) != 1 or get(rows[0], 'id', str) != account or get(rows[0], 'AccountId', str) != account:
        raise Unavailable('DRT native account observation missing or ambiguous')
    drt = rows[0]
    if (get(drt, '_provenance.source_operation', str) != 'shield:DescribeDRTAccess' or
            get(drt, '_provenance.read_only', bool) is not True):
        raise Unavailable('native DRT configuration source unavailable')
    role = get(drt, 'RoleArn', str)
    if role:
        match = re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+', role)
        if match is None or match[1] != account:
            raise Unavailable('DRT role ARN malformed or foreign')
    return result(not role, account_id=account, role_arn=role,
                  observed=(f"Active Shield Advanced subscription configures DRT role {role.rsplit('/', 1)[-1][:24]}." if role else
                            'Active Shield Advanced subscription has no configured DRT role.'),
                  semantics='Configured DRT role only; trust-policy effectiveness, approved log buckets and support readiness are unassessed')


DECLARATIONS = [
    {'id': EKS_ID, 'kind': 'eks_cluster', 'target': 'resource', 'severity': 'medium', 'category': 'hardening',
     'title': 'EKS cluster version has native AWS support', 'evaluator': 'eks_version_supported',
     'dependencies': ['eks_cluster', 'eks_version_catalog'], 'control': 'SI-2'},
    {'id': SHIELD_ID, 'kind': 'shield_subscription', 'target': 'resource', 'severity': 'low', 'category': 'hardening',
     'title': 'Active Shield Advanced subscription has a configured DRT role', 'evaluator': 'shield_drt_role_configured',
     'dependencies': ['shield_subscription', 'shield_drt_access'], 'control': 'IR-4'},
]


def _runtime_cases():
    account, region = '123456789012', 'us-east-1'
    scope = account + '/' + region
    def envelope(kind, items, *, global_scope=False):
        return {'type': kind, 'scope': account + '/global' if global_scope else scope, 'account_id': account,
                'global': global_scope, 'status': 'collected' if items else 'empty', 'items': items}
    cluster = {'name': 'example', 'Cluster': {'collection_status': 'collected', 'cluster': {
        'name': 'example', 'arn': f'arn:aws:eks:{region}:{account}:cluster/example', 'version': '1.35'}}}
    def eks_index(status):
        catalog = {'region': region, 'versions': [{'clusterVersion': '1.35', 'versionStatus': status}],
                   '_provenance': {'source_operation': 'DescribeClusterVersions', 'read_only': True, 'includeAll': True}}
        return {'context': {'provider': 'aws', 'scope': scope}, 'collections': {
            'eks_cluster': [envelope('eks_cluster', [deepcopy(cluster)])],
            'eks_version_catalog': [envelope('eks_version_catalog', [catalog])]}}
    subscription = {'id': 'shield-subscription/' + account, 'AccountId': account, 'SubscriptionState': 'ACTIVE'}
    def shield_index(role):
        drt = {'id': account, 'AccountId': account, 'RoleArn': role, 'LogBucketList': [],
               '_provenance': {'source_operation': 'shield:DescribeDRTAccess', 'read_only': True}}
        return {'context': {'provider': 'aws', 'scope': account + '/global'}, 'collections': {
            'shield_subscription': [envelope('shield_subscription', [deepcopy(subscription)], global_scope=True)],
            'shield_drt_access': [envelope('shield_drt_access', [drt], global_scope=True)]}}
    return {EKS_ID: {'pass': cluster, 'fail': deepcopy(cluster), 'pass_index': eks_index('STANDARD_SUPPORT'),
                     'fail_index': eks_index('UNSUPPORTED'), 'missing': {}, 'malformed': None},
            SHIELD_ID: {'pass': subscription, 'fail': deepcopy(subscription),
                        'pass_index': shield_index(f'arn:aws:iam::{account}:role/DRT'),
                        'fail_index': shield_index(''), 'missing': {}, 'malformed': None}}


RUNTIME_CASES = _runtime_cases()


ADMISSION_DATA = {'schema_version': 1,
 'checks': [{'spec': {'id': 'aws.review.eks.native_version_supported',
                      'provider': 'aws',
                      'resource_kind': 'eks_cluster',
                      'data_source': 'Cluster.cluster.arn, Cluster.cluster.name, Cluster.cluster.version, '
                                     'complete same-scope eks_cluster and eks_version_catalog envelopes, '
                                     'versions[].versionStatus, _provenance.includeAll',
                      'predicate': 'AWS explicitly reports UNSUPPORTED for the matching cluster version. '
                                   'UNKNOWN: required native evidence is missing, denied, partial, foreign, '
                                   'duplicated or malformed.',
                      'severity': 'medium',
                      'category': 'hardening',
                      'title': 'EKS cluster version has native AWS support',
                      'description': 'Checks the actual AWS-reported support status of an EKS cluster '
                                     'version using a complete regional catalog. It accepts standard and '
                                     'extended support; it does not choose an owner-approved version floor '
                                     'or approve extended-support spending.',
                      'remediation_hint': 'Upgrade an unsupported EKS cluster version to a version supported '
                                          'by AWS; separately review the desired support tier and charges.'},
             'description': {'description': 'Checks the actual AWS-reported support status of an EKS cluster '
                                            'version using a complete regional catalog. It accepts standard '
                                            'and extended support; it does not choose an owner-approved '
                                            'version floor or approve extended-support spending.',
                             'evaluated': ['Cluster.cluster.arn',
                                           'Cluster.cluster.name',
                                           'Cluster.cluster.version',
                                           'complete same-scope eks_cluster and eks_version_catalog '
                                           'envelopes',
                                           'versions[].versionStatus',
                                           '_provenance.includeAll'],
                             'pass_when': 'Matching complete native DescribeClusterVersions catalog reports '
                                          'STANDARD_SUPPORT or EXTENDED_SUPPORT for the cluster version.',
                             'fail_when': 'AWS explicitly reports UNSUPPORTED for the matching cluster '
                                          'version.',
                             'not_applicable_when': 'Only collected EKS clusters are evaluated.'},
             'sources': [{'url': 'https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeClusterVersions.html',
                          'sha256': 'a7e6674091be1dd5697832e801a7e4f4911a733037a45e9a5126b898b0636ecb'},
                         {'url': 'https://docs.aws.amazon.com/eks/latest/APIReference/API_ClusterVersionInformation.html',
                          'sha256': '9f9412afd9a8108aacd4283cee69ddabdab1a9f55b5ec3901a006aba033ce343'}],
             'requirements': [],
             'dependencies': ['eks_cluster', 'eks_version_catalog'],
             'target': 'resource',
             'review_notes': 'A bounded native configuration alternative; the broader archived owner-policy '
                             'control remains excluded. No new collector APIs and no approval universe are '
                             'invented. Version absent from the complete catalog remains UNKNOWN; deprecated '
                             'lowercase status is never silently promoted to versionStatus.',
             'function': 'peaso.checks.aws_service_status_review_20261019:eks_version_supported'},
            {'spec': {'id': 'aws.review.shield.drt_role_configured',
                      'provider': 'aws',
                      'resource_kind': 'shield_subscription',
                      'data_source': 'SubscriptionState, AccountId, complete account-global '
                                     'shield_subscription and shield_drt_access envelopes, RoleArn, '
                                     '_provenance.source_operation',
                      'predicate': 'Active Shield Advanced subscription has a proven native empty DRT '
                                   'RoleArn. UNKNOWN: required native evidence is missing, denied, partial, '
                                   'foreign, duplicated or malformed.',
                      'severity': 'low',
                      'category': 'hardening',
                      'title': 'Active Shield Advanced subscription has a configured DRT role',
                      'description': 'Checks whether an active Shield Advanced account has a configured DRT '
                                     'role. It does not establish the role trust policy, effective support '
                                     'access, log-bucket approval or complete incident readiness.',
                      'remediation_hint': 'Configure a reviewed Shield DRT role if desired for the active '
                                          'subscription; separately validate trust, permissions and '
                                          'log-bucket approvals.'},
             'description': {'description': 'Checks whether an active Shield Advanced account has a '
                                            'configured DRT role. It does not establish the role trust '
                                            'policy, effective support access, log-bucket approval or '
                                            'complete incident readiness.',
                             'evaluated': ['SubscriptionState',
                                           'AccountId',
                                           'complete account-global shield_subscription and '
                                           'shield_drt_access envelopes',
                                           'RoleArn',
                                           '_provenance.source_operation'],
                             'pass_when': 'Active Shield Advanced subscription has a native same-account DRT '
                                          'role ARN configured.',
                             'fail_when': 'Active Shield Advanced subscription has a proven native empty DRT '
                                          'RoleArn.',
                             'not_applicable_when': 'Native subscription state is INACTIVE.'},
             'sources': [{'url': 'https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_GetSubscriptionState.html',
                          'sha256': '1483e25b556a9f1424ccaf2c906ae48780ba954cec220dff53a7c61da4e24885'},
                         {'url': 'https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_DescribeDRTAccess.html',
                          'sha256': '58e3479d0654b5bb76ac687f9620525b273944c32bacc546fd7beb581b73ae8b'}],
             'requirements': [],
             'dependencies': ['shield_subscription', 'shield_drt_access'],
             'target': 'resource',
             'review_notes': 'A bounded native configuration alternative; the broader archived owner-policy '
                             'control remains excluded. No new collector APIs and no approval universe are '
                             'invented. Account-global subscription resource is evaluated once across '
                             'selected Regions; only configured DRT role presence is claimed.',
             'function': 'peaso.checks.aws_service_status_review_20261019:shield_drt_role_configured'}]}
