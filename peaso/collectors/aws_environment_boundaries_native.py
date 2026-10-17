"""Explicit environment criteria, passive EC2 classification and imported links.

EC2 is a supported subset, never the complete cross-service workload universe.
Imported observations stay distinguishable from native AWS network metadata.
"""
import copy
from datetime import datetime
import json
import re

NAMESPACE = 'aws_environment_separation'
SPECS = {kind: ('ec2', 'describe_instances', 'Reservations[].Instances[]') for kind in
         ('environment_workload_resource', 'environment_boundary_link')}
NATIVE_IDS = {kind: 'id' for kind in SPECS}
READ_ACTIONS = {('ec2', 'describe_instances')}
_SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9])\Z')
_ENV = {'production', 'development', 'test'}


def _date(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('environment timestamp invalid')
    value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if value.utcoffset() is None:
        raise ValueError('environment timestamp requires timezone')
    return value


def normalize(options, scopes=None):
    parameters = options.get('compliance_parameters', {})
    if not isinstance(parameters, dict):
        raise ValueError('compliance parameters must be an object')
    if NAMESPACE not in parameters:
        return None
    raw = parameters[NAMESPACE]
    fields = {'status', 'scope', 'observed_at', 'max_age_seconds', 'environment_boundaries', 'workload_classifications'}
    if (not isinstance(raw, dict) or set(raw) - fields - {'boundary_evidence'} or not fields <= set(raw)
            or len(json.dumps(raw, allow_nan=False)) > 50000 or raw['status'] != 'collected'
            or not isinstance(raw['scope'], str) or not _SCOPE.fullmatch(raw['scope'])
            or type(raw['max_age_seconds']) is not int or not 1 <= raw['max_age_seconds'] <= 86400):
        raise ValueError('environment owner criteria invalid')
    _date(raw['observed_at'])
    if scopes is not None and scopes != [raw['scope']]:
        raise ValueError('environment criteria require one exact account/region')
    bounds = raw['environment_boundaries']
    if not isinstance(bounds, dict) or set(bounds) != {'production', 'development'}:
        raise ValueError('environment approved boundaries invalid')
    for values in bounds.values():
        if (not isinstance(values, list) or not 1 <= len(values) <= 32
                or any(not isinstance(v, str) or not re.fullmatch(r'[0-9]{12}', v) for v in values)
                or len(set(values)) != len(values)):
            raise ValueError('environment approved boundaries invalid')
    classifications = raw['workload_classifications']
    if not isinstance(classifications, list) or len(classifications) > 256:
        raise ValueError('environment classifications invalid')
    account, region = raw['scope'].split('/')
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    pattern = f'arn:{partition}:ec2:{region}:{account}:instance/i-(?:[0-9a-f]{{8}}|[0-9a-f]{{17}})'
    seen = set()
    for row in classifications:
        if (not isinstance(row, dict) or set(row) != {'resource_arn', 'environment'}
                or not isinstance(row['resource_arn'], str) or not re.fullmatch(pattern, row['resource_arn'])
                or not isinstance(row['environment'], str) or row['environment'] not in _ENV
                or row['resource_arn'] in seen):
            raise ValueError('environment classification identity invalid')
        seen.add(row['resource_arn'])
    if 'boundary_evidence' in raw:
        evidence = raw['boundary_evidence']
        if (not isinstance(evidence, dict) or set(evidence) !=
                {'status', 'scope', 'observed_at', 'source_id', 'complete', 'observations'}
                or evidence['status'] != 'collected' or evidence['scope'] != raw['scope']
                or not isinstance(evidence['source_id'], str) or not 1 <= len(evidence['source_id']) <= 256
                or type(evidence['complete']) is not bool or not isinstance(evidence['observations'], list)
                or len(evidence['observations']) > 1024):
            raise ValueError('environment observed evidence invalid')
        _date(evidence['observed_at'])
        boundaries = set(bounds['production']) | set(bounds['development'])
        pairs = set()
        for row in evidence['observations']:
            if (not isinstance(row, dict) or set(row) != {'source_boundary_id', 'destination_boundary_id', 'reachable'}
                    or not isinstance(row['source_boundary_id'], str) or not isinstance(row['destination_boundary_id'], str)
                    or row['source_boundary_id'] not in boundaries or row['destination_boundary_id'] not in boundaries
                    or row['source_boundary_id'] == row['destination_boundary_id'] or type(row['reachable']) is not bool):
                raise ValueError('environment observed link identity invalid')
            pair = (row['source_boundary_id'], row['destination_boundary_id'])
            if pair in pairs:
                raise ValueError('environment duplicate observed link')
            pairs.add(pair)
        if evidence['complete'] and pairs != {(left, right) for left in boundaries for right in boundaries if left != right}:
            raise ValueError('environment declared link coverage contradicts observations')
    # The flat legacy criterion consumed by SW48 must not compete with ours.
    if 'environment_boundaries' in parameters:
        raise ValueError('conflicting environment owner criteria')
    return copy.deepcopy(raw)


def _fresh(policy, now, stamp=None):
    if not isinstance(now, datetime) or now.utcoffset() is None:
        return False
    age = (now - _date(stamp or policy['observed_at'])).total_seconds()
    return 0 <= age <= policy['max_age_seconds']


def owner_metadata(policy, observed_at):
    if policy is None or not _fresh(policy, _date(observed_at) if isinstance(observed_at, str) else observed_at):
        return {}
    return {'environment_boundaries': copy.deepcopy(policy['environment_boundaries'])}


def _result(items=(), status='not_collected', code=None):
    from .aws import ReadResult
    return ReadResult(list(items), status, {'code': code} if code else None)


def _bound(requests, region, account):
    policy = getattr(requests, 'environment_boundaries_policy', None)
    if policy is None:
        return None
    policy = normalize({'compliance_parameters': {NAMESPACE: policy}}, [account + '/' + region])
    return policy if _fresh(policy, getattr(requests, 'observed_at', None)) else None


def workloads(requests, session, region, account):
    policy = _bound(requests, region, account)
    if policy is None:
        return _result(code='environment_owner_criteria_unavailable')
    read = requests.pages(session, 'ec2', region, 'describe_instances', 'Reservations[].Instances[]')
    if read.status not in {'collected', 'empty'}:
        return _result(status=read.status, code=(read.error or {}).get('code', 'environment_native_inventory_incomplete'))
    if not isinstance(read.items, list) or len(read.items) > 4096:
        return _result(code='environment_workload_projection_budget')
    approved = {row['resource_arn']: row['environment'] for row in policy['workload_classifications']}
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    rows, seen, matched = [], set(), set()
    for item in read.items:
        identifier = item.get('InstanceId') if isinstance(item, dict) else None
        if not isinstance(identifier, str) or not re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})', identifier) or identifier in seen:
            return _result(rows, 'partial' if rows else 'malformed', 'environment_native_identity_invalid')
        seen.add(identifier)
        arn = f'arn:{partition}:ec2:{region}:{account}:instance/{identifier}'
        if arn not in approved:
            continue
        matched.add(arn)
        rows.append({'id': arn, 'ResourceKind': 'instance', 'ResourceId': identifier,
                     'Environment': approved[arn], 'BoundaryId': account,
                     '_provenance': {'source_operation': 'ec2:DescribeInstances', 'read_only': True,
                                     'classification_source': 'explicit_owner_criteria',
                                     'native_scope': account + '/' + region}})
    # Even a complete EC2 LIST cannot certify all services, accounts or links.
    code = ('environment_classification_absent_from_native_inventory' if set(approved) - matched
            else 'environment_cross_service_workload_universe_unresolved')
    return _result(rows, 'partial', code)


def boundary_links(requests, session, region, account):
    policy = _bound(requests, region, account)
    if policy is None:
        return _result(code='environment_owner_criteria_unavailable')
    evidence = policy.get('boundary_evidence')
    if not evidence or not _fresh(policy, requests.observed_at, evidence['observed_at']):
        return _result(code='environment_observed_links_unavailable')
    rows = [{'id': row['source_boundary_id'] + '->' + row['destination_boundary_id'],
             'SourceBoundaryId': row['source_boundary_id'], 'DestinationBoundaryId': row['destination_boundary_id'],
             'Reachable': row['reachable'], '_provenance': {
                 'evidence_source': 'external_observation_import', 'source_id': evidence['source_id'],
                 'observed_at': evidence['observed_at'], 'native_aws_reachability_claimed': False}}
            for row in evidence['observations']]
    # Complete means only the externally supplied declared-boundary pair model;
    # it is not a native effective IAM/network/cross-service universe proof.
    return _result(rows, 'partial', 'environment_effective_cross_boundary_universe_unresolved')


FETCHERS = {'environment_workload_resource': workloads, 'environment_boundary_link': boundary_links}
