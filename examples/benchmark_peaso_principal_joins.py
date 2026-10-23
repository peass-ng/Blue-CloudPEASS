"""Complete principal-exposure projection with former literal relationship scans.

python -m examples.benchmark_peaso_principal_joins --provider gcp --principals 3000

Runs the real provider projection and network/workload stage on native fixtures.
GCP scope candidates retain the complete original scope/ancestry predicate.
The AWS case is a control for its existing policy index.
"""
import argparse
import hashlib
import json
import statistics
import time
from unittest.mock import patch

import peaso.principal_exposure as exposure
from peaso.analysis import cloud_workload_index
from examples.benchmark_peaso_cloud_workloads import LinearCloudWorkloads
from peaso.snapshot import digest, make_snapshot, resources


def synthetic_snapshot(provider, principals):
    if principals < 1:
        raise ValueError('principals must be positive')
    if provider == 'gcp':
        cols = []
        for i in range(principals):
            scope = f'projects/fixture-{i}'
            cols.extend([{'type': 'service_account', 'scope': scope, 'status': 'collected', 'items': [
                {'name': scope + '/serviceAccounts/workload', 'email': f'workload@fixture-{i}.iam.gserviceaccount.com'}]},
                {'type': 'iam_policy', 'scope': scope, 'status': 'collected', 'items': [{'name': scope,
                    'bindings': [{'role': 'roles/iam.serviceAccountTokenCreator',
                                  'members': ['allUsers', 'allAuthenticatedUsers']}]}]}])
        return make_snapshot(provider, [f'projects/fixture-{i}' for i in range(principals)], cols)
    if provider == 'aws':
        account, scope = '111111111111', '111111111111/global'
        policies = [{'Arn': f'arn:aws:iam::{account}:policy/p-{i}', 'PolicyVersionList': [{'IsDefaultVersion': True,
            'Document': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}]} for i in range(principals)]
        roles = [{'Arn': f'arn:aws:iam::{account}:role/r-{i}', 'RoleName': f'r-{i}',
            'AssumeRolePolicyDocument': {'Statement': []}, 'AttachedManagedPolicies': [
                {'PolicyArn': policies[i % 10]['Arn']}]} for i in range(principals)]
        return make_snapshot(provider, [scope], [
            {'type': 'iam_policy', 'scope': scope, 'status': 'collected', 'items': policies},
            {'type': 'iam_role', 'scope': scope, 'status': 'collected', 'items': roles}])
    raise ValueError('provider must be aws or gcp')


def compare(provider='gcp', principals=3000):
    snapshot = synthetic_snapshot(provider, principals)
    inventory = resources(snapshot)
    original = digest(snapshot)
    results = {}
    optimized = cloud_workload_index.CloudWorkloadIndex
    for name, factory in (('baseline', LinearCloudWorkloads), ('optimized', optimized)):
        elapsed, fingerprints = [], []
        with patch.object(cloud_workload_index, 'CloudWorkloadIndex', factory):
            for _ in range(3):
                started = time.perf_counter()
                output = exposure.project(snapshot, inventory)
                elapsed.append(round(time.perf_counter() - started, 6))
                fingerprints.append(hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest())
        assert len(set(fingerprints)) == 1
        results[name] = {'seconds': elapsed, 'output_digest': fingerprints[0]}
    assert results['baseline']['output_digest'] == results['optimized']['output_digest']
    assert digest(snapshot) == original
    return {**results, 'provider': provider, 'resources': len(inventory), 'principal_cards': len(output),
        'exposures': sum(len(card['exposures']) for card in output.values()),
        'grant_reviews': sum(len(card['grant_reviews']) for card in output.values()),
        'identical_output': True, 'input_unchanged': True, 'cloud_calls': 0,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'limitations': 'Synthetic complete principal-exposure projection, including native workload/network assessment. '
                       'Excludes checks, graph construction, other analyses, rendering and cloud collection.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('aws', 'gcp'), default='gcp')
    parser.add_argument('--principals', type=int, default=3000)
    args = parser.parse_args()
    print(json.dumps(compare(args.provider, args.principals), indent=2))
