"""Prepared references preserve exact review documents and authorization hashes."""
import copy

import pytest

from peaso.ai import pipeline


def fixture(provider, access):
    scope = {'aws': '123456789012/us-east-1', 'gcp': 'projects/synthetic',
             'azure': 'subscriptions/synthetic', 'k8s': 'namespace-a'}[provider]
    inventory = {key: {'id': key, 'type': 'synthetic', 'scope': scope,
        'data': {'recorded_label': 'λ', 'references': ['r2']}}
        for key in ('r1', 'r2', 'unrelated')}
    row = {'id': 'finding', 'check_id': 'unit.synthetic', 'provider': provider,
        'scope': scope, 'resource_id': 'r1', 'status': 'UNKNOWN',
        'evidence': {'references': ['r1', 'r1'], 'cluster_id': 'cluster-a'}}
    report = {'provider': provider, 'snapshot_id': 'checkpoint', 'created_at': 'time'}
    entry = {'provider': provider, 'target_scopes': [scope], 'captured_at': 100, 'expires_at': 200,
             'account_id': '123456789012', 'cluster_id': 'cluster-a', 'audience': 'synthetic'}
    entries = [] if access == 'none' else [entry if access == 'matching' else dict(entry, provider='other')]
    return report, inventory, row, entries


# Filled from the unchanged baseline's full document/access hashing path.
GOLDEN = {
    ('aws', 'none'): 'e39bb1d9d41751c87bca19626c56a2ffa2c960da55fd17462fb0fdbece1d6775',
    ('aws', 'matching'): 'f783ed669686b36b43f13a46024328ef0df9bd32aac050a1e9ceed6c0c537bba',
    ('aws', 'other-provider'): 'e39bb1d9d41751c87bca19626c56a2ffa2c960da55fd17462fb0fdbece1d6775',
    ('gcp', 'none'): '78d0f5e2a34e83b0eee799538347da7dfe7af4a850cd5025f5aed6e7cc1d9f3e',
    ('gcp', 'matching'): '5d2771255be2addc85946e0cea6dc60a39c098077d355a9d09c164b55907f54e',
    ('gcp', 'other-provider'): '78d0f5e2a34e83b0eee799538347da7dfe7af4a850cd5025f5aed6e7cc1d9f3e',
    ('azure', 'none'): '0f55b62d9e96351f36038faa7a840d837a61da680ebb1c137e5eb3be5ea26490',
    ('azure', 'matching'): 'fb1770bdb248feac6652ce7efb8e26fb32cd2bddcc6f99d9bec1a84b9a72abe9',
    ('azure', 'other-provider'): '0f55b62d9e96351f36038faa7a840d837a61da680ebb1c137e5eb3be5ea26490',
    ('k8s', 'none'): '58d7e15ad17c4e1a2aa6e18ea42a1538a565a6b6da53f701d1c38e2e959a3be4',
    ('k8s', 'matching'): 'ce4d6627a1c8e76d8e6723896634fee64d1e90a6c796d03bbbf660c3ca247d3b',
    ('k8s', 'other-provider'): '58d7e15ad17c4e1a2aa6e18ea42a1538a565a6b6da53f701d1c38e2e959a3be4',
}


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
@pytest.mark.parametrize('access', ['none', 'matching', 'other-provider'])
def test_exact_fingerprints_match_baseline(provider, access):
    report, inventory, row, entries = fixture(provider, access)
    original = copy.deepcopy((report, inventory, row, entries))
    value = pipeline.review_fingerprints(report, inventory, [row],
        identity={'owner': 'synthetic', 'access_reference': 'sealed'}, entries=entries)
    assert value['finding'] == GOLDEN[provider, access]
    assert (report, inventory, row, entries) == original


def test_references_are_recomputed_after_evidence_and_native_changes():
    report, inventory, row, entries = fixture('aws', 'matching')

    def fingerprint():
        return pipeline.review_fingerprints(report, inventory, [row], identity={}, entries=entries)

    first = fingerprint()
    row['evidence']['references'].append('r2')
    second = fingerprint()
    assert second != first
    inventory['r2']['data']['recorded_label'] = 'fresh'
    third = fingerprint()
    assert third != second
    entries[0]['expires_at'] += 1
    changed = fingerprint()
    assert changed != third
    entries[0]['captured_at'] += 1
    assert fingerprint() != changed


def test_prepared_helpers_preserve_mapped_resource_identity_and_duplicate_rows():
    report, inventory, row, _ = fixture('gcp', 'none')
    inventory['r1']['id'] = 'alias'
    refs = set(pipeline.referenced_strings([row]))
    expected = pipeline.review_context(report, inventory, [row])
    assert pipeline.review_context(report, inventory, [row], _references=refs) == expected
    document = pipeline.findings_document(report, [row, row], expected['resources'])
    assert pipeline.findings_document(report, [row, row], expected['resources'],
                                     _references=(refs, refs)) == document
    assert document['items'][0]['supporting_resources'] == []


def test_no_provider_access_still_validates_scope_row_shapes():
    with pytest.raises(AttributeError):
        pipeline.review_credentials([], 'aws', [None], {})
