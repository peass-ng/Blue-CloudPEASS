"""Section watermarks retain exact scope, completion and revision semantics."""
import copy
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('sections',
    Path(__file__).resolve().parents[1]/'peaso/scan_sections.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_aws_global_reads_deduplicate_accounts_without_completing_missing_regions():
    scopes = ['123456789012/us-east-1', '123456789012/eu-west-1',
              '999999999999/us-east-1', '123456789012/us-east-1']
    needed = {'network': {'vpc', 'iam_role'}}
    rows = {('vpc', scope): {'status': 'denied'} for scope in scopes[:2]}
    rows['iam_role', '123456789012/global'] = {'status': 'unknown'}
    revisions = {key: 2 for key in rows}
    result = module.states('aws', scopes, needed, rows, revisions, global_types={'iam_role'})
    assert result['network'] == dict(status='running', data_revision=2,
        completed_collections=3, expected_collections=5)
    rows['vpc', scopes[2]] = {}
    rows['iam_role', '999999999999/global'] = {}
    rows['vpc', 'outside'] = {}
    revisions['vpc', 'outside'] = 100
    result = module.states('aws', scopes, needed, rows, revisions, global_types={'iam_role'})
    assert result['network'] == dict(status='complete', data_revision=100,
        completed_collections=5, expected_collections=5)


@pytest.mark.parametrize('provider', ['k8s', 'azure'])
def test_cluster_or_tenant_singletons_keep_one_expected_read(provider):
    rows = {('global_kind', 'global'): {'status': 'partial'},
            ('local_kind', 'a'): {'status': 'unknown'}, ('local_kind', 'b'): {'status': 'denied'}}
    result = module.states(provider, ['a', 'b'], {'network': {'global_kind', 'local_kind'}},
        rows, {key: 7 for key in rows}, global_types={'global_kind'}, global_scope='global')
    assert result['network'] == dict(status='complete', data_revision=7,
        completed_collections=3, expected_collections=3)


def test_gcp_does_not_collapse_global_types_across_selected_scopes():
    result = module.states('gcp', ['a', 'b'], {'network': {'kind'}}, {('kind', 'a'): {}},
                           {}, global_types={'kind'}, global_scope='global')
    assert result['network'] == dict(status='running', data_revision=0,
        completed_collections=1, expected_collections=2)


@pytest.mark.parametrize('provider,scopes', [('aws', []), ('aws', ['*']), ('azure', ['/']), ('gcp', ['*'])])
@pytest.mark.parametrize('finished', [False, True])
def test_dynamic_scope_plan_waits_until_sealed(provider, scopes, finished):
    rows = {('kind', 'a'): {}, ('kind', 'b'): {}}
    result = module.states(provider, scopes, {'network': {'kind'}}, rows,
        {('kind', 'a'): 9}, finished=finished)
    assert result['network'] == dict(status='complete' if finished else 'running',
        data_revision=9, completed_collections=2, expected_collections=None)


def test_kubernetes_wildcard_retains_explicit_scope_behavior():
    result = module.states('k8s', ['*'], {'network': {'kind'}}, {('kind', 'a'): {}}, {})
    assert result['network'] == dict(status='running', data_revision=0,
        completed_collections=0, expected_collections=1)


def test_duplicate_dependencies_and_missing_revisions_do_not_mutate_inputs():
    scopes, needed = ['a', 'a'], {'network': ['kind', 'kind'], 'images': set()}
    rows, revisions = {('kind', 'a'): {'status': 'empty'}}, {}
    before = copy.deepcopy((scopes, needed, rows, revisions))
    result = module.states('gcp', scopes, needed, rows, revisions, finished=True)
    assert result == {'network': dict(status='complete', data_revision=0,
        completed_collections=1, expected_collections=1),
        'images': dict(status='not_selected', data_revision=0)}
    assert (scopes, needed, rows, revisions) == before


def test_revision_is_maximum_observed_even_outside_expected_scopes():
    rows = {('kind', 'other'): {}, ('kind2', 'a'): {}}
    result = module.states('gcp', ['a'], {'network': {'kind', 'kind2'}}, rows,
        {('kind', 'other'): -3, ('kind2', 'a'): -8, ('unused', 'a'): 100})
    assert result['network'] == dict(status='running', data_revision=-3,
        completed_collections=1, expected_collections=2)


def test_nonpair_keys_never_count_as_completed_expected_reads():
    rows = {('kind', 'a', 'extra'): {}}
    result = module.states('gcp', ['a'], {'network': {'kind'}}, rows,
                           {('kind', 'a', 'extra'): 4})
    assert result['network'] == dict(status='running', data_revision=4,
        completed_collections=0, expected_collections=1)
