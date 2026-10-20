"""Native asymmetric detector proof and uninstalled paired-producer proposal."""
from copy import deepcopy
import json

import pytest

from peaso.checks import gcp_function_secret_review_20261019 as original
from peaso.checks import gcp_function_secret_partial_positive_candidate_20261020 as candidate
from peaso.collectors import gcp_function_secret_indicators as installed_projection
from peaso.collectors import gcp_function_secret_pairs_candidate_20261020 as proposed_projection
from peaso.secret_scanning import merge_leaks
from tests.gcp_function_partial_positive_native_20261020 import (
    TOKEN, URL, SCOPE, collect_native, index_for, raw,
)
from tests.test_gcp_function_secret_partial_positive_20261020 import MALFORMED, corrupt


@pytest.fixture(scope='module')
def native_asymmetric():
    with pytest.MonkeyPatch.context() as patch:
        envelope, receipt, _ = collect_native(patch, raw({'SETTING': TOKEN}, {'BUILD': TOKEN}),
            asymmetric=True, paired_projection=True)
    installed, = envelope['items']
    proposed, = receipt['proposed_rows']
    original_marker = installed[installed_projection.MARKER]
    paired_marker = proposed[installed_projection.MARKER]
    assert receipt['ordinary_inventory_status'] == 'collected' and receipt['ordinary_items'] == 1
    assert receipt['proposed_hook_installed'] is False
    assert original_marker['complete'] is False and paired_marker['complete'] is False
    assert original_marker['leaks'] == paired_marker['leaks']
    leak, = original_marker['leaks']
    assert {detector['engine'] for detector in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert {loc['path'] for loc in leak['locations']} == {
        'serviceConfig.environmentVariables', 'buildConfig.environmentVariables'}
    for surface, completed in zip(paired_marker['surfaces'], ['kingfisher', 'trufflehog']):
        assert {engine['engine'] for engine in surface['engines'] if engine['status'] == 'complete'} == {completed}
        assert {detector['engine'] for hit in surface['leaks'] for detector in hit['detectors']} == {completed}
        assert {loc['path'] for hit in surface['leaks'] for loc in hit['locations']} == {
            surface['surface'] + '.environmentVariables'}
    assert len(receipt['http_calls']) == 2
    assert len(receipt['detector_runs']) == 8  # standalone proposal + unchanged installed projection
    return installed, proposed, receipt


@pytest.mark.xfail(strict=True, reason='Installed v1 projection loses the asymmetric detector/location pairing')
def test_v1_native_asymmetric_positive_required(native_asymmetric):
    installed, _, _ = native_asymmetric
    # --runxfail is the actual limit red proof, using real SDK/binary hits.
    assert candidate.evaluate(installed, index_for(installed))[0] == 'FAIL'


def test_native_v1_limit_and_v2_supported_positive(native_asymmetric):
    installed, proposed, receipt = native_asymmetric
    assert original.evaluate(installed, index_for(installed))[0] == 'UNKNOWN'
    assert candidate.evaluate(installed, index_for(installed))[0] == 'UNKNOWN'
    before = deepcopy(proposed)
    status, evidence = candidate.evaluate(proposed, index_for(proposed))
    assert status == 'FAIL' and evidence['complete'] is False
    assert proposed == before
    assert evidence['surfaces'] == proposed[installed_projection.MARKER]['surfaces']
    assert evidence['secret_leaks'] == proposed[installed_projection.MARKER]['leaks']
    assert TOKEN not in json.dumps([installed, proposed, evidence, receipt])


@pytest.mark.parametrize('case', MALFORMED)
def test_original_projection_guards_remain_for_v2(native_asymmetric, case):
    proposed = deepcopy(native_asymmetric[1])
    corrupt(proposed, case)
    assert candidate.evaluate(proposed, index_for(proposed))[0] == 'UNKNOWN', case


@pytest.mark.parametrize('case', [
    'missing_pairs', 'pairs_not_list', 'fabricated_runtime_hit', 'fabricated_build_hit',
    'foreign_surface_location', 'missing_global_hit', 'missing_local_hit',
    'fabricated_global_hit', 'foreign_local_metadata', 'mismatched_fingerprint',
    'zero_pairs_with_hit', 'too_many_local_hits', 'too_many_local_locations',
])
def test_paired_attribution_rejects_fabrication_and_contradictions(native_asymmetric, case):
    proposed = deepcopy(native_asymmetric[1])
    marker = proposed[installed_projection.MARKER]
    runtime, build = marker['surfaces']
    if case == 'missing_pairs': del runtime['leaks']
    elif case == 'pairs_not_list': runtime['leaks'] = {}
    elif case == 'fabricated_runtime_hit': runtime['leaks'][0]['detectors'][0]['engine'] = 'trufflehog'
    elif case == 'fabricated_build_hit': build['leaks'][0]['detectors'][0]['engine'] = 'kingfisher'
    elif case == 'foreign_surface_location': runtime['leaks'][0]['locations'][0]['path'] = 'buildConfig.environmentVariables'
    elif case == 'missing_global_hit': marker['leaks'] = []
    elif case == 'missing_local_hit': runtime['leaks'] = []
    elif case == 'fabricated_global_hit': marker['leaks'][0]['detectors'].append({'engine': 'trufflehog', 'rule': 'fabricated'})
    elif case == 'foreign_local_metadata': runtime['leaks'][0]['locations'][0]['scope'] = 'projects/foreign'
    elif case == 'mismatched_fingerprint': runtime['leaks'][0]['fingerprint'] = 'a' * 64
    elif case == 'zero_pairs_with_hit': runtime['pairs'] = 0
    elif case == 'too_many_local_hits': runtime['leaks'] *= installed_projection.MAX_LEAKS + 1
    elif case == 'too_many_local_locations':
        runtime['leaks'][0]['locations'] = [
            {'path': 'serviceConfig.environmentVariables', 'line': i + 1}
            for i in range(installed_projection.MAX_LOCATIONS + 1)]
    assert candidate.evaluate(proposed, index_for(proposed))[0] == 'UNKNOWN', case


def test_schema_downgrade_cannot_authenticate_extra_pairs(native_asymmetric):
    proposed = deepcopy(native_asymmetric[1])
    proposed[installed_projection.MARKER]['schema'] = installed_projection.SCHEMA
    assert candidate.evaluate(proposed, index_for(proposed))[0] == 'UNKNOWN'


@pytest.mark.parametrize('positive', [True, False])
@pytest.mark.parametrize('partial', [True, False])
def test_paired_native_complete_and_partial_verdicts(monkeypatch, positive, partial):
    envelope, receipt, _ = collect_native(monkeypatch,
        raw({'SETTING': TOKEN if positive else 'production'}, {'BUILD': TOKEN if positive else 'release'}),
        unavailable_second=partial, paired_projection=True)
    proposed, = receipt['proposed_rows']
    installed, = envelope['items']
    status, evidence = candidate.evaluate(proposed, index_for(proposed))
    assert status == ('FAIL' if positive else 'UNKNOWN' if partial else 'PASS')
    if status != 'UNKNOWN':
        assert evidence['complete'] is (not partial)
    if not partial:
        original_status, original_evidence = original.evaluate(installed, index_for(installed))
        assert status == original_status
        assert evidence['secret_leaks'] == original_evidence['secret_leaks']
        assert evidence['observed'] == original_evidence['observed']


@pytest.mark.parametrize('case', [
    'unbound_request', 'missing_source', 'sanitized_source', 'foreign_source',
    'malformed_source', 'partial_response', 'denied_collection', 'unreachable', 'disabled',
    'declared_managed_reference',
])
def test_paired_producer_preserves_original_native_source_boundaries(monkeypatch, case):
    # Original native tests already exercise installed HTTP and source guards;
    # these checks ensure the standalone source-derived producer keeps them.
    source = raw({'SETTING': TOKEN})
    options = {'method': 'GET', 'url': URL, 'scope': SCOPE, 'enabled': True}
    response = {'functions': [source]}
    if case == 'unbound_request': options['url'] = URL + '?fields=name'
    elif case == 'missing_source': del source['buildConfig']
    elif case == 'sanitized_source': source['serviceConfig'] = {'environmentVariableNames': ['SETTING']}
    elif case == 'foreign_source': source['name'] = source['name'].replace('/review/', '/foreign/')
    elif case == 'malformed_source': source['buildConfig']['environmentVariables'] = []
    elif case == 'partial_response': options['response_complete'] = False
    elif case == 'denied_collection': options['collection_status'] = 'denied'
    elif case == 'unreachable': response['unreachable'] = ['us-central1']
    elif case == 'disabled': options['enabled'] = False
    elif case == 'declared_managed_reference':
        source['serviceConfig']['environmentVariables'] = {}
        source['serviceConfig']['secretEnvironmentVariables'] = [
            {'key': 'CREDENTIAL', 'projectId': 'review', 'secret': 'managed-token', 'version': 'latest'}]
    if case != 'declared_managed_reference':
        monkeypatch.setattr(proposed_projection, 'scan_content',
                            lambda *args, **kwargs: pytest.fail('invalid source scanned'))
    projected, = proposed_projection.project_response(response, **options)['functions']
    result = candidate.evaluate(projected, index_for(projected))
    assert result[0] == ('PASS' if case == 'declared_managed_reference' else 'UNKNOWN')
    if case == 'declared_managed_reference':
        assert projected[installed_projection.MARKER]['leaks'] == []


def test_pair_evidence_cannot_be_replaced_with_union(native_asymmetric):
    proposed = deepcopy(native_asymmetric[1])
    marker = proposed[installed_projection.MARKER]
    # A simple branch move or naive global completed-engine union would accept
    # this. Local authoritative rows must retain their own supported detectors.
    for surface in marker['surfaces']:
        surface['leaks'] = deepcopy(marker['leaks'])
    assert candidate.evaluate(proposed, index_for(proposed))[0] == 'UNKNOWN'


def test_pair_union_is_derived_exactly_from_local_evidence(native_asymmetric):
    marker = native_asymmetric[1][installed_projection.MARKER]
    assert marker['leaks'] == merge_leaks([
        leak for surface in marker['surfaces'] for leak in surface['leaks']])


def test_existing_grouping_retains_incomplete_flag_but_drops_pairs_limit(native_asymmetric):
    from peaso.secret_findings import deduplicate_secret_findings
    proposed = native_asymmetric[1]
    status, evidence = candidate.evaluate(proposed, index_for(proposed))
    grouped, = deduplicate_secret_findings([{
        'provider': 'gcp', 'check_id': original.CHECK_ID, 'scope': SCOPE,
        'resource_id': proposed['name'], 'native_resource_id': proposed['name'],
        'resource_type': 'function', 'finding_type': 'secrets', 'frameworks': [],
        'status': status, 'evidence': evidence}])
    assert grouped['status'] == 'FAIL' and grouped['evidence']['complete'] is False
    # Explicit unresolved consumer integration: the installed grouping only
    # retains the global union, so local attribution must be preserved by a
    # separately reviewed grouping/evidence successor before end-to-end claims.
    assert 'surfaces' not in grouped['evidence']
    assert TOKEN not in json.dumps(grouped)
