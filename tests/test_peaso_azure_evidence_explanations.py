"""Replay current native witnesses and bind every Azure explanation to its source."""
from copy import deepcopy
import gzip
import hashlib
import inspect
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS
from peaso.checks.catalog import description_for
from peaso.checks.azure_evidence_explanations import ROWS, evidence_summary, reviewed_explanation
from peaso.checks.azure_native_evidence_observations import evidence_summary as native_observation

ROOT = Path(__file__).resolve().parents[1]
CHECK_BY_ID = {check.id: check for check in CHECKS if check.provider == 'azure'}
LEDGER = json.loads((ROOT / 'docs/evidence-reviews/azure.json').read_text())
CASES = json.loads(gzip.decompress((ROOT / 'tests/fixtures/azure_evidence_review.json.gz').read_bytes()))


def test_every_registered_azure_check_has_a_reviewed_explicit_explanation_and_fixtures():
    assert len(CHECK_BY_ID) == 969
    assert set(ROWS) == set(CHECK_BY_ID) == set(LEDGER) == set(CASES)
    for cid, row in ROWS.items():
        assert row['purpose'] and row['limit'] and row['label']
        assert len((row['purpose'] + ' ' + row['limit']).split()) <= 30
        assert LEDGER[cid]['missing_fixtures'] == []
        assert LEDGER[cid]['branch_coverage']
        assert CASES[cid]


@pytest.mark.parametrize('cid', sorted(CHECK_BY_ID))
def test_each_explanation_is_bound_to_the_current_exact_evaluator_and_contract(cid):
    function = inspect.unwrap(CHECK_BY_ID[cid].evaluate)
    assert hashlib.sha256(inspect.getsource(function).encode()).hexdigest() == LEDGER[cid]['source_sha256']
    encoded = json.dumps(description_for(cid), sort_keys=True, separators=(',', ':')).encode()
    assert hashlib.sha256(encoded).hexdigest() == LEDGER[cid]['description_contract_sha256']
    assert LEDGER[cid]['interpretation'] == ROWS[cid]['purpose']
    assert LEDGER[cid]['evidence_limit'] == ROWS[cid]['limit']


@pytest.mark.parametrize('cid', sorted(CASES))
def test_actual_native_positive_negative_unknown_manual_and_inapplicable_witnesses(cid):
    for case in CASES[cid]:
        item, index = deepcopy((case['item'], case['index']))
        status, evidence = CHECK_BY_ID[cid].evaluate(item, index)
        assert status == case['status'], (cid, case['status'], status, evidence)
        assert json.loads(json.dumps(evidence, sort_keys=True)) == case['evidence']
        finding = {'provider': 'azure', 'check_id': cid, 'status': status, 'evidence': evidence}
        before = deepcopy(finding)
        summary = evidence_summary(finding)
        assert finding == before
        if summary:
            assert status in {'PASS', 'FAIL'}
            assert ROWS[cid]['purpose'] in summary
            assert ROWS[cid]['limit'] in summary
            assert '{' not in summary and '\n' not in summary
            assert reviewed_explanation(cid, summary, status) == summary
        elif status not in {'PASS', 'FAIL'}:
            assert native_observation(finding) is None


def test_unrecognized_native_shapes_and_uncertain_statuses_do_not_become_positive_claims():
    for cid in ('azure.other.gateway_vmss_autoscale', 'azure_search_service_10_6_3_27_ba08488'):
        for status in ('PASS', 'FAIL', 'UNKNOWN', 'MANUAL', 'NOT_APPLICABLE'):
            assert evidence_summary({'provider': 'azure', 'check_id': cid, 'status': status, 'evidence': {}}) is None
    assert evidence_summary({'provider': 'aws', 'check_id': 'azure.storage.https_only', 'status': 'FAIL', 'evidence': {'supports_https_traffic_only': False}}) is None
    assert reviewed_explanation('azure.unreviewed', 'An unreviewed fact.') is None


def test_scalar_observation_uses_actual_value_and_does_not_claim_runtime_access():
    summary = evidence_summary({'provider': 'azure', 'check_id': 'azure.storage.no_shared_key', 'status': 'FAIL',
                                'evidence': {'field': 'properties.allowSharedKeyAccess', 'configured': True}})
    assert summary.startswith('Storage Shared Key authorization is enabled.')
    assert 'successful sign-in' in summary
    assert evidence_summary({'provider': 'azure', 'check_id': 'azure.storage.no_shared_key', 'status': 'FAIL',
                             'evidence': {'field': 'properties.allowSharedKeyAccess', 'configured': 'true'}}) is None


def test_native_legacy_identifiers_follow_actual_predicate_instead_of_the_title():
    expectations = {
        'azure_search_service_10_6_3_27_ba08488': 'Access boundaries',
        'azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63': 'Validated HTTPS',
        'azure.gap.network_security_group_rdp_access_restricted': 'Guest user rights',
        'azure.other.ml_sensitive_terminal_disabled': 'terminals',
        'azure_vm_8_2_1_1_712e1ad': 'historical profile prefers no bootstrap SSH keys',
    }
    for cid, text in expectations.items():
        assert text.lower() in ROWS[cid]['purpose'].lower()
    assert 'does not automatically expire' in ROWS['azure.claude.storage_key_expiration_policy_max_90']['limit']
    assert 'regardless of next-hop' in ROWS['azure_route_table_network_http_internet_access_restricted_5cd2484']['limit']


def test_all_new_native_shape_rules_replay_both_interpretable_statuses_and_remain_source_bound():
    from peaso.checks.azure_native_evidence_observations import ROWS as NATIVE_ROWS
    assert len(NATIVE_ROWS) == 325
    for cid, rules in NATIVE_ROWS.items():
        encoded = json.dumps(rules, sort_keys=True, separators=(',', ':')).encode()
        assert hashlib.sha256(encoded).hexdigest() == LEDGER[cid]['native_observation_rules_sha256']
        for case in CASES[cid]:
            finding = dict(case, provider='azure', check_id=cid)
            if case['status'] in {'PASS', 'FAIL'}:
                assert native_observation(finding), (cid, case['status'], case['evidence'])


def test_count_only_success_reports_its_evidence_limit_instead_of_inventing_configuration():
    finding = {'provider': 'azure', 'check_id': 'azure.gap.asset_inventory_required_metadata', 'status': 'PASS', 'evidence': {'evaluated': 7}}
    observed = native_observation(finding)
    assert observed == 'The result records 7 assessed resources; individual inventory tags were not stored.'
    finding['evidence']['evaluated'] = True
    assert native_observation(finding) is None


def test_measured_native_access_checks_follow_the_evidence_rather_than_the_legacy_title():
    for cid, expected in [
        ('azure.other.database_default_login_restricted', 'default database credentials'),
        ('azure_search_service_10_6_3_27_ba08488', 'index or query authorization'),
        ('azure.other.ml_compute_file_download_restricted', 'file downloads'),
    ]:
        case = next(row for row in CASES[cid] if row['status'] == 'FAIL')
        assert expected in native_observation(dict(case, provider='azure', check_id=cid))


def test_every_registered_check_rejects_empty_and_unrelated_positive_witnesses():
    for cid in ROWS:
        for status in ('PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'MANUAL', 'NOT_APPLICABLE', 'EMPTY'):
            for evidence in ({}, {'unrelated': True}):
                assert evidence_summary({'provider': 'azure', 'check_id': cid, 'status': status, 'evidence': evidence}) is None, (cid, status, evidence)


def test_unknown_manual_and_inapplicable_copy_is_check_bound_brief_and_neutral():
    for cid, row in ROWS.items():
        for key in ('missing_observation', 'manual_observation', 'not_applicable_observation'):
            text = reviewed_explanation(cid, row[key])
            assert len(text) <= 240, (cid, key, text)
            assert row['label'] in text
            assert '{' not in text and '\n' not in text


def test_rsa_observation_uses_actual_weak_modulus_and_rejects_a_nonweak_failure_witness():
    cid = 'azure_vault_3_7_1_2_532ecd2'
    case = deepcopy(next(row for row in CASES[cid] if row['status'] == 'FAIL'))
    finding = dict(case, provider='azure', check_id=cid)
    assert '1024-bit RSA' in evidence_summary(finding)
    assert '1024-bit RSA' in native_observation(finding)
    for row in finding['evidence']['outcomes']:
        if row.get('status') == 'FAIL':
            row['measured_rsa_modulus_bits'] = 4096
    assert native_observation(finding) is None
    assert evidence_summary(finding) is None
