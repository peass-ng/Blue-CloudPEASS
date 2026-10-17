"""Disabled-identity falsepass and source key-value retrieval incompatibility."""
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_invalid_app.json').read_text())


def test_disabled_managed_identity_nonempty_object_false_passes_pinned_query():
    duckdb = pytest.importorskip('duckdb')
    proofs = [r['source_review'] for r in REVIEWS.values() if r['source_review']['query_id'] == 'appservice_web_app_register_with_active_directory_enabled']
    assert len(proofs) == 7
    case = proofs[0]['status_case_sql']
    with duckdb.connect(':memory:') as db:
        status = db.execute('SELECT ' + case + ' FROM (SELECT ?::JSON AS identity)', [json.dumps({'Type': 'None'})]).fetchone()[0]
    assert status == 'ok'
    assert all(p['counterexample']['provider_identity']['type'] == 'None' for p in proofs)


def test_host_key_source_operation_requires_secret_value_response_without_executing_it():
    review = REVIEWS['prowler.azure.app_function_access_keys_configured']
    assert review['review_classification'] == 'intrusive_unsuitable'
    assert review['source_review']['operation'].endswith('/host/default/listkeys')
    assert set(review['source_review']['response_secret_fields']) == {'masterKey', 'functionKeys', 'systemKeys'}
    assert review['native_checks'] == []


def test_owned_exact_ten_rows_have_substantive_evidence_and_no_support_stub():
    claude = set(json.loads((ROOT / 'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS) == 10 and not set(REVIEWS) & claude
    assert all(r['disposition'] == 'rejected' and r['native_checks'] == [] and r['official_docs'] for r in REVIEWS.values())


def test_required_mode_does_not_enable_certificate_handling_and_raw_none_identity_is_truthy():
    mode = REVIEWS['prowler.azure.app_client_certificates_on']['source_review']['counterexample']
    identity = REVIEWS['prowler.azure.app_register_with_identity']['source_review']['counterexample']
    assert mode['clientCertMode'] == 'Required' and mode['clientCertEnabled'] is False and mode['source_status'] == 'PASS'
    assert bool(identity['identity']) is True and identity['identity']['type'] == 'None'
