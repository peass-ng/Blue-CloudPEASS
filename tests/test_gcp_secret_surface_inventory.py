"""Inventory contracts, not certification of proposed native content adapters.

Runtime detector/default-off boundaries are reused from the tests cited in the
inventory. These checks prevent planned coverage from becoming advertised
support merely because metadata collection or a REST method exists.
"""
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / 'docs/gcp-review/secret-surfaces.json'


def inventory():
    return json.loads(INVENTORY.read_text())


def test_required_native_surfaces_are_individually_accounted_for():
    data = inventory()
    rows = {r['id']: r for r in data['surfaces']}
    assert len(rows) == len(data['surfaces'])
    assert {
        'functions_literal_environment', 'functions_source_archive',
        'artifact_registry_images', 'artifact_registry_package_files', 'gcr_images',
        'cloud_build_artifacts', 'cloud_build_stored_logs', 'cloud_build_inline',
        'gcs_selected_objects', 'logging_messages', 'source_repositories_legacy',
        'dataform_repository_files', 'dataform_workspace_files', 'composer_dags',
        'appengine_deployment_source', 'cloud_run_deployment_code', 'cloud_run_inline',
        'gke_configmaps', 'gke_pod_literal_env', 'gke_secret_references',
        'compute_inline_configuration', 'secret_manager_values', 'kms_key_material',
        'managed_service_passwords',
    } <= rows.keys()
    assert set(data['required_services']) <= {r['service'] for r in rows.values()}
    for row in rows.values():
        assert row['current_coverage'] and row['native_references'] and row['formats']
        assert row['source_evidence'] and row['unresolved_contracts']
        assert row['primary_docs']
        assert row['status'] in {'implemented', 'proposed', 'unsupported'}
        for source in row['source_evidence']:
            path = ROOT / source['file']
            assert path.is_file()
            assert re.fullmatch('[0-9a-f]{64}', source['sha256'])
            text = path.read_text()
            assert all(symbol.split('.')[-1] in text for symbol in source['symbols'])


def test_metadata_and_verified_api_names_do_not_imply_content_support():
    data = inventory()
    implemented = [r for r in data['surfaces'] if r['content_scan_integrated']]
    assert {'functions_literal_environment', 'artifact_registry_images', 'cloud_build_inline',
            'gcs_selected_objects', 'logging_messages', 'dataform_repository_files',
            'dataform_workspace_files', 'cloud_run_inline', 'compute_inline_configuration',
            'workflows_source', 'scheduler_tasks_payloads', 'appengine_literal_environment'} <= {r['id'] for r in implemented}
    from peaso.checks import CHECKS
    registered = {c.id for c in CHECKS}
    engine = (ROOT / 'peaso/engine.py').read_text()
    registry = (ROOT / 'peaso/checks/__init__.py').read_text()
    for row in implemented:
        assert row['status'] == row['bounds']['status'] == 'implemented'
        contract = row['implementation']
        assert set(contract['check_ids']) <= registered
        assert all(cid in engine for cid in contract['check_ids'])
        assert (ROOT / contract['collector_module']).is_file()
        check_module = Path(contract['registry_module']).stem
        assert check_module + '.install()' in registry
        assert 'explicit' in row['scope_and_opt_in']['option']
    for row in data['surfaces']:
        if row['status'] == 'proposed':
            assert not row['content_scan_integrated']
            assert row['bounds']['status'] == 'proposed_not_enforced'
        for api in row['read_apis']:
            assert api['permissions'] and api['path']
            if api['protocol'] == 'google_rest':
                assert api['native_method_verified'], api['method_id']
                assert api['source']['status'] == 200
                assert re.fullmatch('[0-9a-f]{64}', api['source']['sha256'])
    rows = {r['id']: r for r in data['surfaces']}
    assert any(a['method_id'].endswith('.readFile')
               for a in rows['dataform_repository_files']['read_apis'])
    assert 'contents' in str(rows['dataform_repository_files']['native_references'])
    assert 'fileContents' in str(rows['dataform_workspace_files']['native_references'])
    assert 'Kubernetes' in str(rows['gke_configmaps']['read_apis'])
    assert 'control-plane' in str(rows['gke_configmaps']['unresolved_contracts'])


def test_opt_in_budgets_and_intended_secret_store_exclusions():
    for row in inventory()['surfaces']:
        assert row['scope_and_opt_in']['enabled_by_default'] is False
        assert row['scope_and_opt_in']['required_selection']
        assert row['credential_verification']['enabled'] is False
        assert row['credential_verification']['network_validation'] is False
        assert row['privacy']['retain_plaintext'] is False
        assert row['privacy']['retain_snippets'] is False
        assert row['privacy']['retain_signed_urls_or_tokens'] is False
        assert row['privacy']['read_intended_secret_store_values'] is False
        if row['intentionally_excluded_secret_store']:
            assert row['status'] == 'unsupported'
            assert row['bounds']['max_content_bytes'] == 0
            assert row['bounds']['max_api_calls'] == 0
            assert all('versions.access' not in a['method_id'] for a in row['read_apis'])
        else:
            assert row['bounds']['max_content_bytes'] > 0
            assert row['bounds']['max_total_bytes'] > 0
            assert row['bounds']['max_wall_seconds'] > 0
            assert 'incomplete' in row['negative_result']
    adapter = inventory()['next_adapter']
    assert adapter['native_api'] == 'storage.objects.get metadata + generation-pinned alt=media'
    assert adapter['proposed_first_bounds']['max_objects'] == 10
    assert adapter['proposed_first_bounds']['max_content_bytes_per_object'] == 1048576
    assert 'no list/prefix/archive traversal' in adapter['first_scope']


def test_detector_proof_is_attributed_without_cross_process_or_network_claims():
    shared = inventory()['shared_detector_infrastructure']
    assert shared['engines'] == ['kingfisher', 'trufflehog']
    assert 'exact' in shared['merge_identity'] and 'HMAC' in shared['merge_identity']
    assert 'cross-process/cross-scan merge is not guaranteed' in shared['scope_limit']
    assert '--no-verification' in shared['no_verification']
    assert 'does not run real scanners' in shared['proof_limit']
    for attribution in shared['existing_test_attribution']:
        filename, name = attribution.split('::')
        assert 'def ' + name + '(' in (ROOT / filename).read_text()
