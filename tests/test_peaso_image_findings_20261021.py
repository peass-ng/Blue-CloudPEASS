from copy import deepcopy
import json
import pytest
import peaso.image_findings as module
from peaso.image_findings import build_report

D = 'sha256:' + 'a' * 64
BASE = {'provider': 'gcp', 'scope': 'projects/example-project',
    'asset_id': 'projects/example-project/locations/us-central1/jobs/example',
    'asset_kind': 'cloud_run_job', 'scan': {
        'image': {'provider': 'gcp', 'scope': 'projects/example-project',
            'immutable_reference': 'us-docker.pkg.dev/example-project/repo/image@' + D,
            'manifest_digest': D, 'config_digest': 'sha256:' + 'b' * 64},
        'status': 'FAIL', 'complete': True, 'scan_complete': True,
        'coverage_status': 'COMPLETE', 'database': {'fresh': True},
        'findings': [{'vulnerability_id': 'CVE-2026-12345', 'severity': 'HIGH',
            'package_types': ['alpine'], 'package': 'busybox', 'version': '1.0',
            'fixed_in': ['1.1'], 'fix_status': 'fixed', 'classes': ['os-pkgs'],
            'image_digest': D}]}}


def test_one_immutable_leak_row_and_multiple_asset_locations():
    second = deepcopy(BASE)
    second['asset_id'] += '-other'
    rows = build_report([BASE, BASE, second], selected=True)
    assert rows['complete'] and rows['coverage'] == 'COMPLETE'
    assert len(rows['rows']) == 1
    assert len(rows['rows'][0]['affected_assets']) == 2
    assert rows['rows'][0]['fixed_versions'] == ['1.1']


def test_deterministic_identity_and_order():
    second = deepcopy(BASE)
    second['scan']['findings'][0]['severity'] = 'CRITICAL'
    second['asset_id'] += '-other'
    left, right = build_report([BASE, second], selected=True), build_report([second, BASE], selected=True)
    assert left == right
    assert left['rows'][0]['severity'] == 'CRITICAL'


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_all_provider_shapes_supported(provider):
    row = deepcopy(BASE)
    row['provider'] = row['scan']['image']['provider'] = provider
    assert len(build_report([row], selected=True)['rows']) == 1


def test_scope_and_provider_never_merged():
    other = deepcopy(BASE)
    other['scope'] = other['scan']['image']['scope'] = 'projects/another-project'
    assert len(build_report([BASE, other], selected=True)['rows']) == 2
    other['provider'] = other['scan']['image']['provider'] = 'k8s'
    assert len(build_report([BASE, other], selected=True)['rows']) == 2


def test_unselected_and_empty_are_not_clean():
    assert build_report([BASE])['coverage'] == 'NOT_SCANNED'
    result = build_report([], selected=True)
    assert not result['complete'] and result['coverage'] == 'UNKNOWN'


def test_supported_complete_clean_is_distinct():
    row = deepcopy(BASE)
    row['scan'].update(status='PASS', findings=[])
    result = build_report([row], selected=True)
    assert result['complete'] and result['coverage'] == 'COMPLETE' and result['rows'] == []


def test_partial_positive_preserved_without_clean_claim():
    row = deepcopy(BASE)
    row['scan'].update(complete=False, scan_complete=False, coverage_status='UNKNOWN', database={'fresh': False})
    result = build_report([row], selected=True)
    assert len(result['rows']) == 1 and result['rows'][0]['coverage'] == 'UNKNOWN'
    assert result['coverage'] == 'UNKNOWN' and not result['complete']


@pytest.mark.parametrize('mutation', [
    lambda r: r['scan']['image'].update(provider='azure'),
    lambda r: r['scan']['image'].update(scope='projects/foreign'),
    lambda r: r['scan']['image'].update(immutable_reference='user:pass@evil.example/image'),
    lambda r: r['scan']['image'].update(manifest_digest='sha256:' + 'c' * 64),
    lambda r: r['scan'].update(status='PASS'),
    lambda r: r['scan'].update(complete='true'),
    lambda r: r['scan'].update(database={'fresh': False}),
])
def test_unbound_or_contradictory_scan_never_claims_clean(mutation):
    row = deepcopy(BASE)
    mutation(row)
    result = build_report([row], selected=True)
    assert result['coverage'] == 'UNKNOWN' and not result['rows']


@pytest.mark.parametrize('mutation', [
    lambda v: v.update(image_digest='sha256:' + 'c' * 64),
    lambda v: v.update(vulnerability_id='<script>'),
    lambda v: v.update(severity='LOW'),
    lambda v: v.update(package='not\na\tpackage'),
    lambda v: v.update(fixed_in=['https://untrusted.example']),
    lambda v: v.update(fix_status='unreviewed'),
])
def test_malformed_vulnerability_discarded_and_coverage_incomplete(mutation):
    row = deepcopy(BASE)
    mutation(row['scan']['findings'][0])
    result = build_report([row], selected=True)
    assert result['coverage'] == 'UNKNOWN' and not result['rows']
    assert result['invalid_vulnerabilities'] == 1


def test_unknown_fields_and_sensitive_diagnostics_not_forwarded():
    row = deepcopy(BASE)
    row['credentials'] = row['scan']['stderr'] = 'synthetic-sensitive-canary'
    result = build_report([row], selected=True)
    assert result['complete']
    assert 'synthetic-sensitive-canary' not in json.dumps(result)


def test_bounds_never_silently_report_complete(monkeypatch):
    monkeypatch.setattr(module, 'MAX_OBSERVATIONS', 1)
    result = build_report([BASE, BASE], selected=True)
    assert result['truncated'] and not result['complete']
    monkeypatch.setattr(module, 'MAX_TOTAL_VULNERABILITIES', 0)
    result = build_report([BASE], selected=True)
    assert result['truncated'] and not result['rows']


def test_affected_assets_bound_explicit(monkeypatch):
    monkeypatch.setattr(module, 'MAX_ASSETS_PER_ROW', 1)
    second = deepcopy(BASE)
    second['asset_id'] += '-other'
    result = build_report([BASE, second], selected=True)
    assert result['truncated'] and not result['complete']
    assert result['rows'][0]['coverage'] == 'UNKNOWN'
    assert len(result['rows'][0]['affected_assets']) == 1
