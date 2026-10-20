"""Current-source reconciliation is evidence, never implicit equivalence."""
import hashlib
import json
from pathlib import Path

import pytest

from scripts.audit_aws_prowler_parity import verified_bytes

ROOT = Path(__file__).parents[1]
REVIEW = ROOT / 'docs/aws-review'


def read(name):
    return json.loads((REVIEW / name).read_text())


def test_every_current_source_has_one_precise_disposition_after_admission():
    prowler = read('prowler-parity.json')['checks']
    steampipe = read('steampipe-parity.json')['records']
    ids = ['prowler.aws.' + r['upstream_id'] for r in prowler]
    ids += [r['control_id'] for r in steampipe]
    assert len(ids) == len(set(ids)) == 2336
    assert all(r['disposition'] and r['upstream_evaluator'].get('sha256') for r in prowler)
    assert all(r['validity_verdict'] and not r['manifest_mismatches'] for r in steampipe)
    assert not any(i in {'missing_manifest_row', 'duplicate_manifest_rows',
                        'claimed_port_without_active_native', 'upstream_evaluator_not_cached'}
                   for r in prowler for i in r['issues'])
    assert not any(r['validity_verdict'].startswith(('uncertain', 'missing', 'unresolved', 'stale'))
                   for r in steampipe)


def test_every_excluded_source_is_individually_accounted_for():
    report = read('remaining-source-exclusions.json')
    rows = report['rows']
    expected = {'prowler.aws.' + r['upstream_id'] for r in read('prowler-parity.json')['checks']
                if r['manifest_disposition'] == 'rejected'}
    expected.update(r['control_id'] for r in read('steampipe-parity.json')['records']
                    if r['manifest_disposition'] == 'rejected')
    assert len(expected) == 88
    assert expected == {r['source_id'] for r in rows if r['manifest_disposition'] == 'rejected'}
    assert len(rows) == len({r['source_id'] for r in rows})
    assert all(r['evidence'] and not r['semantic_equivalence_certified'] for r in rows)
    assert all(not r['active_native'] for r in rows if r['manifest_disposition'] == 'rejected')
    assert report['summary']['active_mapped_source_ids'] + len(expected) == 2336


def test_exact_listener_archive_never_counts_as_active_configuration_coverage():
    archive = read('remaining-source-exclusions.json')['archived_exact_listener_contract']
    assert archive['id'] == 'aws_nist_ec2_instance_not_publicly_accessible'
    assert not archive['in_runtime'] and not archive['in_active_catalog']
    assert archive['exclusion']['disposition'] == 'unsupported_exact_contract'
    assert all(r['active'] for r in archive['native_alternatives'])


def test_review_fingerprints_match_companion_reports():
    report = read('remaining-source-exclusions.json')
    for filename, expected in report['companion_report_sha256'].items():
        assert hashlib.sha256((REVIEW / filename).read_bytes()).hexdigest() == expected


def test_cached_source_path_cannot_escape_cache(tmp_path):
    with pytest.raises(ValueError, match='unsafe cached source path'):
        verified_bytes(tmp_path, {'path': '../outside.py'})
    with pytest.raises(ValueError, match='unsafe cached source path'):
        verified_bytes(tmp_path, {'path': '/outside.py'})


def test_manifest_universal_newline_fingerprint_is_not_an_upstream_change():
    rows = read('prowler-parity.json')['checks']
    row = next(r for r in rows if r['upstream_id'] ==
               'ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip')
    evidence = row['upstream_evaluator']
    assert evidence['raw_sha256_differs_from_manifest']
    assert evidence['sha256'] != evidence['normalized_sha256']
    assert not evidence['changed_since_manifest']
    assert 'upstream_evaluator_changed_since_manifest' not in row['issues']
