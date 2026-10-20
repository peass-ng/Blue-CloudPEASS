"""Existing scans use AI corrections before filtering, grouping and detail lookup."""
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient
from peaso.ai.finding_reviews import apply_review, review_index, _UNAVAILABLE
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts
from peaso.storage.reports import publish_report
from tests.test_peaso_api import TestIdentities
from tests.test_peaso_finding_group_api import fixture_report


def test_projection_rejects_unassigned_invalid_duplicate_and_unavailable_reviews():
    finding = dict(id='f', category='hardening', status='FAIL', evidence={'native': True})
    row = dict(finding_id='f', verdict='PASS', reason='Verified setting')
    assert apply_review(finding, review_index({'reviews': {'exposure': [row]}})) == finding
    assert apply_review(dict(finding, status='PASS'), review_index({'reviews': {'hardening': [row]}}))['status'] == 'PASS'
    for rows in ([row, row], [dict(row, verdict='invalid')], [dict(row, verdict='UNKNOWN', reason=_UNAVAILABLE)]):
        assert apply_review(finding, review_index({'reviews': {'hardening': rows}})) == finding
    projected = apply_review(finding, review_index({'reviews': {'hardening': [row]}}))
    assert projected['status'] == 'PASS' and projected['scanner_status'] == 'FAIL'
    assert projected['evidence'] == finding['evidence'] and finding['status'] == 'FAIL'
    assert apply_review(projected, review_index({'reviews': {'hardening': [row]}})) == projected


@pytest.mark.parametrize('chunked', [False, True], ids=['existing-inline', 'existing-chunked'])
def test_existing_scan_filters_counts_groups_and_details_use_rechecked_status(tmp_path, chunked):
    store, artifacts = SQLiteStore(tmp_path/'state'), FileArtifacts(tmp_path/'artifacts')
    connector = store.add_connector('alice', {'provider': 'aws'}, 'encrypted')
    job = store.enqueue('alice', {'connector_id': connector['id']})
    report = fixture_report()
    report['findings'] = [dict(report['findings'][0], id='h1'),
                          dict(report['findings'][1], id='h2'),
                          dict(report['findings'][0], id='e1', category='exposure', check_id='fixture.exposure')]
    report['ai'] = {'status': 'completed', 'reviews': {
        'hardening': [dict(finding_id='h1', verdict='PASS', reason='Confirmed effective setting'),
                      dict(finding_id='h2', verdict='FAIL', reason='')],
        'exposure': [dict(finding_id='e1', verdict='NOT_APPLICABLE', reason='No applicable endpoint')]}}
    original = deepcopy(report)
    reference = publish_report(artifacts, 'alice', job['id'], report) if chunked else artifacts.put('alice', job['id'], 'report', report)
    with store.transaction() as db:
        db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?", (reference, job['id']))
    app = create_app(Settings(state_dir=tmp_path/'settings', identity_dir=tmp_path/'identity'), store=store, artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url='http://127.0.0.1:8000', headers={'Authorization': 'Bearer alice'}) as client:
        base = f"/api/scans/{job['id']}/findings"
        failed = client.get(base, params={'status': 'FAIL'}).json()
        assert [r['id'] for r in failed['items']] == ['h2']
        passed = client.get(base, params={'categories': 'hardening', 'status': 'PASS'}).json()
        assert [r['id'] for r in passed['items']] == ['h1']
        assert passed['items'][0]['scanner_status'] == 'FAIL'
        assert passed['items'][0]['ai_review']['reason'] == 'Confirmed effective setting'
        exposure = client.get(base, params={'categories': 'exposure', 'status': 'NOT_APPLICABLE'}).json()
        assert [r['id'] for r in exposure['items']] == ['e1']
        grouped = client.get(base, params={'categories': 'hardening', 'aggregation': 'check', 'status': 'PASS'}).json()
        assert grouped['total'] == 1 and grouped['items'][0]['status'] == 'PASS'
        assert grouped['status_filter_counts']['FAIL'] == 1 and grouped['status_filter_counts']['PASS'] == 1
        group = client.get(f"/api/scans/{job['id']}/finding-groups/{grouped['items'][0]['id']}", params={'categories': 'hardening', 'status': 'PASS'}).json()
        assert group['members_total'] == 1 and group['members'][0]['status'] == 'PASS'
        detail = client.get(base+'/h1').json()
        assert detail['status'] == 'PASS' and detail['scanner_status'] == 'FAIL'
        assert detail['ai_review']['reason'] == 'Confirmed effective setting'
        assert detail['evidence'] == original['findings'][0]['evidence']
        client.headers['Authorization'] = 'Bearer bob'
        assert client.get(base).status_code == 404
    assert report == original


def test_review_reason_takes_precedence_over_the_original_native_observation(tmp_path):
    from peaso.checks.catalog import description_for
    store, artifacts = SQLiteStore(tmp_path/'state'), FileArtifacts(tmp_path/'artifacts')
    connector = store.add_connector('alice', {'provider': 'aws'}, 'encrypted')
    job = store.enqueue('alice', {'connector_id': connector['id']})
    report = fixture_report()
    finding = dict(report['findings'][0], **description_for('aws.iam.root_mfa'))
    finding.update(id='reviewed-root', check_id='aws.iam.root_mfa', status='FAIL',
                   evidence={'account_mfa_enabled': False})
    reason = 'A targeted read confirms root MFA is now enabled; this setting changed after collection.'
    report['findings'] = [finding]
    report['ai'] = {'status': 'completed', 'reviews': {'hardening': [
        {'finding_id': finding['id'], 'verdict': 'PASS', 'reason': reason}]}}
    reference = publish_report(artifacts, 'alice', job['id'], report)
    with store.transaction() as db:
        db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?", (reference, job['id']))
    app = create_app(Settings(state_dir=tmp_path/'settings', identity_dir=tmp_path/'identity'),
        store=store, artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url='http://127.0.0.1:8000', headers={'Authorization': 'Bearer alice'}) as client:
        response = client.get(f"/api/scans/{job['id']}/findings/{finding['id']}")
        assert response.status_code == 200
        detail = response.json()
        assert detail['status'] == 'PASS' and detail['evidence_summary'] == reason
        assert detail['evidence'] == {'account_mfa_enabled': False}
