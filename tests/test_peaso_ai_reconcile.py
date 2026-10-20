"""Reconciliation is dry by default, tenant-bound and compare-and-swap guarded."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.ai.reconcile import reconcile_scan
from peaso.snapshot import make_snapshot
from peaso.storage import SQLiteStore, FileArtifacts, StoreError
from tests.test_peaso_finding_group_api import fixture_report


def setup_scan(tmp_path, monkeypatch):
    store, artifacts = SQLiteStore(tmp_path/'state'), FileArtifacts(tmp_path/'artifacts')
    connector = store.add_connector('alice', {'provider': 'aws'}, 'encrypted')
    job = store.enqueue('alice', {'connector_id': connector['id'], 'categories': ['hardening', 'exposure']})
    snapshot = make_snapshot('aws', ['111111111111/us-east-1'], [])
    report = fixture_report();report['findings'] = report['findings'][:2];report['snapshot_id'] = snapshot['snapshot_id']
    report['stats']['check_count'] = 1
    report['ai'] = {'status': 'completed', 'coverage': {'reviewed': 2, 'total': 2}, 'actions': [], 'limitations': [], 'reviews': {
        'hardening': [{'finding_id': report['findings'][0]['id'], 'verdict': 'PASS', 'reason': 'Original AI interpretation'},
                      {'finding_id': report['findings'][1]['id'], 'verdict': 'FAIL', 'reason': ''}], 'exposure': []}}
    old = artifacts.put('alice', job['id'], 'report', report)
    snap = artifacts.put('alice', job['id'], 'snapshot', snapshot)
    with store.transaction() as db:
        db.execute("UPDATE jobs SET status='completed',report=?,snapshot=? WHERE id=?", (old,snap,job['id']))
    current = deepcopy(report);current.pop('ai')
    monkeypatch.setattr('peaso.engine.evaluate_snapshot', lambda *a, **k: deepcopy(current))
    decision = {'category': 'hardening', 'finding_id': report['findings'][0]['id'], 'verdict': 'FAIL', 'reason': '',
                'source': 'https://example.test/reviewed-control'}
    return store,artifacts,job['id'],old,snap,decision


def test_dry_run_retains_every_artifact_and_job_pointer(tmp_path, monkeypatch):
    s,a,job,old,snap,decision = setup_scan(tmp_path, monkeypatch)
    before = sorted(a.root.rglob('*.json'))
    receipt = reconcile_scan(s,a,'alice',job,old,source_version='fixture',adjudications=[decision])
    assert receipt['dry_run'] and receipt['adjudications']==1
    assert sorted(a.root.rglob('*.json'))==before and s.job('alice',job)['report']==old


def test_apply_preserves_original_evidence_and_audits_review_decision(tmp_path, monkeypatch):
    s,a,job,old,snap,decision = setup_scan(tmp_path, monkeypatch)
    receipt = reconcile_scan(s,a,'alice',job,old,source_version='fixture',adjudications=[decision],dry_run=False)
    assert receipt['report_replaced']
    new = a.get('alice',s.job('alice',job)['report']);ai = a.get('alice',new['ai_review'])
    assert ai['reviews']['hardening'][0]['verdict']=='FAIL'
    assert ai['adjudications'][0]['original_review']['verdict']=='PASS'
    assert a.get('alice',old)['ai']['reviews']['hardening'][0]['verdict']=='PASS'
    assert s.job('alice',job)['snapshot']==snap
    assert new['summary']['analysis_revision']['previous_report']==old
    assert new['summary']['analysis_revision']['model_rerun'] is False
    with pytest.raises(StoreError):
        reconcile_scan(s,a,'alice',job,old,source_version='fixture',dry_run=False)


def test_wrong_tenant_or_report_and_unknown_decision_do_not_publish(tmp_path, monkeypatch):
    s,a,job,old,snap,decision = setup_scan(tmp_path, monkeypatch)
    before = sorted(a.root.rglob('*.json'))
    with pytest.raises(StoreError):reconcile_scan(s,a,'bob',job,old,source_version='fixture')
    with pytest.raises(StoreError):reconcile_scan(s,a,'alice',job,old+'wrong',source_version='fixture')
    with pytest.raises(ValueError):reconcile_scan(s,a,'alice',job,old,source_version='fixture',adjudications=[dict(decision,finding_id='invented')])
    assert sorted(a.root.rglob('*.json'))==before
    with pytest.raises(StoreError):s.replace_completed_report('bob',job,old,old)


def test_dynamo_report_replacement_is_tenant_bound_and_rejects_stale_or_expired_jobs():
    import boto3
    from moto import mock_aws
    from peaso.storage.dynamodb import DynamoStore, attrs
    with mock_aws():
        client = boto3.client('dynamodb', region_name='us-east-1')
        client.create_table(TableName='reconcile-test',
            KeySchema=[{'AttributeName': 'PK', 'KeyType': 'HASH'}, {'AttributeName': 'SK', 'KeyType': 'RANGE'}],
            AttributeDefinitions=[{'AttributeName': k, 'AttributeType': 'S'} for k in ('PK', 'SK')],
            BillingMode='PAY_PER_REQUEST')
        store = DynamoStore('reconcile-test', client)
        store.clock = lambda: 1000
        original = dict(store.key('alice', 'job', 'scan'), id='scan', status='completed',
                        report='old', snapshot='snapshot', completed=900, expires_at=2000)
        client.put_item(TableName=store.table, Item=attrs(original))
        for tenant, expected in [('bob', 'old'), ('alice', 'stale')]:
            with pytest.raises(StoreError):
                store.replace_completed_report(tenant, 'scan', expected, 'new')
        store.replace_completed_report('alice', 'scan', 'old', 'new')
        assert store.job('alice', 'scan') == dict(original, report='new')
        with pytest.raises(StoreError):
            store.replace_completed_report('alice', 'scan', 'old', 'another')
        store.clock = lambda: 3000
        with pytest.raises(StoreError):
            store.replace_completed_report('alice', 'scan', 'new', 'expired')
