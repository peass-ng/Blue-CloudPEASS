"""Negative, local fixtures for exact OPS-06 monitor and native item binding."""
import copy

from tests.test_peaso_backup_c5_native_binding import (
    MONITOR, ITEM, JOB, VAULT, captured, supplied_monitor, reseal, data, status, digest,
)


def test_foreign_external_record_cannot_be_ignored(monkeypatch):
    snap = supplied_monitor(captured(monkeypatch, MONITOR))
    record = copy.deepcopy(data(snap, 'backup_monitor_evidence'))
    record['id'] = VAULT + '/backupMonitorEvidence/foreign'
    record['properties']['protectedItemId'] = '/subscriptions/foreign/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/v/backupFabrics/Azure/protectionContainers/c/protectedItems/i'
    next(env for env in snap['collections'] if env['type'] == 'backup_monitor_evidence')['items'].append(record)
    assert status(reseal(snap), MONITOR) == 'UNKNOWN', status.last_findings


def test_duplicate_external_record_cannot_certify_scope(monkeypatch):
    snap = supplied_monitor(captured(monkeypatch, MONITOR))
    record = copy.deepcopy(data(snap, 'backup_monitor_evidence'))
    record['id'] = VAULT + '/backupMonitorEvidence/duplicate'
    next(env for env in snap['collections'] if env['type'] == 'backup_monitor_evidence')['items'].append(record)
    assert status(reseal(snap), MONITOR) == 'UNKNOWN', status.last_findings


def test_empty_and_mismatched_monitor_observations_remain_unresolved(monkeypatch):
    snap = supplied_monitor(captured(monkeypatch, MONITOR))
    next(env for env in snap['collections'] if env['type'] == 'backup_monitor_evidence')['items'].clear()
    assert status(reseal(snap), MONITOR) == 'UNKNOWN', status.last_findings
    snap = supplied_monitor(captured(monkeypatch, MONITOR))
    data(snap, 'backup_monitor_evidence')['properties']['monitoringValidation']['jobBindings'][0]['jobStatus'] = 'Failed'
    assert status(reseal(snap), MONITOR) == 'UNKNOWN', status.last_findings


def test_native_item_must_have_exact_protected_item_arm_kind(monkeypatch):
    snap = supplied_monitor(captured(monkeypatch, MONITOR))
    wrong = VAULT + '/backupFabrics/Azure/protectionContainers/container/unrelatedItems/item'
    native = data(snap, 'backup_protected_item')
    native['id'] = wrong
    snap['metadata']['compliance_policy']['sw31']['requiredBackupItemIds'] = [wrong]
    snap['metadata']['compliance_policy']['sw31']['requiredBackupItems'][0]['id'] = wrong
    proof = data(snap, 'backup_monitor_evidence')['properties']
    proof['protectedItemId'] = wrong
    validation = proof['monitoringValidation']
    validation['protectedItemId'] = wrong
    validation['jobBindings'][0]['protectedItemId'] = wrong
    capture = {key: snap['metadata'][key] for key in ('tenant_id', 'credential_context_id', 'customer_context_id')}
    jobs = next(env for env in snap['collections'] if env['type'] == 'backup_job')['items']
    validation['nativeEvidenceSha256'] = digest({'protected_item': native, 'jobs': jobs, 'capture': capture})
    assert status(reseal(snap), MONITOR) == 'UNKNOWN', status.last_findings


def test_valid_monitor_failure_survives_unresolved_completed_peer(monkeypatch):
    snap = supplied_monitor(captured(monkeypatch, MONITOR))
    policy = snap['metadata']['compliance_policy']['sw31']
    second_item = ITEM + '-peer'
    second_job = JOB + '-peer'
    policy['requiredBackupItemIds'].append(second_item)
    policy['requiredBackupItems'].append({'id': second_item, 'dataClass': 'customer', 'workloadType': 'VM'})
    item_env = next(env for env in snap['collections'] if env['type'] == 'backup_protected_item')
    peer_item = copy.deepcopy(item_env['items'][0]); peer_item['id'] = second_item
    item_env['items'].append(peer_item)
    job_env = next(env for env in snap['collections'] if env['type'] == 'backup_job')
    peer_job = copy.deepcopy(job_env['items'][0]); peer_job['id'] = second_job
    peer_job['properties']['status'] = 'Cancelled'
    job_env['items'].append(peer_job)
    evidence_env = next(env for env in snap['collections'] if env['type'] == 'backup_monitor_evidence')
    first = evidence_env['items'][0]
    first['properties']['jobAlertsRouted'] = False
    first['properties']['monitoringValidation']['jobBindings'][0]['monitoringResult'] = 'MissingAlertRouting'
    peer = copy.deepcopy(first); peer['id'] = VAULT + '/backupMonitorEvidence/peer'
    peer_props = peer['properties']; peer_props['protectedItemId'] = second_item
    peer_props['observedJobIds'] = [second_job]
    peer_props['jobAlertsRouted'] = True
    peer_validation = peer_props['monitoringValidation']
    peer_validation['protectedItemId'] = second_item
    peer_binding = peer_validation['jobBindings'][0]
    peer_binding.update(jobId=second_job, protectedItemId=second_item, jobStatus='Cancelled',
                        monitoringResult='DocumentedAndRouted')
    evidence_env['items'].append(peer)
    capture = {key: snap['metadata'][key] for key in ('tenant_id', 'credential_context_id', 'customer_context_id')}
    for record, native_item in ((first, item_env['items'][0]), (peer, peer_item)):
        record['properties']['monitoringValidation']['nativeEvidenceSha256'] = digest(
            {'protected_item': native_item, 'jobs': job_env['items'], 'capture': capture})
    assert status(reseal(snap), MONITOR) == 'FAIL', status.last_findings
    peer_validation['customer_context_id'] = 'foreign-capture'
    assert status(reseal(snap), MONITOR) == 'UNKNOWN', status.last_findings


def test_completed_native_job_alone_does_not_prove_monitoring(monkeypatch):
    assert status(captured(monkeypatch, MONITOR), MONITOR) == 'UNKNOWN', status.last_findings
