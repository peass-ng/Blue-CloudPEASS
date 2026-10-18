"""Independent restore outcomes are test scoped; native jobs are inert read stubs."""
from copy import deepcopy

import pytest

from tests.test_peaso_backup_restore_native_binding import (
    CID, captured, data, digest, fully_specified, reseal, status,
)


def paired(monkeypatch, *, failing_first=True, failed_required=True):
    snap = fully_specified(captured(monkeypatch))
    tests = next(env for env in snap['collections'] if env['type'] == 'backup_restore_test')['items']
    failed = tests[0]
    failed['result'] = 'Failed'
    failed['restoredDataVerified'] = False
    failed['required'] = failed_required
    failed['validationEvidence']['usableDataValidation']['result'] = 'Failed'
    unreadable = deepcopy(failed)
    unreadable['id'] = unreadable['id'].replace('/test1', '/test2')
    unreadable['verificationDocumentId'] = 'external-validation-document-2'
    unreadable['validationEvidence']['document_id'] = 'external-validation-document-2'
    unreadable['result'] = 'Passed'
    unreadable['restoredDataVerified'] = True
    unreadable['validationEvidence']['usableDataValidation'].pop('result')
    tests[:] = [failed, unreadable] if failing_first else [unreadable, failed]
    return reseal(snap)


@pytest.mark.parametrize('failing_first', [True, False])
def test_required_independent_failed_test_survives_unreadable_peer_result(monkeypatch, failing_first):
    assert status(paired(monkeypatch, failing_first=failing_first)) == 'FAIL'


@pytest.mark.parametrize('field', ['result', 'restoredDataVerified'])
def test_unreadable_peer_without_observed_required_failure_is_unknown(monkeypatch, field):
    snap = paired(monkeypatch, failed_required=False)
    tests = next(env for env in snap['collections'] if env['type'] == 'backup_restore_test')['items']
    tests[0]['required'] = False
    tests[1]['validationEvidence']['usableDataValidation']['result'] = 'Passed'
    tests[1].pop(field)
    assert status(reseal(snap)) == 'UNKNOWN'


@pytest.mark.parametrize('mutation', ['foreign_capture', 'bad_digest', 'conflicting_outcome'])
def test_required_failure_does_not_waive_peer_authority_contradiction(monkeypatch, mutation):
    snap = paired(monkeypatch)
    tests = next(env for env in snap['collections'] if env['type'] == 'backup_restore_test')['items']
    proof = tests[1]['validationEvidence']
    if mutation == 'foreign_capture':
        proof['customer_context_id'] = 'other-customer'
    elif mutation == 'bad_digest':
        proof['nativeEvidenceSha256'] = 'b' * 64
    else:
        proof['usableDataValidation']['result'] = 'Failed'
    assert status(reseal(snap)) == 'UNKNOWN'


def test_complete_approved_registry_and_valid_independent_result_still_pass(monkeypatch):
    assert status(fully_specified(captured(monkeypatch))) == 'PASS'


def test_required_failure_cannot_waive_incomplete_global_registry(monkeypatch):
    snap = paired(monkeypatch)
    next(env for env in snap['collections'] if env['type'] == 'backup_restore_window')['items'][0]['testsComplete'] = False
    assert status(reseal(snap)) == 'UNKNOWN'



def test_failed_native_job_alone_does_not_override_later_valid_required_restore(monkeypatch):
    snap = fully_specified(captured(monkeypatch))
    jobs = next(env for env in snap['collections'] if env['type'] == 'backup_job')['items']
    tests = next(env for env in snap['collections'] if env['type'] == 'backup_restore_test')['items']
    first_job = jobs[0]
    first_job['properties']['status'] = 'Failed'
    later_job = deepcopy(first_job)
    later_job['id'] += '-later'
    later_job['properties']['status'] = 'Completed'
    jobs.append(later_job)
    capture = {key: snap['metadata'][key] for key in ('tenant_id', 'credential_context_id', 'customer_context_id')}
    item = data(snap, 'backup_protected_item')
    first_test = tests[0]
    first_test['validationEvidence']['nativeEvidenceSha256'] = digest({
        'job': first_job, 'protected_item': item, 'capture': capture})
    later_test = deepcopy(first_test)
    later_test['id'] += '-later'
    later_test['jobId'] = later_job['id']
    later_test['verificationDocumentId'] += '-later'
    later_test['validationEvidence']['document_id'] = later_test['verificationDocumentId']
    later_test['validationEvidence']['jobId'] = later_job['id']
    later_test['validationEvidence']['nativeEvidenceSha256'] = digest({
        'job': later_job, 'protected_item': item, 'capture': capture})
    tests.append(later_test)
    window = data(snap, 'backup_restore_window')
    window['jobsInventorySha256'] = digest({'jobs': jobs, 'capture': capture})
    assert status(reseal(snap)) == 'PASS'
