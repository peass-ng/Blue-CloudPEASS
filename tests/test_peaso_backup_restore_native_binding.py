"""Read-only native ARM capture joined to explicitly supplied restore validation.

The usable-data observations in this test are inert external fixtures. They are
not produced by collect_live and do not represent an executed restore test.
"""
import copy
from datetime import datetime, timedelta, timezone
import pytest
from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_bulk_native import Transport, SCOPE, SUB, BASE, parent, routes

_AZURE_COLLECT = azure.collect

CID = 'azure.other.backup_restore_evidence'
VAULT = BASE + 'Microsoft.RecoveryServices/vaults/vault'
ITEM = VAULT + '/backupFabrics/Azure/protectionContainers/container/protectedItems/item'
JOB = VAULT + '/backupJobs/restore-job'
TARGET = BASE + 'Microsoft.Compute/virtualMachines/restore-target'
POINT = ITEM + '/recoveryPoints/point1'


def captured(monkeypatch, management='AzureIaasVM'):
    now = datetime.now(timezone.utc)
    data = routes('recovery_vault', VAULT, {})
    protected = parent(ITEM, 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems',
        {'backupManagementType': 'AzureIaasVM', 'protectedItemType': 'Microsoft.Compute/virtualMachines',
         'virtualMachineId': BASE + 'Microsoft.Compute/virtualMachines/source', 'protectionState': 'Protected'})
    job = parent(JOB, 'Microsoft.RecoveryServices/vaults/backupJobs', {'jobType': 'AzureStorageJob' if management == 'AzureStorage' else 'AzureIaaSVMJob',
        'backupManagementType': management, 'operation': 'Restore', 'status': 'Completed',
        'entityFriendlyName': 'ambiguous-display-name',
        'startTime': (now-timedelta(days=2,hours=1)).isoformat(), 'endTime': (now-timedelta(days=2)).isoformat()})
    data[VAULT+'/backupProtectedItems'] = {'value':[protected]}
    data[VAULT+'/backupJobs'] = {'value':[job]}
    api = Transport(data)
    original = _AZURE_COLLECT
    def native(connector, kinds): return original(connector, kinds, transport=api)
    monkeypatch.setattr(azure, 'collect', native)
    owner = {'status':'collected','scope':SCOPE,'authorized_by':'security-owner','document_id':'critical-workload-scope',
        'observed_at':(now-timedelta(days=5)).isoformat(),'expires_at':(now+timedelta(days=1)).isoformat(),
        'checks':{CID.replace('.','|'):{'criticalProtectedItemIds':[ITEM], 'restoreTestMaxAgeDays':3}}}
    connector = {'provider':'azure','scopes':[SUB],'options':{'retries':0,'compliance_policy':{'sw13':owner}}}
    snap = collect_live(connector, plan_collection({'connector':connector,'checks':[CID]}))
    assert api.calls and all(url.startswith(azure.ARM) for url in api.calls)
    return snap


def supplied(snap):
    result = copy.deepcopy(snap)
    at = datetime.fromisoformat(snap['created_at'].replace('Z','+00:00'))
    record = {'id':VAULT+'/restoreTests/test1','scope':SCOPE,'protectedItemId':ITEM,'jobId':JOB,
        '_provenance':{'read_only':True},'independentVerification':True,
        'verifiedAt':(at-timedelta(days=1)).isoformat(),'verificationDocumentId':'external-validation-document',
        'result':'Passed','required':True,'restoredDataVerified':True}
    window = {'id':VAULT+'/restoreWindows/window1','scope':SCOPE,'vaultId':VAULT,'_provenance':{'read_only':True},
        'windowStart':(at-timedelta(days=4)).isoformat(),'windowEnd':at.isoformat(),'jobsComplete':True,'testsComplete':True}
    for kind, row in [('backup_restore_test',record),('backup_restore_window',window)]:
        result['collections'] = [env for env in result['collections'] if env['type'] != kind]
        result['collections'].append({'type':kind,'scope':SCOPE,'service':'external:restore-validation',
            'status':'collected','items':[row]})
    return make_snapshot('azure',result['scopes'],result['collections'],metadata=result['metadata'],created_at=result['created_at'])


def status(snapshot):
    findings = [f for f in evaluate_snapshot(snapshot,checks=[CID],include_not_applicable=True)['findings'] if f['check_id']==CID]
    assert len(findings)==1
    status.last_findings=findings
    return findings[0]['status']


def test_native_restore_job_other_workload_cannot_validate_vm_restore(monkeypatch):
    snap = fully_specified(captured(monkeypatch,'AzureStorage'))
    assert status(snap)=='UNKNOWN'


def test_reference_only_restore_validation_is_not_usable_data_evidence(monkeypatch):
    snap = supplied(captured(monkeypatch))
    assert status(snap)=='UNKNOWN'


def reseal(snap):
    return make_snapshot('azure',snap['scopes'],snap['collections'],metadata=snap['metadata'],created_at=snap['created_at'])


def data(snap, kind):
    return next(e for e in snap['collections'] if e['type']==kind)['items'][0]


def digest(value):
    import hashlib, json
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()


def fully_specified(snap):
    out = supplied(snap)
    test, window = data(out,'backup_restore_test'), data(out,'backup_restore_window')
    capture = {key:out['metadata'][key] for key in ('tenant_id','credential_context_id','customer_context_id')}
    test.update(sourceRecoveryPointId=POINT,restoreTargetId=TARGET)
    test['validationEvidence'] = {'document_id':test['verificationDocumentId'],'authorized_by':'independent-restore-auditor',
        'observed_at':test['verifiedAt'],'expires_at':out['created_at'],
        '_provenance':{'source_operation':'external:restore-validation','representation':'full','read_only':True},
        'vaultId':VAULT,'protectedItemId':ITEM,'jobId':JOB,'sourceRecoveryPointId':POINT,'restoreTargetId':TARGET,
        'credential_context_id':capture['credential_context_id'],'customer_context_id':capture['customer_context_id'],
        'nativeEvidenceSha256':digest({'job':data(out,'backup_job'),'protected_item':data(out,'backup_protected_item'),'capture':capture}),
        'usableDataValidation':{'testId':'inert-independent-restored-data-test','method':'database-consistency-check',
            'result':'Passed','resultArtifactSha256':'a'*64}}
    jobs = next(e for e in out['collections'] if e['type']=='backup_job')['items']
    window.update(document_id='external-complete-test-registry',authorized_by='independent-restore-auditor',
        observed_at=out['created_at'],expires_at=out['created_at'],
        credential_context_id=capture['credential_context_id'],customer_context_id=capture['customer_context_id'],
        jobsInventorySha256=digest({'jobs':jobs,'capture':capture}))
    window['_provenance'].update(source_operation='external:restore-test-registry',representation='full')
    return reseal(out)


def test_complete_independent_validation_binds_actual_native_capture(monkeypatch):
    native = captured(monkeypatch)
    assert status(native)=='UNKNOWN'  # No hosted external-result intake is invented.
    assert status(fully_specified(native))=='PASS', status.last_findings


def test_missing_required_external_bindings_remain_unknown(monkeypatch):
    for field in ('vaultId','protectedItemId','jobId','sourceRecoveryPointId','restoreTargetId','authorized_by',
                  'document_id','credential_context_id','customer_context_id','nativeEvidenceSha256','usableDataValidation'):
        snap = fully_specified(captured(monkeypatch));del data(snap,'backup_restore_test')['validationEvidence'][field]
        assert status(reseal(snap))=='UNKNOWN',field


def test_foreign_or_conflicting_resource_bindings_remain_unknown(monkeypatch):
    for field,value in [('vaultId',VAULT+'other'),('protectedItemId',ITEM+'other'),('jobId',JOB+'other'),
            ('sourceRecoveryPointId',ITEM+'other/recoveryPoints/p'),('restoreTargetId',TARGET+'other')]:
        snap=fully_specified(captured(monkeypatch));data(snap,'backup_restore_test')['validationEvidence'][field]=value
        assert status(reseal(snap))=='UNKNOWN',field


def test_capture_and_native_digest_cannot_be_reused_after_mutation(monkeypatch):
    for mode in ('old-credential','foreign-customer','bad-digest','changed-job','changed-item','unread-native'):
        snap=fully_specified(captured(monkeypatch));evidence=data(snap,'backup_restore_test')['validationEvidence']
        if mode=='old-credential': evidence['credential_context_id']='previous-capture'
        elif mode=='foreign-customer': evidence['customer_context_id']='another-customer'
        elif mode=='bad-digest': evidence['nativeEvidenceSha256']='b'*64
        elif mode=='changed-job': data(snap,'backup_job')['properties']['entityFriendlyName']='changed-after-validation'
        elif mode=='changed-item': data(snap,'backup_protected_item')['properties']['virtualMachineId']=TARGET
        else: data(snap,'backup_job')['_provenance']['read_only']=False
        assert status(reseal(snap))=='UNKNOWN',mode


def test_restore_registry_history_requires_own_current_external_authority(monkeypatch):
    for mode in ('missing-authorization','stale','other-capture','incomplete-jobs','incomplete-tests','bad-history-digest'):
        snap=fully_specified(captured(monkeypatch));window=data(snap,'backup_restore_window')
        if mode=='missing-authorization':del window['authorized_by']
        elif mode=='stale':window['expires_at']=(datetime.fromisoformat(snap['created_at'])-timedelta(days=1)).isoformat()
        elif mode=='other-capture':window['customer_context_id']='another-customer'
        elif mode=='incomplete-jobs':window['jobsComplete']=False
        elif mode=='incomplete-tests':window['testsComplete']=False
        else:window['jobsInventorySha256']='b'*64
        assert status(reseal(snap))=='UNKNOWN',mode


def test_usable_data_test_cannot_be_replaced_by_metadata_or_job_status(monkeypatch):
    for method in ('restore-job-status','metadata-only','future-method'):
        snap=fully_specified(captured(monkeypatch));data(snap,'backup_restore_test')['validationEvidence']['usableDataValidation']['method']=method
        assert status(reseal(snap))=='UNKNOWN'


def test_observed_failed_usable_data_validation_is_a_real_failure(monkeypatch):
    snap=fully_specified(captured(monkeypatch));test=data(snap,'backup_restore_test')
    test['result']='Failed';test['restoredDataVerified']=False
    test['validationEvidence']['usableDataValidation']['result']='Failed'
    assert status(reseal(snap))=='FAIL', status.last_findings


def test_wrong_or_unsupported_native_job_type_cannot_supply_restore_proof(monkeypatch):
    for kind in ('AzureStorageJob','FutureJob'):
        native=captured(monkeypatch);data(native,'backup_job')['properties']['jobType']=kind
        # Recompute externally asserted binding so the actual native type guard is exercised.
        assert status(fully_specified(reseal(native)))=='UNKNOWN'


def test_native_restore_metadata_requires_real_readonly_operation_authority(monkeypatch):
    for kind in ('backup_job','backup_protected_item','recovery_vault'):
        for field in ('read_only','source_operation','representation','api_version'):
            native=captured(monkeypatch)
            data(native,kind)['_provenance'].pop(field,None)
            assert status(fully_specified(reseal(native)))=='UNKNOWN',(kind,field,status.last_findings)


def test_restore_target_and_source_point_reject_invalid_arm_segments(monkeypatch):
    for bad in (BASE+'Microsoft.Compute/virtualMachines',TARGET+'/..',TARGET+'/%2fchild',
                TARGET+'/type/%2e%2e',TARGET+'?token=ignored',TARGET+'/childType'):
        snap=fully_specified(captured(monkeypatch));test=data(snap,'backup_restore_test')
        test['restoreTargetId']=test['validationEvidence']['restoreTargetId']=bad
        assert status(reseal(snap))=='UNKNOWN',bad
    for point in (ITEM+'/recoveryPoints/.',ITEM+'/recoveryPoints/..',ITEM+'/recoveryPoints/%2e%2e',ITEM+'/recoveryPoints/%2Fother'):
        snap=fully_specified(captured(monkeypatch));test=data(snap,'backup_restore_test')
        test['sourceRecoveryPointId']=test['validationEvidence']['sourceRecoveryPointId']=point
        assert status(reseal(snap))=='UNKNOWN',point
