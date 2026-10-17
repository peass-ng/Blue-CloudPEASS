"""C5 native ARM metadata and explicitly supplied external audit observations."""
import copy
from datetime import datetime, timedelta, timezone
from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_bulk_native import Transport, SCOPE, SUB, BASE, parent, routes
from tests.test_peaso_backup_restore_native_binding import fully_specified, data, digest

RESTORE='azure_c5_ops_08_01b'
MONITOR='azure_c5_ops_07_01b'
VAULT=BASE+'Microsoft.RecoveryServices/vaults/vault'
ITEM=VAULT+'/backupFabrics/Azure/protectionContainers/container/protectedItems/item'
JOB=VAULT+'/backupJobs/restore-job'
AZURE_COLLECT=azure.collect


def reseal(snap):
    return make_snapshot('azure',snap['scopes'],snap['collections'],metadata=snap['metadata'],created_at=snap['created_at'])


def captured(monkeypatch, cid, job_status='Completed', mode='complete'):
    now=datetime.now(timezone.utc)
    responses=routes('recovery_vault',VAULT,{})
    protected=parent(ITEM,'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems',
        {'backupManagementType':'AzureIaasVM','protectedItemType':'Microsoft.Compute/virtualMachines','workloadType':'VM',
         'virtualMachineId':BASE+'Microsoft.Compute/virtualMachines/source','protectionState':'Protected',
         'lastBackupStatus':'Completed','lastRecoveryPoint':(now-timedelta(days=1)).isoformat()})
    job=parent(JOB,'Microsoft.RecoveryServices/vaults/backupJobs',{'jobType':'AzureIaaSVMJob','backupManagementType':'AzureIaasVM',
        'operation':'Restore' if cid==RESTORE else 'Backup','status':job_status,'entityFriendlyName':'ambiguous-display-name',
        'startTime':(now-timedelta(days=2,hours=1)).isoformat(),'endTime':(now-timedelta(days=2)).isoformat()})
    responses[VAULT+'/backupProtectedItems']={'value':[protected]}
    responses[VAULT+'/backupJobs']={'value':[job]}
    if mode=='denied':responses[VAULT+'/backupJobs']=azure.AzureReadError('inert_job_denied',403)
    api=Transport(responses)
    def native(connector,kinds):return AZURE_COLLECT(connector,kinds,transport=api)
    monkeypatch.setattr(azure,'collect',native)
    policy={'sw22':{'restore_tests':{'status':'collected','scope':SCOPE,'evidence_ref':'approved-class-scope',
        'maxRestoreTestAgeDays':3,'requiredProtectedItemIds':[ITEM],
        'data_classes':[{'data_class':value,'required_item_ids':[ITEM]} for value in ('customer','derived','provider')]}},
        'sw31':{'requiredBackupItemIds':[ITEM],'requiredBackupItems':[{'id':ITEM,'dataClass':'customer','workloadType':'VM'}],
                'ops06MaxAgeDays':3,'ops06DocumentId':'approved-ops06-policy'}}
    connector={'provider':'azure','scopes':[SUB],'options':{'retries':0,'compliance_policy':policy}}
    plan=plan_collection({'connector':connector,'checks':[cid]})
    assert {'backup_job','backup_protected_item','recovery_vault'} <= set(plan)
    snap=collect_live(connector,plan)
    assert api.calls and all(url.startswith(azure.ARM) for url in api.calls)
    return snap


def replace(snap,kind,rows):
    snap['collections']=[env for env in snap['collections'] if env['type']!=kind]
    snap['collections'].append({'type':kind,'scope':SCOPE,'service':'external:audit','status':'collected' if rows else 'empty','items':rows})


def supplied_restore(native,full=True,legacy_owner=False):
    snap=fully_specified(native)
    if legacy_owner:
        snap['metadata']['sw22']=copy.deepcopy(snap['metadata']['compliance_policy']['sw22'])
    template=data(snap,'backup_restore_test')
    records=[]
    for cls in ('customer','derived','provider'):
        record={'id':VAULT+'/restoreValidation/'+cls,'scope':SCOPE,'protected_item_id':ITEM,'job_id':JOB,
            'data_class':cls,'identity_basis':'stable_resource_id','identity_evidence_ref':'independent-source-target-record',
            'evidence_ref':template['verificationDocumentId'],'validated_at':template['verifiedAt'],'validation_result':'Passed',
            '_provenance':{'source_operation':'external:restore-validation','read_only':True,'representation':'full'}}
        if full:
            record.update(source_recovery_point_id=template['sourceRecoveryPointId'],restore_target_id=template['restoreTargetId'],
                          restored_data_verified=True,validationEvidence=copy.deepcopy(template['validationEvidence']))
            record['validationEvidence']['dataClass']=cls
        records.append(record)
    replace(snap,'restore_test_record',records)
    return reseal(snap)


def supplied_monitor(native,full=True):
    snap=copy.deepcopy(native);at=datetime.fromisoformat(snap['created_at'])
    proof={'id':VAULT+'/backupMonitorEvidence/e','scope':SCOPE,
        '_provenance':{'source_operation':'external:backup-monitor-validation','read_only':True,'representation':'full'},
        'properties':{'protectedItemId':ITEM,'workloadType':'VM','dataClass':'customer','observedJobIds':[JOB],
                      'ops06Documented':True,'jobAlertsRouted':True}}
    if full:
        capture={key:snap['metadata'][key] for key in ('tenant_id','credential_context_id','customer_context_id')}
        jobs=next(e for e in snap['collections'] if e['type']=='backup_job')['items']
        proof['properties']['monitoringValidation']={'document_id':'independent-monitor-review','authorized_by':'independent-auditor',
            'observed_at':snap['created_at'],'expires_at':snap['created_at'],
            '_provenance':{'source_operation':'external:backup-monitor-validation','read_only':True,'representation':'full'},
            'protectedItemId':ITEM,'workloadType':'VM','dataClass':'customer','policyDocumentId':'approved-ops06-policy',
            'windowStart':(at-timedelta(days=4)).isoformat(),'windowEnd':snap['created_at'],'historyComplete':True,
            'credential_context_id':capture['credential_context_id'],'customer_context_id':capture['customer_context_id'],
            'nativeEvidenceSha256':digest({'protected_item':data(snap,'backup_protected_item'),'jobs':jobs,'capture':capture}),
            'jobBindings':[{'jobId':JOB,'protectedItemId':ITEM,'workloadType':'VM','dataClass':'customer',
                'observedAt':snap['created_at'],'jobStatus':data(snap,'backup_job')['properties']['status'],
                'monitoringResult':'DocumentedAndRouted','resultArtifactSha256':'a'*64}]}
    replace(snap,'backup_monitor_evidence',[proof])
    return reseal(snap)


def status(snap,cid):
    findings=[f for f in evaluate_snapshot(snap,checks=[cid],include_not_applicable=True)['findings'] if f['check_id']==cid]
    assert len(findings)==1
    status.last_findings=findings
    return findings[0]['status']


def test_c5_restore_reference_only_records_never_demonstrate_usable_data(monkeypatch):
    assert status(supplied_restore(captured(monkeypatch,RESTORE),False,True),RESTORE)=='UNKNOWN',status.last_findings
    assert status(supplied_monitor(captured(monkeypatch,MONITOR),False),MONITOR)=='UNKNOWN',status.last_findings


def test_c5_monitor_supports_explicit_external_item_job_mapping_on_real_native_fields(monkeypatch):
    snap=supplied_monitor(captured(monkeypatch,MONITOR))
    assert 'protectedItemId' not in data(snap,'backup_job')['properties']
    assert status(snap,MONITOR)=='PASS',status.last_findings


def test_full_c5_restore_preserves_explicit_three_class_scope_and_normal_policy_namespace(monkeypatch):
    snap=supplied_restore(captured(monkeypatch,RESTORE))
    assert 'sw22' not in snap['metadata']
    assert status(snap,RESTORE)=='PASS',status.last_findings


def test_missing_external_authorization_or_class_evidence_is_unknown(monkeypatch):
    for cid in (RESTORE,MONITOR):
        snap=supplied_restore(captured(monkeypatch,cid)) if cid==RESTORE else supplied_monitor(captured(monkeypatch,cid))
        if cid==RESTORE:
            data(snap,'restore_test_record')['validationEvidence'].pop('authorized_by')
        else:data(snap,'backup_monitor_evidence')['properties']['monitoringValidation'].pop('authorized_by')
        assert status(reseal(snap),cid)=='UNKNOWN'
        snap=supplied_restore(captured(monkeypatch,cid)) if cid==RESTORE else supplied_monitor(captured(monkeypatch,cid))
        if cid==RESTORE:data(snap,'restore_test_record')['validationEvidence']['dataClass']='other'
        else:data(snap,'backup_monitor_evidence')['properties']['monitoringValidation']['dataClass']='other'
        assert status(reseal(snap),cid)=='UNKNOWN'


def test_foreign_capture_and_tampered_native_bytes_do_not_reuse_external_proof(monkeypatch):
    for cid in (RESTORE,MONITOR):
        for mode in ('foreign-customer','changed-native'):
            snap=supplied_restore(captured(monkeypatch,cid)) if cid==RESTORE else supplied_monitor(captured(monkeypatch,cid))
            if mode=='changed-native':data(snap,'backup_job')['properties']['entityFriendlyName']='changed-after-independent-review'
            elif cid==RESTORE:data(snap,'restore_test_record')['validationEvidence']['customer_context_id']='other-customer'
            else:data(snap,'backup_monitor_evidence')['properties']['monitoringValidation']['customer_context_id']='other-customer'
            assert status(reseal(snap),cid)=='UNKNOWN'


def test_wrong_native_workload_or_backup_restore_operation_is_unknown(monkeypatch):
    for cid in (RESTORE,MONITOR):
        native=captured(monkeypatch,cid);data(native,'backup_job')['properties']['backupManagementType']='AzureStorage'
        snap=supplied_restore(reseal(native)) if cid==RESTORE else supplied_monitor(reseal(native))
        assert status(snap,cid)=='UNKNOWN'
    native=captured(monkeypatch,MONITOR);data(native,'backup_job')['properties']['operation']='Restore'
    assert status(supplied_monitor(reseal(native)),MONITOR)=='UNKNOWN'


def test_history_gaps_and_class_inventory_gaps_do_not_prove_missing_test(monkeypatch):
    for cid in (RESTORE,MONITOR):
        snap=supplied_restore(captured(monkeypatch,cid)) if cid==RESTORE else supplied_monitor(captured(monkeypatch,cid))
        if cid==RESTORE:data(snap,'backup_restore_window')['testsComplete']=False
        else:data(snap,'backup_monitor_evidence')['properties']['monitoringValidation']['historyComplete']=False
        assert status(reseal(snap),cid)=='UNKNOWN'
    snap=supplied_restore(captured(monkeypatch,RESTORE))
    snap['metadata']['compliance_policy']['sw22']['restore_tests']['data_classes'].pop()
    assert status(reseal(snap),RESTORE)=='UNKNOWN'


def test_coherent_independent_failed_test_or_missing_monitor_process_is_fail(monkeypatch):
    snap=supplied_restore(captured(monkeypatch,RESTORE));r=data(snap,'restore_test_record')
    r['validation_result']='Failed';r['restored_data_verified']=False;r['validationEvidence']['usableDataValidation']['result']='Failed'
    assert status(reseal(snap),RESTORE)=='FAIL',status.last_findings
    snap=supplied_monitor(captured(monkeypatch,MONITOR));p=data(snap,'backup_monitor_evidence')['properties']
    p['jobAlertsRouted']=False;p['monitoringValidation']['jobBindings'][0]['monitoringResult']='MissingAlertRouting'
    assert status(reseal(snap),MONITOR)=='FAIL',status.last_findings


def test_incomplete_native_source_never_certifies_but_retained_backup_failure_survives(monkeypatch):
    for cid in (RESTORE,MONITOR):
        native=captured(monkeypatch,cid);snap=supplied_restore(native) if cid==RESTORE else supplied_monitor(native)
        env=next(e for e in snap['collections'] if e['type']=='backup_job');env['status']='partial'
        assert status(reseal(snap),cid)=='UNKNOWN'
    native=captured(monkeypatch,MONITOR);data(native,'backup_protected_item')['properties']['lastBackupStatus']='Failed'
    assert status(reseal(native),MONITOR)=='FAIL',status.last_findings


def test_external_bindings_cannot_use_friendly_name_or_different_job(monkeypatch):
    snap=supplied_restore(captured(monkeypatch,RESTORE));data(snap,'restore_test_record')['identity_basis']='entityFriendlyName'
    assert status(reseal(snap),RESTORE)=='UNKNOWN'
    snap=supplied_monitor(captured(monkeypatch,MONITOR));data(snap,'backup_monitor_evidence')['properties']['monitoringValidation']['jobBindings'][0]['jobId']=JOB+'other'
    assert status(reseal(snap),MONITOR)=='UNKNOWN'
