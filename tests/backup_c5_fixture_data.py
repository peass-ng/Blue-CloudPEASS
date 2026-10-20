"""Deterministic synthetic C5 audit fixtures; never native/live proof."""
import copy
import json
import hashlib
from datetime import datetime, timedelta

RESTORE='azure_c5_ops_08_01b'
MONITOR='azure_c5_ops_07_01b'


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()


def fixture_index(cid,scope,stamp):
    at=datetime.fromisoformat(stamp.replace('Z','+00:00'))
    vault=scope+'/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/vault'
    item=vault+'/backupFabrics/Azure/protectionContainers/container/protectedItems/item'
    job_id=vault+'/backupJobs/job';point=item+'/recoveryPoints/p';target=scope+'/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/restored'
    capture={'tenant_id':'synthetic-tenant','credential_context_id':'synthetic-c5-capture','customer_context_id':'synthetic-c5-customer'}
    row_proof=lambda operation,representation,**extra:{'read_only':True,'source_operation':operation,'representation':representation,
        'api_version':'2024-04-01','credential_context_id':capture['credential_context_id'],'customer_context_id':capture['customer_context_id'],**extra}
    vault_row={'id':vault,'properties':{},'_provenance':row_proof('get','full')}
    protected={'id':item,'parent_id':vault,'properties':{'backupManagementType':'AzureIaasVM','protectedItemType':'Microsoft.Compute/virtualMachines',
        'workloadType':'VM','protectionState':'Protected','lastBackupStatus':'Completed','lastRecoveryPoint':(at-timedelta(days=1)).isoformat()},
        '_provenance':row_proof('BackupProtectedItems_List','metadata',endpoint=vault+'/backupProtectedItems')}
    job={'id':job_id,'parent_id':vault,'properties':{'jobType':'AzureIaaSVMJob','backupManagementType':'AzureIaasVM',
        'operation':'Restore' if cid==RESTORE else 'Backup','status':'Completed','entityFriendlyName':'unused-display-name',
        'startTime':(at-timedelta(days=2,hours=1)).isoformat(),'endTime':(at-timedelta(days=2)).isoformat()},
        '_provenance':row_proof('BackupJobs_List','metadata',endpoint=vault+'/backupJobs')}
    rows={'recovery_vault':[vault_row],'backup_protected_item':[protected],'backup_job':[job]}
    expiry=(at+timedelta(days=1)).isoformat()
    if cid==RESTORE:
        owner={'status':'collected','scope':scope,'evidence_ref':'explicit-required-data-classes','maxRestoreTestAgeDays':365,
            'requiredProtectedItemIds':[item],'data_classes':[{'data_class':cls,'required_item_ids':[item]} for cls in ('customer','derived','provider')]}
        metadata={'sw22':{'restore_tests':owner},'compliance_policy':{'sw22':{'restore_tests':owner}}}
        records=[]
        for cls in ('customer','derived','provider'):
            observed=(at-timedelta(days=1)).isoformat();document='independent-synthetic-validation-'+cls
            validation={'document_id':document,'authorized_by':'independent-synthetic-auditor','observed_at':observed,'expires_at':expiry,
                '_provenance':{'read_only':True,'source_operation':'external:restore-validation','representation':'full'},
                'vaultId':vault,'protectedItemId':item,'jobId':job_id,'sourceRecoveryPointId':point,'restoreTargetId':target,'dataClass':cls,
                'credential_context_id':capture['credential_context_id'],'customer_context_id':capture['customer_context_id'],
                'nativeEvidenceSha256':digest({'job':job,'protected_item':protected,'capture':capture}),
                'usableDataValidation':{'testId':'synthetic-usable-data-'+cls,'method':'database-consistency-check','result':'Passed','resultArtifactSha256':'a'*64}}
            records.append({'id':vault+'/restoreValidation/'+cls,'scope':scope,'protected_item_id':item,'job_id':job_id,'data_class':cls,
                'identity_basis':'stable_resource_id','identity_evidence_ref':'independent-explicit-source-target-mapping',
                'evidence_ref':document,'validated_at':observed,'validation_result':'Passed','source_recovery_point_id':point,
                'restore_target_id':target,'restored_data_verified':True,'validationEvidence':validation,
                '_provenance':{'source_operation':'external:restore-validation','read_only':True,'representation':'full'}})
        window={'id':vault+'/restoreWindows/window','scope':scope,'vaultId':vault,'windowStart':(at-timedelta(days=366)).isoformat(),
            'windowEnd':stamp,'jobsComplete':True,'testsComplete':True,'document_id':'independent-synthetic-complete-history',
            'authorized_by':'independent-synthetic-auditor','observed_at':stamp,'expires_at':expiry,
            '_provenance':{'source_operation':'external:restore-test-registry','read_only':True,'representation':'full'},
            'credential_context_id':capture['credential_context_id'],'customer_context_id':capture['customer_context_id'],
            'jobsInventorySha256':digest({'jobs':[job],'capture':capture})}
        rows.update(restore_test_record=records,backup_restore_window=[window])
    else:
        owner={'requiredBackupItemIds':[item],'requiredBackupItems':[{'id':item,'dataClass':'customer','workloadType':'VM'}],
            'ops06MaxAgeDays':14,'ops06DocumentId':'approved-synthetic-ops06-policy'}
        metadata={'compliance_policy':{'sw31':owner}}
        validation={'document_id':'independent-synthetic-monitor-review','authorized_by':'independent-synthetic-auditor','observed_at':stamp,'expires_at':expiry,
            '_provenance':{'source_operation':'external:backup-monitor-validation','read_only':True,'representation':'full'},
            'protectedItemId':item,'workloadType':'VM','dataClass':'customer','policyDocumentId':owner['ops06DocumentId'],
            'windowStart':(at-timedelta(days=15)).isoformat(),'windowEnd':stamp,'historyComplete':True,
            'credential_context_id':capture['credential_context_id'],'customer_context_id':capture['customer_context_id'],
            'nativeEvidenceSha256':digest({'protected_item':protected,'jobs':[job],'capture':capture}),
            'jobBindings':[{'jobId':job_id,'protectedItemId':item,'workloadType':'VM','dataClass':'customer','observedAt':stamp,
                'jobStatus':'Completed','monitoringResult':'DocumentedAndRouted','resultArtifactSha256':'a'*64}]}
        rows['backup_monitor_evidence']=[{'id':vault+'/monitorEvidence/e','scope':scope,
            '_provenance':{'source_operation':'external:backup-monitor-validation','read_only':True,'representation':'full'},
            'properties':{'protectedItemId':item,'workloadType':'VM','dataClass':'customer','observedJobIds':[job_id],
                'ops06Documented':True,'jobAlertsRouted':True,'monitoringValidation':validation}}]
    metadata.update(capture,tenant_verified=True)
    collections={};index={'context':{'provider':'azure','scope':scope,'created_at':stamp,'metadata':metadata},'collections':collections}
    for kind,values in rows.items():
        service='Microsoft.RecoveryServices' if kind in ('recovery_vault','backup_job','backup_protected_item') else 'external:audit'
        collections[kind]=[{'type':kind,'scope':scope,'service':service,'status':'collected','items':values,
            '_provenance':{k:capture[k] for k in ('credential_context_id','customer_context_id')}}]
        index[kind]=[{'type':kind,'provider':'azure','scope':scope,'data':value} for value in values]
    return index


def refresh_restore_digests(index):
    capture={k:index['context']['metadata'][k] for k in ('tenant_id','credential_context_id','customer_context_id')}
    jobs=[w['data'] for w in index['backup_job']];protected={w['data']['id'].casefold():w['data'] for w in index['backup_protected_item']}
    for w in index['restore_test_record']:
        r=w['data'];job=next(j for j in jobs if j['id']==r['job_id'])
        r['validationEvidence']['nativeEvidenceSha256']=digest({'job':job,'protected_item':protected[r['protected_item_id'].casefold()],'capture':capture})
    for w in index['backup_restore_window']:
        window=w['data'];window['jobsInventorySha256']=digest({'jobs':[j for j in jobs if j['parent_id']==window['vaultId']],'capture':capture})
