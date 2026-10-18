"""Exact ARM storage default-retention and recovery-point expiry metadata."""
from __future__ import annotations
import copy
import re
from datetime import datetime,timezone

ARM='https://management.azure.com'
STORAGE_VERSION='2023-05-01'
BACKUP_VERSION='2024-04-01'
IMMUTABLE='azure_storage_account_10_3_4_7_02943e9'
POINTS='azure_recovery_vault_10_3_3_3_45b190e'
NATIVE_TYPES={'storage_immutability_evidence','backup_recovery_point'}
_SEG=r'[^/?#%\x00-\x20]+'
_SUB=r'/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'


def required_types(wanted):
    out=set()
    if 'storage_immutability_evidence'in wanted:out.add('storage_account')
    if 'backup_recovery_point'in wanted:out.update(('recovery_vault','backup_protected_item'))
    return out


def _time(value):
    if not isinstance(value,str):raise ValueError('native timestamp missing')
    t=datetime.fromisoformat(value.replace('Z','+00:00'))
    if t.utcoffset()is None:raise ValueError('native timestamp timezone missing')
    return t.astimezone(timezone.utc)


def normalize(options):
    params=options.get('compliance_parameters',{})
    if not isinstance(params,dict):raise ValueError('invalid compliance parameters')
    if 'azure_storage_recovery'not in params:return None
    raw=params['azure_storage_recovery']
    required={'scope','status','authorized_by','document_id','observed_at','expires_at','controls'}
    if not isinstance(raw,dict)or set(raw)!=required or not isinstance(raw['scope'],str)or not re.fullmatch(_SUB,raw['scope'],re.I)or raw['status']!='collected':raise ValueError('invalid storage/recovery owner review')
    for name in('authorized_by','document_id'):
        if not isinstance(raw[name],str)or not 0<len(raw[name])<=512 or raw[name].strip()!=raw[name]or any(ord(c)<32 for c in raw[name]):raise ValueError('invalid approval identity')
    if not _time(raw['observed_at'])<_time(raw['expires_at']):raise ValueError('invalid approval window')
    controls=raw['controls']
    if not isinstance(controls,dict)or not controls or set(controls)-{'defaultImmutability','recoveryPointRetention'}:raise ValueError('unsupported retention control')
    if 'defaultImmutability'in controls:
        v=controls['defaultImmutability']
        if not isinstance(v,dict)or set(v)!={'accountIds'}or not isinstance(v['accountIds'],list)or len(v['accountIds'])>1000:raise ValueError('invalid immutability account policy')
        ids=v['accountIds']
        if any(not isinstance(r,str)or not re.fullmatch(re.escape(raw['scope'])+'/resourceGroups/'+_SEG+'/providers/Microsoft.Storage/storageAccounts/'+_SEG,r,re.I)for r in ids)or len({r.casefold()for r in ids})!=len(ids):raise ValueError('foreign or duplicate approved account')
    if 'recoveryPointRetention'in controls:
        v=controls['recoveryPointRetention']
        if not isinstance(v,dict)or set(v)!={'minRetentionDays'}or type(v['minRetentionDays'])is not int or not 0<v['minRetentionDays']<=146000:raise ValueError('invalid recovery point retention')
    return copy.deepcopy(raw)


def owner_policy(options,scopes):
    review=normalize(options)
    if not review or review['scope'].casefold()not in{s.casefold()for s in scopes}:return {}
    if 'recoveryPointRetention'not in review['controls']:return {}
    return {**{k:review[k]for k in('scope','status','authorized_by','document_id','observed_at','expires_at')},
            'checks':{POINTS.replace('.','|'):copy.deepcopy(review['controls']['recoveryPointRetention'])}}


def _id(value,parent,suffix):
    if not isinstance(value,str)or not re.fullmatch(re.escape(parent)+suffix,value,re.I)or any(p in('.', '..')for p in value.split('/')):raise ValueError('foreign native retention identity')
    return value


def _parent(reader,kind,scope):
    from .azure import AzureReadError
    rows=[c for c in reader.collections if c['type']==kind and c['scope'].casefold()==scope.casefold()]
    if len(rows)!=1 or rows[0]['status']not in('collected','empty'):raise AzureReadError('native_retention_parent_incomplete')
    return rows[0]['items']


def _get(reader,request,rid,version,typ):
    raw=reader.call(request,ARM+rid+'?api-version='+version)
    if not isinstance(raw,dict)or str(raw.get('id','')).casefold()!=rid.casefold()or str(raw.get('type','')).casefold()!=typ.casefold()or not isinstance(raw.get('properties'),dict):raise ValueError('native retention GET identity/type mismatch')
    return raw


def _list(reader,request,parent,path,version):
    seen=set()
    for page in reader.pages(request,ARM+parent+'/'+path+'?api-version='+version):
        for raw in page:
            if not isinstance(raw,dict):raise ValueError('native retention list item malformed')
            rid=_id(raw.get('id'),parent,'/'+re.escape(path)+'/'+_SEG)
            if rid.casefold()in seen:raise ValueError('duplicate native retention child')
            seen.add(rid.casefold())
            if reader.budget.max_items is not None and len(seen)>reader.budget.max_items:
                from .azure import AzureReadError
                raise AzureReadError('resource_limit')
            yield raw


def _policy(value):
    if not isinstance(value,dict)or value.get('state')not in('Locked','Unlocked','Disabled')or type(value.get('immutabilityPeriodSinceCreationInDays'))is not int or not 1<=value['immutabilityPeriodSinceCreationInDays']<=146000:raise ValueError('native immutability policy unresolved')
    return {k:value[k]for k in('state','immutabilityPeriodSinceCreationInDays')}


def _immutability(reader,request,account):
    from .azure import AzureReadError
    aid=account['id'];full=_get(reader,request,aid,STORAGE_VERSION,'Microsoft.Storage/storageAccounts');props=full['properties']
    account_mode=props.get('immutableStorageWithVersioning')
    if not isinstance(account_mode,dict)or type(account_mode.get('enabled'))is not bool:raise AzureReadError('native_account_version_immutability_mode_unresolved')
    containers=[]
    for summary in _list(reader,request,aid,'blobServices/default/containers',STORAGE_VERSION):
        cid=summary['id'];container=_get(reader,request,cid,STORAGE_VERSION,'Microsoft.Storage/storageAccounts/blobServices/containers');cp=container['properties']
        if cp.get('deleted')is True:raise AzureReadError('native_deleted_container_scope_unresolved')
        mode=cp.get('immutableStorageWithVersioning')
        if not isinstance(mode,dict)or type(mode.get('enabled'))is not bool:raise AzureReadError('native_container_version_immutability_mode_unresolved')
        if mode.get('migrationState')not in(None,'Completed'):raise AzureReadError('native_immutability_migration_incomplete')
        if account_mode['enabled']and not mode['enabled']:raise AzureReadError('native_immutability_inheritance_conflict')
        has=cp.get('hasImmutabilityPolicy')
        if type(has)is not bool:raise AzureReadError('native_container_default_policy_presence_unresolved')
        embedded=cp.get('immutabilityPolicy')
        if embedded is not None and not has:raise AzureReadError('native_immutability_policy_presence_conflict')
        effective={'read_complete':True,'inheritance_resolved':True}
        if has:
            policy_id=cid+'/immutabilityPolicies/default'
            policy=_get(reader,request,policy_id,STORAGE_VERSION,'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies')
            actual=_policy(policy['properties'])
            if embedded is not None and (not isinstance(embedded,dict)or _policy(embedded.get('properties'))!=actual):raise AzureReadError('native_immutability_policy_detail_conflict')
            effective.update(present=True,properties=actual,new_writes_inherit=actual['state']!='Disabled',
              source_kind='container_version_default'if mode['enabled']else'container_time',source_id=cid if mode['enabled']else policy_id,
              native_source_id=policy_id)
        elif mode['enabled']and account_mode['enabled']and account_mode.get('immutabilityPolicy')is not None:
            actual=_policy(account_mode['immutabilityPolicy'])
            effective.update(present=True,properties=actual,new_writes_inherit=actual['state']!='Disabled',source_kind='account_version_default',source_id=aid)
        else:
            effective.update(present=False,new_writes_inherit=False)
        containers.append({'id':cid,'container_read_complete':True,'default_version_policy_support_resolved':True,'effective_default_policy':effective})
    return {'account_read_complete':True,'containers':{'collection_status':'collected'if containers else'empty','items':containers}}


def collect(reader,request,scopes,wanted,options):
    if not NATIVE_TYPES.intersection(wanted):return
    review=normalize(options)
    for scope in scopes:
        jobs=[]
        if 'storage_immutability_evidence'in wanted:
            def storage(scope=scope):
                for account in _parent(reader,'storage_account',scope):
                    aid=_id(account.get('id'),scope,'/resourceGroups/'+_SEG+'/providers/Microsoft.Storage/storageAccounts/'+_SEG)
                    payload=_immutability(reader,request,account)
                    approved=bool(review and review['scope'].casefold()==scope.casefold()and _time(review['observed_at'])<=datetime.now(timezone.utc)<=_time(review['expires_at'])and aid.casefold()in{r.casefold()for r in review['controls'].get('defaultImmutability',{}).get('accountIds',[])})
                    yield [{'id':aid+'/complianceEvidence/defaultImmutability','parent_id':aid,'payload':payload,'_provenance':{'schema_version':1,'read_only':True,'complete':True,'policy_approved':approved,'captured_at':'pending_native_snapshot_binding','source_operation':'storageAccounts.GET+containers.LIST/GET+immutabilityPolicies.GET'}}]
            jobs.append(('storage_immutability_evidence',scope,'Microsoft.Storage',storage))
        if 'backup_recovery_point'in wanted:
            def points(scope=scope):
                from .azure import AzureReadError
                vaults={v['id'].casefold():v['id']for v in _parent(reader,'recovery_vault',scope)}
                for protected in _parent(reader,'backup_protected_item',scope):
                    pid=protected.get('id');vault=protected.get('parent_id')
                    if not isinstance(vault,str)or vault.casefold()not in vaults:raise ValueError('protected item native vault parent missing')
                    _id(pid,vault,'/backupFabrics/'+_SEG+'/protectionContainers/'+_SEG+'/protectedItems/'+_SEG)
                    state=protected.get('properties',{}).get('protectionState')
                    if state not in('Protected','ProtectionStopped','SoftDeleted'):raise AzureReadError('native_protected_item_state_unresolved')
                    if state!='Protected':continue
                    pp=protected['properties']
                    if pp.get('backupManagementType')!='AzureStorage'or pp.get('workloadType')!='AzureFileShare'or pp.get('protectedItemType')!='AzureFileShareProtectedItem':raise AzureReadError('native_point_metadata_workload_unsupported')
                    for summary in _list(reader,request,pid,'recoveryPoints',BACKUP_VERSION):
                        rid=summary['id'];detail=_get(reader,request,rid,BACKUP_VERSION,'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints');props=detail['properties']
                        if props.get('objectType')!='AzureFileShareRecoveryPoint':raise AzureReadError('native_point_expiry_workload_unsupported')
                        native=props.get('recoveryPointProperties')
                        if not isinstance(native,dict)or type(native.get('isSoftDeleted'))is not bool:raise ValueError('native point deletion state missing')
                        if 'isSoftDeleted'in props and props['isSoftDeleted']is not native['isSoftDeleted']:raise ValueError('conflicting point deletion state')
                        projected={'isSoftDeleted':native['isSoftDeleted']}
                        if not native['isSoftDeleted']:
                            created=_time(props.get('recoveryPointTime'));expiry=_time(native.get('expiryTime'))
                            if expiry<created:raise ValueError('native recovery point expiry predates creation')
                            projected.update(recoveryPointTime=props['recoveryPointTime'],recoveryPointProperties={'expiryTime':native['expiryTime']})
                        yield [{'id':rid,'parent_id':pid,'properties':projected,'_provenance':{'read_only':True,'detail_get_complete':True,'retention_schema_supported':True,'source_operation':'RecoveryPoints.List/Get','api_version':BACKUP_VERSION,'field_mapping':{'properties.isSoftDeleted':'properties.recoveryPointProperties.isSoftDeleted'}}}]
            jobs.append(('backup_recovery_point',scope,'Microsoft.RecoveryServices',points))
        reader.run(jobs)


def snapshot_instant(collections,wanted):
    if not NATIVE_TYPES.intersection(wanted):return None
    instant=datetime.now(timezone.utc).isoformat()
    for collection in collections:
        if collection['type']=='storage_immutability_evidence':
            for row in collection['items']:row['_provenance']['captured_at']=instant
    return instant
