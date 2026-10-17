"""Versioned native regional storage location inventory; no object contents."""
import copy
from concurrent.futures import Future
from datetime import datetime, timezone
import re

VERSION='2026-10-15.storage-locations.v1'
KINDS=('aws_enabled_region','aws_data_resource','aws_data_resource_coverage')
SPECS={kind:('ec2','describe_regions','Regions')for kind in KINDS}
GLOBAL_TYPES=set(KINDS)
NATIVE_IDS={kind:'id'for kind in KINDS}
# Every listed regional endpoint must succeed, including zero-resource endpoints.
# Parent storage containers cover their children in the same native Region;
# no customer-data classification or physical-residency assertion is implied.
CATALOG=(
 ('s3','s3','list_directory_buckets','Buckets','BucketArn'),
 ('s3','outposts','list_outposts','Outposts','OutpostArn'),
 ('s3','s3tables','list_table_buckets','tableBuckets','arn'),
 ('s3','s3vectors','list_vector_buckets','vectorBuckets','vectorBucketArn'),
 ('rds','rds','describe_db_instances','DBInstances','DBInstanceArn'),
 ('rds','rds','describe_db_clusters','DBClusters','DBClusterArn'),
 ('rds','rds','describe_db_snapshots','DBSnapshots','DBSnapshotArn'),
 ('rds','rds','describe_db_cluster_snapshots','DBClusterSnapshots','DBClusterSnapshotArn'),
 ('rds','rds','describe_db_instance_automated_backups','DBInstanceAutomatedBackups','DBInstanceAutomatedBackupsArn'),
 ('rds','rds','describe_db_cluster_automated_backups','DBClusterAutomatedBackups','DBClusterAutomatedBackupsArn'),
 ('ec2_volume','ec2','describe_volumes','Volumes','VolumeId'),
 ('ec2_volume','ec2','describe_snapshots','Snapshots','SnapshotId'),
 ('dynamodb','dynamodb','list_tables','TableNames',None),
 ('dynamodb','dynamodb','list_backups','BackupSummaries','BackupArn'),
 ('efs','efs','describe_file_systems','FileSystems','FileSystemArn'),
 ('redshift','redshift','describe_clusters','Clusters','ClusterIdentifier'),
 ('redshift','redshift','describe_cluster_snapshots','Snapshots','SnapshotArn'),
 ('redshift','redshift-serverless','list_namespaces','namespaces','namespaceArn'),
 ('redshift','redshift-serverless','list_snapshots','snapshots','snapshotArn'),
 ('redshift','redshift-serverless','list_recovery_points','recoveryPoints','recoveryPointId'),
 ('backup','backup','list_backup_vaults','BackupVaultList','BackupVaultArn'),
)
READ_ACTIONS={(service,op)for _,service,op,_,_ in CATALOG}|{('sts','get_caller_identity'),('s3','list_buckets'),('s3','get_bucket_location'),('dynamodb','describe_table'),('backup','list_recovery_points_by_backup_vault'),('s3control','list_regional_buckets')}
_OK={'collected','empty'}
_REGION=r'[a-z]{2}(?:-[a-z]+)+-[0-9]+'

def normalize(options):
    params=options.get('compliance_parameters',{})
    if not isinstance(params,dict):raise ValueError('compliance parameters must be an object')
    value=params.get('aws_data_regions')
    if value is None:return None
    fields={'scope','authorized_by','document_id','observed_at','expires_at','approved_region_names'}
    if not isinstance(value,dict)or set(value)!=fields:raise ValueError('invalid AWS data-region owner requirements')
    if not isinstance(value['scope'],str)or not re.fullmatch(r'[0-9]{12}/global',value['scope']):raise ValueError('invalid AWS data-region owner scope')
    for field in ('authorized_by','document_id'):
        v=value[field]
        if not isinstance(v,str)or not v.strip()or len(v)>512 or any(ord(c)<32 for c in v):raise ValueError('invalid AWS data-region owner identity')
    dates=[]
    for field in ('observed_at','expires_at'):
        try:date=datetime.fromisoformat(value[field].replace('Z','+00:00'))
        except (AttributeError,ValueError,TypeError):raise ValueError('invalid AWS data-region owner date')from None
        if date.utcoffset()is None:raise ValueError('AWS data-region owner dates require timezone')
        dates.append(date)
    if not dates[0]<=datetime.now(timezone.utc)<dates[1]:raise ValueError('AWS data-region owner requirements not current')
    names=value['approved_region_names']
    if not isinstance(names,list)or not 1<=len(names)<=100 or any(not isinstance(n,str)or not re.fullmatch(_REGION,n)or not n.startswith('eu-')for n in names)or len(names)!=len(set(names)):raise ValueError('invalid approved EU Region list')
    return copy.deepcopy(value)

def owner_metadata(policy,scopes):
    if policy is None or {s.split('/')[0]for s in scopes}!={policy['scope'].split('/')[0]}:return {}
    return {'approved_region_names':list(policy['approved_region_names']),
            'aws_data_region_owner':copy.deepcopy(policy)}

def _rows(requests,session,region,service,operation,field,**kwargs):
    from .aws import ReadFailure
    if (service,operation)in {('outposts','list_outposts'),('s3control','list_regional_buckets')}:
        kwargs['_tokens']=('NextToken','NextToken')
    read=requests.pages(session,service,region,operation,field,**kwargs)
    if read.status not in _OK:raise ReadFailure(read.status,(read.error or{}).get('code','data_region_inventory_incomplete'))
    return read.items

def _detail(requests,session,region,service,operation,**kwargs):
    from .aws import ReadFailure
    value=requests.detail(session,service,region,operation,**kwargs)
    if not isinstance(value,dict)or value.get('collection_status')!='collected':raise ReadFailure(value.get('collection_status','malformed')if isinstance(value,dict)else'malformed',(value.get('error')or{}).get('code','data_region_detail_incomplete')if isinstance(value,dict)else'data_region_detail_incomplete')
    return value

def _compute(requests,session,region,account):
    from .aws import ReadResult,ReadFailure
    out={kind:[]for kind in KINDS};seen=set();operations=[]
    def record(rid,observed,group,subtype):
        if not isinstance(rid,str)or not rid or rid in seen:raise ValueError('duplicate or unavailable native data-resource identity')
        seen.add(rid)
        out['aws_data_resource'].append({'id':rid,'ResourceId':rid,'AccountId':account,'Region':observed,'Service':group,'NativeType':subtype,'_provenance':{'read_only':True,'catalog_version':VERSION,'location_only':True}})
    try:
        identity=_detail(requests,session,region,'sts','get_caller_identity')
        partition=session.get_partition_for_region(region)
        if identity.get('Account')!=account or not re.fullmatch('arn:'+re.escape(partition)+r':(?:iam|sts)::'+re.escape(account)+r':.+',str(identity.get('Arn',''))):raise ValueError('native account identity mismatch')
        raw=_rows(requests,session,region,'ec2','describe_regions','Regions',AllRegions=True)
        enabled=[];seen_regions=set()
        for row in raw:
            name,state=row.get('RegionName'),row.get('OptInStatus')
            if not isinstance(name,str)or not re.fullmatch(_REGION,name)or name in seen_regions or state not in {'opted-in','not-opted-in','opt-in-not-required'}or session.get_partition_for_region(name)!=partition:raise ValueError('enabled Region identity unavailable')
            seen_regions.add(name)
            out['aws_enabled_region'].append({'id':account+'/'+name,'RegionName':name,'OptInStatus':state})
            if state!='not-opted-in':enabled.append(name)
        if not enabled:raise ValueError('enabled Region universe unavailable')
        audited=getattr(requests,'audited_regions_by_account',{}).get(account)
        if not isinstance(audited,list)or len(set(audited))!=len(audited)or set(audited)!=set(enabled):raise ReadFailure('not_collected','data_region_account_selection_incomplete')
        policy=getattr(requests,'data_regions_policy',None)
        if policy is None or policy['scope']!=account+'/global':raise ReadFailure('not_collected','data_region_owner_requirements_missing')
        # Global general-purpose S3 list is owned-account complete; each bucket
        # location is verified with ExpectedBucketOwner, not inferred from name.
        buckets=_rows(requests,session,region,'s3','list_buckets','Buckets',MaxBuckets=1000)
        bucket_names=set()
        for bucket in buckets:
            name=bucket.get('Name')
            if not isinstance(name,str)or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',name)or name in bucket_names:raise ValueError('bucket identity malformed or duplicate')
            bucket_names.add(name)
            location=_detail(requests,session,region,'s3','get_bucket_location',Bucket=name,ExpectedBucketOwner=account)
            if 'LocationConstraint'not in location:raise ValueError('bucket location omitted')
            where=location['LocationConstraint'];where='us-east-1'if where is None else'eu-west-1'if where=='EU'else where
            if where not in enabled:raise ValueError('bucket Region outside enabled universe')
            record(f'arn:{partition}:s3:::'+name,where,'s3','general-purpose-bucket')
        for observed in sorted(enabled):
            groups={g:[]for g in {'s3','rds','ec2_volume','dynamodb','efs','redshift','backup'}}
            for group,service,operation,field,key in CATALOG:
                kwargs={}
                if operation=='list_regional_buckets':kwargs={'AccountId':account}
                elif operation=='describe_snapshots':kwargs={'OwnerIds':[account]}
                elif operation=='list_backups':kwargs={'BackupType':'ALL'}
                elif operation=='describe_cluster_snapshots':kwargs={'OwnerAccount':account}
                elif operation=='list_snapshots':kwargs={'ownerAccount':account}
                elif operation=='describe_db_snapshots':kwargs={'IncludeShared':False,'IncludePublic':False}
                elif operation=='describe_db_cluster_snapshots':kwargs={'IncludeShared':False,'IncludePublic':False}
                variants=[{'type':'customer'},{'type':'aws'}]if service=='s3tables'else[kwargs]
                for args in variants:
                    items=_rows(requests,session,observed,service,operation,field,**args)
                    operations.append((observed,service,operation))
                    groups[group].append(operation+(':'+args['type']if service=='s3tables'else''))
                    local=set()
                    if operation=='list_outposts':
                        for outpost in items:
                            oid=outpost.get('OutpostId');oarn=outpost.get('OutpostArn')
                            if (not isinstance(oid,str)or not re.fullmatch(r'op-[a-f0-9]{17}',oid)
                                    or oarn!=f'arn:{partition}:outposts:{observed}:{account}:outpost/'+oid
                                    or outpost.get('OwnerId')!=account or oid in local):raise ValueError('Outposts identity malformed or foreign')
                            local.add(oid)
                            outpost_buckets=_rows(requests,session,observed,'s3control','list_regional_buckets','RegionalBucketList',AccountId=account,OutpostId=oid)
                            groups[group].append('list_regional_buckets')
                            for bucket in outpost_buckets:
                                bid=bucket.get('BucketArn')
                                if (not isinstance(bid,str)or not re.fullmatch(re.escape(f'arn:{partition}:s3-outposts:{observed}:{account}:outpost/'+oid)+r'/bucket/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',bid)
                                        or bucket.get('OutpostId')!=oid):raise ValueError('Outposts bucket parent differs')
                                record(bid,observed,'s3','outposts-bucket-control-plane-region')
                        continue
                    for row in items:
                        if operation=='list_tables':
                            if not isinstance(row,str)or not re.fullmatch(r'[A-Za-z0-9_.-]{3,255}',row):raise ValueError('table identity malformed')
                            detail=_detail(requests,session,observed,'dynamodb','describe_table',TableName=row)
                            table=detail.get('Table',{});rid=table.get('TableArn')
                            if table.get('TableName')!=row:raise ValueError('table detail identity differs')
                        else:
                            if not isinstance(row,dict):raise ValueError('native resource row malformed')
                            rid=row.get(key)
                        if not isinstance(rid,str)or not rid or rid in local:raise ValueError('native list duplicate or malformed identity')
                        local.add(rid)
                        if operation in {'describe_volumes','describe_snapshots'}:
                            prefix='vol-'if operation=='describe_volumes'else'snap-'
                            if not re.fullmatch(prefix+r'(?:[a-f0-9]{8}|[a-f0-9]{17})',rid):raise ValueError('EBS native identity malformed')
                            if operation=='describe_snapshots'and row.get('OwnerId')!=account:raise ValueError('foreign EBS snapshot')
                            rid=f'arn:{partition}:ec2:{observed}:{account}:'+('volume/'if operation=='describe_volumes'else'snapshot/')+rid
                        elif operation=='describe_clusters':
                            if not re.fullmatch(r'[a-z][a-z0-9-]{0,62}',rid):raise ValueError('Redshift cluster identity malformed')
                            rid=f'arn:{partition}:redshift:{observed}:{account}:cluster:'+rid
                        elif operation=='list_recovery_points':
                            namespace=row.get('namespaceArn')
                            if not isinstance(namespace,str)or not namespace.startswith(f'arn:{partition}:redshift-serverless:{observed}:{account}:namespace/'):raise ValueError('recovery point namespace foreign')
                            if not re.fullmatch(r'[A-Za-z0-9-]{1,128}',rid):raise ValueError('recovery point identity malformed')
                            rid=f'arn:{partition}:redshift-serverless:{observed}:{account}:recoverypoint/'+rid
                        allowed_service={'s3':{'s3express','s3-outposts','s3tables','s3vectors'},'rds':{'rds'},'ec2_volume':{'ec2'},'dynamodb':{'dynamodb'},'efs':{'elasticfilesystem'},'redshift':{'redshift','redshift-serverless'},'backup':{'backup'}}[group]
                        match=re.fullmatch(r'arn:([^:]+):([^:]+):([^:]+):([0-9]{12}):(.+)',rid)
                        if not match or match.group(1)!=partition or match.group(2)not in allowed_service or match.group(3)!=observed or match.group(4)!=account:raise ValueError('foreign native resource ARN')
                        if service=='s3tables'and row.get('ownerAccountId')!=account:raise ValueError('table bucket owner differs')
                        record(rid,observed,group,operation)
                        if group=='backup':
                            name=row.get('BackupVaultName')
                            if not isinstance(name,str)or not re.fullmatch(r'[A-Za-z0-9_-]{2,50}',name):raise ValueError('backup vault name malformed')
                            recovery=_rows(requests,session,observed,'backup','list_recovery_points_by_backup_vault','RecoveryPoints',BackupVaultName=name,BackupVaultAccountId=account)
                            point_ids=set()
                            for point in recovery:
                                pid=point.get('RecoveryPointArn')
                                pm=re.fullmatch(r'arn:([^:]+):([^:]+):([^:]+):([0-9]{12})?:(.+)',pid)if isinstance(pid,str)else None
                                if not pm or pm.group(1)!=partition or pm.group(3)!=observed or(pm.group(4)!=account and not(pm.group(2)=='ec2'and pm.group(4)is None and pm.group(5).startswith('snapshot/'))):raise ValueError('foreign recovery point ARN')
                                if point.get('BackupVaultArn')!=rid:raise ValueError('recovery point vault differs')
                                if pid in point_ids:raise ValueError('duplicate recovery point in a native vault list')
                                point_ids.add(pid)
                                # A recovery point may reference an already listed
                                # EBS/RDS snapshot: account-global ResourceId stays unique.
                                if pid not in seen:record(pid,observed,'backup','vault-recovery-point')
            for group,ops in sorted(groups.items()):
                out['aws_data_resource_coverage'].append({'id':f'{account}/{observed}/{group}','Region':observed,'Service':group,'Complete':True,'CatalogVersion':VERSION,'Operations':sorted(set(ops)),'_provenance':{'read_only':True,'all_enabled_regions':True,'observed_at':requests.observed_at.isoformat(),'scope':'native-owned-storage-containers-and-backups; location signal only'}})
        return {kind:ReadResult(rows,'collected'if rows else'empty')for kind,rows in out.items()}
    except ReadFailure as exc:
        failure_status=exc.status;code=exc.code
    except (ValueError,TypeError,KeyError,AttributeError):
        failure_status='malformed';code='data_region_native_identity_or_catalog_unresolved'
    # Never expose a complete aggregate when even one catalog endpoint failed.
    return {kind:ReadResult(rows,'partial'if rows else failure_status,{'code':code,'cause_status':failure_status})for kind,rows in out.items()}

def _fetch(kind):
    def fetch(requests,session,region,account):
        with requests._lock:
            cache=getattr(requests,'_data_region_bundle_cache',None)
            if cache is None:cache={};requests._data_region_bundle_cache=cache
            key=(id(session),account)
            owner=key not in cache
            if owner:cache[key]=Future()
            future=cache[key]
        if owner:
            try:future.set_result(_compute(requests,session,region,account))
            except BaseException as exc:future.set_exception(exc);raise
        return copy.deepcopy(future.result()[kind])
    return fetch
FETCHERS={kind:_fetch(kind)for kind in KINDS}
