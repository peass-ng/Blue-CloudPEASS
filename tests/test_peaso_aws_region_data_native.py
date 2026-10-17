import copy
from contextlib import ExitStack
from datetime import datetime,timedelta,timezone
import pytest
import boto3
from botocore.stub import Stubber
from peaso.collectors import aws, aws_region_data_native as native

ACCOUNT='123456789012'
CID='aws_account_non_eu_resource_region_detected'

@pytest.fixture
def private():
 return aws,native

def owner():
 now=datetime.now(timezone.utc)
 return {'scope':ACCOUNT+'/global','authorized_by':'owned-reviewer','document_id':'owned-approved-EU-register','observed_at':(now-timedelta(minutes=1)).isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),'approved_region_names':['eu-west-1']}

def capture(private,monkeypatch,mode):
 aws,native=private
 region='us-east-1'if mode=='outside-eu'else'eu-west-1'
 session=boto3.Session(aws_access_key_id='INERT',aws_secret_access_key='INERT',region_name=region)
 clients={};stubs={};stack=ExitStack()
 original=session.client
 def client(service,**kwargs):
  key=(service,kwargs.get('region_name',region))
  if key not in clients:
   clients[key]=original(service,region_name=key[1]);stubs[key]=stack.enter_context(Stubber(clients[key]))
  return clients[key]
 monkeypatch.setattr(session,'client',client)
 def add(service,op,response,args,client_region=region,error=None):
  client(service,region_name=client_region)
  if error:stubs[service,client_region].add_client_error(op,error,expected_params=args)
  else:stubs[service,client_region].add_response(op,response,args)
 arn=f'arn:aws:iam::{ACCOUNT}:user/offline-reader'
 add('sts','get_caller_identity',{'Account':ACCOUNT,'Arn':arn,'UserId':'reader'}, {})
 native_regions=[{'RegionName':region,'OptInStatus':'opt-in-not-required'}]
 if mode=='duplicate-region':native_regions*=2
 add('ec2','describe_regions',{'Regions':native_regions},{'AllRegions':True})
 # Same describe_regions request is reused by collector discovery and helper.
 add('s3','list_buckets',{'Buckets':[]},{'MaxBuckets':1000})
 for group,service,op,field,key in native.CATALOG:
  args={}
  if op=='list_regional_buckets':args={'AccountId':ACCOUNT}
  elif op=='describe_snapshots':args={'OwnerIds':[ACCOUNT]}
  elif op=='list_backups':args={'BackupType':'ALL'}
  elif op=='describe_cluster_snapshots':args={'OwnerAccount':ACCOUNT}
  elif op=='list_snapshots':args={'ownerAccount':ACCOUNT}
  elif op in {'describe_db_snapshots','describe_db_cluster_snapshots'}:args={'IncludeShared':False,'IncludePublic':False}
  variants=[{'type':'customer'},{'type':'aws'}]if service=='s3tables'else[args]
  for params in variants:
   rows=[]
   if op=='list_backup_vaults'and mode in {'backup-recovery-valid','backup-recovery-duplicate','backup-recovery-foreign'}:
    rows=[{'BackupVaultName':'owned','BackupVaultArn':f'arn:aws:backup:{region}:{ACCOUNT}:backup-vault:owned'}]
   if op=='list_backups'and mode=='system-backup':
    rows=[{'BackupArn':f'arn:aws:dynamodb:{region}:{ACCOUNT}:table/owned/backup/system-owned','BackupType':'SYSTEM'}]
   if op=='list_outposts'and mode in {'outposts','outposts-bucket-paged','outposts-bucket-repeated','outposts-bucket-cap'}:
    rows=[{'OutpostId':'op-0123456789abcdef0','OutpostArn':f'arn:aws:outposts:{region}:{ACCOUNT}:outpost/op-0123456789abcdef0','OwnerId':ACCOUNT}]
   if op=='list_vector_buckets'and mode in {'outside-eu','vector','duplicate','foreign-account','foreign-region','missing-arn'}:
    rid=f'arn:aws:s3vectors:{region}:{ACCOUNT}:bucket/offline-owned'
    if mode=='foreign-account':rid=rid.replace(ACCOUNT,'999999999999')
    if mode=='foreign-region':rid=rid.replace(region,'us-west-2')
    row={'vectorBucketName':'offline-owned','vectorBucketArn':rid,'creationTime':datetime.now(timezone.utc)}
    if mode=='missing-arn':row['vectorBucketArn']=''
    rows=[row]* (2 if mode=='duplicate'else 1)
   if op=='describe_db_cluster_automated_backups'and mode=='retained-rds':
    rows=[{'DBClusterAutomatedBackupsArn':f'arn:aws:rds:{region}:{ACCOUNT}:cluster-auto-backup:owned'}]
   if op=='list_recovery_points'and mode in {'serverless-recovery','canonical-recovery-arn','foreign-recovery-namespace','invalid-recovery-id'}:
    rows=[{'namespaceArn':f'arn:aws:redshift-serverless:{region}:{ACCOUNT}:namespace/owned','recoveryPointId':'owned-point'}]
    if mode=='foreign-recovery-namespace':rows[0]['namespaceArn']=rows[0]['namespaceArn'].replace(ACCOUNT,'999999999999')
    if mode=='invalid-recovery-id':rows[0]['recoveryPointId']='bad/escape'
   if op=='list_directory_buckets'and mode=='directory':
    rows=[{'Name':'owned--euw1-az1--x-s3','BucketArn':f'arn:aws:s3express:{region}:{ACCOUNT}:bucket/owned--euw1-az1--x-s3'}]
   if service=='s3tables'and params.get('type')=='customer'and mode=='table-bucket':
    rows=[{'arn':f'arn:aws:s3tables:{region}:{ACCOUNT}:bucket/owned','name':'owned','ownerAccountId':ACCOUNT,'createdAt':datetime.now(timezone.utc),'tableBucketId':'owned','type':'customer'}]
   if mode=='endpoint-denied'and op=='list_vector_buckets':add(service,op,{},params,error='AccessDeniedException')
   elif mode in {'paged','page-cap','repeated-token'}and op=='list_vector_buckets':
    add(service,op,{field:[],'nextToken':'cursor'},params)
    add(service,op,{field:[],**({'nextToken':'cursor'}if mode=='repeated-token'else{})},{**params,'nextToken':'cursor'})
   else:add(service,op,{field:rows},params)
   if op=='list_backup_vaults'and mode in {'backup-recovery-valid','backup-recovery-duplicate','backup-recovery-foreign'}:
    point={'RecoveryPointArn':f'arn:aws:backup:{region}:{ACCOUNT}:recovery-point:owned','BackupVaultArn':rows[0]['BackupVaultArn']}
    if mode=='backup-recovery-foreign':point['BackupVaultArn']=point['BackupVaultArn'].replace(':owned',':foreign')
    points=[point]*(2 if mode=='backup-recovery-duplicate'else 1)
    add('backup','list_recovery_points_by_backup_vault',{'RecoveryPoints':points},{'BackupVaultName':'owned','BackupVaultAccountId':ACCOUNT})
   if op=='list_outposts'and mode in {'outposts','outposts-bucket-paged','outposts-bucket-repeated','outposts-bucket-cap'}:
    bucket={'Bucket':'owned','PublicAccessBlockEnabled':True,'CreationDate':datetime.now(timezone.utc),'BucketArn':f'arn:aws:s3-outposts:{region}:{ACCOUNT}:outpost/op-0123456789abcdef0/bucket/owned','OutpostId':'op-0123456789abcdef0'}
    args={'AccountId':ACCOUNT,'OutpostId':'op-0123456789abcdef0'}
    if mode=='outposts':add('s3control','list_regional_buckets',{'RegionalBucketList':[bucket]},args)
    else:
     add('s3control','list_regional_buckets',{'RegionalBucketList':[],'NextToken':'owned-cursor'},args)
     add('s3control','list_regional_buckets',{'RegionalBucketList':[bucket],**({'NextToken':'owned-cursor'}if mode=='outposts-bucket-repeated'else{})},{**args,'NextToken':'owned-cursor'})
 monkeypatch.setattr(aws,'_session',lambda auth,where:(session,'offline'))
 opts={'retry_attempts':1,'service_concurrency':1,'compliance_parameters':{'aws_data_regions':owner()}}
 if mode=='missing-owner':opts.pop('compliance_parameters')
 if mode in {'page-cap','outposts-bucket-cap'}:opts['max_pages']=1
 if mode=='call-cap':opts['max_calls']=5
 if mode=='resource-cap':opts['max_resources']=1
 connector={'provider':'aws','scopes':[ACCOUNT+'/'+region],'options':opts}
 from peaso.engine import collect_snapshot,evaluate_snapshot
 try:
  snap=collect_snapshot({'connector':connector,'checks':[CID]})
  findings=[f for f in evaluate_snapshot(snap,checks=[CID])['findings']if f['check_id']==CID]
  assert len(findings)==1,findings
  return findings[0]['status'],snap
 finally:stack.close()

@pytest.mark.parametrize('mode,expected',[
 ('outposts-bucket-paged','PASS'),('outposts-bucket-repeated','UNKNOWN'),('outposts-bucket-cap','UNKNOWN'),('canonical-recovery-arn','PASS'),('foreign-recovery-namespace','UNKNOWN'),('invalid-recovery-id','UNKNOWN'),('system-backup','PASS'),('backup-recovery-valid','PASS'),('backup-recovery-duplicate','UNKNOWN'),('backup-recovery-foreign','UNKNOWN'),('outposts','PASS'),('empty','PASS'),('vector','PASS'),('outside-eu','FAIL'),('directory','PASS'),('table-bucket','PASS'),('retained-rds','PASS'),('serverless-recovery','PASS'),('paged','PASS'),
 ('duplicate','UNKNOWN'),('foreign-account','UNKNOWN'),('foreign-region','UNKNOWN'),('missing-arn','UNKNOWN'),('duplicate-region','UNKNOWN'),('missing-owner','UNKNOWN'),('endpoint-denied','DENIED'),('page-cap','UNKNOWN'),('repeated-token','UNKNOWN'),('call-cap','UNKNOWN'),('resource-cap','UNKNOWN')])
def test_public_native_region_pipeline(private,monkeypatch,mode,expected):
 status,snap=capture(private,monkeypatch,mode)
 if mode=='canonical-recovery-arn':
  resource=next(c for c in snap['collections']if c['type']=='aws_data_resource')['items'][0]
  assert resource['ResourceId']=='arn:aws:redshift-serverless:eu-west-1:'+ACCOUNT+':recoverypoint/owned-point'
 assert status==expected,(status,[c for c in snap['collections']if c['type']in private[1].KINDS])
 if status in {'PASS','FAIL'}:
  cov=next(c for c in snap['collections']if c['type']=='aws_data_resource_coverage')
  assert len(cov['items'])==7 and all(r['Complete']is True and r['CatalogVersion']==private[1].VERSION for r in cov['items'])


@pytest.mark.parametrize('change', ['missing', 'extra', 'expired', 'unaware', 'foreign-scope', 'non-eu', 'duplicate', 'blank-owner'])
def test_owner_policy_strict(private,change):
 native=private[1];value=owner()
 if change=='missing':value.pop('document_id')
 elif change=='extra':value['Complete']=True
 elif change=='expired':value['expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
 elif change=='unaware':value['observed_at']='2026-10-15T12:00:00'
 elif change=='foreign-scope':value['scope']=ACCOUNT+'/eu-west-1'
 elif change=='non-eu':value['approved_region_names']=['us-east-1']
 elif change=='duplicate':value['approved_region_names']*=2
 elif change=='blank-owner':value['authorized_by']=' '
 with pytest.raises(ValueError):native.normalize({'compliance_parameters':{'aws_data_regions':value}})
