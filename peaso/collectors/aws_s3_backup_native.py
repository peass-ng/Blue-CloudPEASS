"""Complete enabled-region AWS Backup selection metadata; never backup execution."""
from __future__ import annotations
import copy,re
SPECS={'s3_backup_plan_coverage':('backup','list_backup_plans','BackupPlansList')}
GLOBAL_TYPES={'s3_backup_plan_coverage'}
NATIVE_IDS={'s3_backup_plan_coverage':'id'}
READ_ACTIONS={('ec2','describe_regions'),('backup','list_backup_plans'),('backup','get_backup_plan'),('backup','list_backup_selections'),('backup','get_backup_selection'),('s3','list_buckets'),('s3','get_bucket_location')}
OK=('collected','empty')
def result(rows=(),status=None,code=None):
 from .aws import ReadResult
 rows=list(rows);return ReadResult(rows,status or('collected'if rows else'empty'),{'code':code}if code else None)
def failed(read):
 return result([],read.status if read.status not in OK else'malformed',(read.error or{}).get('code','backup_inventory_incomplete'))
def detail(requests,session,region,operation,**args):
 value=requests.detail(session,'backup',region,operation,**args)
 if value.get('collection_status')!='collected':
  from .aws import ReadFailure
  raise ReadFailure(value.get('collection_status','not_collected'),(value.get('error')or{}).get('code','backup_detail_incomplete'))
 return value

def coverage(requests,session,region,account):
 from .aws import ReadFailure
 proof=getattr(requests,'backup_region_discovery',{}).get(account)
 if proof is None:return result([],'not_collected','complete_account_region_discovery_required')
 if proof.status not in OK:return failed(proof)
 try:
  partition=session.get_partition_for_region(region);enabled=[];seen=set()
  for row in proof.items:
   name,state=row.get('RegionName'),row.get('OptInStatus')
   if not isinstance(name,str)or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+',name)or name in seen or session.get_partition_for_region(name)!=partition or state not in('opt-in-not-required','opted-in','not-opted-in'):raise ValueError('region proof invalid')
   seen.add(name)
   if state!='not-opted-in':enabled.append(name)
  if not enabled:raise ValueError('enabled region universe unavailable')
  buckets=requests.pages(session,'s3',region,'list_buckets','Buckets')
  if buckets.status not in OK:return failed(buckets)
  names=[r.get('Name')for r in buckets.items]
  if any(not isinstance(n,str)or not n for n in names)or len(set(names))!=len(names):raise ValueError('bucket inventory ambiguous')
  own={f'arn:{partition}:s3:::'+n:n for n in names};locations={}
  selections=[]
  for observed_region in sorted(enabled):
   plans=requests.pages(session,'backup',observed_region,'list_backup_plans','BackupPlansList')
   if plans.status not in OK:return failed(plans)
   plan_ids=set()
   for summary in plans.items:
    pid=summary.get('BackupPlanId');arn=summary.get('BackupPlanArn')
    prefix=f'arn:{partition}:backup:{observed_region}:{account}:'
    if not isinstance(pid,str)or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_+/=-]{0,1023}',pid)or pid in plan_ids or not isinstance(arn,str)or not re.fullmatch(re.escape(prefix)+r'(?:backup-plan|plan):'+re.escape(pid),arn) or summary.get('DeletionDate')is not None:raise ValueError('active plan identity invalid')
    plan_ids.add(pid)
    current=detail(requests,session,observed_region,'get_backup_plan',BackupPlanId=pid)
    if current.get('BackupPlanId')!=pid or current.get('BackupPlanArn')!=arn or not isinstance(current.get('VersionId'),str)or not current['VersionId']or(summary.get('VersionId')is not None and summary['VersionId']!=current['VersionId'])or current.get('DeletionDate')is not None:raise ValueError('current plan differs from list')
    rules=current.get('BackupPlan',{}).get('Rules');rule_ids=set()
    if not isinstance(rules,list)or not rules:raise ValueError('current plan rules missing')
    for rule in rules:
     name=rule.get('RuleName');schedule=rule.get('ScheduleExpression')
     if not isinstance(name,str)or not name or name in rule_ids or not isinstance(schedule,str)or not re.fullmatch(r'(?:cron|rate)\([^\r\n]+\)',schedule):raise ValueError('scheduled rule unresolved')
     rule_ids.add(name)
    listed=requests.pages(session,'backup',observed_region,'list_backup_selections','BackupSelectionsList',BackupPlanId=pid)
    if listed.status not in OK:return failed(listed)
    selection_ids=set()
    for summary_selection in listed.items:
     sid=summary_selection.get('SelectionId')
     if summary_selection.get('BackupPlanId',pid)!=pid or not isinstance(sid,str)or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_+/=-]{0,1023}',sid)or sid in selection_ids:raise ValueError('selection identity duplicate or missing')
     selection_ids.add(sid)
     selected=detail(requests,session,observed_region,'get_backup_selection',BackupPlanId=pid,SelectionId=sid)
     if selected.get('BackupPlanId')!=pid or selected.get('SelectionId')!=sid:raise ValueError('selection detail foreign')
     data=selected.get('BackupSelection')
     if not isinstance(data,dict):raise ValueError('selection detail absent')
     row={'Region':observed_region,'Active':True,'ScheduledRules':len(rules),'BackupPlanId':pid,'SelectionId':sid,'VersionId':current['VersionId']}
     for field,default in(('Resources',[]),('NotResources',[]),('Conditions',{}),('ListOfTags',[])):
      value=data.get(field,default)
      if not isinstance(value,type(default))or(isinstance(value,list)and field!='ListOfTags'and any(not isinstance(v,str)or not v for v in value)):raise ValueError('selection fields malformed')
      row[field]=copy.deepcopy(value)
     if not row['Resources']and not row['Conditions']and not row['ListOfTags']:return result([],'not_collected','implicit_backup_resource_selection_unresolved')
     applicable=[]
     for resource in row['Resources']:
      if resource in own:
       if resource not in locations:
        location=requests.detail(session,'s3',region,'get_bucket_location',Bucket=own[resource])
        if location.get('collection_status')!='collected':return result([],location.get('collection_status','not_collected'),(location.get('error')or{}).get('code','bucket_location_incomplete'))
        home=location.get('LocationConstraint')
        home='us-east-1'if home is None else'eu-west-1'if home=='EU'else home
        if home not in enabled:raise ValueError('bucket home region outside proved enabled universe')
        locations[resource]=home
       if locations[resource]!=observed_region:continue
      applicable.append(resource)
     row['Resources']=applicable
     selections.append(row)
  return result([{'id':account+'/backup-plan-coverage','AccountId':account,'AllEnabledRegionsCollected':True,'Selections':selections,'_provenance':{'read_only':True,'source_operations':['ec2:DescribeRegions','backup:ListBackupPlans','backup:GetBackupPlan','backup:ListBackupSelections','backup:GetBackupSelection','s3:ListBuckets','s3:GetBucketLocation'],'bucket_regions':locations,'regions':sorted(enabled),'semantics':'current configured scheduled literal selections; no backup execution or recovery claim'}}])
 except ReadFailure as exc:return result([],exc.status,exc.code)
 except (TypeError,ValueError,AttributeError):return result([],'malformed','native_backup_selection_join_unresolved')
FETCHERS={'s3_backup_plan_coverage':coverage}
