"""Account-wide WAF logging configuration, with proven enabled-region inventory."""
from __future__ import annotations
import re
SPECS={'waf_account_acl_inventory':('wafv2','list_web_acls','WebACLs')}
GLOBAL_TYPES={'waf_account_acl_inventory'}
NATIVE_IDS={'waf_account_acl_inventory':'id'}
READ_ACTIONS={('ec2','describe_regions'),('waf-regional','list_web_acls'),('waf-regional','get_web_acl'),('waf-regional','get_logging_configuration'),('wafv2','list_web_acls'),('wafv2','get_web_acl'),('wafv2','get_logging_configuration')}
OK=('collected','empty')
def inventory(requests,session,region,account):
 from .aws import ReadResult
 from peaso.aws_waf_logging import valid_destination_arn
 def failed(status='malformed',code='waf_account_inventory_identity_invalid'):
  return ReadResult([],status,{'code':code})
 proof=getattr(requests,'backup_region_discovery',{}).get(account)
 if proof is None:return failed('not_collected','complete_account_region_discovery_required')
 if proof.status not in OK:return failed(proof.status,(proof.error or{}).get('code','region_inventory_incomplete'))
 if session.get_partition_for_region(region)!='aws':return failed('not_collected','waf_account_partition_support_unverified')
 enabled=[];seen=set();regional=[];v2=[];acl_seen=set()
 for row in proof.items:
  name=row.get('RegionName')if isinstance(row,dict)else None;state=row.get('OptInStatus')if isinstance(row,dict)else None
  if not isinstance(name,str)or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+',name)or name in seen or session.get_partition_for_region(name)!='aws'or state not in('opt-in-not-required','opted-in','not-opted-in'):return failed()
  seen.add(name)
  if state!='not-opted-in':enabled.append(name)
 if not enabled or'us-east-1'not in enabled:return failed('not_collected','waf_global_region_not_proven')
 def details(service,home,operation,**params):
  return requests.detail(session,service,home,operation,**params)
 def logging(service,home,arn):
  read=requests.detail(session,service,home,'get_logging_configuration',ResourceArn=arn,absent=('WAFNonexistentItemException',))
  if read.get('collection_status')=='empty'and read.get('absent')is True and(read.get('error')or{}).get('code')=='WAFNonexistentItemException':return read,None
  if read.get('collection_status')!='collected':return None,failed(read.get('collection_status','not_collected'),(read.get('error')or{}).get('code','waf_logging_incomplete'))
  config=read.get('LoggingConfiguration')
  if not isinstance(config,dict)or config.get('ResourceArn')!=arn or not isinstance(config.get('LogDestinationConfigs'),list)or len(config['LogDestinationConfigs'])!=1 or any(not valid_destination_arn(x,classic=service=='waf-regional')for x in config['LogDestinationConfigs']):return None,failed()
  return read,None
 for home in sorted(enabled):
  classic=requests.pages(session,'waf-regional',home,'list_web_acls','WebACLs',_tokens=('NextMarker','NextMarker'),Limit=100)
  if classic.status not in OK:return failed(classic.status,(classic.error or{}).get('code','waf_classic_inventory_incomplete'))
  for summary in classic.items:
   ident=summary.get('WebACLId')if isinstance(summary,dict)else None
   if not isinstance(ident,str)or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',ident):return failed()
   arn=f'arn:aws:waf-regional:{home}:{account}:webacl/{ident}'
   if arn in acl_seen:return failed()
   acl_seen.add(arn);detail=details('waf-regional',home,'get_web_acl',WebACLId=ident)
   if detail.get('collection_status')!='collected':return failed(detail.get('collection_status','not_collected'),(detail.get('error')or{}).get('code','waf_classic_detail_incomplete'))
   body=detail.get('WebACL')
   if not isinstance(body,dict)or body.get('WebACLId')!=ident or body.get('WebACLArn')!=arn:return failed()
   config,error=logging('waf-regional',home,arn)
   if error:return error
   regional.append({'WebACLId':ident,'Region':home,'WebACL':{'WebACLArn':arn},'LoggingConfiguration':config})
  for scope in ['REGIONAL']+(['CLOUDFRONT']if home=='us-east-1'else[]):
   listed=requests.pages(session,'wafv2',home,'list_web_acls','WebACLs',_tokens=('NextMarker','NextMarker'),Scope=scope,Limit=100)
   if listed.status not in OK:return failed(listed.status,(listed.error or{}).get('code','wafv2_inventory_incomplete'))
   for summary in listed.items:
    ident=summary.get('Id')if isinstance(summary,dict)else None;name=summary.get('Name')if isinstance(summary,dict)else None;arn=summary.get('ARN')if isinstance(summary,dict)else None;prefix='regional'if scope=='REGIONAL'else'global'
    if not isinstance(ident,str)or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',ident)or not isinstance(name,str)or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',name)or arn!=f'arn:aws:wafv2:{home}:{account}:{prefix}/webacl/{name}/{ident}'or arn in acl_seen:return failed()
    acl_seen.add(arn);detail=details('wafv2',home,'get_web_acl',Name=name,Id=ident,Scope=scope)
    if detail.get('collection_status')!='collected':return failed(detail.get('collection_status','not_collected'),(detail.get('error')or{}).get('code','wafv2_detail_incomplete'))
    body=detail.get('WebACL')
    if not isinstance(body,dict)or any(body.get(k)!=summary.get(k)for k in ('Id','Name','ARN')):return failed()
    config,error=logging('wafv2',home,arn)
    if error:return error
    v2.append({'ARN':arn,'Region':home,'Scope':scope,'LoggingConfiguration':config})
 return ReadResult([{'id':account+'/waf-account-acl-inventory','AccountId':account,'AllEnabledRegionsCollected':True,'RegionalClassic':regional,'WAFv2':v2,'_provenance':{'read_only':True,'source_operations':sorted(s+':'+o for s,o in READ_ACTIONS),'regions':sorted(enabled),'boundary':'Current logging configuration only; not successful log ingestion or delivery'}}],'collected')
FETCHERS={'waf_account_acl_inventory':inventory}
