"""Native VPC DNS Firewall configuration; owner policy supplies only normative scope."""
import re

KIND='resolver_firewall'
SPECS={KIND:('ec2','describe_vpcs','Vpcs')}
NATIVE_IDS={KIND:'id'}
READ_ACTIONS={('route53resolver','list_firewall_rule_group_associations'),
 ('route53resolver','list_firewall_rules'),('route53resolver','list_firewall_domain_lists')}
_OK=('collected','empty')

def _matches(pattern,value):
 return isinstance(value,str)and re.fullmatch(pattern,value)is not None

def normalize(options):
 params=options.get('compliance_parameters',{})
 if not isinstance(params,dict):raise ValueError('invalid compliance parameters')
 raw=params.get('aws_resolver_firewall')
 if raw is None:return None
 if not isinstance(raw,list)or len(raw)>10000:raise ValueError('invalid resolver policy')
 out={}
 for row in raw:
  if not isinstance(row,dict)or set(row)!={'scope','vpc_id','approved_managed_domain_list_ids'}:raise ValueError('invalid resolver policy fields')
  scope,vpc,ids=row['scope'],row['vpc_id'],row['approved_managed_domain_list_ids']
  if not _matches(r'[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]',scope)or not _matches(r'vpc-(?:[a-f0-9]{8}|[a-f0-9]{17})',vpc):raise ValueError('invalid resolver scope or VPC')
  if not isinstance(ids,list)or not 1<=len(ids)<=1000 or any(not _matches(r'rslvr-fdl-[A-Za-z0-9-]{1,64}',i)for i in ids)or len(ids)!=len(set(ids))or(scope,vpc)in out:raise ValueError('invalid resolver approved list identity')
  out[scope,vpc]=list(ids)
 return out

def collect(requests,session,region,account):
 from .aws import ReadResult,ReadFailure
 def fail(code):raise ValueError(code)
 operations={'sts:GetCallerIdentity'}
 def rows(service,op,field,**kwargs):
  operations.add(service+':'+''.join(part.title()for part in op.split('_')))
  r=requests.pages(session,service,region,op,field,**kwargs)
  if r.status not in _OK:raise ReadFailure(r.status,(r.error or{}).get('code','resolver_inventory_incomplete'))
  if any(not isinstance(x,dict)for x in r.items):fail('invalid native row')
  return r.items
 try:
  policy=getattr(requests,'resolver_firewall_policy',None)
  if policy is None:return ReadResult([],'not_collected',{'code':'resolver_owner_policy_missing'})
  identity=requests.detail(session,'sts',region,'get_caller_identity')
  partition=session.get_partition_for_region(region)
  if identity.get('collection_status')!='collected'or identity.get('Account')!=account or not _matches(re.escape(f'arn:{partition}:')+r'(?:iam|sts)::'+re.escape(account)+r':.+',identity.get('Arn')):fail('resolver caller scope mismatch')
  vpcs=rows('ec2','describe_vpcs','Vpcs'); seen=set();selected=[]
  for v in vpcs:
   vid=v.get('VpcId')
   if not _matches(r'vpc-(?:[a-f0-9]{8}|[a-f0-9]{17})',vid)or v.get('OwnerId')!=account or vid in seen:fail('resolver VPC identity mismatch')
   seen.add(vid)
   if (account+'/'+region,vid)in policy:selected.append(vid)
  if any(scope==account+'/'+region and vid not in seen for scope,vid in policy):fail('designated VPC absent from complete inventory')
  if not selected:return ReadResult([],'empty')
  native_lists=rows('route53resolver','list_firewall_domain_lists','FirewallDomainLists');managed={};allids=set()
  for row in native_lists:
   lid=row.get('Id')
   if not _matches(r'rslvr-fdl-[A-Za-z0-9-]{1,64}',lid)or lid in allids:fail('invalid duplicate domain list')
   allids.add(lid)
   if not _matches(re.escape(f'arn:{partition}:route53resolver:{region}:')+r'[0-9]{12}:firewall-domain-list/'+re.escape(lid),row.get('Arn')):fail('domain list ARN scope mismatch')
   if row.get('ManagedOwnerName')=='Route 53 Resolver DNS Firewall':managed[lid]=row
  associations=rows('route53resolver','list_firewall_rule_group_associations','FirewallRuleGroupAssociations')
  by_vpc={v:[]for v in seen};assids=set();priorities={};rulecache={}
  for a in associations:
   vid,aid,gid=a.get('VpcId'),a.get('Id'),a.get('FirewallRuleGroupId')
   if vid not in seen or not _matches(r'rslvr-frgassoc-[A-Za-z0-9-]{1,64}',aid)or aid in assids or not _matches(r'rslvr-frg-[A-Za-z0-9-]{1,64}',gid):fail('association scope mismatch')
   if a.get('Arn')!=f'arn:{partition}:route53resolver:{region}:{account}:firewall-rule-group-association/{aid}':fail('association ARN mismatch')
   priority=a.get('Priority')
   if type(priority)is not int or not 100<=priority<=9900 or(vid,priority)in priorities:fail('association priority ambiguous')
   priorities[vid,priority]=True;assids.add(aid)
   if a.get('Status')not in {'COMPLETE','DELETING','UPDATING'}:fail('association status unsupported')
   if vid not in selected:continue
   if a['Status']!='COMPLETE':raise ReadFailure('not_collected','resolver_association_transition')
   if gid not in rulecache:
    rr=rows('route53resolver','list_firewall_rules','FirewallRules',FirewallRuleGroupId=gid);order=set();projected=[]
    for r in rr:
     lid=r.get('FirewallDomainListId');p=r.get('Priority')
     if r.get('FirewallRuleGroupId')!=gid or not _matches(r'rslvr-fdl-[A-Za-z0-9-]{1,64}',lid)or type(p)is not int or not 100<=p<=9900 or p in order:fail('rule parent/priority mismatch')
     order.add(p)
     if r.get('Action')not in {'BLOCK','ALLOW','ALERT'}:fail('unsupported firewall rule')
     if 'Status'in r and r['Status']!='COMPLETE':raise ReadFailure('not_collected','resolver_rule_status_unresolved')
     if r.get('Action')=='BLOCK'and r.get('BlockResponse')not in {'NODATA','NXDOMAIN','OVERRIDE'}:fail('missing block response')
     if r.get('Action')=='BLOCK'and r.get('BlockResponse')=='OVERRIDE':raise ReadFailure('not_collected','resolver_override_unresolved')
     projected.append({k:r[k]for k in ('FirewallDomainListId','Action','Priority','Qtype','FirewallDomainRedirectionAction','Status')if k in r})
    rulecache[gid]=projected
   by_vpc[vid].append({'VpcId':vid,'Status':a['Status'],'Rules':rulecache[gid]})
  out=[]
  for vid in selected:
   approved=policy[account+'/'+region,vid]
   if any(lid not in managed for lid in approved):raise ReadFailure('not_collected','resolver_approved_managed_identity_unresolved')
   out.append({'id':vid,'AccountId':account,'Region':region,'VpcId':vid,'Designated':True,'ApprovedManagedDomainListIds':approved,'Associations':by_vpc[vid],
    '_provenance':{'read_only':True,'source_operations':sorted(operations),'configuration_only':True}})
  return ReadResult(out,'collected')
 except ReadFailure as e:return ReadResult([],e.status,{'code':e.code})
 except (ValueError,TypeError,AttributeError,KeyError):return ReadResult([],'malformed',{'code':'resolver_native_join_unresolved'})
FETCHERS={KIND:collect}
