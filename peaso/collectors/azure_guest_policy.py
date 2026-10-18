"""Validate owner baseline intent separately from native guest observations."""
import copy
import json
import re

PREFIX='azure.gap.compute_vm_'
FIELDS={
 'administrators_group_with_extra_accounts_windows':'approvedAdministrators',
 'administrators_group_with_no_specified_members_windows':'requiredAdministrators',
 'administrators_group_with_specified_members_windows':'prohibitedAdministrators',
 'meet_firewall_properties_windows':'requiredSettings',
 'password_file_permissions_0644_linux':None,
 'with_no_specified_certificates_in_trusted_root_windows':'requiredThumbprints',
}
BASE={'assignmentName','configurationName','configurationVersion','maxReportAgeSeconds'}
CATEGORIES={'firewallState','inboundConnections','outboundConnections','ruleManagement','notifications'}

def normalize(options):
 parameters=options.get('compliance_parameters',{})
 if not isinstance(parameters,dict):raise ValueError('compliance parameters must be an object')
 if 'azure_guest_configuration' not in parameters:return None
 value=parameters['azure_guest_configuration']
 if not isinstance(value,dict) or set(value)!={'scope','checks'}:raise ValueError('invalid guest policy fields')
 scope=value['scope']
 if not isinstance(scope,str) or not re.fullmatch(r'/subscriptions/[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',scope):
  raise ValueError('invalid guest policy subscription')
 checks=value['checks']
 if not isinstance(checks,dict) or not checks or len(checks)>len(FIELDS):raise ValueError('invalid guest policy checks')
 output={}
 for cid,policy in checks.items():
  suffix=cid.removeprefix(PREFIX) if isinstance(cid,str) and cid.startswith(PREFIX) else None
  if suffix not in FIELDS or not isinstance(policy,dict):raise ValueError('unsupported guest baseline')
  field=FIELDS[suffix];allowed=BASE|({field}if field else set())
  if field=='requiredThumbprints':allowed.add('emptyRequiredSetApproved')
  if set(policy)-allowed or not BASE<=set(policy) or field and field not in policy:raise ValueError('invalid guest baseline fields')
  for key in ('assignmentName','configurationName','configurationVersion'):
   if not isinstance(policy[key],str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,256}',policy[key]):raise ValueError('invalid guest baseline identity')
  if type(policy['maxReportAgeSeconds'])is not int or not 0<policy['maxReportAgeSeconds']<=366*86400:raise ValueError('invalid report age policy')
  if field and field!='requiredSettings':
   members=policy[field]
   if not isinstance(members,list) or len(members)>1000 or any(not isinstance(x,str) or not x or len(x)>256 or x!=x.strip() or any(ord(c)<32 for c in x) for x in members):raise ValueError('invalid guest baseline members')
   if len({x.casefold()for x in members})!=len(members):raise ValueError('duplicate guest baseline member')
   if field=='requiredThumbprints':
    if any(not re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}',x)for x in members):raise ValueError('invalid certificate thumbprint')
    if not members and policy.get('emptyRequiredSetApproved')is not True:raise ValueError('empty certificate requirement unapproved')
    if 'emptyRequiredSetApproved'in policy and type(policy['emptyRequiredSetApproved'])is not bool:raise ValueError('invalid empty-set approval')
   elif not members:raise ValueError('empty administrator requirement')
  if field=='requiredSettings':
   settings=policy[field]
   if not isinstance(settings,dict) or not settings or len(settings)>1000:raise ValueError('invalid firewall baseline')
   categories=set()
   for key,setting in settings.items():
    if not isinstance(key,str) or not key or len(key)>256 or not isinstance(setting,dict) or set(setting)!={'category','expected'} or not isinstance(setting['category'],str) or setting['category']not in CATEGORIES:raise ValueError('invalid firewall setting')
    if type(setting['expected'])not in (bool,int,float,str) or len(json.dumps(setting['expected'],allow_nan=False))>1024:raise ValueError('invalid expected firewall setting')
    categories.add(setting['category'])
   if categories!=CATEGORIES:raise ValueError('incomplete firewall baseline categories')
  output[cid]=copy.deepcopy(policy)
 return {'scope':scope,'checks':output,'status':'collected','source':'owner_declared_policy'}
