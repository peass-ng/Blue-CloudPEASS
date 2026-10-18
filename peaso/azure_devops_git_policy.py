"""Pure owner applicability and nonsecret native Git URL parse assessments."""
import copy,json,re
from urllib.parse import urlsplit
OPTION='azure_devops_git'
UUID=r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
ORG=r'[a-z0-9](?:[a-z0-9-]{0,48}[a-z0-9])?'
OPERATIONS=['Projects_List','Projects_Get','Repositories_List','Repositories_Get']

def normalize(options,auth=None):
 if not isinstance(options,dict)or auth is not None and not isinstance(auth,dict):raise ValueError('invalid DevOps input')
 parent=options.get('compliance_parameters',{})
 if not isinstance(parent,dict):raise ValueError('invalid DevOps owner parameters')
 raw=parent.get(OPTION);out={};total=0
 if raw is not None:
  try:bounded=len(json.dumps(raw,allow_nan=False))<=50000
  except(TypeError,ValueError,RecursionError):bounded=False
  if not bounded or not isinstance(raw,dict)or set(raw)!={'subscriptions'}or not isinstance(raw['subscriptions'],list)or not 1<=len(raw['subscriptions'])<=16:raise ValueError('invalid DevOps subscriptions')
  for row in raw['subscriptions']:
   if not isinstance(row,dict)or set(row)!={'scope','organization','project_ids'}:raise ValueError('invalid DevOps owner fields')
   scope=row['scope'];org=row['organization'];ids=row['project_ids']
   if not isinstance(scope,str)or not re.fullmatch('/subscriptions/'+UUID,scope)or not isinstance(org,str)or not re.fullmatch(ORG,org):raise ValueError('invalid DevOps applicability identity')
   if not isinstance(ids,list)or not 1<=len(ids)<=256 or any(not isinstance(i,str)or not re.fullmatch(UUID,i)for i in ids):raise ValueError('invalid DevOps project UUIDs')
   ids=[i.lower()for i in ids];scope=scope.lower();total+=len(ids)
   if total>256 or len(ids)!=len(set(ids))or scope in out:raise ValueError('duplicate or excessive DevOps applicability')
   out[scope]={'scope':scope,'organization':org,'project_ids':ids}
 if auth is not None and 'devops_credentials'in auth:
  rows=auth['devops_credentials'];seen=set()
  if not isinstance(rows,list)or not 1<=len(rows)<=16:raise ValueError('invalid DevOps credential list')
  for row in rows:
   if not isinstance(row,dict)or set(row)!={'server','method','token'}:raise ValueError('invalid DevOps credential fields')
   server=row['server'];token=row['token']
   if not isinstance(server,str)or not re.fullmatch(r'https://dev\.azure\.com/'+ORG,server)or server in seen or row['method']not in ('pat','bearer'):raise ValueError('invalid DevOps credential origin')
   if not isinstance(token,str)or not 1<=len(token)<=16384 or any(ord(c)<=32 or ord(c)>=127 for c in token):raise ValueError('invalid DevOps credential')
   if server.rsplit('/',1)[-1]not in {v['organization']for v in out.values()}:raise ValueError('unbound DevOps credential')
   seen.add(server)
 return copy.deepcopy(out)

def assess_urls(row):
 """Do not retain URL values or hashes: userinfo may contain low-entropy secrets."""
 remote=row.get('remoteUrl');values=row.get('validRemoteUrls');items=[]
 complete=isinstance(remote,str)and bool(remote)and isinstance(values,list)and all(isinstance(u,str)and bool(u)for u in values)
 if complete:
  if len(values)>256 or any(len(u)>16384 for u in [remote]+values):raise ValueError('DevOps URL assessment limit')
  for field,index,url in [('remoteUrl',0,remote)]+[('validRemoteUrls',i,u)for i,u in enumerate(values)]:
   valid=False;userinfo=None
   try:
    parsed=urlsplit(url)
    valid=parsed.scheme in ('https','http','ssh')and bool(parsed.netloc)and bool(parsed.hostname)and parsed.port!=0
    if valid:userinfo='@'in parsed.netloc
   except ValueError:pass
   items.append({'source_field':field,'index':index,'valid_parse':bool(valid),'userinfo_present':userinfo})
 return {'fields_complete':complete,'valid_remote_urls_count':len(values)if complete else None,'items':items}

def evaluate_project(project,scope,all_ids):
 """Exact legacy URL semantics over typed, secret-free native parse facts."""
 from peaso.checks.facts import Unavailable
 def fail():raise Unavailable('native DevOps URL evidence malformed or incomplete')
 proof=project.get('_provenance');repos=project.get('repositories');coverage=project.get('_coverage',{});coverage=coverage.get('repositories')if isinstance(coverage,dict)else None
 if not isinstance(proof,dict)or type(proof.get('native_devops_git_schema'))is not int or proof['native_devops_git_schema']!=2:fail()
 if (proof.get('source_operations')!=OPERATIONS or proof.get('read_only')is not True or proof.get('api_version')!='7.1'or proof.get('includeHidden')is not True or proof.get('includeAllUrls')is not True or proof.get('owner_scope')!=scope.lower()or proof.get('project_id')!=project.get('id')or proof.get('declared_project_ids')!=all_ids or not isinstance(proof.get('organization'),str)or not re.fullmatch(ORG,proof['organization'])or not isinstance(proof.get('capture_id'),str)or not re.fullmatch(UUID,proof['capture_id'])):fail()
 if (not isinstance(project.get('id'),str)or not re.fullmatch(UUID,project['id'])or not isinstance(all_ids,list)
     or not 1<=len(all_ids)<=256 or any(not isinstance(i,str)or not re.fullmatch(UUID,i)for i in all_ids)or len(set(all_ids))!=len(all_ids)):fail()
 if (not isinstance(repos,list)or len(repos)>1000 or not isinstance(coverage,dict)or coverage.get('api_pages_complete')is not True or coverage!={'status':'partial','reason':'repository_authorization_universe_unverified','api_pages_complete':True}):fail()
 seen=set();outcomes=[]
 for repo in repos:
  if not isinstance(repo,dict)or set(repo)!={'id','projectId','url_assessments'}or not isinstance(repo['id'],str)or not re.fullmatch(UUID,repo['id'])or repo['id']in seen or repo['projectId']!=project['id']:fail()
  seen.add(repo['id']);facts=repo['url_assessments']
  if not isinstance(facts,dict)or set(facts)!={'fields_complete','valid_remote_urls_count','items'}or type(facts['fields_complete'])is not bool or not isinstance(facts['items'],list):fail()
  if not facts['fields_complete']:
   if facts['valid_remote_urls_count']is not None or facts['items']:fail()
   outcomes.append(None);continue
  count=facts['valid_remote_urls_count']
  if type(count)is not int or not 0<=count<=256 or len(facts['items'])!=count+1:fail()
  outcome=False
  for position,item in enumerate(facts['items']):
   field,index=('remoteUrl',0)if position==0 else ('validRemoteUrls',position-1)
   if not isinstance(item,dict)or set(item)!={'source_field','index','valid_parse','userinfo_present'}or item['source_field']!=field or type(item['index'])is not int or item['index']!=index or type(item['valid_parse'])is not bool:fail()
   if item['valid_parse']:
    if type(item['userinfo_present'])is not bool:fail()
   elif item['userinfo_present']is not None:fail()
  # Legacy stops at first malformed URL within a repository, but proceeds to
  # later repositories, where a complete counterexample may still FAIL.
  for item in facts['items']:
   if not item['valid_parse']:outcome=None;break
   if item['userinfo_present']:outcome=True;break
  outcomes.append(outcome)
 if True in outcomes:return True
 # Read ACLs can conceal repositories. Even a complete accessible API page
 # sequence cannot prove project-wide absence of userinfo.
 return None
