"""Native provider-aware database firewall and Entra administrator evidence.

ARM GET/LIST only; no database connections, credentials or active probes.
"""
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
import copy
import re

ARM='https://management.azure.com'
KIND='mysql_postgresql_sql_server'
SOURCES={'sql_server':('Microsoft.Sql/servers','2023-08-01'),
         'mysql_flexible_server':('Microsoft.DBforMySQL/flexibleServers','2023-12-30'),
         'postgresql_flexible_server':('Microsoft.DBforPostgreSQL/flexibleServers','2024-08-01')}
SCHEMA='native-database-arm-v1'


def required_types(wanted):
 return set(SOURCES) if KIND in wanted else set()


def collect(reader,request,scopes,wanted,options=None):
 if KIND not in wanted and not (options or {}).get("_azure_database_native_requested"):return
 jobs=[]
 bindings={}
 for scope in scopes:
  if not any(c['type'] in ('mysql_flexible_server','postgresql_flexible_server') and c['scope']==scope and c['items'] for c in reader.collections):continue
  try:
   value=reader.call(request,ARM+scope+"?api-version=2022-12-01")
   if isinstance(value,dict) and str(value.get("id","")).casefold()==scope.casefold() and isinstance(value.get("tenantId"),str) and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",value["tenantId"],re.I):
    bindings[scope]=value["tenantId"]
  except Exception:
   pass  # Networking remains independently measurable; administrator tenant binding does not.
 for collection in list(reader.collections):
  kind=collection['type']
  if kind not in SOURCES or collection['scope'] not in scopes:continue
  provider,version=SOURCES[kind]
  for item in collection['items']:
   for field in ('administrators','serverAdministrators'):
    for admin in item.get(field,[]):
     if isinstance(admin,dict) and isinstance(admin.get('properties'),dict):
      admin['properties']={key:value for key,value in admin['properties'].items()if key in ('sid','objectId','principalId','administratorType','tenantId','identityResourceId','principalType')}
   rid=item.get('id');scope=collection['scope']
   def fetch(item=item,rid=rid,scope=scope,kind=kind,provider=provider,version=version):
    if not isinstance(rid,str) or any(part in ('.','..') for part in rid.split('/')) or any(ord(c)<33 for c in rid) or not re.fullmatch(re.escape(scope)+r'/resourceGroups/[^/?#%]+/providers/'+re.escape(provider)+r'/[^/?#%]+',rid,re.I):
     raise ValueError('foreign native database identity')
    raw=reader.call(request,ARM+rid+'?api-version='+version)
    if (not isinstance(raw,dict) or str(raw.get('id','')).casefold()!=rid.casefold() or not isinstance(raw.get('properties'),dict)
        or 'type' in raw and str(raw['type']).casefold()!=provider.casefold()
        or 'name' in raw and str(raw['name']).casefold()!=rid.rsplit('/',1)[-1].casefold()):
     raise ValueError('native database GET identity unavailable')
    native={key:copy.deepcopy(value) for key,value in raw['properties'].items() if key in ('publicNetworkAccess','network','authConfig')}
    # These fields are documented structural enums and ARM IDs, never secrets.
    if isinstance(native.get('network'),dict):native['network']={key:value for key,value in native['network'].items() if key=='publicNetworkAccess'}
    if isinstance(native.get('authConfig'),dict):native['authConfig']={key:value for key,value in native['authConfig'].items() if key in ('activeDirectoryAuth','passwordAuth','tenantId')}
    output=copy.deepcopy(item)
    for field in ('publicNetworkAccess','network','authConfig'):
     output.setdefault('properties',{}).pop(field,None)
     if field in native:output['properties'][field]=copy.deepcopy(native[field])
    output['_database_native']={'schema':SCHEMA,'provider_kind':kind,'properties':native,'_provenance':{'read_only':True,'source_operation':'Servers_Get','api_version':version}}
    if scope in bindings:
     output['_database_native']['tenant_id']=bindings[scope]
    for segment in ['firewallRules']+(['administrators'] if kind!='sql_server' else []):
     def children(segment=segment):
      seen=set()
      for page in reader.pages(request,ARM+rid+'/'+segment+'?api-version='+version):
       safe=[]
       for row in page:
        if (not isinstance(row,dict) or not isinstance(row.get('id'),str) or any(part in ('.','..') for part in row['id'].split('/')) or any(ord(c)<33 for c in row['id']) or not re.fullmatch(re.escape(rid)+'/'+segment+r'/[^/?#%]+',row['id'],re.I) or row['id'].casefold() in seen or not isinstance(row.get('properties'),dict)
            or 'type' in row and str(row['type']).casefold()!=(provider+'/'+segment).casefold()
            or 'name' in row and str(row['name']).casefold() not in (row['id'].rsplit('/',1)[-1].casefold(),'/'.join(re.split('/providers/',row['id'],flags=re.I)[-1].split('/')[2::2]).casefold())):
         raise ValueError('foreign or duplicate native database child')
        seen.add(row['id'].casefold());props=row['properties']
        keep=('startIpAddress','endIpAddress')if segment=='firewallRules'else('sid','objectId','administratorType','tenantId','identityResourceId','principalType')
        projected={key:copy.deepcopy(value)for key,value in props.items()if key in keep}
        if segment=='firewallRules':
         low,high=IPv4Address(projected['startIpAddress']),IPv4Address(projected['endIpAddress'])
         if low>high:raise ValueError('reversed native firewall range')
        safe.append({'id':row['id'],'parent_id':rid,'properties':projected,'_provenance':{'read_only':True,'source_operation':'FirewallRules_ListByServer'if segment=='firewallRules'else'Administrators_ListByServer','api_version':version,'native_database_schema':SCHEMA}})
       yield safe
     result=reader._read(('database_'+segment,rid,provider,children))
     output.setdefault('_coverage',{})[segment]={key:result[key]for key in ('status','error')if key in result}
     output[segment]=result['items']
    if output['_coverage']['firewallRules']['status']in('collected','empty'):
     zero=any(rule['properties']['startIpAddress']=='0.0.0.0'and rule['properties']['endIpAddress']=='0.0.0.0'for rule in output['firewallRules'])
     output['publicBypassEvidence']={'status':'collected','serverId':rid,'admitsExternalPublicClient':zero,
      'source':provider+'/firewallRules@'+version,'native_database_schema':SCHEMA}
     for rule in output['firewallRules']:
      if rule['properties']['startIpAddress']=='0.0.0.0'and rule['properties']['endIpAddress']=='0.0.0.0':
       rule.update(specialRuleSemanticsResolved=True,admitsExternalPublicClient=True)
    yield[output]
   jobs.append((collection,item,('database_detail',scope,provider,fetch)))
 with ThreadPoolExecutor(max_workers=reader.workers)as pool:
  results=pool.map(reader._read,[job[2]for job in jobs])
  for(collection,item,_),result in zip(jobs,results):
   if result['status']=='collected'and len(result['items'])==1:
    item.clear();item.update(result['items'][0])
   else:
    collection['status']='partial';collection['error']=result.get('error',{'code':'database_detail_incomplete'})
 if KIND not in wanted:return
 composite_jobs=[]
 for scope in scopes:
  sources=[c for c in reader.collections if c['type']in SOURCES and c['scope']==scope]
  complete=len(sources)==len(SOURCES)and{c['type']for c in sources}==set(SOURCES)and all(c['status']in('collected','empty')for c in sources)
  items=[copy.deepcopy(item)for c in sources for item in c['items']]
  def combined(items=items,complete=complete):
   yield items
   if not complete:
    from .azure import AzureReadError
    raise AzureReadError('database_parent_inventory_incomplete')
  composite_jobs.append((KIND,scope,'AzureDatabaseNative',combined))
 reader.run(composite_jobs)
