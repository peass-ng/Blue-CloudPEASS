"""Authoritative ARM inventory, with explicit unmeasured behavioral requirements.

No stream-auth/flood/RBAC assertion is inferred from these metadata responses.
"""
import copy,re
from urllib.parse import urlsplit,parse_qs
ARM='https://management.azure.com'
NATIVE_TYPES=('data_collection_rule','dashboard')
SPECS={'data_collection_rule':('Microsoft.Insights/dataCollectionRules','2024-03-11'),
       'dashboard':('Microsoft.Portal/dashboards','2020-09-01-preview')}
GAPS={'data_collection_rule':('metric_source_universe_inventory_read','stream_universe_inventory_read',
 'metric_trace_stream_inventory_read','custom_metric_source_inventory_read',
 'ingestion_authentication_logs_read','metric_throttle_alert_telemetry_read'),
 'dashboard':('effective_viewer_inventory','ancestor_scope_authorization','deny_assignments',
 'transitive_groups','alternate_sharing')}

def _identity(row,scope,typ):
 if not isinstance(row,dict):raise ValueError('native monitoring resource is not an object')
 rid=row.get('id')
 if (not isinstance(rid,str)or any(ord(c)<=32 or ord(c)==127 for c in rid)or '%'in rid or '\\'in rid
     or any(p in ('.','..')for p in rid.split('/'))
     or not re.fullmatch(re.escape(scope)+r'/resourceGroups/[^/?#]+/providers/'+re.escape(typ)+r'/[^/?#]+',rid,re.I)
     or not isinstance(row.get('type'),str)or row['type'].casefold()!=typ.casefold()):
  raise ValueError('foreign or malformed native monitoring identity')
 if row.get('name')!=rid.rsplit('/',1)[-1]:raise ValueError('native monitoring resource name mismatch')
 return rid

def _strings(value):
 if not isinstance(value,list)or any(not isinstance(x,str)or not x for x in value):raise ValueError('native stream list malformed')
 return list(value)

def _projection(raw,kind,rid,version):
 props=raw.get('properties')
 if not isinstance(props,dict):raise ValueError('native monitoring GET properties absent')
 out={k:copy.deepcopy(raw[k])for k in('id','name','type','location','kind','etag')if k in raw};out['properties']={}
 if kind=='data_collection_rule':
  for k in ('immutableId','dataCollectionEndpointId','provisioningState'):
   if k in props:
    if not isinstance(props[k],str):raise ValueError('native DCR identity/state malformed')
    out['properties'][k]=props[k]
  if 'streamDeclarations'in props:
   declarations=props['streamDeclarations']
   if not isinstance(declarations,dict)or any(not isinstance(k,str)or not isinstance(v,dict)for k,v in declarations.items()):raise ValueError('native stream declarations malformed')
   # Schema only: arbitrary extension settings, KQL literals and source payloads
   # are deliberately excluded, rather than copied and redacted later.
   projected_declarations={}
   for name,value in declarations.items():
    columns=value.get('columns')
    if not isinstance(columns,list)or any(not isinstance(col,dict)or not isinstance(col.get('name'),str)or not isinstance(col.get('type'),str)for col in columns):raise ValueError('native declared columns malformed')
    projected_declarations[name]={'columns':[{'name':col['name'],'type':col['type']}for col in columns]}
   out['properties']['streamDeclarations']=projected_declarations
  if 'dataFlows'in props:
   if not isinstance(props['dataFlows'],list):raise ValueError('native data flows malformed')
   flows=[]
   for flow in props['dataFlows']:
    if not isinstance(flow,dict):raise ValueError('native data flow malformed')
    projected={}
    for key in ('streams','destinations'):
     if key in flow:projected[key]=_strings(flow[key])
    if 'outputStream'in flow:
     if not isinstance(flow['outputStream'],str):raise ValueError('native output stream malformed')
     projected['outputStream']=flow['outputStream']
    flows.append(projected)
   out['properties']['dataFlows']=flows
 else:
  if 'provisioningState'in props:
   if not isinstance(props['provisioningState'],str):raise ValueError('native dashboard state malformed')
   out['properties']['provisioningState']=props['provisioningState']
  # Dashboard tiles can contain inline content or arbitrary settings; neither
  # their bodies nor an invented effectiveAccess/public-sharing flag is retained.
 out['_provenance']={'source_operations':['ListBySubscription','Get'],'api_version':version,
                     'read_only':True,'representation':'projected_native_metadata','exact_resource_id':rid}
 out['_coverage']={gap:{'status':'not_collected','reason':'ARM metadata does not establish this evidence'}for gap in GAPS[kind]}
 return out

def collect(reader,request,scopes,wanted):
 jobs=[]
 for scope in scopes:
  for kind in NATIVE_TYPES:
   if kind not in wanted:continue
   typ,version=SPECS[kind]
   def inventory(scope=scope,kind=kind,typ=typ,version=version):
    seen=set()
    list_path=scope+'/providers/'+typ
    def scoped_list_request(url,**kwargs):
     parsed=urlsplit(url);query=parse_qs(parsed.query)
     if parsed.scheme!='https'or parsed.netloc!='management.azure.com'or parsed.path.casefold()!=list_path.casefold()or query.get('api-version',[version])!=[version]:raise ValueError('foreign monitoring pagination URL')
     return request(url,**kwargs)
    for page in reader.pages(scoped_list_request,ARM+list_path+'?api-version='+version):
     projected=[]
     for item in page:
      rid=_identity(item,scope,typ)
      if rid.casefold()in seen:raise ValueError('duplicate native monitoring resource')
      seen.add(rid.casefold())
      raw=reader.call(request,ARM+rid+'?api-version='+version)
      if _identity(raw,scope,typ).casefold()!=rid.casefold():raise ValueError('monitoring LIST/GET identity mismatch')
      projected.append(_projection(raw,kind,rid,version))
     yield projected
   jobs.append((kind,scope,typ.split('/')[0],inventory))
 reader.run(jobs)
 for collection in reader.collections:
  if collection['type']in NATIVE_TYPES:
   collection['semantic_coverage']={name:{'status':'not_collected','reason':'Separate behavioral/authorization evidence required'}for name in GAPS[collection['type']]}
