"""Bounded native Graph access reviews; identity metadata and actual decision times."""
from __future__ import annotations
import re

GRAPH = 'https://graph.microsoft.com'
ROOT = '/v1.0/identityGovernance/accessReviews/definitions'
NATIVE_TYPES = frozenset({'access_review_subject','access_review_definition','access_review_instance','access_review_decision'})
_GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',re.I)


def required_types(wanted):
    return {'directory_group','subscription'} if set(wanted)&NATIVE_TYPES else set()


def _id(value):
    if not isinstance(value,str) or not _GUID.fullmatch(value):
        raise ValueError('malformed native access review identity')
    return value


def _proof(tenant,operation):
    return {'tenant_id':tenant,'tenant_verified':True,'read_only':True,'representation':'full',
            'source_operation':operation,'adapter':'graph-access-reviews-native-v1'}


def _project(raw,tenant,kind,parent=None):
    row={'id':_id(raw.get('id')),'_provenance':_proof(tenant,kind)}
    if kind=='access_review_definition':
        settings=raw.get('settings')
        row.update(status=raw.get('status'),scope=raw.get('scope'),instanceEnumerationScope=raw.get('instanceEnumerationScope'),
            stageCount=len(raw.get('stageSettings', [])) if isinstance(raw.get('stageSettings', []),list) else None,
            reviewSettings={k:settings[k] for k in ('recurrence','instanceDurationInDays') if k in settings} if isinstance(settings,dict) else settings)
        row['_provenance']['native_field_mapping']={'reviewSettings':'settings'}
    elif kind=='access_review_instance':
        row.update(definitionId=parent)
        row.update({k:raw[k] for k in ('status','startDateTime','endDateTime','scope') if k in raw})
    else:
        if 'accessReviewId' in raw and raw['accessReviewId'] != parent:
            raise ValueError('native review decision returned a foreign instance')
        row.update(instanceId=parent)
        row.update({k:raw[k] for k in ('decision','reviewedDateTime') if k in raw})
        for name in ('principal','resource','reviewedBy'):
            value=raw.get(name)
            row[name]={k:value[k] for k in ('id','@odata.type') if k in value} if isinstance(value,dict) else value
    return row


def _children(reader,request,tenant,kind,parent_kind,path):
    parents=[c for c in reader.collections if c['type']==parent_kind and c['scope']=='/tenants/'+tenant]
    full=len(parents)==1 and parents[0]['status'] in ('collected','empty')
    rows=parents[0]['items'] if len(parents)==1 else []
    jobs=[]
    for parent in rows:
        pid=_id(parent['id'])
        url=GRAPH+path(parent)
        def fetch(pid=pid,url=url):
            seen=set()
            for page in reader.pages(request,url,audience=GRAPH,next_key='@odata.nextLink'):
                values=[]
                for raw in page:
                    row=_project(raw,tenant,kind,pid)
                    if row['id'].casefold() in seen:raise ValueError('duplicate access review child identity')
                    seen.add(row['id'].casefold());values.append(row)
                yield values
        jobs.append(('_native_'+kind,'/tenants/'+tenant+'/'+pid,'Microsoft.Graph',fetch))
    begin=len(reader.collections);reader.run(jobs);children=reader.collections[begin:];del reader.collections[begin:]
    complete=full and len(children)==len(rows) and all(c['status'] in ('collected','empty') for c in children)
    items=[r for c in children for r in c['items']]
    status=('collected' if items else 'empty') if complete else 'partial' if items else 'denied' if children and all(c['status']=='denied' for c in children) else 'not_collected'
    reader.collections.append({'type':kind,'scope':'/tenants/'+tenant,'service':'Microsoft.Graph','status':status,'items':items,
        '_provenance':_proof(tenant,kind),'parent_inventory':parent_kind,
        'covered_parent_ids':[p['id'] for p,c in zip(rows,children) if c['status'] in ('collected','empty')],
        **({} if complete else {'error':{'code':'native_access_review_parent_or_child_incomplete'}})})


def collect(reader,request,wanted,transport):
    if not set(wanted)&NATIVE_TYPES:return
    from .azure import AzureReadError
    tenant=getattr(transport,'verified_tenant',None)
    if not isinstance(tenant,str) or not _GUID.fullmatch(tenant):
        for kind in sorted(set(wanted)&NATIVE_TYPES):
            reader.unavailable(kind,'/tenants/unverified','Microsoft.Graph',AzureReadError('access_review_tenant_unverified'))
        return
    def subjects():
        seen=set()
        for page in reader.pages(request,GRAPH+'/v1.0/users?$select=id,userType,accountEnabled,createdDateTime',audience=GRAPH,next_key='@odata.nextLink'):
            rows=[]
            for user in page:
                uid=_id(user.get('id'))
                if uid.casefold() in seen:raise ValueError('duplicate native directory subject')
                seen.add(uid.casefold())
                rows.append({'id':uid,'principalId':uid,**{k:user[k] for k in ('userType','accountEnabled','createdDateTime') if k in user},
                    '_provenance':{**_proof(tenant,'users_List'),'subject_model':'directory_users'}})
            yield rows
    reader.run([('access_review_subject','/tenants/'+tenant,'Microsoft.Graph',subjects)])
    reader.collections[-1]['_provenance']={**_proof(tenant,'users_List'),'subject_model':'directory_users'}
    def definitions():
        seen=set()
        for page in reader.pages(request,GRAPH+ROOT,audience=GRAPH,next_key='@odata.nextLink'):
            rows=[]
            for raw in page:
                row=_project(raw,tenant,'access_review_definition')
                if row['id'].casefold() in seen:raise ValueError('duplicate native review definition')
                seen.add(row['id'].casefold());rows.append(row)
            yield rows
    reader.run([('access_review_definition','/tenants/'+tenant,'Microsoft.Graph',definitions)])
    _children(reader,request,tenant,'access_review_instance','access_review_definition',lambda p:ROOT+'/'+p['id']+'/instances')
    _children(reader,request,tenant,'access_review_decision','access_review_instance',
        lambda p:ROOT+'/'+p['definitionId']+'/instances/'+p['id']+'/decisions')
