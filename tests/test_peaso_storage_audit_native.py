"""Cloud Storage Data Access audit policy through native collector and engine."""
import copy
import pytest
from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot

CHECK='gcp.claude.project.storage_data_access_audit_logs'
ANY='gcp.claude.project.audit_logs_configured'
SCOPE='projects/p-one'
READ={'logType':'DATA_READ'}
WRITE={'logType':'DATA_WRITE'}

def config(service='storage.googleapis.com', rows=None):
    return {'service':service,'auditLogConfigs':copy.deepcopy(rows if rows is not None else [READ,WRITE])}

class Transport:
    def __init__(self, *, project=None, folder=None, org=None, denied=False):
        self.configs={'projects/p-one':project,'folders/12':folder,'organizations/34':org}
        self.denied=denied;self.calls=[];self.evidence=[]
    def request(self, method, url, **kwargs):
        ref=f'request-{len(self.calls)+1}';self.calls.append((method,url))
        if url.endswith(':getAncestry'):
            result={'ancestor':[{'resourceId':{'type':'project','id':'p-one'}},
                {'resourceId':{'type':'folder','id':'12'}},
                {'resourceId':{'type':'organization','id':'34'}}]}
        elif url.endswith(':getIamPolicy'):
            scope=url.split('/v3/',1)[1].split(':getIamPolicy',1)[0]
            if self.denied and scope=='organizations/34':
                exc=gcp.ReadError('denied','api_error',http_status=403);exc.request_id=ref
                self.evidence.append({'id':ref,'url':url,'method':method,'status':'denied','error':exc.error})
                raise exc
            result={'version':3,'bindings':[]}
            if self.configs[scope] is not None:result['auditConfigs']=copy.deepcopy(self.configs[scope])
        else:result={'results':[]}
        self.evidence.append({'id':ref,'url':url,'method':method,'status':'collected'})
        return result,ref

def collect(**kwargs):
    request={'connector':{'provider':'gcp','scopes':[SCOPE], 'options':{
        'inventories':['iam_policy'],'include_inherited':True,'concurrency':1,'max_calls':20}},
        'checks':[CHECK],'categories':[]}
    assert plan_collection(request)==['iam_policy']
    transport=Transport(**kwargs)
    snapshot=gcp.GCPCollector(request['connector'],transport=transport).collect()
    assert 0<len(transport.calls)<=20 and all(method in ('GET','POST') for method,_ in transport.calls)
    return snapshot

def finding(snapshot, check=CHECK):
    rows=[r for r in evaluate_snapshot(snapshot,checks=[check])['findings'] if r['check_id']==check
          and r['resource_id']!='inventory:iam_policy' and r.get('scope')==SCOPE]
    assert len(rows)==1,[(r.get('status'),r.get('resource_id')) for r in rows]
    return rows[0]['status']

def project(snapshot):
    return next(row for c in snapshot['collections'] if c['type']=='iam_policy' and c['scope']==SCOPE
                for row in c['items'] if row.get('name')==SCOPE)

@pytest.mark.parametrize('kwargs',[
    {'project':[config()]}, {'folder':[config('allServices')]}, {'org':[config()]},
    {'project':[config(rows=[READ])],'folder':[config(rows=[WRITE])]},
])
def test_complete_native_union_pass(kwargs):assert finding(collect(**kwargs))=='PASS'

@pytest.mark.parametrize('kwargs',[{}, {'folder':[config(rows=[READ])]}, {'project':[config(rows=[WRITE])]}])
def test_complete_missing_type_fails(kwargs):assert finding(collect(**kwargs))=='FAIL'

@pytest.mark.parametrize('kwargs',[
    {'project':[config(rows=[READ,{'logType':'DATA_WRITE','exemptedMembers':['user:excluded@example.com']}])]},
    {'folder':[config('allServices',rows=[READ,{'logType':'DATA_WRITE','exemptedMembers':['group:team@example.com']}])]},
    {'folder':[config(rows=[READ,{'logType':'DATA_WRITE','exemptedMembers':[None]}])]},
    {'org':[config(rows=[READ,{'logType':'DATA_WRITE','exemptedMembers':'bad'}])]},
])
def test_exemption_cannot_prove_universal_logging(kwargs):assert finding(collect(**kwargs))=='UNKNOWN'

def test_denied_ancestor_unknown():assert finding(collect(folder=[config()],denied=True))=='UNKNOWN'

@pytest.mark.parametrize('change',['partial','missing_entry','foreign_policy_request','foreign_ancestry_request','missing_annotation'])
def test_incomplete_or_foreign_proof_unknown(change):
    snapshot=collect(folder=[config()]);collections=copy.deepcopy(snapshot['collections']);metadata=copy.deepcopy(snapshot['metadata'])
    row=next(row for c in collections if c['type']=='iam_policy' and c['scope']==SCOPE
             for row in c['items'] if row.get('name')==SCOPE)
    coverage=row['_coverage']['effectiveAuditConfigs']
    if change=='partial':coverage['status']='partial'
    elif change=='missing_entry':row['effectiveAuditConfigs'].pop(1)
    elif change=='foreign_policy_request':
        ref=row['effectiveAuditConfigs'][1]['source_requests'][0]
        next(x for x in metadata['source_requests'] if x['id']==ref)['url']='https://cloudresourcemanager.googleapis.com/v3/folders/99:getIamPolicy'
    elif change=='foreign_ancestry_request':
        ref=coverage['ancestry_source_requests'][0]
        next(x for x in metadata['source_requests'] if x['id']==ref)['url']='https://cloudresourcemanager.googleapis.com/v1/projects/foreign:getAncestry'
    else:row.pop('effectiveAuditConfigs');row['_coverage'].pop('effectiveAuditConfigs')
    assert finding(make_snapshot('gcp',snapshot['scopes'],collections,metadata=metadata))=='UNKNOWN'

def test_cai_partial_alias_not_direct_project_policy():
    snapshot=collect(folder=[config()]);collections=copy.deepcopy(snapshot['collections'])
    row=next(row for c in collections if c['type']=='iam_policy' and c['scope']==SCOPE
             for row in c['items'] if row.get('name')==SCOPE)
    row['_provenance']['representation']='partial';row['auditConfigs']=[config()]
    assert finding(make_snapshot('gcp',snapshot['scopes'],collections,metadata=snapshot['metadata']))=='NOT_APPLICABLE'

def test_existing_audit_any_uses_shared_validator():assert finding(collect(folder=[config()]),ANY)=='PASS'

@pytest.mark.parametrize('legacy,expected',[(False,'UNKNOWN'),(True,'PASS')])
def test_missing_effective_annotation_preserves_only_legacy_direct_compatibility(legacy,expected):
    snapshot=collect(project=[config()]);collections=copy.deepcopy(snapshot['collections'])
    row=next(row for c in collections if c['type']=='iam_policy' and c['scope']==SCOPE
             for row in c['items'] if row.get('name')==SCOPE)
    row.pop('effectiveAuditConfigs');row['_coverage'].pop('effectiveAuditConfigs')
    if legacy:row.pop('_provenance')
    assert finding(make_snapshot('gcp',snapshot['scopes'],collections,metadata=snapshot['metadata']))==expected

def test_legacy_no_direct_declaration_remains_manual():
    snapshot=collect();collections=copy.deepcopy(snapshot['collections'])
    row=next(row for c in collections if c['type']=='iam_policy' and c['scope']==SCOPE
             for row in c['items'] if row.get('name')==SCOPE)
    row.pop('effectiveAuditConfigs');row['_coverage'].pop('effectiveAuditConfigs');row.pop('_provenance')
    assert finding(make_snapshot('gcp',snapshot['scopes'],collections,metadata=snapshot['metadata']))=='MANUAL'

def test_unrelated_service_does_not_enable_storage():
    assert finding(collect(folder=[config('pubsub.googleapis.com')]))=='FAIL'

def test_allservices_and_storage_exemption_union_is_not_universal_pass():
    inherited=[config('allServices')]
    direct=[config(rows=[{'logType':'DATA_READ','exemptedMembers':['user:excluded@example.com']}])]
    assert finding(collect(project=direct,folder=inherited))=='UNKNOWN'
