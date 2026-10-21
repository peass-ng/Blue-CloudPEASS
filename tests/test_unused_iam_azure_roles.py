from copy import deepcopy
from types import SimpleNamespace
import pytest
from peaso import unused_iam_azure_roles as subject
from peaso import azure_unused_role_contract as producer

TENANT='11111111-1111-4111-8111-111111111111'
ROLE='22222222-2222-4222-8222-222222222222'
PRINCIPAL='33333333-3333-4333-8333-333333333333'
OTHER='44444444-4444-4444-8444-444444444444'
SCOPE='/tenants/'+TENANT
NOW='2026-10-21T12:00:00Z'


def proof(endpoint=None):
    out={'tenant_id':TENANT,'tenant_verified':True,'credential_context_id':'capture-one','customer_context_id':'customer-one'}
    if endpoint:out.update(endpoint=endpoint,read_only=True)
    return out


def grant(schedule=False, **extra):
    row={'id':'opaque-consumer-one','roleDefinitionId':ROLE,'principalId':PRINCIPAL,'directoryScopeId':'/'}
    if schedule:row.update(status='Granted',scheduleInfo={'startDateTime':'2025-01-01T00:00:00Z','expiration':{'type':'noExpiration'}})
    return {**row,**extra}


def report(name, rows=None):
    return {'name':name,'endpoint':producer.REPORTS[name],'audience':producer.GRAPH,'method':'GET','body':None,'filter':None,
        'projection':'full','items':rows or [],'status':'collected' if rows else 'empty','integrity_error':False}


def fixture(bound=None):
    role={'id':ROLE,'displayName':'Synthetic application role','isBuiltIn':False,'isEnabled':True,
        'rolePermissions':[{'allowedResourceActions':['microsoft.directory/applications/credentials/update','microsoft.directory/applications/basic/read']}],
        '_provenance':proof('/v1.0/roleManagement/directory/roleDefinitions')}
    reports=[report(name,[grant(name!='assignments')] if name==bound else []) for name in producer.REPORTS]
    rp={**proof('native-unused-role-projection'),'schema':producer.SCHEMA,'observed_at':NOW}
    record={'id':SCOPE+'/unusedRoleEvidence','schema':producer.SCHEMA,'reports':reports,'_provenance':rp}
    index={'context':{'provider':'azure','scope':SCOPE,'created_at':NOW,'metadata':proof()},'collections':{}}
    for kind,items in [('directory_role_definition',[role]),(producer.KIND,[record])]:
        index[kind]=[{'type':kind,'scope':SCOPE,'data':row} for row in items]
        index['collections'][kind]=[{'type':kind,'scope':SCOPE,'service':'Microsoft.Graph','status':'collected','items':items,'_provenance':proof()}]
    return role,index


def sources(index):return index[producer.KIND][0]['data']['reports']


def test_complete_unassigned_custom_role_fails_with_exact_permissions():
    item,index=fixture();before=deepcopy(index)
    status,evidence=subject.evaluate(item,index)
    assert status=='FAIL',evidence
    assert evidence['role_permissions']==item['rolePermissions']
    assert index==before


@pytest.mark.parametrize('source',list(producer.REPORTS))
def test_current_assignment_or_eligibility_and_future_schedule_are_consumers(source):
    item,index=fixture(source)
    if source!='assignments': sources(index)[list(producer.REPORTS).index(source)]['items'][0]['scheduleInfo']['startDateTime']='2027-01-01T00:00:00Z'
    status,evidence=subject.evaluate(item,index)
    assert status=='PASS',evidence
    assert evidence['declared_consumers'][0]['principal_id']==PRINCIPAL


@pytest.mark.parametrize('status',sorted(subject.ACTIVE|subject.INACTIVE))
def test_pim_status_controls_current_or_planned_consumers(status):
    item,index=fixture('eligibility_schedules');sources(index)[2]['items'][0]['status']=status
    assert subject.evaluate(item,index)[0]==('PASS' if status in subject.ACTIVE else 'FAIL')


@pytest.mark.parametrize('expiration,expected',[
    ({'type':'afterDateTime','endDateTime':'2026-10-21T12:00:00Z'},'FAIL'),
    ({'type':'afterDateTime','endDateTime':'2027-01-01T00:00:00Z'},'PASS'),
    ({'type':'afterDuration','duration':'PT3H'},'FAIL'),
    ({'type':'afterDuration','duration':'P3650D'},'PASS'),
    ({'type':'afterDuration','duration':'P3M'},'UNKNOWN'),
    ({'type':'notSpecified'},'UNKNOWN'),
    ({'type':'noExpiration','endDateTime':'2027-01-01T00:00:00Z'},'UNKNOWN'),
    ({'type':'afterDateTime','endDateTime':'2024-01-01T00:00:00Z'},'UNKNOWN'),
])
def test_pim_expiration_never_counts_expired_or_ambiguous_lifetimes(expiration,expected):
    item,index=fixture('eligibility_schedules');sources(index)[2]['items'][0]['scheduleInfo']['expiration']=expiration
    assert subject.evaluate(item,index)[0]==expected


@pytest.mark.parametrize('mutation',['tenant','capture','endpoint','role_projection','evidence_projection','missing_pim','foreign_source','filtered','projected',
    'denied','partial_denied','partial','integrity','duplicate_role','permission_shape','missing_boolean','future_capture','missing_scope','foreign_role','missing_schema'])
def test_no_role_absence_without_bound_complete_native_sources(mutation):
    item,index=fixture();reports=sources(index);expected='UNKNOWN'
    if mutation=='tenant':index['context']['metadata']['tenant_id']=OTHER
    elif mutation=='capture':item['_provenance']['credential_context_id']='foreign'
    elif mutation=='endpoint':item['_provenance']['endpoint']='/v1.0/roleManagement/entitlementManagement/roleDefinitions'
    elif mutation=='role_projection':index['directory_role_definition']=[]
    elif mutation=='evidence_projection':index[producer.KIND]=[]
    elif mutation=='missing_pim':reports.pop()
    elif mutation=='foreign_source':reports[2]['endpoint']='/v1.0/roleManagement/directory/roleAssignments'
    elif mutation=='filtered':reports[2]['filter']='principalId eq other'
    elif mutation=='projected':reports[2]['projection']='id_only'
    elif mutation=='denied':reports[2]['status']='denied';expected='DENIED'
    elif mutation=='partial_denied':reports[2].update(status='partial',error={'kind':'denied'});expected='DENIED'
    elif mutation=='partial':reports[2]['status']='partial'
    elif mutation=='integrity':reports[2]['integrity_error']=True
    elif mutation=='duplicate_role':index['directory_role_definition'].append(deepcopy(index['directory_role_definition'][0]));index['collections']['directory_role_definition'][0]['items'].append(deepcopy(item))
    elif mutation=='permission_shape':item['rolePermissions'][0]['allowedResourceActions']=[None]
    elif mutation=='missing_boolean':item.pop('isBuiltIn')
    elif mutation=='future_capture':index[producer.KIND][0]['data']['_provenance']['observed_at']='2027-01-01T00:00:00Z'
    elif mutation=='missing_scope':reports[2].update(status='collected',items=[grant(True)]);reports[2]['items'][0].pop('directoryScopeId')
    elif mutation=='foreign_role':item=deepcopy(item);item['id']=OTHER
    elif mutation=='missing_schema':index[producer.KIND][0]['data'].pop('schema')
    assert subject.evaluate(item,index)[0]==expected


def test_known_assignment_survives_unrelated_pim_denial():
    item,index=fixture('assignments');sources(index)[2]['status']='denied'
    assert subject.evaluate(item,index)[0]=='PASS'


def test_malformed_duplicate_binding_cannot_certify_a_consumer():
    item,index=fixture('assignments');sources(index)[0]['items'].append(deepcopy(sources(index)[0]['items'][0]))
    assert subject.evaluate(item,index)[0]=='UNKNOWN'


def test_empty_source_status_with_rows_cannot_certify_a_consumer():
    item,index=fixture('assignments');sources(index)[0]['status']='empty'
    assert subject.evaluate(item,index)[0]=='UNKNOWN'


def test_builtin_role_is_not_applicable_but_disabled_custom_role_can_be_unassigned():
    item,index=fixture();item['isBuiltIn']=True
    assert subject.evaluate(item,index)[0]=='NOT_APPLICABLE'
    item,index=fixture();item['isEnabled']=False
    assert subject.evaluate(item,index)[0]=='FAIL'


def test_shared_memo_joins_assignment_graph_once(monkeypatch):
    from peaso.checks.facts import MemoIndex
    item,index=fixture('assignments');calls=[];original=subject.reports
    def tracked(*args):calls.append(True);return original(*args)
    monkeypatch.setattr(subject,'reports',tracked);index=MemoIndex(index)
    assert subject.evaluate(item,index)[0]=='PASS'
    assert subject.evaluate(item,index)[0]=='PASS'
    assert len(calls)==1


def test_collector_skips_unspecified_roles():
    from peaso.collectors import azure_unused_roles_20261021 as producer
    producer.collect(None,None,[],set(),None,None,None)


@pytest.mark.parametrize('mode',['bound','empty','denied','partial_positive','page_limit','resource_limit','filter_injection','duplicate'])
def test_real_reader_preserves_pages_failure_types_and_only_get_metadata(mode):
    from peaso.collectors import azure_unused_roles_20261021 as producer
    from peaso.collectors.azure import _Reader
    reader=_Reader({'retries':0,**({'max_pages':1} if mode=='page_limit' else {}),**({'max_resources':1} if mode=='resource_limit' else {})});calls=[]
    class Denied(Exception):status_code=403
    def request(url,*,audience,body=None):
        assert audience==producer.GRAPH and body is None;calls.append(url)
        if 'roleAssignments' in url:
            if '$skiptoken=' in url:
                if mode=='partial_positive':raise Denied('PRIVATE_ERROR_DO_NOT_RETAIN')
                return {'value':[grant()] if mode=='duplicate' else []}
            if mode=='denied':raise Denied('PRIVATE_ERROR_DO_NOT_RETAIN')
            if mode=='resource_limit':return {'value':[grant(),grant(id='second-consumer')]}
            if mode in ('partial_positive','page_limit','filter_injection','duplicate'):
                return {'value':[grant()], '@odata.nextLink':url+'?'+('$filter=principalId%20eq%20other' if mode=='filter_injection' else '$skiptoken=next')}
            return {'value':[dict(grant(),secretText='PRIVATE_VALUE_DO_NOT_RETAIN',displayName='NOT_NEEDED')] if mode=='bound' else []}
        return {'value':[]}
    producer.collect(reader,request,[],{producer.KIND},SimpleNamespace(tenant=TENANT,verified_tenant=TENANT),'capture-one','customer-one')
    record=reader.collections[-1]['items'][0]
    text=str(record);assert 'PRIVATE_VALUE_DO_NOT_RETAIN' not in text and 'PRIVATE_ERROR_DO_NOT_RETAIN' not in text
    source=record['reports'][0]
    assert source['status']=={'bound':'collected','empty':'empty','denied':'denied'}.get(mode,'partial')
    if mode=='filter_injection':assert not any('$filter' in url for url in calls)
    item,index=fixture();index[producer.KIND][0]['data'].update(reports=record['reports'])
    expected={'bound':'PASS','empty':'FAIL','denied':'DENIED','partial_positive':'PASS','page_limit':'PASS','resource_limit':'PASS','filter_injection':'UNKNOWN','duplicate':'UNKNOWN'}[mode]
    assert subject.evaluate(item,index)[0]==expected


@pytest.mark.parametrize('source,expected',[(None,'FAIL'),('assignments','PASS'),('eligibility_schedules','PASS')])
def test_normal_native_registration_and_hardening_json(source,expected):
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    from peaso.snapshot import make_snapshot
    from peaso.engine import evaluate_snapshot,hydrate_frameworks
    check=next(c for c in CHECKS if c.id==subject.CHECK);case=CASES[subject.CHECK]
    for verdict in ('PASS','FAIL'):
        key=verdict.lower();assert check.evaluate(case[key],case[key+'_index'])[0]==verdict
    item,index=fixture(source)
    collections=[deepcopy(c) for cs in index['collections'].values() for c in cs]
    snapshot=make_snapshot('azure',[SCOPE],collections,created_at=NOW,metadata=proof())
    finding=hydrate_frameworks(evaluate_snapshot(snapshot,categories=['hardening'],checks=[subject.CHECK]))['findings'][0]
    assert finding['status']==expected,finding
    assert finding['evidence']['role_permissions']==item['rolePermissions']
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']


@pytest.mark.parametrize('source,expected',[(None,'FAIL'),('assignments','PASS'),('eligibility_schedules','PASS')])
def test_normal_azure_collector_dispatches_only_role_definition_and_consumer_reads(source,expected):
    from urllib.parse import urlsplit
    from peaso.collectors import azure
    from peaso.engine import evaluate_snapshot,hydrate_frameworks
    item,index=fixture(source);payload={r['endpoint']:r['items'] for r in sources(index)}
    class Transport:
        tenant=TENANT
        verified_tenant=TENANT
        def __init__(self):self.calls=[]
        def request(self,url,*,audience=azure.ARM,body=None):
            assert body is None and audience==producer.GRAPH
            self.calls.append(url);path=urlsplit(url).path
            if path=='/v1.0/roleManagement/directory/roleDefinitions':return {'value':[deepcopy(item)]}
            if path in payload:return {'value':deepcopy(payload[path])}
            raise AssertionError('Unexpected native read: '+path)
    transport=Transport()
    snapshot=azure.collect({'provider':'azure','scopes':['/subscriptions/'+OTHER],'auth':{'tenant_id':TENANT},
        'options':{'inventories':[producer.KIND],'concurrency':1,'retries':0}},transport=transport)
    finding=hydrate_frameworks(evaluate_snapshot(snapshot,categories=['hardening'],checks=[subject.CHECK]))['findings'][0]
    assert finding['status']==expected,finding['evidence']
    assert finding['evidence']['role_permissions']==item['rolePermissions']
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    assert len(transport.calls)==4
