"""Successor edge cases use the reviewed native HTTP transport, never CASES."""
from copy import deepcopy
import json
import socket
import pytest
from peaso import engine
from peaso.collectors import gcp
from peaso.snapshot import seal
from tests import test_gcp_native57_data_review_20261020 as native


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):pytest.fail('actual network/DNS/cloud auth forbidden')
    for name in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,name,blocked)
    for name in ('getaddrinfo','create_connection'):monkeypatch.setattr(socket,name,blocked)
    monkeypatch.setattr(gcp,'Credentials',blocked)
    import google.auth
    monkeypatch.setattr(google.auth,'default',blocked)


def findings(snapshot,cid='gcp.sql.iam_database_authentication'):
    return engine.evaluate_snapshot(snapshot,checks=[cid])['findings']


@pytest.mark.parametrize('kinds',[['sql_instance'],['bigquery_dataset'],['bigquery_table'],['sql_instance','bigquery_table']])
def test_numeric_scope_uses_one_native_project_read_without_explicit_project_dependency(monkeypatch,kinds):
    snapshot,trace=native.native_capture(monkeypatch,scope='projects/'+native.NUMBER,api_project=native.PROJECT,
        kinds=kinds,options={'concurrency':8})
    crm=[r for r in trace.calls if 'cloudresourcemanager.googleapis.com' in r['url']]
    assert len(crm)==1 and crm[0]['url']=='https://cloudresourcemanager.googleapis.com/v3/projects/'+native.NUMBER
    assert not any('compute.googleapis.com' in r['url'] for r in trace.calls)
    assert all('/projects/'+native.NUMBER+'/' not in r['url'] for r in trace.calls if 'cloudresourcemanager' not in r['url'])
    assert 'project' not in trace.collector.needed
    binding=snapshot['metadata']['data_service_project_bindings']['projects/'+native.NUMBER]
    assert binding['project_id']==native.PROJECT and binding['project_number']==native.NUMBER
    for kind,cid in [('sql_instance','gcp.sql.iam_database_authentication'),('bigquery_dataset','gcp.reviewed.bigquery.cmek'),('bigquery_table',native.TABLE_ID)]:
        if kind in kinds:assert {r['status'] for r in findings(snapshot,cid)}=={'PASS'}


def test_numeric_resolution_reused_for_multiple_instances_and_native_project_not_rewritten(monkeypatch):
    objects=[native.sql(name='first-db'),native.sql(name='second-db')]
    user={'kind':'sql#user','name':'operator@corp.example','host':'%','type':'CLOUD_IAM_USER','project':native.PROJECT}
    snapshot,trace=native.native_capture(monkeypatch,scope='projects/'+native.NUMBER,api_project=native.PROJECT,
        instances=objects,users=[user],options={'concurrency':8})
    assert sum('cloudresourcemanager.googleapis.com' in r['url'] for r in trace.calls)==1
    assert len(trace.calls)==4
    assert {r['status'] for r in findings(snapshot)}=={'PASS'}
    rows=next(c for c in snapshot['collections'] if c['type']=='sql_instance')['items']
    assert len(rows)==2 and all(r['usersList']['items'][0]['project']==native.PROJECT for r in rows)


@pytest.mark.parametrize('payload',[
    {},{'name':'projects/'+native.NUMBER},{'projectId':native.PROJECT},
    {'name':'projects/999999999999','projectId':native.PROJECT},
    {'name':'projects/'+native.NUMBER,'projectId':None},
    {'name':'projects/'+native.NUMBER,'projectId':'123456'},
    {'name':'projects/'+native.NUMBER,'projectId':'a'*31},
    {'name':'projects/'+native.NUMBER,'projectId':native.PROJECT,'items':[{},{}]},
    {'name':'projects/'+native.NUMBER,'projectId':native.PROJECT,'projects':[{},{}]},
    {'name':'projects/'+native.NUMBER,'projectId':native.PROJECT,'nextPageToken':'next'},
])
def test_malformed_foreign_or_multiple_native_project_proofs_cannot_authorize_reads(monkeypatch,payload):
    snapshot,trace=native.native_capture(monkeypatch,scope='projects/'+native.NUMBER,api_project=native.PROJECT,
        kinds=['sql_instance','bigquery_dataset'],overrides={'project-get':payload})
    assert len(trace.calls)==1 and 'cloudresourcemanager.googleapis.com' in trace.calls[0]['url']
    assert all(r['status'] in ('UNKNOWN','DENIED') for r in findings(snapshot))
    assert snapshot['metadata']['data_service_project_bindings']=={}


@pytest.mark.parametrize('status',[400,401,403,404,429,500])
def test_denied_project_alias_proof_is_cached_no_service_or_numeric_guess(monkeypatch,status):
    snapshot,trace=native.native_capture(monkeypatch,scope='projects/'+native.NUMBER,api_project=native.PROJECT,
        kinds=['sql_instance','bigquery_table'],overrides={'project-get':native.Response({'error':{'code':status,'status':'PERMISSION_DENIED'}},status)})
    assert len(trace.calls)==1
    assert all(r['status'] in ('UNKNOWN','DENIED') for r in findings(snapshot))


def test_duplicate_project_identity_json_rejected_before_cache(monkeypatch):
    response=native.Response({})
    response.content=('{'+'"name":"projects/'+native.NUMBER+'","projectId":"foreign-project",'+
        '"projectId":"'+native.PROJECT+'"}').encode()
    snapshot,trace=native.native_capture(monkeypatch,scope='projects/'+native.NUMBER,api_project=native.PROJECT,
        kinds=['project','sql_instance'],overrides={'project-get':response})
    assert sum('cloudresourcemanager.googleapis.com' in r['url'] for r in trace.calls)==1
    assert all(r['status'] in ('UNKNOWN','DENIED') for r in findings(snapshot))
    assert snapshot['metadata']['data_service_project_bindings']=={}


@pytest.mark.parametrize('change',[
    lambda b:b.update(scope='projects/foreign'),lambda b:b.update(status='denied'),
    lambda b:b.update(project_id='foreign-project'),lambda b:b.update(project_number='999999999999'),
    lambda b:b.update(source_requests=[]),lambda b:b.update(source_requests=['missing']),
    lambda b:b.update(source_requests=['same','same']),
])
def test_consumer_rejects_unbound_numeric_alias_metadata(monkeypatch,change):
    snapshot,_=native.native_capture(monkeypatch,scope='projects/'+native.NUMBER,api_project=native.PROJECT)
    assert {r['status'] for r in findings(snapshot)}=={'PASS'}
    snapshot=deepcopy(snapshot);change(snapshot['metadata']['data_service_project_bindings']['projects/'+native.NUMBER])
    assert {r['status'] for r in findings(seal(snapshot))}=={'UNKNOWN'}


@pytest.mark.parametrize('field,value',[
    ('scope','projects/foreign'),('method','POST'),('url','https://foreign.invalid/v3/projects/'+native.NUMBER),
    ('http_status',206),('status','denied'),('query',{'fields':'name'}),
])
def test_consumer_rejects_tampered_native_crm_source_receipt(monkeypatch,field,value):
    snapshot,_=native.native_capture(monkeypatch,scope='projects/'+native.NUMBER,api_project=native.PROJECT)
    snapshot=deepcopy(snapshot)
    ref=snapshot['metadata']['data_service_project_bindings']['projects/'+native.NUMBER]['source_requests'][0]
    next(r for r in snapshot['metadata']['source_requests'] if r['id']==ref)[field]=value
    assert {r['status'] for r in findings(seal(snapshot))}=={'UNKNOWN'}


@pytest.mark.parametrize('field,value',[
    ('project','foreign-project'),('projectId','foreign-project'),('name','../foreign'),
    ('selfLink','https://foreign.invalid/sql/v1beta4/projects/'+native.PROJECT+'/instances/'+native.INSTANCE),
    ('selfLink','https://sqladmin.googleapis.com/sql/v1beta4/projects/'+native.PROJECT+'/instances/other-db'),
    ('selfLink','https://sqladmin.googleapis.com/sql/v1beta4/projects/'+native.PROJECT+'/instances/'+native.INSTANCE+'?alt=json'),
    ('connectionName',native.PROJECT+':foreign-region:'+native.INSTANCE),
    ('connectionName','foreign-project:us-central1:'+native.INSTANCE),
])
def test_sql_parent_identity_conflicts_prevent_user_hydration(monkeypatch,field,value):
    obj=native.sql();obj[field]=value
    snapshot,trace=native.native_capture(monkeypatch,instances=[obj])
    assert len(trace.calls)==1 and all(r['status'] in ('UNKNOWN','DENIED') for r in findings(snapshot))


@pytest.mark.parametrize('field,value',[
    ('instance','foreign-db'),('instanceId','foreign-db'),('project','foreign-project'),('userName','foreign-user'),
])
def test_native_sql_user_identity_fields_not_overwritten_to_pass(monkeypatch,field,value):
    user=native.user();user[field]=value
    snapshot,_=native.native_capture(monkeypatch,users=[user])
    assert all(r['status'] in ('UNKNOWN','DENIED') for r in findings(snapshot))


@pytest.mark.parametrize('kind,field,value',[
    ('dataset','id',native.PROJECT+':foreign_dataset'),
    ('dataset','projectId','foreign-project'),
    ('table','project','foreign-project'),
    ('dataset','selfLink','https://foreign.invalid/bigquery/v2/projects/'+native.PROJECT+'/datasets/'+native.DATASET),
    ('dataset','datasetId','foreign_dataset'),
    ('table','id',native.PROJECT+':foreign_dataset.'+native.TABLE),
    ('table','selfLink','https://foreign.invalid/bigquery/v2/projects/'+native.PROJECT+'/datasets/'+native.DATASET+'/tables/'+native.TABLE),
    ('table','datasetId','foreign_dataset'),('table','tableId','foreign_table'),
])
def test_bigquery_detail_native_ids_and_hosts_must_match_exact_parent(monkeypatch,kind,field,value):
    payload=native.dataset() if kind=='dataset' else native.table();payload[field]=value
    snapshot,_=native.native_capture(monkeypatch,kinds=['bigquery_dataset' if kind=='dataset' else 'bigquery_table'],
        overrides={kind+'-get':payload})
    cid='gcp.reviewed.bigquery.cmek' if kind=='dataset' else native.TABLE_ID
    assert all(r['status'] in ('UNKNOWN','DENIED') for r in findings(snapshot,cid))


@pytest.mark.parametrize('kind',['dataset','table'])
def test_bigquery_list_identity_conflict_never_drives_detail_read(monkeypatch,kind):
    payload=native.dataset() if kind=='dataset' else native.table()
    payload['datasetReference' if kind=='dataset' else 'tableReference']['projectId']='foreign-project'
    override={'datasets':[payload]} if kind=='dataset' else {'tables':[payload]}
    snapshot,trace=native.native_capture(monkeypatch,kinds=['bigquery_dataset' if kind=='dataset' else 'bigquery_table'],overrides={kind+'-list':override})
    assert len(trace.calls)==(1 if kind=='dataset' else 3)
    cid='gcp.reviewed.bigquery.cmek' if kind=='dataset' else native.TABLE_ID
    assert all(r['status'] in ('UNKNOWN','DENIED') for r in findings(snapshot,cid))


@pytest.mark.parametrize('version,expected',[
    ('MYSQL_5_7','PASS'),('MYSQL_8_4','PASS'),('POSTGRES_16','NOT_APPLICABLE'),
    ('SQLSERVER_2022_ENTERPRISE','NOT_APPLICABLE'),('SQLSERVER_NEW_EDITION','UNKNOWN'),('FUTURE_1','UNKNOWN')])
def test_mysql_binary_log_actual_engine_guard(monkeypatch,version,expected):
    snapshot,_=native.native_capture(monkeypatch,instances=[native.sql(version)])
    assert {r['status'] for r in findings(snapshot,'gcp.ports.sql_instance_mysql_binary_log_enabled')}=={expected}


@pytest.mark.parametrize('backend,expected',[('SECOND_GEN','PASS'),('EXTERNAL','NOT_APPLICABLE'),('FIRST_GEN','NOT_APPLICABLE'),('UNSPECIFIED','UNKNOWN'),('FUTURE','UNKNOWN')])
def test_second_gen_applicability_never_accepts_unknown_backend(monkeypatch,backend,expected):
    obj=native.sql();obj['backendType']=backend
    snapshot,_=native.native_capture(monkeypatch,instances=[obj])
    assert {r['status'] for r in findings(snapshot,'gcp.claude.sql_instance.second_gen_no_public_ip')}=={expected}


def test_native_anonymous_dataset_detail_denial_does_not_hide_other_tables(monkeypatch):
    anonymous='_'+'a'*40
    datasets=[native.dataset(name=anonymous),native.dataset()]
    def details(payload):
        return native.Response({'error':{'code':403,'status':'PERMISSION_DENIED'}},403) if payload['datasetReference']['datasetId']==anonymous else payload
    snapshot,trace=native.native_capture(monkeypatch,kinds=['bigquery_table'],datasets=datasets,
        overrides={'dataset-get':details})
    assert {r['status'] for r in findings(snapshot,native.TABLE_ID)}=={'PASS'}
    assert not any('/datasets/'+anonymous+'/tables' in r['url'] for r in trace.calls)
    assert len(next(c for c in snapshot['collections'] if c['type']=='bigquery_table')['items'])==1


def test_native_dataset_acl_denial_retains_list_identity_without_claiming_clean_acl(monkeypatch):
    snapshot,trace=native.native_capture(monkeypatch,kinds=['bigquery_dataset'],
        overrides={'dataset-get':native.Response({'error':{'code':403,'status':'PERMISSION_DENIED'}},403)})
    row=next(c for c in snapshot['collections'] if c['type']=='bigquery_dataset')['items'][0]
    assert row['datasetReference']=={'projectId':native.PROJECT,'datasetId':native.DATASET}
    assert row['_provenance']['representation']=='partial' and 'access' not in row
    assert {r['status'] for r in findings(snapshot,'gcp.ports.bigquery_dataset_not_publicly_accessible')}=={'UNKNOWN'}
    assert len(trace.calls)==2
