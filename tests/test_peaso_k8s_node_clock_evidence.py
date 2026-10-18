"""Imported measurement fixtures are external assertions, never native captures."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
import pytest
from peaso.collectors import k8s,k8s_node_clock_evidence as external
from tests.archived_check_contract import collect_snapshot,evaluate_snapshot
CHECK='k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4'
C='clock-fixture';UID='11111111-2222-4333-8444-555555555555';SYSTEM='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'

def options(delta=0):
    now=datetime.now(timezone.utc)-timedelta(seconds=1)
    row={'node_name':'node1','node_uid':UID,'measurement_id':'m-1','observer_id':'monitor',
         'reference_id':'nts-server','measured_at':now.isoformat(),
         'node_utc':(now+timedelta(seconds=delta)).isoformat(),'reference_utc':now.isoformat(),
         'uncertainty_seconds':0.1,'node_measurement_method':'host_agent_clock_read',
         'node_identity_record_id':'identity-1','reference_protocol':'NTS',
         'reference_verification_record_id':'nts-exchange-1'}
    review={'cluster_id':C,'kube_system_uid':SYSTEM,'reviewer_id':'reviewer',
            'review_record_id':'review-1','reviewed_at':now.isoformat(),'max_age_seconds':120,
            'approved_observer_ids':['monitor'],'approved_reference_ids':['nts-server'],
            'reviewed_measurement_ids':['m-1']}
    return {'inventories':['node_clock'],'retries':0,'concurrency':1,
            'compliance_policy':{'cluster_id':C,'observed_at':now.isoformat(),'max_age_seconds':120,
                                 'max_policy_items':20,'approved_clock_skew':2},
            external.OPTION:{'review':review,'observations':[row]}}

class API:
    server='https://fixture.invalid'
    api_client=SimpleNamespace(configuration=SimpleNamespace(host=server))
    def __init__(self,mode=None):self.mode=mode;self.calls=[]
    def close(self):pass
    def get_json(self,path,params=None):
        self.calls.append((path,deepcopy(params)))
        if path=='/api/v1/nodes':
            if self.mode=='denied' or self.mode=='partial' and(params or {}).get('continue'):
                raise k8s.K8sReadError('permission_denied',403)
            return {'metadata':{'resourceVersion':'1','continue':'next'if self.mode=='partial'else ''},
                    'items':[{'metadata':{'name':'node1','uid':'replacement'if self.mode=='replacement'else UID}}]}
        if path=='/api/v1/namespaces':
            return {'metadata':{'resourceVersion':'1'},'items':[{'metadata':{'name':'kube-system','uid':SYSTEM}}]}
        raise AssertionError(path)

def run(monkeypatch,opt=None,mode=None):
    api=API(mode);monkeypatch.setattr(k8s,'_new_api',lambda auth:api)
    snapshot=collect_snapshot({'connector':{'provider':'k8s','scopes':['*'],
        'auth':{'cluster_id':C,'server':api.server},'options':options()if opt is None else opt},'checks':[CHECK]})
    report=evaluate_snapshot(snapshot,checks=[CHECK])
    status={f['status']for f in report['findings']if f['check_id']==CHECK}
    return snapshot,report,status,api

@pytest.mark.parametrize('delta,expected',[(0,'PASS'),(10,'FAIL'),(2,'UNKNOWN')])
def test_external_public_pipeline_interval_and_provenance(monkeypatch,delta,expected):
    opt=options(delta);before=deepcopy(opt);s,r,status,api=run(monkeypatch,opt)
    assert status=={expected};assert opt==before
    assert {p for p,_ in api.calls}=={'/api/v1/nodes','/api/v1/namespaces'}
    row=next(c for c in s['collections']if c['type']=='node_clock')['items'][0]
    assert row['source_operation']==external.SOURCE
    assert 'node_response_verified'not in row and'trusted_clock_verified'not in row
    assert row['provenance']['native_clock_verified']is False
    if expected!='UNKNOWN':
        evidence=next(f['evidence']for f in r['findings']if f['check_id']==CHECK)
        assert evidence['native_clock_verified']is False
        assert evidence['external_authenticity_independently_verified']is False

@pytest.mark.parametrize('mode',['missing','stale','future','foreign_uid','foreign_cluster','unreviewed','duplicate'])
def test_unavailable_external_measurements_unknown(monkeypatch,mode):
    opt=options();raw=opt[external.OPTION]
    if mode=='missing':opt.pop(external.OPTION)
    elif mode in('stale','future'):
        raw['observations'][0]['measured_at']=(datetime.now(timezone.utc)+timedelta(seconds=300 if mode=='future'else -300)).isoformat()
    elif mode=='foreign_uid':raw['observations'][0]['node_uid']='foreign'
    elif mode=='foreign_cluster':raw['review']['kube_system_uid']='foreign'
    elif mode=='unreviewed':raw['observations'][0]['observer_id']='unapproved'
    else:raw['observations'].append(deepcopy(raw['observations'][0]))
    assert run(monkeypatch,opt)[2]=={'UNKNOWN'}

@pytest.mark.parametrize('mode',['denied','partial','replacement'])
def test_native_identity_incomplete_or_changed_unknown(monkeypatch,mode):
    assert run(monkeypatch,mode=mode)[2]==({'DENIED'}if mode=='denied'else{'UNKNOWN'})

@pytest.mark.parametrize('field,value',[('uncertainty_seconds',True),('node_response_verified',True),
    ('trusted_clock_verified',True),('source_operation','GET /api/v1/nodes/{name}/proxy/healthz')])
def test_no_checkbox_or_native_provenance_laundering(monkeypatch,field,value):
    opt=options();opt[external.OPTION]['observations'][0][field]=value;calls=[]
    monkeypatch.setattr(k8s,'_new_api',lambda auth:calls.append(True))
    with pytest.raises(ValueError):k8s.collect({'auth':{},'options':opt,'scopes':['*']},requirements=['node_clock'])
    assert not calls

def test_native_node_uid_cannot_alias_two_names():
    opt=options();raw=opt[external.OPTION];row=deepcopy(raw['observations'][0]);row.update(node_name='node2',measurement_id='m-2')
    raw['observations'].append(row);raw['review']['reviewed_measurement_ids'].append('m-2')
    nodes=[{'metadata':{'name':name,'uid':UID}}for name in ('node1','node2')]
    with pytest.raises(ValueError,match='duplicate'):
        external.validate_measurements(raw['review'],raw['observations'],nodes,
            [{'metadata':{'name':'kube-system','uid':SYSTEM}}],C,datetime.now(timezone.utc).isoformat())

@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_new_clock_intake_accepts_review_and_real_skew_policy(auth_mode):
    from peaso.server.validation import validate_connector
    opt=options();opt['retries']=1;opt['compliance_policy']['system_namespaces']=['kube-system'];before=deepcopy(opt)
    auth={'method':'token','server':'https://8.8.8.8:6443','token':'INERT-NOT-CREDENTIAL','cluster_id':C}
    validate_connector('k8s',auth,opt,SimpleNamespace(auth_mode=auth_mode))
    assert opt==before

@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('mutation',['foreign_provider','forged_native_flag'])
def test_new_clock_intake_rejects_provider_and_native_checkbox(auth_mode,mutation):
    from peaso.server.validation import validate_connector
    from fastapi import HTTPException
    opt=options();provider='azure'if mutation=='foreign_provider'else'k8s'
    if mutation=='forged_native_flag':opt[external.OPTION]['observations'][0]['trusted_clock_verified']=True
    with pytest.raises(HTTPException)as error:
        validate_connector(provider,{},opt,SimpleNamespace(auth_mode=auth_mode))
    assert error.value.status_code==422


def test_new_clock_huge_integer_uncertainty_intake_422():
    from peaso.server.validation import validate_connector
    from fastapi import HTTPException
    opt=options();opt[external.OPTION]['observations'][0]['uncertainty_seconds']=1<<2048
    with pytest.raises(HTTPException)as error:
        validate_connector('k8s',{},opt,SimpleNamespace(auth_mode='cognito'))
    assert error.value.status_code==422

@pytest.mark.parametrize('skew',[True,-1])
def test_new_hosted_clock_skew_rejects_bool_and_negative(skew):
    from peaso.server.validation import validate_connector
    from fastapi import HTTPException
    opt=options();opt['compliance_policy'].update(system_namespaces=['kube-system'],approved_clock_skew=skew)
    auth={'method':'token','server':'https://8.8.8.8:6443','token':'INERT','cluster_id':C}
    with pytest.raises(HTTPException)as error:
        validate_connector('k8s',auth,opt,SimpleNamespace(auth_mode='cognito'))
    assert error.value.status_code==422
