"""Offline selected-image database admission, using normal package imports."""
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from peaso.collectors import selected_image_trivy_database_20261021 as db
from peaso.collectors import k8s_selected_registry_image_20261021 as k8s_image
from peaso.collectors import azure_selected_aks_image_20261021 as aks_image
from peaso.collectors import gcp_gke_selected_pod_image_20261021 as gke_image
from peaso.collectors import gcp_appengine_flex_image_runtime_20261021 as flex


class Lease:
    def __init__(self, events, fail=False):
        self.events, self.fail = events, fail
    @contextmanager
    def __call__(self, *, enabled):
        assert enabled is True
        self.events.append('enter')
        if self.fail:
            raise db.DatabaseUnavailable('stale database')
        try:
            yield Path('/trusted/trivy/generation')
        finally:
            self.events.append('exit')


def test_trusted_lease_lifecycle_failure_disabled_and_cancel(monkeypatch):
    events=[]
    monkeypatch.setattr(db, 'database_lease', Lease(events))
    with ExitStack() as stack:
        assert db.acquire(stack, enabled=False, cancel=lambda: events.append('cancel')) is None
        assert events == []
        cache=db.acquire(stack, enabled=True, cancel=lambda: events.append('cancel'))
        assert cache == Path('/trusted/trivy/generation')
        assert events == ['cancel','enter','cancel']
    assert events[-1] == 'exit'
    events.clear()
    monkeypatch.setattr(db, 'database_lease', Lease(events, fail=True))
    with ExitStack() as stack:
        assert db.acquire(stack, enabled=True, cancel=lambda: None) is None
    assert events == ['enter']
    events.clear()
    with pytest.raises(RuntimeError, match='cancelled'):
        with ExitStack() as stack:
            db.acquire(stack, enabled=True, cancel=lambda: (_ for _ in ()).throw(RuntimeError('cancelled')))
    assert events == []
    monkeypatch.setattr(db, 'database_lease', Lease(events))
    checks=[0]
    def cancelled_after_acquire():
        checks[0]+=1
        if checks[0]==2:
            raise RuntimeError('cancelled')
    with pytest.raises(RuntimeError, match='cancelled'):
        with ExitStack() as stack:
            db.acquire(stack, enabled=True, cancel=cancelled_after_acquire)
    assert events == ['enter','exit']


@pytest.mark.parametrize('module,call', [
    (k8s_image, lambda mod, opts: mod.selected_targets(opts, ['default'], [])),
    (aks_image, lambda mod, opts: mod.selected_targets(opts, [], [])),
    (flex, lambda mod, opts: mod.validate_request({'provider':'gcp','options':opts,'scopes':[]}, {'checks':[]})),
])
def test_request_cannot_choose_database_or_executable(module, call):
    for key in ('trivy_db_cache', 'trivy_cli'):
        with pytest.raises((ValueError, k8s_image.Incomplete)):
            call(module, {key:'/user/controlled/path'})


def test_k8s_collect_lease_once_secret_survives_rejected_db(monkeypatch):
    from peaso.collectors import k8s_selected_log_sample_secret_indicators as native
    target={'cluster_id':'cluster.example','namespace':'default','pod':'pod-a','uid':'poduid',
            'resource_version':'42','container_type':'regular','container_name':'app',
            'image':'ghcr.io/owned/demo@sha256:'+'a'*64}
    monkeypatch.setattr(k8s_image, 'selected_targets', lambda options, scopes, named: [target,target])
    monkeypatch.setattr(k8s_image, 'registry_credentials', lambda *a, **kw: {})
    monkeypatch.setattr(k8s_image, 'enabled', lambda *a: (True,True))
    pool=SimpleNamespace(literal_paths=frozenset())
    client=SimpleNamespace(last_response='old')
    monkeypatch.setattr(native, '_context', lambda *a: (client,pool,None,None,None))
    calls=[]
    def inspect(target, pod_get, **kw):
        calls.append((kw['trivy_enabled'],kw['trivy_db'],kw['secret_enabled']))
        return {'complete':True,'leaks':[{'fingerprint':'a'*64}], 'vulnerability':None}
    monkeypatch.setattr(k8s_image, 'inspect', inspect)
    events=[]
    monkeypatch.setattr(db, 'database_lease', Lease(events,fail=True))
    reader=SimpleNamespace(budget=SimpleNamespace(max_items=None),total=0,collections=[],
                           check_cancelled=lambda: None)
    opts={k8s_image.ALLOWLIST:['ghcr.io'],'_registry_image_named_checks':[
        k8s_image.SECRET_CHECK,k8s_image.VULN_CHECK]}
    metadata,matches=k8s_image.collect(reader,object(),opts,['default'],'cluster.example',{})
    assert events==['enter'] and calls==[(False,None,True)]*2
    assert {c['type'] for c in reader.collections}=={k8s_image.SECRET_KIND,k8s_image.VULN_KIND}
    assert next(c for c in reader.collections if c['type']==k8s_image.SECRET_KIND)['status']=='collected'
    assert next(c for c in reader.collections if c['type']==k8s_image.VULN_KIND)['status']=='partial'
    assert client.last_response is None and pool.literal_paths==frozenset()
    class Cancelled(Exception):
        code='collection_cancelled'
    def cancelled_inspect(target,pod_get,**kw):
        kw['redact_values']({'matched-value'})
        raise Cancelled()
    monkeypatch.setattr(k8s_image,'inspect',cancelled_inspect)
    events.clear()
    monkeypatch.setattr(db,'database_lease',Lease(events))
    with pytest.raises(Cancelled):
        k8s_image.collect(reader,object(),opts,['default'],'cluster.example',{})
    assert events==['enter','exit'] and pool.literal_paths==frozenset()


def test_flex_selected_cve_lease_cache_and_failure_preserves_secret(monkeypatch):
    target={'version_name':'apps/example/services/default/versions/v1',
            'immutable_reference':'europe-west1-docker.pkg.dev/example/repo/image@sha256:'+'a'*64}
    monkeypatch.setattr(flex.selection,'selected',lambda *a: [target])
    events=[]
    monkeypatch.setattr(db,'database_lease',Lease(events))
    captured=[]
    from peaso.collectors import gcp_registry_trivy_20261021 as trivy_source
    from peaso.checks import gcp_registry_trivy_review_20261021 as review
    def scan(transport, **kw):
        captured.append((events[:],kw['db_cache']))
        return {'rows':[{'scan':{},'complete':False,'source_requests':[]}],'source_requests':[]}
    monkeypatch.setattr(trivy_source,'collect_native',scan)
    monkeypatch.setattr(review,'project',lambda *a: {'scan':{}})
    monkeypatch.setattr(review,'evaluate',lambda *a: ('UNKNOWN',{}))
    monkeypatch.setattr(flex.native,'bind_version',lambda target,raw:{'version':'v1'})
    monkeypatch.setattr(flex.native,'requests_for',lambda target,scope:[('project','fields'),('repository','fields'),('image','fields')])
    monkeypatch.setattr(flex.native,'bind_registry',lambda target,scope,bodies:{'owner':'bound'})
    monkeypatch.setattr(flex.native,'inspect_image',lambda *a,**kw:{'complete':True,
        'leaks':[{'fingerprint':'a'*64}]})
    def native_collect(transport, **kw):
        capture=SimpleNamespace(captures=[],records=[],get=lambda *a:{'stable':'native'})
        reader=SimpleNamespace(request_ids=[])
        row=flex.native.inspect_selected(target,kw['scope'],version_get=kw['version_get'],
            capture=capture,reader=reader,secret_enabled=kw['secret_enabled'],
            vuln_enabled=kw['vuln_enabled'],trivy_collect=kw['trivy_collect'])
        return {'rows':[row], 'source_requests':[]}
    monkeypatch.setattr(flex.native,'collect_native',native_collect)
    collector=SimpleNamespace(options={flex.selection.ENABLE_SECRET:True,flex.selection.ENABLE_VULN:True,
        '_appengine_flex_image_named_checks':[flex.selection.SECRET_CHECK,flex.selection.VULN_CHECK]},
        requested_scopes=['projects/example'],needed={flex.selection.SECRET_KIND,flex.selection.VULN_KIND},
        max_items=None,total_items=0,collections={},read_time='now',
        transport=SimpleNamespace(check_cancelled=lambda:None),remember_selected_image_matches=lambda *a:None,
        read=lambda *a,**kw: ({'name':'stable'},'version-ref'))
    flex.collect(collector)
    assert events==['enter','exit'] and captured==[(['enter'],Path('/trusted/trivy/generation'))], {key:collector.collections[(flex.selection.SECRET_KIND,'projects/example')]['items'][0][flex.MARKER]['row'][key] for key in ('version_source_requests','declaration','content','vulnerability','reason')}
    assert collector.collections[(flex.selection.SECRET_KIND,'projects/example')]['items'][0][flex.MARKER]['row']['status']=='FAIL'
    events.clear(); captured.clear()
    monkeypatch.setattr(db,'database_lease',Lease(events,fail=True))
    collector.collections={};collector.total_items=0
    flex.collect(collector)
    assert events==['enter'] and captured==[]
    row=collector.collections[(flex.selection.SECRET_KIND,'projects/example')]['items'][0][flex.MARKER]['row']
    assert row['status']=='FAIL' and row['vulnerability']['status']=='UNKNOWN'


def test_aks_runtime_holds_one_cache_through_selected_scan(monkeypatch):
    from peaso.collectors import k8s, k8s_selected_log_sample_secret_indicators as native
    rid='/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks'
    scope=rid.split('/resourceGroups/')[0].casefold()
    target={'cluster_id':rid,'namespace':'default','pod':'pod-a','uid':'uid','resource_version':'42',
            'container_type':'regular','container_name':'app','image':'ghcr.io/owned/demo@sha256:'+'a'*64}
    monkeypatch.setattr(aks_image,'selected_targets',lambda *a:[target])
    monkeypatch.setattr(aks_image.aks,'normalize',lambda *a:(None,{rid.casefold():{'server':'https://aks.example','ca_cert_data':'fake-ca','token':'fake-token'}}))
    monkeypatch.setattr(aks_image.image,'registry_credentials',lambda *a,**kw:{})
    monkeypatch.setattr(k8s,'_new_api',lambda *a:object())
    pool=SimpleNamespace(literal_paths=frozenset())
    monkeypatch.setattr(native,'_context',lambda *a:(None,pool,None,None,None))
    events=[];calls=[]
    monkeypatch.setattr(db,'database_lease',Lease(events))
    def inspect(target,**kw):
        calls.append((events[:],kw['trivy_db'],kw['trivy_enabled']))
        return {'image':{'complete':True,'vulnerability':{'complete':True}},
                'arm_before':{'id':rid},'arm_after':{'id':rid}}
    monkeypatch.setattr(aks_image,'inspect_selected',inspect)
    reader=SimpleNamespace(budget=SimpleNamespace(max_items=None),total=0,collections=[
        {'type':'subscription','scope':scope,'status':'collected','items':[{'id':scope,'tenantId':'tenant'}]}],
        check_cancelled=lambda:None)
    transport=SimpleNamespace(verified_tenant='tenant')
    options={'content_secret_scans':True,'image_vulnerability_scans':True,
             '_azure_aks_image_named_checks':[aks_image.CHECK,aks_image.VULN_CHECK],
             aks_image.image.ALLOWLIST:['ghcr.io']}
    aks_image.collect(reader,lambda *a:None,transport,[scope],{aks_image.KIND,aks_image.VULN_KIND},options,{})
    assert events==['enter','exit']
    assert calls==[(['enter'],Path('/trusted/trivy/generation'),True)]
    assert {c['type'] for c in reader.collections if c['type']!= 'subscription'}=={aks_image.KIND,aks_image.VULN_KIND}
    assert pool.literal_paths==frozenset()


def test_gke_runtime_holds_one_cache_and_rejects_user_paths(monkeypatch):
    rid='projects/demo-project/locations/us-central1/clusters/cluster-a'
    target={'cluster_id':rid,'namespace':'default','pod':'pod-a','uid':'uid','resource_version':'42',
            'container_type':'regular','container_name':'app','image':'ghcr.io/owned/demo@sha256:'+'a'*64}
    monkeypatch.setattr(gke_image.selection,'selected',lambda *a:[target])
    monkeypatch.setattr(gke_image.selection,'kubernetes_auth',lambda *a:{rid:{'server':'https://gke.example'}})
    monkeypatch.setattr(gke_image.image,'registry_credentials',lambda *a,**kw:{})
    events=[];calls=[]
    monkeypatch.setattr(db,'database_lease',Lease(events))
    def inspect(target,**kw):
        calls.append((events[:],kw['trivy_db'],kw['trivy_enabled']))
        return {'image':{'complete':True,'vulnerability':{'complete':True}},
                'gke_before':{'id':rid},'gke_after':{'id':rid}}
    monkeypatch.setattr(gke_image,'inspect_selected',inspect)
    collector=SimpleNamespace(options={'content_secret_scans':True,'image_vulnerability_scans':True,
        '_gke_image_named_checks':[gke_image.selection.SECRET_CHECK,gke_image.selection.VULN_CHECK],
        gke_image.selection.HOSTS:['ghcr.io']},auth={},requested_scopes=['projects/demo-project'],
        needed={gke_image.SECRET_KIND,gke_image.VULN_KIND},max_items=None,total_items=0,
        collections={},transport=SimpleNamespace(check_cancelled=lambda:None),read_time='now')
    gke_image.collect(collector)
    assert events==['enter','exit']
    assert calls==[(['enter'],Path('/trusted/trivy/generation'),True)]
    assert {kind for kind,scope in collector.collections}=={gke_image.SECRET_KIND,gke_image.VULN_KIND}
    for key in ('trivy_cli','trivy_db_cache'):
        collector.options[key]='/user/path';events.clear()
        with pytest.raises(ValueError,match='trivy_runtime_configuration'):
            gke_image.collect(collector)
        assert events==[]
        del collector.options[key]


def test_default_off_collectors_never_acquire_database(monkeypatch):
    events=[]
    monkeypatch.setattr(db,'database_lease',Lease(events))
    monkeypatch.setattr(k8s_image,'selected_targets',lambda *a:[])
    monkeypatch.setattr(k8s_image,'registry_credentials',lambda *a,**kw:{})
    monkeypatch.setattr(k8s_image,'enabled',lambda *a:(False,False))
    k8s_image.collect(SimpleNamespace(),object(),{},['default'],'cluster.example',{})
    assert aks_image.collect(object(),object(),object(),[],set(),{}, {}) is None
    monkeypatch.setattr(gke_image.selection,'selected',lambda *a:[])
    gke_image.collect(SimpleNamespace(options={},auth={},requested_scopes=[],needed=set()))
    monkeypatch.setattr(flex.selection,'selected',lambda *a:[])
    flex.collect(SimpleNamespace(options={},requested_scopes=[],needed=set()))
    assert events==[]


def test_ecr_public_failed_db_still_runs_secret_native_collection(monkeypatch):
    from peaso.collectors import aws_ecr_public_image_runtime_20261021 as ecr
    from peaso.collectors.aws import ReadResult
    events=[];calls=[]
    monkeypatch.setattr(db,'database_lease',Lease(events,fail=True))
    from peaso.collectors import aws_ecr_public_image_native_20261021 as native
    target={'scope':'123456789012/us-east-1'}
    def collect_native(requests,session,identity,region,targets,**kwargs):
        calls.append(kwargs)
        return ReadResult([{'id':'selected-image','ECRPublicImageContent':{
            'leaks':[{'fingerprint':'a'*64}],'secret_complete':True,
            'vulnerability':None,'native_stable':True}}], 'collected')
    monkeypatch.setattr(native,'collect_scope',collect_native)
    requests=SimpleNamespace(check_deadline=lambda:None)
    result=ecr.collect_scope(requests,object(),{'Account':'123456789012'},'us-east-1',[target],secret=True,vuln=True)
    assert events==['enter'] and len(calls)==1
    assert calls[0]=={'secret_enabled':True,'vuln_enabled':False,'trivy_db':None}
    assert result.status=='partial' and result.error=={'code':'trivy_database_unavailable'}
    assert result.items[0]['ECRPublicImageContent']['leaks']==[{'fingerprint':'a'*64}]
    events.clear();calls.clear()
    result=ecr.collect_scope(requests,object(),{'Account':'123456789012'},'us-east-1',[target],secret=True,vuln=False)
    assert events==[] and calls[0]['secret_enabled'] is True and calls[0]['vuln_enabled'] is False
