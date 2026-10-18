"""Diagnostic inventory must settle absent resource children conservatively."""
from types import SimpleNamespace
import pytest
from peaso.collectors import azure
SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'

def parents():
    return [dict(type=kind,scope=SCOPE,service='azure',status='empty',items=[]) for kind in set(azure.ENDPOINTS)-azure.NO_DIAGNOSTIC_KINDS]

@pytest.mark.parametrize('state', ['empty','denied','partial','missing','nonempty','foreign'])
def test_diagnostic_completion_requires_complete_empty_parent_universe(state):
    rows=parents()
    if state=='missing': rows.pop()
    elif state=='foreign': rows[0]['scope']=SCOPE+'0'
    elif state=='nonempty': rows[0].update(status='collected',items=[{'id':SCOPE+'/resources/r'}])
    elif state!='empty': rows[0]['status']=state
    reader=SimpleNamespace(collections=rows)
    azure._complete_diagnostic_inventory(reader,[SCOPE])
    child=[c for c in reader.collections if c['type']=='diagnostic_setting']
    assert len(child)==1
    assert child[0]['status']==('empty' if state=='empty' else 'partial')
    assert child[0]['items']==[]

def test_diagnostic_completion_preserves_existing_resource_child():
    rows=parents()
    child=dict(type='diagnostic_setting',scope=SCOPE+'/resourceGroups/rg/providers/Microsoft.Web/sites/a',service='Microsoft.Insights',status='denied',items=[])
    reader=SimpleNamespace(collections=rows+[child])
    azure._complete_diagnostic_inventory(reader,[SCOPE])
    assert [c for c in reader.collections if c['type']=='diagnostic_setting']==[child]

def test_diagnostic_completion_isolates_subscriptions():
    other=SCOPE[:-1]+'2'
    rows=parents()
    reader=SimpleNamespace(collections=rows)
    azure._complete_diagnostic_inventory(reader,[SCOPE,other])
    children={c['scope']:c for c in reader.collections if c['type']=='diagnostic_setting'}
    assert children[SCOPE]['status']=='empty'
    assert children[other]['status']=='partial'

@pytest.mark.parametrize('deny_parent',[False,True])
def test_public_requested_diagnostics_has_an_envelope(deny_parent):
    from urllib.parse import urlsplit
    class Transport:
        tenant=verified_tenant='22222222-2222-2222-2222-222222222222'
        def request(self,url,*,body=None,audience=azure.ARM):
            path=urlsplit(url).path
            if path=='/subscriptions':
                return {'value':[{'id':SCOPE,'subscriptionId':SCOPE.rsplit('/',1)[1],'tenantId':self.tenant,'state':'Enabled'}]}
            if path==SCOPE:return {'id':SCOPE,'subscriptionId':SCOPE.rsplit('/',1)[1],'tenantId':self.tenant,'state':'Enabled'}
            if path=='/providers/Microsoft.ResourceGraph/resources':return {'data':[],'resultTruncated':False}
            if deny_parent and path==SCOPE+'/providers/Microsoft.Insights/logProfiles':
                raise azure.AzureReadError('fixture_denied',403)
            assert 'diagnosticSettings' not in path
            return {'value':[]}
    connector={'provider':'azure','scopes':[SCOPE],'auth':{'method':'token','arm_token':'inert-fixture'},'options':{'concurrency':1,'retries':1,'max_calls':100}}
    snapshot=azure.collect(connector,['diagnostic_setting'],transport=Transport())
    children=[c for c in snapshot['collections'] if c['type']=='diagnostic_setting']
    assert len(children)==1
    assert children[0]['scope']==SCOPE
    assert children[0]['status']==('partial' if deny_parent else 'empty'),children
