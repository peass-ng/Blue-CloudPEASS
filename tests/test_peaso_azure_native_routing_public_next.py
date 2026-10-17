"""Public collection regressions for previously omitted inventory kinds."""
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure
SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
@pytest.mark.parametrize('kind',['diagnostic_setting','directory_membership','subnet_effective_route'])
def test_empty_native_requested_inventory_is_not_silently_omitted(kind):
    calls=[]
    class Transport:
        tenant=verified_tenant=TENANT
        def request(self,url,*,body=None,audience=azure.ARM):
            path=urlsplit(url).path
            calls.append(path)
            assert 'effectiveRouteTable' not in path
            if path=='/subscriptions':return {'value':[{'id':SCOPE,'subscriptionId':SCOPE.rsplit('/',1)[1],'tenantId':TENANT,'state':'Enabled'}]}
            if path==SCOPE:return {'id':SCOPE,'subscriptionId':SCOPE.rsplit('/',1)[1],'tenantId':TENANT,'state':'Enabled'}
            if path=='/providers/Microsoft.ResourceGraph/resources':return {'data':[],'resultTruncated':False}
            return {'value':[]}
    snapshot=azure.collect({'scopes':[SCOPE],'options':{'retries':0,'concurrency':1,'max_calls':100}},[kind],transport=Transport())
    children=[c for c in snapshot['collections'] if c['type']==kind]
    assert len(children)==1,snapshot['collections']
    if kind=='subnet_effective_route':
        assert children[0]['status'] not in ('collected','empty')
        assert calls==[]
    else:assert children[0]['status']=='empty'
    assert children[0]['items']==[]
