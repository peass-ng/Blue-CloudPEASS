"""Subscription checks can consume Graph facts only from their verified capture."""
import copy
import pytest
from peaso.checks import Check
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks.facts import complete_items

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'

def facts():
 metadata={'tenant_verified':True,'tenant_id':TENANT,'credential_context_id':'capture-1',
  'customer_context_id':'customer-1','subscription_tenants':{SCOPE:TENANT}}
 proof={k:metadata[k]for k in ('tenant_verified','tenant_id','credential_context_id','customer_context_id')}
 row={'id':'user-1','_provenance':{'tenant_verified':True,'tenant_id':TENANT}}
 envelope={'type':'directory_user','scope':'/tenants/'+TENANT,'service':'Microsoft.Graph',
  'status':'collected','items':[row],'_provenance':proof}
 return metadata,envelope

def run(monkeypatch,metadata,envelope):
 def predicate(item,index):
  rows=complete_items(index,'directory_user')
  return ('PASS'if len(rows)==1 else 'FAIL'),{'count':len(rows)}
 check=Check('azure.test.directory_binding','azure','hardening','subscription','Directory binding',
  'medium','AC-2','Review',predicate,'scope',('directory_user',))
 monkeypatch.setattr('peaso.engine._registry',lambda:[check])
 snapshot=make_snapshot('azure',[SCOPE],[envelope],metadata=metadata)
 before=copy.deepcopy(snapshot)
 report=evaluate_snapshot(snapshot,categories=['hardening'],checks=[check.id])
 assert snapshot==before
 return report['findings'][0]['status']

def test_current_customer_and_tenant_directory_facts_are_visible_to_subscription(monkeypatch):
 metadata,envelope=facts()
 assert run(monkeypatch,metadata,envelope)=='PASS'

@pytest.mark.parametrize('mutation',['tenant','capture','customer','unverified','item_tenant','subscription','service','fake_subscription_scope'])
def test_other_tenants_and_captures_cannot_join(monkeypatch,mutation):
 metadata,envelope=facts()
 if mutation=='tenant':envelope['_provenance']['tenant_id']='other'
 if mutation=='capture':envelope['_provenance']['credential_context_id']='capture-old'
 if mutation=='customer':envelope['_provenance']['customer_context_id']='customer-other'
 if mutation=='unverified':metadata['tenant_verified']=False
 if mutation=='item_tenant':envelope['items'][0]['_provenance']['tenant_id']='other'
 if mutation=='subscription':metadata['subscription_tenants']={SCOPE:'other'}
 if mutation=='service':envelope['service']='unverified'
 if mutation=='fake_subscription_scope':envelope['scope']=SCOPE
 assert run(monkeypatch,metadata,envelope)=='UNKNOWN'

@pytest.mark.parametrize('status',['denied','partial','not_collected'])
def test_join_does_not_override_unavailable_directory_read(monkeypatch,status):
 metadata,envelope=facts();envelope.update(status=status,items=[])
 assert run(monkeypatch,metadata,envelope) in ('UNKNOWN','DENIED')
