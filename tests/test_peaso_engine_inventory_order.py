"""Native API ordering must not turn complete inventory into UNKNOWN."""
import copy
import pytest
from peaso.engine import evaluate_snapshot, _index
from peaso.snapshot import make_snapshot, resources

ACCOUNT='123456789012'
SCOPE=ACCOUNT+'/global'
POLICY='arn:aws:iam::aws:policy/ReadOnlyAccess'
CHECK='aws.pci.iam.role_required_managed_policies'

def snapshot(names=('z-role','a-role'),status='collected'):
 rows=[{'Arn':f'arn:aws:iam::{ACCOUNT}:role/{name}','RoleName':name,'AccountId':ACCOUNT,
        'AttachedManagedPolicies':[{'PolicyArn':POLICY}]}for name in names]
 return make_snapshot('aws',[SCOPE],[{'type':'iam_role','scope':SCOPE,'service':'iam','status':status,
  'global':True,'account_id':ACCOUNT,'items':rows if status in ('collected','partial')else[]}],
  metadata={'compliance_policy':{'status':'collected','scope':SCOPE,'required_policy_arns':[POLICY]}})

@pytest.mark.parametrize('names',[('z-role','a-role'),('a-role','z-role'),('z-role','middle-role','a-role')])
def test_real_registered_predicate_uses_exact_native_inventory_order(names):
 source=snapshot(names);before=copy.deepcopy(source)
 report=evaluate_snapshot(source,checks=[CHECK])
 assert len(report['findings'])==len(names) and all(row['status']=='PASS'for row in report['findings'])
 index=_index(source,resources(source))
 assert [row['data']['RoleName']for row in index['iam_role']]==list(names)
 assert source==before

def test_sorting_public_resources_remains_deterministic_and_does_not_change_native_rows():
 source=snapshot();inventory=resources(source)
 assert [row['data']['RoleName']for row in inventory]==['a-role','z-role']
 _index(source,inventory)
 assert [row['data']['RoleName']for row in inventory]==['a-role','z-role']

def test_real_negative_managed_policy_stays_a_failure():
 source=snapshot();source['collections'][0]['items'][0]['AttachedManagedPolicies']=[]
 source=make_snapshot('aws',source['scopes'],source['collections'],metadata=source['metadata'])
 report=evaluate_snapshot(source,checks=[CHECK])
 assert sorted(row['status']for row in report['findings'])==['FAIL','PASS']

@pytest.mark.parametrize('status',['partial','denied','not_collected'])
def test_reordering_never_certifies_unavailable_inventory(status):
 report=evaluate_snapshot(snapshot(status=status),checks=[CHECK])
 assert all(row['status']not in ('PASS','FAIL')for row in report['findings'])

def test_duplicate_identity_still_fails_complete_inventory_count_guard():
 report=evaluate_snapshot(snapshot(('same','same')),checks=[CHECK])
 assert report['findings'] and all(row['status']=='UNKNOWN'for row in report['findings'])

def test_foreign_account_role_still_fails_subject_authority_guard():
 source=snapshot();source['collections'][0]['items'][0]['Arn']='arn:aws:iam::999999999999:role/foreign'
 source=make_snapshot('aws',source['scopes'],source['collections'],metadata=source['metadata'])
 findings=evaluate_snapshot(source,checks=[CHECK])['findings']
 assert any(row['status']=='UNKNOWN'for row in findings)
