"""Subscription MFA must cover delegated readers as well as tenant users."""
import copy
import json
from pathlib import Path
import pytest
from peaso.checks import evaluate_check

CID='azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled'
BASE=json.loads((Path(__file__).parent/'fixtures/bulk_pending_behavior.json').read_text())[CID]
FIELDS=('directRoleAssignments','inheritedGrants','transitiveGroups','activePim',
        'conditionalGrants','lighthouseDelegations','managedApplicationAccess','principalClassification')
def case(failing=False):
    name='fail' if failing else 'pass'
    return copy.deepcopy(BASE[name]),copy.deepcopy(BASE[name+'_index'])
def coverage(index):
    scope=index['context']['scope']; tenant=index['context']['metadata']['tenant_id']
    proof={'scope':scope,'managedTenantId':tenant,'delegatedTenantIds':[],
        'principal_ids':[x['data']['id'] for x in index['entra_user']],
        'observed_at':index['context']['created_at'],
        '_provenance':{'read_only':True,'source_operation':'subscription_effective_principal_universe_read'},
        'resolution':{key:'complete' for key in FIELDS},'source_evidence_ids':['independent-principal-universe']}
    index['collections']['entra_user'][0]['scopeCoverage']=proof
    return proof

def test_known_delegated_reader_outside_local_roster_cannot_be_certified():
    item,index=case(); proof=coverage(index)
    proof['delegatedTenantIds']=['unobserved-managing-tenant']
    proof['principal_ids'].append('foreign-reader')
    assert evaluate_check(CID,item,index)[0]=='UNKNOWN'

def test_missing_global_reader_universe_is_unknown():
    item,index=case();index['collections']['entra_user'][0].pop('scopeCoverage',None)
    assert evaluate_check(CID,item,index)[0]=='UNKNOWN'

def test_current_complete_nondelegated_reader_universe_passes():
    item,index=case();coverage(index)
    assert evaluate_check(CID,item,index)[0]=='PASS'

@pytest.mark.parametrize('damage',['foreignscope','future','stale','duplicate','tenant','delegation','readonly','capture'])
def test_principal_universe_authority_and_projection_boundaries(damage):
    item,index=case();proof=coverage(index)
    if damage=='foreignscope':proof['scope']='/subscriptions/foreign'
    elif damage=='future':proof['observed_at']='2099-01-01T00:00:00Z'
    elif damage=='stale':proof['observed_at']='2000-01-01T00:00:00Z'
    elif damage=='duplicate':proof['principal_ids']*=2
    elif damage=='tenant':proof['managedTenantId']='foreign-tenant'
    elif damage=='delegation':proof['resolution']['lighthouseDelegations']='missing'
    elif damage=='readonly':proof['_provenance']['read_only']=False
    else:proof['_provenance']['customer_context_id']='another-customer'
    assert evaluate_check(CID,item,index)[0]=='UNKNOWN'

def test_local_verified_mfa_violation_survives_unavailable_global_universe():
    item,index=case(True);index['collections']['entra_user'][0].pop('scopeCoverage',None)
    assert evaluate_check(CID,item,index)[0]=='FAIL'

@pytest.mark.parametrize('complete',[False,True])
def test_empty_tenant_roster_requires_complete_subscription_universe(complete):
    item,index=case(); index['entra_user']=[]
    env=index['collections']['entra_user'][0];env.update(status='empty',items=[])
    env.pop('scopeCoverage',None)
    if complete:coverage(index)
    assert evaluate_check(CID,item,index)[0]==('NOT_APPLICABLE' if complete else 'UNKNOWN')

@pytest.mark.parametrize('delegated',[False,True])
def test_snapshot_engine_preserves_complete_principal_universe(delegated):
    from peaso.snapshot import make_snapshot
    from peaso.engine import evaluate_snapshot
    _,index=case();proof=coverage(index)
    if delegated:
        proof['principal_ids'].append('foreign-reader')
        proof['delegatedTenantIds']=['managing-tenant']
    envs=[env for values in index['collections'].values() for env in values]
    snap=make_snapshot('azure',[index['context']['scope']],envs,
        created_at=index['context']['created_at'],metadata=index['context']['metadata'])
    findings=[f for f in evaluate_snapshot(snap,checks=[CID],include_not_applicable=True)['findings'] if f['check_id']==CID]
    assert len(findings)==1
    assert findings[0]['status']==('UNKNOWN' if delegated else 'PASS')
