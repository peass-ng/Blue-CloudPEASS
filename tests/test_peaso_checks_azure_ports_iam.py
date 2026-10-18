"""Declared control/data exclusions and same-scope complete role/policy metadata."""
import copy,json
from pathlib import Path
import pytest
from peaso.checks import CHECKS,azure_ports_iam as ports
from peaso.checks.fixtures import CASES
ROOT=Path(__file__).resolve().parent.parent
REVIEWS=json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_iam.json').read_text())
REGISTRY={c.id:c for c in CHECKS}


@pytest.mark.parametrize('cid',ports.CHECK_IDS)
def test_iam_metadata_pass_fail_missing_denied_malformed_and_purity(cid):
    f=CASES[cid]
    for label,want in (('pass','PASS'),('fail','FAIL')):
        item,index=copy.deepcopy(f[label]),copy.deepcopy(f.get(label+'_index',{}));before=copy.deepcopy((item,index))
        assert REGISTRY[cid].evaluate(item,index)[0]==want
        assert (item,index)==before
    for item in ({},None,[],{'collection_status':'denied'},{'collection_status':'partial'}):assert REGISTRY[cid].evaluate(item,{})[0]=='UNKNOWN'


def test_wildcard_declaration_is_not_effectiveowner_notactions_notdeny_and_dataplane_separate():
    check=REGISTRY[ports.SOURCE_QUERIES['iam_no_custom_subscription_owner_roles_created']]
    item={'scope':'/subscriptions/sub'}
    role=ports._role(['*']);role['properties']['permissions'][0]['notActions']=['*']
    assert check.evaluate(item,ports._index([role]))[0]=='FAIL'
    role['properties']['permissions'][0].update(actions=['Microsoft.Compute/*'],dataActions=['*'])
    assert check.evaluate(item,ports._index([role]))[0]=='PASS'
    role['properties']['permissions'][0]['actions']=['*:*']
    assert check.evaluate(item,ports._index([role]))[0]=='FAIL'
    role['properties']['roleType']='BuiltInRole'
    assert check.evaluate(item,ports._index([role]))[0]=='PASS'
    assert check.evaluate(item,ports._index([]))[0]=='PASS'
    assert check.evaluate({'scope':'/tenants/tenant'},ports._index([role]))[0]=='NOT_APPLICABLE'


def test_authoritative_subscription_envelope_guard_preserves_inherited_roleid_and_denial():
    check=REGISTRY[ports.SOURCE_QUERIES['iam_no_custom_subscription_owner_roles_created']]
    role=ports._role(['*']);role['id']='/providers/Microsoft.Management/managementGroups/group/providers/Microsoft.Authorization/roleDefinitions/role'
    index=ports._index([role])
    assert check.evaluate({'scope':'/subscriptions/sub'},index)[0]=='FAIL'
    index['collections']['role_definition'][0]['scope']='/subscriptions/foreign'
    assert check.evaluate({'scope':'/subscriptions/sub'},index)[0]=='UNKNOWN'
    index['collections']['role_definition'][0]['scope']='/subscriptions/sub'
    for state in ('denied','partial','malformed'):
        index['collections']['role_definition'][0]['status']=state
        assert check.evaluate({'scope':'/subscriptions/sub'},index)[0]=='UNKNOWN'


def test_tenant_transfer_both_booleans_required_foreign_and_missing_context_unknown():
    check=REGISTRY[ports.SOURCE_QUERIES['iam_subscription_tenant_transfer_restricted']]
    item=copy.deepcopy(CASES[check.id]['pass'])
    for into,leaving,want in ((True,True,'PASS'),(True,False,'FAIL'),(False,True,'FAIL'),(False,False,'FAIL')):
        item['properties'].update(blockSubscriptionsIntoTenant=into,blockSubscriptionsLeavingTenant=leaving)
        assert check.evaluate(item,{})[0]==want
    assert check.evaluate(item,{'context':{'metadata':{'tenant_id':'foreign'}}})[0]=='UNKNOWN'
    item['properties'].pop('blockSubscriptionsLeavingTenant')
    assert check.evaluate(item,{})[0]=='UNKNOWN'


def test_pinned_declared_wildcard_selectors_and_conjunctive_policy_truth_are_exact():
    duckdb=pytest.importorskip('duckdb')
    with duckdb.connect(':memory:') as db:
        assert db.execute("SELECT role_type='CustomRole' AND action IN ('*','*:*') FROM (SELECT 'CustomRole' AS role_type, '*' AS action)").fetchone()[0] is True
        assert db.execute('SELECT into_tenant AND leaving_tenant FROM (SELECT TRUE AS into_tenant,FALSE AS leaving_tenant)').fetchone()[0] is False
    claude=set(json.loads((ROOT/'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS)==11 and not set(REVIEWS)&claude
    assert all(r['source_review']['arguments']==[] and r['source_review']['pinned_sql'] for r in REVIEWS.values())
