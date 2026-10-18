"""Tenant administrative values require real unique policy context; no missing defaults."""
import copy,json,re
from pathlib import Path
import pytest
from peaso.checks import CHECKS,azure_ports_directory_extra as ports
from peaso.checks.fixtures import CASES

ROOT=Path(__file__).resolve().parent.parent
REVIEWS=json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_directory_extra.json').read_text())
REGISTRY={c.id:c for c in CHECKS}


@pytest.mark.parametrize('cid',ports.CHECK_IDS)
def test_known_policy_pass_fail_missing_denied_partial_malformed_and_purity(cid):
    f=CASES[cid]
    for label,want in (('pass','PASS'),('fail','FAIL')):
        item,index=copy.deepcopy(f[label]),copy.deepcopy(f.get(label+'_index',{}));before=copy.deepcopy((item,index))
        assert REGISTRY[cid].evaluate(item,index)[0]==want
        assert (item,index)==before
    for item in ({},None,[],{'collection_status':'denied'},{'collection_status':'partial'}):assert REGISTRY[cid].evaluate(item,{})[0]=='UNKNOWN'


@pytest.mark.parametrize('query',list(ports.SOURCE_QUERIES)[:4])
def test_admin_setting_scope_empty_denied_duplicate_foreign_and_native_constraints_unknown(query):
    check=REGISTRY[ports.SOURCE_QUERIES[query]];f=CASES[check.id]
    index=copy.deepcopy(f['pass_index']);row=index['directory_setting'][0]['data'];entry=row['values'][0]
    assert check.evaluate({'scope':'/subscriptions/sub'},index)[0]=='NOT_APPLICABLE'
    row['values']=[]
    assert check.evaluate(f['pass'],index)[0]=='UNKNOWN'
    row['values']=[entry,copy.deepcopy(entry)]
    assert check.evaluate(f['pass'],index)[0]=='UNKNOWN'
    row['values']=[entry];row['_provenance']['tenant_id']='foreign'
    assert check.evaluate(f['pass'],index)[0]=='UNKNOWN'
    row['_provenance']['tenant_id']='tenant'
    for value in ('',None,'bad'):
        entry['value']=value
        assert check.evaluate(f['pass'],index)[0]=='UNKNOWN'
    for state in ('denied','partial','malformed','empty'):
        broken=copy.deepcopy(f['pass_index']);broken['collections']['directory_setting'][0]['status']=state
        if state=='empty':broken['directory_setting']=[]
        assert check.evaluate(f['pass'],broken)[0]=='UNKNOWN'


def test_registration_upn_scope_and_capability_does_not_substitute_registration():
    check=REGISTRY[ports.SOURCE_QUERIES['ad_user_mfa_enabled']]
    item=copy.deepcopy(CASES[check.id]['pass']);item['userPrincipalName']=None
    assert check.evaluate(item,{})[0]=='NOT_APPLICABLE'
    item=copy.deepcopy(CASES[check.id]['pass']);item.pop('isMfaRegistered');item['isMfaCapable']=True
    assert check.evaluate(item,{})[0]=='UNKNOWN'
    item['_provenance']['tenant_id']='foreign'
    assert check.evaluate(item,{'context':{'metadata':{'tenant_id':'tenant'}}})[0]=='UNKNOWN'


def test_pinned_admin_value_case_truth_and_exact_source_ownership():
    duckdb=pytest.importorskip('duckdb')
    queryvals={'ad_m365_group_creation_disabled':('false','true'),'ad_custom_banned_password_enforced':('true','false'),'ad_account_duration_min_60_seconds':('60','59'),'ad_account_lockout_threshold_max_10':('10','11')}
    for row in REVIEWS.values():
        q=row['source_review']['query_id']
        if q not in queryvals:continue
        case=row['source_review']['status_case_sql'][0]
        case=case.replace('(value)::bool','CAST(value AS BOOLEAN)').replace('(value)::int','CAST(value AS INTEGER)')
        with duckdb.connect(':memory:') as db:
            assert db.execute('SELECT '+case+' FROM (SELECT ? AS value)',[queryvals[q][0]]).fetchone()[0]=='ok'
            assert db.execute('SELECT '+case+' FROM (SELECT ? AS value)',[queryvals[q][1]]).fetchone()[0]=='alarm'
    claude=set(json.loads((ROOT/'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS)==11 and not set(REVIEWS)&claude
