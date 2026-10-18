"""Pinned predicates are rejected for actual false conclusions, not collection gaps."""
import json,re
from pathlib import Path
from types import SimpleNamespace as NS
import pytest
ROOT=Path(__file__).resolve().parent.parent
REVIEWS=json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_invalid_tail.json').read_text())
VA=json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_invalid_va_conditions.json').read_text())
PROOFS={r['source_review']['query_id']:r['source_review'] for r in REVIEWS.values()}


@pytest.mark.parametrize('query',['ad_admin_portals_require_mfa','ad_mfa_service_mgmt_api'])
def test_mfa_presence_with_or_compliant_device_is_not_required_mfa(query):
    duckdb=pytest.importorskip('duckdb');sql=PROOFS[query]['pinned_sql']
    assert "built_in_controls @> '[1]'::jsonb" in sql and 'operator' not in sql
    policy=PROOFS[query]['counterexample']
    with duckdb.connect(':memory:') as db:
        assert db.execute("SELECT json_contains('[1,2]'::JSON, '[1]'::JSON)").fetchone()[0] is True
    assert policy['grantControls']['operator']=='OR' and policy['mfa_required'] is False


@pytest.mark.parametrize('query',['ad_require_mfa_for_device_join','iam_global_administrator_max_5'])
def test_full_source_unguarded_tenant_cross_product_copies_foreign_context(query):
    duckdb=pytest.importorskip('duckdb');sql=PROOFS[query]['pinned_sql']
    assert 'distinct_tenant as t,' in sql
    with duckdb.connect(':memory:') as db:
        if query.startswith('ad_'):
            result=db.execute("SELECT t.tenant_id,CASE WHEN p.multi_factor_auth_configuration='required' THEN 'ok' ELSE 'alarm' END FROM (VALUES ('A'),('B')) t(tenant_id),(VALUES ('A','required')) p(tenant_id,multi_factor_auth_configuration)").fetchall()
        else:
            result=db.execute("SELECT t.tenant_id,CASE WHEN json_array_length(member_ids)>=2 AND json_array_length(member_ids)<5 THEN 'ok' ELSE 'alarm' END FROM (VALUES ('A'),('B')) t(tenant_id),(VALUES ('A','[1,2,3]'::JSON)) p(tenant_id,member_ids)").fetchall()
    assert len(result)==2 and all(row[1]=='ok' for row in result)
    assert PROOFS[query]['counterexample']['required_statuses']==['ok','unknown']


@pytest.mark.parametrize('query',['aks_clusters_public_access_disabled','app_function_identity_is_configured','app_function_identity_without_admin_privileges'])
def test_actual_source_check_class_falsepasses_known_invalid_configuration(query):
    class Report:
        def __init__(self,*args,**kwargs):pass
    env={'Check':type('Check',(),{'metadata':lambda self:{}}),'Check_Report_Azure':Report}
    if query.startswith('aks'):
        cluster=NS(name='cluster',private_fqdn='private.invalid',agent_pool_profiles=[NS(enable_node_public_ip=False),NS(enable_node_public_ip=True)])
        env['aks_client']=NS(clusters={'sub':{'c':cluster}},subscriptions={})
    else:
        identity=NS(type='None') if query.endswith('configured') else NS(type='UserAssigned',principal_id=None,user_assigned_identities={'/identity':NS(principal_id='user-principal')})
        env['app_client']=NS(functions={'sub':{'f':NS(name='function',identity=identity)}},subscriptions={})
        if not query.endswith('configured'):
            env.update(CONTRIBUTOR_ROLE_ID='contributor',OWNER_ROLE_ID='owner',ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID='rbac',USER_ACCESS_ADMINISTRATOR_ROLE_ID='uaa',iam_client=NS(role_assignments={'sub':{'a':NS(agent_id='user-principal',role_id='owner')}},roles={'sub':{}}))
    source=PROOFS[query]['pinned_python'];exec(source[source.index('class '+query):],env)
    assert env[query]().execute()[0].status=='PASS'
    assert PROOFS[query]['counterexample']['required_status']=='FAIL'


def test_empty_restrictions_and_default_allow_do_not_disable_public_access():
    proof=PROOFS['appservice_function_app_restrict_public_acces'];sql=proof['pinned_sql']
    assert "r ->> 'ipAddress' = 'Any'" in sql and 'ipSecurityRestrictionsDefaultAction' not in sql
    assert proof['counterexample']['ipSecurityRestrictions']==[] and proof['counterexample']['ipSecurityRestrictionsDefaultAction']=='Allow'


@pytest.mark.parametrize('query',sorted({r['source_review']['query_id'] for r in VA.values()}))
def test_actual_sql_status_case_ignores_disabled_flag_when_documented_path_is_omitted(query):
    duckdb=pytest.importorskip('duckdb');proof=next(r['source_review'] for r in VA.values() if r['source_review']['query_id']==query)
    case=re.search(r'(case\b.*?\bend)\s+as\s+status',proof['pinned_sql'],re.I|re.S).group(1)
    # DuckDB's JSON arrow precedence differs from PostgreSQL. Parenthesize the
    # original extraction chains without changing any CASE/gate/comparison.
    case=re.sub(r"(?:security|assessment)(?:\s*->>?\s*'[^']*')+",lambda m:'('+m[0]+')',case)
    assessment={'properties':{'recurringScans':{'isEnabled':False,'emailSubscriptionAdmins':False,'emails':[]}}}
    with duckdb.connect(':memory:') as db:
        actual=db.execute('SELECT '+case+' FROM (SELECT ?::JSON AS security,?::JSON AS assessment)',[json.dumps({'properties':{'state':'Enabled'}}),json.dumps(assessment)]).fetchone()[0]
    assert actual=='ok' and proof['counterexample']['required_status']=='alarm'


def test_all_exact_source_ids_revisions_kept_and_no_native_replacement_claim():
    excluded=set(json.loads((ROOT/'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS)==14 and len(VA)==12 and not (set(REVIEWS)|set(VA))&excluded
    assert all(r['disposition']=='rejected' and r['native_checks']==[] and r['source_review']['source_revision'] and r['source_review']['counterexample'] for r in [*REVIEWS.values(),*VA.values()])
