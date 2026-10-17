"""Substantive scope, declared-state and retired-runtime source counterexamples."""
import json
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parent.parent
REVIEWS=json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_invalid_remaining.json').read_text())
PROOFS={r['source_review']['query_id']:r['source_review'] for r in REVIEWS.values()}


def test_region_only_watcher_join_accepts_foreign_subscription():
    duckdb=pytest.importorskip('duckdb')
    with duckdb.connect(':memory:') as db:
        rows=db.execute("SELECT loc.subscription_id,CASE WHEN watcher.id IS NULL THEN 'alarm' ELSE 'ok' END FROM (VALUES ('A','eastus'),('B','eastus')) loc(subscription_id,name) LEFT JOIN (VALUES ('watcher','A','eastus')) watcher(id,subscription_id,region) ON watcher.region=loc.name").fetchall()
    assert [r[1] for r in rows]==['ok','ok']
    assert PROOFS['network_watcher_enabled']['counterexample']['required_statuses']==['ok','alarm']


def test_source_nullness_does_not_prove_subnet_association():
    duckdb=pytest.importorskip('duckdb')
    with duckdb.connect(':memory:') as db:
        assert db.execute("SELECT CASE WHEN subnets IS NULL THEN 'alarm' ELSE 'ok' END FROM (SELECT '[]'::JSON AS subnets)").fetchone()[0]=='ok'
    assert PROOFS['network_security_group_subnet_associated']['counterexample']['required_status']=='alarm'


@pytest.mark.parametrize('query',['nsg_network_watcher_flow_log_send_to_log_analytics','network_virtual_network_watcher_flow_log_send_to_log_analytics'])
def test_disabled_flow_and_analytics_falsepass_source_workspace_only_selector(query):
    duckdb=pytest.importorskip('duckdb');sql=PROOFS[query]['pinned_sql']
    assert "traffic_analytics -> 'workspaceId' is not null" in sql
    assert 'and enabled' not in sql and "traffic_analytics -> 'enabled'" not in sql
    with duckdb.connect(':memory:') as db:
        for value in ('workspace',None):
            assert db.execute("SELECT (traffic_analytics -> 'workspaceId') IS NOT NULL FROM (SELECT ?::JSON AS traffic_analytics)",[json.dumps({'workspaceId':value,'enabled':False})]).fetchone()[0] is True


def test_owner_row_count_passes_two_assignments_for_single_owner_and_omits_zero():
    duckdb=pytest.importorskip('duckdb');sql=PROOFS['iam_subscription_owner_between_2_and_3']['pinned_sql']
    assert 'count(*) >= 2' in sql and 'distinct' not in sql.lower()
    with duckdb.connect(':memory:') as db:
        assert db.execute("SELECT CASE WHEN count(*)>=2 AND count(*)<=3 THEN 'ok' ELSE 'alarm' END FROM (VALUES ('one'),('one')) roles(principal)").fetchone()[0]=='ok'
    assert PROOFS['iam_subscription_owner_between_2_and_3']['counterexample']['required_status']=='alarm'


@pytest.mark.parametrize('query',['network_ddos_enabled','batch_account_logging_enabled'])
def test_source_name_join_identity_collision_is_real(query):
    sql=PROOFS[query]['pinned_sql']
    assert ('a.name = b.vn_name' in sql) if query.startswith('network') else ('v.name = l.account_name' in sql)
    example=PROOFS[query]['counterexample']
    assert example.get('pinned_status',example.get('pinned_statuses'))!=example.get('required_status',example.get('required_statuses'))


def test_country_location_has_no_trust_field_and_retired_runtime_proofs_are_explicit():
    assert 'isTrusted' not in PROOFS['iam_conditional_access_trusted_location_configured']['counterexample']['locations'][1]
    for q,extension in [('arc_compute_machine_linux_log_analytics_agent_installed','OMSAgentForLinux'),('arc_compute_machine_windows_log_analytics_agent_installed','MicrosoftMonitoringAgent')]:
        assert extension in PROOFS[q]['pinned_sql']
        assert PROOFS[q]['counterexample']['retirement']=='2024-08-31'
    assert "('v6.0', 'v7.0')" in PROOFS['appservice_web_app_latest_dotnet_framework_version']['pinned_sql']


def test_no_missing_fact_rejections_and_no_transferred_source_ids():
    excluded=set(json.loads((ROOT/'peaso/rulepacks/port_partitions_claude.json').read_text())['partitions']['claude_azure']['check_ids'])
    assert len(REVIEWS)==30 and len(PROOFS)==11 and not set(REVIEWS)&excluded
    assert all(r['native_checks']==[] and r['source_review']['source_revision'] and r['official_docs'] and r['source_review']['counterexample'] for r in REVIEWS.values())
