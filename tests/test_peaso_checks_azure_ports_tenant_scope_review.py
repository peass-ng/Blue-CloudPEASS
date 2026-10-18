"""Actual unjoined tenant policy scopes are not exact scoped native associations."""
import json,re
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parent.parent
REVIEWS={sid:row for name in ('directory','directory_extra','iam') for sid,row in json.loads((ROOT/('peaso/rulepacks/reviewed_azure_ports_'+name+'.json')).read_text()).items() if row.get('accepted_history_re_adjudication_required')}
PROOFS={r['source_review']['query_id']:r['source_review'] for r in REVIEWS.values()}


def _verified_merge(row):
    """A corrected merge is legitimate only with a recorded same-requirement verification."""
    v = row.get('native_equivalence_verification')
    return bool(row.get('disposition') == 'merged' and row.get('review_classification') == 'corrected_native_merge' and v
                and v.get('verdict') == 'same_control_requirement' and v.get('target_native_checks') == row['native_checks'] and row['native_checks']
                and all(v.get(k) for k in ('resource', 'property', 'pass_condition', 'upstream_defect_only'))
                and row.get('upstream_defect', {}).get('reason'))


def _not_fake(row):
    """Unverified rows stay rejected with no native; verified rows are corrected merges."""
    return _verified_merge(row) or (row['disposition'] == 'rejected' and row['native_checks'] == [] and 'native_equivalence_verification' not in row)


def _cls(row):
    return row.get('upstream_defect', {}).get('classification') if row.get('review_classification') == 'corrected_native_merge' else row.get('review_classification')


@pytest.mark.parametrize('query',sorted(PROOFS))
def test_actual_source_status_case_and_from_scope_copies_authenticated_policy_to_foreign_tenant(query):
    duckdb=pytest.importorskip('duckdb');proof=PROOFS[query];sql=proof['pinned_sql']
    assert ('distinct_tenant as t,' in sql) or query=='iam_subscription_tenant_transfer_restricted'
    case=re.search(r'(case\b.*?\bend)\s+as\s+status',sql,re.I|re.S).group(1)
    case=re.sub(r'\b(?:a|p|t)\.', '',case)
    case=case.replace('::bool','::BOOLEAN')
    case=re.sub(r"(?:default_user_role_permissions|subscription_policy)(?:\s*->>?\s*'[^']*')+",lambda m:'('+m[0]+')',case)
    # One authenticated policy representation, two actual ARM tenant rows;
    # source CASE and unguarded cross product are retained. For transfer policy,
    # the documented adapter repeats credential-tenant GET for both ARM items.
    policy=json.dumps({'allowedToCreateApps':False,'allowedToCreateSecurityGroups':False,'allowedToCreateTenants':False})
    transfer=json.dumps({'properties':{'blockSubscriptionsIntoTenant':True,'blockSubscriptionsLeavingTenant':True}})
    value='false' if query=='ad_m365_group_creation_disabled' else 'true' if query=='ad_custom_banned_password_enforced' else '60' if query=='ad_account_duration_min_60_seconds' else '10'
    with duckdb.connect(':memory:') as db:
        rows=db.execute('SELECT tenants.tenant_id,'+case+" FROM (VALUES ('A'),('B')) tenants(tenant_id),(SELECT ?::JSON AS default_user_role_permissions,?::JSON AS subscription_policy,true AS is_enabled,'2af84b1e-32c8-42b7-82bc-daa82404023b' AS guest_user_role_id,'none' AS allow_invites_from,? AS value) captured_policy",[policy,transfer,value]).fetchall()
    assert len(rows)==2 and all(row[1]=='ok' for row in rows)
    assert proof['counterexample']['authoritative_scope'].startswith('A only')


def test_corrections_preserve_all_ids_evidence_and_require_central_history_review():
    assert len(PROOFS)==11 and len(REVIEWS)>11
    assert all(_not_fake(r) and r['source_review']['former_native_checks'] and r['accepted_history_re_adjudication_required'] for r in REVIEWS.values())
