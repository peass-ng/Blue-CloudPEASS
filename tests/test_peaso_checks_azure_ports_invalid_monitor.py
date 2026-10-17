"""Full pinned query, including the global LIMIT, against two compliant scopes."""
import json,re
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parent.parent
REVIEWS={**json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_monitor.json').read_text()),**json.loads((ROOT/'peaso/rulepacks/reviewed_azure_ports_invalid_monitor.json').read_text())}
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


@pytest.mark.parametrize('query',PROOFS)
def test_actual_global_limit_query_wrongly_alarms_one_compliant_subscription(query):
    duckdb=pytest.importorskip('duckdb');sql=PROOFS[query]['pinned_sql']
    sql=re.sub(r'^\s*\$\{.*?\}\s*$','',sql,flags=re.M)
    sql=sql.replace('jsonb_array_elements_text(scopes) as sc',"unnest(from_json(scopes, '[\"VARCHAR\"]')) as scope_items(sc)")
    sql=sql.replace('jsonb_array_length(', 'json_array_length(').replace('::jsonb','::JSON')
    sql=re.sub(r"alert.condition -> 'allOf' @> ('[^']*')",r"json_contains(alert.condition -> 'allOf', \1::JSON)",sql)
    # All leaf alternatives are satisfied in both scopes; the actual CTE, LIMIT,
    # subscription join and CASE are executed, not a reconstructed predicate.
    leaves=[json.loads(value)[0] for value in re.findall(r"@> '([^']*)'",PROOFS[query]['pinned_sql'])]
    operation=[x for x in leaves if x['field']=='operationName']
    categories=[x for x in leaves if x['field']=='category']
    types=[x for x in leaves if x['field']=='resourceType']
    conditions=categories[:1]+(operation[:1] or types[:1])
    with duckdb.connect(':memory:') as db:
        db.execute('CREATE TABLE azure_subscription(subscription_id VARCHAR,display_name VARCHAR,_ctx VARCHAR)')
        db.execute("INSERT INTO azure_subscription VALUES ('sub-a','A','ctx'),('sub-b','B','ctx')")
        db.execute('CREATE TABLE azure_log_alert(id VARCHAR,name VARCHAR,enabled BOOLEAN,location VARCHAR,subscription_id VARCHAR,scopes JSON,condition JSON)')
        for scope in ('sub-a','sub-b'):
            db.execute('INSERT INTO azure_log_alert VALUES (?,?,?,?,?,?::JSON,?::JSON)',[scope,'alert',True,'global',scope,json.dumps(['/subscriptions/'+scope]),json.dumps({'allOf':conditions})])
        rows=db.execute(sql).fetchall()
    assert len(rows)==2 and sorted(row[1] for row in rows)==['alarm','ok']
    assert PROOFS[query]['counterexample']['required_statuses']==['ok','ok']


def test_all_corrected_reference_ids_and_versions_remain_visible_without_fake_merge():
    assert len(REVIEWS)==78 and len(PROOFS)==13
    assert all(_not_fake(r) for r in REVIEWS.values())
    assert sum(map(_verified_merge, REVIEWS.values()))==72
    assert all('limit 1' in r['source_review']['pinned_sql'].lower() for r in REVIEWS.values())
