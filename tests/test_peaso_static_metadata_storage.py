"""Storage sharing preserves public mutable-copy and factoring contracts."""
import copy
import json
from peaso.engine import factor_check_meta, hydrate_finding
from peaso.remediation import _read_static_rulepack


def test_factoring_retains_finding_objects_order_and_nested_references():
    evidence={'observations':[{'resource':'example'}]}
    rows=[{'check_id':'one','id':'a','title':'shared title','severity':'high','category':'hardening','evidence':evidence},
          {'check_id':'one','id':'b','title':'shared title','severity':'medium','category':'hardening','evidence':{'observations':[]}}]
    before=copy.deepcopy(rows)
    original_list=rows
    aliases=list(rows)
    metadata=factor_check_meta(rows)
    assert rows is original_list
    assert all(row is alias for row,alias in zip(rows,aliases))
    assert rows[0]['evidence'] is evidence
    assert [row['id']for row in rows]==['a','b']
    assert [hydrate_finding(row,check_meta=metadata)for row in rows]==before


def test_static_string_pool_never_shares_mutable_template_containers(tmp_path):
    label='Repeated bundled template text with enough length to avoid incidental literal reuse.'
    path=tmp_path/'metadata.json'
    path.write_text(json.dumps({'one':{'summary':label,'steps':[label]},'two':{'summary':label,'steps':[label]}}))
    rows=_read_static_rulepack(path)
    assert rows['one']['summary']is rows['two']['summary']
    assert rows['one']['steps'][0]is rows['two']['summary']
    assert rows['one']is not rows['two'] and rows['one']['steps']is not rows['two']['steps']
    rows['one']['steps'].append('local change')
    assert rows['two']['steps']==[label]
