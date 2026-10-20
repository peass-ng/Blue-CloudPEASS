"""Actual registered secret consumers remain displayable after value deduplication."""
from copy import deepcopy
import inspect
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.secret_findings import deduplicate_secret_findings
from peaso.finding_observation import evidence_summary


@pytest.mark.parametrize('cid',[
    'k8s.review.selected_container_logs.secret_indicators',
    'k8s.review.selected_literals.secret_indicators',
    'k8s.review.selected_metadata.secret_indicators',
])
def test_registered_native_secret_hit_survives_public_observation(cid):
    case=CASES[cid];check=next(c for c in CHECKS if c.id==cid)
    item,index=deepcopy(case['fail']),deepcopy(case['fail_index'])
    status,evidence=inspect.unwrap(check.evaluate)(item,index)
    assert status=='FAIL' and evidence['secret_leaks']
    original={'provider':'k8s','check_id':cid,'id':'native-hit','resource_id':item['id'],
              'scope':index['context']['scope'],'status':status,'evidence':evidence,'frameworks':[]}
    finding,=deduplicate_secret_findings([original]);before=deepcopy(finding)
    summary=evidence_summary(finding)
    assert summary is None or isinstance(summary,str) and len(summary.split())<=55
    assert finding==before and finding['status']=='FAIL'
    assert finding['evidence']['secret_leaks'] and finding['linked_check_ids']==[cid]


@pytest.mark.parametrize('cid',[
    'k8s.review.selected_container_logs.secret_indicators',
    'k8s.review.selected_literals.secret_indicators',
    'k8s.review.selected_metadata.secret_indicators',
])
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_actual_native_secret_branches_do_not_require_optional_renderer_fields(cid,branch):
    case=CASES[cid];check=next(c for c in CHECKS if c.id==cid)
    item,index=deepcopy(case[branch]),deepcopy(case.get(branch+'_index',case.get('index',{})))
    status,evidence=inspect.unwrap(check.evaluate)(item,index)
    assert status==branch.upper()
    finding={'provider':'k8s','check_id':cid,'status':status,'evidence':evidence}
    before=deepcopy(finding)
    summary=evidence_summary(finding)
    assert summary is None or isinstance(summary,str) and summary
    assert finding==before
