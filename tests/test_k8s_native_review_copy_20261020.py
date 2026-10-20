"""Copy corrections preserve predecessor attestations and exact source intent."""
from copy import deepcopy
import pytest
from peaso.checks.k8s_native_review_copy_20261020 import _rows,reviewed_fields
from peaso.checks.k8s_finding_clarity_reviewed import ROWS as COMPONENT
from peaso.checks.k8s_workload_clarity_reviewed import ROWS as WORKLOAD
ROWS={**COMPONENT,**WORKLOAD}
@pytest.mark.parametrize('cid,kind',[(cid,kind)for cid,row in _rows().items()for kind in row])
def test_native_copy_binds_predecessor_and_rejects_unreviewed_fields(cid,kind):
    before=deepcopy(ROWS[cid][kind+'_fields']);expected=deepcopy(before)
    after=reviewed_fields(cid,kind,before)
    assert before==expected and after!=before
    if kind=='description':assert len(after['description'].split())<=45
    with pytest.raises(ValueError,match='predecessor changed'):
        reviewed_fields(cid,kind,{**before,'unreviewed':'changed'})
    after['unreviewed']='mutation'
    assert 'unreviewed'not in reviewed_fields(cid,kind,before)
