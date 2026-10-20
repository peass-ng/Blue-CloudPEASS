"""Brief observations preserve current native outcomes and reject contradictions."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.checks.azure_review_observed_20261020 import observation

ROWS=json.loads((Path(__file__).parent/'fixtures/azure-network-audit-evidence-review-20261020.json').read_text())

@pytest.mark.parametrize('cid,row',[(cid,row)for cid,rows in ROWS.items()for row in rows])
def test_native_observation_matches_exact_status_and_rejects_flipped_verdict(cid,row):
    f={'provider':'azure','check_id':cid,**deepcopy(row)}
    assert observation(f)==row['expected_observation']
    if row['status']!='UNKNOWN':
        assert len(observation(f))<190
        f['status']='FAIL' if row['status']=='PASS' else 'PASS'
        assert observation(f) is None


@pytest.mark.parametrize('cid',ROWS)
def test_unreviewed_marker_cannot_promote_arbitrary_observed_text(cid):
    row=deepcopy(ROWS[cid][0]);row['evidence']['criterion']='unreviewed';row['evidence']['observed']='Everything is fully protected.'
    assert observation({'provider':'azure','check_id':cid,**row}) is None
