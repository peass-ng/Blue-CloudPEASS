"""Existing gateway policy namespace must preserve declared read failures."""
import copy,json
from pathlib import Path
import pytest
from peaso.checks import evaluate_check
CID='azure.other.gateway_backend_health_alert'
BASE=json.loads((Path(__file__).parent/'fixtures/bulk_pending_behavior.json').read_text())[CID]

def status(mode,coverage=None):
    idx=copy.deepcopy(BASE['pass_index']);m=idx['context']['metadata']
    if mode=='root':m['_coverage']={'sw25_policy':coverage}
    elif mode=='field':m['sw25_policy']['_coverage']={CID:coverage}
    elif mode=='absent':m.pop('sw25_policy')
    return evaluate_check(CID,copy.deepcopy(BASE['pass']),idx)[0]

@pytest.mark.parametrize('state',['denied','partial','unknown','not_collected'])
def test_declared_legacy_policy_root_read_failure_never_passes(state):
    assert status('root',{'status':state})=='UNKNOWN'

@pytest.mark.parametrize('mode',['root','field'])
def test_collected_original_policy_still_passes(mode):
    assert status(mode,{'status':'collected'})=='PASS'

def test_existing_literal_leaf_read_failure_remains_unknown():
    assert status('field',{'status':'denied'})=='UNKNOWN'

def test_absent_policy_does_not_manufacture_gateway_requirements():
    assert status('absent')=='UNKNOWN'
