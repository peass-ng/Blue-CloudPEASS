"""Actual native public command findings retain concise, honest source meaning."""
import json,re
from pathlib import Path
from copy import deepcopy
import pytest
from peaso.checks.aws_workload_command_observed_20261020 import observation
from peaso.checks.aws_evidence_explanations import evidence_summary

ROWS=[pytest.param(f,id=r['case']+'-'+str(i)) for r in json.loads(Path('tests/fixtures/aws-workload-command-brief-native-20261020.json').read_text())['records'] for i,f in enumerate(r['findings'])]

@pytest.mark.parametrize('f',ROWS)
def test_actual_native_public_copy_is_brief_and_preserves_partial(f):
    before=deepcopy(f); text=observation(f); rendered=evidence_summary(f)
    assert rendered and len(re.split(r'[.!?] +',rendered))<=3
    if f['status'] in ('PASS','FAIL'):
        assert text and 'command literals' in text and text in rendered
        if f['evidence'].get('complete')is False:assert 'incomplete' in text
    assert f==before

@pytest.mark.parametrize('fault',['provider','status','fingerprint','link','scope','engine','raw','path'])
def test_source_copy_rejects_foreign_or_malformed_leak(fault):
    f=next(deepcopy(p.values[0]) for p in ROWS if p.values[0]['status']=='FAIL');assert observation(f)
    leak=f['evidence']['secret_leaks'][0]
    if fault=='provider':f['provider']='gcp'
    elif fault=='status':f['status']='PASS'
    elif fault=='fingerprint':f['secret_fingerprint']='0'*64
    elif fault=='link':f['linked_check_ids'].append('foreign')
    elif fault=='scope':leak['locations'][0]['scope']='foreign'
    elif fault=='engine':leak['detectors'][0]['engine']='unknown'
    elif fault=='path':leak['locations'][0]['path']='foreign'
    else:leak['raw']='must never render'
    assert observation(f)is None
