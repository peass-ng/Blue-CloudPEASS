"""Retain original evaluator source and explain formerly identical PASS/FAIL evidence."""
import gzip
import hashlib
import json
from pathlib import Path
from copy import deepcopy

import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from tests.observed_evidence_successors import AWS_FIELDS

ROOT=Path(__file__).resolve().parents[1]
PROOF=json.loads((ROOT/'tests/fixtures/aws_observed_evidence_successors.json').read_text())
BY_ID={check.id:check for check in CHECKS}
FROZEN={}
for name in ('aws_bulk_clarity_reviewed.json.gz','aws_final_clarity_reviewed.json.gz'):
    FROZEN.update(json.loads(gzip.decompress((ROOT/'tests/fixtures'/name).read_bytes())))
for case in json.loads((ROOT/'tests/fixtures/post_dfaf_aws.json').read_text()):
    if case['name'] in ('pass','fail'):
        FROZEN.setdefault(case['id'],{})[case['expected']] = case

@pytest.mark.parametrize('name', sorted(PROOF))
def test_only_reviewed_additive_evidence_changes_reconstruct_original_source(name):
    record=PROOF[name]
    text=(ROOT/'peaso/checks'/name).read_text()
    assert hashlib.sha256(text.encode()).hexdigest()==record['current_sha256']
    for before,after in reversed(record['replacements']):
        assert after in text
        text=text.replace(after,before)
    assert hashlib.sha256(text.encode()).hexdigest()==record['original_sha256']

@pytest.mark.parametrize('cid',sorted(set(CASES)&set(AWS_FIELDS)))
def test_actual_evaluator_keeps_verdict_and_records_decisive_setting(cid):
    cases=CASES[cid];check=BY_ID[cid]
    for state in ('pass','fail'):
        if state not in cases:continue
        case=cases[state];index=deepcopy(case.get('index',{}))
        # Native CASES keep the raw item alongside their named index.
        if state+'_index' in cases:index=deepcopy(cases[state+'_index'])
        if 'index' in cases:index=deepcopy(cases['index'])
        item=deepcopy(case.get('item',case))
        if cid in FROZEN:
            frozen=FROZEN[cid][state.upper()];item,index=deepcopy((frozen['item'],frozen['index']))
        status,evidence=check.evaluate(item,index)
        assert status==state.upper(),(cid,state,status,evidence)
        # Some positive paths already carried a distinct match marker.
        if state == 'pass':
            assert set(evidence)&(AWS_FIELDS[cid]|{'matched','active_attachment','policy'}),(cid,state,evidence)
