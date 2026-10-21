"""Selected ECR workload findings participate in canonical cross-detector dedup."""
from copy import deepcopy
import json
from pathlib import Path

from peaso.checks import aws_workload_image_secret_review_20261021 as source
from peaso.secret_findings import deduplicate_secret_findings

CASES=Path(__file__).with_name('fixtures')/'aws_workload_image_secret_native_20261021.json'

def capture(name):
    document=json.loads(CASES.read_text())
    return next(row for row in document['cases'] if row['name']==name)

def test_workload_image_hmac_leaks_deduplicate_both_detectors():
    case=capture('fail_secret');status,evidence=source.evaluate_item(case['item'],case['index'])
    assert status=='FAIL' and len(evidence['secret_leaks'])==1
    leak=evidence['secret_leaks'][0]
    assert {d['engine'] for d in leak['detectors']}=={'kingfisher','trufflehog'}
    observations=[]
    for detector in leak['detectors']:
        single=deepcopy(evidence);single['secret_leaks'][0]['detectors']=[detector]
        observations.append(dict(provider='aws',check_id=source.CHECK,status='FAIL',resource_id=case['item']['id'],scope=case['index']['context']['scope'],frameworks=[],evidence=single))
    rows=deduplicate_secret_findings(observations)
    assert len(rows)==1
    assert {d['engine'] for d in rows[0]['evidence']['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}

def test_workload_positive_keeps_partial_coverage_after_dedup():
    case=capture('fail_partial_positive');status,evidence=source.evaluate_item(case['item'],case['index'])
    assert status=='FAIL' and evidence['complete'] is False and evidence['secret_leaks']
    row=dict(provider='aws',check_id=source.CHECK,status=status,resource_id=case['item']['id'],scope=case['index']['context']['scope'],frameworks=[],evidence=evidence)
    result,=deduplicate_secret_findings([row])
    assert result['evidence']['complete'] is False and result['evidence']['coverage']=='incomplete'
