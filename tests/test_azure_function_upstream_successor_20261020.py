"""Preserve exact upstream identities while admitting only narrower native claims."""
import csv
import gzip
import hashlib
import inspect
import io
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

REPORT=Path('docs/check-review/azure-function-source-parity-successor-20261020.json')


def test_only_two_accepted_function_source_associations_change():
    r=json.loads(REPORT.read_text());a=r['preserved_predecessor'];raw=Path(a['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==a['sha256']
    old=json.loads(gzip.decompress(raw))
    for entry in old.values():assert hashlib.sha256(entry['content'].encode()).hexdigest()==entry['sha256']
    path='docs/check-review/azure-upstream-parity-20261020.csv'
    before={x['source_id']:x for x in csv.DictReader(io.StringIO(old[path]['content']))}
    after={x['source_id']:x for x in csv.DictReader(open(path))}
    assert before.keys()==after.keys() and len(after)==1871
    changes={x['source_id']:x for x in r['changes']}
    assert set(changes)==set(r['exact_changed_source_ids']) and len(changes)==2
    assert {cid for cid in before if before[cid]!=after[cid]}==set(changes)
    for cid,change in changes.items():
        assert change['before']==before[cid] and change['after']==after[cid]
        for field in ['repository','revision','source_metadata_sha256','baseline_disposition','source_reason']:
            assert before[cid][field]==after[cid][field]
        assert after[cid]['current_disposition']=='reviewed_bounded_native_successor_not_equivalent'
        assert next(c for c in CHECKS if c.id==after[cid]['native_ids']).provider=='azure'
    assert r['full_upstream_equivalence']is False and r['new_numbered_compliance_mapping']is False


@pytest.mark.parametrize('cid',[
    'azure.review.function.application_insights_setting_declared',
    'azure.review.function.runtime_major4_update_channel_declared'])
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_association_points_to_actual_decisive_native_consumer(cid,branch):
    from copy import deepcopy
    check=next(c for c in CHECKS if c.id==cid);case=CASES[cid]
    status,evidence=inspect.unwrap(check.evaluate)(deepcopy(case[branch]),deepcopy(case[branch+'_index']))
    assert status==branch.upper() and isinstance(evidence,dict)
    # A related setting declaration cannot prove telemetry delivery or latest build.
    assert 'declared' in check.title.lower() or 'declares'in check.title.lower()
