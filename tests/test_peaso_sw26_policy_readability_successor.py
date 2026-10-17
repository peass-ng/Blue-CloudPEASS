"""Readability of the documented modern SW26 literal check policy."""
import copy,json
from pathlib import Path
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot
CID='azure.other.app_latest_tls'
FIXTURE=Path(__file__).parent/'fixtures/bulk_pending_behavior.json'
def fixture(state='pass'):
    index=copy.deepcopy(json.loads(FIXTURE.read_text())[CID][state+'_index'])
    return index['collections'],index['context']
def policy(ctx):return ctx['metadata']['compliance_policy']['sw26']
def status(c,ctx):
    snap=make_snapshot('azure',[ctx['scope']],[dict(e) for batches in c.values() for e in batches],metadata=ctx['metadata'],created_at=ctx['created_at'])
    rows=[r for r in evaluate_snapshot(snap,checks=[CID],include_not_applicable=True)['findings'] if r['check_id']==CID]
    assert len(rows)==1
    status.last=rows
    return rows[0]['status']

def test_denied_documented_modern_policy_cannot_produce_pass():
    c,ctx=fixture();policy(ctx)['_coverage']={CID:{'status':'denied'}}
    assert status(c,ctx)=='UNKNOWN',status.last

def test_declared_partial_unknown_empty_or_malformed_coverage_is_unknown():
    results=[]
    for coverage in ({'status':'partial'},{'status':'unknown'},{'status':'empty'},{},None,1,'collected'):
        c,ctx=fixture();policy(ctx)['_coverage']={CID:coverage}
        results.append((coverage,status(c,ctx)))
    assert all(s=='UNKNOWN' for _,s in results),results

def test_successful_or_undeclared_policy_coverage_preserves_positive():
    for explicit in (False,True):
        c,ctx=fixture()
        if explicit:policy(ctx)['_coverage']={CID:{'status':'collected'}}
        assert status(c,ctx)=='PASS',status.last

def test_missing_selected_policy_stays_unknown_even_with_collected_coverage():
    c,ctx=fixture();policy(ctx).pop(CID);policy(ctx)['_coverage']={CID:{'status':'collected'}}
    assert status(c,ctx)=='UNKNOWN',status.last

def test_unrelated_policy_readability_does_not_change_selected_authority():
    c,ctx=fixture();policy(ctx)['_coverage']={'another.unrelated.check':{'status':'denied'}}
    assert status(c,ctx)=='PASS',status.last

def test_documented_root_scope_status_and_parent_coverage_stay_required():
    for field,value in [('status','partial'),('scope','/subscriptions/foreign')]:
        c,ctx=fixture();policy(ctx)[field]=value
        assert status(c,ctx)=='UNKNOWN',status.last
    c,ctx=fixture();ctx['metadata']['compliance_policy']['_coverage']={'sw26':{'status':'denied'}}
    assert status(c,ctx)=='UNKNOWN',status.last

def test_unreadable_policy_cannot_produce_false_failure_either():
    c,ctx=fixture('fail')
    assert status(c,ctx)=='FAIL',status.last
    policy(ctx)['_coverage']={CID:{'status':'denied'}}
    assert status(c,ctx)=='UNKNOWN',status.last

def test_undocumented_legacy_metadata_is_not_competing_authority():
    c,ctx=fixture();ctx['metadata']['sw26']={'scope':'/subscriptions/unrelated','status':'denied'}
    assert status(c,ctx)=='PASS',status.last
