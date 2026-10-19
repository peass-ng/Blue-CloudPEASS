"""Pure historical audit-storage evaluator fixtures; never admit archived controls.

Collector authority tests still call the real read-only collector. This adapter
only builds its original single-subscription fact index and calls the retained
registered evaluator directly, without changing product admission/exclusions.
"""
from peaso.checks import CHECKS
from peaso.checks.facts import MemoIndex
from peaso.checks.native_only import exclusions
from peaso.engine import _index
from peaso.snapshot import freeze, resources, validate

CID='azure.other.audit_storage_access_logging'


def requirements():
    assert CID in exclusions()
    check=next(c for c in CHECKS if c.id==CID)
    return sorted(set(check.dependencies+[check.kind]))


def evaluate(snapshot):
    snapshot=validate(snapshot,read_only=True)
    assert snapshot['provider']=='azure' and len(snapshot['scopes'])==1
    scope=snapshot['scopes'][0]
    check=next(c for c in CHECKS if c.id==CID)
    index=MemoIndex(_index(snapshot,resources(snapshot)))
    context=freeze({'provider':'azure','scope':scope,'_scope':scope,'created_at':snapshot['created_at'],
                    'snapshot_id':snapshot['snapshot_id'],'metadata':snapshot.get('metadata',{})})
    index['context']=context;index['_snapshot']=context
    subjects=[row['data'] for row in index.get(check.kind,[]) if row['scope']==scope]
    findings=[]
    for item in subjects:
        status,evidence=check.evaluate(item,index)
        findings.append({'check_id':CID,'status':status,'evidence':evidence})
    if not subjects:
        findings.append({'check_id':CID,'status':'UNKNOWN','evidence':{'reason':'Historical parent inventory unavailable'}})
    return findings


def test_customer_classified_historical_control_remains_excluded_from_product():
    from peaso.engine import _registry, get_catalog, plan_collection
    import pytest
    before=dict(exclusions())
    assert CID not in {check.id for check in _registry()}
    assert CID not in {row['id'] for row in get_catalog()['checks']}
    with pytest.raises(ValueError,match='external policy or manual evidence'):
        plan_collection({'connector':{'provider':'azure','scopes':['/subscriptions/example']},'checks':[CID]})
    assert exclusions()==before


def test_current_assessment_rejects_archived_control_without_running_predicate():
    import pytest
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    snapshot=make_snapshot('azure',['/subscriptions/example'],[])
    with pytest.raises(ValueError,match='external policy or manual evidence'):
        evaluate_snapshot(snapshot,checks=[CID])


def test_historical_dependency_description_does_not_change_product_admission():
    before=dict(exclusions())
    assert requirements()==['audit_storage_access_evidence','storage_account']
    assert exclusions()==before and CID in exclusions()
