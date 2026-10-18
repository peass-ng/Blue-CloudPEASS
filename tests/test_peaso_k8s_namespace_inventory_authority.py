"""Namespace policy inventory does not infer absence from unreadable identities."""
from copy import deepcopy
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
CID="k8s.network.namespace_policy_inventory"

def observed(namespace,policies):
    snap=make_snapshot("k8s",["*"],[{"type":"namespace","scope":"*","status":"collected","items":[deepcopy(namespace)]},{"type":"networkpolicy","scope":"*","status":"collected" if policies else "empty","items":deepcopy(policies)}],created_at="2026-10-17T00:00:00Z")
    before=deepcopy(snap);rows=[f for f in evaluate_snapshot(snap,checks=[CID])["findings"] if f["check_id"]==CID]
    assert snap==before and len(rows)==1
    return rows[0]["status"]

def test_unavailable_namespace_name_does_not_prove_absence():
    ns={"metadata":{"name":"apps","_coverage":{"name":{"status":"denied"}}}}
    assert observed(ns,[])=="UNKNOWN"

def test_unknown_policy_namespace_cannot_prove_it_belongs_elsewhere():
    policy={"metadata":{"name":"p1","namespace":"other","_coverage":{"namespace":{"status":"denied"}}}}
    assert observed({"metadata":{"name":"apps"}},[policy])=="UNKNOWN"

def test_known_presence_stays_manual_amid_unknown_peers():
    policies=[{"metadata":{"name":"p0","namespace":"other","_coverage":{"namespace":{"status":"denied"}}}},{"metadata":{"name":"p1","namespace":"apps"}}]
    assert observed({"metadata":{"name":"apps"}},policies)=="MANUAL"

def test_available_empty_and_foreign_inventory_remain_absence():
    ns={"metadata":{"name":"apps"}}
    assert observed(ns,[])=="FAIL"
    assert observed(ns,[{"metadata":{"name":"p1","namespace":"other"}}])=="FAIL"
