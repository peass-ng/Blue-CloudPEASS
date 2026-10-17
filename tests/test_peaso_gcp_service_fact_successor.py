"""GKE allocation-mode facts through inert native collection and public engine."""
import copy
import pytest
from peaso.collectors import gcp
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import seal

CID = "gcp.ports.kubernetes_cluster_use_ip_aliases"

class API:
    def __init__(self, policy, denied=False):
        self.policy, self.denied, self.requests, self.evidence = policy, denied, [], []
    def request(self, method, url, **kwargs):
        assert method == "GET"
        assert url == "https://container.googleapis.com/v1/projects/p-one/locations/-/clusters"
        rid="request-"+str(len(self.requests)+1)
        self.requests.append({"method":method,"url":url,**kwargs})
        if self.denied:
            exc=gcp.ReadError("denied","inert_gke_denied");exc.request_id=rid
            self.evidence.append({"id":rid,"url":url,"method":method,"status":"denied"})
            raise exc
        row={"name":"cluster-one","location":"us-central1","ipAllocationPolicy":copy.deepcopy(self.policy)}
        self.evidence.append({"id":rid,"url":url,"method":method,"status":"collected"})
        return {"clusters":[row]},rid
    def close(self): pass

def observed(monkeypatch,policy,*,denied=False,denied_field=None,partial=False):
    api=API(policy,denied)
    monkeypatch.setattr(gcp,"Credentials",lambda *a,**k:None)
    monkeypatch.setattr(gcp,"Transport",lambda *a,**k:api)
    request={"connector":{"provider":"gcp","scopes":["projects/p-one"],"options":{"include_inherited":False,"concurrency":1}},"checks":[CID]}
    snapshot=collect_snapshot(request)
    target=next(c for c in snapshot["collections"] if c["type"]=="gke_cluster")
    if denied_field is not None:
        # Normalized unavailable-source metadata is not a provider API field.
        target["items"][0]["ipAllocationPolicy"].setdefault("_coverage",{})[denied_field]={"status":"denied"}
    if partial:
        target["status"]=target["coverage_status"]="partial"
    snapshot=seal(snapshot)
    before=copy.deepcopy(snapshot)
    findings=[f for f in evaluate_snapshot(snapshot,checks=[CID],include_not_applicable=True)["findings"] if f["check_id"]==CID]
    assert snapshot==before and findings
    assert len(api.requests)==1
    return {f["status"] for f in findings}

def test_contradictory_true_modes_cannot_prove_vpc_native(monkeypatch):
    assert observed(monkeypatch,{"useIpAliases":True,"useRoutes":True})=={"UNKNOWN"}

def test_both_false_or_unselected_mode_does_not_invent_server_default(monkeypatch):
    for policy in ({"useIpAliases":False,"useRoutes":False},{"useIpAliases":False},{"useRoutes":False},{}):
        assert observed(monkeypatch,policy)=={"UNKNOWN"}

def test_explicit_noncontradictory_alias_selection_remains_positive(monkeypatch):
    for policy in ({"useIpAliases":True,"useRoutes":False},{"useIpAliases":True}):
        assert observed(monkeypatch,policy)=={"PASS"}

def test_explicit_route_selection_remains_negative(monkeypatch):
    for policy in ({"useIpAliases":False,"useRoutes":True},{"useRoutes":True}):
        assert observed(monkeypatch,policy)=={"FAIL"}

def test_unreadable_complementary_mode_cannot_prove_consistency(monkeypatch):
    for field in ("useRoutes","useIpAliases"):
        assert observed(monkeypatch,{"useIpAliases":True,"useRoutes":False},denied_field=field)=={"UNKNOWN"}

def test_invalid_typed_mode_is_not_ignored_when_other_mode_true(monkeypatch):
    for value in ("true",1,None):
        assert observed(monkeypatch,{"useIpAliases":True,"useRoutes":value})=={"UNKNOWN"}
        assert observed(monkeypatch,{"useIpAliases":value,"useRoutes":True})=={"UNKNOWN"}

def test_native_collection_denial_and_partial_coverage_remain_visible(monkeypatch):
    assert observed(monkeypatch,{"useIpAliases":True},denied=True)=={"DENIED"}
    # An observed resource remains assessable; incomplete universe emits UNKNOWN.
    assert observed(monkeypatch,{"useIpAliases":True},partial=True)=={"PASS","UNKNOWN"}
