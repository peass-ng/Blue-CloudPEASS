"""Native configuration regressions with actual planner/collector/evaluator, inert HTTP only."""
import copy
import pytest
from peaso.collectors import gcp
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import seal

FW = "gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only"
ON = "gcp.ports.sql_instance_sql_3625_trace_database_flag_on"
OFF = "gcp.gap.sql_3625_trace_flag_off_cis_v1"

class API:
    def __init__(self, kind, row, denied=False):
        self.kind, self.row, self.denied, self.requests, self.evidence = kind, row, denied, [], []
    def request(self, method, url, **kwargs):
        request_id = "request-" + str(len(self.requests)+1)
        self.requests.append({"method":method,"url":url,**kwargs})
        assert method == "GET"
        if url.endswith("/instances/db/users"):
            data = {"kind":"sql#usersList","items":[]}
        else:
            assert url.endswith("/firewalls" if self.kind=="firewall" else "/instances")
            if self.denied:
                error = gcp.ReadError("denied","inert_inventory_denied")
                error.request_id = request_id
                self.evidence.append({"id":request_id,"url":url,"method":method,"status":"denied"})
                raise error
            data = {"items":[self.row]}
        self.evidence.append({"id":request_id,"url":url,"method":method,"status":"collected"})
        return copy.deepcopy(data), request_id
    def close(self): pass

def observed(monkeypatch, cid, row, denied=False, denied_field=None):
    api = API("firewall" if cid==FW else "sql_instance",row,denied)
    monkeypatch.setattr(gcp,"Credentials",lambda *a,**k:None)
    monkeypatch.setattr(gcp,"Transport",lambda *a,**k:api)
    request={"connector":{"provider":"gcp","scopes":["projects/p-one"],"options":{"include_inherited":False,"concurrency":1}},"checks":[cid]}
    snapshot=collect_snapshot(request)
    if denied_field is not None:
        # Coverage is normalized snapshot metadata, never a provider API field.
        target = next(c for c in snapshot["collections"] if c["type"] == api.kind)
        target["items"][0].setdefault("_coverage",{})[denied_field]={"status":"denied"}
        snapshot=seal(snapshot)
    before=copy.deepcopy(snapshot)
    findings=[f for f in evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)["findings"] if f["check_id"]==cid]
    assert snapshot==before
    assert len(findings)==1
    return findings[0]["status"]

def rule(**values):
    return {"name":"iap-source-rule","direction":"INGRESS","network":"projects/p-one/global/networks/default",
            "allowed":[{"IPProtocol":"tcp","ports":["22-443"]}],"sourceRanges":["35.235.240.0/20"],**values}

def sql(flags, **values):
    return {"name":"db","project":"p-one","databaseVersion":"SQLSERVER_2019_STANDARD",
            "settings":{"databaseFlags":flags},**values}

def test_iap_ranges_or_source_tags_is_not_cidr_only(monkeypatch):
    assert observed(monkeypatch,FW,rule(sourceTags=["workload"]))=="FAIL"

def test_iap_ranges_or_source_accounts_is_not_cidr_only(monkeypatch):
    assert observed(monkeypatch,FW,rule(sourceServiceAccounts=["workload@p-one.iam.gserviceaccount.com"]))=="FAIL"

def test_iap_trusted_subnets_tcp_number_and_all_protocols(monkeypatch):
    for protocol in ("tcp","6","all"):
        allowed={"IPProtocol":protocol}
        if protocol!="all":allowed["ports"]=["22-443"]
        assert observed(monkeypatch,FW,rule(allowed=[allowed],sourceRanges=["35.235.241.0/24","130.211.0.0/22","35.191.0.0/16"]))=="PASS"

def test_iap_ipv4_ipv6_or_mixed_outside_frozen_cis_sources(monkeypatch):
    for ranges in (["10.0.0.0/8"],["::/0"],["35.235.240.0/20","2600:2d00:1:7::/64"]):
        assert observed(monkeypatch,FW,rule(sourceRanges=ranges))=="FAIL"

def test_iap_malformed_or_unreadable_source_selectors_are_unknown(monkeypatch):
    for selector in ([42],[""],None):
        assert observed(monkeypatch,FW,rule(sourceTags=selector))=="UNKNOWN"
    assert observed(monkeypatch,FW,rule(),denied_field="sourceTags")=="UNKNOWN"

def test_iap_applicability_and_primary_denial(monkeypatch):
    for fields in ({"direction":"EGRESS"},{"disabled":True},{"allowed":[{"IPProtocol":"udp","ports":["53"]}]}):
        assert observed(monkeypatch,FW,rule(**fields))=="NOT_APPLICABLE"
    assert observed(monkeypatch,FW,rule(),denied=True)=="DENIED"

def test_sql_provider_trace_name_preserves_each_benchmark_polarity(monkeypatch):
    for cid,value,expected in ((ON,"on","PASS"),(OFF,"off","PASS"),(ON,"off","FAIL"),(OFF,"on","FAIL")):
        assert observed(monkeypatch,cid,sql([{"name":"3625 (trace flag)","value":value}]))==expected

def test_sql_legacy_and_provider_alias_conflict_is_unknown(monkeypatch):
    for cid in (ON,OFF):
        for values in (("on","off"),("on","on")):
            flags=[{"name":"3625","value":values[0]},{"name":"3625 (trace flag)","value":values[1]}]
            assert observed(monkeypatch,cid,sql(flags))=="UNKNOWN"

def test_sql_trace_invalid_value_and_field_denial_are_unknown(monkeypatch):
    for cid in (ON,OFF):
        for value in ("future-value",True):
            assert observed(monkeypatch,cid,sql([{"name":"3625 (trace flag)","value":value}]))=="UNKNOWN"
        assert observed(monkeypatch,cid,sql([]),denied_field="settings")=="UNKNOWN"

def test_sql_explicit_flag_absence_not_invented_default_and_engine_scope(monkeypatch):
    for cid in (ON,OFF):
        assert observed(monkeypatch,cid,sql([]))=="FAIL"
        assert observed(monkeypatch,cid,sql([],databaseVersion="POSTGRES_16"))=="NOT_APPLICABLE"
        assert observed(monkeypatch,cid,sql([]),denied=True)=="DENIED"
