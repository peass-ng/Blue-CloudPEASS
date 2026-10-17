"""Effective org policy needs readable project and alias binding fields."""
from copy import deepcopy
import pytest
from test_peaso_gcp_effective_policy_consumer_binding import imported,status as _sealed_status,SCOPE,CONSTRAINT,ALIAS,TRACE
from peaso.snapshot import make_snapshot

def status(snapshot):
    sealed=make_snapshot(snapshot["provider"],snapshot["scopes"],snapshot["collections"],created_at=snapshot["created_at"],metadata=snapshot["metadata"])
    before=deepcopy(sealed)
    value=_sealed_status(sealed)
    assert sealed==before
    return value

def deny(row,key):
    row.setdefault("_coverage",{})[key]={"status":"denied"}

def policy(snapshot):
    return next(c for c in snapshot["collections"] if c["type"]=="org_policy_effective")["items"][0]

@pytest.mark.parametrize("field",["name","constraint","_provenance","project_alias"])
def test_unreadable_policy_binding_cannot_prove_inherited_enforcement(field):
    snap=imported(SCOPE+"/policies/"+CONSTRAINT);deny(policy(snap),field)
    assert status(snap)=="UNKNOWN"

@pytest.mark.parametrize("field",list(ALIAS))
def test_unreadable_numeric_project_alias_cannot_prove_enforcement(field):
    snap=imported("projects/1/policies/"+CONSTRAINT,alias=ALIAS,trace=TRACE)
    deny(policy(snap)["project_alias"],field)
    assert status(snap)=="UNKNOWN"

@pytest.mark.parametrize("field",list(TRACE))
def test_unreadable_alias_request_trace_cannot_prove_enforcement(field):
    snap=imported("projects/1/policies/"+CONSTRAINT,alias=ALIAS,trace=TRACE)
    deny(snap["metadata"]["source_requests"][0],field)
    assert status(snap)=="UNKNOWN"

def test_readable_coverage_on_simple_boolean_rule_is_valid():
    snap=imported(SCOPE+"/policies/"+CONSTRAINT)
    policy(snap)["spec"]["rules"][0]["_coverage"]={"enforce":{"status":"collected"}}
    assert status(snap)=="PASS"

def test_unreadable_scope_in_provenance_is_not_binding_proof():
    snap=imported(SCOPE+"/policies/"+CONSTRAINT);policy(snap)["_provenance"]={"scope":SCOPE};deny(policy(snap)["_provenance"],"scope")
    assert status(snap)=="UNKNOWN"

@pytest.mark.parametrize("field",["condition","values","allowAll","denyAll"])
def test_unreadable_nonboolean_rule_fields_cannot_prove_unconditional_enforcement(field):
    snap=imported(SCOPE+"/policies/"+CONSTRAINT)
    deny(policy(snap)["spec"]["rules"][0],field)
    assert status(snap)=="UNKNOWN"
