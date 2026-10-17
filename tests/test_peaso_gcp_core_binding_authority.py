"""GCP project-policy fields cannot be inferred through explicit unreadability."""
from copy import deepcopy
import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
PUBLIC="gcp.iam.restrict_public_members"
BASIC="gcp.iam.avoid_basic_roles"

def verdict(cid,bindings):
    scope="project-test"
    snap=make_snapshot("gcp",[scope],[{"scope":scope,"type":"iam_policy","status":"collected","items":[{"bindings":deepcopy(bindings)}]}],created_at="2026-10-17T00:00:00Z")
    before=deepcopy(snap)
    rows=[f for f in evaluate_snapshot(snap,checks=[cid])["findings"] if f["check_id"]==cid]
    assert len(rows)==1 and snap==before
    return rows[0]["status"]

def denied(binding,field):
    binding=deepcopy(binding);binding["_coverage"]={field:{"status":"denied"}};return binding

@pytest.mark.parametrize("cid",[PUBLIC,BASIC])
@pytest.mark.parametrize("field",["role","members"])
def test_selected_binding_authority_required(cid,field):
    assert verdict(cid,[denied({"role":"roles/viewer","members":["user:me@example.com"]},field)])=="UNKNOWN"

@pytest.mark.parametrize("cid",[PUBLIC,BASIC])
def test_member_array_malformed_cannot_prove_safety(cid):
    assert verdict(cid,[{"role":"roles/viewer","members":[1]}])=="UNKNOWN"

def test_unreadable_public_binding_condition_cannot_prove_unconditional_grant():
    assert verdict(PUBLIC,[denied({"role":"roles/viewer","members":["allUsers"]},"condition")])=="UNKNOWN"

@pytest.mark.parametrize("cid,bad",[(PUBLIC,{"role":"roles/viewer","members":["allUsers"]}),(BASIC,{"role":"roles/owner","members":["user:me@example.com"]})])
@pytest.mark.parametrize("reverse",[False,True])
def test_independent_known_bad_binding_survives_unavailable_peer(cid,bad,reverse):
    rows=[denied({"role":"roles/viewer","members":["user:me@example.com"]},"members"),bad]
    if reverse:rows.reverse()
    assert verdict(cid,rows)=="FAIL"

def test_conditional_public_binding_keeps_manual():
    assert verdict(PUBLIC,[{"role":"roles/viewer","members":["allUsers"],"condition":{"expression":"request.time < timestamp(\"2030-01-01T00:00:00Z\")"}}])=="MANUAL"

def test_irrelevant_condition_does_not_block_nonpublic_or_basic():
    row=denied({"role":"roles/viewer","members":["user:me@example.com"]},"condition")
    assert verdict(PUBLIC,[row])=="PASS"
    assert verdict(BASIC,[row])=="PASS"
