"""Azure declared role risk requires readable native role facts."""
from copy import deepcopy
import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
OWNER="azure.iam.review_owner_assignment"
CUSTOM="azure.iam.no_full_custom_role"

def verdict(cid,properties):
    scope="/subscriptions/11111111-1111-1111-1111-111111111111"
    kind="role_assignment" if cid==OWNER else "role_definition"
    snap=make_snapshot("azure",[scope],[{"type":kind,"scope":scope,"status":"collected","items":[{"id":scope+"/providers/Microsoft.Authorization/roleAssignments/r1","properties":deepcopy(properties)}]}],created_at="2026-10-17T00:00:00Z")
    before=deepcopy(snap);rows=[f for f in evaluate_snapshot(snap,checks=[cid])["findings"] if f["check_id"]==cid]
    assert len(rows)==1 and snap==before
    return rows[0]["status"]

@pytest.mark.parametrize("field",["roleDefinitionId","principalId"])
def test_unavailable_role_assignment_cannot_prove_safety(field):
    p={"roleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/reader","principalId":"user1","_coverage":{field:{"status":"denied"}}}
    assert verdict(OWNER,p)=="UNKNOWN"

def test_malformed_principal_cannot_prove_safety():
    assert verdict(OWNER,{"roleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/reader","principalId":42})=="UNKNOWN"

@pytest.mark.parametrize("field",["type","permissions"])
def test_unavailable_role_definition_cannot_prove_safety(field):
    p={"type":"CustomRole","permissions":[{"actions":["Microsoft.Storage/*/read"]}],"_coverage":{field:{"status":"denied"}}}
    assert verdict(CUSTOM,p)=="UNKNOWN"

@pytest.mark.parametrize("field",["actions","dataActions"])
def test_unavailable_permission_actions_cannot_prove_safety(field):
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":[{"actions":["Microsoft.Storage/*/read"],"_coverage":{field:{"status":"denied"}}}]})=="UNKNOWN"

@pytest.mark.parametrize("field,grant",[("notActions","actions"),("notDataActions","dataActions")])
def test_unavailable_exclusions_cannot_prove_unrestricted_violation(field,grant):
    permission={grant:["*"],"_coverage":{field:{"status":"denied"}}}
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":[permission]})=="UNKNOWN"

def test_malformed_action_array_cannot_prove_risk():
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":[{"actions":"*"}]})=="UNKNOWN"

def test_native_omissions_and_built_in_role_keep_outcomes():
    assert verdict(CUSTOM,{"type":"BuiltInRole"})=="NOT_APPLICABLE"
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":[{"actions":["Microsoft.Storage/*/read"]}]})=="PASS"
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":[{"actions":["*"]}]})=="FAIL"
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":[{"actions":["*"],"notActions":["Microsoft.Compute/*"]}]})=="MANUAL"


@pytest.mark.parametrize("reverse",[False,True])
def test_independent_unexcluded_wildcard_survives_excluded_block(reverse):
    blocks=[{"actions":["*"]},{"actions":["*"],"notActions":["Microsoft.Compute/*"]}]
    if reverse: blocks.reverse()
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":blocks})=="FAIL"


@pytest.mark.parametrize("grant,other_exclusion",[("actions","notDataActions"),("dataActions","notActions")])
def test_opposite_plane_exclusion_does_not_restrict_wildcard(grant,other_exclusion):
    permission={grant:["*"],other_exclusion:["Microsoft.Storage/*"]}
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":[permission]})=="FAIL"


@pytest.mark.parametrize("grant,other_exclusion",[("actions","notDataActions"),("dataActions","notActions")])
def test_unreadable_opposite_plane_exclusion_does_not_hide_known_violation(grant,other_exclusion):
    permission={grant:["*"],"_coverage":{other_exclusion:{"status":"denied"}}}
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":[permission]})=="FAIL"


@pytest.mark.parametrize("grant,exclusion",[("actions","notActions"),("dataActions","notDataActions")])
def test_only_matching_plane_exclusions_require_manual_review(grant,exclusion):
    permission={grant:["*"],exclusion:["Microsoft.Storage/*"]}
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":[permission]})=="MANUAL"


def test_known_unexcluded_wildcard_survives_unreadable_peer():
    permissions=[{"actions":["*"]},{"actions":["Microsoft.Storage/*/read"],
        "_coverage":{"dataActions":{"status":"denied"}}}]
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":permissions})=="FAIL"


def test_excluded_wildcard_with_unreadable_peer_is_unknown():
    permissions=[{"actions":["*"],"notActions":["Microsoft.Compute/*"]},
        {"actions":["Microsoft.Storage/*/read"],"_coverage":{"dataActions":{"status":"denied"}}}]
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":permissions})=="UNKNOWN"

@pytest.mark.parametrize("reverse",[False,True])
def test_unrestricted_role_block_survives_malformed_peer(reverse):
    permissions=[None,{"actions":["*"]}]
    if reverse:permissions.reverse()
    assert verdict(CUSTOM,{"type":"CustomRole","permissions":permissions})=="FAIL"
