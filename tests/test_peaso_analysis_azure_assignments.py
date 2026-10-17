"""Azure least-privilege review per assignment, built-in role resolution and unattributed principals."""
from peaso.analysis import analyze

from test_peaso_analysis import snapshot

SUB = "/subscriptions/00000000-0000-0000-0000-00000000000a"
TENANT = "11111111-1111-1111-1111-111111111111"
OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"


def owner_definition():
    return {"id": "/providers/Microsoft.Authorization/roleDefinitions/" + OWNER, "name": OWNER,
            "properties": {"roleName": "Owner", "type": "BuiltInRole", "permissions": [{"actions": ["*"], "notActions": []}]}}


def reader_definition():
    return {"id": "/providers/Microsoft.Authorization/roleDefinitions/" + READER, "name": READER,
            "properties": {"roleName": "Resource Group Lister", "type": "BuiltInRole", "permissions": [{"actions": ["Microsoft.Resources/subscriptions/resourceGroups/read"], "notActions": []}]}}


def assignment(name, principal, guid, scope=SUB, ptype="User"):
    return {"id": scope + "/providers/Microsoft.Authorization/roleAssignments/" + name, "name": name,
            "properties": {"principalId": principal, "principalType": ptype, "scope": scope,
                           "roleDefinitionId": SUB + "/providers/Microsoft.Authorization/roleDefinitions/" + guid}}


def facts(assignments, directory=True):
    data = {("role_definition", "/"): [owner_definition(), reader_definition()],
            ("role_assignment", SUB): assignments,
            ("subscription", SUB): [{"id": SUB, "subscriptionId": SUB.rsplit("/", 1)[-1], "tenantId": TENANT}]}
    if directory:
        data.update({("directory_user", "/tenants/" + TENANT): [{"id": "user-member", "userType": "Member"}, {"id": "user-guest", "userType": "Guest"}],
                     ("directory_group", "/tenants/" + TENANT): [{"id": "group-1"}],
                     ("directory_service_principal", "/tenants/" + TENANT): [{"id": "sp-home", "appOwnerOrganizationId": TENANT}]})
    return data


def by_check(result, check):
    return [f for f in result["findings"] if f["check_id"] == check]


def test_grant_review_only_for_high_impact_assignments_deduplicated():
    # The same Owner assignment is listed twice (inherited listing at another scope);
    # the Reader assignment and the unassigned definitions produce no grant review.
    duplicate = assignment("a1", "user-member", OWNER)
    result = analyze(snapshot("azure", {**facts([duplicate, assignment("a2", "user-member", READER)]),
                                        ("role_assignment", "/"): [dict(duplicate)]}, scopes=[SUB]))
    reviews = by_check(result, "analysis.grant_review")
    assert len(reviews) == 1
    evidence = reviews[0]["evidence"]
    assert evidence["assignment"]["roleName"] == "Owner" and evidence["assignment"]["principalId"] == "user-member"
    assert evidence["grants"][0]["native_grant"]["actions"] == ["*"]
    assert evidence["role_definition_source"]["resource_type"] == "role_definition"
    assert not any(f["evidence"].get("source", {}).get("resource_type") == "role_definition" for f in reviews)


def test_assignment_resolves_scope_qualified_builtin_definition_by_guid_in_iam_graph():
    result = analyze(snapshot("azure", facts([assignment("a1", "user-member", OWNER)]), scopes=[SUB]))
    graph = result["graphs"]["iam"]
    edge = next(e for e in graph["edges"] if e["type"] == "role_definition")
    target = next(n for n in graph["nodes"] if n["id"] == edge["target"])
    assert target["type"] == "role_definition"
    assert target.get("evidence", {}).get("inventory_status") != "reference_only"


def test_principal_exposure_attribution_and_unknown_reasons():
    assignments = [assignment("a1", "user-member", READER), assignment("a2", "group-1", READER, ptype="Group"),
                   assignment("a3", "sp-home", READER, ptype="ServicePrincipal"), assignment("a4", "user-guest", READER),
                   assignment("a5", "deleted-sp", READER, ptype="ServicePrincipal")]
    result = analyze(snapshot("azure", facts(assignments), scopes=[SUB]))
    exposure = {f["evidence"]["principals"][0]["principal"]: f for f in by_check(result, "analysis.principal_exposure")}
    # Home-tenant directory objects are inside the boundary; guests are external.
    assert set(exposure) == {"user-guest", "deleted-sp"}
    assert exposure["user-guest"]["status"] == "FAIL"
    unknown = exposure["deleted-sp"]
    assert unknown["status"] == "UNKNOWN" and unknown["evidence"]["reason"] == "principal_not_in_directory"
    assert unknown["evidence"]["facts_needed"] and unknown["evidence"]["principals"][0]["unknown_reason"] == "principal_not_in_directory"


def test_principal_exposure_unknown_names_missing_directory_collections():
    result = analyze(snapshot("azure", facts([assignment("a1", "someone", READER)], directory=False), scopes=[SUB]))
    unknown = by_check(result, "analysis.principal_exposure")[0]
    assert unknown["status"] == "UNKNOWN" and unknown["evidence"]["reason"] == "directory_not_collected"
    assert any(fact.startswith("directory_user") for fact in unknown["evidence"]["facts_needed"])
