"""Prospective row-policy self-grants require new, table-bound access."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
TABLE = PROJECT + "/datasets/private/tables/records"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-bigquery-row-policy-create-self-grant"
ACTIONS = ["bigquery.rowAccessPolicies.create", "bigquery.rowAccessPolicies.setIamPolicy",
           "bigquery.tables.getData", "bigquery.jobs.create"]


def snapshot(*, actions=ACTIONS, members=("user:other@example.com",), policy_count=1,
             policy_status="collected", table_policy="collected", table_type="TABLE",
             group_member=False):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": records, "error": None}
    writer = PROJECT + "/roles/rowPolicyWriter"
    policies = [{"name": TABLE + "/rowAccessPolicies/p" + str(i),
                 "iamPolicy": {"bindings": [{"role": "roles/bigquery.filteredDataViewer",
                                               "members": list(members)}]},
                 "_coverage": {"iamPolicy": {"status": "collected"}}}
                for i in range(policy_count)]
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [{"name": writer, "includedPermissions": list(actions)}]),
                row("iam_policy", [{"name": PROJECT, "bindings":
                    [{"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", ([{"name": "groups/g1", "groupKey": {"id": "team@example.com"}}]
                              if group_member else []), "collected" if group_member else "empty"),
                row("group_membership", ([{"group": "groups/g1", "preferredMemberKey":
                    {"id": "editor@example.com"}}] if group_member else []),
                    "collected" if group_member else "empty"),
                row("bigquery_dataset", [{"name": PROJECT + "/datasets/private", "access": [],
                    "_coverage": {"datasetDetails": {"status": "collected"}}}]),
                row("bigquery_table", [{"name": TABLE, "type": table_type,
                    "iamPolicy": {"bindings": []}, "_coverage": {"iamPolicy":
                        {"status": table_policy}}}]),
                row("bigquery_row_policy_inventory", [{"name": TABLE + "/rowAccessPolicyInventory",
                    "table": TABLE, "status": policy_status, "policies": policies}]),
            ]}


def reaches(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    return {grant.confidence for reach in Evaluator(GcpModel(snap), [entry]).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:possible-bigquery-row-policy-self-grant:")}


def test_exact_table_with_existing_policy_and_missing_grantee_is_conditional():
    assert reaches(snapshot()) == {"conditional"}


def test_existing_direct_group_or_public_grant_is_not_a_new_permission():
    assert not reaches(snapshot(members=(SOURCE,)))
    assert not reaches(snapshot(members=("group:team@example.com",), group_member=True))
    assert not reaches(snapshot(members=("allAuthenticatedUsers",)))


def test_no_existing_row_policy_or_policy_capacity_means_no_create_path():
    assert not reaches(snapshot(policy_count=0))
    assert not reaches(snapshot(policy_count=400))


def test_each_required_action_and_exact_table_evidence_matter():
    for action in ACTIONS:
        assert not reaches(snapshot(actions=[a for a in ACTIONS if a != action]))
    assert "conditional" not in reaches(snapshot(policy_status="denied"))
    assert "conditional" not in reaches(snapshot(table_policy="denied"))
    assert not reaches(snapshot(table_type="VIEW"))
