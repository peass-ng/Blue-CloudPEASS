"""Continuous SQL reports only an exact new table-write path."""

from types import SimpleNamespace

import pytest

from peaso.privesc.effective_permissions.gcp_bigquery_continuous_query import select


PROJECT = "projects/p1"
SOURCE = PROJECT + "/datasets/source/tables/incoming"
DEST = PROJECT + "/datasets/output/tables/received"
EMAIL = "runner@p1.iam.gserviceaccount.com"
SA = PROJECT + "/serviceAccounts/" + EMAIL


class Model:
    def __init__(self):
        self.sas = {"serviceAccount:" + EMAIL: SimpleNamespace(
            id="serviceAccount:" + EMAIL, attrs={"resource": SA, "email": EMAIL})}
        self.continuous_assignment_status = {PROJECT: "collected"}
        self.continuous_assignments = {(PROJECT, "us"): [{"principal": None, "state": "ACTIVE",
            "reservation_status": "collected", "edition": "ENTERPRISE"}]}
        self.bigquery_datasets = {
            PROJECT + "/datasets/source": {"location": "US"},
            PROJECT + "/datasets/output": {"location": "US"}}
        self.bigquery_tables = {name: {"type": "TABLE", "_schema_full": True,
            "schema": {"fields": [{"name": "value", "type": "STRING"}]},
            "_coverage": {"tableDetails": {"status": "collected"}}}
            for name in (SOURCE, DEST)}
        self.resource_policy_status = {
            "bigquery_dataset": {name: "collected" for name in self.bigquery_datasets},
            "bigquery_table": {name: "collected" for name in self.bigquery_tables}}
        self.resource_inventory_status = {"bigquery_dataset": {PROJECT: "collected"},
                                          "bigquery_table": {PROJECT: "collected"}}
        self.bigquery_row_policy_status = {name: "collected" for name in self.bigquery_tables}
        self.bigquery_row_policies = {name: [] for name in self.bigquery_tables}
        self.iam_policy_inventory_status = {PROJECT: "collected"}
        self.iam_role_inventory_status = {PROJECT: "collected"}
        self.grants = {}
        self.allowed = {
            ("caller", "iam.serviceAccounts.actAs", SA),
            ("caller", "bigquery.jobs.create", PROJECT),
            ("serviceAccount:" + EMAIL, "bigquery.tables.getData", SOURCE),
            ("serviceAccount:" + EMAIL, "bigquery.tables.updateData", DEST),
        }

    def check(self, principal, req, resource):
        return (SimpleNamespace(confidence="derived")
                if (principal.id, req["action"], resource) in self.allowed else None)

    def ancestors(self, scope):
        return [scope]


def path(model):
    target = SimpleNamespace(scope=PROJECT, attrs={"project": PROJECT, "email": EMAIL})
    return select(model, {
        "gcp_verified_authority:bigquery_continuous_query:serviceAccount:" + EMAIL: target},
        SimpleNamespace(id="caller", kind="gcp_user"))


def test_exact_existing_source_and_destination_grant_bounded_write():
    assert list(path(Model()).values()) == [("conditional", "continuous_query_exact_table_write_gain")]


@pytest.mark.parametrize("change", [
    lambda m: m.continuous_assignments[(PROJECT, "us")][0].update(edition="STANDARD"),
    lambda m: m.continuous_assignments[(PROJECT, "us")][0].update(state="PENDING"),
    lambda m: m.continuous_assignments[(PROJECT, "us")][0].update(principal="other@example.com"),
    lambda m: m.bigquery_datasets[PROJECT + "/datasets/source"].update(location="EU"),
    lambda m: m.bigquery_tables[SOURCE]["schema"]["fields"][0].update(policyTags={"names": ["restricted"]}),
    lambda m: m.bigquery_row_policies[SOURCE].append({"name": "policy"}),
])
def test_ineligible_reservation_or_source_never_produces_positive(change):
    model = Model()
    change(model)
    assert not any(value[0] == "conditional" for value in path(model).values())


def test_permission_gain_and_missing_reservation_evidence():
    model = Model()
    model.allowed.add(("caller", "bigquery.tables.updateData", DEST))
    assert path(model) == {}
    model.allowed.add(("caller", "bigquery.tables.getData", DEST))
    assert list(path(model).values()) == [("conditional", "continuous_query_exact_table_read_gain")]
    model.allowed.add(("caller", "bigquery.tables.getData", SOURCE))
    assert path(model) == {}
    model = Model()
    model.continuous_assignments[(PROJECT, "us")][0]["reservation_status"] = "denied"
    assert list(path(model).values())[0][0] == "unknown"


def test_catalog_evaluator_uses_collected_reservation_and_table_authority():
    from peaso import privesc
    from peaso.privesc.effective_permissions.gcp import GcpModel
    from peaso.privesc.evaluator import Evaluator

    def row(kind, values, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind, "status": status,
                "items": values, "error": None}

    caller_role = PROJECT + "/roles/caller"
    runner_role = PROJECT + "/roles/runner"
    datasets = [{"name": name, "location": "US", "access": [],
                 "_coverage": {"datasetDetails": {"status": "collected"}}}
                for name in (PROJECT + "/datasets/source", PROJECT + "/datasets/output")]
    tables = [{"name": name, "type": "TABLE", "_schema_full": True,
               "schema": {"fields": [{"name": "value", "type": "STRING"}]},
               "iamPolicy": {"bindings": []},
               "_coverage": {"tableDetails": {"status": "collected"},
                             "iamPolicy": {"status": "collected"}}}
              for name in (SOURCE, DEST)]
    rows = [
        row("project", [{"projectId": "p1", "name": "projects/111"}]),
        row("iam_role", [
            {"name": caller_role, "includedPermissions": ["bigquery.jobs.create",
                "iam.serviceAccounts.actAs"]},
            {"name": runner_role, "includedPermissions": ["bigquery.tables.getData",
                "bigquery.tables.updateData"]}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": caller_role, "members": ["user:operator@example.com"]},
            {"role": runner_role, "members": ["serviceAccount:" + EMAIL]}]}]),
        row("service_account", [{"email": EMAIL, "projectId": "p1"}]),
        row("bigquery_dataset", datasets),
        row("bigquery_table", tables),
        row("bigquery_row_policy_inventory", [
            {"name": name + "/rowAccessPolicyInventory", "table": name,
             "status": "collected", "policies": []} for name in (SOURCE, DEST)]),
        row("bigquery_continuous_assignment", [{
            "name": "projects/admin/locations/US/reservations/cq/assignments/a1",
            "assignee": PROJECT, "jobType": "CONTINUOUS", "state": "ACTIVE",
            "sourceLocation": "US", "reservationEdition": "ENTERPRISE",
            "_coverage": {"reservationDetails": {"status": "collected"}}}]),
        row("iam_deny_policy", [], "empty"),
    ]
    snap = {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "collections": rows, "metadata": {}}
    entry = next(e for e in privesc.catalog()["entries"]
                 if e["id"] == "gcp-bigquery-continuous-query-actas")
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    found = [(tid, grant.confidence) for reach in reaches
             if reach.source.id == "user:operator@example.com"
             for tid, grant in reach.targets.items()]
    assert len(found) == 1
    assert found[0][0].startswith("gcp_verified_authority:bigquery_continuous_query:")
    assert found[0][1] == "conditional"
