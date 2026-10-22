"""Scheduled SQL must add a concrete BigQuery authority on compatible assets."""

from types import SimpleNamespace

from peaso.privesc.effective_permissions.gcp_bigquery_scheduled_query import select


PROJECT = "projects/p1"
DEST = PROJECT + "/datasets/output"
SOURCE = "projects/p2/datasets/private"
TABLE = SOURCE + "/tables/records"
CONFIG = PROJECT + "/locations/US/transferConfigs/one"
EMAIL = "runner@p1.iam.gserviceaccount.com"
SA_RESOURCE = PROJECT + "/serviceAccounts/" + EMAIL


class Model:
    def __init__(self, route="update"):
        self.project_alias = {"111": "p1"}
        self.transfer_service_state = {PROJECT: "enabled"}
        self.grants = {
            "serviceAccount:service-111@gcp-sa-bigquerydatatransfer.iam.gserviceaccount.com":
                [(PROJECT, "roles/bigquerydatatransfer.serviceAgent", None, {})]}
        self.principals = {}
        self.sas = {"serviceAccount:" + EMAIL: SimpleNamespace(
            id="serviceAccount:" + EMAIL, attrs={"email": EMAIL, "resource": SA_RESOURCE})}
        self.bigquery_datasets = {DEST: {"location": "US"}, SOURCE: {"location": "US"}}
        self.resource_policy_status = {"bigquery_dataset": {DEST: "collected", SOURCE: "collected"},
                                       "bigquery_table": {TABLE: "collected"}}
        self.resource_inventory_status = {"bigquery_table": {PROJECT: "collected"}}
        self.iam_policy_inventory_status = {PROJECT: "collected", "projects/p2": "collected"}
        self.iam_role_inventory_status = {PROJECT: "collected", "projects/p2": "collected"}
        self.bigquery_row_policy_status = {TABLE: "collected"}
        self.bigquery_row_policies = {TABLE: []}
        self.bigquery_tables = {TABLE: {"type": "TABLE", "_schema_full": True,
            "schema": {"fields": [{"name": "value"}]},
            "_coverage": {"tableDetails": {"status": "collected"}}}}
        self.transfer_configs = {CONFIG: {"project": PROJECT, "dataset": DEST, "disabled": False}}
        self.allowed = {
            ("caller", "iam.serviceAccounts.actAs", SA_RESOURCE),
            ("caller", "bigquery.datasets.get", DEST),
            ("caller", "bigquery.tables.getData", DEST),
            ("serviceAccount:" + EMAIL, "bigquery.jobs.create", PROJECT),
            ("serviceAccount:" + EMAIL, "bigquery.datasets.get", DEST),
            ("serviceAccount:" + EMAIL, "bigquery.tables.create", DEST),
            ("serviceAccount:" + EMAIL, "bigquery.tables.getData", TABLE),
        }
        if route == "update":
            self.allowed.update({("caller", "bigquery.transfers.update", PROJECT)})
        elif route == "jobs":
            self.allowed.update({("caller", "bigquery.jobs.create", PROJECT),
                                 ("caller", "bigquery.transfers.get", PROJECT)})
        elif route == "config":
            self.allowed.update({("caller", "bigquery.transfers.update", CONFIG),
                                 ("caller", "bigquery.transfers.get", CONFIG)})

    def check(self, principal, req, resource):
        return True if (principal.id, req["action"], resource) in self.allowed else None


def path(model):
    return select(model, {"target": SimpleNamespace(attrs={"project": PROJECT, "email": EMAIL},
                                                     scope=PROJECT)}, SimpleNamespace(id="caller"))


def test_both_documented_creation_alternatives_and_existing_config_update():
    for route in ("update", "jobs", "config"):
        assert path(Model(route)) == {"target": ("conditional", "scheduled_query_exact_table_read_gain")}
    model = Model("jobs")
    model.transfer_configs.clear()
    assert path(model) == {"target": ("conditional", "scheduled_query_exact_table_read_gain")}


def test_no_gain_when_caller_already_reads_source_table():
    model = Model()
    model.allowed.add(("caller", "bigquery.tables.getData", TABLE))
    assert path(model) == {}


def test_no_path_when_api_is_disabled_or_location_mismatches():
    model = Model()
    model.transfer_service_state[PROJECT] = "disabled"
    assert path(model) == {}
    model = Model()
    model.bigquery_datasets[SOURCE]["location"] = "EU"
    assert path(model) == {}


def test_missing_agent_or_destination_execution_is_unresolved():
    model = Model()
    model.grants.clear()
    assert path(model)["target"][0] == "unknown"
    model = Model()
    model.allowed.remove(("serviceAccount:" + EMAIL, "bigquery.tables.create", DEST))
    assert path(model)["target"][0] == "unknown"


def test_incomplete_iam_or_protected_table_stays_unresolved():
    model = Model()
    model.iam_policy_inventory_status["projects/p2"] = "denied"
    assert path(model)["target"][0] == "unknown"
    model = Model()
    model.bigquery_tables[TABLE]["schema"]["fields"][0]["policyTags"] = {"names": ["restricted"]}
    assert path(model)["target"][0] == "unknown"


def test_catalog_evaluator_keeps_only_exact_scheduled_query_gain():
    from peaso import privesc
    from peaso.privesc.effective_permissions.gcp import GcpModel
    from peaso.privesc.evaluator import Evaluator

    def row(kind, scope, entries, status="collected"):
        return {"type": kind, "scope": scope, "service": kind, "status": status, "items": entries,
                "error": None}

    caller_role = PROJECT + "/roles/scheduler"
    runner_role = PROJECT + "/roles/runner"
    reader_role = "projects/p2/roles/privateReader"
    agent = "serviceAccount:service-111@gcp-sa-bigquerydatatransfer.iam.gserviceaccount.com"
    collections = [
        row("project", PROJECT, [{"projectId": "p1", "name": "projects/111"}]),
        row("project", "projects/p2", [{"projectId": "p2", "name": "projects/222"}]),
        row("iam_role", PROJECT, [
            {"name": caller_role, "includedPermissions": ["iam.serviceAccounts.actAs",
                "bigquery.transfers.update", "bigquery.datasets.get", "bigquery.tables.getData"]},
            {"name": runner_role, "includedPermissions": ["bigquery.jobs.create",
                "bigquery.datasets.get", "bigquery.tables.create"]}]),
        row("iam_role", "projects/p2", [{"name": reader_role,
            "includedPermissions": ["bigquery.tables.getData"]}]),
        row("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": caller_role, "members": ["user:operator@example.com"]},
            {"role": runner_role, "members": ["serviceAccount:" + EMAIL]},
            {"role": "roles/bigquerydatatransfer.serviceAgent", "members": [agent]}]}]),
        row("iam_policy", "projects/p2", [{"name": "projects/p2", "bindings": [
            {"role": reader_role, "members": ["serviceAccount:" + EMAIL]}]}]),
        row("service_account", PROJECT, [{"email": EMAIL, "projectId": "p1"}]),
        row("service_usage", PROJECT, [{"name": PROJECT + "/services/bigquerydatatransfer.googleapis.com",
                                          "state": "ENABLED"}]),
        row("bigquery_dataset", PROJECT, [{"name": DEST, "location": "US", "access": [],
            "_coverage": {"datasetDetails": {"status": "collected"}}}]),
        row("bigquery_dataset", "projects/p2", [{"name": SOURCE, "location": "US", "access": [],
            "_coverage": {"datasetDetails": {"status": "collected"}}}]),
        row("bigquery_table", "projects/p2", [{"name": TABLE, "type": "TABLE",
            "schema": {"fields": [{"name": "value"}]}, "_schema_full": True,
            "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"},
                          "tableDetails": {"status": "collected"}}}]),
        row("bigquery_row_policy_inventory", "projects/p2", [{"name": TABLE + "/rowAccessPolicyInventory",
            "table": TABLE, "status": "collected", "policies": []}]),
        row("iam_deny_policy", PROJECT, [], "empty"),
        row("iam_deny_policy", "projects/p2", [], "empty"),
    ]
    snap = {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT, "projects/p2"],
            "collections": collections, "metadata": {}}
    entry = next(e for e in privesc.catalog()["entries"]
                 if e["id"] == "gcp-bigquery-transfers-scheduled-query-actas")
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    found = [(tid, grant.confidence) for reach in reaches
             if reach.source.id == "user:operator@example.com"
             for tid, grant in reach.targets.items()]
    assert len(found) == 1
    assert found[0][0].startswith("gcp_verified_authority:bigquery_scheduled_query:")
    assert found[0][1] == "conditional"
