"""A Spark connection must bind its service identity to its exact native resource."""

from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso import privesc
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
NAME = PROJECT + "/locations/US/connections/spark1"
EMAIL = "bqcx-123@gcp-sa-bigquery-consp.iam.gserviceaccount.com"


def snapshot(*, detail="collected", policy="collected", email=EMAIL, duplicate=False):
    connection = {"name": NAME, "spark": {"serviceAccountId": email},
                  "_coverage": {"connectionDetails": {"status": detail},
                                "iamPolicy": {"status": policy}},
                  "iamPolicy": {"bindings": [{"role": PROJECT + "/roles/connectionUser",
                                              "members": ["user:editor@example.com"]}]}}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT], "metadata": {},
            "collections": [{"type": "project", "scope": PROJECT, "service": "project",
                             "status": "collected", "items": [{"projectId": "p1", "name": "projects/111"}]},
                            {"type": "iam_role", "scope": PROJECT, "service": "iam",
                             "status": "collected", "items": [{"name": PROJECT + "/roles/connectionUser",
                               "includedPermissions": ["bigquery.connections.use"]}]},
                            {"type": "bigquery_dataset", "scope": PROJECT, "service": "bigquery",
                             "status": "collected", "items": [{"name": PROJECT + "/datasets/private",
                               "location": "US", "access": [], "_coverage": {"datasetDetails":
                                   {"status": "collected"}}}]},
                            {"type": "bigquery_routine_metadata", "scope": PROJECT,
                             "service": "bigquery", "status": "collected", "items": [{
                               "name": PROJECT + "/datasets/private/routines/existing_spark",
                               "routineType": "PROCEDURE", "language": "PYTHON",
                               "datasetLocation": "US"}]},
                            {"type": "bigquery_connection", "scope": PROJECT,
                             "service": "bigqueryconnection", "status": "collected",
                             "items": [connection, dict(connection)] if duplicate else [connection]}]}


def test_exact_spark_identity_and_policy_are_bound():
    model = GcpModel(snapshot())
    assert model.spark_connections[NAME]["identity"].id == "serviceAccount:" + EMAIL
    assert model.spark_connections[NAME]["location"] == "US"
    assert model.hosts[EMAIL]["bigquery_spark_connection"] == [NAME]
    assert model.host_status[(PROJECT, "bigquery_spark_connection")] == "collected"
    assert model.spark_routines[PROJECT + "/datasets/private/routines/existing_spark"] == {
        "dataset": PROJECT + "/datasets/private", "location": "US"}
    assert model.check(model.principals["user:editor@example.com"],
                       {"action": "bigquery.connections.use"}, NAME) is not None


def test_incomplete_or_duplicate_details_never_create_an_attachment():
    for snap in (snapshot(detail="denied"), snapshot(email="not-an-email"),
                 snapshot(duplicate=True)):
        model = GcpModel(snap)
        assert NAME not in model.spark_connections
        assert model.host_status[(PROJECT, "bigquery_spark_connection")] == "partial"


def test_denied_policy_preserves_identity_but_no_direct_connection_grant():
    model = GcpModel(snapshot(policy="denied"))
    assert model.spark_connections[NAME]["policy_status"] == "denied"
    assert "user:editor@example.com" not in model.principals


def path_snapshot(*, writer=None, target_permissions=("storage.objects.get",),
                  location="US", routine_status="collected", policy="collected"):
    snap = snapshot(policy=policy)
    snap["collections"][2]["items"][0]["location"] = location
    snap["collections"][3]["status"] = routine_status
    snap["collections"][4]["items"][0]["iamPolicy"] = {"bindings": []}
    writer = writer if writer is not None else (
        "bigquery.jobs.create", "bigquery.routines.create", "bigquery.routines.get",
        "bigquery.connections.delegate", "bigquery.connections.use")
    snap["collections"][1]["items"].extend([
        {"name": PROJECT + "/roles/writer", "includedPermissions": list(writer)},
        {"name": PROJECT + "/roles/target", "includedPermissions": list(target_permissions)}])
    snap["collections"].extend([
        {"type": "iam_policy", "scope": PROJECT, "status": "collected", "items": [{
            "name": PROJECT, "bindings": [
                {"role": PROJECT + "/roles/writer", "members": ["user:editor@example.com"]},
                {"role": PROJECT + "/roles/target", "members": ["serviceAccount:" + EMAIL]}]}]},
        {"type": "group_membership", "scope": PROJECT, "status": "empty", "items": []},
        {"type": "iam_deny_policy", "scope": PROJECT, "status": "empty", "items": []}])
    return snap


def reaches(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] ==
              "gcp-bigquery-spark-procedure-connection-identity"]
    return [(target, grant.confidence) for reach in Evaluator(GcpModel(snap), [entry]).run()
            if reach.source.id == "user:editor@example.com" for target, grant in reach.targets.items()]


def test_create_path_requires_compatible_dataset_connection_and_new_permission():
    assert ("serviceAccount:" + EMAIL, "conditional") in reaches(path_snapshot())
    assert ("serviceAccount:" + EMAIL, "conditional") in reaches(
        path_snapshot(routine_status="denied"))
    assert ("serviceAccount:" + EMAIL, "conditional") not in reaches(
        path_snapshot(target_permissions=("bigquery.jobs.create",)))
    assert ("serviceAccount:" + EMAIL, "conditional") not in reaches(path_snapshot(location="EU"))
    assert ("serviceAccount:" + EMAIL, "conditional") not in reaches(path_snapshot(writer=(
        "bigquery.jobs.create", "bigquery.routines.create", "bigquery.routines.get",
        "bigquery.connections.use")))
    for missing in ("bigquery.jobs.create", "bigquery.routines.get", "bigquery.connections.use"):
        writer = ("bigquery.jobs.create", "bigquery.routines.create", "bigquery.routines.get",
                  "bigquery.connections.delegate", "bigquery.connections.use")
        assert ("serviceAccount:" + EMAIL, "conditional") not in reaches(
            path_snapshot(writer=tuple(action for action in writer if action != missing)))


def test_existing_spark_procedure_allows_exact_update_path():
    writer = ("bigquery.jobs.create", "bigquery.routines.update", "bigquery.routines.get",
              "bigquery.connections.delegate", "bigquery.connections.use")
    assert ("serviceAccount:" + EMAIL, "conditional") in reaches(path_snapshot(writer=writer))
    assert ("serviceAccount:" + EMAIL, "conditional") not in reaches(
        path_snapshot(writer=writer, routine_status="denied"))


def test_policy_write_without_delegate_is_only_unresolved():
    writer = ("bigquery.jobs.create", "bigquery.routines.create", "bigquery.routines.get",
              "bigquery.connections.setIamPolicy")
    assert ("serviceAccount:" + EMAIL, "conditional") not in reaches(path_snapshot(writer=writer))
    snap = path_snapshot(writer=writer)
    snap["collections"].append({"type": "org_policy_effective", "scope": PROJECT,
                                "status": "empty", "items": []})
    assert ("serviceAccount:" + EMAIL, "conditional") in reaches(snap)
    restricted = path_snapshot(writer=writer)
    restricted["collections"].append({"type": "org_policy_effective", "scope": PROJECT,
        "status": "collected", "items": [{"constraint": "iam.allowedPolicyMemberDomains",
                                          "name": PROJECT + "/policies/allowedPolicyMemberDomains"}]})
    assert ("serviceAccount:" + EMAIL, "conditional") not in reaches(restricted)
    denied = path_snapshot(writer=writer, policy="denied")
    denied["collections"].append({"type": "org_policy_effective", "scope": PROJECT,
                                  "status": "empty", "items": []})
    assert ("serviceAccount:" + EMAIL, "conditional") not in reaches(denied)


def test_missing_project_iam_evidence_prevents_a_definite_permission_gain():
    snap = path_snapshot()
    next(row for row in snap["collections"] if row["type"] == "iam_policy")["status"] = "denied"
    assert ("serviceAccount:" + EMAIL, "conditional") not in reaches(snap)
