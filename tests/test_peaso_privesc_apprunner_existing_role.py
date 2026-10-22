"""App Runner updates must bind the service to its recorded instance role."""
import json

from peaso import privesc
from peaso.privesc.schema import load_catalog
from peaso.privesc import versioned_catalog


ACCOUNT = "111111111111"
USER = f"arn:aws:iam::{ACCOUNT}:user/alice"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/app"
OTHER = f"arn:aws:iam::{ACCOUNT}:role/other"
SERVICE = f"arn:aws:apprunner:us-east-1:{ACCOUNT}:service/app/one"
ENTRY = next(row for row in load_catalog()["entries"] if row["id"] == "aws-apprunner-updateservice")


def _snapshot(*, role=ROLE, service=SERVICE, status="RUNNING", source_type="IMAGE", permission=True):
    statement = {"Effect": "Allow", "Action": "apprunner:UpdateService", "Resource": SERVICE}
    alice = {"UserName": "alice", "Arn": USER, "GroupList": [], "AttachedManagedPolicies": [],
             "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": [statement]}}] if permission else []}
    roles = [{"RoleName": name, "Arn": arn, "Path": "/", "RolePolicyList": [], "AttachedManagedPolicies": [],
              "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "tasks.apprunner.amazonaws.com"}}]}}
             for name, arn in (("app", ROLE), ("other", OTHER))]
    app = {"ServiceArn": service, "Status": status, "NetworkDetails": {"InstanceRoleArn": role, "SourceType": source_type}}
    collections = [("iam_user", [alice]), ("iam_role", roles), ("iam_group", []), ("iam_policy", []),
                   ("scp_policy", []), ("app_runner_service", [app])]
    return {"schema_version": 1, "provider": "aws", "scopes": [f"{ACCOUNT}/us-east-1"], "metadata": {},
            "collections": [{"type": kind, "service": kind, "scope": f"{ACCOUNT}/us-east-1", "status": "collected" if rows else "empty", "items": rows, "error": None}
                            for kind, rows in collections]}


def _edges(snapshot):
    graph = privesc.analyze(snapshot, entries=[ENTRY])["graph"]
    return {edge["target"]: edge["confidence"] for edge in graph["edges"] if edge["source"] == USER}


def test_existing_role_update_targets_only_recorded_instance_role():
    assert _edges(_snapshot()) == {ROLE: "conditional"}
    assert _edges(_snapshot(role=OTHER)) == {OTHER: "conditional"}


def test_existing_role_update_rejects_wrong_service_state_and_permission():
    assert _edges(_snapshot(service=SERVICE.replace("us-east-1", "eu-west-1"))) == {}
    assert _edges(_snapshot(status="DELETED")) == {}
    assert _edges(_snapshot(source_type="CODE")) == {}
    assert _edges(_snapshot(permission=False)) == {}


def test_app_runner_projection_keeps_role_and_source_type_without_variables():
    from peaso.collectors.aws_network_catalog import detail_enricher

    class Requests:
        def call(self, session, service, region, operation, **arguments):
            return {"Service": {"ServiceArn": SERVICE, "InstanceConfiguration": {"InstanceRoleArn": ROLE},
                    "SourceConfiguration": {"ImageRepository": {"ImageIdentifier": "public.ecr.aws/example/image:latest",
                        "ImageConfiguration": {"RuntimeEnvironmentVariables": {"TOKEN": "SECRET_SENTINEL"}}}}}}

    rows = detail_enricher("app_runner_service")(Requests(), None, "us-east-1", [{"ServiceArn": SERVICE}])
    assert rows[0]["NetworkDetails"]["InstanceRoleArn"] == ROLE
    assert rows[0]["NetworkDetails"]["SourceType"] == "IMAGE"
    assert "SECRET_SENTINEL" not in json.dumps(rows)


def test_current_and_previous_catalog_bindings_stay_exact():
    current = versioned_catalog.current_binding()
    entries, status = versioned_catalog.lookup_entries(["aws-apprunner-updateservice"], current)
    assert status == "exact_strict_privesc" and set(entries) == {"aws-apprunner-updateservice"}
    old = {"schema": versioned_catalog.BINDING_SCHEMA,
           "manifest_sha256": versioned_catalog.BATCH_CURRENT_MANIFEST,
           "effective_tree_sha256": versioned_catalog.BATCH_CURRENT_TREE,
           "source_revision": versioned_catalog.V4_REVISION}
    entries, status = versioned_catalog.lookup_entries(["aws-apprunner-updateservice"], old)
    assert status == "exact_previous_current" and entries == {}
    assert len(versioned_catalog._verified_batch_current()) == 665
