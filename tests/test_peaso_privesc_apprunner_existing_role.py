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
ECR_ENTRY = next(row for row in load_catalog()["entries"] if row["id"] == "aws-apprunner-mutable-ecr-autodeploy")
REPOSITORY = f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/app"
IMAGE = f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/app:stable"


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


def _ecr_snapshot(*, role=ROLE, auto=True, mutability="MUTABLE", image=IMAGE, omit_action=None,
                  filters=None, can_change_mutability=False):
    actions = ["ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload",
               "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage"]
    actions = [action for action in actions if action != omit_action]
    if can_change_mutability:
        actions.append("ecr:PutImageTagMutability")
    alice = {"UserName": "alice", "Arn": USER, "GroupList": [], "AttachedManagedPolicies": [],
             "UserPolicyList": [{"PolicyName": "push", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                 {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
                 {"Effect": "Allow", "Action": actions, "Resource": REPOSITORY}]}}]}
    target = {"RoleName": "app", "Arn": ROLE, "Path": "/", "RolePolicyList": [], "AttachedManagedPolicies": [],
              "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                  {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "tasks.apprunner.amazonaws.com"}}]}}
    service = {"ServiceArn": SERVICE, "Status": "RUNNING", "NetworkDetails": {
        "InstanceRoleArn": role, "SourceType": "IMAGE", "AutoDeploymentsEnabled": auto, "ImageIdentifier": image}}
    repository = {"repositoryArn": REPOSITORY, "repositoryUri": IMAGE.rsplit(":", 1)[0],
                  "repositoryName": "app", "imageTagMutability": mutability}
    if filters is not None:
        repository["imageTagMutabilityExclusionFilters"] = [
            {"filterType": "WILDCARD", "filter": value} for value in filters]
    rows = [("iam_user", [alice]), ("iam_role", [target]), ("iam_group", []), ("iam_policy", []),
            ("scp_policy", []), ("app_runner_service", [service]), ("ecr_repository", [repository])]
    return {"schema_version": 1, "provider": "aws", "scopes": [f"{ACCOUNT}/us-east-1"], "metadata": {},
            "collections": [{"type": kind, "service": kind, "scope": f"{ACCOUNT}/us-east-1",
                             "status": "collected" if items else "empty", "items": items, "error": None}
                            for kind, items in rows]}


def test_mutable_ecr_tag_autodeployment_joins_exact_role_and_push_permissions():
    def edges(snapshot):
        from peaso.privesc.effective_permissions.aws import AwsModel
        model = AwsModel(snapshot)
        return {target: verdict[0] for target, verdict in model.precondition(
            "apprunner_mutable_ecr_autodeploy_instance_role", {ROLE: model.principals[ROLE]},
            model.principals[USER]).items()}

    assert edges(_ecr_snapshot()) == {ROLE: "conditional"}
    assert edges(_ecr_snapshot(role=OTHER)) == {}
    assert edges(_ecr_snapshot(auto=False)) == {}
    assert edges(_ecr_snapshot(mutability="IMMUTABLE")) == {}
    assert edges(_ecr_snapshot(mutability="IMMUTABLE", can_change_mutability=True)) == {ROLE: "conditional"}
    assert edges(_ecr_snapshot(mutability="IMMUTABLE_WITH_EXCLUSION", filters=["sta*"])) == {ROLE: "conditional"}
    assert edges(_ecr_snapshot(mutability="MUTABLE_WITH_EXCLUSION", filters=["sta*"])) == {}
    assert edges(_ecr_snapshot(mutability="IMMUTABLE_WITH_EXCLUSION")) == {ROLE: "unknown"}
    assert edges(_ecr_snapshot(image=IMAGE.replace(":stable", ":other"))) == {ROLE: "conditional"}
    assert edges(_ecr_snapshot(image=IMAGE.replace("/app:", "/different:"))) == {}
    assert edges(_ecr_snapshot(omit_action="ecr:PutImage")) == {}


def test_ecr_authorization_token_requires_global_resource_grant():
    from peaso.privesc.effective_permissions.aws import AwsModel

    scoped = _ecr_snapshot()
    user = next(c for c in scoped["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]["Resource"] = REPOSITORY
    model = AwsModel(scoped)
    verdicts = model.precondition("apprunner_mutable_ecr_autodeploy_instance_role",
                                  {ROLE: model.principals[ROLE]}, model.principals[USER])
    assert ROLE not in verdicts or verdicts[ROLE][0] != "conditional"


def test_app_runner_projection_keeps_only_image_identity_and_auto_deployment_flag():
    from peaso.collectors.aws_network_catalog import MetadataClient, detail_enricher

    class Native:
        def describe_service(self, **arguments):
            return {"Service": {"ServiceArn": SERVICE, "InstanceConfiguration": {"InstanceRoleArn": ROLE},
                    "SourceConfiguration": {"AutoDeploymentsEnabled": True,
                        "ImageRepository": {"ImageIdentifier": IMAGE, "ImageConfiguration": {
                            "RuntimeEnvironmentVariables": {"TOKEN": "SECRET_SENTINEL"}}}}}}

    projected = MetadataClient(Native(), "apprunner").describe_service(ServiceArn=SERVICE)
    assert "SECRET_SENTINEL" not in json.dumps(projected)

    class Requests:
        def call(self, session, service, region, operation, **arguments):
            return projected

    rows = detail_enricher("app_runner_service")(Requests(), None, "us-east-1", [{"ServiceArn": SERVICE}])
    detail = rows[0]["NetworkDetails"]
    assert detail["ImageIdentifier"] == IMAGE
    assert detail["AutoDeploymentsEnabled"] is True
    assert "SECRET_SENTINEL" not in json.dumps(rows)


def test_current_and_previous_catalog_bindings_stay_exact():
    current = versioned_catalog.current_binding()
    entries, status = versioned_catalog.lookup_entries(["aws-apprunner-updateservice"], current)
    assert status == "exact_strict_privesc" and set(entries) == {"aws-apprunner-updateservice"}
    entries, status = versioned_catalog.lookup_entries(["aws-apprunner-mutable-ecr-autodeploy"], current)
    assert status == "exact_strict_privesc" and set(entries) == {"aws-apprunner-mutable-ecr-autodeploy"}
    prior = {"schema": versioned_catalog.BINDING_SCHEMA,
             "manifest_sha256": versioned_catalog.SAGEMAKER_LCC_677_PREVIOUS_MANIFEST,
             "effective_tree_sha256": versioned_catalog.SAGEMAKER_LCC_677_PREVIOUS_TREE,
             "source_revision": versioned_catalog.V4_REVISION}
    entries, status = versioned_catalog.lookup_entries(
        ["aws-apprunner-updateservice", "aws-apprunner-mutable-ecr-autodeploy"], prior)
    assert status == "exact_previous_current" and set(entries) == {"aws-apprunner-updateservice"}
    old = {"schema": versioned_catalog.BINDING_SCHEMA,
           "manifest_sha256": versioned_catalog.BATCH_CURRENT_MANIFEST,
           "effective_tree_sha256": versioned_catalog.BATCH_CURRENT_TREE,
           "source_revision": versioned_catalog.V4_REVISION}
    entries, status = versioned_catalog.lookup_entries(["aws-apprunner-updateservice"], old)
    assert status == "exact_previous_current" and entries == {}
    assert len(versioned_catalog._verified_batch_current()) == 665
