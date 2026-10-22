"""MWAA Serverless creation checks its actual service-linked role ARN."""
from __future__ import annotations

from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc import versioned_catalog as catalog
from peaso.privesc.schema import load_catalog
from tests.test_peaso_privesc_aws_ext_facts import ACCOUNT, ALICE, SCOPE, aws_snap, role, trust_service, user, allow


SERVICE = "airflow-serverless.amazonaws.com"
SLR = (f"arn:aws:iam::{ACCOUNT}:role/aws-service-role/{SERVICE}/"
       "AWSServiceRoleForAmazonMWAAServerless")


def _route(*, slr_grant=None, existing=False):
    target = role("workflow", trust_service(SERVICE))
    statements = [allow("airflow-serverless:CreateWorkflow"),
                  {"Effect": "Allow", "Action": "iam:PassRole", "Resource": target["Arn"],
                   "Condition": {"StringEquals": {"iam:PassedToService": SERVICE}}}]
    if slr_grant:
        statements.append({"Effect": "Allow", "Action": "iam:CreateServiceLinkedRole",
                           "Resource": slr_grant,
                           "Condition": {"StringEquals": {"iam:AWSServiceName": SERVICE}}})
    roles = [target]
    if existing:
        linked = role("AWSServiceRoleForAmazonMWAAServerless", trust_service(SERVICE))
        linked["Arn"] = SLR
        linked["Path"] = f"/aws-service-role/{SERVICE}/"
        roles.append(linked)
    model = AwsModel(aws_snap([user("alice", *statements)], roles,
                              [("mwaa_serverless_workflow", SCOPE, [], "empty")]))
    return model._mwaa_serverless_new_workflow_route(model.principals[ALICE],
                                                     model.principals[target["Arn"]])


def test_create_service_linked_role_matches_exact_arn():
    assert _route(slr_grant=SLR)[1] == "mwaa_serverless_logging_permission_not_verified"
    assert _route(slr_grant=SLR.replace("AmazonMWAAServerless", "Other"))[1] == (
        "mwaa_serverless_create_or_passrole_not_verified")


def test_existing_service_linked_role_does_not_need_creation_permission():
    assert _route(existing=True)[1] == "mwaa_serverless_logging_permission_not_verified"


def test_current_catalog_makes_service_linked_role_requirement_conditional():
    technique = "aws-mwaa-serverless-passrole-createworkflow"
    current = next(row for row in load_catalog(strict=True)["entries"] if row["id"] == technique)
    assert "iam:CreateServiceLinkedRole" not in {row["action"] for row in current["requires"]["all_of"]}
    old_binding = {"schema": catalog.BINDING_SCHEMA,
                   "manifest_sha256": catalog.MWAA_SLR_690_PREVIOUS_MANIFEST,
                   "effective_tree_sha256": catalog.MWAA_SLR_690_PREVIOUS_TREE,
                   "source_revision": catalog.V4_REVISION}
    old, status = catalog.lookup_entries([technique], old_binding)
    assert status == "exact_previous_current"
    assert "iam:CreateServiceLinkedRole" in {row["action"] for row in old[technique]["requires"]["all_of"]}
    assert catalog.current_binding()["manifest_sha256"] != old_binding["manifest_sha256"]
