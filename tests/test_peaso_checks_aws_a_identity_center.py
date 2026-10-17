"""Ordinary Identity Center metadata enumeration, never credentials or actions."""
import json

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber

from peaso.collectors import aws

REGION = "us-east-1"
ACCOUNT = "123456789012"
INSTANCE = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
STORE = "d-1234567890"
PERMISSION = "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-1234567890abcdef"


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name=REGION)
    clients, stubs = {}, {}
    def add(service):
        if service not in clients:
            clients[service] = session.client(service, region_name=REGION)
            stubs[service] = Stubber(clients[service])
            stubs[service].activate()
        return stubs[service]
    monkeypatch.setattr(aws.Requests, "client", lambda requests, context, service, region: clients[service])
    yield session, add
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def instance_response():
    return {"Instances": [{"InstanceArn": INSTANCE, "IdentityStoreId": STORE, "OwnerAccountId": ACCOUNT}]}


def test_identity_center_instance_discovery_and_users_full_pagination(sdk):
    session, add = sdk
    add("sso-admin").add_response("list_instances", instance_response(), {})
    users = add("identitystore")
    first = {"UserId": "12345678-1234-1234-1234-123456789012", "IdentityStoreId": STORE, "UserName": "reviewer"}
    second = {"UserId": "12345678-1234-1234-1234-123456789013", "IdentityStoreId": STORE, "UserName": "reader"}
    # UserArn/Revision exist only in newer identitystore models; the validating Stubber rejects them on older botocore.
    user_shape = session.client("identitystore", region_name=REGION).meta.service_model.shape_for("User")
    for user in (first, second):
        if "UserArn" in user_shape.members:
            user["UserArn"] = f"arn:aws:identitystore::{ACCOUNT}:user/{user['UserId']}"
        if "Revision" in user_shape.members:
            user["Revision"] = "1"
    users.add_response("list_users", {"Users": [first], "NextToken": "next"}, {"IdentityStoreId": STORE})
    users.add_response("list_users", {"Users": [second]}, {"IdentityStoreId": STORE, "NextToken": "next"})
    requests = aws.Requests({})
    read = aws._identity_center(requests, session, REGION, "aws_identity_center_user")
    assert read.status == "collected"
    assert requests.calls == 3
    assert len(read.items) == 2
    assert read.items[0]["InstanceArn"] == INSTANCE
    assert read.items[0]["InstanceOwnerAccountId"] == ACCOUNT
    assert read.items[0]["id"] != read.items[1]["id"]


def test_permission_set_metadata_inline_managed_and_boundary_without_values(sdk):
    session, add = sdk
    sso = add("sso-admin")
    sso.add_response("list_instances", instance_response(), {})
    sso.add_response("list_permission_sets", {"PermissionSets": [PERMISSION]}, {"InstanceArn": INSTANCE})
    args = {"InstanceArn": INSTANCE, "PermissionSetArn": PERMISSION}
    sso.add_response("describe_permission_set", {"PermissionSet": {"Name": "Review", "PermissionSetArn": PERMISSION, "SessionDuration": "PT1H"}}, args)
    sso.add_response("get_inline_policy_for_permission_set", {"InlinePolicy": '{"Version":"2012-10-17","Statement":[]}'}, args)
    sso.add_response("list_managed_policies_in_permission_set", {"AttachedManagedPolicies": [{"Name": "ReadOnlyAccess", "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]}, args)
    sso.add_response("get_permissions_boundary_for_permission_set", {}, args)
    requests = aws.Requests({})
    read = aws._identity_center(requests, session, REGION, "aws_identity_center_permission_set")
    assert read.status == "collected"
    assert requests.calls == 6
    item = read.items[0]
    assert item["PermissionSetArn"] == PERMISSION
    assert item["InlinePolicy"]["InlinePolicy"]["Statement"] == []
    assert item["AttachedManagedPolicies"]["collection_status"] == "collected"
    assert item["PermissionsBoundary"]["collection_status"] == "collected"
    assert "SecretAccessKey" not in json.dumps(aws._safe(read.items))


@pytest.mark.parametrize("kind", ["aws_identity_center_user", "aws_identity_center_permission_set"])
def test_empty_instance_discovery_is_known_empty(sdk, kind):
    session, add = sdk
    add("sso-admin").add_response("list_instances", {"Instances": []}, {})
    read = aws._identity_center(aws.Requests({}), session, REGION, kind)
    assert read.status == "empty"
    assert read.items == []


@pytest.mark.parametrize("kind", ["aws_identity_center_user", "aws_identity_center_permission_set"])
def test_instance_discovery_permission_denial_is_not_empty(sdk, kind):
    session, add = sdk
    add("sso-admin").add_client_error("list_instances", "AccessDeniedException", expected_params={})
    read = aws._identity_center(aws.Requests({}), session, REGION, kind)
    assert read.status == "denied"
    assert read.items == []


def test_user_list_denial_retains_explicit_unavailable_coverage(sdk):
    session, add = sdk
    add("sso-admin").add_response("list_instances", instance_response(), {})
    add("identitystore").add_client_error("list_users", "AccessDeniedException", expected_params={"IdentityStoreId": STORE})
    read = aws._identity_center(aws.Requests({}), session, REGION, "aws_identity_center_user")
    assert read.status == "denied"
    assert read.error["code"] == "AccessDeniedException"


def test_malformed_instance_store_mapping_is_not_fabricated(sdk):
    session, add = sdk
    add("sso-admin").add_response("list_instances", {"Instances": [{"InstanceArn": INSTANCE}]}, {})
    read = aws._identity_center(aws.Requests({}), session, REGION, "aws_identity_center_user")
    assert read.status == "malformed"
    assert read.error["code"] == "missing_identity_store_id"
