"""Privesc joins over the aws_facts_ext collector facts: Cognito group / identity-pool roles, CodeDeploy deployment-group
instance roles, Roles Anywhere profiles and trust anchors, SageMaker / Image Builder hosts, application planes and
Identity Center group assignments. Collected joins decide membership; missing joins stay unresolved (never FAIL)."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc import MODELS

from test_peaso_privesc_followups import ACCOUNT, ALICE, aws_snap, catalog_entry as active_catalog_entry, archived_catalog_entry, edges, pol, reached, role, trust_service, user


HISTORICAL = {
    "aws-cognito-adminaddusertogroup", "aws-cognito-admincreateuser",
    "aws-codedeploy-createdeployment-instance-roles",
    "aws-rolesanywhere-updateprofile-remove-session-policy",
    "aws-quicksight-updateuser-admin", "aws-identitystore-creategroupmembership",
}


def catalog_entry(eid):
    """Exercise old join behavior from its immutable archive, with active exclusion asserted."""
    return archived_catalog_entry(eid) if eid in HISTORICAL else active_catalog_entry(eid)

REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
POOL_ID = "us-east-1_Pool1"
POOL = f"arn:aws:cognito-idp:{REGION}:{ACCOUNT}:userpool/{POOL_ID}"


def arn(name):
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def trust_federated(provider):
    return pol({"Effect": "Allow", "Principal": {"Federated": provider}, "Action": "sts:AssumeRoleWithWebIdentity"})


def allow(action, resource="*"):
    return {"Effect": "Allow", "Action": action, "Resource": resource}


def nodes(result):
    return {n["id"]: n for n in result["graph"]["nodes"]}


def model(snap):
    return MODELS["aws"](snap)


# --- Cognito -------------------------------------------------------------------------------------------
def _cognito_roles():
    return [role("admin", trust_federated("cognito-identity.amazonaws.com")), role("other", trust_federated("cognito-identity.amazonaws.com"))]


def test_user_pool_group_role_reached_only_through_its_pool():
    pools = ("cognito_user_pool", SCOPE, [{"Id": POOL_ID, "Groups": {"collection_status": "collected",
             "items": [{"GroupName": "admins", "RoleArn": arn("admin"), "Precedence": 1}]}}])
    entry = catalog_entry("aws-cognito-adminaddusertogroup")
    result = privesc.analyze(aws_snap([user("alice", allow("cognito-idp:AdminAddUserToGroup", POOL))], _cognito_roles(), [pools]),
                             entries=[entry])
    assert set(reached(result, ALICE)) == {arn("admin")}
    other_pool = POOL.replace("Pool1", "Pool2")
    result = privesc.analyze(aws_snap([user("alice", allow("cognito-idp:AdminAddUserToGroup", other_pool))], _cognito_roles(), [pools]),
                             entries=[entry])
    assert reached(result, ALICE) == {}


def test_user_pool_groups_not_collected_stay_unresolved():
    pools = ("cognito_user_pool", SCOPE, [{"Id": POOL_ID, "Groups": {"collection_status": "denied", "items": []}}])
    result = privesc.analyze(aws_snap([user("alice", allow("cognito-idp:AdminAddUserToGroup"))], _cognito_roles(), [pools]),
                             entries=[catalog_entry("aws-cognito-adminaddusertogroup")], include_unknown=True)
    targets = [nodes(result)[e["target"]] for e in edges(result, ALICE)]
    assert targets and all(t["id"].startswith("unresolved:") for t in targets)


def test_identity_pool_authenticated_role_of_federated_user_pool():
    identity = ("cognito_identity_pool", SCOPE, [{"IdentityPoolId": "us-east-1:abc",
        "Configuration": {"collection_status": "collected", "CognitoIdentityProviders": [
            {"ProviderName": f"cognito-idp.{REGION}.amazonaws.com/{POOL_ID}", "ClientId": "c"}]},
        "Roles": {"collection_status": "collected", "Roles": {"authenticated": arn("admin")}}}])
    result = privesc.analyze(aws_snap([user("alice", allow("cognito-idp:AdminCreateUser", POOL))], _cognito_roles(), [identity]),
                             entries=[catalog_entry("aws-cognito-admincreateuser")])
    assert set(reached(result, ALICE)) == {arn("admin")}


# --- CodeDeploy ------------------------------------------------------------------------------------------
def _instance(iid, profile, env):
    return {"InstanceId": iid, "State": {"Name": "running"}, "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/{profile}"},
            "Tags": [{"Key": "Env", "Value": env}]}


def test_codedeploy_group_reaches_tag_matched_instance_roles():
    roles = [role("app", trust_service("ec2.amazonaws.com"), profile=True), role("idle", trust_service("ec2.amazonaws.com"), profile=True)]
    extra = [("instance", SCOPE, [_instance("i-1", "app", "prod"), _instance("i-2", "idle", "dev")]),
             ("codedeploy_deployment_group", SCOPE, [{"applicationName": "web", "deploymentGroupName": "prod", "computePlatform": "Server",
              "ec2TagFilters": [{"Key": "Env", "Value": "prod", "Type": "KEY_AND_VALUE"}]}])]
    alice = user("alice", allow("codedeploy:*"))
    result = privesc.analyze(aws_snap([alice], roles, extra), entries=[catalog_entry("aws-codedeploy-createdeployment-instance-roles")])
    assert set(reached(result, ALICE)) == {arn("app")}
    hosts = model(aws_snap([alice], roles, extra)).hosts[arn("app")]["codedeploy_deployment_group"]
    assert hosts == [f"arn:aws:codedeploy:{REGION}:{ACCOUNT}:deploymentgroup:web/prod"]


def test_codedeploy_auto_scaling_group_matched_by_instance_tag():
    roles = [role("app", trust_service("ec2.amazonaws.com"), profile=True)]
    inst = _instance("i-1", "app", "x")
    inst["Tags"].append({"Key": "aws:autoscaling:groupName", "Value": "web-asg"})
    extra = [("instance", SCOPE, [inst]), ("codedeploy_deployment_group", SCOPE, [{"applicationName": "web", "deploymentGroupName": "g",
              "ec2TagFilters": [], "autoScalingGroups": [{"name": "web-asg"}]}])]
    m = model(aws_snap([user("alice")], roles, extra))
    assert m.hosts[arn("app")]["codedeploy_deployment_group"]


# --- Roles Anywhere ---------------------------------------------------------------------------------------
def test_rolesanywhere_profile_membership_and_profile_arn():
    profile = f"arn:aws:rolesanywhere:{REGION}:{ACCOUNT}:profile/p1"
    anchor = f"arn:aws:rolesanywhere:{REGION}:{ACCOUNT}:trust-anchor/t1"
    roles = [role("edge", trust_service("rolesanywhere.amazonaws.com")), role("spare", trust_service("rolesanywhere.amazonaws.com"))]
    extra = [("rolesanywhere_profile", SCOPE, [{"profileArn": profile, "enabled": True, "roleArns": [arn("edge")]}]),
             ("rolesanywhere_trust_anchor", SCOPE, [{"trustAnchorArn": anchor, "enabled": True}])]
    result = privesc.analyze(aws_snap([user("alice", allow("rolesanywhere:UpdateProfile", profile))], roles, extra),
                             entries=[catalog_entry("aws-rolesanywhere-updateprofile-remove-session-policy")])
    assert set(reached(result, ALICE)) == {arn("edge")}
    result = privesc.analyze(aws_snap([user("alice", allow("rolesanywhere:UpdateTrustAnchor", anchor))], roles, extra),
                             entries=[catalog_entry("aws-rolesanywhere-updatetrustanchor")])
    assert set(reached(result, ALICE)) == {arn("edge")}
    result = privesc.analyze(aws_snap([user("alice", allow("rolesanywhere:UpdateTrustAnchor", anchor + "x"))], roles, extra),
                             entries=[catalog_entry("aws-rolesanywhere-updatetrustanchor")])
    assert reached(result, ALICE) == {}


# --- SageMaker / Image Builder hosts ---------------------------------------------------------------------
def test_sagemaker_user_profile_execution_role_host():
    profile = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:user-profile/d-1/alice"
    roles = [role("sm", trust_service("sagemaker.amazonaws.com")), role("sm2", trust_service("sagemaker.amazonaws.com"))]
    extra = [("sagemaker_user_profile", SCOPE, [{"DomainId": "d-1", "UserProfileName": "alice", "UserProfileArn": profile,
                                                 "ExecutionRole": arn("sm"), "ExecutionRoleSource": "user_settings"}])]
    result = privesc.analyze(aws_snap([user("alice", allow("sagemaker:CreatePresignedDomainUrl", profile))], roles, extra),
                             entries=[catalog_entry("aws-sagemaker-createpresigneddomainurl")])
    assert set(reached(result, ALICE)) == {arn("sm")}


def test_imagebuilder_and_hyperpod_hosts_loaded():
    roles = [role("builder", trust_service("ec2.amazonaws.com"), profile=True), role("hp", trust_service("sagemaker.amazonaws.com"))]
    pipeline = f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:image-pipeline/p"
    cluster = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:cluster/c"
    extra = [("imagebuilder_pipeline", SCOPE, [{"arn": pipeline, "InstanceProfileName": "builder"}]),
             ("sagemaker_cluster", SCOPE, [{"ClusterArn": cluster, "InstanceGroups": [{"InstanceGroupName": "g", "ExecutionRole": arn("hp")}]}])]
    m = model(aws_snap([user("alice")], roles, extra))
    assert m.hosts[arn("builder")]["imagebuilder_pipeline"] == [pipeline]
    assert m.hosts[arn("hp")]["sagemaker_cluster"] == [cluster]
    assert m.host_status[(ACCOUNT, "imagebuilder_pipeline")] == "collected"


# --- application planes / Identity Center -----------------------------------------------------------------
def test_grafana_workspace_is_a_service_plane_target():
    ws = f"arn:aws:grafana:{REGION}:{ACCOUNT}:/workspaces/g-1"
    extra = [("grafana_workspace", SCOPE, [{"id": "g-1", "Arn": ws}])]
    entry = catalog_entry("aws-grafana-createworkspaceapikey-admin")
    result = privesc.analyze(aws_snap([user("alice", allow("grafana:CreateWorkspaceApiKey", ws))], [], extra), entries=[entry])
    assert set(reached(result, ALICE)) == {f"aws_service_plane_admin:grafana:{ws}"}
    result = privesc.analyze(aws_snap([user("alice", allow("grafana:CreateWorkspaceApiKey", ws + "x"))], [], extra), entries=[entry])
    assert reached(result, ALICE) == {}
    empty = [("grafana_workspace", SCOPE, [], "empty")]
    result = privesc.analyze(aws_snap([user("alice", allow("grafana:CreateWorkspaceApiKey"))], [], empty), entries=[entry])
    assert edges(result, ALICE) == []


def test_service_plane_not_collected_stays_unresolved():
    result = privesc.analyze(aws_snap([user("alice", allow("grafana:CreateWorkspaceApiKey"))], []),
                             entries=[catalog_entry("aws-grafana-createworkspaceapikey-admin")], include_unknown=True)
    targets = [nodes(result)[e["target"]] for e in edges(result, ALICE)]
    assert targets and all(t["id"].startswith(("unresolved:", "unknown:")) and t["confidence"] == "unknown" for t in targets)


def test_quicksight_subscription_found_in_any_region():
    users = [("quicksight_user", SCOPE, [{"Arn": f"arn:aws:quicksight:{REGION}:{ACCOUNT}:user/default/bob", "Role": "ADMIN"}]),
             ("quicksight_user", f"{ACCOUNT}/eu-west-1", [], "denied")]
    result = privesc.analyze(aws_snap([user("alice", allow("quicksight:UpdateUser"))], [], users),
                             entries=[catalog_entry("aws-quicksight-updateuser-admin")])
    assert set(reached(result, ALICE)) == {f"aws_service_plane_admin:quicksight:arn:aws:quicksight:*:{ACCOUNT}:user/*"}


def test_identity_center_group_assignments_decide_creategroupmembership():
    entry = catalog_entry("aws-identitystore-creategroupmembership")
    alice = user("alice", allow("identitystore:CreateGroupMembership"))
    groups = [("aws_identity_center_account_assignment", SCOPE, [{"AccountId": "222222222222", "PrincipalType": "GROUP", "PrincipalId": "g-1",
               "PermissionSetArn": "arn:aws:sso:::permissionSet/ssoins-1/ps-1"}])]
    result = privesc.analyze(aws_snap([alice], [], groups), entries=[entry])
    assert set(reached(result, ALICE)) == {f"aws_identity_center_permission_set:{ACCOUNT}"}
    users_only = [("aws_identity_center_account_assignment", SCOPE, [{"AccountId": ACCOUNT, "PrincipalType": "USER", "PrincipalId": "u-1"}])]
    result = privesc.analyze(aws_snap([alice], [], users_only), entries=[entry])
    assert edges(result, ALICE) == []
