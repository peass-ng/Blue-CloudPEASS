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
    "aws-identitystore-creategroupmembership",
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
    roles_anywhere_trust = pol({"Effect": "Allow", "Principal": {"Service": "rolesanywhere.amazonaws.com"},
                                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]})
    roles = [role("edge", roles_anywhere_trust), role("spare", roles_anywhere_trust)]
    extra = [("rolesanywhere_profile", SCOPE, [{"profileArn": profile, "enabled": True, "roleArns": [arn("edge")]}]),
             ("rolesanywhere_trust_anchor", SCOPE, [{"trustAnchorArn": anchor, "enabled": True,
                                                     "source": {"sourceType": "CERTIFICATE_BUNDLE"}}])]
    result = privesc.analyze(aws_snap([user("alice", allow("rolesanywhere:UpdateProfile", profile))], roles, extra),
                             entries=[catalog_entry("aws-rolesanywhere-updateprofile-remove-session-policy")])
    assert set(reached(result, ALICE)) == {arn("edge")}
    result = privesc.analyze(aws_snap([user("alice", allow("rolesanywhere:UpdateTrustAnchor", anchor))], roles, extra),
                             entries=[catalog_entry("aws-rolesanywhere-updatetrustanchor")])
    assert set(reached(result, ALICE)) == {arn("edge")}
    result = privesc.analyze(aws_snap([user("alice", allow("rolesanywhere:UpdateTrustAnchor", anchor + "x"))], roles, extra),
                             entries=[catalog_entry("aws-rolesanywhere-updatetrustanchor")])
    assert reached(result, ALICE) == {}


def test_rolesanywhere_anchor_update_matches_profile_region_and_role_trust():
    profile = f"arn:aws:rolesanywhere:{REGION}:{ACCOUNT}:profile/p1"
    anchor = f"arn:aws:rolesanywhere:{REGION}:{ACCOUNT}:trust-anchor/t1"
    other = f"arn:aws:rolesanywhere:{REGION}:{ACCOUNT}:trust-anchor/t2"
    target = role("edge", pol({"Effect": "Allow", "Principal": {"Service": "rolesanywhere.amazonaws.com"},
                               "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                               "Condition": {"ArnEquals": {"aws:SourceArn": anchor}}}))
    profile_row = {"profileArn": profile, "enabled": True, "roleArns": [arn("edge")]}
    anchor_rows = [{"trustAnchorArn": anchor, "enabled": True, "source": {"sourceType": "CERTIFICATE_BUNDLE"}},
                   {"trustAnchorArn": other, "enabled": True, "source": {"sourceType": "CERTIFICATE_BUNDLE"}}]
    technique = catalog_entry("aws-rolesanywhere-updatetrustanchor")

    def evaluate(permission):
        extra = [("rolesanywhere_profile", SCOPE, [profile_row]),
                 ("rolesanywhere_trust_anchor", SCOPE, anchor_rows)]
        snap = aws_snap([user("alice", allow("rolesanywhere:UpdateTrustAnchor", permission))], [target], extra)
        return reached(privesc.analyze(snap, entries=[technique]), ALICE)

    assert set(evaluate(anchor)) == {arn("edge")}
    target["AssumeRolePolicyDocument"]["Statement"][0]["Action"].remove("sts:TagSession")
    assert evaluate(anchor) == {}
    target["AssumeRolePolicyDocument"]["Statement"][0]["Action"].append("sts:TagSession")
    assert evaluate(other) == {}
    anchor_rows[0]["enabled"] = False
    assert evaluate(anchor) == {}
    anchor_rows[0]["enabled"] = True
    anchor_rows[0]["source"]["sourceType"] = "AWS_ACM_PCA"
    assert evaluate(anchor) == {}
    anchor_rows[0]["source"]["sourceType"] = "CERTIFICATE_BUNDLE"
    profile_row["enabled"] = False
    assert evaluate(anchor) == {}
    profile_row["enabled"] = True
    profile_row["sessionPolicy"] = '{"Version":"2012-10-17","Statement":[]}'
    assert evaluate(anchor) == {}
    profile_row.pop("sessionPolicy")
    anchor_rows[0]["trustAnchorArn"] = anchor.replace(f":{REGION}:", ":us-west-2:")
    assert evaluate(anchor_rows[0]["trustAnchorArn"]) == {}
    anchor_rows[0]["trustAnchorArn"] = anchor
    target["AssumeRolePolicyDocument"]["Statement"].append({
        "Effect": "Deny", "Principal": {"Service": "rolesanywhere.amazonaws.com"},
        "Action": "sts:AssumeRole", "Condition": {"ArnEquals": {"aws:SourceArn": anchor}}})
    assert evaluate(anchor) == {}


# --- SageMaker / Image Builder hosts ---------------------------------------------------------------------
def test_sagemaker_user_profile_execution_role_host():
    profile = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:user-profile/d-1/alice"
    roles = [role("sm", trust_service("sagemaker.amazonaws.com")), role("sm2", trust_service("sagemaker.amazonaws.com"))]
    user_profile = {"DomainId": "d-1", "UserProfileName": "alice", "UserProfileArn": profile,
                    "ExecutionRole": arn("sm"), "ExecutionRoleSource": "user_settings", "Status": "InService"}
    domain = {"DomainId": "d-1", "AuthMode": "IAM", "Status": "InService",
              "AppNetworkAccessType": "PublicInternetOnly"}
    app = {"DomainId": "d-1", "UserProfileName": "alice", "AppType": "KernelGateway",
           "AppName": "default", "Status": "InService"}
    def analyze(apps=(app,), create=False, add_tags=True, url_resource=profile):
        extra = [("sagemaker_user_profile", SCOPE, [user_profile]), ("sagemaker_domain", SCOPE, [domain]),
                 ("sagemaker_app", SCOPE, list(apps))]
        grants = [allow("sagemaker:CreatePresignedDomainUrl", url_resource)]
        if create:
            app_arn = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:app/d-1/alice/KernelGateway/default"
            grants.append(allow("sagemaker:CreateApp", app_arn))
            if add_tags:
                grants.append(allow("sagemaker:AddTags", app_arn))
        return privesc.analyze(aws_snap([user("alice", *grants)], roles, extra),
                               entries=[catalog_entry("aws-sagemaker-createpresigneddomainurl")])
    assert set(reached(analyze(), ALICE)) == {arn("sm")}
    assert reached(analyze(url_resource=profile + "-other"), ALICE) == {}
    assert reached(analyze(apps=()), ALICE) == {}
    assert set(reached(analyze(apps=(), create=True), ALICE)) == {arn("sm")}
    assert reached(analyze(apps=(), create=True, add_tags=False), ALICE) == {}
    app["SpaceName"] = "other-role-space"
    assert reached(analyze(), ALICE) == {}
    app.pop("SpaceName")
    domain["AuthMode"] = "SSO"
    assert reached(analyze(), ALICE) == {}
    domain["AuthMode"] = "IAM"
    user_profile["Status"] = "Failed"
    assert reached(analyze(), ALICE) == {}
    user_profile["Status"] = "InService"
    domain["Status"] = "Deleting"
    assert reached(analyze(), ALICE) == {}
    domain["Status"] = "InService"
    domain["AppNetworkAccessType"] = "VpcOnly"
    assert set(reached(analyze(), ALICE)) == {arn("sm")}
    domain["DomainId"] = "d-other"
    assert reached(analyze(), ALICE) == {}


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


def test_sagemaker_space_host_uses_only_its_collected_execution_role():
    space = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:space/d-1/shared"
    roles = [role("space", trust_service("sagemaker.amazonaws.com")),
             role("other", trust_service("sagemaker.amazonaws.com"))]
    record = {"SpaceArn": space, "DomainId": "d-1", "SpaceName": "shared",
              "SharingType": "Shared", "AppType": "JupyterLab", "Status": "InService",
              "ExecutionRole": arn("space"), "ExecutionRoleSource": "domain_default_space"}
    m = model(aws_snap([user("alice")], roles, [("sagemaker_space", SCOPE, [record])]))
    assert m.hosts[arn("space")]["sagemaker_space"] == [space]
    assert not m.hosts.get(arn("other"), {}).get("sagemaker_space")
    record.pop("ExecutionRole")
    m = model(aws_snap([user("alice")], roles, [("sagemaker_space", SCOPE, [record])]))
    assert not m.hosts.get(arn("space"), {}).get("sagemaker_space")


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


def test_quicksight_existing_iam_user_self_promotion_requires_exact_identity_and_resource():
    technique = active_catalog_entry("aws-quicksight-updateuser-admin")
    user_arn = f"arn:aws:quicksight:{REGION}:{ACCOUNT}:user/default/qs-alice"
    subscription = ("quicksight_account_subscription", SCOPE, [{"id": ACCOUNT,
        "AccountSubscriptionStatus": "ACCOUNT_CREATED", "AuthenticationType": "IAM_ONLY"}])
    identity = {"Arn": user_arn, "UserName": "qs-alice", "PrincipalId": "federated/iam/AIDAALICE123456789",
                "IdentityType": "IAM", "Role": "AUTHOR", "Active": True}

    def route(source, row=identity, sub=subscription, status="collected"):
        return privesc.analyze(aws_snap([source], [], [("quicksight_user", SCOPE, [row], status), sub]),
                               entries=[technique])

    def caller(resource=user_arn):
        principal = user("alice", allow("quicksight:UpdateUser", resource))
        principal["UserId"] = "AIDAALICE123456789"
        return principal

    target = f"aws_service_plane_admin:quicksight:{user_arn}"
    assert set(reached(route(caller()), ALICE)) == {target}
    other_region_denied = privesc.analyze(aws_snap([caller()], [], [
        ("quicksight_user", SCOPE, [identity]), subscription,
        ("quicksight_user", f"{ACCOUNT}/eu-west-1", [], "denied")]), entries=[technique])
    assert set(reached(other_region_denied, ALICE)) == {target}
    assert reached(route(caller(user_arn + "-other")), ALICE) == {}
    assert reached(route(caller(), {**identity, "PrincipalId": "federated/iam/AIDABOB123456789"}), ALICE) == {}
    assert reached(route(caller(), {**identity, "Role": "ADMIN"}), ALICE) == {}
    assert reached(route(caller(), {**identity, "Active": False}), ALICE) == {}
    assert reached(route(caller(), {**identity, "IdentityType": "QUICKSIGHT"}), ALICE) == {}
    assert reached(route(caller(), {**identity, "CustomPermissionsName": "restricted"}), ALICE) == {}
    assert reached(route(caller(), status="denied"), ALICE) == {}
    inactive = ("quicksight_account_subscription", SCOPE, [{"id": ACCOUNT,
        "AccountSubscriptionStatus": "ACCOUNT_CREATED", "AuthenticationType": "ACTIVE_DIRECTORY"}])
    assert reached(route(caller(), sub=inactive), ALICE) == {}


def test_quicksight_registeruser_requires_iam_subscription_and_controlled_identity():
    technique = catalog_entry("aws-quicksight-registeruser-admin")
    qs_user = ("quicksight_user", SCOPE, [{"Arn": f"arn:aws:quicksight:{REGION}:{ACCOUNT}:user/default/bob",
        "UserName": "bob", "PrincipalId": "federated/iam/AIDABOB123456789", "IdentityType": "IAM", "Role": "AUTHOR"}])
    subscription = ("quicksight_account_subscription", SCOPE, [{"id": ACCOUNT,
        "AccountSubscriptionStatus": "ACCOUNT_CREATED", "AuthenticationType": "IAM_ONLY"}])

    def route(source, sub=subscription, users=qs_user):
        return privesc.analyze(aws_snap([source], [], [users, sub]), entries=[technique])

    def alice_user(*statements):
        source = user("alice", *statements)
        source["UserId"] = "AIDAALICE123456789"
        return source

    alice = alice_user(allow("quicksight:RegisterUser"))
    new_user_arn = f"arn:aws:quicksight:{REGION}:{ACCOUNT}:user/default/alice"
    target_id = f"aws_service_plane_admin:quicksight:{SCOPE}"
    assert set(reached(route(alice), ALICE)) == {target_id}
    assert set(reached(route(alice_user(allow("quicksight:RegisterUser", new_user_arn))), ALICE)) == {target_id}
    assert reached(route(alice_user(allow("quicksight:RegisterUser", new_user_arn + "x"))), ALICE) == {}
    assert set(reached(route(alice, users=("quicksight_user", SCOPE, [], "empty")), ALICE)) == {target_id}
    collision = ("quicksight_user", SCOPE, [{"Arn": new_user_arn, "UserName": "alice", "Role": "READER"}])
    assert reached(route(alice, users=collision), ALICE) == {}
    same_identity = ("quicksight_user", SCOPE, [{"Arn": f"arn:aws:quicksight:{REGION}:{ACCOUNT}:user/default/other",
        "UserName": "other", "PrincipalId": "federated/iam/AIDAALICE123456789", "IdentityType": "IAM", "Role": "AUTHOR"}])
    assert reached(route(alice, users=same_identity), ALICE) == {}
    assert reached(route(alice, users=("quicksight_user", SCOPE, [], "denied")), ALICE) == {}
    no_identity_id = ("quicksight_user", SCOPE, [{"Arn": qs_user[2][0]["Arn"],
        "UserName": "bob", "IdentityType": "IAM", "Role": "AUTHOR"}])
    assert reached(route(alice, users=no_identity_id), ALICE) == {}
    directory = ("quicksight_account_subscription", SCOPE, [{"id": ACCOUNT,
        "AccountSubscriptionStatus": "ACCOUNT_CREATED", "AuthenticationType": "ACTIVE_DIRECTORY"}])
    assert reached(route(alice, directory), ALICE) == {}
    denied = ("quicksight_account_subscription", SCOPE, [], "denied")
    assert reached(route(alice, denied), ALICE) == {}
    wrong_identity = alice_user({"Effect": "Allow", "Action": "quicksight:RegisterUser", "Resource": "*",
        "Condition": {"ArnEquals": {"quicksight:IamArn": f"arn:aws:iam::{ACCOUNT}:user/bob"}}})
    assert reached(route(wrong_identity), ALICE) == {}
    role_session_only = alice_user({"Effect": "Allow", "Action": "quicksight:RegisterUser", "Resource": "*",
        "Condition": {"StringEquals": {"quicksight:SessionName": "special-session"}}})
    assert reached(route(role_session_only), ALICE) == {}


def test_flink_passrole_binds_service_condition():
    technique = catalog_entry("aws-flink-passrole-createapplication")
    target = role("flink", trust_service("kinesisanalytics.amazonaws.com"))
    actions = allow(["kinesisanalytics:CreateApplication", "kinesisanalytics:StartApplication"])
    empty = ("flink_application", SCOPE, [], "empty")
    valid = user("alice", actions, {"Effect": "Allow", "Action": "iam:PassRole", "Resource": target["Arn"],
        "Condition": {"StringEquals": {"iam:PassedToService": "kinesisanalytics.amazonaws.com"}}})
    wrong = user("alice", actions, {"Effect": "Allow", "Action": "iam:PassRole", "Resource": target["Arn"],
        "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}})
    assert target["Arn"] in reached(privesc.analyze(aws_snap([valid], [target], [empty]), entries=[technique]), ALICE)
    assert reached(privesc.analyze(aws_snap([wrong], [target], [empty]), entries=[technique]), ALICE) == {}


def test_flink_start_permission_selects_one_unused_application_name():
    technique = catalog_entry("aws-flink-passrole-createapplication")
    target = role("flink", trust_service("kinesisanalytics.amazonaws.com"))
    application = f"arn:aws:kinesisanalytics:{REGION}:{ACCOUNT}:application/new-app"
    base = [allow("iam:PassRole", target["Arn"]), allow("kinesisanalytics:CreateApplication")]

    def route(start_arn, names=(), inventory_status="collected"):
        apps = ("flink_application", SCOPE, [{"ApplicationARN": f"arn:aws:kinesisanalytics:{REGION}:{ACCOUNT}:application/{name}",
            "ApplicationName": name} for name in names], inventory_status)
        source = user("alice", *base, allow("kinesisanalytics:StartApplication", start_arn))
        return privesc.analyze(aws_snap([source], [target], [apps]), entries=[technique])

    assert target["Arn"] in reached(route(application), ALICE)
    assert reached(route(application, names=("new-app",)), ALICE) == {}
    assert reached(route(application.replace(ACCOUNT, "999999999999")), ALICE) == {}
    assert reached(route(application, inventory_status="denied"), ALICE) == {}


def test_spot_fleet_requires_passable_fleet_role_and_service_linked_roles():
    technique = catalog_entry("aws-ec2-passrole-requestspotfleet")
    target = role("power", trust_service("ec2.amazonaws.com"), profile=True)
    fleet = role("fleet", trust_service("spotfleet.amazonaws.com"))

    def service_linked(service, name):
        item = role(name, trust_service(service))
        item["Arn"] = f"arn:aws:iam::{ACCOUNT}:role/aws-service-role/{service}/{name}"
        item["Path"] = f"/aws-service-role/{service}/"
        return item

    service_roles = [service_linked("spotfleet.amazonaws.com", "AWSServiceRoleForEC2SpotFleet"),
                     service_linked("spot.amazonaws.com", "AWSServiceRoleForEC2Spot")]

    def route(pass_fleet=True, roles=service_roles, create=False):
        passed = [target["Arn"], fleet["Arn"]] if pass_fleet else [target["Arn"]]
        statements = [allow(["ec2:RequestSpotFleet", "ec2:RunInstances"]), allow("iam:PassRole", passed)]
        if create:
            statements.append(allow("iam:CreateServiceLinkedRole"))
        return privesc.analyze(aws_snap([user("alice", *statements)], [target, fleet, *roles]), entries=[technique])

    assert target["Arn"] in reached(route(), ALICE)
    assert reached(route(pass_fleet=False), ALICE) == {}
    assert reached(route(roles=[]), ALICE) == {}
    assert target["Arn"] in reached(route(roles=[], create=True), ALICE)
    wrong_service = user("alice", allow(["ec2:RequestSpotFleet", "ec2:RunInstances"]),
        allow("iam:PassRole", target["Arn"]), {"Effect": "Allow", "Action": "iam:PassRole",
        "Resource": fleet["Arn"], "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}})
    result = privesc.analyze(aws_snap([wrong_service], [target, fleet, *service_roles]), entries=[technique])
    assert reached(result, ALICE) == {}
    for passed_to in ("ec2.amazonaws.com", "spotfleet.amazonaws.com"):
        conditioned = user("alice", allow(["ec2:RequestSpotFleet", "ec2:RunInstances"]),
            allow("iam:PassRole", target["Arn"]), {"Effect": "Allow", "Action": "iam:PassRole",
            "Resource": fleet["Arn"], "Condition": {"StringEquals": {"iam:PassedToService": passed_to}}})
        result = privesc.analyze(aws_snap([conditioned], [target, fleet, *service_roles]), entries=[technique])
        assert target["Arn"] in reached(result, ALICE)


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
