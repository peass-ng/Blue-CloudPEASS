"""Follow-ups to the AWS privesc catalog refresh: EKS cluster-admin targets, ECScape co-location, organization member
accounts, OIDC / orphaned identity-provider trusts, EMR runtime and EMR on EKS roles, PCS profiles, Service Catalog
portfolios, PCA Connector for AD, Redshift Serverless trusts and the Pacu DynamoDB-stream Lambda variant.

Each technique has a true positive, a false-positive negative and (where facts can be missing) an UNKNOWN case:
missing inventory must give an unresolved placeholder, never a concrete edge or a FAIL.
"""
from __future__ import annotations

import json

from peaso import privesc
from peaso.privesc.versioned_catalog import _verified_prior

ACCOUNT, OTHER, STRANGER = "111111111111", "222222222222", "333333333333"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
ORG = "o-abc123def4"
ALICE = f"arn:aws:iam::{ACCOUNT}:user/alice"
EKS_ARN = f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/prod"


# --------------------------------------------------------------------------- builders
def snapshot(provider, collections):
    cols = [{"type": t, "scope": scope, "service": t, "status": status, "items": items, "error": None}
            for t, scope, items, status in collections]
    return {"schema_version": 1, "provider": provider, "scopes": sorted({c["scope"] for c in cols}),
            "collections": cols, "metadata": {}}


def col(kind, items, status="collected", scope=SCOPE):
    return (kind, scope, list(items), status)


def aws_snap(users=(), roles=(), extra=(), other_roles=()):
    cols = [col("iam_user", users), col("iam_role", roles), col("iam_group", []), col("iam_policy", []),
            col("scp_policy", [], "empty"), *extra]
    for account, items in other_roles:
        scope = f"{account}/{REGION}"
        cols += [col("iam_role", items, scope=scope), col("iam_user", [], scope=scope), col("iam_group", [], scope=scope),
                 col("iam_policy", [], scope=scope), col("scp_policy", [], "empty", scope=scope)]
    return snapshot("aws", cols)


def real(snap, *ids, **kw):
    active = {e["id"]: e for e in privesc.catalog()["entries"]}
    historical = set(ids) - set(active)
    prior, _ = _verified_prior() if historical else ({}, {})
    entries = [active[i] if i in active else prior[i] for i in ids]
    assert historical.intersection(ids).isdisjoint(active), "historical paths must stay excluded"
    assert {e["id"] for e in entries} == set(ids)
    return privesc.analyze(snap, entries=entries, **kw)


def edges(result, source=None, technique=None):
    return [e for e in result["graph"]["edges"] if (source is None or e["source"] == source)
            and (technique is None or technique in e["techniques"])]


def reached(result, source, technique=None):
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    out = {}
    for edge in edges(result, source, technique):
        node = nodes.get(edge["target"], {})
        for member in (node.get("members") if node.get("kind") == "aggregate" else [edge["target"]]) or []:
            out[member] = edge["confidence"]
    return out


def assert_unresolved(result, source, technique=None):
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    targets = [nodes[e["target"]] for e in edges(result, source, technique)]
    assert targets, "expected an unresolved placeholder"
    for node in targets:
        # unresolved:* = selector/placeholder facts missing; unknown:* = the candidate inventory itself is unavailable
        assert node["id"].startswith(("unresolved:", "unknown:")), node["id"]
        assert node["members"] == [] and node["confidence"] == "unknown"
        assert node["facts_needed"] if node["id"].startswith("unresolved:") else "inventory unavailable" in node["label"]
    statuses = {f["status"] for f in result["findings"] if technique is None or f["check_id"] == technique}
    assert "FAIL" not in statuses
    return targets


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(*actions, resource="*"):
    return {"Effect": "Allow", "Action": list(actions), "Resource": resource}


def user(name, *statements, account=ACCOUNT):
    return {"UserName": name, "Arn": f"arn:aws:iam::{account}:user/{name}", "Path": "/", "GroupList": [],
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": policy(*statements)}] if statements else [],
            "AttachedManagedPolicies": []}


def role(name, trust, *statements, account=ACCOUNT, profiles=None):
    if isinstance(trust, str):
        trust = [{"Effect": "Allow", "Principal": {"Service": trust}, "Action": "sts:AssumeRole"}]
    item = {"RoleName": name, "Arn": f"arn:aws:iam::{account}:role/{name}", "Path": "/",
            "AssumeRolePolicyDocument": policy(*trust),
            "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": policy(*statements)}] if statements else [],
            "AttachedManagedPolicies": []}
    if profiles is not False:
        item["InstanceProfileList"] = [{"Arn": a} for a in (profiles or [])]
    return item


def profile_arn(name, account=ACCOUNT, path="/"):
    return f"arn:aws:iam::{account}:instance-profile{path}{name}"


def role_arn(name, account=ACCOUNT):
    return f"arn:aws:iam::{account}:role/{name}"


# --------------------------------------------------------------------------- EKS
EKS_ADMIN = allow("eks:CreateAccessEntry", "eks:AssociateAccessPolicy")


def eks_cluster(mode="API_AND_CONFIG_MAP", name="prod"):
    cluster = {"name": name, "arn": f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/{name}",
               "endpoint": f"https://{name.upper()}.gr7.{REGION}.eks.amazonaws.com"}
    if mode:
        cluster["accessConfig"] = {"authenticationMode": mode}
    return {"Cluster": {"cluster": cluster}}


def test_eks_access_entry_reaches_cluster_admin_entity():
    snap = aws_snap([user("alice", EKS_ADMIN)], extra=[col("eks_cluster", [eks_cluster("API")])])
    result = real(snap, "aws-eks-createaccessentry-associateaccesspolicy")
    target = f"k8s_cluster_admin:{EKS_ARN}"
    assert reached(result, ALICE) == {target: "conditional"}
    node = next(n for n in result["graph"]["nodes"] if n["id"] == target)
    assert node["label"] == "EKS cluster prod (cluster-admin)" and node["type"] == "k8s_cluster_admin"
    finding = next(f for f in result["findings"] if f["check_id"] == "aws-eks-createaccessentry-associateaccesspolicy")
    assert finding["status"] == "MANUAL"


def test_eks_config_map_only_cluster_is_not_a_target():
    snap = aws_snap([user("alice", EKS_ADMIN)], extra=[col("eks_cluster", [eks_cluster("CONFIG_MAP")])])
    assert edges(real(snap, "aws-eks-createaccessentry-associateaccesspolicy"), ALICE) == []


def test_eks_access_policy_scoped_to_other_cluster_is_not_an_edge():
    scoped = [allow("eks:CreateAccessEntry"),
              allow("eks:AssociateAccessPolicy", resource=f"arn:aws:eks:*:{ACCOUNT}:access-entry/other/*")]
    snap = aws_snap([user("alice", *scoped)], extra=[col("eks_cluster", [eks_cluster("API")])])
    assert edges(real(snap, "aws-eks-createaccessentry-associateaccesspolicy"), ALICE) == []


def test_eks_mode_or_inventory_missing_is_unknown_not_fail():
    snap = aws_snap([user("alice", EKS_ADMIN)], extra=[col("eks_cluster", [eks_cluster(None)])])
    assert_unresolved(real(snap, "aws-eks-createaccessentry-associateaccesspolicy", include_unknown=True), ALICE)
    snap = aws_snap([user("alice", EKS_ADMIN)], extra=[col("eks_cluster", [], "denied")])
    assert_unresolved(real(snap, "aws-eks-createaccessentry-associateaccesspolicy", include_unknown=True), ALICE)


POD_ID = [allow("eks:CreatePodIdentityAssociation", "iam:PassRole", "iam:GetRole")]


def test_eks_pod_identity_needs_an_existing_cluster():
    pods = role("pods-role", "pods.eks.amazonaws.com")
    tid = "aws-eks-createpodidentityassociation-passrole"
    result = real(aws_snap([user("alice", *POD_ID)], [pods], [col("eks_cluster", [eks_cluster("API")])]), tid)
    assert role_arn("pods-role") in reached(result, ALICE)
    assert edges(real(aws_snap([user("alice", *POD_ID)], [pods], [col("eks_cluster", [], "empty")]), tid), ALICE) == []
    assert_unresolved(real(aws_snap([user("alice", *POD_ID)], [pods], [col("eks_cluster", [], "denied")]), tid, include_unknown=True), ALICE)


def test_eks_nodegroup_passrole_needs_an_existing_cluster():
    node = role("node-role", "ec2.amazonaws.com", profiles=[profile_arn("node-role")])
    alice = user("alice", allow("eks:CreateNodegroup", "iam:PassRole", "iam:GetRole", "ec2:RunInstances",
                                "ec2:CreateLaunchTemplate", "ec2:DescribeSubnets"))
    tid = "aws-eks-passrole-createnodegroup"
    assert role_arn("node-role") in reached(real(aws_snap([alice], [node], [col("eks_cluster", [eks_cluster()])]), tid), ALICE)
    assert edges(real(aws_snap([alice], [node], [col("eks_cluster", [], "empty")]), tid), ALICE) == []


def test_eks_entity_joins_related_k8s_cluster_admin():
    snap = aws_snap([user("alice", EKS_ADMIN)], extra=[col("eks_cluster", [eks_cluster("API")])])
    k8s = snapshot("k8s", [("clusterrole", "prod", [{"kind": "ClusterRole", "metadata": {"name": "x"},
                                                      "provenance": {"cluster_id": "prod"}}], "collected")])
    result = real(snap, "aws-eks-createaccessentry-associateaccesspolicy", related_snapshots=[k8s])
    joins = edges(result, f"k8s_cluster_admin:{EKS_ARN}", "cloud-identity-join")
    assert [e["target"] for e in joins] == ["k8s_cluster_admin:prod"]
    assert result["stats"]["cross_snapshot_edges"] == 1
    # an unrelated K8s snapshot is not joined
    other = snapshot("k8s", [("clusterrole", "dev", [{"kind": "ClusterRole", "metadata": {"name": "x"},
                                                       "provenance": {"cluster_id": "dev"}}], "collected")])
    result = real(snap, "aws-eks-createaccessentry-associateaccesspolicy", related_snapshots=[other])
    assert edges(result, f"k8s_cluster_admin:{EKS_ARN}", "cloud-identity-join") == []


# --------------------------------------------------------------------------- ECScape
ECSCAPE = "aws-ecs-ecscape-agent-impersonation"
NODE_ARN = role_arn("ecs-node")
CLUSTER_ARN = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/web"


def ecs_snap(cluster, task_defs=None, instances=("i-1",)):
    node = role("ecs-node", "ec2.amazonaws.com", allow("ecs:DiscoverPollEndpoint", "ecs:Poll"),
                profiles=[profile_arn("ecs-node")])
    roles = [node, role("app", "ecs-tasks.amazonaws.com"), role("far", "ecs-tasks.amazonaws.com")]
    tds = task_defs if task_defs is not None else [
        {"taskDefinitionArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/app:1", "taskRoleArn": role_arn("app"),
         "compatibilities": ["EC2", "FARGATE"]},
        {"taskDefinitionArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/far:1", "taskRoleArn": role_arn("far"),
         "compatibilities": ["EC2"]}]
    ec2 = [{"InstanceId": i, "IamInstanceProfile": {"Arn": profile_arn("ecs-node")}, "State": {"Name": "running"}}
           for i in instances]
    return aws_snap([], roles, [col("ecs_cluster", [cluster] if cluster else [], "collected" if cluster else "empty"),
                                col("ecs_task_definition", tds), col("instance", ec2)])


def placed_cluster():
    ci1, ci2 = f"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/web/1", f"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/web/2"
    return {"clusterArn": CLUSTER_ARN, "registeredContainerInstancesCount": 2,
            "ContainerInstances": [{"containerInstanceArn": ci1, "ec2InstanceId": "i-1"},
                                   {"containerInstanceArn": ci2, "ec2InstanceId": "i-2"}],
            "Tasks": [{"taskDefinitionArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/app:1",
                       "containerInstanceArn": ci1, "launchType": "EC2"},
                      {"taskDefinitionArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/far:1",
                       "containerInstanceArn": ci2, "launchType": "EC2"}]}


def test_ecscape_reaches_only_task_roles_on_the_source_instance():
    got = reached(real(ecs_snap(placed_cluster()), ECSCAPE), NODE_ARN)
    assert set(got) == {role_arn("app")}   # "far" runs on i-2, not on the source's instance


def test_ecscape_fargate_only_or_no_container_instances_is_dropped():
    fargate = {"clusterArn": CLUSTER_ARN, "registeredContainerInstancesCount": 0}
    assert edges(real(ecs_snap(fargate), ECSCAPE), NODE_ARN) == []
    fargate_tds = [{"taskDefinitionArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/app:1",
                    "taskRoleArn": role_arn("app"), "compatibilities": ["FARGATE"]}]
    assert edges(real(ecs_snap({"clusterArn": CLUSTER_ARN, "registeredContainerInstancesCount": 3}, fargate_tds),
                      ECSCAPE), NODE_ARN) == []


def test_ecscape_without_placement_is_unknown_not_fail():
    cluster = {"clusterArn": CLUSTER_ARN, "registeredContainerInstancesCount": 2}
    assert_unresolved(real(ecs_snap(cluster), ECSCAPE, include_unknown=True), NODE_ARN, ECSCAPE)


def test_ecscape_source_must_be_a_container_instance_role():
    snap = ecs_snap(placed_cluster())
    snap["collections"][0]["items"].append(user("alice", allow("ecs:DiscoverPollEndpoint", "ecs:Poll")))
    assert edges(real(snap, ECSCAPE), ALICE) == []


# --------------------------------------------------------------------------- organizations
def org_accounts(*members, status="collected"):
    accounts = [{"Id": a, "Arn": f"arn:aws:organizations::{ACCOUNT}:account/{ORG}/{a}", "State": "ACTIVE"}
                for a in (ACCOUNT, *members)]
    return col("organization_account", accounts, status)


def test_assumeroot_reaches_org_member_accounts_only():
    alice = user("alice", allow("sts:AssumeRoot"))
    snap = aws_snap([alice], extra=[org_accounts(OTHER)], other_roles=[(STRANGER, [role("x", "ec2.amazonaws.com")])])
    got = reached(real(snap, "aws-sts-assumeroot-member-accounts"), ALICE)
    assert set(got) == {f"aws_account_admin:{OTHER}"}   # not the management account, not the non-member 333...


def test_assumeroot_without_org_inventory_is_unknown():
    snap = aws_snap([user("alice", allow("sts:AssumeRoot"))], other_roles=[(OTHER, [role("x", "ec2.amazonaws.com")])])
    assert_unresolved(real(snap, "aws-sts-assumeroot-member-accounts", include_unknown=True), ALICE)


def org_trust(org=ORG):
    return [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
             "Condition": {"StringEquals": {"aws:PrincipalOrgID": org}}}]


CREATE_ACCOUNT = "aws-organizations-createaccount-principalorgid-trust"


def test_createaccount_reaches_principalorgid_trusts_from_management_account():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    shared, foreign = role("shared", org_trust(), account=OTHER), role("foreign", org_trust("o-zzzzzzzzzz"), account=OTHER)
    snap = aws_snap([alice], extra=[org_accounts(OTHER)], other_roles=[(OTHER, [shared, foreign])])
    assert set(reached(real(snap, CREATE_ACCOUNT), ALICE)) == {role_arn("shared", OTHER)}


def test_createaccount_from_member_account_is_not_an_edge():
    bob = user("bob", allow("organizations:CreateAccount", "sts:AssumeRole"), account=OTHER)
    snap = aws_snap([], extra=[org_accounts(OTHER), col("iam_user", [bob], scope=f"{OTHER}/{REGION}")],
                    other_roles=[(STRANGER, [role("shared", org_trust(), account=STRANGER)])])
    assert edges(real(snap, CREATE_ACCOUNT), f"arn:aws:iam::{OTHER}:user/bob") == []


def test_createaccount_without_org_inventory_is_unknown():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    snap = aws_snap([alice], other_roles=[(OTHER, [role("shared", org_trust(), account=OTHER)])])
    assert_unresolved(real(snap, CREATE_ACCOUNT, include_unknown=True), ALICE)


# --------------------------------------------------------------------------- OIDC / orphaned providers
GH = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
SAML = f"arn:aws:iam::{ACCOUNT}:saml-provider/okta"


def federated(provider, action="sts:AssumeRoleWithWebIdentity"):
    return [{"Effect": "Allow", "Principal": {"Federated": provider}, "Action": action,
             "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}}
            if "oidc" in provider else {"Effect": "Allow", "Principal": {"Federated": provider}, "Action": action}]


def test_oidc_audience_change_reaches_roles_trusting_the_provider():
    roles = [role("gh", federated(GH)), role("ec2", "ec2.amazonaws.com")]
    tid = "aws-iam-oidcprovider-add-client-id"
    assert set(reached(real(aws_snap([user("alice", allow("iam:AddClientIDToOpenIDConnectProvider"))], roles), tid), ALICE)) == \
        {role_arn("gh")}
    recreate = user("alice", allow("iam:DeleteOpenIDConnectProvider", "iam:CreateOpenIDConnectProvider"))
    assert set(reached(real(aws_snap([recreate], roles), tid), ALICE)) == {role_arn("gh")}
    other = user("alice", allow("iam:AddClientIDToOpenIDConnectProvider",
                                resource=f"arn:aws:iam::{ACCOUNT}:oidc-provider/other.example.com"))
    assert edges(real(aws_snap([other], roles), tid), ALICE) == []


def test_orphaned_oidc_and_saml_trusts():
    roles = [role("gh", federated(GH)), role("sso", federated(SAML, "sts:AssumeRoleWithSAML"))]
    alice = user("alice", allow("iam:CreateOpenIDConnectProvider", "iam:CreateSAMLProvider"))
    ids = ("aws-iam-createoidcprovider-orphaned-trust", "aws-iam-createsamlprovider-orphaned-trust")
    missing = aws_snap([alice], roles, [col("iam_oidc_provider", [], "empty"), col("iam_saml_provider", [], "empty")])
    result = real(missing, *ids)
    assert set(reached(result, ALICE, ids[0])) == {role_arn("gh")}
    assert reached(result, ALICE, ids[1]) == {role_arn("sso"): "derived"}
    present = aws_snap([alice], roles, [col("iam_oidc_provider", [{"Arn": GH}]), col("iam_saml_provider", [{"Arn": SAML}])])
    assert edges(real(present, *ids), ALICE) == []
    assert_unresolved(real(aws_snap([alice], roles), *ids, include_unknown=True), ALICE)


# --------------------------------------------------------------------------- EMR
def emr_roles():
    ec2 = role("emr-ec2", "ec2.amazonaws.com", profiles=[profile_arn("emr-ec2")])
    runtime = role("runtime", [{"Effect": "Allow", "Principal": {"AWS": role_arn("emr-ec2")},
                                "Action": ["sts:AssumeRole", "sts:TagSession"]}], profiles=[])
    return [ec2, runtime, role("unrelated", "ec2.amazonaws.com", profiles=[])]


def emr_cluster(security=True):
    cluster = {"Id": "j-1", "Ec2InstanceAttributes": {"IamInstanceProfile": "emr-ec2"}}
    if security:
        cluster["SecurityConfiguration"] = "runtime-roles"
    return {"Cluster": {"Cluster": cluster}}


def test_emr_getclustersessioncredentials_reaches_runtime_roles():
    tid = "aws-emr-getclustersessioncredentials-runtime-role"
    alice = user("alice", allow("elasticmapreduce:GetClusterSessionCredentials"))
    assert set(reached(real(aws_snap([alice], emr_roles(), [col("emr_cluster", [emr_cluster()])]), tid), ALICE)) == \
        {role_arn("runtime")}
    assert edges(real(aws_snap([alice], emr_roles(), [col("emr_cluster", [emr_cluster(False)])]), tid), ALICE) == []
    assert_unresolved(real(aws_snap([alice], emr_roles()), tid, include_unknown=True), ALICE)


def test_emr_on_eks_execution_roles_trust_the_cluster_oidc_provider():
    oidc = f"arn:aws:iam::{ACCOUNT}:oidc-provider/oidc.eks.{REGION}.amazonaws.com/id/ABC"
    job = role("emr-job", [{"Effect": "Allow", "Principal": {"Federated": oidc}, "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {"StringLike": {f"oidc.eks.{REGION}.amazonaws.com/id/ABC:sub":
                                                         "system:serviceaccount:spark:emr-containers-sa-*-*-111111111111-*"}}}])
    irsa = role("irsa", [{"Effect": "Allow", "Principal": {"Federated": oidc}, "Action": "sts:AssumeRoleWithWebIdentity",
                          "Condition": {"StringEquals": {f"oidc.eks.{REGION}.amazonaws.com/id/ABC:sub": "system:serviceaccount:a:b"}}}])
    alice = user("alice", allow("iam:PassRole", "emr-containers:StartJobRun", "emr-containers:GetManagedEndpointSessionCredentials"))
    ids = ("aws-emr-containers-passrole-startjobrun", "aws-emr-containers-getmanagedendpointsessioncredentials")
    result = real(aws_snap([alice], [job, irsa]), *ids)
    for tid in ids:
        assert set(reached(result, ALICE, tid)) == {role_arn("emr-job")}
    no_pass = user("alice", allow("emr-containers:StartJobRun"))
    assert edges(real(aws_snap([no_pass], [job]), *ids), ALICE) == []


# --------------------------------------------------------------------------- PCS / Service Catalog / PCA
def test_pcs_matches_instance_profile_name_prefix_or_path():
    roles = [role("by-name", "ec2.amazonaws.com", profiles=[profile_arn("AWSPCS-nodes")]),
             role("by-path", "ec2.amazonaws.com", profiles=[profile_arn("nodes", path="/aws-pcs/")]),
             role("AWSPCS-role-name-only", "ec2.amazonaws.com", profiles=[profile_arn("generic")])]
    alice = user("alice", allow("iam:PassRole", "pcs:CreateComputeNodeGroup"))
    tid = "aws-pcs-passrole-createcomputenodegroup"
    assert set(reached(real(aws_snap([alice], roles), tid), ALICE)) == {role_arn("by-name"), role_arn("by-path")}
    unknown = [role("np", "ec2.amazonaws.com", profiles=False)]
    assert_unresolved(real(aws_snap([alice], unknown), tid, include_unknown=True), ALICE)


PORTFOLIO = f"arn:aws:catalog:{REGION}:{ACCOUNT}:portfolio/port-1"


def sc_portfolio():
    return {"PortfolioDetail": {"ARN": PORTFOLIO, "Id": "port-1"},
            "Constraints": [{"Type": "LAUNCH", "ProductId": "prod-1",
                             "ConstraintParameters": json.dumps({"RoleArn": role_arn("launch")})}]}


def test_servicecatalog_associate_principal_needs_the_launch_roles_portfolio():
    tid = "aws-servicecatalog-associateprincipal-createartifact-provision"
    roles = [role("launch", "servicecatalog.amazonaws.com"), role("unused", "servicecatalog.amazonaws.com")]
    prov = allow("servicecatalog:CreateProvisioningArtifact", "servicecatalog:ProvisionProduct")
    alice = user("alice", allow("servicecatalog:AssociatePrincipalWithPortfolio", resource=PORTFOLIO), prov)
    snap = aws_snap([alice], roles, [col("servicecatalog_portfolio", [sc_portfolio()])])
    assert set(reached(real(snap, tid), ALICE)) == {role_arn("launch")}
    wrong = user("alice", allow("servicecatalog:AssociatePrincipalWithPortfolio",
                                resource=f"arn:aws:catalog:{REGION}:{ACCOUNT}:portfolio/port-2"), prov)
    assert edges(real(aws_snap([wrong], roles, [col("servicecatalog_portfolio", [sc_portfolio()])]), tid), ALICE) == []
    assert_unresolved(real(aws_snap([alice], roles), tid, include_unknown=True), ALICE)


def test_pca_connector_ad_template_chain_is_an_unresolved_domain_admin_target():
    ids = ("aws-pca-connector-ad-createtemplate-esc1", "aws-pca-connector-ad-updatetemplate")
    both = user("alice", allow("pca-connector-ad:CreateTemplate", "pca-connector-ad:CreateTemplateGroupAccessControlEntry"))
    targets = assert_unresolved(real(aws_snap([both]), ids[0], include_unknown=True), ALICE)
    assert all("aws_directory_domain_admin" in t["id"] for t in targets)
    only_create = user("alice", allow("pca-connector-ad:CreateTemplate"))
    assert edges(real(aws_snap([only_create]), *ids), ALICE) == []


# --------------------------------------------------------------------------- Redshift / Lambda
def test_redshift_matches_serverless_only_trust():
    # This historical PassRole operation only attaches a role to Redshift; it
    # does not grant the caller that role's permissions in the active catalog.
    ident = "aws-redshift-passrole-attach-warehouse-role"
    assert ident not in {e["id"] for e in privesc.catalog()["entries"]}
    prior, _ = _verified_prior()
    roles = [role("rs-sl", "redshift-serverless.amazonaws.com"), role("rs", "redshift.amazonaws.com"),
             role("glue", "glue.amazonaws.com")]
    alice = user("alice", allow("iam:PassRole", "redshift:ModifyClusterIamRoles"))
    got = reached(privesc.analyze(aws_snap([alice], roles), entries=[prior[ident]]), ALICE)
    assert set(got) == {role_arn("rs-sl"), role_arn("rs")}


def test_lambda_dynamodb_stream_variant_needs_table_and_item_write():
    tid = "aws-lambda-passrole-createfunction-dynamodb-stream-trigger"
    base = ("iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping", "dynamodb:CreateTable")
    roles = [role("fn", "lambda.amazonaws.com"), role("ec2", "ec2.amazonaws.com")]
    assert set(reached(real(aws_snap([user("alice", allow(*base, "dynamodb:PutItem"))], roles), tid), ALICE)) == {role_arn("fn")}
    assert edges(real(aws_snap([user("alice", allow(*base))], roles), tid), ALICE) == []
