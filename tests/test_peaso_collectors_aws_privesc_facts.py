"""Privesc precision facts (ECS placement, IdPs, org tree, EMR, Service Catalog, SCP levels, global scope)."""
import json
from datetime import datetime, timezone

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.collectors import aws_privesc_facts as facts

ACCOUNT = "123456789012"
REGION = "us-east-1"
CLUSTER = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


@pytest.fixture
def stub(monkeypatch):
    session = boto3.Session(aws_access_key_id="k", aws_secret_access_key="s", region_name=REGION)
    clients, stubs = {}, {}

    def add(service):
        if service not in clients:
            clients[service] = session.client(service, region_name=REGION)
            stubs[service] = Stubber(clients[service])
            stubs[service].activate()
        return stubs[service]

    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: clients[service])
    yield session, add
    for item in stubs.values():
        item.assert_no_pending_responses()
        item.deactivate()


def test_extension_registers_read_only_kinds_and_globals():
    for kind in facts.SPECS:
        assert kind in aws.AWS_TYPES and aws._NATIVE_IDS[kind] == facts.NATIVE_IDS[kind]
    assert {"iam_saml_provider", "iam_oidc_provider"} <= aws.GLOBAL_TYPES
    assert all(op.startswith(("list_", "describe_", "get_")) for _, op in aws.READ_ACTIONS if (_, op) in facts.READ_ACTIONS)
    assert facts.READ_ACTIONS <= aws.READ_ACTIONS


def test_ecs_container_instances_batched_and_projected(stub):
    session, add = stub
    ecs = add("ecs")
    ecs.add_response("list_clusters", {"clusterArns": [CLUSTER]})
    arns = [f"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/prod/{n}" for n in range(101)]
    ecs.add_response("list_container_instances", {"containerInstanceArns": arns}, {"cluster": CLUSTER})
    rows = [{"containerInstanceArn": arn, "ec2InstanceId": f"i-{n:017x}", "status": "ACTIVE", "agentConnected": True,
        "attributes": [{"name": "secret-ish", "value": "drop"}]} for n, arn in enumerate(arns)]
    ecs.add_response("describe_container_instances", {"containerInstances": rows[:100], "failures": []}, {"cluster": CLUSTER, "containerInstances": arns[:100]})
    ecs.add_response("describe_container_instances", {"containerInstances": rows[100:], "failures": []}, {"cluster": CLUSTER, "containerInstances": arns[100:]})
    read = facts.FETCHERS["ecs_container_instance"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected" and len(read.items) == 101
    item = read.items[0]
    assert item["clusterArn"] == CLUSTER and item["ec2InstanceId"].startswith("i-") and item["agentConnected"] is True
    assert "attributes" not in item


def test_ecs_tasks_drop_container_overrides_and_failures_are_partial(stub):
    session, add = stub
    ecs = add("ecs")
    ecs.add_response("list_clusters", {"clusterArns": [CLUSTER]})
    task = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/prod/abc"
    ecs.add_response("list_tasks", {"taskArns": [task, task + "x"]}, {"cluster": CLUSTER})
    ecs.add_response("describe_tasks", {"tasks": [{"taskArn": task, "clusterArn": CLUSTER, "lastStatus": "RUNNING", "launchType": "EC2",
        "containerInstanceArn": "arn:aws:ecs:us-east-1:123456789012:container-instance/prod/1",
        "overrides": {"taskRoleArn": f"arn:aws:iam::{ACCOUNT}:role/override", "containerOverrides": [{"name": "app",
            "environment": [{"name": "PASSWORD", "value": "hunter2"}]}]},
        "containers": [{"name": "app", "lastStatus": "RUNNING", "reason": "drop",
                        "managedAgents": [{"name": "ExecuteCommandAgent", "lastStatus": "RUNNING", "reason": "drop"}]}]}],
        "failures": [{"arn": task + "x", "reason": "MISSING"}]}, None)
    read = facts.FETCHERS["ecs_task"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "partial"
    assert read.items[0]["overrides"] == {"taskRoleArn": f"arn:aws:iam::{ACCOUNT}:role/override"}
    assert "hunter2" not in json.dumps(read.items) and "drop" not in json.dumps(read.items)
    assert read.items[0]["containers"] == [{"name": "app", "lastStatus": "RUNNING",
                                           "managedAgents": [{"name": "ExecuteCommandAgent", "lastStatus": "RUNNING"}]}]


def test_ecs_denied_cluster_listing_is_denied_not_empty(stub):
    session, add = stub
    add("ecs").add_client_error("list_clusters", "AccessDeniedException", http_status_code=403)
    read = facts.FETCHERS["ecs_task"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "denied" and not read.items


def test_oidc_provider_detail(stub):
    session, add = stub
    arn = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
    add("iam").add_response("get_open_id_connect_provider", {"Url": "token.actions.githubusercontent.com", "ClientIDList": ["sts.amazonaws.com"],
        "ThumbprintList": ["a" * 40]}, {"OpenIDConnectProviderArn": arn})
    items = facts.ENRICHERS["iam_oidc_provider"](aws.Requests({}), session, REGION, [{"Arn": arn}])
    assert items[0]["Url"] == "token.actions.githubusercontent.com" and items[0]["Provider"]["collection_status"] == "collected"


def test_emr_cluster_detail_strips_kerberos_secrets_and_configuration_properties(stub):
    session, add = stub
    add("emr").add_response("describe_cluster", {"Cluster": {"Id": "j-1", "Name": "c", "Status": {"State": "WAITING"},
        "SecurityConfiguration": "sec", "Ec2InstanceAttributes": {"IamInstanceProfile": "EMR_EC2_DefaultRole", "Ec2SubnetId": "subnet-1"},
        "KerberosAttributes": {"Realm": "EC2.INTERNAL", "KdcAdminPassword": "s3cret", "CrossRealmTrustPrincipalPassword": "x"},
        "Configurations": [{"Classification": "hive-site", "Properties": {"javax.jdo.option.ConnectionPassword": "dbpass"}}]}}, {"ClusterId": "j-1"})
    item = facts.ENRICHERS["emr_cluster"](aws.Requests({}), session, REGION, [{"Id": "j-1", "Name": "c", "ClusterArn": "arn:aws:elasticmapreduce:us-east-1:123456789012:cluster/j-1", "Status": {"State": "WAITING"}}])[0]
    cluster = item["Cluster"]["Cluster"]
    assert item["Cluster"]["collection_status"] == "collected"
    assert cluster["Ec2InstanceAttributes"]["IamInstanceProfile"] == "EMR_EC2_DefaultRole" and cluster["SecurityConfiguration"] == "sec"
    assert cluster["KerberosAttributes"] == {"Realm": "EC2.INTERNAL"} and cluster["ConfigurationClassifications"] == ["hive-site"]
    assert "s3cret" not in json.dumps(item) and "dbpass" not in json.dumps(item)


def test_servicecatalog_launch_constraints_and_shares(stub):
    session, add = stub
    sc = add("servicecatalog")
    sc.add_response("list_constraints_for_portfolio", {"ConstraintDetails": [{"ConstraintId": "cons-1", "Type": "LAUNCH", "ProductId": "prod-1",
        "PortfolioId": "port-1", "Owner": ACCOUNT}, {"ConstraintId": "cons-2", "Type": "NOTIFICATION", "ProductId": "prod-1"}]}, {"PortfolioId": "port-1"})
    sc.add_response("describe_constraint", {"ConstraintDetail": {"ConstraintId": "cons-1", "Type": "LAUNCH"},
        "ConstraintParameters": json.dumps({"RoleArn": f"arn:aws:iam::{ACCOUNT}:role/launch"}), "Status": "AVAILABLE"}, {"Id": "cons-1"})
    sc.add_response("describe_portfolio_shares", {"PortfolioShareDetails": [{"PrincipalId": "999999999999", "Type": "ACCOUNT", "Accepted": True}]},
        {"PortfolioId": "port-1", "Type": "ACCOUNT"})
    sc.add_response("describe_portfolio_shares", {"PortfolioShareDetails": [], "NextPageToken": "t"}, {"PortfolioId": "port-1", "Type": "ORGANIZATION"})
    sc.add_response("describe_portfolio_shares", {"PortfolioShareDetails": []}, {"PortfolioId": "port-1", "Type": "ORGANIZATION", "PageToken": "t"})
    sc.add_client_error("describe_portfolio_shares", "AccessDeniedException", http_status_code=403)
    sc.add_response("describe_portfolio_shares", {"PortfolioShareDetails": []}, {"PortfolioId": "port-1", "Type": "ORGANIZATION_MEMBER_ACCOUNT"})
    item = facts.ENRICHERS["servicecatalog_portfolio"](aws.Requests({}), session, REGION, [{"Id": "port-1", "ARN": "arn:aws:catalog:us-east-1:123456789012:portfolio/port-1"}])[0]
    launch = item["Constraints"]["items"][0]
    assert item["Constraints"]["collection_status"] == "collected"
    assert launch["Type"] == "LAUNCH" and launch["ProductId"] == "prod-1" and launch["ConstraintParameters"] == {"RoleArn": f"arn:aws:iam::{ACCOUNT}:role/launch"}
    assert item["Shares"]["ACCOUNT"]["PortfolioShareDetails"][0]["PrincipalId"] == "999999999999"
    assert item["Shares"]["ORGANIZATION"]["collection_status"] == "empty"
    assert item["Shares"]["ORGANIZATIONAL_UNIT"]["collection_status"] == "denied"


def test_unhandled_continuation_token_is_never_complete(stub):
    session, add = stub
    add("servicecatalog").add_response("describe_portfolio_shares", {"PortfolioShareDetails": [], "NextPageToken": "t"}, None)
    read = aws.Requests({}).pages(session, "servicecatalog", REGION, "describe_portfolio_shares", "PortfolioShareDetails", PortfolioId="p", Type="ACCOUNT")
    assert read.status not in ("collected", "empty")


def test_organization_account_parent_paths(stub):
    session, add = stub
    org = add("organizations")
    org.add_response("list_roots", {"Roots": [{"Id": "r-ab12", "Name": "Root", "Arn": "arn:aws:organizations::111111111111:root/o-abcdefghij/r-ab12"}]})
    org.add_response("list_accounts_for_parent", {"Accounts": [{"Id": "111111111111"}]}, {"ParentId": "r-ab12"})
    org.add_response("list_organizational_units_for_parent", {"OrganizationalUnits": [{"Id": "ou-ab12-11111111", "Name": "Prod"}]}, {"ParentId": "r-ab12"})
    org.add_response("list_accounts_for_parent", {"Accounts": [{"Id": ACCOUNT}]}, {"ParentId": "ou-ab12-11111111"})
    org.add_response("list_organizational_units_for_parent", {"OrganizationalUnits": []}, {"ParentId": "ou-ab12-11111111"})
    items = facts.ENRICHERS["organization_account"](aws.Requests({}), session, REGION, [{"Id": ACCOUNT}, {"Id": "111111111111"}, {"Id": "222222222222"}])
    member, management, missing = items
    assert member["ParentId"] == "ou-ab12-11111111" and member["ParentType"] == "ORGANIZATIONAL_UNIT"
    assert member["ParentPath"] == [ACCOUNT, "ou-ab12-11111111", "r-ab12"] and member["OrganizationPath"][0]["Name"] == "Prod"
    assert member["Parents"]["collection_status"] == "collected"
    assert management["ParentId"] == "r-ab12"
    assert "ParentId" not in missing and missing["Parents"]["collection_status"] == "unknown"


def test_organization_tree_denied_marks_parents_denied(stub):
    session, add = stub
    add("organizations").add_client_error("list_roots", "AccessDeniedException", http_status_code=403)
    item = facts.ENRICHERS["organization_account"](aws.Requests({}), session, REGION, [{"Id": ACCOUNT}])[0]
    assert "ParentId" not in item and item["Parents"]["collection_status"] == "denied"


def _scp(org, target, policies):
    org.add_response("list_policies_for_target", {"Policies": policies}, {"TargetId": target, "Filter": "SERVICE_CONTROL_POLICY"})


def _describe(org, pid, content):
    org.add_response("describe_policy", {"Policy": {"PolicySummary": {"Id": pid, "Name": pid, "Type": "SERVICE_CONTROL_POLICY"},
        "Content": json.dumps(content)}}, {"PolicyId": pid})


def test_scp_attached_above_account_is_evaluated_at_its_own_level(stub):
    session, add = stub
    org = add("organizations")
    allow = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    deny = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]}
    full = {"Id": "p-FullAWSAccess", "Name": "FullAWSAccess", "Type": "SERVICE_CONTROL_POLICY"}
    _scp(org, ACCOUNT, [full])
    _describe(org, "p-FullAWSAccess", allow)
    org.add_response("list_parents", {"Parents": [{"Id": "ou-ab12-11111111", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": ACCOUNT})
    _scp(org, "ou-ab12-11111111", [full, {"Id": "p-denyiam", "Name": "DenyIam", "Type": "SERVICE_CONTROL_POLICY"}])
    _describe(org, "p-denyiam", deny)
    org.add_response("list_parents", {"Parents": [{"Id": "r-ab12", "Type": "ROOT"}]}, {"ChildId": "ou-ab12-11111111"})
    _scp(org, "r-ab12", [full])
    read = aws._scp_policies(aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected"
    by_id = {item["Id"]: item for item in read.items}
    assert by_id["p-FullAWSAccess"]["TargetId"] == ACCOUNT and by_id["p-FullAWSAccess"]["AttachedToAccount"] is True
    assert by_id["p-denyiam"]["TargetId"] == "ou-ab12-11111111" and by_id["p-denyiam"]["AttachedToAccount"] is False
    inherited = by_id["p-denyiam"]["InheritedPolicies"]
    assert inherited["collection_status"] == "collected"
    assert {(row["TargetId"], row["Id"]) for row in inherited["items"]} == {
        ("ou-ab12-11111111", "p-FullAWSAccess"), ("ou-ab12-11111111", "p-denyiam"), ("r-ab12", "p-FullAWSAccess")}
    assert all(isinstance(row["Content"], dict) for row in inherited["items"])


def test_global_kinds_are_scoped_account_global_once(stub, monkeypatch):
    session, add = stub
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "test-pinned"))
    add("sts").add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/r", "UserId": "AIDA"}, {})
    add("iam").add_response("list_saml_providers", {"SAMLProviderList": [{"Arn": f"arn:aws:iam::{ACCOUNT}:saml-provider/okta"}]}, {})
    add("ec2").add_response("describe_vpcs", {"Vpcs": []}, None)
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "auth": {"profile": "p"}, "options": {"regions": [REGION]}},
        ["iam_saml_provider", "vpc"])
    saml = [c for c in snapshot["collections"] if c["type"] == "iam_saml_provider"]
    assert len(saml) == 1 and saml[0]["scope"] == f"{ACCOUNT}/global" and saml[0]["global"] is True
    assert saml[0]["items"][0]["Arn"].endswith("saml-provider/okta") and "Region" not in saml[0]["items"][0]
    assert f"{ACCOUNT}/global" not in snapshot["scopes"] and f"{ACCOUNT}/{REGION}" in snapshot["scopes"]
    assert all(c["scope"] == f"{ACCOUNT}/global" for c in snapshot["collections"] if c["type"] in aws.GLOBAL_TYPES)


def _stub_ou_tree(org, deny_statement, ou_full=True):
    allow = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    full = {"Id": "p-FullAWSAccess", "Name": "FullAWSAccess", "Type": "SERVICE_CONTROL_POLICY"}
    _scp(org, ACCOUNT, [full])
    _describe(org, "p-FullAWSAccess", allow)
    org.add_response("list_parents", {"Parents": [{"Id": "ou-ab12-11111111", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": ACCOUNT})
    _scp(org, "ou-ab12-11111111", ([full] if ou_full else []) + [{"Id": "p-ou", "Name": "OuGuardrail", "Type": "SERVICE_CONTROL_POLICY"}])
    _describe(org, "p-ou", {"Version": "2012-10-17", "Statement": [deny_statement]})
    org.add_response("list_parents", {"Parents": [{"Id": "r-ab12", "Type": "ROOT"}]}, {"ChildId": "ou-ab12-11111111"})
    _scp(org, "r-ab12", [full])


def _model_from_collected_scps(stub, statement, ou_full=True):
    from peaso.privesc.effective_permissions.aws import AwsModel
    session, add = stub
    _stub_ou_tree(add("organizations"), statement, ou_full)
    scp = aws._scp_policies(aws.Requests({}), session, REGION, ACCOUNT)
    doc = lambda *statements: {"Version": "2012-10-17", "Statement": list(statements)}
    alice = {"UserName": "alice", "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice", "Path": "/", "GroupList": [], "AttachedManagedPolicies": [],
        "Tags": [], "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": doc({"Effect": "Allow", "Action": "*", "Resource": "*"})}]}
    target = {"RoleName": "ec2-role", "Arn": f"arn:aws:iam::{ACCOUNT}:role/ec2-role", "Path": "/", "RolePolicyList": [], "AttachedManagedPolicies": [],
        "AssumeRolePolicyDocument": doc({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}),
        "InstanceProfileList": [{"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/ec2-role"}]}
    scope = f"{ACCOUNT}/global"
    rows = [("iam_user", [alice], "collected"), ("iam_role", [target], "collected"), ("iam_group", [], "empty"),
        ("iam_policy", [], "empty"), ("scp_policy", [{**item, "AccountId": ACCOUNT} for item in scp.items], scp.status)]
    snap = {"schema_version": 1, "provider": "aws", "scopes": [f"{ACCOUNT}/{REGION}"], "metadata": {},
        "collections": [{"type": kind, "scope": scope, "service": kind, "status": status, "items": items, "error": None,
            "global": True, "account_id": ACCOUNT} for kind, items, status in rows]}
    model = AwsModel(snap)
    return lambda action: model.check(model.principals[alice["Arn"]], {"action": action}, target["Arn"])


def test_collected_ou_scp_deny_reaches_the_privesc_evaluator(stub):
    """End to end: an SCP attached only to the account's OU denies the action in the (read-only) evaluator."""
    check = _model_from_collected_scps(stub, {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"})
    assert check("iam:PassRole") is None                                   # OU-level deny is enforced
    grant = check("ec2:RunInstances")
    assert grant is not None and grant.confidence == "derived"             # complete path: no inherited_scps_not_evaluated


def test_ou_allow_list_scp_is_not_satisfied_by_account_level_full_access(stub):
    """Regression: an OU allow-list (iam:* only) must cut ec2 even though FullAWSAccess is attached to the account."""
    check = _model_from_collected_scps(stub, {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}, ou_full=False)
    assert check("ec2:RunInstances") is None
    assert check("iam:PassRole") is not None


def _rcp(org, target, policies):
    org.add_response("list_policies_for_target", {"Policies": policies}, {"TargetId": target, "Filter": "RESOURCE_CONTROL_POLICY"})


def _stub_rcp_tree(org, ou_statement):
    full = {"Id": "p-RCPFullAWSAccess", "Name": "RCPFullAWSAccess", "Type": "RESOURCE_CONTROL_POLICY", "AwsManaged": True}
    _rcp(org, ACCOUNT, [])
    org.add_response("list_parents", {"Parents": [{"Id": "ou-ab12-11111111", "Type": "ORGANIZATIONAL_UNIT"}]}, {"ChildId": ACCOUNT})
    _rcp(org, "ou-ab12-11111111", [full, {"Id": "p-rcpou", "Name": "OuRcp", "Type": "RESOURCE_CONTROL_POLICY"}])
    _describe(org, "p-RCPFullAWSAccess", {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]})
    _describe(org, "p-rcpou", {"Version": "2012-10-17", "Statement": [ou_statement]})
    org.add_response("list_parents", {"Parents": [{"Id": "r-ab12", "Type": "ROOT"}]}, {"ChildId": "ou-ab12-11111111"})
    _rcp(org, "r-ab12", [full])


def test_rcp_policies_are_rows_per_attachment_target(stub):
    session, add = stub
    _stub_rcp_tree(add("organizations"), {"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole", "Resource": "*"})
    read = facts.FETCHERS["rcp_policy"](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == "collected"
    assert sorted((row["Id"], row["TargetId"]) for row in read.items) == [
        ("p-RCPFullAWSAccess", "ou-ab12-11111111"), ("p-RCPFullAWSAccess", "r-ab12"), ("p-rcpou", "ou-ab12-11111111")]
    assert len({row["AttachmentId"] for row in read.items}) == 3          # distinct native ids survive envelope dedupe
    assert all(row["Type"] == "RESOURCE_CONTROL_POLICY" and row["InheritanceComplete"] for row in read.items)
    assert all(isinstance(row["Detail"]["Policy"]["Content"], dict) for row in read.items)


def test_rcp_not_enabled_is_empty_but_denied_stays_denied(stub):
    session, add = stub
    org = add("organizations")
    org.add_client_error("list_policies_for_target", "PolicyTypeNotEnabledException", http_status_code=400)
    assert facts.FETCHERS["rcp_policy"](aws.Requests({}), session, REGION, ACCOUNT).status == "empty"
    org.add_client_error("list_policies_for_target", "AccessDeniedException", http_status_code=403)
    read = facts.FETCHERS["rcp_policy"](aws.Requests({}), session, REGION, "210987654321")
    assert read.status == "denied" and not read.items


def test_collected_ou_rcp_deny_reaches_the_privesc_evaluator(stub):
    from peaso.privesc.effective_permissions.aws import AwsModel
    session, add = stub
    _stub_rcp_tree(add("organizations"), {"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole", "Resource": "*"})
    rcp = facts.FETCHERS["rcp_policy"](aws.Requests({}), session, REGION, ACCOUNT)
    doc = lambda *statements: {"Version": "2012-10-17", "Statement": list(statements)}
    alice = {"UserName": "alice", "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice", "Path": "/", "GroupList": [], "AttachedManagedPolicies": [],
        "Tags": [], "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": doc({"Effect": "Allow", "Action": "*", "Resource": "*"})}]}
    target = {"RoleName": "admin", "Arn": f"arn:aws:iam::{ACCOUNT}:role/admin", "Path": "/", "RolePolicyList": [], "AttachedManagedPolicies": [],
        "AssumeRolePolicyDocument": doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"}),
        "InstanceProfileList": []}
    parent = [{"ChildId": ACCOUNT, "ParentId": "ou-ab12-11111111"}, {"ChildId": "ou-ab12-11111111", "ParentId": "r-ab12"}]
    rows = [("iam_user", [alice], "collected"), ("iam_role", [target], "collected"), ("iam_group", [], "empty"), ("iam_policy", [], "empty"),
        ("scp_policy", [], "empty"), ("organization_parent", parent, "collected"), ("rcp_policy", rcp.items, rcp.status)]
    snap = {"schema_version": 1, "provider": "aws", "scopes": [f"{ACCOUNT}/{REGION}"], "metadata": {},
        "collections": [{"type": kind, "scope": f"{ACCOUNT}/global", "service": kind, "status": status, "items": [{**i, "AccountId": ACCOUNT} for i in items],
            "error": None, "global": True, "account_id": ACCOUNT} for kind, items, status in rows]}
    model = AwsModel(snap)
    assert model.rcp_status[ACCOUNT] == "collected"
    assert model.check(model.principals[alice["Arn"]], {"action": "sts:AssumeRole"}, target["Arn"]) is None   # OU RCP deny enforced


def test_privesc_engine_required_ecs_and_ssm_kinds_are_collected_inventories():
    for kind in ("ssm_managed_instance", "ecs_cluster", "ecs_task_definition", "ecs_container_instance", "ecs_task", "eks_cluster"):
        assert kind in aws.AWS_TYPES and kind not in aws.GLOBAL_TYPES
        assert kind in aws.SPECS or kind in aws.FETCHERS
    assert aws.SPECS["ssm_managed_instance"][:2] == ("ssm", "describe_instance_information")
    assert aws.SPECS["eks_cluster"][:2] == ("eks", "list_clusters")
    assert {("ecs", "describe_task_definition"), ("ecs", "describe_clusters"), ("eks", "describe_cluster")} <= aws.READ_ACTIONS
