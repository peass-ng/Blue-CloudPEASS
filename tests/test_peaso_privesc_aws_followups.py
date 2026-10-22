"""Follow-ups to the AWS privesc catalog refresh: EKS cluster-admin targets, ECScape co-location, organization member
accounts, OIDC / orphaned identity-provider trusts, EMR runtime and EMR on EKS roles, PCS profiles, Service Catalog
portfolios, PCA Connector for AD, Redshift Serverless trusts and the Pacu DynamoDB-stream Lambda variant.

Each technique has a true positive, a false-positive negative and (where facts can be missing) an UNKNOWN case:
missing inventory must give an unresolved placeholder, never a concrete edge or a FAIL.
"""
from __future__ import annotations

import json
import hashlib
import copy

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
            col("scp_policy", [], "empty"), col("eks_access_entry", [], "empty"), *extra]
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


def test_ec2_launch_template_asg_requires_matching_unpinned_version_and_template_grants():
    technique = "aws-ec2-launchtemplate-version-asg"
    template = f"arn:aws:ec2:{REGION}:{ACCOUNT}:launch-template/lt-0123456789abcdef0"
    group = f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:abc:autoScalingGroupName/web"
    target = role("target", "ec2.amazonaws.com", profiles=[profile_arn("target")])

    def evaluate(version, grants, *, template_status="collected", group_status="collected", max_size=2):
        caller = user("caller", *grants)
        group_items = [{"AutoScalingGroupARN": group, "MaxSize": max_size,
                        "LaunchTemplate": {"LaunchTemplateId": "lt-0123456789abcdef0", "Version": version}}]
        template_items = [{"LaunchTemplateId": "lt-0123456789abcdef0",
                           "LaunchTemplateName": "web", "LaunchTemplateArn": template}]
        extra = [col("autoscaling_group", group_items if group_status == "collected" else [], group_status),
                 col("ec2_launch_template", template_items if template_status == "collected" else [], template_status)]
        result = real(aws_snap([caller], [target], extra), technique, include_unknown=True)
        return reached(result, caller["Arn"], technique), result, caller["Arn"]

    create = allow("ec2:CreateLaunchTemplateVersion", resource=template)
    modify = allow("ec2:ModifyLaunchTemplate", resource=template)
    latest, _, _ = evaluate("$Latest", [create])
    assert target["Arn"] in latest
    default, _, _ = evaluate("$Default", [create, modify])
    assert target["Arn"] in default
    assert target["Arn"] not in evaluate("$Default", [create])[0]
    assert target["Arn"] not in evaluate("$Default", [create, modify,
        {"Effect": "Deny", "Action": "ec2:ModifyLaunchTemplate", "Resource": template}])[0]
    assert target["Arn"] not in evaluate("7", [create, modify])[0]
    assert target["Arn"] not in evaluate("$Latest", [allow("ec2:CreateLaunchTemplateVersion",
                                                           resource=template + "-other")])[0]
    assert target["Arn"] not in evaluate("$Latest", [create], max_size=0)[0]
    for missing in ("template", "group"):
        kwargs = {f"{missing}_status": "denied"}
        members, result, source = evaluate("$Latest", [create], **kwargs)
        assert target["Arn"] not in members
        assert_unresolved(result, source, technique)


def test_ec2_launch_template_asg_mixed_override_uses_its_own_template():
    technique = "aws-ec2-launchtemplate-version-asg"
    base = f"arn:aws:ec2:{REGION}:{ACCOUNT}:launch-template/lt-11111111111111111"
    override = f"arn:aws:ec2:{REGION}:{ACCOUNT}:launch-template/lt-22222222222222222"
    group = f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:abc:autoScalingGroupName/mixed"
    target = role("target", "ec2.amazonaws.com", profiles=[profile_arn("target")])
    templates = [col("ec2_launch_template", [
        {"LaunchTemplateId": "lt-11111111111111111", "LaunchTemplateArn": base},
        {"LaunchTemplateId": "lt-22222222222222222", "LaunchTemplateArn": override}])]
    group_row = {"AutoScalingGroupARN": group, "MaxSize": 3, "MixedInstancesPolicy": {"LaunchTemplate": {
        "LaunchTemplateSpecification": {"LaunchTemplateId": "lt-11111111111111111", "Version": "$Latest"},
        "Overrides": [{"InstanceType": "t3.micro", "LaunchTemplateSpecification": {
            "LaunchTemplateId": "lt-22222222222222222", "Version": "$Default"}}]}}}

    def run(grants):
        caller = user("caller", *grants)
        result = real(aws_snap([caller], [target], [col("autoscaling_group", [group_row]), *templates]), technique)
        return reached(result, caller["Arn"], technique)

    assert target["Arn"] not in run([allow("ec2:CreateLaunchTemplateVersion", resource=base)])
    assert target["Arn"] not in run([allow("ec2:CreateLaunchTemplateVersion", resource=override)])
    assert target["Arn"] in run([allow("ec2:CreateLaunchTemplateVersion", resource=override),
                                  allow("ec2:ModifyLaunchTemplate", resource=override)])


def test_instance_connect_key_push_does_not_prove_host_role_access():
    technique = "aws-ec2-instance-connect-sendsshpublickey"
    instance_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-1234567890abcdef0"
    target = role("target", "ec2.amazonaws.com", profiles=[profile_arn("target")])
    instance = {"InstanceId": "i-1234567890abcdef0", "State": {"Name": "running"},
                "IamInstanceProfile": {"Arn": profile_arn("target")},
                "MetadataOptions": {"HttpEndpoint": "enabled", "State": "applied"}}
    caller = user("alice", allow("ec2-instance-connect:SendSSHPublicKey", resource=instance_arn))
    result = real(aws_snap([caller], [target], [col("instance", [instance])]),
                  technique, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, technique)
    assert_unresolved(result, ALICE, technique)

    wrong = user("alice", allow("ec2-instance-connect:SendSSHPublicKey",
                                resource=instance_arn.replace("i-1234567890abcdef0", "i-fffffffffffffffff")))
    result = real(aws_snap([wrong], [target], [col("instance", [instance])]),
                  technique, include_unknown=False)
    assert not reached(result, ALICE, technique)


def test_instance_connect_requires_fresh_exact_ssh_and_role_credential_witness():
    technique = "aws-ec2-instance-connect-sendsshpublickey"
    instance_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-1234567890abcdef0"
    target = role("target", "ec2.amazonaws.com", profiles=[profile_arn("target")])
    target["RoleId"] = "AROATARGET123456789"
    instance = {"InstanceId": "i-1234567890abcdef0", "State": {"Name": "running"},
                "IamInstanceProfile": {"Arn": profile_arn("target"), "Id": "AIPATARGET123456789"},
                "MetadataOptions": {"HttpEndpoint": "enabled", "State": "applied"}}
    grant = allow("ec2-instance-connect:SendSSHPublicKey", resource=instance_arn)
    grant["Condition"] = {"StringEquals": {"ec2:osuser": "ec2-user"}}
    proof = {"TechniqueId": technique, "SourceArn": ALICE, "TargetKind": "aws_role",
             "TargetId": target["Arn"], "TargetScope": SCOPE, "TargetRoleId": target["RoleId"],
             "TargetProfileArn": profile_arn("target"), "TargetProfileId": "AIPATARGET123456789",
             "InstanceArn": instance_arn, "OsUser": "ec2-user", "Status": "verified",
             "VerifiedPreconditions": True,
             "SendSSHPublicKeyAccepted": True, "SessionUsedPushedKey": True,
             "HostSessionEstablished": True, "RoleCredentialsReachable": True,
             "RoleCredentialsUsable": True, "CredentialRoleId": target["RoleId"],
             "EvidenceRef": "reviewed-host-session", "EvidenceObservedAt": "2026-10-21T11:59:30+00:00",
             "EvidenceExpiresAt": "2026-10-21T12:00:15+00:00"}

    def result(*, witness=None, proof_status="collected", statement=grant):
        witnesses = witness if isinstance(witness, list) else ([witness] if witness else [])
        snap = aws_snap([user("alice", statement)], [target], [col("instance", [instance]),
            col("aws_privesc_challenge_evidence", witnesses, proof_status)])
        snap["created_at"] = "2026-10-21T12:00:00+00:00"
        return real(snap, technique, include_unknown=True)

    assert target["Arn"] in reached(result(witness=proof), ALICE, technique)
    assert target["Arn"] not in reached(result(), ALICE, technique)
    assert_unresolved(result(), ALICE, technique)
    assert target["Arn"] not in reached(result(witness=[proof, dict(proof)]), ALICE, technique)
    for changed in ({"VerifiedPreconditions": False}, {"SendSSHPublicKeyAccepted": False},
                    {"SessionUsedPushedKey": False},
                    {"HostSessionEstablished": False}, {"RoleCredentialsReachable": False},
                    {"RoleCredentialsUsable": False}, {"CredentialRoleId": "AROANOTHER"},
                    {"TargetRoleId": "AROANOTHER"}, {"TargetProfileId": "AIPAOTHER"},
                    {"InstanceArn": instance_arn.replace("i-1234567890abcdef0", "i-fffffffffffffffff")},
                    {"OsUser": "root"}, {"EvidenceObservedAt": "2026-10-21T11:55:00+00:00"}):
        witness = dict(proof, **changed)
        assert target["Arn"] not in reached(result(witness=witness), ALICE, technique)
    assert target["Arn"] not in reached(result(witness=proof, proof_status="access_denied"), ALICE, technique)
    wrong_user = copy.deepcopy(grant)
    wrong_user["Condition"]["StringEquals"]["ec2:osuser"] = "ubuntu"
    assert target["Arn"] not in reached(result(witness=proof, statement=wrong_user), ALICE, technique)


def test_instance_connect_prior_catalog_binding_keeps_conditional_wording():
    from peaso.privesc import versioned_catalog as catalog

    ident = "aws-ec2-instance-connect-sendsshpublickey"
    prior_binding = {"schema": catalog.BINDING_SCHEMA,
                     "manifest_sha256": catalog.INSTANCE_CONNECT_690_PREVIOUS_MANIFEST,
                     "effective_tree_sha256": catalog.INSTANCE_CONNECT_690_PREVIOUS_TREE,
                     "source_revision": catalog.V4_REVISION}
    old, old_status = catalog.lookup_entries([ident], prior_binding)
    new, new_status = catalog.lookup_entries([ident], catalog.current_binding())
    assert old_status == "exact_previous_current"
    assert new_status == "exact_strict_privesc"
    assert "remain conditional" in old[ident]["notes"]
    assert "remain unresolved" not in old[ident]["notes"]
    assert "Without that witness, host access and role-credential use remain unresolved" in new[ident]["notes"]


def test_ecs_runtask_override_binds_task_cluster_and_passed_roles():
    technique = "aws-ecs-passrole-runtask-overrides"
    target = role("target", "ecs-tasks.amazonaws.com", allow("s3:GetObject"))
    execution = role("execution", "ecs-tasks.amazonaws.com")
    task_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/app:1"
    cluster_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
    definition = {"taskDefinitionArn": task_arn, "status": "ACTIVE", "compatibilities": ["EC2"],
                  "networkMode": "bridge", "executionRoleArn": execution["Arn"],
                  "containerDefinitions": [{"name": "app", "image": "public.ecr.aws/docker/library/alpine:latest"}]}
    task = {"taskDefinitionArn": task_arn,
            "Definition": {"collection_status": "collected", "taskDefinition": definition}}
    cluster = {"clusterArn": cluster_arn, "status": "ACTIVE", "registeredContainerInstancesCount": 1}
    passed = allow("iam:PassRole", resource=[target["Arn"], execution["Arn"]])
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}
    run = allow("ecs:RunTask", resource=task_arn)
    run["Condition"] = {"ArnEquals": {"ecs:cluster": cluster_arn}}

    def result(passrole=passed, runtask=run, state="ACTIVE", compatibility="EC2", capacity=1):
        item = copy.deepcopy(task)
        item["Definition"]["taskDefinition"]["status"] = state
        item["Definition"]["taskDefinition"]["compatibilities"] = [compatibility]
        current_cluster = {**cluster, "registeredContainerInstancesCount": capacity}
        caller = user("alice", passrole, runtask)
        return real(aws_snap([caller], [target, execution], [
            col("ecs_task_definition", [item]), col("ecs_cluster", [current_cluster])]),
            technique, include_unknown=True)

    assert target["Arn"] in reached(result(), ALICE, technique)
    wrong_task = allow("ecs:RunTask", resource=task_arn.replace("app:1", "other:1"))
    assert target["Arn"] not in reached(result(runtask=wrong_task), ALICE, technique)
    wrong_cluster = copy.deepcopy(run)
    wrong_cluster["Condition"]["ArnEquals"]["ecs:cluster"] = cluster_arn.replace("prod", "other")
    assert target["Arn"] not in reached(result(runtask=wrong_cluster), ALICE, technique)
    wrong_service = copy.deepcopy(passed)
    wrong_service["Condition"]["StringEquals"]["iam:PassedToService"] = "lambda.amazonaws.com"
    assert target["Arn"] not in reached(result(passrole=wrong_service), ALICE, technique)
    no_execution_role = allow("iam:PassRole", resource=target["Arn"])
    assert target["Arn"] not in reached(result(passrole=no_execution_role), ALICE, technique)
    assert target["Arn"] not in reached(result(state="INACTIVE"), ALICE, technique)
    assert target["Arn"] not in reached(result(capacity=0), ALICE, technique)
    fargate = result(compatibility="FARGATE")
    assert target["Arn"] not in reached(fargate, ALICE, technique)
    assert_unresolved(fargate, ALICE, technique)


def test_ecs_new_task_definition_runtask_needs_same_cluster_and_all_revisions():
    technique = "aws-ecs-passrole-registertaskdefinition-runtask"
    target = role("target", "ecs-tasks.amazonaws.com")
    cluster_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
    family = "PeasoPrivesc" + hashlib.sha256((ALICE + target["Arn"] + REGION).encode()).hexdigest()[:16]
    task_scope = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{family}:*"
    passed = allow("iam:PassRole", resource=target["Arn"])
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}
    register = allow("ecs:RegisterTaskDefinition", resource=task_scope)
    run = allow("ecs:RunTask", resource=task_scope)
    run["Condition"] = {"ArnEquals": {"ecs:cluster": cluster_arn}}

    def result(statements=(passed, register, run), capacity=1, cluster_status="collected",
               instance_status="ACTIVE", agent_connected=True, instance_inventory="collected"):
        cluster = {"clusterArn": cluster_arn, "status": "ACTIVE",
                   "registeredContainerInstancesCount": capacity}
        container_instances = [{"containerInstanceArn": f"{cluster_arn.replace(':cluster/', ':container-instance/')}/host",
                                "clusterArn": cluster_arn, "status": instance_status,
                                "agentConnected": agent_connected}] if capacity else []
        return real(aws_snap([user("alice", *statements)], [target], [
            col("ecs_cluster", [cluster] if cluster_status == "collected" else [], cluster_status),
            col("ecs_container_instance", container_instances if instance_inventory == "collected" else [],
                instance_inventory)]),
            technique, include_unknown=True)

    assert target["Arn"] in reached(result(), ALICE, technique)
    assert target["Arn"] not in reached(result(capacity=0), ALICE, technique)
    assert_unresolved(result(capacity=0), ALICE, technique)
    for unavailable in (result(instance_status="DRAINING"), result(agent_connected=False),
                        result(instance_inventory="access_denied")):
        assert target["Arn"] not in reached(unavailable, ALICE, technique)
        assert_unresolved(unavailable, ALICE, technique)
    assert target["Arn"] not in reached(result(cluster_status="empty"), ALICE, technique)
    wrong_service = copy.deepcopy(passed)
    wrong_service["Condition"]["StringEquals"]["iam:PassedToService"] = "lambda.amazonaws.com"
    assert target["Arn"] not in reached(result((wrong_service, register, run)), ALICE, technique)
    one_revision = allow("ecs:RunTask", resource=task_scope[:-1] + "1")
    assert target["Arn"] not in reached(result((passed, register, one_revision)), ALICE, technique)
    assert_unresolved(result((passed, register, one_revision)), ALICE, technique)
    wrong_cluster = copy.deepcopy(run)
    wrong_cluster["Condition"]["ArnEquals"]["ecs:cluster"] = cluster_arn.replace("prod", "other")
    assert target["Arn"] not in reached(result((passed, register, wrong_cluster)), ALICE, technique)
    denied_revision = {"Effect": "Deny", "Action": "ecs:RunTask", "Resource": task_scope[:-1] + "2"}
    assert target["Arn"] not in reached(result((passed, register, run, denied_revision)), ALICE, technique)
    assert_unresolved(result((passed, register, run, denied_revision)), ALICE, technique)


def test_ecs_new_task_definition_starttask_binds_exact_connected_host():
    technique = "aws-ecs-passrole-registertaskdefinition-starttask"
    target = role("target", "ecs-tasks.amazonaws.com")
    cluster_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
    host_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/prod/host1"
    family = "PeasoPrivesc" + hashlib.sha256((ALICE + target["Arn"] + REGION).encode()).hexdigest()[:16]
    task_scope = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{family}:*"
    passed = allow("iam:PassRole", resource=target["Arn"])
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}
    register = allow("ecs:RegisterTaskDefinition", resource=task_scope)
    start = allow("ecs:StartTask", resource=task_scope)
    start["Condition"] = {"ArnEquals": {"ecs:cluster": cluster_arn,
                                        "ecs:container-instances": host_arn}}

    def result(statements=(passed, register, start), *, host_status="ACTIVE", connected=True,
               host_inventory="collected", cluster_inventory="collected"):
        cluster = {"clusterArn": cluster_arn, "status": "ACTIVE", "registeredContainerInstancesCount": 1}
        host = {"clusterArn": cluster_arn, "containerInstanceArn": host_arn,
                "status": host_status, "agentConnected": connected}
        return real(aws_snap([user("alice", *statements)], [target], [
            col("ecs_cluster", [cluster] if cluster_inventory == "collected" else [], cluster_inventory),
            col("ecs_container_instance", [host] if host_inventory == "collected" else [], host_inventory)]),
            technique, include_unknown=True)

    assert target["Arn"] in reached(result(), ALICE, technique)
    for unresolved in (result(host_status="DRAINING"), result(connected=False),
                       result(host_inventory="access_denied")):
        assert target["Arn"] not in reached(unresolved, ALICE, technique)
        assert_unresolved(unresolved, ALICE, technique)
    assert target["Arn"] not in reached(result(cluster_inventory="empty"), ALICE, technique)
    wrong_host = copy.deepcopy(start)
    wrong_host["Condition"]["ArnEquals"]["ecs:container-instances"] = host_arn.replace("host1", "host2")
    assert target["Arn"] not in reached(result((passed, register, wrong_host)), ALICE, technique)
    one_revision = allow("ecs:StartTask", resource=task_scope[:-1] + "1")
    assert target["Arn"] not in reached(result((passed, register, one_revision)), ALICE, technique)
    assert_unresolved(result((passed, register, one_revision)), ALICE, technique)
    denied_revision = {"Effect": "Deny", "Action": "ecs:StartTask", "Resource": task_scope[:-1] + "2"}
    assert target["Arn"] not in reached(result((passed, register, start, denied_revision)), ALICE, technique)
    assert_unresolved(result((passed, register, start, denied_revision)), ALICE, technique)


def test_ecs_new_task_definition_service_binds_cluster_task_and_existing_service():
    technique = "aws-ecs-passrole-registertaskdefinition-service"
    target = role("target", "ecs-tasks.amazonaws.com")
    cluster_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
    family = "PeasoPrivesc" + hashlib.sha256((ALICE + target["Arn"] + REGION).encode()).hexdigest()[:16]
    task_scope = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{family}:*"
    new_service_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/prod/{family}"
    existing_service_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/prod/old"
    passed = allow("iam:PassRole", resource=target["Arn"])
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}
    register = allow("ecs:RegisterTaskDefinition", resource=task_scope)
    create = allow("ecs:CreateService", resource=new_service_arn)
    create["Condition"] = {"ArnEquals": {"ecs:cluster": cluster_arn}}
    update = allow("ecs:UpdateService", resource=existing_service_arn)
    update["Condition"] = {"ArnEquals": {"ecs:cluster": cluster_arn}}

    def result(statements=(passed, register, create), *, services=(), service_status="collected",
               connected=True, cluster_status="ACTIVE"):
        cluster = {"clusterArn": cluster_arn, "status": cluster_status, "registeredContainerInstancesCount": 1}
        host = {"clusterArn": cluster_arn,
                "containerInstanceArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/prod/host1",
                "status": "ACTIVE", "agentConnected": connected}
        return real(aws_snap([user("alice", *statements)], [target], [
            col("ecs_cluster", [cluster]), col("ecs_container_instance", [host]),
            col("ecs_service", services if service_status == "collected" else [], service_status)]),
            technique, include_unknown=True)

    assert target["Arn"] in reached(result(), ALICE, technique)
    existing = {"serviceArn": existing_service_arn, "clusterArn": cluster_arn,
                "status": "ACTIVE", "deploymentController": {"type": "ECS"}}
    assert target["Arn"] in reached(result((passed, register, update), services=[existing]), ALICE, technique)
    fargate_service = dict(existing, launchType="FARGATE")
    assert target["Arn"] not in reached(result((passed, register, update), services=[fargate_service]), ALICE, technique)
    assert_unresolved(result((passed, register, update), services=[fargate_service]), ALICE, technique)
    assert target["Arn"] not in reached(result((passed, register, update)), ALICE, technique)
    assert target["Arn"] not in reached(result(connected=False), ALICE, technique)
    assert_unresolved(result(connected=False), ALICE, technique)
    assert target["Arn"] not in reached(result(cluster_status="INACTIVE"), ALICE, technique)
    assert_unresolved(result(cluster_status="INACTIVE"), ALICE, technique)
    assert target["Arn"] not in reached(result(service_status="access_denied"), ALICE, technique)
    assert_unresolved(result(service_status="access_denied"), ALICE, technique)
    wrong_cluster = copy.deepcopy(create)
    wrong_cluster["Condition"]["ArnEquals"]["ecs:cluster"] = cluster_arn.replace("prod", "other")
    assert target["Arn"] not in reached(result((passed, register, wrong_cluster)), ALICE, technique)
    task_one = copy.deepcopy(create)
    task_one["Condition"]["ArnEquals"]["ecs:task-definition"] = task_scope[:-1] + "1"
    assert target["Arn"] not in reached(result((passed, register, task_one)), ALICE, technique)
    denied_service = {"Effect": "Deny", "Action": "ecs:CreateService", "Resource": new_service_arn}
    assert target["Arn"] not in reached(result((passed, register, create, denied_service)), ALICE, technique)


def test_ecs_privileged_task_requires_exact_linux_host_and_start_permission():
    technique = "aws-ecs-registertaskdefinition-node-escape"
    node = role("node", "ec2.amazonaws.com", profiles=[profile_arn("node")])
    task_role = role("task", "ecs-tasks.amazonaws.com")
    unrelated = role("unrelated", "ec2.amazonaws.com", profiles=[profile_arn("unrelated")])
    cluster_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
    ci_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/prod/host1"
    instance_id = "i-1234567890abcdef0"
    family = "PeasoPrivesc" + hashlib.sha256((ALICE + node["Arn"] + REGION).encode()).hexdigest()[:16]
    task_scope = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{family}:*"
    # Each target gets its own deterministic family, so the caller may cover all families.
    register = allow("ecs:RegisterTaskDefinition", resource=f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/PeasoPrivesc*:*")
    register["Condition"] = {"StringEquals": {"ecs:privileged": "true"}}
    start = allow("ecs:StartTask", resource=f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/PeasoPrivesc*:*")
    start["Condition"] = {"ArnEquals": {"ecs:cluster": cluster_arn,
                                       "ecs:container-instances": ci_arn}}

    def result(statements=(register, start), *, connected=True, host_id=instance_id,
               platform=None, metadata="enabled", task_ci=ci_arn, capacity=1,
               services=(), service_status="empty"):
        cluster = {"clusterArn": cluster_arn, "status": "ACTIVE", "registeredContainerInstancesCount": capacity}
        ci = {"clusterArn": cluster_arn, "containerInstanceArn": ci_arn, "ec2InstanceId": host_id,
              "status": "ACTIVE", "agentConnected": connected}
        instance = {"InstanceId": instance_id, "State": {"Name": "running"},
                    "IamInstanceProfile": {"Arn": profile_arn("node")},
                    "MetadataOptions": {"HttpEndpoint": metadata, "State": "applied"}}
        if platform:
            instance["Platform"] = platform
        task = {"clusterArn": cluster_arn, "containerInstanceArn": task_ci,
                "taskDefinitionArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/existing:1",
                "taskRoleArn": task_role["Arn"], "launchType": "EC2", "lastStatus": "RUNNING"}
        return real(aws_snap([user("alice", *statements)], [node, task_role, unrelated], [
            col("ecs_cluster", [cluster]), col("ecs_container_instance", [ci]),
            col("instance", [instance]), col("ecs_task", [task]),
            col("ecs_service", services if service_status == "collected" else [], service_status)]),
            technique, include_unknown=True)

    positive = reached(result(), ALICE, technique)
    assert node["Arn"] in positive and task_role["Arn"] in positive
    assert unrelated["Arn"] not in positive
    assert node["Arn"] not in reached(result(connected=False), ALICE, technique)
    assert node["Arn"] not in reached(result(host_id="i-other"), ALICE, technique)
    assert node["Arn"] not in reached(result(platform="windows"), ALICE, technique)
    assert node["Arn"] not in reached(result(metadata="disabled"), ALICE, technique)
    assert task_role["Arn"] not in reached(result(task_ci=ci_arn.replace("host1", "host2")), ALICE, technique)
    wrong_ci = copy.deepcopy(start)
    wrong_ci["Condition"]["ArnEquals"]["ecs:container-instances"] = ci_arn.replace("host1", "host2")
    assert node["Arn"] not in reached(result((register, wrong_ci)), ALICE, technique)
    unprivileged = copy.deepcopy(register)
    unprivileged["Condition"]["StringEquals"]["ecs:privileged"] = "false"
    assert node["Arn"] not in reached(result((unprivileged, start)), ALICE, technique)
    one_revision = allow("ecs:StartTask", resource=task_scope[:-1] + "1")
    assert node["Arn"] not in reached(result((register, one_revision)), ALICE, technique)
    assert_unresolved(result((register, one_revision)), ALICE, technique)
    run_only = allow("ecs:RunTask", resource=f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/PeasoPrivesc*:*")
    assert node["Arn"] in reached(result((register, run_only)), ALICE, technique)
    assert node["Arn"] in reached(result((register, start, run_only)), ALICE, technique)
    assert node["Arn"] not in reached(result((register, run_only), capacity=2), ALICE, technique)
    assert_unresolved(result((register, run_only), capacity=2), ALICE, technique)
    create_service = allow("ecs:CreateService",
                           resource=f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/prod/PeasoPrivesc*")
    create_service["Condition"] = {"ArnEquals": {"ecs:cluster": cluster_arn}}
    assert node["Arn"] in reached(result((register, create_service)), ALICE, technique)
    existing_service_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/prod/existing"
    update_service = allow("ecs:UpdateService", resource=existing_service_arn)
    update_service["Condition"] = {"ArnEquals": {"ecs:cluster": cluster_arn}}
    existing_service = {"serviceArn": existing_service_arn, "clusterArn": cluster_arn,
                        "status": "ACTIVE", "deploymentController": {"type": "ECS"}, "launchType": "EC2"}
    assert node["Arn"] in reached(result((register, update_service), services=[existing_service],
                                     service_status="collected"), ALICE, technique)
    assert node["Arn"] not in reached(result((register, create_service), capacity=2), ALICE, technique)
    assert_unresolved(result((register, create_service), capacity=2), ALICE, technique)
    denied_revision = {"Effect": "Deny", "Action": "ecs:RegisterTaskDefinition",
                       "Resource": task_scope[:-1] + "2"}
    assert node["Arn"] not in reached(result((register, start, denied_revision)), ALICE, technique)
    assert_unresolved(result((register, start, denied_revision)), ALICE, technique)


def test_ecs_external_taskset_binds_same_service_and_generated_resources():
    technique = "aws-ecs-taskset-primary"
    target = role("target", "ecs-tasks.amazonaws.com")
    cluster_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
    service_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/prod/old"
    family = "PeasoPrivesc" + hashlib.sha256((ALICE + target["Arn"] + REGION).encode()).hexdigest()[:16]
    task_scope = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{family}:*"
    taskset_scope = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-set/prod/old/*"
    passed = allow("iam:PassRole", resource=target["Arn"])
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}
    register = allow("ecs:RegisterTaskDefinition", resource=task_scope)
    create = allow("ecs:CreateTaskSet", resource=taskset_scope)
    create["Condition"] = {"ArnEquals": {"ecs:cluster": cluster_arn, "ecs:service": service_arn}}
    promote = allow("ecs:UpdateServicePrimaryTaskSet", resource=service_arn)
    promote["Condition"] = {"ArnEquals": {"ecs:cluster": cluster_arn}}

    def result(statements=(passed, register, create, promote), *, controller="EXTERNAL",
               service_status="ACTIVE", connected=True, service_inventory="collected"):
        cluster = {"clusterArn": cluster_arn, "status": "ACTIVE", "registeredContainerInstancesCount": 1}
        host = {"clusterArn": cluster_arn,
                "containerInstanceArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/prod/host1",
                "status": "ACTIVE", "agentConnected": connected}
        service = {"serviceArn": service_arn, "clusterArn": cluster_arn, "status": service_status,
                   "deploymentController": {"type": controller}, "launchType": "EC2"}
        return real(aws_snap([user("alice", *statements)], [target], [
            col("ecs_cluster", [cluster]), col("ecs_container_instance", [host]),
            col("ecs_service", [service] if service_inventory == "collected" else [], service_inventory)]),
            technique, include_unknown=True)

    assert target["Arn"] in reached(result(), ALICE, technique)
    assert target["Arn"] not in reached(result(controller="ECS"), ALICE, technique)
    assert target["Arn"] not in reached(result(service_status="INACTIVE"), ALICE, technique)
    assert target["Arn"] not in reached(result(connected=False), ALICE, technique)
    assert_unresolved(result(connected=False), ALICE, technique)
    assert target["Arn"] not in reached(result(service_inventory="access_denied"), ALICE, technique)
    assert_unresolved(result(service_inventory="access_denied"), ALICE, technique)
    wrong_service = copy.deepcopy(create)
    wrong_service["Condition"]["ArnEquals"]["ecs:service"] = service_arn.replace("old", "other")
    assert target["Arn"] not in reached(result((passed, register, wrong_service, promote)), ALICE, technique)
    wrong_cluster = copy.deepcopy(promote)
    wrong_cluster["Condition"]["ArnEquals"]["ecs:cluster"] = cluster_arn.replace("prod", "other")
    assert target["Arn"] not in reached(result((passed, register, create, wrong_cluster)), ALICE, technique)
    one_revision = allow("ecs:RegisterTaskDefinition", resource=task_scope[:-1] + "1")
    assert target["Arn"] not in reached(result((passed, one_revision, create, promote)), ALICE, technique)
    assert_unresolved(result((passed, one_revision, create, promote)), ALICE, technique)
    guessed_id = allow("ecs:CreateTaskSet", resource=taskset_scope[:-1] + "PeasoPrivesc*")
    assert target["Arn"] not in reached(result((passed, register, guessed_id, promote)), ALICE, technique)
    assert_unresolved(result((passed, register, guessed_id, promote)), ALICE, technique)
    denied_taskset = {"Effect": "Deny", "Action": "ecs:CreateTaskSet", "Resource": taskset_scope}
    assert target["Arn"] not in reached(result((passed, register, create, promote, denied_taskset)), ALICE, technique)


def test_spot_request_scoped_grant_stays_visible_without_claiming_role_execution():
    ident = "aws-ec2-requestspotinstances-passrole"
    target = role("target", "ec2.amazonaws.com", profiles=[profile_arn("target")])
    image = f"arn:aws:ec2:{REGION}:{ACCOUNT}:image/ami-1234567890abcdef0"

    def caller(service, spot=True):
        passrole = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": target["Arn"],
                    "Condition": {"StringEquals": {"iam:PassedToService": service}}}
        statements = [passrole]
        if spot:
            statements.append(allow("ec2:RequestSpotInstances", resource=image))
        return user("alice", *statements)

    source = caller("ec2.amazonaws.com")
    result = real(aws_snap([source], [target]), ident, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, ident)
    assert_unresolved(result, ALICE, ident)
    for source in (caller("lambda.amazonaws.com"), caller("ec2.amazonaws.com", spot=False)):
        assert not reached(real(aws_snap([source], [target]), ident), ALICE, ident)


def test_spot_request_prior_catalog_binding_keeps_global_requirement():
    from peaso.privesc import versioned_catalog as catalog

    ident = "aws-ec2-requestspotinstances-passrole"
    old_binding = {"schema": catalog.BINDING_SCHEMA,
                   "manifest_sha256": catalog.SPOT_REQUEST_690_PREVIOUS_MANIFEST,
                   "effective_tree_sha256": catalog.SPOT_REQUEST_690_PREVIOUS_TREE,
                   "source_revision": catalog.V4_REVISION}
    old, old_status = catalog.lookup_entries([ident], old_binding)
    new, new_status = catalog.lookup_entries([ident], catalog.current_binding())
    assert old_status == "exact_previous_current"
    assert new_status == "exact_strict_privesc"
    assert any(req["action"] == "ec2:RequestSpotInstances"
               for req in old[ident]["requires"]["all_of"])
    assert all(req["action"] != "ec2:RequestSpotInstances"
               for req in new[ident]["requires"]["all_of"])


def test_ec2_changed_user_data_needs_reviewed_reexecution_on_same_instance():
    technique = "aws-ec2-modifyinstanceattribute-userdata"
    instance_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-1234567890abcdef0"
    target = role("target", "ec2.amazonaws.com", profiles=[profile_arn("target")])
    target["RoleId"] = "AROATARGET123456789"
    instance = {"InstanceId": "i-1234567890abcdef0", "RootDeviceType": "ebs",
                "State": {"Name": "running"},
                "IamInstanceProfile": {"Arn": profile_arn("target"), "Id": "AIPATARGET123456789"},
                "MetadataOptions": {"HttpEndpoint": "enabled", "State": "applied"}}
    proof = {"TechniqueId": technique, "SourceArn": f"arn:aws:iam::{ACCOUNT}:user/caller",
             "TargetKind": "aws_role", "TargetId": target["Arn"], "TargetScope": SCOPE,
             "TargetRoleId": target["RoleId"], "TargetProfileArn": profile_arn("target"),
             "TargetProfileId": "AIPATARGET123456789", "InstanceArn": instance_arn,
             "Status": "verified", "VerifiedPreconditions": True,
             "UserDataRunsOnRestart": True, "RoleCredentialsReachable": True,
             "StopProtectionDisabled": True, "EvidenceRef": "host-review",
             "EvidenceObservedAt": "2026-10-21T11:59:00+00:00",
             "EvidenceExpiresAt": "2026-10-21T12:05:00+00:00"}

    def evaluate(*, state="running", attested=True, actions=None, changed=None):
        row, fact = copy.deepcopy(instance), copy.deepcopy(proof)
        row["State"]["Name"] = state
        if changed:
            row.update(changed.get("instance", {}))
            fact.update(changed.get("proof", {}))
        grants = actions if actions is not None else [allow("ec2:ModifyInstanceAttribute", "ec2:StartInstances",
                                                              "ec2:StopInstances", resource=instance_arn)]
        caller = user("caller", *grants)
        snap = aws_snap([caller], [target], [col("instance", [row]),
                                            col("aws_privesc_challenge_evidence", [fact] if attested else [],
                                                "collected" if attested else "empty")])
        snap["created_at"] = "2026-10-21T12:00:00+00:00"
        result = real(snap, technique, include_unknown=True)
        return reached(result, caller["Arn"], technique), result, caller["Arn"]

    assert target["Arn"] in evaluate()[0]
    assert target["Arn"] in evaluate(actions=[
        allow("ec2:StartInstances", "ec2:StopInstances", resource=instance_arn),
        {"Effect": "Allow", "Action": "ec2:ModifyInstanceAttribute", "Resource": instance_arn,
         "Condition": {"StringEquals": {"ec2:Attribute": "userData"}}}])[0]
    assert target["Arn"] in evaluate(state="stopped", actions=[
        allow("ec2:ModifyInstanceAttribute", "ec2:StartInstances", resource=instance_arn)])[0]
    assert target["Arn"] in evaluate(changed={"proof": {"StopProtectionDisabled": False}})[0]
    missing, unresolved, source = evaluate(attested=False)
    assert target["Arn"] not in missing
    assert_unresolved(unresolved, source, technique)
    for kwargs in ({"attested": False},
                   {"actions": [allow("ec2:ModifyInstanceAttribute", "ec2:StartInstances", resource=instance_arn)]},
                   {"actions": [allow("ec2:StartInstances", "ec2:StopInstances", resource=instance_arn),
                                {"Effect": "Allow", "Action": "ec2:ModifyInstanceAttribute", "Resource": instance_arn,
                                 "Condition": {"StringEquals": {"ec2:Attribute": "groupSet"}}}]},
                   {"changed": {"instance": {"RootDeviceType": "instance-store"}}},
                   {"changed": {"proof": {"UserDataRunsOnRestart": False}}},
                   {"changed": {"proof": {"StopProtectionDisabled": False}},
                    "actions": [allow("ec2:StartInstances", "ec2:StopInstances", resource=instance_arn),
                                {"Effect": "Allow", "Action": "ec2:ModifyInstanceAttribute", "Resource": instance_arn,
                                 "Condition": {"StringEquals": {"ec2:Attribute": "userData"}}}]},
                   {"changed": {"proof": {"TargetRoleId": "old-role"}}},
                   {"changed": {"proof": {"EvidenceExpiresAt": "2026-10-21T11:59:30+00:00"}}}):
        reached_roles, _, _ = evaluate(**kwargs)
        assert target["Arn"] not in reached_roles


def test_cloudcontrol_passrole_needs_a_creatable_admin_user_path():
    technique = "aws-cloudcontrol-passrole-createresource"
    caller = user("caller", allow("iam:PassRole", "cloudformation:CreateResource"))
    complete = role("complete", "cloudformation.amazonaws.com",
                    allow("iam:CreateUser", "iam:GetUser", "iam:CreateLoginProfile", "iam:AttachUserPolicy"))
    no_password = role("no-password", "cloudformation.amazonaws.com",
                       allow("iam:CreateUser", "iam:GetUser", "iam:AttachUserPolicy"))
    no_read = role("no-read", "cloudformation.amazonaws.com",
                   allow("iam:CreateUser", "iam:CreateLoginProfile", "iam:AttachUserPolicy"))
    inline = role("inline", "cloudformation.amazonaws.com",
                  allow("iam:CreateUser", "iam:GetUser", "iam:CreateLoginProfile", "iam:PutUserPolicy"))
    blocked = role("blocked-policy", "cloudformation.amazonaws.com",
                   allow("iam:CreateUser", "iam:GetUser", "iam:CreateLoginProfile"),
                   {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*",
                    "Condition": {"StringEquals": {"iam:PolicyARN":
                                   "arn:aws:iam::aws:policy/ReadOnlyAccess"}}})
    admin = f"aws_account_admin:{ACCOUNT}"
    for usable in (complete, inline):
        result = real(aws_snap([caller], [usable]), technique)
        assert admin in reached(result, caller["Arn"], technique)
    for unusable in (no_password, no_read, blocked):
        result = real(aws_snap([caller], [unusable]), technique)
        assert admin not in reached(result, caller["Arn"], technique)
    without_passrole = user("without-passrole", allow("cloudformation:CreateResource"))
    result = real(aws_snap([without_passrole], [complete]), technique)
    assert admin not in reached(result, without_passrole["Arn"], technique)
    wrong_trust = role("wrong-trust", "lambda.amazonaws.com",
                       allow("iam:CreateUser", "iam:GetUser", "iam:CreateLoginProfile", "iam:AttachUserPolicy"))
    result = real(aws_snap([caller], [wrong_trust]), technique)
    assert admin not in reached(result, caller["Arn"], technique)
    scoped_control = user("scoped-control", allow("iam:PassRole"),
                          allow("cloudformation:CreateResource",
                                resource=f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/example"))
    result = real(aws_snap([scoped_control], [complete]), technique)
    assert admin not in reached(result, scoped_control["Arn"], technique)
    existing = user("reserved")
    exact_existing = role("exact-existing", "cloudformation.amazonaws.com",
                          allow("iam:CreateUser", "iam:GetUser", "iam:CreateLoginProfile",
                                "iam:AttachUserPolicy", resource=existing["Arn"]))
    result = real(aws_snap([caller, existing], [exact_existing]), technique)
    assert admin not in reached(result, caller["Arn"], technique)


def test_cloudcontrol_catalog_keeps_previous_global_action_binding():
    from peaso.privesc import versioned_catalog as catalog

    technique = "aws-cloudcontrol-passrole-createresource"
    prior = {"schema": catalog.BINDING_SCHEMA,
             "manifest_sha256": catalog.CLOUDCONTROL_690_PREVIOUS_MANIFEST,
             "effective_tree_sha256": catalog.CLOUDCONTROL_690_PREVIOUS_TREE,
             "source_revision": catalog.V4_REVISION}
    old, old_status = catalog.lookup_entries([technique], prior)
    current, current_status = catalog.lookup_entries([technique], catalog.current_binding())
    assert old_status == "exact_previous_current"
    assert current_status == "exact_strict_privesc"
    assert old[technique]["requires"]["all_of"][0]["action"] == "cloudformation:CreateResource"
    assert current[technique]["requires"]["all_of"] == []


def test_stepfunctions_teststate_needs_a_supported_role_task_witness():
    technique = "aws-stepfunctions-teststate-passrole"
    caller = user("caller", {"Effect": "Allow", "Action": "iam:PassRole",
                             "Resource": role_arn("execution"), "Condition": {"StringEquals": {
                                 "iam:PassedToService": "states.amazonaws.com"}}},
                  allow("states:TestState"))
    execution_role = role("execution", "states.amazonaws.com", allow("iam:AttachUserPolicy"))
    result = real(aws_snap([caller], [execution_role]), technique, include_unknown=True)
    assert execution_role["Arn"] not in reached(result, caller["Arn"], technique)
    assert_unresolved(result, caller["Arn"], technique)

    wrong_service = user("caller", {"Effect": "Allow", "Action": "iam:PassRole",
                                    "Resource": role_arn("execution"), "Condition": {"StringEquals": {
                                        "iam:PassedToService": "lambda.amazonaws.com"}}},
                         allow("states:TestState"))
    assert not reached(real(aws_snap([wrong_service], [execution_role]), technique),
                       wrong_service["Arn"], technique)


def test_stepfunctions_teststate_accepts_only_reviewed_unmocked_role_effect():
    technique = "aws-stepfunctions-teststate-passrole"
    object_arn = "arn:aws:s3:::example-private-bucket/evidence.txt"
    target = role("execution", "states.amazonaws.com", allow("s3:PutObject", resource=object_arn))
    target["RoleId"] = "AROAEXECUTION123456789"
    passed = allow("iam:PassRole", resource=target["Arn"])
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "states.amazonaws.com"}}
    proof = {"TechniqueId": technique, "SourceArn": ALICE, "TargetKind": "aws_role",
             "TargetId": target["Arn"], "TargetScope": SCOPE, "TargetRoleId": target["RoleId"],
             "Status": "verified", "VerifiedPreconditions": True, "UnmockedTask": True,
             "TestStateSucceeded": True, "TaskOutcomeUsefulToSource": True,
             "TaskAction": "s3:PutObject", "TaskResource": object_arn,
             "EvidenceRef": "reviewed-teststate-call",
             "EvidenceObservedAt": "2026-10-21T11:59:00+00:00",
             "EvidenceExpiresAt": "2026-10-21T12:05:00+00:00"}

    def result(evidence=proof, *, extra_caller=()):
        caller = user("alice", passed, allow("states:TestState"), *extra_caller)
        proofs = evidence if isinstance(evidence, list) else ([evidence] if evidence else [])
        snap = aws_snap([caller], [target], [col("aws_privesc_challenge_evidence", proofs)])
        snap["created_at"] = "2026-10-21T12:00:00+00:00"
        return real(snap, technique, include_unknown=True)

    assert target["Arn"] in reached(result(), ALICE, technique)
    assert target["Arn"] not in reached(result(None), ALICE, technique)
    assert_unresolved(result(None), ALICE, technique)
    assert target["Arn"] not in reached(result([proof, dict(proof)]), ALICE, technique)
    for changed in ({"UnmockedTask": False}, {"TestStateSucceeded": False},
                    {"TaskOutcomeUsefulToSource": False}, {"TargetRoleId": "AROANOTHER"},
                    {"TaskAction": "s3:DeleteObject"}, {"TargetScope": f"{ACCOUNT}/eu-west-1"},
                    {"SourceArn": f"arn:aws:iam::{ACCOUNT}:user/other"},
                    {"EvidenceObservedAt": "2026-10-21T11:40:00+00:00"}):
        assert target["Arn"] not in reached(result(dict(proof, **changed)), ALICE, technique)
    assert target["Arn"] not in reached(result(extra_caller=[allow("s3:PutObject", resource=object_arn)]),
                                        ALICE, technique)


def test_config_automatic_remediation_requires_service_context_and_runtime_witness():
    technique = "aws-config-passrole-automatic-remediation"
    target = role("automation", "ssm.amazonaws.com", allow("iam:AttachUserPolicy"))

    def caller(service):
        return user("caller", {"Effect": "Allow", "Action": "iam:PassRole",
                               "Resource": target["Arn"],
                               "Condition": {"StringEquals": {"iam:PassedToService": service}}},
                    allow("config:PutRemediationConfigurations", "ssm:CreateDocument"))

    correct = caller("ssm.amazonaws.com")
    result = real(aws_snap([correct], [target]), technique, include_unknown=True)
    assert target["Arn"] not in reached(result, correct["Arn"], technique)
    assert_unresolved(result, correct["Arn"], technique)

    scoped = user("caller", {"Effect": "Allow", "Action": "iam:PassRole",
                             "Resource": target["Arn"], "Condition": {"StringEquals": {
                                 "iam:PassedToService": "ssm.amazonaws.com"}}},
                  allow("config:PutRemediationConfigurations",
                        resource=f"arn:aws:config:{REGION}:{ACCOUNT}:remediation-configuration/*"),
                  allow("ssm:CreateDocument",
                        resource=f"arn:aws:ssm:{REGION}:{ACCOUNT}:document/*"))
    assert_unresolved(real(aws_snap([scoped], [target]), technique, include_unknown=True),
                      scoped["Arn"], technique)

    wrong = caller("lambda.amazonaws.com")
    assert not reached(real(aws_snap([wrong], [target]), technique), wrong["Arn"], technique)


def test_stepfunctions_create_and_update_passrole_use_states_service_context():
    execution_role = role("execution", "states.amazonaws.com", allow("iam:AttachUserPolicy"))
    techniques = ("aws-stepfunctions-createstatemachine-passrole-start",
                  "aws-stepfunctions-updatestatemachine-passrole")
    for technique in techniques:
        def caller(service):
            return user("caller", {"Effect": "Allow", "Action": "iam:PassRole",
                                   "Resource": role_arn("execution"),
                                   "Condition": {"StringEquals": {"iam:PassedToService": service}}},
                        allow("states:CreateStateMachine", "states:StartExecution",
                              "states:UpdateStateMachine"))

        right = caller("states.amazonaws.com")
        right_result = real(aws_snap([right], [execution_role]), technique, include_unknown=True)
        assert execution_role["Arn"] not in reached(right_result, right["Arn"], technique)
        assert_unresolved(right_result, right["Arn"], technique)

        wrong = caller("lambda.amazonaws.com")
        wrong_result = real(aws_snap([wrong], [execution_role]), technique)
        assert not reached(wrong_result, wrong["Arn"], technique)


def test_stepfunctions_create_and_update_need_reviewed_role_operation():
    techniques = ("aws-stepfunctions-createstatemachine-passrole-start",
                  "aws-stepfunctions-updatestatemachine-passrole")
    object_arn = "arn:aws:s3:::example-private-bucket/evidence.txt"
    target = role("execution", "states.amazonaws.com", allow("s3:PutObject", resource=object_arn))
    target["RoleId"] = "AROAEXECUTION123456789"
    machine_arn = f"arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:existing"
    machine = {"stateMachineArn": machine_arn, "roleArn": target["Arn"],
               "status": "ACTIVE", "type": "STANDARD", "revisionId": "revision-123"}
    passed = allow("iam:PassRole", resource=target["Arn"])
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "states.amazonaws.com"}}
    caller_actions = allow("states:CreateStateMachine", "states:StartExecution",
                           "states:UpdateStateMachine")

    def result(technique, *, proof=None, machine_row=machine, extra_caller=()):
        caller = user("alice", passed, caller_actions, *extra_caller)
        proofs = proof if isinstance(proof, list) else ([proof] if proof else [])
        snap = aws_snap([caller], [target], [col("sfn_state_machine", [machine_row]),
            col("aws_privesc_challenge_evidence", proofs)])
        snap["created_at"] = "2026-10-21T12:00:00+00:00"
        return real(snap, technique, include_unknown=True)

    for technique in techniques:
        proof = {"TechniqueId": technique, "SourceArn": ALICE, "TargetKind": "aws_role",
                 "TargetId": target["Arn"], "TargetScope": SCOPE, "TargetRoleId": target["RoleId"],
                 "StateMachineArn": machine_arn, "StateMachineRevisionId": "revision-123",
                 "ExecutionArn": f"arn:aws:states:{REGION}:{ACCOUNT}:execution:existing:run1",
                 "Status": "verified", "VerifiedPreconditions": True, "SdkTaskSucceeded": True,
                 "TaskOutcomeUsefulToSource": True, "TaskAction": "s3:PutObject",
                 "TaskResource": object_arn, "EvidenceRef": "reviewed-execution",
                 "EvidenceObservedAt": "2026-10-21T11:59:00+00:00",
                 "EvidenceExpiresAt": "2026-10-21T12:05:00+00:00"}
        assert target["Arn"] in reached(result(technique, proof=proof), ALICE, technique)
        assert target["Arn"] not in reached(result(technique), ALICE, technique)
        assert_unresolved(result(technique), ALICE, technique)
        assert target["Arn"] not in reached(result(technique, proof=[proof, dict(proof)]), ALICE, technique)
        for changed in ({"StateMachineRevisionId": "another"}, {"SdkTaskSucceeded": False},
                        {"TaskOutcomeUsefulToSource": False}, {"TaskAction": "s3:DeleteObject"},
                        {"SourceArn": "arn:aws:iam::111111111111:user/other"},
                        {"EvidenceObservedAt": "2026-10-21T11:40:00+00:00"},
                        {"ExecutionArn": machine_arn}):
            assert target["Arn"] not in reached(result(technique, proof=dict(proof, **changed)), ALICE, technique)
        wrong_role = dict(machine, roleArn=role_arn("other"))
        assert target["Arn"] not in reached(result(technique, proof=proof, machine_row=wrong_role), ALICE, technique)
        direct = allow("s3:PutObject", resource=object_arn)
        assert target["Arn"] not in reached(result(technique, proof=proof, extra_caller=[direct]), ALICE, technique)


def test_stepfunctions_teststate_prior_binding_keeps_previous_route():
    from peaso.privesc import versioned_catalog as catalog

    ident = "aws-stepfunctions-teststate-passrole"
    old_binding = {"schema": catalog.BINDING_SCHEMA,
                   "manifest_sha256": catalog.TESTSTATE_690_PREVIOUS_MANIFEST,
                   "effective_tree_sha256": catalog.TESTSTATE_690_PREVIOUS_TREE,
                   "source_revision": catalog.V4_REVISION}
    old, old_status = catalog.lookup_entries([ident], old_binding)
    new, new_status = catalog.lookup_entries([ident], catalog.current_binding())
    assert old_status == "exact_previous_current"
    assert new_status == "exact_strict_privesc"
    assert "preconditions" not in old[ident]
    assert "stepfunctions_teststate_privileged_task_unverified" in new[ident]["preconditions"]


def test_cloudformation_passrole_requires_a_reviewed_template_effect():
    techniques = {
        "aws-cloudformation-passrole-createstack": "CreateStack",
        "aws-cloudformation-passrole-changeset": "CreateChangeSet",
        "aws-cloudformation-passrole-updatestack": "UpdateStack",
    }
    target_arn = "arn:aws:s3:::private-bucket/evidence.txt"
    target = role("cfn", "cloudformation.amazonaws.com", allow("s3:PutObject", resource=target_arn))
    target["RoleId"] = "AROACFN1234567890123"
    stack_arn = (f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/Existing/"
                 "01234567-89ab-4def-8123-456789abcdef")
    stack = {"StackId": stack_arn, "StackName": "Existing", "StackStatus": "UPDATE_COMPLETE",
             "RoleARN": target["Arn"]}
    passed = allow("iam:PassRole", resource=target["Arn"])
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}}

    def result(technique, evidence=None, *, role_row=target, extra_caller=()):
        caller = user("alice", passed, allow("cloudformation:CreateStack",
                                             "cloudformation:CreateChangeSet",
                                             "cloudformation:ExecuteChangeSet",
                                             "cloudformation:UpdateStack"), *extra_caller)
        proofs = evidence if isinstance(evidence, list) else ([evidence] if evidence else [])
        snap = aws_snap([caller], [role_row], [col("cloudformation_stack", [stack]),
            col("aws_privesc_challenge_evidence", proofs)])
        snap["created_at"] = "2026-10-21T12:00:00+00:00"
        return real(snap, technique, include_unknown=True)

    for technique, operation in techniques.items():
        proof = {"TechniqueId": technique, "SourceArn": ALICE, "TargetKind": "aws_role",
                 "TargetId": target["Arn"], "TargetScope": SCOPE, "TargetRoleId": target["RoleId"],
                 "StackArn": stack_arn, "CloudFormationOperation": operation,
                 "Status": "verified", "VerifiedPreconditions": True,
                 "TemplateControlledBySource": True, "RoleOperationUsed": True,
                 "TemplateEffectSucceeded": True, "EffectUsefulToSource": True,
                 "ChangeSetExecuted": True, "ChangeSetType": "CREATE",
                 "RoleAction": "s3:PutObject", "RoleResource": target_arn,
                 "EvidenceRef": "reviewed-stack-operation",
                 "EvidenceObservedAt": "2026-10-21T11:59:00+00:00",
                 "EvidenceExpiresAt": "2026-10-21T12:05:00+00:00"}
        assert target["Arn"] in reached(result(technique, proof), ALICE, technique)
        no_proof = result(technique)
        assert target["Arn"] not in reached(no_proof, ALICE, technique)
        assert_unresolved(no_proof, ALICE, technique)
        assert target["Arn"] not in reached(result(technique, [proof, dict(proof)]), ALICE, technique)
        for changed in ({"TargetRoleId": "AROADIFFERENT"}, {"RoleOperationUsed": False},
                        {"TemplateEffectSucceeded": False}, {"EffectUsefulToSource": False},
                        {"RoleAction": "s3:DeleteObject"}, {"CloudFormationOperation": "DeleteStack"},
                        {"EvidenceObservedAt": "2026-10-21T11:40:00+00:00"},
                        {"SourceArn": f"arn:aws:iam::{ACCOUNT}:user/other"},
                        {"StackArn": stack_arn.replace(ACCOUNT, OTHER)}):
            assert target["Arn"] not in reached(result(technique, dict(proof, **changed)), ALICE, technique)
        if operation == "CreateChangeSet":
            assert target["Arn"] not in reached(result(technique, dict(proof, ChangeSetExecuted=False)),
                                                ALICE, technique)
            assert target["Arn"] not in reached(result(technique, dict(proof, ChangeSetType="UPDATE")),
                                                ALICE, technique)
        if operation == "UpdateStack":
            assert target["Arn"] not in reached(result(technique, dict(proof, StackArn=stack_arn + "-other")),
                                                ALICE, technique)
        assert target["Arn"] not in reached(result(technique, proof,
            extra_caller=[allow("s3:PutObject", resource=target_arn)]), ALICE, technique)
        readonly = role("cfn", "cloudformation.amazonaws.com", allow("s3:GetObject", resource=target_arn))
        readonly["RoleId"] = target["RoleId"]
        assert target["Arn"] not in reached(result(technique, proof, role_row=readonly), ALICE, technique)


def test_new_iam_user_routes_do_not_reuse_an_existing_exact_name():
    technique = "aws-iam-createuser-policy-accesskey"
    existing = user("reserved")
    exact = user("exact", allow("iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy",
                                resource=existing["Arn"]))
    admin = f"aws_account_admin:{ACCOUNT}"
    result = real(aws_snap([existing, exact]), technique)
    assert admin not in reached(result, exact["Arn"], technique)
    other_path = user("Reserved")
    other_path["Arn"] = f"arn:aws:iam::{ACCOUNT}:user/other/Reserved"
    other_path["Path"] = "/other/"
    same_name = f"arn:aws:iam::{ACCOUNT}:user/team/reserved"
    path_scoped = user("path-scoped", allow("iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy",
                                     resource=same_name))
    result = real(aws_snap([other_path, path_scoped]), technique)
    assert admin not in reached(result, path_scoped["Arn"], technique)
    path_wildcard = f"arn:aws:iam::{ACCOUNT}:user/*/reserved"
    wildcard_path = user("wildcard-path", allow("iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy",
                                           resource=path_wildcard))
    result = real(aws_snap([other_path, wildcard_path]), technique)
    assert admin not in reached(result, wildcard_path["Arn"], technique)
    collision = user("peasobound")
    broad = user("broad", allow("iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy"))
    result = real(aws_snap([collision, broad]), technique)
    assert admin in reached(result, broad["Arn"], technique)


def test_appstream_new_resources_need_a_startable_streaming_path():
    target = role("target", "appstream.amazonaws.com")
    builder_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:app-block-builder/team-a"
    other_builder_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:app-block-builder/team-b"
    block_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:app-block/app-a"
    subnets = [{"SubnetId": "subnet-a", "VpcId": "vpc-1", "AvailabilityZone": "us-east-1a", "State": "available"},
               {"SubnetId": "subnet-b", "VpcId": "vpc-1", "AvailabilityZone": "us-east-1b", "State": "available"}]
    bucket = {"Name": "packages", "Location": {"collection_status": "collected", "LocationConstraint": REGION}}

    def reach(start=True, stream_arn=builder_arn, subnet_rows=subnets, bucket_row=bucket,
              occupied=(), create_block_resource="*"):
        grants = [allow("iam:PassRole", resource=target["Arn"]),
                  allow("appstream:CreateAppBlockBuilder", resource=builder_arn),
                  allow("appstream:CreateAppBlock", resource=create_block_resource),
                  allow("appstream:AssociateAppBlockBuilderAppBlock", resource=[builder_arn, block_arn]),
                  allow("appstream:CreateAppBlockBuilderStreamingURL", resource=stream_arn)]
        if start:
            grants.append(allow("appstream:StartAppBlockBuilder", resource=builder_arn))
        snap = aws_snap([user("alice", *grants)], roles=[target], extra=[
            col("appstream_app_block_builder", [{"Name": name} for name in occupied]),
            col("appstream_app_block", []), col("subnet", subnet_rows),
            col("bucket", [bucket_row], scope=f"{ACCOUNT}/global")])
        return reached(real(snap, "aws-appstream-passrole-createappblockbuilder"), ALICE)

    expected = {target["Arn"]: "conditional"}
    assert reach() == expected
    assert reach(start=False) == {}
    assert reach(stream_arn=other_builder_arn) == {}
    assert reach(subnet_rows=subnets[:1]) == {}
    assert reach(bucket_row={**bucket, "Location": {"collection_status": "collected", "LocationConstraint": "eu-west-1"}}) == {}
    assert reach(occupied=("team-a",)) == {}
    assert reach(create_block_resource=block_arn) == {}


def test_appstream_new_builder_can_use_existing_unassociated_app_block():
    target = role("target", "appstream.amazonaws.com")
    builder_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:app-block-builder/new"
    block_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:app-block/existing"
    subnets = [{"SubnetId": "subnet-a", "VpcId": "vpc-1", "AvailabilityZone": "us-east-1a", "State": "available"},
               {"SubnetId": "subnet-b", "VpcId": "vpc-1", "AvailabilityZone": "us-east-1b", "State": "available"}]
    grants = [allow("iam:PassRole", resource=target["Arn"]),
              allow("appstream:CreateAppBlockBuilder", "appstream:StartAppBlockBuilder",
                    "appstream:CreateAppBlockBuilderStreamingURL", resource=builder_arn),
              allow("appstream:AssociateAppBlockBuilderAppBlock", resource=[builder_arn, block_arn])]
    block = {"Arn": block_arn, "Name": "existing", "PackagingType": "APPSTREAM2", "State": "INACTIVE"}

    def reach(associations=(), package_type="APPSTREAM2"):
        snap = aws_snap([user("alice", *grants)], roles=[target], extra=[
            col("appstream_app_block_builder", []),
            col("appstream_app_block", [{**block, "PackagingType": package_type}]),
            col("appstream_app_block_builder_association", list(associations)),
            col("subnet", subnets)])
        return reached(real(snap, "aws-appstream-passrole-createappblockbuilder"), ALICE)

    assert reach() == {target["Arn"]: "conditional"}
    assert reach(associations=({"AppBlockArn": block_arn, "AppBlockBuilderName": "other"},)) == {}
    assert reach(package_type="CUSTOM") == {}


def test_appstream_new_fleet_binds_image_fleet_and_stack_permissions():
    technique = "aws-appstream-passrole-createimagebuilder-createfleet"
    target = role("target", "appstream.amazonaws.com")
    image_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:image/base"
    fleet_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:fleet/team-a"
    other_fleet_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:fleet/team-b"
    stack_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:stack/prod"
    image = {"Arn": image_arn, "Name": "base", "State": "AVAILABLE", "Visibility": "PRIVATE"}
    stack = {"Arn": stack_arn, "Name": "prod"}

    def reach(stream_arn=fleet_arn, image_row=image, stacks=(stack,), occupied=(), create_stack=False,
              stack_url=True):
        grants = [allow("iam:PassRole", resource=target["Arn"]),
                  allow("appstream:CreateFleet", resource=[image_arn, fleet_arn]),
                  allow("appstream:StartFleet", "appstream:AssociateFleet", resource=fleet_arn),
                  allow("appstream:CreateStreamingURL", resource=stream_arn),
                  allow("appstream:AssociateFleet", resource=stack_arn)]
        if stack_url:
            grants.append(allow("appstream:CreateStreamingURL", resource=stack_arn))
        if create_stack:
            grants.append(allow("appstream:CreateStack", "appstream:AssociateFleet",
                                "appstream:CreateStreamingURL"))
        snap = aws_snap([user("alice", *grants)], roles=[target], extra=[
            col("appstream_image", [image_row]),
            col("appstream_fleet", [{"Name": name} for name in occupied]),
            col("appstream_stack", list(stacks))])
        return reached(real(snap, technique), ALICE)

    expected = {target["Arn"]: "conditional"}
    assert reach() == expected
    assert reach(stack_url=False) == {}
    assert reach(stream_arn=other_fleet_arn) == {}
    assert reach(image_row={**image, "State": "FAILED"}) == {}
    assert reach(occupied=("team-a",)) == {}
    assert reach(stacks=()) == {}
    assert reach(stacks=(), create_stack=True) == expected


def test_appstream_new_image_builder_uses_available_image_and_one_builder_arn():
    technique = "aws-appstream-passrole-createimagebuilder"
    target = role("target", "appstream.amazonaws.com")
    image_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:image/base"
    builder_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:image-builder/team-a"
    other_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:image-builder/team-b"
    image = {"Arn": image_arn, "Name": "base", "State": "AVAILABLE",
             "ImageBuilderSupported": True, "Visibility": "PRIVATE"}

    def reach(image_row=image, create_arn=builder_arn, stream_arn=builder_arn, occupied=()):
        grants = [allow("iam:PassRole", resource=target["Arn"]),
                  allow("appstream:CreateImageBuilder", resource=[image_arn, create_arn]),
                  allow("appstream:CreateImageBuilderStreamingURL", resource=stream_arn)]
        snap = aws_snap([user("alice", *grants)], roles=[target], extra=[
            col("appstream_image", [image_row]),
            col("appstream_image_builder", [{"Name": name} for name in occupied])])
        return reached(real(snap, technique), ALICE)

    assert reach() == {target["Arn"]: "conditional"}
    assert reach(stream_arn=other_arn) == {}
    assert reach(image_row={**image, "State": "FAILED"}) == {}
    assert reach(image_row={**image, "ImageBuilderSupported": False}) == {}
    assert reach(occupied=("team-a",)) == {}


def test_appstream_fleet_role_swap_uses_one_associated_fleet_and_its_state():
    technique = "aws-appstream-passrole-updatefleet"
    target = role("target", "appstream.amazonaws.com")
    fleet_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:fleet/team-a"
    other_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:fleet/team-b"
    expected = {target["Arn"]: "conditional"}

    def reach(state="STOPPED", stacks=("prod",), extra_actions=(), url_arn=fleet_arn,
              associations=True, stack_url=True):
        fleet = {"Arn": fleet_arn, "Name": "team-a", "State": state}
        if associations:
            fleet["AssociatedStacks"] = {"collection_status": "collected", "items": list(stacks)}
        grants = [allow("iam:PassRole", resource=target["Arn"]),
                  allow("appstream:UpdateFleet", "appstream:StartFleet", resource=fleet_arn),
                  allow("appstream:CreateStreamingURL", resource=url_arn)]
        if stack_url:
            grants.append(allow("appstream:CreateStreamingURL",
                                resource=f"arn:aws:appstream:{REGION}:{ACCOUNT}:stack/prod"))
        grants += [allow(action, resource=fleet_arn) for action in extra_actions]
        snap = aws_snap([user("alice", *grants)], roles=[target], extra=[col("appstream_fleet", [fleet])])
        return reached(real(snap, technique), ALICE)

    assert reach() == expected
    assert reach(stack_url=False) == {}
    assert reach(url_arn=other_arn) == {}
    assert reach(state="RUNNING") == {}
    assert reach(state="RUNNING", extra_actions=("appstream:StopFleet",)) == expected
    assert reach(stacks=()) == {}
    assert reach(associations=False) == {}


def test_appstream_unassociated_fleet_needs_creatable_stack_in_same_region():
    technique = "aws-appstream-passrole-updatefleet"
    target = role("target", "appstream.amazonaws.com")
    fleet_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:fleet/f"
    fleet = {"Arn": fleet_arn, "Name": "f", "State": "STOPPED",
             "AssociatedStacks": {"collection_status": "collected", "items": []}}
    base = [allow("iam:PassRole", resource=target["Arn"]),
            allow("appstream:UpdateFleet", "appstream:StartFleet", "appstream:CreateStreamingURL", resource=fleet_arn)]

    def reach(stack_status="empty", extra_grants=()):
        snap = aws_snap([user("alice", *(base + list(extra_grants)))], roles=[target],
                        extra=[col("appstream_fleet", [fleet]), col("appstream_stack", [], stack_status)])
        return reached(real(snap, technique), ALICE)

    create = [allow("appstream:CreateStack", "appstream:AssociateFleet",
                    "appstream:CreateStreamingURL")]
    assert reach() == {}
    assert reach(extra_grants=[allow("appstream:CreateStack", "appstream:AssociateFleet")]) == {}
    assert reach(extra_grants=create) == {target["Arn"]: "conditional"}
    assert reach(stack_status="denied", extra_grants=create) == {}


def test_appstream_builder_role_swap_needs_one_associated_startable_builder():
    technique = "aws-appstream-passrole-updateappblockbuilder"
    target = role("target", "appstream.amazonaws.com")
    builder_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:app-block-builder/team-a"
    other_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:app-block-builder/team-b"
    block_arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:app-block/app-a"
    expected = {target["Arn"]: "conditional"}

    def reach(state="STOPPED", association=True, stop=False, stream_arn=builder_arn, assoc_status="collected"):
        builder = {"Arn": builder_arn, "Name": "team-a", "State": state}
        grants = [allow("iam:PassRole", resource=target["Arn"]),
                  allow("appstream:UpdateAppBlockBuilder", "appstream:StartAppBlockBuilder", resource=builder_arn),
                  allow("appstream:CreateAppBlockBuilderStreamingURL", resource=stream_arn)]
        if stop:
            grants.append(allow("appstream:StopAppBlockBuilder", resource=builder_arn))
        associations = [{"AppBlockBuilderName": "team-a", "AppBlockArn": block_arn}] if association else []
        snap = aws_snap([user("alice", *grants)], roles=[target], extra=[
            col("appstream_app_block_builder", [builder]),
            col("appstream_app_block_builder_association", associations, assoc_status)])
        return reached(real(snap, technique), ALICE)

    assert reach() == expected
    assert reach(stream_arn=other_arn) == {}
    assert reach(state="RUNNING") == {}
    assert reach(state="RUNNING", stop=True) == expected
    assert reach(association=False) == {}
    assert reach(assoc_status="denied") == {}


# --------------------------------------------------------------------------- EKS
EKS_ADMIN = allow("eks:CreateAccessEntry", "eks:AssociateAccessPolicy")


def eks_cluster(mode="API_AND_CONFIG_MAP", name="prod"):
    cluster = {"name": name, "arn": f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/{name}",
               "endpoint": f"https://{name.upper()}.gr7.{REGION}.eks.amazonaws.com",
               "status": "ACTIVE", "version": "1.31", "platformVersion": "eks.1"}
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


def test_eks_admin_routes_require_cluster_admin_policy_and_cluster_scope():
    admin_policy = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    edit_policy = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy"

    def association(condition):
        statement = allow("eks:AssociateAccessPolicy")
        statement["Condition"] = {"StringEquals": condition}
        return statement

    for condition in ({"eks:policyArn": edit_policy}, {"eks:accessScope": "namespace"}):
        principal = user("alice", allow("eks:CreateAccessEntry"), association(condition))
        snap = aws_snap([principal], extra=[col("eks_cluster", [eks_cluster("API")])])
        assert reached(real(snap, "aws-eks-createaccessentry-associateaccesspolicy"), ALICE) == {}

    allowed = association({"eks:policyArn": admin_policy, "eks:accessScope": "cluster"})
    principal = user("alice", allow("eks:CreateAccessEntry"), allowed)
    snap = aws_snap([principal], extra=[col("eks_cluster", [eks_cluster("API")])])
    assert reached(real(snap, "aws-eks-createaccessentry-associateaccesspolicy"), ALICE) == {
        f"k8s_cluster_admin:{EKS_ARN}": "conditional"}

    for mode, expected in (("API", {}), ("API_AND_CONFIG_MAP", {f"k8s_cluster_admin:{EKS_ARN}": "conditional"})):
        change = allow("eks:UpdateClusterConfig")
        change["Condition"] = {"StringEquals": {"eks:authenticationMode": mode}}
        principal = user("alice", change, allow("eks:CreateAccessEntry"), allowed)
        snap = aws_snap([principal], extra=[col("eks_cluster", [eks_cluster("CONFIG_MAP")])])
        assert reached(real(snap, "aws-eks-updateclusterconfig-enable-access-entries"), ALICE) == expected
    principal = user("alice", allow("eks:UpdateClusterConfig", "eks:CreateAccessEntry",
                                    "eks:AssociateAccessPolicy"))
    for version, platform, status, allowed_result in (("1.28", "eks.5", "ACTIVE", False),
                                                       ("1.28", "eks.6", "ACTIVE", True),
                                                       ("1.30", "eks.1", "ACTIVE", False),
                                                       ("1.30", "eks.2", "ACTIVE", True),
                                                       ("1.31", "eks.1", "UPDATING", False)):
        cluster = eks_cluster("CONFIG_MAP")
        cluster["Cluster"]["cluster"].update(version=version, platformVersion=platform, status=status)
        snap = aws_snap([principal], extra=[col("eks_cluster", [cluster])])
        found = reached(real(snap, "aws-eks-updateclusterconfig-enable-access-entries"), ALICE)
        assert bool(found) is allowed_result, (version, platform, status, found)
    missing = eks_cluster("CONFIG_MAP")
    missing["Cluster"]["cluster"].pop("version")
    snap = aws_snap([principal], extra=[col("eks_cluster", [missing])])
    assert_unresolved(real(snap, "aws-eks-updateclusterconfig-enable-access-entries",
                           include_unknown=True), ALICE)


def test_eks_new_admin_entry_is_bound_to_the_callers_iam_principal():
    entry = f"arn:aws:eks:{REGION}:{ACCOUNT}:access-entry/prod/user/{ACCOUNT}/alice/*"
    other = entry.replace("/alice/", "/bob/")
    associated = allow("eks:AssociateAccessPolicy", resource=entry)

    def check(create, associate=associated, entries=(), status="empty"):
        snap = aws_snap([user("alice", create, associate)], extra=[col("eks_cluster", [eks_cluster("API")])])
        collection = next(c for c in snap["collections"] if c["type"] == "eks_access_entry")
        collection.update(items=list(entries), status=status)
        return reached(real(snap, "aws-eks-createaccessentry-associateaccesspolicy"), ALICE)

    expected = {f"k8s_cluster_admin:{EKS_ARN}": "conditional"}
    own = allow("eks:CreateAccessEntry")
    own["Condition"] = {"ArnEquals": {"eks:principalArn": ALICE}}
    assert check(own) == expected
    bob = allow("eks:CreateAccessEntry")
    bob["Condition"] = {"ArnEquals": {"eks:principalArn": f"arn:aws:iam::{ACCOUNT}:user/bob"}}
    assert check(bob) == {}
    assert check(own, allow("eks:AssociateAccessPolicy", resource=other)) == {}
    assert check(own, entries=[{"clusterName": "prod", "principalArn": ALICE}]) == {}
    assert check(own, status="denied") == {}


def test_eks_existing_admin_entry_requires_exact_controlled_standard_entry():
    technique = "aws-eks-associateaccesspolicy-existing-entry"
    arn = f"arn:aws:eks:{REGION}:{ACCOUNT}:access-entry/prod/user/{ACCOUNT}/alice/" + "a" * 32
    policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    row = {"clusterName": "prod", "principalArn": ALICE, "accessEntryArn": arn, "type": "STANDARD",
           "AssociatedAccessPolicies": {"collection_status": "empty", "items": []}}

    def check(entries, statement=None):
        snap = aws_snap([user("alice", statement or allow("eks:AssociateAccessPolicy", resource=arn))],
                        extra=[col("eks_cluster", [eks_cluster("API")])])
        collection = next(c for c in snap["collections"] if c["type"] == "eks_access_entry")
        collection.update(items=entries, status="collected" if entries else "empty")
        return reached(real(snap, technique), ALICE)

    expected = {f"k8s_cluster_admin:{EKS_ARN}": "conditional"}
    assert check([row]) == expected
    assert check([dict(row, principalArn=f"arn:aws:iam::{ACCOUNT}:user/bob")]) == {}
    assert check([dict(row, type="EC2_LINUX")]) == {}
    assert check([dict(row, AssociatedAccessPolicies={"collection_status": "collected", "items": [
        {"policyArn": policy_arn, "accessScope": {"type": "cluster"}}]})]) == {}
    assert check([row], allow("eks:AssociateAccessPolicy", resource=arn.replace("/alice/", "/bob/"))) == {}
    namespace = allow("eks:AssociateAccessPolicy", resource=arn)
    namespace["Condition"] = {"StringEquals": {"eks:accessScope": "namespace"}}
    assert check([row], namespace) == {}
    other_policy = allow("eks:AssociateAccessPolicy", resource=arn)
    other_policy["Condition"] = {"ArnEquals": {
        "eks:policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"}}
    assert check([row], other_policy) == {}


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
    roles = [node, role("app", "ecs-tasks.amazonaws.com"), role("app-execution", "ecs-tasks.amazonaws.com"),
             role("far", "ecs-tasks.amazonaws.com")]
    tds = task_defs if task_defs is not None else [
        {"taskDefinitionArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/app:1", "taskRoleArn": role_arn("app"),
         "executionRoleArn": role_arn("app-execution"),
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


def test_ecscape_reaches_task_and_execution_roles_on_the_source_instance():
    got = reached(real(ecs_snap(placed_cluster()), ECSCAPE), NODE_ARN)
    assert set(got) == {role_arn("app"), role_arn("app-execution")}   # "far" runs on i-2


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


def complete_root_scp(snap, *statements):
    root = "r-root123"
    content = policy(*(statements or (allow("*"),)))
    row = {"Id": "p-root", "TargetId": root, "TargetType": "ROOT",
           "Detail": {"Policy": {"Content": content}}, "InheritanceComplete": True,
           "InheritedPolicies": {"complete": True, "collection_status": "collected",
                                 "ParentPath": [{"Id": ACCOUNT, "Type": "ACCOUNT"},
                                                {"Id": root, "Type": "ROOT"}],
                                 "items": [{"Id": "p-root", "TargetId": root, "Content": content}]}}
    management = next(c for c in snap["collections"] if c["type"] == "scp_policy" and c["scope"] == SCOPE)
    management["status"] = "collected"
    management["items"].append(row)
    snap["collections"].append({"type": "organization_parent", "scope": SCOPE,
                                "service": "organization_parent", "status": "collected",
                                "items": [{"ChildId": ACCOUNT, "ParentId": root}], "error": None})
    for collection in list(snap["collections"]):
        if collection["type"] != "organization_account":
            continue
        for member in collection["items"]:
            member_scope = f"{member['Id']}/{REGION}"
            if not any(c["type"] == "rcp_policy" and c["scope"] == member_scope
                       for c in snap["collections"]):
                snap["collections"].append({"type": "rcp_policy", "scope": member_scope,
                                            "service": "organizations", "status": "empty",
                                            "items": [], "error": None})
    return snap


def test_createaccount_reaches_principalorgid_trusts_from_management_account():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    shared, foreign = role("shared", org_trust(), account=OTHER), role("foreign", org_trust("o-zzzzzzzzzz"), account=OTHER)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [shared, foreign])]))
    assert set(reached(real(snap, CREATE_ACCOUNT), ALICE)) == {role_arn("shared", OTHER)}


def test_createaccount_needs_generated_access_role_grant_not_target_role_grant():
    shared = role("shared", org_trust(), account=OTHER)
    only_target = user("alice", allow("organizations:CreateAccount"),
                       allow("sts:AssumeRole", resource=shared["Arn"]))
    snap = aws_snap([only_target], extra=[org_accounts(OTHER)], other_roles=[(OTHER, [shared])])
    result = real(snap, CREATE_ACCOUNT, include_unknown=True)
    assert shared["Arn"] not in reached(result, ALICE, CREATE_ACCOUNT)
    assert_unresolved(result, ALICE, CREATE_ACCOUNT)

    generated_role = user("alice", allow("organizations:CreateAccount"),
                          allow("sts:AssumeRole",
                                resource="arn:aws:iam::*:role/OrganizationAccountAccessRole"))
    snap = complete_root_scp(aws_snap([generated_role], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [shared])]))
    assert shared["Arn"] in reached(real(snap, CREATE_ACCOUNT), ALICE, CREATE_ACCOUNT)

    custom_role = user("alice", allow("organizations:CreateAccount"),
                       allow("sts:AssumeRole", resource="arn:aws:iam::*:role/ChosenAccessRole"))
    snap = complete_root_scp(aws_snap([custom_role], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [shared])]))
    assert shared["Arn"] in reached(real(snap, CREATE_ACCOUNT), ALICE, CREATE_ACCOUNT)


def test_createaccount_does_not_override_explicit_role_trust_deny():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    denied = role("denied", [*org_trust(), {"Effect": "Deny", "Principal": "*",
                                            "Action": "sts:AssumeRole"}], account=OTHER)
    snap = aws_snap([alice], extra=[org_accounts(OTHER)], other_roles=[(OTHER, [denied])])
    assert role_arn("denied", OTHER) not in reached(real(snap, CREATE_ACCOUNT), ALICE)


def test_createaccount_additional_target_trust_condition_is_unknown():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    target_trust = org_trust()
    target_trust[0]["Condition"]["IpAddress"] = {"aws:SourceIp": "192.0.2.0/24"}
    target = role("shared", target_trust, account=OTHER)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [target])]))
    result = real(snap, CREATE_ACCOUNT, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, CREATE_ACCOUNT)
    assert_unresolved(result, ALICE, CREATE_ACCOUNT)


def test_createaccount_new_member_cannot_bypass_root_scp_assume_role_deny():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    target = role("shared", org_trust(), account=OTHER)
    unaffected = role("other-shared", org_trust(), account=OTHER)
    root = "r-root123"
    parent = col("organization_parent", [{"ChildId": ACCOUNT, "ParentId": root}])
    baseline = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER), parent],
                                         other_roles=[(OTHER, [target, unaffected])]))
    assert target["Arn"] in reached(real(baseline, CREATE_ACCOUNT), ALICE)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [target, unaffected])]),
                             allow("*"), {"Effect": "Deny", "Action": "sts:AssumeRole",
                                          "Resource": target["Arn"]})
    assert target["Arn"] not in reached(real(snap, CREATE_ACCOUNT), ALICE)
    assert unaffected["Arn"] in reached(real(snap, CREATE_ACCOUNT), ALICE)


def test_createaccount_new_member_needs_root_scp_assume_role_allow():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    target = role("shared", org_trust(), account=OTHER)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [target])]), allow("s3:*"))
    result = real(snap, CREATE_ACCOUNT, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, CREATE_ACCOUNT)
    assert_unresolved(result, ALICE, CREATE_ACCOUNT)


def test_createaccount_new_member_root_scp_conditional_deny_is_unknown():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    target = role("shared", org_trust(), account=OTHER)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [target])]),
                             allow("*"), {"Effect": "Deny", "Action": "sts:AssumeRole",
                                          "Resource": target["Arn"], "Condition": {"StringEquals": {
                                              "aws:PrincipalTag/Environment": "restricted"}}})
    result = real(snap, CREATE_ACCOUNT, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, CREATE_ACCOUNT)
    assert_unresolved(result, ALICE, CREATE_ACCOUNT)


def test_createaccount_new_member_needs_complete_root_scp_inventory():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    target = role("shared", org_trust(), account=OTHER)
    snap = aws_snap([alice], extra=[org_accounts(OTHER)], other_roles=[(OTHER, [target])])
    result = real(snap, CREATE_ACCOUNT, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, CREATE_ACCOUNT)
    assert_unresolved(result, ALICE, CREATE_ACCOUNT)


def test_createaccount_partial_scp_cannot_broaden_complete_root_allowlist():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    target = role("shared", org_trust(), account=OTHER)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [target])]), allow("s3:*"))
    member = next(c for c in snap["collections"] if c["type"] == "scp_policy" and
                  c["scope"] == f"{OTHER}/{REGION}")
    member["status"] = "partial"
    member["items"].append({"Id": "p-incomplete", "TargetId": "r-root123",
                            "Detail": {"Policy": {"Content": policy(allow("*"))}}})
    result = real(snap, CREATE_ACCOUNT, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, CREATE_ACCOUNT)
    assert_unresolved(result, ALICE, CREATE_ACCOUNT)


def test_createaccount_target_role_rcp_deny_blocks_new_member():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    target = role("shared", org_trust(), account=OTHER)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [target])]))
    snap["collections"].append({"type": "organization_parent", "scope": f"{OTHER}/{REGION}",
                                "service": "organization_parent", "status": "collected",
                                "items": [{"ChildId": OTHER, "ParentId": "r-root123"}], "error": None})
    rcp = next(c for c in snap["collections"] if c["type"] == "rcp_policy" and
               c["scope"] == f"{OTHER}/{REGION}")
    rcp["status"] = "collected"
    rcp["items"] = [{"Id": "p-deny", "TargetId": OTHER, "Content": policy(
        {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": target["Arn"]})}]
    assert target["Arn"] not in reached(real(snap, CREATE_ACCOUNT), ALICE, CREATE_ACCOUNT)


def test_createaccount_target_role_rcp_unknown_stays_unresolved():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    target = role("shared", org_trust(), account=OTHER)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [target])]))
    rcp = next(c for c in snap["collections"] if c["type"] == "rcp_policy" and
               c["scope"] == f"{OTHER}/{REGION}")
    rcp["status"] = "access_denied"
    result = real(snap, CREATE_ACCOUNT, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, CREATE_ACCOUNT)
    assert_unresolved(result, ALICE, CREATE_ACCOUNT)


def test_createaccount_can_use_complete_root_scp_from_known_member():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    target = role("shared", org_trust(), account=OTHER)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [target])]))
    management = next(c for c in snap["collections"] if c["type"] == "scp_policy" and c["scope"] == SCOPE)
    member = next(c for c in snap["collections"] if c["type"] == "scp_policy" and
                  c["scope"] == f"{OTHER}/{REGION}")
    root_policy = management["items"].pop()
    management["status"] = "empty"
    member["status"] = "collected"
    root_policy["InheritedPolicies"]["ParentPath"][0]["Id"] = OTHER
    member["items"].append(root_policy)
    assert target["Arn"] in reached(real(snap, CREATE_ACCOUNT), ALICE, CREATE_ACCOUNT)


def test_createaccount_new_member_needs_definite_generated_role_grant():
    assume = allow("sts:AssumeRole", resource="arn:aws:iam::*:role/OrganizationAccountAccessRole")
    assume["Condition"] = {"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}}
    alice = user("alice", allow("organizations:CreateAccount"), assume)
    target = role("shared", org_trust(), account=OTHER)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [target])]))
    result = real(snap, CREATE_ACCOUNT, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, CREATE_ACCOUNT)
    assert_unresolved(result, ALICE, CREATE_ACCOUNT)


def test_createaccount_management_identity_is_exempt_from_scps():
    alice = user("alice", allow("organizations:CreateAccount", "sts:AssumeRole"))
    target = role("shared", org_trust(), account=OTHER)
    snap = complete_root_scp(aws_snap([alice], extra=[org_accounts(OTHER)],
                                     other_roles=[(OTHER, [target])]))
    management_scp = next(c for c in snap["collections"] if c["type"] == "scp_policy" and c["scope"] == SCOPE)
    management_scp["status"] = "collected"
    management_scp["items"].append({"Id": "p-management", "TargetId": ACCOUNT,
        "Detail": {"Policy": {"Content": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Action": ["organizations:CreateAccount", "sts:AssumeRole"],
             "Resource": "*"}]}}}, "InheritanceComplete": True,
        "InheritedPolicies": {"complete": True, "collection_status": "collected",
                              "ParentPath": [{"Id": ACCOUNT, "Type": "ACCOUNT"},
                                             {"Id": "r-root123", "Type": "ROOT"}], "items": []}})
    assert target["Arn"] in reached(real(snap, CREATE_ACCOUNT), ALICE)

    member = user("bob", allow("sts:AssumeRole"), account=OTHER)
    member_snap = aws_snap([], extra=[org_accounts(OTHER),
        col("iam_user", [member], scope=f"{OTHER}/{REGION}")], other_roles=[(OTHER, [])])
    member_scp = next(c for c in member_snap["collections"]
                      if c["type"] == "scp_policy" and c["scope"] == f"{OTHER}/{REGION}")
    member_scp["status"] = "collected"
    member_scp["items"] = [{"Id": "p-member", "TargetId": OTHER,
        "Detail": {"Policy": {"Content": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"}]}}}}]
    model = privesc.MODELS["aws"](member_snap)
    assert model._check_action(model.principals[member["Arn"]], "sts:AssumeRole", target["Arn"]) is None


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
    ec2 = role("emr-ec2", "ec2.amazonaws.com",
               allow("sts:AssumeRole", "sts:TagSession", resource=role_arn("runtime")),
               profiles=[profile_arn("emr-ec2")])
    runtime = role("runtime", [{"Effect": "Allow", "Principal": {"AWS": role_arn("emr-ec2")},
                                "Action": ["sts:AssumeRole", "sts:TagSession"]}], profiles=[])
    return [ec2, runtime, role("unrelated", "ec2.amazonaws.com", profiles=[])]


def emr_cluster(security=True):
    cluster = {"Id": "j-1", "Status": {"State": "WAITING"},
               "Ec2InstanceAttributes": {"IamInstanceProfile": "emr-ec2"}}
    if security:
        cluster["SecurityConfiguration"] = "runtime-roles"
    return {"Cluster": {"Cluster": cluster}}


def emr_security_config(enabled, external_id=None):
    iam = {"EnableApplicationScopedIAMRole": enabled}
    if external_id is not None:
        iam["ExternalIdSha256"] = hashlib.sha256(external_id.encode()).hexdigest()
    return {"Name": "runtime-roles", "Configuration": {"collection_status": "collected",
            "SecurityConfiguration": json.dumps({"AuthorizationConfiguration": {"IAMConfiguration": iam}})}}


def test_emr_getclustersessioncredentials_reaches_runtime_roles():
    tid = "aws-emr-getclustersessioncredentials-runtime-role"
    alice = user("alice", allow("elasticmapreduce:GetClusterSessionCredentials"))
    active = [col("emr_cluster", [emr_cluster()]), col("emr_security_configuration", [emr_security_config(True)])]
    assert_unresolved(real(aws_snap([alice], emr_roles(), active), tid, include_unknown=True), ALICE)
    cluster_arn = f"arn:aws:elasticmapreduce:{REGION}:{ACCOUNT}:cluster/j-1"
    scoped = user("alice", allow("elasticmapreduce:GetClusterSessionCredentials", resource=cluster_arn))
    assert_unresolved(real(aws_snap([scoped], emr_roles(), active), tid, include_unknown=True), ALICE)
    wrong_cluster = user("alice", allow("elasticmapreduce:GetClusterSessionCredentials",
                                resource=cluster_arn.replace("j-1", "j-other")))
    assert edges(real(aws_snap([wrong_cluster], emr_roles(), active), tid), ALICE) == []
    wrong_role_condition = user("alice", {"Effect": "Allow",
        "Action": "elasticmapreduce:GetClusterSessionCredentials", "Resource": cluster_arn,
        "Condition": {"ArnEquals": {"elasticmapreduce:ExecutionRoleArn": role_arn("other")}}})
    assert edges(real(aws_snap([wrong_role_condition], emr_roles(), active), tid), ALICE) == []
    matching_role_condition = user("alice", {"Effect": "Allow",
        "Action": "elasticmapreduce:GetClusterSessionCredentials", "Resource": cluster_arn,
        "Condition": {"ArnEquals": {"elasticmapreduce:ExecutionRoleArn": role_arn("runtime")}}})
    assert_unresolved(real(aws_snap([matching_role_condition], emr_roles(), active),
                           tid, include_unknown=True), ALICE)
    external_id_roles = emr_roles()
    external_id_roles[1]["AssumeRolePolicyDocument"]["Statement"][0]["Condition"] = {
        "StringEquals": {"sts:ExternalId": "uncollected-emr-external-id"}}
    conditional_trust = real(aws_snap([alice], external_id_roles, active), tid, include_unknown=True)
    assert all(finding["status"] != "FAIL" for finding in conditional_trust["findings"])
    matched_external = [col("emr_cluster", [emr_cluster()]),
                        col("emr_security_configuration", [emr_security_config(True, "uncollected-emr-external-id")])]
    assert_unresolved(real(aws_snap([alice], external_id_roles, matched_external),
                           tid, include_unknown=True), ALICE)
    wrong_external = [col("emr_cluster", [emr_cluster()]),
                      col("emr_security_configuration", [emr_security_config(True, "different-external-id")])]
    assert edges(real(aws_snap([alice], external_id_roles, wrong_external), tid), ALICE) == []
    denied_roles = emr_roles()
    denied_roles[1]["AssumeRolePolicyDocument"]["Statement"].append({
        "Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"})
    assert edges(real(aws_snap([alice], denied_roles, active), tid), ALICE) == []
    disabled = [col("emr_cluster", [emr_cluster()]), col("emr_security_configuration", [emr_security_config(False)])]
    assert edges(real(aws_snap([alice], emr_roles(), disabled), tid), ALICE) == []
    assert edges(real(aws_snap([alice], emr_roles(), [col("emr_cluster", [emr_cluster(False)]),
                             col("emr_security_configuration", [emr_security_config(True)])]), tid), ALICE) == []
    missing_config = real(aws_snap([alice], emr_roles(), [col("emr_cluster", [emr_cluster()])]),
                          tid, include_unknown=True)
    assert all(finding["status"] != "FAIL" for finding in missing_config["findings"])
    assert_unresolved(real(aws_snap([alice], emr_roles()), tid, include_unknown=True), ALICE)


def test_emr_runtime_role_steps_need_exact_cluster_role_and_host_permissions():
    tid = "aws-emr-addjobflowsteps-runtime-role"
    cluster_arn = f"arn:aws:elasticmapreduce:{REGION}:{ACCOUNT}:cluster/j-1"
    active = [col("emr_cluster", [emr_cluster()]),
              col("emr_security_configuration", [emr_security_config(True)])]
    allowed = user("alice", {"Effect": "Allow", "Action": "elasticmapreduce:AddJobFlowSteps",
                             "Resource": cluster_arn, "Condition": {"ArnEquals": {
                                 "elasticmapreduce:ExecutionRoleArn": role_arn("runtime")}}})
    assert reached(real(aws_snap([allowed], emr_roles(), active), tid), ALICE, tid) == {
        role_arn("runtime"): "conditional"}
    wrong_cluster = user("alice", allow("elasticmapreduce:AddJobFlowSteps",
                                         resource=cluster_arn.replace("j-1", "j-other")))
    assert edges(real(aws_snap([wrong_cluster], emr_roles(), active), tid), ALICE) == []
    wrong_role = user("alice", {"Effect": "Allow", "Action": "elasticmapreduce:AddJobFlowSteps",
                               "Resource": cluster_arn, "Condition": {"ArnEquals": {
                                   "elasticmapreduce:ExecutionRoleArn": role_arn("unrelated")}}})
    assert edges(real(aws_snap([wrong_role], emr_roles(), active), tid), ALICE) == []
    no_host_grant = emr_roles()
    no_host_grant[0]["RolePolicyList"] = []
    assert edges(real(aws_snap([allowed], no_host_grant, active), tid), ALICE) == []
    no_host_tag = emr_roles()
    no_host_tag[0]["RolePolicyList"][0]["PolicyDocument"]["Statement"][0]["Action"] = "sts:AssumeRole"
    assert edges(real(aws_snap([allowed], no_host_tag, active), tid), ALICE) == []
    disabled = [col("emr_cluster", [emr_cluster()]),
                col("emr_security_configuration", [emr_security_config(False)])]
    assert edges(real(aws_snap([allowed], emr_roles(), disabled), tid), ALICE) == []


def test_emr_on_eks_execution_roles_trust_the_cluster_oidc_provider():
    oidc = f"arn:aws:iam::{ACCOUNT}:oidc-provider/oidc.eks.{REGION}.amazonaws.com/id/ABC"
    job = role("emr-job", [{"Effect": "Allow", "Principal": {"Federated": oidc}, "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {"StringLike": {f"oidc.eks.{REGION}.amazonaws.com/id/ABC:sub":
                                                         "system:serviceaccount:spark:emr-containers-sa-*-*-111111111111-*"}}}])
    irsa = role("irsa", [{"Effect": "Allow", "Principal": {"Federated": oidc}, "Action": "sts:AssumeRoleWithWebIdentity",
                          "Condition": {"StringEquals": {f"oidc.eks.{REGION}.amazonaws.com/id/ABC:sub": "system:serviceaccount:a:b"}}}])
    alice = user("alice", allow("iam:PassRole", "emr-containers:StartJobRun", "emr-containers:GetManagedEndpointSessionCredentials"))
    ids = ("aws-emr-containers-passrole-startjobrun", "aws-emr-containers-getmanagedendpointsessioncredentials")
    virtual_cluster = f"arn:aws:emr-containers:{REGION}:{ACCOUNT}:/virtualclusters/abc123"
    endpoint = virtual_cluster + "/endpoints/def456"
    inventory = [col("emr_container_virtual_cluster", [{"arn": virtual_cluster, "state": "RUNNING",
                  "EksNamespace": "spark", "EksClusterName": "cluster-one"}]),
                 col("emr_container_endpoint", [{"arn": endpoint, "state": "ACTIVE"}]),
                 col("eks_cluster", [{"cluster": {"name": "cluster-one",
                     "arn": f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/cluster-one",
                     "status": "ACTIVE", "identity": {"oidc": {
                         "issuer": f"https://oidc.eks.{REGION}.amazonaws.com/id/ABC"}}}}])]
    result = real(aws_snap([alice], [job, irsa], inventory), *ids)
    for tid in ids:
        assert set(reached(result, ALICE, tid)) == {role_arn("emr-job")}
    no_pass = user("alice", allow("emr-containers:StartJobRun"))
    assert edges(real(aws_snap([no_pass], [job], inventory), *ids), ALICE) == []
    wrong_action = copy.deepcopy(job)
    wrong_action["RoleName"] = "wrong-action"
    wrong_action["Arn"] = role_arn("wrong-action")
    wrong_action["AssumeRolePolicyDocument"]["Statement"][0]["Action"] = "sts:AssumeRole"
    denied = copy.deepcopy(job)
    denied["RoleName"] = "denied"
    denied["Arn"] = role_arn("denied")
    denied["AssumeRolePolicyDocument"]["Statement"].append(
        {"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRoleWithWebIdentity"})
    assert edges(real(aws_snap([alice], [wrong_action, denied], inventory), *ids), ALICE) == []
    missing = real(aws_snap([alice], [job]), *ids, include_unknown=True)
    assert {edge["confidence"] for edge in edges(missing, ALICE)} == {"unknown"}
    assert all(finding["status"] != "FAIL" for finding in missing["findings"])
    inactive = [col("emr_container_virtual_cluster", [{"arn": virtual_cluster, "state": "ARRESTED",
                 "EksNamespace": "spark", "EksClusterName": "cluster-one"}]),
                col("emr_container_endpoint", [{"arn": endpoint, "state": "TERMINATED"}])]
    assert edges(real(aws_snap([alice], [job], inactive), *ids), ALICE) == []
    wrong_scope = user("alice", allow("iam:PassRole"), allow("emr-containers:StartJobRun",
                       resource=f"arn:aws:emr-containers:{REGION}:{ACCOUNT}:/virtualclusters/other"),
                       allow("emr-containers:GetManagedEndpointSessionCredentials",
                             resource=virtual_cluster + "/endpoints/other"))
    assert edges(real(aws_snap([wrong_scope], [job], inventory), *ids), ALICE) == []
    wrong_namespace = copy.deepcopy(inventory)
    wrong_namespace[0][2][0]["EksNamespace"] = "other"
    assert edges(real(aws_snap([alice], [job], wrong_namespace), *ids), ALICE) == []
    wrong_issuer = copy.deepcopy(inventory)
    wrong_issuer[2][2][0]["cluster"]["identity"]["oidc"]["issuer"] = "https://oidc.eks.us-east-1.amazonaws.com/id/OTHER"
    assert edges(real(aws_snap([alice], [job], wrong_issuer), *ids), ALICE) == []
    wrong_audience = copy.deepcopy(job)
    wrong_audience["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]["StringEquals"] = {
        f"oidc.eks.{REGION}.amazonaws.com/id/ABC:aud": "not-sts.example"}
    assert edges(real(aws_snap([alice], [wrong_audience], inventory), *ids), ALICE) == []
    provider_deny = copy.deepcopy(job)
    provider_deny["AssumeRolePolicyDocument"]["Statement"].append({
        "Effect": "Deny", "Principal": {"Federated": oidc}, "Action": "sts:AssumeRoleWithWebIdentity"})
    assert edges(real(aws_snap([alice], [provider_deny], inventory), *ids), ALICE) == []
    exact_subject = copy.deepcopy(job)
    exact_subject["AssumeRolePolicyDocument"]["Statement"][0]["Condition"] = {
        "StringEquals": {f"oidc.eks.{REGION}.amazonaws.com/id/ABC:sub":
            f"system:serviceaccount:spark:emr-containers-sa-spark-client-{ACCOUNT}-sample"}}
    assert edges(real(aws_snap([alice], [exact_subject], inventory), *ids), ALICE) == []
    exact_subject["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]["StringEquals"][
        f"oidc.eks.{REGION}.amazonaws.com/id/ABC:sub"] = (
            f"system:serviceaccount:spark:emr-containers-sa-spark-client-{ACCOUNT}-7t3vvv3mh5u")
    for tid in ids:
        assert set(reached(real(aws_snap([alice], [exact_subject], inventory), tid), ALICE)) == {role_arn("emr-job")}
    scoped = user("alice", allow("iam:PassRole", resource=role_arn("emr-job")),
                  allow("emr-containers:StartJobRun", resource=virtual_cluster),
                  allow("emr-containers:GetManagedEndpointSessionCredentials", resource=endpoint))
    scoped_result = real(aws_snap([scoped], [job], inventory), *ids)
    for tid in ids:
        assert set(reached(scoped_result, ALICE, tid)) == {role_arn("emr-job")}
    wrong_role_context = user("alice", allow("iam:PassRole", resource=role_arn("emr-job")),
                              {"Effect": "Allow", "Action": "emr-containers:StartJobRun",
                               "Resource": virtual_cluster,
                               "Condition": {"StringEquals": {"emr-containers:ExecutionRoleArn": role_arn("other")}}})
    assert edges(real(aws_snap([wrong_role_context], [job], inventory), ids[0]), ALICE) == []


def test_eks_pod_identity_passrole_cluster_condition_is_not_rejected_as_wrong_service():
    from peaso.privesc.effective_permissions.aws_conditions import Context, evaluate
    condition = {"ArnLike": {"iam:AssociatedResourceArn":
                 f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/*"}}
    ctx = Context(action="iam:passrole", resource=role_arn("pod-job"),
                  passed_to=("pods.eks.amazonaws.com",))
    verdict, reason = evaluate(condition, ctx)
    assert verdict is None and reason
    wrong = {"ArnLike": {"iam:AssociatedResourceArn":
             f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:*"}}
    assert evaluate(wrong, ctx)[0] is False


def test_emr_on_eks_pod_identity_requires_matching_associations_and_exact_grants():
    tid = "aws-emr-containers-passrole-startjobrun-pod-identity"
    target = role("pod-job", [{"Effect": "Allow", "Principal": {"Service": "pods.eks.amazonaws.com"},
                               "Action": ["sts:AssumeRole", "sts:TagSession"]}])
    cluster_arn = f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/cluster-one"
    vc_arn = f"arn:aws:emr-containers:{REGION}:{ACCOUNT}:/virtualclusters/abc123"
    passrole = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn("pod-job"),
                "Condition": {"StringEquals": {"iam:PassedToService": "pods.eks.amazonaws.com"},
                              "ArnLike": {"iam:AssociatedResourceArn": cluster_arn}}}
    start = {"Effect": "Allow", "Action": "emr-containers:StartJobRun", "Resource": vc_arn,
             "Condition": {"ArnEquals": {"emr-containers:ExecutionRoleArn": role_arn("pod-job")}}}
    alice = user("alice", passrole, start)
    associations = [{"clusterName": "cluster-one", "namespace": "spark", "roleArn": role_arn("pod-job"),
                     "serviceAccount": f"emr-containers-sa-spark-{kind}-{ACCOUNT}-8nm5wgw14yq"}
                    for kind in ("client", "driver", "executor")]
    inventory = [col("emr_container_virtual_cluster", [{"arn": vc_arn, "state": "RUNNING",
                  "EksNamespace": "spark", "EksClusterName": "cluster-one"}]),
                 col("eks_cluster", [{"cluster": {"name": "cluster-one", "arn": cluster_arn,
                     "status": "ACTIVE"}}]),
                 col("eks_pod_identity_association", associations)]
    assert set(reached(real(aws_snap([alice], [target], inventory), tid), ALICE)) == {role_arn("pod-job")}
    missing_executor = copy.deepcopy(inventory)
    missing_executor[2][2].pop()
    assert edges(real(aws_snap([alice], [target], missing_executor), tid), ALICE) == []
    wrong_suffix = copy.deepcopy(inventory)
    for association in wrong_suffix[2][2]:
        association["serviceAccount"] = association["serviceAccount"].replace("8nm5wgw14yq", "abc123")
    assert edges(real(aws_snap([alice], [target], wrong_suffix), tid), ALICE) == []
    wrong_namespace = copy.deepcopy(inventory)
    wrong_namespace[0][2][0]["EksNamespace"] = "other"
    assert edges(real(aws_snap([alice], [target], wrong_namespace), tid), ALICE) == []
    wrong_service = user("alice", {**passrole, "Condition": {"StringEquals": {
        "iam:PassedToService": "emr-containers.amazonaws.com"}}}, start)
    assert edges(real(aws_snap([wrong_service], [target], inventory), tid), ALICE) == []
    missing_tag_session = copy.deepcopy(target)
    missing_tag_session["AssumeRolePolicyDocument"]["Statement"][0]["Action"] = "sts:AssumeRole"
    assert edges(real(aws_snap([alice], [missing_tag_session], inventory), tid), ALICE) == []
    wrong_start = user("alice", passrole, {**start, "Resource": vc_arn.replace("abc123", "other")})
    assert edges(real(aws_snap([wrong_start], [target], inventory), tid), ALICE) == []
    no_associations = inventory[:2]
    missing = real(aws_snap([alice], [target], no_associations), tid, include_unknown=True)
    assert all(finding["status"] != "FAIL" for finding in missing["findings"])


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
    result = real(snap, tid, include_unknown=True)
    assert role_arn("launch") not in reached(result, ALICE, tid)
    assert_unresolved(result, ALICE, tid)
    wrong = user("alice", allow("servicecatalog:AssociatePrincipalWithPortfolio",
                                resource=f"arn:aws:catalog:{REGION}:{ACCOUNT}:portfolio/port-2"), prov)
    assert edges(real(aws_snap([wrong], roles, [col("servicecatalog_portfolio", [sc_portfolio()])]), tid), ALICE) == []
    assert_unresolved(real(aws_snap([alice], roles), tid, include_unknown=True), ALICE)


def test_servicecatalog_create_artifact_does_not_prove_launch_role_effect():
    tid = "aws-servicecatalog-createprovisioningartifact-provisionproduct"
    alice = user("alice", allow("servicecatalog:CreateProvisioningArtifact",
                                "servicecatalog:ProvisionProduct"))
    target = role("launch", "servicecatalog.amazonaws.com", allow("iam:CreateRole"))
    snap = aws_snap([alice], [target], [col("servicecatalog_portfolio", [sc_portfolio()])])
    result = real(snap, tid, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, tid)
    assert_unresolved(result, ALICE, tid)


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


def test_lambda_new_function_url_requires_both_invoke_actions_on_one_function():
    tid = "aws-lambda-passrole-createfunction-functionurl"
    fn_a = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:alpha"
    fn_b = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:beta"
    base = (allow("iam:PassRole", resource=role_arn("fn")),
            allow("lambda:CreateFunction", resource=fn_a),
            allow("lambda:CreateFunctionUrlConfig", resource=fn_a),
            allow("lambda:InvokeFunctionUrl", resource=fn_a))
    via_url = {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_a,
               "Condition": {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}}
    roles = [role("fn", "lambda.amazonaws.com")]
    def snap(principal, functions=()):
        return aws_snap([principal], roles, [col("lambda_function", functions, "empty" if not functions else "collected")])
    permitted = user("alice", *base, via_url)
    assert reached(real(snap(permitted), tid), ALICE) == {role_arn("fn"): "conditional"}
    assert edges(real(snap(user("alice", *base)), tid), ALICE) == []
    disjoint = user("alice", *base, allow("lambda:InvokeFunction", resource=fn_b))
    assert edges(real(snap(disjoint), tid), ALICE) == []
    wrong_auth = user("alice", *base[:-1], {"Effect": "Allow", "Action": "lambda:InvokeFunctionUrl",
                   "Resource": fn_a, "Condition": {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}}, via_url)
    assert edges(real(snap(wrong_auth), tid), ALICE) == []
    wrong_create_auth = user("alice", base[0], base[1],
                             {"Effect": "Allow", "Action": "lambda:CreateFunctionUrlConfig",
                              "Resource": fn_a, "Condition": {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}},
                             base[3], via_url)
    assert edges(real(snap(wrong_create_auth), tid), ALICE) == []
    assert edges(real(snap(permitted, ({"FunctionName": "alpha", "FunctionArn": fn_a},)), tid), ALICE) == []
    associated = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn("fn"),
                  "Condition": {"ArnEquals": {"iam:AssociatedResourceArn": fn_b}}}
    assert edges(real(snap(user("alice", associated, *base[1:], via_url)), tid), ALICE) == []
    associated["Condition"]["ArnEquals"]["iam:AssociatedResourceArn"] = fn_a
    assert reached(real(snap(user("alice", associated, *base[1:], via_url)), tid), ALICE) == {
        role_arn("fn"): "conditional"}


def test_lambda_eventbridge_trigger_joins_rule_region_and_passrole_function():
    tid = "aws-lambda-passrole-createfunction-eventbridge-trigger"
    function = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:alpha"
    rule = f"arn:aws:events:{REGION}:{ACCOUNT}:rule/trigger"
    other_rule = f"arn:aws:events:us-west-2:{ACCOUNT}:rule/trigger"
    roles = [role("fn", "lambda.amazonaws.com")]
    def snap(principal, rules=(), rule_status="empty"):
        return aws_snap([principal], roles, [col("lambda_function", [], "empty"),
                                           col("event_rule", rules, rule_status)])
    def principal(rule_arn, associated=function, grant_principal=None):
        add_permission = allow("lambda:AddPermission", resource=function)
        if grant_principal:
            add_permission["Condition"] = {"StringEquals": {"lambda:Principal": grant_principal}}
        return user("alice",
                    allow("iam:PassRole", resource=role_arn("fn")) |
                    {"Condition": {"ArnEquals": {"iam:AssociatedResourceArn": associated}}},
                    allow("lambda:CreateFunction", resource=function),
                    add_permission,
                    allow("events:PutRule", resource=rule_arn),
                    allow("events:PutTargets", resource=rule_arn))
    assert reached(real(snap(principal(rule)), tid), ALICE) == {role_arn("fn"): "conditional"}
    wildcard_rule = f"arn:aws:events:*:{ACCOUNT}:rule/*"
    assert reached(real(snap(principal(wildcard_rule)), tid), ALICE) == {
        role_arn("fn"): "conditional"}
    assert edges(real(snap(principal(other_rule)), tid), ALICE) == []
    assert edges(real(snap(principal(rule, function.replace("alpha", "beta"))), tid), ALICE) == []
    assert edges(real(snap(principal(rule, grant_principal="s3.amazonaws.com")), tid), ALICE) == []
    assert reached(real(snap(principal(rule, grant_principal="events.amazonaws.com")), tid), ALICE) == {
        role_arn("fn"): "conditional"}
    assert edges(real(snap(principal(rule), [{"Arn": rule, "ManagedBy": "aws.events"}],
                           "collected"), tid), ALICE) == []
    assert edges(real(snap(principal(rule), [{"Arn": rule}], "collected"), tid), ALICE) == []
    assert role_arn("fn") not in reached(real(aws_snap([principal(rule)], roles,
                                                        [col("lambda_function", [], "empty")]), tid), ALICE)


def test_lambda_new_function_routes_reject_disjoint_exact_function_names():
    fn_a = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:alpha"
    fn_b = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:beta"
    roles = [role("fn", "lambda.amazonaws.com")]
    def snap(principal, functions=()):
        return aws_snap([principal], roles, [col("lambda_function", functions, "empty" if not functions else "collected")])
    for tid, last_action in (
            ("aws-lambda-passrole-createfunction-invokefunction", "lambda:InvokeFunction"),
            ("aws-lambda-passrole-createfunction-addpermission", "lambda:AddPermission")):
        base = (allow("iam:PassRole", resource=role_arn("fn")),
                allow("lambda:CreateFunction", resource=fn_a))
        possible = user("alice", *base, allow(last_action, resource=fn_a))
        assert reached(real(snap(possible), tid), ALICE) == {role_arn("fn"): "conditional"}
        assert role_arn("fn") not in reached(real(aws_snap([possible], roles), tid, include_unknown=True), ALICE)
        impossible = user("alice", *base, allow(last_action, resource=fn_b))
        assert edges(real(snap(impossible), tid), ALICE) == []
        assert edges(real(snap(possible, ({"FunctionName": "alpha", "FunctionArn": fn_a},)), tid), ALICE) == []
        wrong_association = user("alice", allow("iam:PassRole", resource=role_arn("fn")) |
                                 {"Condition": {"ArnEquals": {"iam:AssociatedResourceArn": fn_b}}},
                                 *base[1:], allow(last_action, resource=fn_a))
        assert edges(real(snap(wrong_association), tid), ALICE) == []
        right_association = user("alice", allow("iam:PassRole", resource=role_arn("fn")) |
                                 {"Condition": {"ArnEquals": {"iam:AssociatedResourceArn": fn_a}}},
                                 *base[1:], allow(last_action, resource=fn_a))
        assert reached(real(snap(right_association), tid), ALICE) == {role_arn("fn"): "conditional"}
        two_functions = user("alice", allow("iam:PassRole", resource=role_arn("fn")) |
                             {"Condition": {"ArnEquals": {"iam:AssociatedResourceArn": fn_b}}},
                             allow("lambda:CreateFunction", resource=[fn_a, fn_b]),
                             allow(last_action, resource=[fn_a, fn_b]))
        result = real(snap(two_functions), tid)
        assert reached(result, ALICE) == {role_arn("fn"): "conditional"}
        detail = next(d for e in edges(result, ALICE, tid) for d in e["technique_details"] if d["id"] == tid)
        assert [ref["bound_resource"] for ref in detail["evidence_refs"]
                if isinstance(ref, dict) and "bound_resource" in ref] == [fn_b]


def test_lambda_addpermission_must_allow_grant_to_the_source_principal():
    tid = "aws-lambda-passrole-createfunction-addpermission"
    fn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:alpha"
    base = (allow("iam:PassRole", resource=role_arn("fn")),
            allow("lambda:CreateFunction", resource=fn))
    def scoped(principal):
        return {"Effect": "Allow", "Action": "lambda:AddPermission", "Resource": fn,
                "Condition": {"StringEquals": {"lambda:Principal": principal}}}
    roles = [role("fn", "lambda.amazonaws.com")]
    def snap(principal):
        return aws_snap([principal], roles, [col("lambda_function", (), "empty")])
    correct = user("alice", *base, scoped(ALICE))
    assert reached(real(snap(correct), tid), ALICE) == {role_arn("fn"): "conditional"}
    service_only = user("alice", *base, scoped("events.amazonaws.com"))
    assert edges(real(snap(service_only), tid), ALICE) == []
    explicit_deny = user("alice", *base, scoped(ALICE),
                         {"Effect": "Deny", "Action": "lambda:InvokeFunction", "Resource": fn})
    assert edges(real(snap(explicit_deny), tid), ALICE) == []
    other_function_deny = user("alice", *base, scoped(ALICE),
                               {"Effect": "Deny", "Action": "lambda:InvokeFunction",
                                "Resource": fn.replace(":alpha", ":beta")})
    assert reached(real(snap(other_function_deny), tid), ALICE) == {role_arn("fn"): "conditional"}
    boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/limit"
    bounded = user("alice", *base, scoped(ALICE))
    bounded["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary_arn}
    bounded_snap = snap(bounded)
    boundary = {"Arn": boundary_arn, "PolicyName": "limit", "PolicyVersionList": [
        {"IsDefaultVersion": True, "Document": policy(
            allow("*"), {"Effect": "Deny", "Action": "lambda:InvokeFunction", "Resource": fn})}]}
    next(c for c in bounded_snap["collections"] if c["type"] == "iam_policy")["items"] = [boundary]
    assert edges(real(bounded_snap, tid), ALICE) == []
    scp_snap = snap(correct)
    scp = {"Id": "p-invoke-deny", "TargetId": ACCOUNT,
           "Detail": {"Policy": {"Content": policy(
               allow("*"), {"Effect": "Deny", "Action": "lambda:InvokeFunction", "Resource": fn})}}}
    scp_collection = next(c for c in scp_snap["collections"] if c["type"] == "scp_policy")
    scp_collection.update(status="collected", items=[scp])
    assert edges(real(scp_snap, tid), ALICE) == []


def test_athena_spark_route_needs_one_creatable_executable_workgroup():
    tid = "aws-athena-passrole-createworkgroup-spark"
    group_a = f"arn:aws:athena:{REGION}:{ACCOUNT}:workgroup/alpha"
    group_b = f"arn:aws:athena:{REGION}:{ACCOUNT}:workgroup/beta"
    roles = [role("spark", "athena.amazonaws.com")]
    base = (allow("iam:PassRole", resource=role_arn("spark")),
            allow("athena:CreateWorkGroup", resource=group_a),
            allow("athena:StartSession", resource=group_a))
    def snap(principal, groups=(), status="empty"):
        return aws_snap([principal], roles, [col("athena_workgroup", groups, status)])
    possible = user("alice", *base, allow("athena:StartCalculationExecution", resource=group_a))
    assert reached(real(snap(possible), tid), ALICE) == {role_arn("spark"): "conditional"}
    disjoint = user("alice", *base, allow("athena:StartCalculationExecution", resource=group_b))
    assert edges(real(snap(disjoint), tid), ALICE) == []
    assert edges(real(snap(possible, ({"Name": "alpha"},), "collected"), tid), ALICE) == []
    assert reached(real(snap(possible, ({"Name": "beta"},), "collected"), tid), ALICE) == {
        role_arn("spark"): "conditional"}
    assert edges(real(snap(possible, status="denied"), tid), ALICE) == []
    wildcard = user("alice", allow("iam:PassRole", resource=role_arn("spark")),
                    allow("athena:CreateWorkGroup", "athena:StartSession",
                          "athena:StartCalculationExecution",
                          resource=f"arn:aws:athena:{REGION}:{ACCOUNT}:workgroup/team-*"))
    occupied = ({"Name": "team-peasobound"},)
    assert reached(real(snap(wildcard, occupied, "collected"), tid), ALICE) == {
        role_arn("spark"): "conditional"}
    invalid_region = user("alice", allow("iam:PassRole", resource=role_arn("spark")),
                          allow("athena:CreateWorkGroup", "athena:StartSession",
                                "athena:StartCalculationExecution",
                                resource=f"arn:aws:athena:invalid:{ACCOUNT}:workgroup/alpha"))
    assert edges(real(snap(invalid_region), tid), ALICE) == []
    def passrole_for(workgroup):
        return {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn("spark"),
                "Condition": {"ArnEquals": {"iam:AssociatedResourceArn": workgroup},
                              "StringEquals": {"iam:PassedToService": "athena.amazonaws.com"}}}
    wrong_binding = user("alice", passrole_for(group_b), *base[1:],
                         allow("athena:StartCalculationExecution", resource=group_a))
    assert edges(real(snap(wrong_binding), tid), ALICE) == []
    right_binding = user("alice", passrole_for(group_a), *base[1:],
                         allow("athena:StartCalculationExecution", resource=group_a))
    assert reached(real(snap(right_binding), tid), ALICE) == {role_arn("spark"): "conditional"}


def test_grafana_api_key_admin_requires_supported_active_workspace():
    tid = "aws-grafana-createworkspaceapikey-admin"
    arn = f"arn:aws:grafana:{REGION}:{ACCOUNT}:/workspaces/g-0123456789"
    principal = user("alice", allow("grafana:CreateWorkspaceApiKey", resource=arn))
    def snap(version, status="ACTIVE"):
        workspace = {"id": "g-0123456789", "Arn": arn, "status": status}
        if version is not None:
            workspace["grafanaVersion"] = version
        return aws_snap([principal], extra=[col("grafana_workspace", [workspace])])
    assert reached(real(snap("10.4"), tid), ALICE)
    assert reached(real(snap("11.0"), tid), ALICE)
    assert edges(real(snap("12.0"), tid), ALICE) == []
    assert edges(real(snap("10.4", "DELETING"), tid), ALICE) == []
    assert edges(real(snap(None), tid), ALICE) == []
    assert_unresolved(real(snap(None), tid, include_unknown=True), ALICE)


def test_grafana_service_account_admin_requires_version_nine_and_both_actions():
    tid = "aws-grafana-serviceaccounttoken-admin"
    arn = f"arn:aws:grafana:{REGION}:{ACCOUNT}:/workspaces/g-0123456789"
    def snap(version, *actions):
        workspace = {"id": "g-0123456789", "Arn": arn, "status": "ACTIVE",
                     "grafanaVersion": version}
        return aws_snap([user("alice", allow(*actions, resource=arn))],
                        extra=[col("grafana_workspace", [workspace])])
    actions = ("grafana:CreateWorkspaceServiceAccount",
               "grafana:CreateWorkspaceServiceAccountToken")
    assert reached(real(snap("9.5", *actions), tid), ALICE)
    assert reached(real(snap("12.0", *actions), tid), ALICE)
    assert edges(real(snap("8.4", *actions), tid), ALICE) == []
    assert edges(real(snap("9.5", actions[0]), tid), ALICE) == []
    assert edges(real(snap("9.5", actions[1]), tid), ALICE) == []


def test_grafana_saml_admin_requires_active_workspace():
    tid = "aws-grafana-updateworkspaceauthentication-saml-admin"
    arn = f"arn:aws:grafana:{REGION}:{ACCOUNT}:/workspaces/g-0123456789"
    def snap(status, action="grafana:UpdateWorkspaceAuthentication"):
        row = {"id": "g-0123456789", "Arn": arn}
        if status is not None:
            row["status"] = status
        return aws_snap([user("alice", allow(action, resource=arn))],
                        extra=[col("grafana_workspace", [row])])
    assert reached(real(snap("ACTIVE"), tid), ALICE)
    assert edges(real(snap("DELETING"), tid), ALICE) == []
    assert edges(real(snap("ACTIVE", "grafana:DescribeWorkspace"), tid), ALICE) == []
    assert_unresolved(real(snap(None), tid, include_unknown=True), ALICE)


def test_braket_passrole_service_condition_is_evaluated():
    tid = "aws-braket-passrole-createjob"
    def snap(service):
        passrole = {"Effect": "Allow", "Action": "iam:PassRole",
                    "Resource": role_arn("job"),
                    "Condition": {"StringEquals": {"iam:PassedToService": service}}}
        return aws_snap([user("alice", passrole, allow("braket:CreateJob"))],
                        [role("job", "braket.amazonaws.com")])
    assert edges(real(snap("lambda.amazonaws.com"), tid), ALICE) == []
    assert_unresolved(real(snap("braket.amazonaws.com"), tid, include_unknown=True), ALICE)


def test_braket_prior_catalog_binding_keeps_global_createjob_requirement():
    from peaso.privesc import versioned_catalog as catalog

    prior_binding = {"schema": catalog.BINDING_SCHEMA,
                     "manifest_sha256": catalog.BRAKET_690_PREVIOUS_MANIFEST,
                     "effective_tree_sha256": catalog.BRAKET_690_PREVIOUS_TREE,
                     "source_revision": catalog.V4_REVISION}
    old, old_status = catalog.lookup_entries(["aws-braket-passrole-createjob"], prior_binding)
    new, new_status = catalog.lookup_entries(["aws-braket-passrole-createjob"],
                                             catalog.current_binding())
    assert old_status == "exact_previous_current"
    assert new_status == "exact_strict_privesc"
    assert any(req["action"] == "braket:CreateJob"
               for req in old["aws-braket-passrole-createjob"]["requires"]["all_of"])
    assert all(req["action"] != "braket:CreateJob"
               for req in new["aws-braket-passrole-createjob"]["requires"]["all_of"])


def test_scheduler_requires_grant_on_same_account_schedule_resource():
    from pathlib import Path
    import yaml
    from peaso.privesc.effective_permissions.aws import AwsModel
    from peaso.privesc.evaluator import Evaluator

    catalog_file = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/aws/scheduler.yaml"
    entry = next(item for item in yaml.safe_load(catalog_file.read_text())
                 if item["id"] == "aws-scheduler-passrole-createschedule-or-updateschedule")
    passed = role("scheduled", "scheduler.amazonaws.com",
                  allow("iam:PutUserPolicy", resource=ALICE))

    def evaluate(schedule_resource, *, target_role=passed, pass_service=None, source_grants=()):
        passing = allow("iam:PassRole", resource=passed["Arn"])
        if pass_service is not None:
            passing["Condition"] = {"StringEquals": {"iam:PassedToService": pass_service}}
        caller = user("alice", passing, allow("scheduler:CreateSchedule", resource=schedule_resource),
                      *source_grants)
        snap = aws_snap([caller], [target_role])
        return [reach.targets for reach in Evaluator(AwsModel(snap), [entry],
                 include_unknown=False).run() if reach.source.id == ALICE]

    same_account = f"arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule/default/*"
    other_account = f"arn:aws:scheduler:{REGION}:{OTHER}:schedule/default/*"
    assert evaluate(f"arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule-group/*") == []
    assert evaluate(other_account) == []
    assert any(any("scheduler-policy:" in target for target in targets)
               for targets in evaluate(same_account))
    assert evaluate(same_account, target_role=role("scheduled", "scheduler.amazonaws.com")) == []
    assert evaluate(same_account, target_role=role("scheduled", "lambda.amazonaws.com",
                                                    allow("iam:PutUserPolicy", resource=ALICE))) == []
    wrong_schedule_trust = role("scheduled", [{"Effect": "Allow",
        "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"ArnEquals": {"aws:SourceArn":
            f"arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule/default/other"}}}],
        allow("iam:PutUserPolicy", resource=ALICE))
    assert evaluate(same_account, target_role=wrong_schedule_trust) == []
    assert evaluate(same_account, target_role=role("scheduled", "scheduler.amazonaws.com",
                                                    allow("iam:PutUserPolicy", resource=role_arn("other")))) == []
    assert evaluate(same_account, pass_service="lambda.amazonaws.com") == []
    assert evaluate(same_account, source_grants=[allow("iam:CreateUser")]) == []
    assert evaluate(same_account, source_grants=[{"Effect": "Deny", "Action": "iam:CreateUser",
                                                  "Resource": "*"}]) == []


def test_scheduler_inline_policy_route_can_target_creator_role():
    from pathlib import Path
    import yaml
    from peaso.privesc.effective_permissions.aws import AwsModel
    from peaso.privesc.evaluator import Evaluator

    entry = yaml.safe_load((Path(__file__).resolve().parents[1] /
                            "peaso/privesc/catalog/aws/scheduler.yaml").read_text())[0]
    executor_arn = role_arn("scheduled")
    creator = role("creator", "ec2.amazonaws.com",
                   allow("iam:PassRole", resource=executor_arn),
                   allow("scheduler:CreateSchedule", resource=
                         f"arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule/default/*"))
    executor = role("scheduled", "scheduler.amazonaws.com",
                    allow("iam:PutRolePolicy", resource=creator["Arn"]))
    reaches = [reach.targets for reach in Evaluator(AwsModel(aws_snap([], [creator, executor])),
               [entry], include_unknown=False).run() if reach.source.id == creator["Arn"]]
    assert any(any("scheduler-policy:" in target for target in targets) for targets in reaches)


def test_datapipeline_grants_without_customer_and_role_pair_stay_unresolved():
    from pathlib import Path
    import yaml
    from peaso.privesc.effective_permissions.aws import AwsModel
    from peaso.privesc.evaluator import Evaluator

    entry = yaml.safe_load((Path(__file__).resolve().parents[1] /
                            "peaso/privesc/catalog/aws/datapipeline.yaml").read_text())[0]
    target = role("instance", "ec2.amazonaws.com", profiles=[profile_arn("instance")])
    caller = user("alice", allow("iam:PassRole", resource=target["Arn"]),
                  allow("datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition",
                        "datapipeline:ActivatePipeline"))
    snap = aws_snap([caller], [target])
    assert [r for r in Evaluator(AwsModel(snap), [entry], include_unknown=False).run()
            if r.source.id == ALICE] == []
    unresolved = [r for r in Evaluator(AwsModel(snap), [entry], include_unknown=True).run()
                  if r.source.id == ALICE]
    assert unresolved and all(grant.confidence == "unknown" for r in unresolved
                              for grant in r.targets.values())


def test_synthetics_canary_inventory_binds_exact_execution_role():
    import ast
    from pathlib import Path
    from peaso.privesc.effective_permissions.aws import AwsModel, HOST_KIND

    collector = ast.parse((Path(__file__).resolve().parents[1] / "peaso/collectors/aws.py").read_text())
    declared = {node.targets[0].id: ast.literal_eval(node.value)
                for node in collector.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in {"SPECS", "_NATIVE_IDS"}}
    assert declared["SPECS"]["synthetics_canary"] == ("synthetics", "describe_canaries", "Canaries")
    assert declared["_NATIVE_IDS"]["synthetics_canary"] == "Name"

    canary_role = role("canary", "lambda.amazonaws.com")
    canary_arn = f"arn:aws:synthetics:{REGION}:{ACCOUNT}:canary:daily_check"
    snap = aws_snap([user("alice")], [canary_role], [col("synthetics_canary", [
        {"Id": "canary-id", "Name": "daily_check", "ExecutionRoleArn": canary_role["Arn"]}])])
    model = AwsModel(snap)
    assert HOST_KIND["synthetics_canary"] == "synthetics_canary"
    assert model.hosts[canary_role["Arn"]]["synthetics_canary"] == [canary_arn]
    assert model.host_status[(ACCOUNT, "synthetics_canary")] == "collected"

    missing_role = aws_snap([user("alice")], [canary_role], [col("synthetics_canary", [
        {"Id": "canary-id", "Name": "daily_check"}])])
    incomplete = AwsModel(missing_role)
    assert incomplete.hosts.get(canary_role["Arn"], {}).get("synthetics_canary") is None
    assert incomplete.host_status[(ACCOUNT, "synthetics_canary")] == "partial"


def test_sqs_queue_policy_self_grant_requires_new_effective_receive_permission():
    from pathlib import Path
    import yaml
    from peaso.privesc.effective_permissions.aws import AwsModel
    from peaso.privesc.evaluator import Evaluator

    catalog_file = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/aws/sqs.yaml"
    entry = yaml.safe_load(catalog_file.read_text())[0]
    queue_arn = f"arn:aws:sqs:{REGION}:{ACCOUNT}:sensitive"
    queue_url = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/sensitive"

    def evaluate(*, grants=(), encryption="", queue_policy=None, details="collected", writer_resource=None,
                 queue_location=queue_url, boundary_deny=None, key_policy=None, key_status="collected"):
        attrs = {"QueueArn": queue_arn, "KmsMasterKeyId": encryption}
        if queue_policy is not None:
            attrs["Policy"] = queue_policy
        queue = {"QueueUrl": queue_location, "Attributes": {"collection_status": details,
                 "Attributes": attrs}}
        caller = user("alice", allow("sqs:SetQueueAttributes", resource=writer_resource or queue_arn), *grants)
        if boundary_deny is not None:
            boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/sqs-boundary"
            caller["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary_arn}
        extra = [col("sqs_queue", [queue])]
        if key_policy is not None:
            key_arn = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/12345678-1234-1234-1234-123456789012"
            extra.append(col("kms_key", [{"KeyId": key_arn.rsplit("/", 1)[1], "KeyArn": key_arn,
                "Metadata": {"collection_status": key_status, "KeyMetadata": {"Arn": key_arn}},
                "Policy": {"collection_status": key_status, "Policy": key_policy}}]))
        snap = aws_snap([caller], [], extra)
        if boundary_deny is not None:
            statements = [allow("sqs:SetQueueAttributes", resource=queue_arn)]
            if boundary_deny:
                statements.append({"Effect": "Deny", "Action": "sqs:ReceiveMessage", "Resource": queue_arn})
            next(c for c in snap["collections"] if c["type"] == "iam_policy")["items"] = [
                {"Arn": boundary_arn, "PolicyName": "sqs-boundary", "PolicyVersionList": [
                    {"IsDefaultVersion": True, "Document": policy(*statements)}]}]
        return [reach.targets for reach in Evaluator(AwsModel(snap), [entry],
                 include_unknown=False).run() if reach.source.id == ALICE]

    gained = evaluate()
    assert len(gained) == 1
    assert any("sqs-policy:" in target and grant.confidence == "conditional"
               for target, grant in gained[0].items())
    assert len(evaluate(boundary_deny=False)) == 1
    assert evaluate(grants=[allow("sqs:ReceiveMessage", resource=queue_arn)]) == []
    assert evaluate(boundary_deny=True) == []
    assert evaluate(grants=[{"Effect": "Deny", "Action": "sqs:ReceiveMessage", "Resource": queue_arn}]) == []
    assert evaluate(writer_resource=f"arn:aws:sqs:{REGION}:{ACCOUNT}:other") == []
    assert evaluate(queue_location=f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/other") == []
    deny_policy = policy({"Effect": "Deny", "Principal": {"AWS": ALICE},
                          "Action": "sqs:ReceiveMessage", "Resource": queue_arn})
    assert len(evaluate(queue_policy=deny_policy)) == 1
    not_principal_deny = policy({"Effect": "Deny", "NotPrincipal": {"AWS": ALICE},
                                 "Action": "sqs:ReceiveMessage", "Resource": queue_arn})
    assert len(evaluate(queue_policy=not_principal_deny)) == 1
    assert len(evaluate(queue_policy=not_principal_deny, boundary_deny=False)) == 1
    existing_allow = policy({"Effect": "Allow", "Principal": {"AWS": ALICE},
                             "Action": "sqs:ReceiveMessage", "Resource": queue_arn})
    assert evaluate(queue_policy=existing_allow) == []
    assert evaluate(queue_policy=existing_allow, boundary_deny=False) == []
    assert len(evaluate(queue_policy=policy(*existing_allow["Statement"], *deny_policy["Statement"]))) == 1
    account_delegation = policy({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                                 "Action": "sqs:ReceiveMessage", "Resource": queue_arn})
    assert len(evaluate(queue_policy=account_delegation)) == 1
    assert evaluate(encryption=None) == []
    assert evaluate(encryption="alias/aws/sqs") == []
    key_arn = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/12345678-1234-1234-1234-123456789012"
    decrypt_policy = policy({"Effect": "Allow", "Principal": {"AWS": ALICE},
                             "Action": "kms:Decrypt", "Resource": "*"})
    assert evaluate(encryption=key_arn) == []
    assert len(evaluate(encryption=key_arn, key_policy=decrypt_policy)) == 1
    assert len(evaluate(encryption=key_arn.rsplit("/", 1)[1], key_policy=decrypt_policy)) == 1
    assert evaluate(encryption=key_arn, key_policy=decrypt_policy, key_status="access_denied") == []
    assert evaluate(encryption=key_arn, key_policy=policy()) == []
    assert evaluate(details="access_denied") == []


def test_sns_topic_policy_self_grant_requires_new_effective_subscribe_permission():
    from pathlib import Path
    import yaml
    from peaso.privesc.effective_permissions.aws import AwsModel
    from peaso.privesc.evaluator import Evaluator

    catalog_file = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/aws/sns.yaml"
    entry = yaml.safe_load(catalog_file.read_text())[0]
    topic_arn = f"arn:aws:sns:{REGION}:{ACCOUNT}:alerts"

    def evaluate(*, grants=(), topic_policy=None, details="collected", writer_resource=None,
                 boundary_deny=None):
        attrs = {"TopicArn": topic_arn}
        if topic_policy is not None:
            attrs["Policy"] = topic_policy
        topic = {"TopicArn": topic_arn, "Attributes": {"collection_status": details,
                 "Attributes": attrs}}
        caller = user("alice", allow("sns:SetTopicAttributes", resource=writer_resource or topic_arn), *grants)
        if boundary_deny is not None:
            boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/sns-boundary"
            caller["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary_arn}
        snap = aws_snap([caller], [], [col("sns_topic", [topic])])
        if boundary_deny is not None:
            statements = [allow("sns:SetTopicAttributes", resource=topic_arn)]
            if boundary_deny:
                statements.append({"Effect": "Deny", "Action": "sns:Subscribe", "Resource": topic_arn})
            next(c for c in snap["collections"] if c["type"] == "iam_policy")["items"] = [
                {"Arn": boundary_arn, "PolicyName": "sns-boundary", "PolicyVersionList": [
                    {"IsDefaultVersion": True, "Document": policy(*statements)}]}]
        return [reach.targets for reach in Evaluator(AwsModel(snap), [entry],
                 include_unknown=False).run() if reach.source.id == ALICE]

    assert len(evaluate()) == 1
    assert len(evaluate(boundary_deny=False)) == 1
    assert evaluate(boundary_deny=True) == []
    assert evaluate(grants=[allow("sns:Subscribe", resource=topic_arn)]) == []
    assert evaluate(grants=[{"Effect": "Deny", "Action": "sns:Subscribe", "Resource": topic_arn}]) == []
    assert evaluate(writer_resource=f"arn:aws:sns:{REGION}:{ACCOUNT}:other") == []
    existing_allow = policy({"Effect": "Allow", "Principal": {"AWS": ALICE},
                             "Action": "sns:Subscribe", "Resource": topic_arn})
    assert evaluate(topic_policy=existing_allow) == []
    deny_policy = policy({"Effect": "Deny", "Principal": {"AWS": ALICE},
                          "Action": "sns:Subscribe", "Resource": topic_arn})
    assert len(evaluate(topic_policy=deny_policy)) == 1
    assert len(evaluate(topic_policy=policy(*existing_allow["Statement"], *deny_policy["Statement"]))) == 1
    assert evaluate(details="access_denied") == []


def test_dynamodb_table_policy_self_grant_requires_new_effective_getitem_permission():
    from pathlib import Path
    import yaml
    from peaso.privesc.effective_permissions.aws import AwsModel
    from peaso.privesc.evaluator import Evaluator

    catalog_file = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/aws/dynamodb.yaml"
    entry = yaml.safe_load(catalog_file.read_text())[0]
    table_arn = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/sensitive"

    def evaluate(*, grants=(), table_policy=None, policy_status="empty", table_status="ACTIVE",
                 encryption=None, writer_resource=None, boundary_deny=None):
        table = {"TableArn": table_arn, "TableName": "sensitive", "TableStatus": table_status}
        if encryption is not None:
            table["SSEDescription"] = {"SSEType": encryption}
        resource_policy = {"collection_status": policy_status}
        if table_policy is not None:
            resource_policy.update(collection_status="collected", Policy=table_policy)
        item = {"TableName": "sensitive", "Table": {"collection_status": "collected", "Table": table},
                "ResourcePolicy": resource_policy}
        caller = user("alice", allow("dynamodb:PutResourcePolicy", resource=writer_resource or table_arn), *grants)
        if boundary_deny is not None:
            boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/dynamodb-boundary"
            caller["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary_arn}
        snap = aws_snap([caller], [], [col("dynamodb_table", [item])])
        if boundary_deny is not None:
            statements = [allow("dynamodb:PutResourcePolicy", resource=table_arn)]
            if boundary_deny:
                statements.append({"Effect": "Deny", "Action": "dynamodb:GetItem", "Resource": table_arn})
            next(c for c in snap["collections"] if c["type"] == "iam_policy")["items"] = [
                {"Arn": boundary_arn, "PolicyName": "dynamodb-boundary", "PolicyVersionList": [
                    {"IsDefaultVersion": True, "Document": policy(*statements)}]}]
        return [reach.targets for reach in Evaluator(AwsModel(snap), [entry],
                 include_unknown=False).run() if reach.source.id == ALICE]

    assert len(evaluate()) == 1
    assert len(evaluate(boundary_deny=False)) == 1
    assert evaluate(boundary_deny=True) == []
    assert evaluate(grants=[allow("dynamodb:GetItem", resource=table_arn)]) == []
    assert evaluate(grants=[{"Effect": "Deny", "Action": "dynamodb:GetItem", "Resource": table_arn}]) == []
    assert evaluate(writer_resource=f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/other") == []
    existing_allow = policy({"Effect": "Allow", "Principal": {"AWS": ALICE},
                             "Action": "dynamodb:GetItem", "Resource": table_arn})
    assert evaluate(table_policy=existing_allow) == []
    assert evaluate(table_policy=existing_allow, boundary_deny=False) == []
    account_delegation = policy({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                                 "Action": "dynamodb:GetItem", "Resource": table_arn})
    assert len(evaluate(table_policy=account_delegation)) == 1
    deny_policy = policy({"Effect": "Deny", "Principal": {"AWS": ALICE},
                          "Action": "dynamodb:GetItem", "Resource": table_arn})
    assert len(evaluate(table_policy=deny_policy)) == 1
    not_principal_deny = policy({"Effect": "Deny", "NotPrincipal": {"AWS": ALICE},
                                 "Action": "dynamodb:GetItem", "Resource": table_arn})
    assert len(evaluate(table_policy=not_principal_deny)) == 1
    assert len(evaluate(table_policy=not_principal_deny, boundary_deny=False)) == 1
    assert len(evaluate(table_policy=policy(*existing_allow["Statement"], *deny_policy["Statement"]))) == 1
    assert evaluate(table_status="DELETING") == []
    assert evaluate(encryption="KMS") == []
    assert evaluate(policy_status="denied") == []


def test_agentcore_created_interpreter_needs_grants_covering_its_generated_id():
    tid = "aws-bedrock-agentcore-createcodeinterpreter-passrole"
    prefix = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:code-interpreter-custom/"
    roles = [role("core", "bedrock-agentcore.amazonaws.com")]
    base = (allow("iam:PassRole", resource=role_arn("core")),
            allow("bedrock-agentcore:CreateCodeInterpreter"))
    def candidate(start, invoke):
        return user("alice", *base,
                    allow("bedrock-agentcore:StartCodeInterpreterSession", resource=start),
                    allow("bedrock-agentcore:InvokeCodeInterpreter", resource=invoke))
    permitted = candidate(prefix + "alpha-*", prefix + "alpha-??????????")
    assert edges(real(aws_snap([permitted], roles), tid), ALICE) == []
    assert any(row.get("status") == "unresolved" for row in
               real(aws_snap([permitted], roles), tid, include_unknown=True)["coverage"])
    broad = candidate(prefix + "*", prefix + "*")
    assert reached(real(aws_snap([broad], roles), tid), ALICE) == {role_arn("core"): "conditional"}
    scoped_create = user("alice", allow("iam:PassRole", resource=role_arn("core")),
                         allow("bedrock-agentcore:CreateCodeInterpreter", resource=prefix + "*"),
                         allow("bedrock-agentcore:StartCodeInterpreterSession", resource=prefix + "*"),
                         allow("bedrock-agentcore:InvokeCodeInterpreter", resource=prefix + "*"))
    assert edges(real(aws_snap([scoped_create], roles), tid), ALICE) == []
    restricted_role = role("core", [{"Effect": "Allow", "Principal": {
        "Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"ArnEquals": {"aws:SourceArn": prefix + "other-1234567890"}}}])
    assert edges(real(aws_snap([broad], [restricted_role]), tid), ALICE) == []
    exact = candidate(prefix + "alpha-1234567890", prefix + "alpha-1234567890")
    assert edges(real(aws_snap([exact], roles), tid), ALICE) == []
    disjoint = candidate(prefix + "alpha-*", prefix + "beta-*")
    assert edges(real(aws_snap([disjoint], roles), tid), ALICE) == []
    free_name = candidate(prefix + "alpha-*", prefix + "alpha-??????????")
    available = aws_snap([free_name], roles, extra=[col("agentcore_code_interpreter", [], "empty")])
    assert reached(real(available, tid), ALICE, tid) == {role_arn("core"): "conditional"}
    occupied = {"codeInterpreterArn": prefix + "alpha-1234567890", "name": "alpha",
                "codeInterpreterId": "alpha-1234567890", "status": "READY",
                "executionRoleArn": role_arn("core")}
    occupied_snap = aws_snap([free_name], roles,
                             extra=[col("agentcore_code_interpreter", [occupied])])
    assert edges(real(occupied_snap, tid), ALICE) == []
    unnamed_snap = aws_snap([free_name], roles,
                            extra=[col("agentcore_code_interpreter", [{k: v for k, v in occupied.items()
                                                                      if k != "name"}])])
    assert edges(real(unnamed_snap, tid), ALICE) == []
    partial_snap = aws_snap([free_name], roles,
                            extra=[col("agentcore_code_interpreter", [], "partial")])
    assert edges(real(partial_snap, tid), ALICE) == []


def test_agentcore_existing_interpreter_joins_exact_ready_role_and_grants():
    tid = "aws-bedrock-agentcore-codeinterpreter-existing"
    arn = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:code-interpreter-custom/team-0123456789"
    other = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:code-interpreter-custom/other-0123456789"
    execution_role = role("core", "bedrock-agentcore.amazonaws.com")
    ready = {"codeInterpreterArn": arn, "codeInterpreterId": "team-0123456789",
             "executionRoleArn": role_arn("core"), "status": "READY"}
    principal = user("alice", allow("bedrock-agentcore:StartCodeInterpreterSession", resource=arn),
                     allow("bedrock-agentcore:InvokeCodeInterpreter", resource=arn))
    result = real(aws_snap([principal], [execution_role],
                           extra=[col("agentcore_code_interpreter", [ready])]), tid)
    assert reached(result, ALICE, tid) == {role_arn("core"): "conditional"}
    wrong_invoke = user("alice", allow("bedrock-agentcore:StartCodeInterpreterSession", resource=arn),
                        allow("bedrock-agentcore:InvokeCodeInterpreter", resource=other))
    assert edges(real(aws_snap([wrong_invoke], [execution_role],
                               extra=[col("agentcore_code_interpreter", [ready])]), tid), ALICE) == []
    failed = {**ready, "status": "CREATE_FAILED"}
    assert edges(real(aws_snap([principal], [execution_role],
                               extra=[col("agentcore_code_interpreter", [failed])]), tid), ALICE) == []
    incomplete = {**ready, "status": "READY"}
    partial_result = real(aws_snap([principal], [execution_role],
                                   extra=[col("agentcore_code_interpreter", [incomplete], "partial")]),
                          tid, include_unknown=True)
    assert_unresolved(partial_result, ALICE, tid)


def test_agentcore_runtime_update_needs_one_runtime_and_default_endpoint():
    tid = "aws-bedrock-agentcore-updateagentruntime-passrole"
    arn = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/team-0123456789"
    endpoint = arn + "/runtime-endpoint/DEFAULT"
    other = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/other-0123456789"
    target = role("core", "bedrock-agentcore.amazonaws.com")
    runtime = {"agentRuntimeArn": arn, "agentRuntimeId": "team-0123456789", "status": "READY",
               "roleArn": role_arn("old")}
    default = {"agentRuntimeArn": arn, "agentRuntimeEndpointArn": endpoint,
               "name": "DEFAULT", "status": "READY"}
    passed = allow("iam:PassRole", resource=role_arn("core"))
    def scan(principal, runtime_rows=(runtime,), endpoint_rows=(default,), endpoint_status="collected"):
        return real(aws_snap([principal], [target], extra=[
            col("agentcore_agent_runtime", runtime_rows),
            col("agentcore_runtime_endpoint", endpoint_rows, endpoint_status)]), tid)
    principal = user("alice", passed, allow("bedrock-agentcore:UpdateAgentRuntime", resource=arn),
                     allow("bedrock-agentcore:InvokeAgentRuntime", resource=[arn, endpoint]))
    assert reached(scan(principal), ALICE, tid) == {role_arn("core"): "conditional"}
    wrong_update = user("alice", passed, allow("bedrock-agentcore:UpdateAgentRuntime", resource=other),
                        allow("bedrock-agentcore:InvokeAgentRuntime", resource=[arn, endpoint]))
    assert edges(scan(wrong_update), ALICE) == []
    no_endpoint_grant = user("alice", passed, allow("bedrock-agentcore:UpdateAgentRuntime", resource=arn),
                             allow("bedrock-agentcore:InvokeAgentRuntime", resource=arn))
    assert edges(scan(no_endpoint_grant), ALICE) == []
    wrong_pass = user("alice", {"Effect": "Allow", "Action": "iam:PassRole",
                                "Resource": role_arn("core"),
                                "Condition": {"ArnEquals": {"iam:AssociatedResourceArn": other}}},
                      allow("bedrock-agentcore:UpdateAgentRuntime", resource=arn),
                      allow("bedrock-agentcore:InvokeAgentRuntime", resource=[arn, endpoint]))
    assert edges(scan(wrong_pass), ALICE) == []
    nondefault = {**default, "name": "STAGING", "agentRuntimeEndpointArn": arn + "/runtime-endpoint/STAGING"}
    assert edges(scan(principal, endpoint_rows=(nondefault,)), ALICE) == []
    failed = {**default, "status": "UPDATE_FAILED"}
    assert edges(scan(principal, endpoint_rows=(failed,)), ALICE) == []
    partial = real(aws_snap([principal], [target], extra=[
        col("agentcore_agent_runtime", [runtime]),
        col("agentcore_runtime_endpoint", [default], "partial")]), tid, include_unknown=True)
    assert_unresolved(partial, ALICE, tid)


def test_agentcore_new_runtime_binds_generated_id_endpoint_and_free_name():
    tid = "aws-bedrock-agentcore-createagentruntime-passrole"
    prefix = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/"
    target = role("core", "bedrock-agentcore.amazonaws.com")
    pass_role = allow("iam:PassRole", resource=role_arn("core"))
    create = allow("bedrock-agentcore:CreateAgentRuntime")
    def principal(runtime_scope, endpoint_scope):
        return user("alice", pass_role, create,
                    allow("bedrock-agentcore:CreateAgentRuntimeEndpoint", resource=runtime_scope),
                    allow("bedrock-agentcore:InvokeAgentRuntime",
                          resource=[runtime_scope, endpoint_scope]))
    def scan(who, rows=(), status="empty"):
        return real(aws_snap([who], [target], extra=[col("agentcore_agent_runtime", rows, status)]), tid)
    broad = principal("*", "*")
    assert reached(scan(broad), ALICE, tid) == {role_arn("core"): "conditional"}
    named = principal(prefix + "alpha-*", prefix + "alpha-*/runtime-endpoint/DEFAULT")
    assert reached(scan(named), ALICE, tid) == {role_arn("core"): "conditional"}
    generated_suffix = principal(prefix + "alpha-??????????",
                                 prefix + "alpha-??????????/runtime-endpoint/DEFAULT")
    assert reached(scan(generated_suffix), ALICE, tid) == {role_arn("core"): "conditional"}
    occupied = {"agentRuntimeArn": prefix + "alpha-1234567890", "agentRuntimeName": "alpha",
                "agentRuntimeId": "alpha-1234567890", "status": "READY", "roleArn": role_arn("core")}
    assert edges(scan(named, [occupied], "collected"), ALICE) == []
    assert edges(scan(named, [], "partial"), ALICE) == []
    partial = real(aws_snap([named], [target], extra=[
        col("agentcore_agent_runtime", [], "partial")]), tid, include_unknown=True)
    assert_unresolved(partial, ALICE, tid)
    disjoint = principal(prefix + "alpha-*", prefix + "beta-*/runtime-endpoint/DEFAULT")
    assert edges(scan(disjoint), ALICE) == []
    wrong_endpoint = principal(prefix + "alpha-*", prefix + "alpha-*/runtime-endpoint/STAGING")
    assert edges(scan(wrong_endpoint), ALICE) == []
    exact_generated_id = principal(prefix + "alpha-1234567890",
                                   prefix + "alpha-1234567890/runtime-endpoint/DEFAULT")
    assert edges(scan(exact_generated_id), ALICE) == []
    wrong_service = user("alice", {"Effect": "Allow", "Action": "iam:PassRole",
                                   "Resource": role_arn("core"),
                                   "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}},
                         create, allow("bedrock-agentcore:CreateAgentRuntimeEndpoint"),
                         allow("bedrock-agentcore:InvokeAgentRuntime"))
    assert edges(scan(wrong_service), ALICE) == []


def test_agentcore_new_harness_requires_composite_actions_on_one_generated_scope():
    tid = "aws-bedrock-agentcore-createharness-passrole"
    target = role("core", "bedrock-agentcore.amazonaws.com")
    creates = allow("bedrock-agentcore:CreateHarness", "bedrock-agentcore:CreateAgentRuntime",
                    "bedrock-agentcore:CreateMemory")
    pass_role = allow("iam:PassRole", resource=role_arn("core"))
    def principal(invokes="*", command="*", memory="*", create=creates):
        return user("alice", pass_role, create,
                    allow("bedrock-agentcore:GetMemory", resource=memory),
                    allow("bedrock-agentcore:InvokeHarness", "bedrock-agentcore:InvokeAgentRuntime",
                          resource=invokes),
                    allow("bedrock-agentcore:InvokeAgentRuntimeCommand", resource=command))
    def scan(who, *, unknown=False, harnesses=None, status="empty"):
        extra = [] if harnesses is None else [col("agentcore_harness", harnesses, status)]
        return real(aws_snap([who], [target], extra=extra), tid, include_unknown=unknown)
    assert reached(scan(principal()), ALICE, tid) == {role_arn("core"): "conditional"}
    assert edges(scan(principal(create=allow("bedrock-agentcore:CreateHarness",
                                              "bedrock-agentcore:CreateAgentRuntime"))), ALICE) == []
    assert_unresolved(scan(principal(memory="arn:aws:bedrock-agentcore:us-east-1:111111111111:memory/specific"),
                           unknown=True), ALICE, tid)
    scoped = "arn:aws:bedrock-agentcore:us-east-1:111111111111:harness/alpha-*"
    assert_unresolved(scan(principal(invokes=scoped, command=scoped), unknown=True), ALICE, tid)
    assert reached(scan(principal(invokes=scoped, command=scoped), harnesses=[]), ALICE, tid) == {
        role_arn("core"): "conditional"}
    occupied = {"arn": scoped[:-1] + "1234567890", "harnessId": "alpha-1234567890",
                "harnessName": "alpha", "status": "READY", "executionRoleArn": role_arn("core")}
    assert edges(scan(principal(invokes=scoped, command=scoped), harnesses=[occupied], status="collected"), ALICE) == []
    assert_unresolved(scan(principal(invokes=scoped, command=scoped), harnesses=[], status="partial",
                           unknown=True), ALICE, tid)
    assert edges(scan(principal(command="arn:aws:bedrock-agentcore:us-east-1:111111111111:harness/beta-*")), ALICE) == []
    missing_start = user("alice", pass_role, creates, allow("bedrock-agentcore:GetMemory"),
                         allow("bedrock-agentcore:InvokeAgentRuntime",
                               "bedrock-agentcore:InvokeAgentRuntimeCommand"))
    assert edges(scan(missing_start), ALICE) == []
    wrong_service = user("alice", {"Effect": "Allow", "Action": "iam:PassRole",
                                   "Resource": role_arn("core"),
                                   "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}},
                         creates, allow("bedrock-agentcore:GetMemory"),
                         allow("bedrock-agentcore:InvokeHarness", "bedrock-agentcore:InvokeAgentRuntime",
                               "bedrock-agentcore:InvokeAgentRuntimeCommand"))
    assert edges(scan(wrong_service), ALICE) == []


def test_sagemaker_job_scopes_and_passrole_service_remain_unresolved_without_execution():
    target = role("core", "sagemaker.amazonaws.com")
    for suffix, action, resource_type in (
        ("createprocessingjob", "sagemaker:CreateProcessingJob", "processing-job"),
        ("createtrainingjob", "sagemaker:CreateTrainingJob", "training-job"),
        ("createhyperparametertuningjob", "sagemaker:CreateHyperParameterTuningJob",
         "hyper-parameter-tuning-job"),
    ):
        tid = "aws-sagemaker-passrole-" + suffix
        job = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:{resource_type}/alpha-*"
        caller = user("alice", allow("iam:PassRole", resource=role_arn("core")),
                      allow(action, resource=job))
        assert_unresolved(real(aws_snap([caller], [target]), tid, include_unknown=True), ALICE, tid)
        wrong_service = user("alice", {"Effect": "Allow", "Action": "iam:PassRole",
                                       "Resource": role_arn("core"),
                                       "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}},
                             allow(action, resource=job))
        assert edges(real(aws_snap([wrong_service], [target]), tid), ALICE, tid) == []


def test_sagemaker_processing_inline_route_requires_free_scoped_job_and_matching_passrole():
    tid = "aws-sagemaker-passrole-createprocessingjob"
    target = role("core", "sagemaker.amazonaws.com")
    job = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:processing-job/alpha-*"
    create = allow("sagemaker:CreateProcessingJob", resource=job)
    passed = allow("iam:PassRole", resource=role_arn("core"))

    def evaluate(grants, inventory=(), status="collected"):
        caller = user("alice", *grants)
        result = real(aws_snap([caller], [target], [col("sagemaker_processing_job", inventory, status)]),
                      tid, include_unknown=True)
        return reached(result, ALICE, tid), result

    members, _ = evaluate((passed, create))
    assert members == {role_arn("core"): "conditional"}
    exact = allow("sagemaker:CreateProcessingJob", resource=job[:-1] + "fixed")
    assert role_arn("core") not in evaluate((passed, exact),
        [{"ProcessingJobName": "alpha-fixed"}])[0]
    assert role_arn("core") not in evaluate((passed, create), status="denied")[0]
    wrong_service = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn("core"),
                     "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}}
    assert role_arn("core") not in evaluate((wrong_service, create))[0]
    isolated = {"Effect": "Allow", "Action": "sagemaker:CreateProcessingJob", "Resource": job,
                "Condition": {"Bool": {"sagemaker:NetworkIsolation": "true"}}}
    assert role_arn("core") not in evaluate((passed, isolated))[0]


def test_sagemaker_training_inline_route_requires_writable_regional_output():
    tid = "aws-sagemaker-passrole-createtrainingjob"
    target = role("core", "sagemaker.amazonaws.com", allow("s3:PutObject",
        resource="arn:aws:s3:::training-output/peaso-training-*"))
    job = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:training-job/alpha-*"
    passed = allow("iam:PassRole", resource=role_arn("core"))
    create = allow("sagemaker:CreateTrainingJob", resource=job)
    bucket = {"Name": "training-output", "Location": {"collection_status": "collected",
              "LocationConstraint": REGION}, "Policy": {"collection_status": "empty", "absent": True},
              "Encryption": {"collection_status": "empty", "absent": True}}

    def evaluate(grants=(passed, create), role_item=target, buckets=(bucket,), bucket_state="collected",
                 jobs=(), job_state="collected"):
        caller = user("alice", *grants)
        snap = aws_snap([caller], [role_item], [col("sagemaker_training_job", jobs, job_state),
            col("bucket", buckets, bucket_state, scope=f"{ACCOUNT}/global")])
        result = real(snap, tid, include_unknown=True)
        return reached(result, ALICE, tid), result

    assert evaluate()[0] == {role_arn("core"): "conditional"}
    assert role_arn("core") not in evaluate(role_item=role("core", "sagemaker.amazonaws.com"))[0]
    public_bucket = {**bucket, "Policy": {"collection_status": "collected", "Policy": policy({
        "Effect": "Allow", "Principal": "*", "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::training-output/*"})}}
    assert role_arn("core") not in evaluate(role_item=role("core", "sagemaker.amazonaws.com"),
                                             buckets=(public_bucket,))[0]
    assert role_arn("core") not in evaluate(role_item=role("core", "sagemaker.amazonaws.com",
        allow("s3:PutObject", resource="arn:aws:s3:::other-output/*")))[0]
    assert role_arn("core") not in evaluate(buckets=())[0]
    assert role_arn("core") not in evaluate(bucket_state="denied")[0]
    assert role_arn("core") not in evaluate(jobs=[{"TrainingJobName": "alpha-fixed"}],
        grants=(passed, allow("sagemaker:CreateTrainingJob", resource=job[:-1] + "fixed")))[0]
    other_region = {**bucket, "Location": {"collection_status": "collected",
                                         "LocationConstraint": "eu-west-1"}}
    assert role_arn("core") not in evaluate(buckets=(other_region,))[0]
    kms_bucket = {**bucket, "Encryption": {"collection_status": "collected",
        "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault":
            {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "key"}}]}}}
    assert role_arn("core") not in evaluate(buckets=(kms_bucket,))[0]
    denying_bucket = {**bucket, "Policy": {"collection_status": "collected", "Policy": policy({
        "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::training-output/*"})}}
    assert role_arn("core") not in evaluate(buckets=(denying_bucket,))[0]
    isolated = {"Effect": "Allow", "Action": "sagemaker:CreateTrainingJob", "Resource": job,
                "Condition": {"Bool": {"sagemaker:NetworkIsolation": "true"}}}
    assert role_arn("core") not in evaluate(grants=(passed, isolated))[0]


def test_sagemaker_hpo_script_route_joins_code_output_and_tuning_job():
    tid = "aws-sagemaker-passrole-createhyperparametertuningjob"
    job = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:hyper-parameter-tuning-job/alpha-*"
    code = "arn:aws:s3:::training-output/peaso-hpo-*/code.tar.gz"
    passed = allow("iam:PassRole", resource=role_arn("core"))
    create = allow("sagemaker:CreateHyperParameterTuningJob", resource=job)
    upload = allow("s3:PutObject", resource=code)
    target = role("core", "sagemaker.amazonaws.com", allow("s3:GetObject", resource=code),
                  allow("s3:PutObject", resource="arn:aws:s3:::training-output/output/*"))
    bucket = {"Name": "training-output", "Location": {"collection_status": "collected",
              "LocationConstraint": REGION}, "Policy": {"collection_status": "empty", "absent": True},
              "Encryption": {"collection_status": "empty", "absent": True}}

    def evaluate(grants=(passed, create, upload), role_item=target, buckets=(bucket,),
                 bucket_state="collected", jobs=(), job_state="collected"):
        caller = user("alice", *grants)
        snap = aws_snap([caller], [role_item], [
            col("sagemaker_hyperparameter_tuning_job", jobs, job_state),
            col("bucket", buckets, bucket_state, scope=f"{ACCOUNT}/global")])
        result = real(snap, tid, include_unknown=True)
        return reached(result, ALICE, tid), result

    assert evaluate()[0] == {role_arn("core"): "conditional"}
    assert role_arn("core") not in evaluate(grants=(passed, create))[0]
    assert role_arn("core") not in evaluate(role_item=role("core", "sagemaker.amazonaws.com",
        allow("s3:PutObject", resource="arn:aws:s3:::training-output/output/*")))[0]
    assert role_arn("core") not in evaluate(role_item=role("core", "sagemaker.amazonaws.com",
        allow("s3:GetObject", resource=code)))[0]
    assert role_arn("core") not in evaluate(buckets=())[0]
    assert role_arn("core") not in evaluate(job_state="denied")[0]
    other_region = {**bucket, "Location": {"collection_status": "collected",
                                         "LocationConstraint": "eu-west-1"}}
    assert role_arn("core") not in evaluate(buckets=(other_region,))[0]
    kms_bucket = {**bucket, "Encryption": {"collection_status": "collected",
        "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault":
            {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "key"}}]}}}
    assert role_arn("core") not in evaluate(buckets=(kms_bucket,))[0]
    denying_bucket = {**bucket, "Policy": {"collection_status": "collected", "Policy": policy({
        "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::training-output/*"})}}
    assert role_arn("core") not in evaluate(buckets=(denying_bucket,))[0]
    assert role_arn("core") not in evaluate(jobs=[{"HyperParameterTuningJobName": "alpha-fixed"}],
        grants=(passed, allow("sagemaker:CreateHyperParameterTuningJob",
            resource=job[:-1] + "fixed"), upload))[0]
    wrong_service = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn("core"),
                     "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}}
    assert role_arn("core") not in evaluate(grants=(wrong_service, create, upload))[0]
    isolated = {"Effect": "Allow", "Action": "sagemaker:CreateHyperParameterTuningJob",
                "Resource": job, "Condition": {"Bool": {"sagemaker:NetworkIsolation": "true"}}}
    assert role_arn("core") not in evaluate(grants=(passed, isolated, upload))[0]


def test_lambda_edge_requires_both_replication_permissions_in_us_east_1():
    tid = "aws-cloudfront-lambda-edge-passrole"
    edge_role = role("edge", [{"Effect": "Allow", "Principal": {"Service": [
        "lambda.amazonaws.com", "edgelambda.amazonaws.com"]}, "Action": "sts:AssumeRole"}])
    actions = ("lambda:CreateFunction", "lambda:PublishVersion", "lambda:GetFunction",
               "lambda:EnableReplication", "lambda:DisableReplication", "cloudfront:UpdateDistribution",
               "iam:CreateServiceLinkedRole")
    distribution = {"ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/DIST1",
                    "Id": "DIST1", "Status": "Deployed"}
    def snap(principal, distributions=(distribution,), functions=()):
        return aws_snap([principal], [edge_role],
                        [col("cloudfront_distribution", distributions, scope=f"{ACCOUNT}/global"),
                         col("lambda_function", functions, scope=f"{ACCOUNT}/us-east-1")])
    permitted = user("alice", allow("iam:PassRole", resource=role_arn("edge")), allow(*actions))
    assert reached(real(snap(permitted), tid), ALICE) == {role_arn("edge"): "conditional"}
    assert edges(real(snap(permitted, ()), tid), ALICE) == []
    no_slr = user("alice", allow("iam:PassRole", resource=role_arn("edge")),
                  allow(*(action for action in actions if action != "iam:CreateServiceLinkedRole")))
    assert edges(real(snap(no_slr), tid), ALICE) == []
    no_disable = user("alice", allow("iam:PassRole", resource=role_arn("edge")),
                      allow(*(action for action in actions if action != "lambda:DisableReplication")))
    assert edges(real(snap(no_disable), tid), ALICE) == []
    ohio = f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:demo"
    wrong_region = user("alice", allow("iam:PassRole", resource=role_arn("edge")),
                        allow("lambda:CreateFunction", resource=ohio),
                        allow(*(action for action in actions if action != "lambda:CreateFunction")))
    assert edges(real(snap(wrong_region), tid), ALICE) == []
    alpha = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:alpha"
    beta = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:beta"
    disjoint = user("alice", allow("iam:PassRole", resource=role_arn("edge")),
                    allow("lambda:CreateFunction", resource=alpha),
                    allow("lambda:PublishVersion", resource=beta),
                    allow(*(action for action in actions if action not in (
                        "lambda:CreateFunction", "lambda:PublishVersion"))))
    assert edges(real(snap(disjoint), tid), ALICE) == []
    exact = user("alice", allow("iam:PassRole", resource=role_arn("edge")),
                 allow("lambda:CreateFunction", resource=alpha),
                 allow("lambda:PublishVersion", resource=alpha),
                 allow("lambda:GetFunction", "lambda:EnableReplication", "lambda:DisableReplication",
                       resource=alpha + ":1"),
                 allow("cloudfront:UpdateDistribution", "iam:CreateServiceLinkedRole"))
    assert reached(real(snap(exact), tid), ALICE) == {role_arn("edge"): "conditional"}
    assert edges(real(snap(exact, functions=({"FunctionName": "alpha", "FunctionArn": alpha},)), tid), ALICE) == []


def test_lambda_edge_new_distribution_and_scoped_existing_distribution():
    tid = "aws-cloudfront-lambda-edge-passrole"
    edge_role = role("edge", [{"Effect": "Allow", "Principal": {"Service": [
        "lambda.amazonaws.com", "edgelambda.amazonaws.com"]}, "Action": "sts:AssumeRole"}])
    function_actions = ("lambda:CreateFunction", "lambda:PublishVersion", "lambda:GetFunction",
                        "lambda:EnableReplication", "lambda:DisableReplication")
    distribution_arn = f"arn:aws:cloudfront::{ACCOUNT}:distribution/DIST1"
    def principal(distribution_action=None, resource="*"):
        grants = [allow("iam:PassRole", resource=role_arn("edge")), allow(*function_actions),
                  allow("iam:CreateServiceLinkedRole")]
        if distribution_action:
            grants.append(allow(distribution_action, resource=resource))
        return user("alice", *grants)
    def snapshot(source, distributions=None):
        collections = [col("lambda_function", [], scope=f"{ACCOUNT}/us-east-1")]
        if distributions is not None:
            collections.append(col("cloudfront_distribution", distributions, scope=f"{ACCOUNT}/global"))
        return aws_snap([source], [edge_role], collections)
    assert reached(real(snapshot(principal("cloudfront:CreateDistribution")), tid), ALICE) == {
        role_arn("edge"): "conditional"}
    assert edges(real(snapshot(principal()), tid), ALICE) == []
    assert edges(real(snapshot(principal("cloudfront:CreateDistribution", distribution_arn)), tid), ALICE) == []
    only_lambda_trust = aws_snap([principal("cloudfront:CreateDistribution")],
                                 [role("edge", "lambda.amazonaws.com")],
                                 [col("lambda_function", [], scope=f"{ACCOUNT}/us-east-1")])
    assert edges(real(only_lambda_trust, tid), ALICE) == []
    deployed = {"ARN": distribution_arn, "Id": "DIST1", "Status": "Deployed"}
    assert reached(real(snapshot(principal("cloudfront:UpdateDistribution", distribution_arn),
                                 [deployed]), tid), ALICE) == {role_arn("edge"): "conditional"}
    assert edges(real(snapshot(principal("cloudfront:UpdateDistribution", distribution_arn),
                               []), tid), ALICE) == []


def test_codebuild_startbuild_requires_permission_for_a_buildspec_override():
    tid = "aws-codebuild-startbuild-attached-role"
    project = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/demo"
    item = {"name": "demo", "Configuration": {"collection_status": "collected", "projects": [
        {"name": "demo", "arn": project, "serviceRole": role_arn("builder")}]}}
    def snap(principal, service="codebuild.amazonaws.com"):
        return aws_snap([principal], [role("builder", service)],
                        [col("codebuild_project", [item])])
    allowed = user("alice", allow("codebuild:StartBuild", resource=project))
    assert reached(real(snap(allowed), tid), ALICE) == {role_arn("builder"): "conditional"}
    assert edges(real(snap(allowed, service="lambda.amazonaws.com"), tid), ALICE) == []
    mismatched = snap(allowed)
    mismatched["collections"][-1]["items"][0]["Configuration"]["projects"][0]["arn"] = project.replace(REGION, "us-west-2")
    assert edges(real(mismatched, tid), ALICE) == []
    item["Configuration"]["projects"][0]["arn"] = project
    no_override = user("alice", {"Effect": "Allow", "Action": "codebuild:StartBuild", "Resource": project,
                                 "Condition": {"Null": {"codebuild:source.buildspec": "true"}}})
    assert edges(real(snap(no_override), tid), ALICE) == []
    batch_only = user("alice", allow("codebuild:StartBuildBatch", resource=project))
    assert edges(real(snap(batch_only), tid), ALICE) == []
    batch_item = {"name": "demo", "Configuration": {"collection_status": "collected", "projects": [
        {"name": "demo", "arn": project, "serviceRole": role_arn("builder"),
         "buildBatchConfig": {"serviceRole": role_arn("batch")}}]}}
    batch_snap = aws_snap([batch_only], [role("builder", "codebuild.amazonaws.com"),
                                         role("batch", "codebuild.amazonaws.com",
                                              allow("codebuild:StartBuild", resource=project))],
                          [col("codebuild_project", [batch_item])])
    assert reached(real(batch_snap, tid), ALICE) == {role_arn("builder"): "conditional"}
    missing_child_permission = aws_snap([batch_only], [role("builder", "codebuild.amazonaws.com"),
                                                     role("batch", "codebuild.amazonaws.com")],
                                        [col("codebuild_project", [batch_item])])
    assert edges(real(missing_child_permission, tid), ALICE) == []


def test_codebuild_existing_sandbox_routes_need_an_exact_running_sandbox():
    project = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/demo"
    sandbox = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:sandbox/demo:" + "a" * 36
    project_item = {"name": "demo", "Configuration": {"collection_status": "collected", "projects": [
        {"name": "demo", "arn": project, "serviceRole": role_arn("builder")}]}}
    running = {"id": "demo:" + "a" * 36, "Detail": {"collection_status": "collected",
               "arn": sandbox, "projectName": "demo", "status": "RUN_SANDBOX",
               "serviceRole": role_arn("builder")}}
    def snap(principal, sandboxes=None, with_project=True):
        extra = [col("codebuild_project", [project_item])] if with_project else []
        if sandboxes is not None:
            extra.append(col("codebuild_sandbox", sandboxes))
        return aws_snap([principal], [role("builder", "codebuild.amazonaws.com")], extra)
    for tid, action in (("aws-codebuild-startcommandexecution", "codebuild:StartCommandExecution"),
                        ("aws-codebuild-startsandboxconnection", "codebuild:StartSandboxConnection")):
        permitted = user("alice", allow(action, resource=sandbox))
        assert reached(real(snap(permitted, [running]), tid), ALICE) == {role_arn("builder"): "conditional"}
        assert reached(real(snap(permitted, [running], with_project=False), tid), ALICE) == {
            role_arn("builder"): "conditional"}
        assert edges(real(snap(permitted, []), tid), ALICE) == []
        assert edges(real(snap(permitted, [dict(running, Detail={**running["Detail"],
                           "status": "STOPPED"})]), tid), ALICE) == []
        assert edges(real(snap(permitted, [dict(running, Detail={**running["Detail"],
                           "serviceRole": role_arn("other")})]), tid), ALICE) == []
        assert_unresolved(real(snap(permitted), tid, include_unknown=True), ALICE, tid)


def test_codebuild_sandbox_detail_keeps_only_role_and_running_state():
    from peaso.collectors.aws_codebuild_redaction import project_batch_get_sandboxes
    from peaso.collectors.aws_b_services import _codebuild_sandboxes

    sandbox_id = "demo:" + "a" * 36
    sandbox_arn = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:sandbox/{sandbox_id}"
    raw = {"sandboxes": [{"id": sandbox_id, "arn": sandbox_arn, "projectName": "demo",
                          "status": "RUN_SANDBOX", "serviceRole": role_arn("builder"),
                          "environment": {"environmentVariables": [{"value": "sensitive"}]},
                          "source": {"buildspec": "sensitive"}}], "sandboxesNotFound": []}
    projected = project_batch_get_sandboxes(raw)
    assert "sensitive" not in repr(projected)
    class Requests:
        def detail(self, session, service, region, operation, **kwargs):
            assert (service, region, operation, kwargs) == (
                "codebuild", REGION, "batch_get_sandboxes", {"ids": [sandbox_id]})
            return {**projected, "collection_status": "collected"}
    rows = _codebuild_sandboxes(Requests(), None, REGION, [{"id": sandbox_id}])
    assert rows[0]["Detail"] == {**projected["sandboxes"][0], "collection_status": "collected"}


def test_codebuild_start_new_sandbox_needs_project_and_future_sandbox_permissions():
    tid = "aws-codebuild-startsandbox-exec"
    project = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/demo"
    sandbox = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:sandbox/demo:*"
    item = {"name": "demo", "Configuration": {"collection_status": "collected", "projects": [
        {"name": "demo", "arn": project, "serviceRole": role_arn("builder")}]}}
    def snap(principal, service="codebuild.amazonaws.com"):
        return aws_snap([principal], [role("builder", service)],
                        [col("codebuild_project", [item])])
    permitted = user("alice", allow("codebuild:StartSandbox", resource=project),
                     allow("codebuild:StartCommandExecution", resource=sandbox))
    assert reached(real(snap(permitted), tid), ALICE) == {role_arn("builder"): "conditional"}
    assert edges(real(snap(permitted, service="lambda.amazonaws.com"), tid), ALICE) == []
    disjoint = user("alice", allow("codebuild:StartSandbox", resource=project),
                    allow("codebuild:StartCommandExecution", resource=sandbox.replace("demo", "other")))
    assert edges(real(snap(disjoint), tid), ALICE) == []
    no_start = user("alice", allow("codebuild:StartCommandExecution", resource=sandbox))
    assert edges(real(snap(no_start), tid), ALICE) == []


def test_codebuild_updateproject_requires_permission_to_change_the_buildspec():
    tid = "aws-codebuild-updateproject-attached-role"
    project = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/demo"
    item = {"name": "demo", "Configuration": {"collection_status": "collected", "projects": [
        {"name": "demo", "arn": project, "serviceRole": role_arn("builder")}]}}
    def snap(principal, service="codebuild.amazonaws.com"):
        return aws_snap([principal], [role("builder", service)],
                        [col("codebuild_project", [item])])
    allowed = user("alice", allow("codebuild:UpdateProject", resource=project),
                   allow("codebuild:StartBuild", resource=project))
    assert reached(real(snap(allowed), tid), ALICE) == {role_arn("builder"): "conditional"}
    assert edges(real(snap(allowed, service="lambda.amazonaws.com"), tid), ALICE) == []
    mismatched = snap(allowed)
    mismatched["collections"][-1]["items"][0]["Configuration"]["projects"][0]["arn"] = project.replace(REGION, "us-west-2")
    assert edges(real(mismatched, tid), ALICE) == []
    item["Configuration"]["projects"][0]["arn"] = project
    no_change = user("alice", {"Effect": "Allow", "Action": "codebuild:UpdateProject", "Resource": project,
                               "Condition": {"Null": {"codebuild:source.buildspec": "true"}}},
                     allow("codebuild:StartBuild", resource=project))
    assert edges(real(snap(no_change), tid), ALICE) == []
    no_start = user("alice", allow("codebuild:UpdateProject", resource=project),
                    {"Effect": "Allow", "Action": "codebuild:StartBuild", "Resource": project,
                     "Condition": {"Null": {"codebuild:source.buildspec": "false"}}})
    assert edges(real(snap(no_start), tid), ALICE) == []
    batch_only = user("alice", allow("codebuild:UpdateProject", resource=project),
                      allow("codebuild:StartBuildBatch", resource=project))
    assert edges(real(snap(batch_only), tid), ALICE) == []
    batch_item = {"name": "demo", "Configuration": {"collection_status": "collected", "projects": [
        {"name": "demo", "arn": project, "serviceRole": role_arn("builder"),
         "buildBatchConfig": {"serviceRole": role_arn("batch")}}]}}
    def batch_snap(batch_role):
        return aws_snap([batch_only], [role("builder", "codebuild.amazonaws.com"), batch_role],
                        [col("codebuild_project", [batch_item])])
    assert reached(real(batch_snap(role("batch", "codebuild.amazonaws.com",
                                        allow("codebuild:StartBuild", resource=project))), tid), ALICE) == {
                                            role_arn("builder"): "conditional"}
    assert edges(real(batch_snap(role("batch", "codebuild.amazonaws.com")), tid), ALICE) == []
    role_bound_update = {"Effect": "Allow", "Action": "codebuild:UpdateProject", "Resource": project,
                         "Condition": {"StringEquals": {"codebuild:serviceRole": role_arn("builder")}}}
    with_passrole = user("alice", role_bound_update, allow("iam:PassRole", resource=role_arn("builder")),
                         allow("codebuild:StartBuild", resource=project))
    assert reached(real(snap(with_passrole), tid), ALICE) == {role_arn("builder"): "conditional"}
    without_passrole = user("alice", role_bound_update, allow("codebuild:StartBuild", resource=project))
    assert edges(real(snap(without_passrole), tid), ALICE) == []


def test_codepipeline_updateproject_uses_one_configured_pipeline_and_project():
    tid = "aws-codepipeline-updatepipeline-codebuild-updateproject"
    pipeline_arn = f"arn:aws:codepipeline:{REGION}:{ACCOUNT}:pipe"
    project_arn = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/demo"
    builder = role_arn("builder")
    pipeline_role = role_arn("pipeline")
    def snap(principal, *, artifact="src-out", override=None, action_role=None,
             pipeline_start=True, pipeline_passrole=False, buildspec_override=False,
             batch_enabled=False, batch_role_can_start=True):
        build_action = {"name": "build", "owner": "AWS", "category": "Build", "provider": "CodeBuild",
                        "region": REGION, "runOrder": 1,
                        "BuildspecOverridePresent": buildspec_override,
                        "configuration": {"ProjectName": "demo", "ServiceRoleArnOverride": override,
                                          "BatchEnabled": "true" if batch_enabled else "false"},
                        "inputArtifacts": [{"name": artifact}]}
        if action_role:
            build_action["roleArn"] = action_role
        pipeline = {"name": "pipe", "ActionMetadata": {"collection_status": "collected", "pipeline": {
            "name": "pipe", "roleArn": pipeline_role, "stages": [
                {"name": "Source", "actions": [{"name": "source", "category": "Source", "provider": "S3",
                    "region": REGION, "runOrder": 1, "outputArtifacts": [{"name": "src-out"}]}]},
                {"name": "Build", "actions": [build_action]}]}}}
        project = {"name": "demo", "Configuration": {"collection_status": "collected", "projects": [
            {"name": "demo", "arn": project_arn, "serviceRole": builder,
             "source": {"type": "CODEPIPELINE"},
             **({"buildBatchConfig": {"serviceRole": role_arn("batch")}} if batch_enabled else {})}]}}
        pipeline_permissions = [allow("codebuild:StartBuildBatch" if batch_enabled else "codebuild:StartBuild",
                                      resource=project_arn)] if pipeline_start else []
        if pipeline_passrole:
            pipeline_permissions.append(allow("iam:PassRole", resource=override))
        roles = [role("builder", "codebuild.amazonaws.com"),
                 role("pipeline", "codepipeline.amazonaws.com", *pipeline_permissions)]
        if override:
            roles.append(role("override", "codebuild.amazonaws.com"))
        if batch_enabled:
            roles.append(role("batch", "codebuild.amazonaws.com",
                              *( [allow("codebuild:StartBuild", resource=project_arn)] if batch_role_can_start else [])))
        if action_role:
            roles[1]["RolePolicyList"][0]["PolicyDocument"]["Statement"].append(
                allow("sts:AssumeRole", resource=action_role))
            roles.append(role("action", [{"Effect": "Allow", "Principal": {"AWS": pipeline_role},
                                          "Action": "sts:AssumeRole"}],
                              allow("codebuild:StartBuild", resource=project_arn)))
        return aws_snap([principal], roles, [col("codepipeline_pipeline", [pipeline]),
                                               col("codebuild_project", [project])])
    allowed = user("alice", allow("codebuild:UpdateProject", resource=project_arn),
                   allow("codepipeline:StartPipelineExecution", resource=pipeline_arn))
    assert_unresolved(real(snap(allowed), tid, include_unknown=True), ALICE, tid)
    wrong_pipeline = user("alice", allow("codebuild:UpdateProject", resource=project_arn),
                          allow("codepipeline:StartPipelineExecution", resource=pipeline_arn + "-other"))
    assert edges(real(snap(wrong_pipeline), tid), ALICE) == []
    wrong_project = user("alice", allow("codebuild:UpdateProject", resource=project_arn + "-other"),
                         allow("codepipeline:StartPipelineExecution", resource=pipeline_arn))
    assert edges(real(snap(wrong_project), tid), ALICE) == []
    assert edges(real(snap(allowed, artifact="unrelated"), tid), ALICE) == []
    assert edges(real(snap(allowed, pipeline_start=False), tid), ALICE) == []
    assert edges(real(snap(allowed, buildspec_override=True), tid), ALICE) == []
    assert_unresolved(real(snap(allowed, action_role=role_arn("action")), tid, include_unknown=True), ALICE, tid)
    override = role_arn("override")
    assert edges(real(snap(allowed, override=override), tid), ALICE) == []
    assert_unresolved(real(snap(allowed, override=override, pipeline_passrole=True),
                           tid, include_unknown=True), ALICE, tid)
    assert_unresolved(real(snap(allowed, batch_enabled=True), tid, include_unknown=True), ALICE, tid)
    assert edges(real(snap(allowed, batch_enabled=True, batch_role_can_start=False), tid), ALICE) == []
    incomplete = snap(allowed)
    incomplete["collections"][-2]["items"][0]["ActionMetadata"]["pipeline"]["roleArn"] = [pipeline_role]
    assert_unresolved(real(incomplete, tid, include_unknown=True), ALICE, tid)


def test_codepipeline_new_s3_project_requires_names_roles_and_versioned_bucket():
    tid = "aws-codepipeline-passrole-createpipeline-codebuild"
    seed = hashlib.sha256(ALICE.encode()).hexdigest()[:10]
    pipeline_name, project_name = "PeasoPipe" + seed, "PeasoBuild" + seed
    pipeline_arn = f"arn:aws:codepipeline:{REGION}:{ACCOUNT}:{pipeline_name}"
    project_arn = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/{project_name}"
    bucket_arn = "arn:aws:s3:::pipeline-source"
    target_arn, pipeline_role_arn = role_arn("builder"), role_arn("pipeline")
    def snap(principal, *, versioning="Enabled", pipeline_can_start=True):
        bucket = {"Name": "pipeline-source", "Location": {"collection_status": "collected",
                  "LocationConstraint": REGION}, "Versioning": {"collection_status": "collected",
                  "Status": versioning}, "Encryption": {"collection_status": "absent"}}
        pipeline_permissions = [allow("codebuild:StartBuild", resource=project_arn)] if pipeline_can_start else []
        pipeline_permissions.extend((allow("s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                                           resource=bucket_arn + "/*"),
                                     allow("s3:GetBucketVersioning", "s3:GetBucketLocation", "s3:GetBucketAcl",
                                           resource=bucket_arn)))
        roles = [role("builder", "codebuild.amazonaws.com",
                      allow("s3:GetObject", "s3:GetObjectVersion", resource=bucket_arn + "/*")),
                 role("pipeline", "codepipeline.amazonaws.com", *pipeline_permissions)]
        return aws_snap([principal], roles, [col("codepipeline_pipeline", []),
                                            col("codebuild_project", []), col("bucket", [bucket])])
    granted = user("alice", allow("iam:PassRole", resource=[target_arn, pipeline_role_arn]),
                   allow("codepipeline:CreatePipeline", resource=pipeline_arn),
                   allow("codepipeline:StartPipelineExecution", resource=pipeline_arn),
                   allow("codebuild:CreateProject", resource=project_arn),
                   allow("s3:PutObject", resource=bucket_arn + "/*"))
    assert reached(real(snap(granted), tid), ALICE) == {target_arn: "conditional"}
    assert edges(real(snap(granted, versioning="Suspended"), tid), ALICE) == []
    assert edges(real(snap(granted, pipeline_can_start=False), tid), ALICE) == []
    disjoint = user("alice", allow("iam:PassRole", resource=[target_arn, pipeline_role_arn]),
                    allow("codepipeline:CreatePipeline", resource=pipeline_arn),
                    allow("codepipeline:StartPipelineExecution", resource=pipeline_arn + "-other"),
                    allow("codebuild:CreateProject", resource=project_arn),
                    allow("s3:PutObject", resource=bucket_arn + "/*"))
    assert edges(real(snap(disjoint), tid), ALICE) == []
    no_pipeline_pass = user("alice", allow("iam:PassRole", resource=target_arn),
                            allow("codepipeline:CreatePipeline", resource=pipeline_arn),
                            allow("codepipeline:StartPipelineExecution", resource=pipeline_arn),
                            allow("codebuild:CreateProject", resource=project_arn),
                            allow("s3:PutObject", resource=bucket_arn + "/*"))
    assert edges(real(snap(no_pipeline_pass), tid), ALICE) == []
    no_target_pass = user("alice", allow("iam:PassRole", resource=pipeline_role_arn),
                          allow("codepipeline:CreatePipeline", resource=pipeline_arn),
                          allow("codepipeline:StartPipelineExecution", resource=pipeline_arn),
                          allow("codebuild:CreateProject", resource=project_arn),
                          allow("s3:PutObject", resource=bucket_arn + "/*"))
    assert edges(real(snap(no_target_pass), tid), ALICE) == []
    kms_bucket = snap(granted)
    kms_bucket["collections"][-1]["items"][0]["Encryption"] = {
        "collection_status": "collected", "ServerSideEncryptionConfiguration": {"Rules": [
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}}
    assert_unresolved(real(kms_bucket, tid, include_unknown=True), ALICE, tid)


def test_codepipeline_new_codecommit_project_uses_pushable_branch_and_artifact_bucket():
    tid = "aws-codepipeline-passrole-createpipeline-codebuild-codecommit"
    seed = hashlib.sha256(ALICE.encode()).hexdigest()[:10]
    pipeline_name, project_name = "PeasoPipe" + seed, "PeasoBuild" + seed
    pipeline_arn = f"arn:aws:codepipeline:{REGION}:{ACCOUNT}:{pipeline_name}"
    project_arn = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/{project_name}"
    repository_arn = f"arn:aws:codecommit:{REGION}:{ACCOUNT}:repo"
    bucket_arn = "arn:aws:s3:::pipeline-artifacts"
    target_arn, pipeline_role_arn = role_arn("builder"), role_arn("pipeline")
    codecommit_reads = ("codecommit:GetRepository", "codecommit:GetBranch", "codecommit:GetCommit",
                        "codecommit:UploadArchive", "codecommit:GetUploadArchiveStatus",
                        "codecommit:CancelUploadArchive")
    def snap(principal, *, can_read_repository=True, versioning="Suspended", recorded_branch=None):
        bucket = {"Name": "pipeline-artifacts", "Location": {"collection_status": "collected",
                  "LocationConstraint": REGION}, "Versioning": {"collection_status": "collected",
                  "Status": versioning}, "Encryption": {"collection_status": "absent"}}
        pipeline_statements = [allow("codebuild:StartBuild", resource=project_arn),
                               allow("s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                                     resource=bucket_arn + "/*"),
                               allow("s3:GetBucketVersioning", "s3:GetBucketLocation", "s3:GetBucketAcl",
                                     resource=bucket_arn)]
        if can_read_repository:
            pipeline_statements.append(allow(*codecommit_reads, resource=repository_arn))
        repository = {"repositoryName": "repo"}
        if recorded_branch:
            repository["ContentSecretIndicators"] = {"collection_status": "collected",
                "identity": repository_arn, "branch": recorded_branch, "commit": "a" * 40}
        return aws_snap([principal], [
            role("builder", "codebuild.amazonaws.com",
                 allow("s3:GetObject", "s3:GetObjectVersion", resource=bucket_arn + "/*")),
            role("pipeline", "codepipeline.amazonaws.com", *pipeline_statements)], [
                col("codepipeline_pipeline", []), col("codebuild_project", []),
                col("bucket", [bucket]), col("codecommit_repository", [repository])])
    push_main = {"Effect": "Allow", "Action": "codecommit:GitPush", "Resource": repository_arn,
                 "Condition": {"StringEquals": {"codecommit:References": "refs/heads/main"}}}
    granted = user("alice", allow("iam:PassRole", resource=[target_arn, pipeline_role_arn]),
                   allow("codepipeline:CreatePipeline", resource=pipeline_arn),
                   allow("codepipeline:StartPipelineExecution", resource=pipeline_arn),
                   allow("codebuild:CreateProject", resource=project_arn), push_main)
    assert reached(real(snap(granted), tid), ALICE) == {target_arn: "conditional"}
    assert reached(real(snap(granted, versioning="Disabled"), tid), ALICE) == {target_arn: "conditional"}
    assert edges(real(snap(granted, can_read_repository=False), tid), ALICE) == []
    no_push = user("alice", allow("iam:PassRole", resource=[target_arn, pipeline_role_arn]),
                   allow("codepipeline:CreatePipeline", resource=pipeline_arn),
                   allow("codepipeline:StartPipelineExecution", resource=pipeline_arn),
                   allow("codebuild:CreateProject", resource=project_arn))
    assert_unresolved(real(snap(no_push), tid, include_unknown=True), ALICE, tid)
    assert reached(real(snap(no_push, recorded_branch="main"), tid), ALICE) == {target_arn: "conditional"}


def test_codepipeline_new_ecr_project_uses_existing_tagged_image():
    tid = "aws-codepipeline-passrole-createpipeline-codebuild-ecr"
    seed = hashlib.sha256(ALICE.encode()).hexdigest()[:10]
    pipeline_name, project_name = "PeasoPipe" + seed, "PeasoBuild" + seed
    pipeline_arn = f"arn:aws:codepipeline:{REGION}:{ACCOUNT}:{pipeline_name}"
    project_arn = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/{project_name}"
    repository_arn = f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/application"
    bucket_arn = "arn:aws:s3:::pipeline-artifacts"
    target_arn, pipeline_role_arn = role_arn("builder"), role_arn("pipeline")
    def snap(*, tags=("release",), can_describe=True, images_status="collected", digest=None):
        bucket = {"Name": "pipeline-artifacts", "Location": {"collection_status": "collected",
                  "LocationConstraint": REGION}, "Encryption": {"collection_status": "absent"}}
        images = {"collection_status": images_status, "items": [{"imageDigest": digest or "sha256:" + "a" * 64,
                  "imageTags": list(tags)}]}
        pipeline_statements = [allow("codebuild:StartBuild", resource=project_arn),
                               allow("s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                                     resource=bucket_arn + "/*"),
                               allow("s3:GetBucketVersioning", "s3:GetBucketLocation", "s3:GetBucketAcl",
                                     resource=bucket_arn)]
        if can_describe:
            pipeline_statements.append(allow("ecr:DescribeImages", resource=repository_arn))
        principal = user("alice", allow("iam:PassRole", resource=[target_arn, pipeline_role_arn]),
                         allow("codepipeline:CreatePipeline", resource=pipeline_arn),
                         allow("codepipeline:StartPipelineExecution", resource=pipeline_arn),
                         allow("codebuild:CreateProject", resource=project_arn))
        return aws_snap([principal], [
            role("builder", "codebuild.amazonaws.com",
                 allow("s3:GetObject", "s3:GetObjectVersion", resource=bucket_arn + "/*")),
            role("pipeline", "codepipeline.amazonaws.com", *pipeline_statements)], [
                col("codepipeline_pipeline", []), col("codebuild_project", []),
                col("bucket", [bucket]), col("ecr_repository", [{"repositoryArn": repository_arn,
                    "repositoryName": "application", "Images": images}])])
    assert reached(real(snap(), tid), ALICE) == {target_arn: "conditional"}
    assert edges(real(snap(tags=()), tid), ALICE) == []
    assert edges(real(snap(can_describe=False), tid), ALICE) == []
    assert_unresolved(real(snap(images_status="denied"), tid, include_unknown=True), ALICE, tid)
    assert_unresolved(real(snap(digest="malformed"), tid, include_unknown=True), ALICE, tid)


def test_codebuild_createproject_needs_create_and_start_on_one_new_project():
    tid = "aws-codebuild-passrole-createproject"
    a = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/alpha"
    b = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/beta"
    roles = [role("builder", "codebuild.amazonaws.com")]
    def snap(principal, projects=()):
        return aws_snap([principal], roles, [col("codebuild_project", projects)])
    base = (allow("iam:PassRole", resource=role_arn("builder")),
            allow("codebuild:CreateProject", resource=a))
    possible = user("alice", *base, allow("codebuild:StartBuild", resource=a))
    assert reached(real(snap(possible), tid), ALICE) == {role_arn("builder"): "conditional"}
    assert_unresolved(real(aws_snap([possible], roles), tid, include_unknown=True), ALICE, tid)
    assert edges(real(snap(possible, ({"name": "alpha"},)), tid), ALICE) == []
    disjoint = user("alice", *base, allow("codebuild:StartBuild", resource=b))
    assert edges(real(snap(disjoint), tid), ALICE) == []
    wrong_role = user("alice", base[0],
                      {"Effect": "Allow", "Action": "codebuild:CreateProject", "Resource": a,
                       "Condition": {"StringEquals": {"codebuild:serviceRole": role_arn("old")}}},
                      allow("codebuild:StartBuild", resource=a))
    assert edges(real(snap(wrong_role), tid), ALICE) == []
    batch = user("alice", base[0], base[1], allow("codebuild:StartBuildBatch", resource=a))
    assert edges(real(snap(batch), tid), ALICE) == []
    batch_role = role("builder", "codebuild.amazonaws.com", allow("codebuild:StartBuild", resource=a))
    batch_snap = aws_snap([batch], [batch_role], [col("codebuild_project", [])])
    assert reached(real(batch_snap, tid), ALICE) == {role_arn("builder"): "conditional"}
    separate_batch = user("alice", base[0], allow("iam:PassRole", resource=role_arn("batch")),
                          base[1], allow("codebuild:StartBuildBatch", resource=a))
    separate_roles = [roles[0], role("batch", "codebuild.amazonaws.com",
                                   allow("codebuild:StartBuild", resource=a))]
    separate_snap = aws_snap([separate_batch], separate_roles, [col("codebuild_project", [])])
    assert reached(real(separate_snap, tid), ALICE)[role_arn("builder")] == "conditional"
    no_batch_passrole = aws_snap([batch], separate_roles, [col("codebuild_project", [])])
    assert edges(real(no_batch_passrole, tid), ALICE) == []
    no_batch_role = user("alice", base[0],
                         {"Effect": "Allow", "Action": "codebuild:CreateProject", "Resource": a,
                          "Condition": {"Null": {"codebuild:buildBatchConfig.serviceRole": "true"}}},
                         allow("codebuild:StartBuildBatch", resource=a))
    assert edges(real(snap(no_batch_role), tid), ALICE) == []


def test_codebuild_updateproject_needs_existing_project_and_target_role_allowed():
    tid = "aws-codebuild-passrole-updateproject"
    project = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/demo"
    other = f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/other"
    item = {"name": "demo", "Configuration": {"collection_status": "collected", "projects": [
        {"name": "demo", "arn": project, "serviceRole": role_arn("old")}]}}
    roles = [role("builder", "codebuild.amazonaws.com"), role("old", "codebuild.amazonaws.com")]
    def snap(principal, projects=(item,)):
        return aws_snap([principal], roles, [col("codebuild_project", projects)])
    base = allow("iam:PassRole", resource=role_arn("builder"))
    possible = user("alice", base, allow("codebuild:UpdateProject", resource=project),
                    allow("codebuild:StartBuild", resource=project))
    assert reached(real(snap(possible), tid), ALICE) == {role_arn("builder"): "conditional"}
    wrong_region = {"name": "demo", "Configuration": {"collection_status": "collected", "projects": [
        {"name": "demo", "arn": project.replace(REGION, "us-west-2"), "serviceRole": role_arn("old")}]}}
    assert edges(real(snap(possible, (wrong_region,)), tid), ALICE) == []
    assert edges(real(snap(possible, ()), tid), ALICE) == []
    disjoint = user("alice", base, allow("codebuild:UpdateProject", resource=project),
                    allow("codebuild:StartBuild", resource=other))
    assert edges(real(snap(disjoint), tid), ALICE) == []
    wrong_role = user("alice", base,
                      {"Effect": "Allow", "Action": "codebuild:UpdateProject", "Resource": project,
                       "Condition": {"StringEquals": {"codebuild:serviceRole": role_arn("old")}}},
                      allow("codebuild:StartBuild", resource=project))
    assert edges(real(snap(wrong_role), tid), ALICE) == []
    batch_only = user("alice", base, allow("codebuild:UpdateProject", resource=project),
                      allow("codebuild:StartBuildBatch", resource=project))
    assert edges(real(snap(batch_only), tid), ALICE) == []
    batch_capable = role("builder", "codebuild.amazonaws.com", allow("codebuild:StartBuild", resource=project))
    created_batch_config = aws_snap([batch_only], [batch_capable, roles[1]],
                                    [col("codebuild_project", [item])])
    assert reached(real(created_batch_config, tid), ALICE) == {role_arn("builder"): "conditional"}
    existing_batch = {"name": "demo", "Configuration": {"collection_status": "collected", "projects": [
        {"name": "demo", "arn": project, "serviceRole": role_arn("old"),
         "buildBatchConfig": {"serviceRole": role_arn("batch")}}]}}
    batch_role = role("batch", "codebuild.amazonaws.com", allow("codebuild:StartBuild", resource=project))
    reuse_batch_config = aws_snap([batch_only], [roles[0], roles[1], batch_role],
                                  [col("codebuild_project", [existing_batch])])
    assert reached(real(reuse_batch_config, tid), ALICE) == {role_arn("builder"): "conditional"}
    no_child_grant = aws_snap([batch_only], [roles[0], roles[1], role("batch", "codebuild.amazonaws.com")],
                              [col("codebuild_project", [existing_batch])])
    assert edges(real(no_child_grant, tid), ALICE) == []


def test_runinstances_scoped_grant_stays_visible_without_claiming_role_execution():
    ident = "aws-ec2-passrole-runinstances"
    target = role("target", "ec2.amazonaws.com", profiles=[profile_arn("target")])
    image = f"arn:aws:ec2:{REGION}::image/ami-1234567890abcdef0"

    def caller(service, run=True):
        passrole = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": target["Arn"],
                    "Condition": {"StringEquals": {"iam:PassedToService": service}}}
        statements = [passrole]
        if run:
            statements.append(allow("ec2:RunInstances", resource=image))
        return user("alice", *statements)

    result = real(aws_snap([caller("ec2.amazonaws.com")], [target]), ident, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, ident)
    assert_unresolved(result, ALICE, ident)
    for source in (caller("lambda.amazonaws.com"), caller("ec2.amazonaws.com", run=False)):
        assert not reached(real(aws_snap([source], [target]), ident), ALICE, ident)


def test_runinstances_prior_catalog_binding_preserves_earlier_requirements():
    from peaso.privesc import versioned_catalog as catalog

    ident = "aws-ec2-passrole-runinstances"
    old_binding = {"schema": catalog.BINDING_SCHEMA,
                   "manifest_sha256": catalog.EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST,
                   "effective_tree_sha256": catalog.EC2_RUNINSTANCES_689_PREVIOUS_TREE,
                   "source_revision": catalog.V4_REVISION}
    old, old_status = catalog.lookup_entries([ident], old_binding)
    new, new_status = catalog.lookup_entries([ident], catalog.current_binding())
    assert old_status == "exact_previous_current"
    assert new_status == "exact_strict_privesc"
    assert any(req["action"] == "ec2:RunInstances" for req in old[ident]["requires"]["all_of"])
    assert all(req["action"] != "ec2:RunInstances" for req in new[ident]["requires"]["all_of"])
    assert new[ident]["preconditions"] == ["ec2_runinstances_launch_with_passed_profile_unverified"]
