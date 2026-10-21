"""claude2_aws_b compute: Lambda, ECS, EKS, EC2 Auto Scaling, AppStream, Elastic Beanstalk, Batch.

Each predicate is a pure function over read-only snapshot facts. Kinds that the
collector does not gather yet (autoscaling_group, launch_configuration, ecs_service,
ecs_task_set, ecs_container_instance, ecs_account_setting, appstream_fleet,
elastic_beanstalk_environment, eks VpcCniAddon detail) are written against the
documented API response shape and stay UNKNOWN until collected (see COLLECTOR_FACTS).
"""
from __future__ import annotations

import json
import re

from . import alias_check, result, unknown
from .facts import Unavailable, get, list_of_objects, complete_items, optional
from .claude2_aws_b_common import (install, flag, manual_case, detail, absent_or, strings, policy_document, is_policy_public,  # noqa: F401
    account, inventory, indexes, CONTEXT, ABSENT, P, C, X)

# Row -> ([existing native ids], note). Same question, threshold and applicability.
MERGED = {
    P + "awslambda_function_vpc_multi_az": (["aws.cb.lambda.vpc_multiple_az"],
        "VPC-attached function subnets span at least two Availability Zones (lambda_min_azs default 2). Prowler reports non-VPC functions only when awslambda_function_inside_vpc did not already fail them; that case is reported by aws.lambda.vpc_configuration, so the native is NOT_APPLICABLE for them."),
    P + "ecs_task_definitions_containers_readonly_access": (["aws.b.ecs.all_readonly_roots"],
        "Every container declares readonlyRootFilesystem true (absent = false)."),
    P + "ecs_task_definitions_host_namespace_not_shared": (["aws.b.ecs.no_host_pid"], "Task definition pidMode is not host."),
    P + "ecs_task_definitions_no_privileged_containers": (["aws.b.ecs.no_privileged_containers"], "No container sets privileged true (absent = false)."),
    P + "ecs_service_no_assign_public_ip": (["aws.c2b.ecs.awsvpc_service_no_public_ip"],
        "The awsvpc service predicate covers assignPublicIp; other network modes are not applicable."),
    P + "eks_cluster_private_nodes_enabled": (["aws.eks.private_endpoint"], "Cluster resourcesVpcConfig.endpointPrivateAccess is true."),
}

MANUAL = {}

_SECRET_SCAN = ("Upstream runs a secret-content scanner over the decoded payload (detect-secrets / Kingfisher or substring and password-regex matching). PEASO is a read-only configuration CSPM that does not collect or scan secret material; "
                "the collector deliberately discards user data, environment values, commands and option values, and collecting them to grep for credentials is intrusive and unsuitable for the snapshot.")
REJECTED = {
    P + "autoscaling_find_secrets_ec2_launch_configuration": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_LaunchConfiguration.html"]},
    C + "autoscaling_ec2_launch_configuration_no_sensitive_data": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_LaunchConfiguration.html"]},
    P + "batch_job_definition_no_secrets": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/batch/latest/APIReference/API_ContainerProperties.html"]},
    P + "ecs_task_definitions_no_environment_secrets": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": ["aws.c2b.ecs.no_credential_named_env_vars"],
        "docs": ["https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html"]},
    P + "elasticbeanstalk_environment_no_secrets_in_configuration": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_DescribeConfigurationSettings.html"]},
}

# Facts this module reads that the collector does not gather yet (read-only APIs only).
COLLECTOR_FACTS = [
    {"kind": "lambda_function", "api": "lambda:ListFunctions (existing)", "fields": ["Environment.VariableCount (number of Environment.Variables keys; values discarded)"],
     "checks": ["aws.c2b.lambda.env_vars_cmk"]},
    {"kind": "autoscaling_group", "api": "autoscaling:DescribeAutoScalingGroups",
     "fields": ["AutoScalingGroupARN", "AvailabilityZones", "LoadBalancerNames", "TargetGroupARNs", "HealthCheckType", "CapacityRebalance", "LaunchConfigurationName",
                "LaunchTemplate", "MixedInstancesPolicy.LaunchTemplate (LaunchTemplateSpecification, Overrides[].InstanceType/InstanceRequirements)", "SuspendedProcesses",
                "Tags[].PropagateAtLaunch", "Instances[].AvailabilityZone/InstanceType"],
     "checks": ["aws.c2b.autoscaling.*"]},
    {"kind": "launch_configuration", "api": "autoscaling:DescribeLaunchConfigurations",
     "fields": ["LaunchConfigurationARN", "LaunchConfigurationName", "AssociatePublicIpAddress", "MetadataOptions.HttpTokens/HttpEndpoint/HttpPutResponseHopLimit (UserData discarded)"],
     "checks": ["aws.c2b.autoscaling.lc_no_public_ip", "aws.c2b.autoscaling.lc_imdsv2_required", "aws.c2b.autoscaling.lc_hop_limit",
                "aws.c2b.autoscaling.group_lc_no_public_ip", "aws.c2b.autoscaling.group_lc_imdsv2"]},
    {"kind": "ecs_service", "api": "ecs:ListServices + ecs:DescribeServices",
     "fields": ["serviceArn", "clusterArn", "launchType", "capacityProviderStrategy", "desiredCount", "platformVersion", "platformFamily", "taskDefinition", "networkConfiguration.awsvpcConfiguration.assignPublicIp", "loadBalancers"],
     "checks": ["aws.c2b.ecs.awsvpc_service_no_public_ip", "aws.c2b.ecs.fargate_latest_platform", "aws.c2b.ecs.service_load_balancer_attached", "aws.c2b.ecs.cluster_has_registered_instances"]},
    {"kind": "ecs_task_set", "api": "ecs:DescribeTaskSets (per service)", "fields": ["taskSetArn", "networkConfiguration.awsvpcConfiguration.assignPublicIp"],
     "checks": ["aws.c2b.ecs.task_set_no_public_ip"]},
    {"kind": "ecs_container_instance", "api": "ecs:ListContainerInstances + ecs:DescribeContainerInstances (per cluster)",
     "fields": ["containerInstanceArn", "clusterArn (the cluster queried)", "ec2InstanceId", "agentConnected", "status"],
     "checks": ["aws.c2b.ecs.container_instance_agents_connected", "aws.c2b.ecs.cluster_instance_volumes_encrypted", "aws.c2b.ecs.container_instance_in_vpc"]},
    {"kind": "ecs_account_setting", "api": "ecs:ListAccountSettings(name=defaultLogDriverMode, effectiveSettings=true)", "fields": ["name", "value"],
     "checks": ["aws.c2b.ecs.logging_non_blocking"]},
    {"kind": "ecs_task_definition", "api": "ecs:DescribeTaskDefinition (existing)", "fields": ["containerDefinitions[].environment[].name (names only; values discarded)"],
     "checks": ["aws.c2b.ecs.no_credential_named_env_vars"]},
    {"kind": "eks_cluster", "api": "eks:DescribeAddon(clusterName, addonName=vpc-cni) stored as VpcCniAddon (ResourceNotFoundException = absent marker)",
     "fields": ["addon.configurationValues (only enableNetworkPolicy is needed)"], "checks": ["aws.c2b.eks.vpc_cni_network_policy"]},
    {"kind": "appstream_fleet", "api": "appstream:DescribeFleets",
     "fields": ["Arn", "EnableDefaultInternetAccess", "MaxUserDurationInSeconds", "DisconnectTimeoutInSeconds", "IdleDisconnectTimeoutInSeconds"],
     "checks": ["aws.c2b.appstream.*"]},
    {"kind": "elastic_beanstalk_environment", "api": "elasticbeanstalk:DescribeEnvironments + DescribeConfigurationSettings stored as Configuration",
     "fields": ["EnvironmentArn", "Configuration.ConfigurationSettings[].OptionSettings[] restricted to aws:elasticbeanstalk:cloudwatch:logs/StreamLogs, "
                "aws:elasticbeanstalk:managedactions/ManagedActionsEnabled, aws:elasticbeanstalk:healthreporting:system/SystemType (other option values discarded)"],
     "checks": ["aws.c2b.elasticbeanstalk.*"]},
]

CTX = {"context": dict(CONTEXT)}
ACCOUNT_ID = CONTEXT["Account"]

# =========================================================================== Lambda
D_LAMBDA = "https://docs.aws.amazon.com/lambda/latest/api/API_FunctionConfiguration.html"
FN = "arn:aws:lambda:us-east-1:111111111111:function:f"
LBASE = {"FunctionName": "f", "FunctionArn": FN, "PackageType": "Zip", "Runtime": "python3.12"}


def _fn(**fields):
    return {**LBASE, "Policy": ABSENT, "FunctionUrl": ABSENT, **fields}


def lambda_policy(item):
    container = detail(item, "Policy")
    if container is None:
        return None
    return policy_document(get(container, "Policy"))


@install("aws.c2b.lambda.env_vars_cmk", "lambda_function", "Lambda function environment variables are encrypted with a customer managed KMS key",
    _fn(Environment={"VariableCount": 2}, KMSKeyArn="arn:aws:kms:us-east-1:111111111111:key/k"), _fn(Environment={"VariableCount": 2}),
    rows=[P + "awslambda_function_env_vars_not_encrypted_with_cmk"], severity="medium", control="SC-28",
    remediation="Set KMSKeyArn on the function to a customer managed KMS key that encrypts its environment variables.",
    docs=[D_LAMBDA, "https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html"],
    extra={"no_env_pass": _fn(), "stripped": _fn(Environment={}), "stripped_expect": "UNKNOWN"},
    note="Prowler: no environment variables PASS; KMSKeyArn set PASS; otherwise FAIL. The collector discards Environment.Variables values, so presence is read from a key count; without it UNKNOWN.")
def lambda_env_cmk(item, index):
    kms = absent_or(item, "FunctionArn", "KMSKeyArn", None, str)
    if kms:
        return result(False, kms_key_arn=kms)
    env = absent_or(item, "FunctionArn", "Environment", None, dict)
    if env is None:
        return result(False, environment_variables=0)
    if "Variables" in env:
        count = len(get(env, "Variables", dict))
    elif "VariableCount" in env:
        count = get(env, "VariableCount", int)
    else:
        raise Unavailable("environment variable presence not collected")
    return result(count > 0, environment_variables=count, kms_key_arn=None)


def _trails(selectors=None, advanced=None):
    return inventory("cloudtrail", [{"Name": "t", "TrailARN": "arn:aws:cloudtrail:us-east-1:111111111111:trail/t",
                                     "EventSelectors": {"EventSelectors": selectors or [], **({"AdvancedEventSelectors": advanced} if advanced else {})}}])


def _prowler_trail_covers(trail, arn, partition):
    body = get(trail, "EventSelectors", dict)
    for selector in list_of_objects(body.get("EventSelectors") or []):
        for data in list_of_objects(selector.get("DataResources") or []):
            values = strings(data.get("Values") or [])
            if data.get("Type") == "AWS::Lambda::Function" and (arn in values or "arn:%s:lambda" % partition in values):
                return True
    for selector in list_of_objects(body.get("AdvancedEventSelectors") or []):
        for field in list_of_objects(selector.get("FieldSelectors") or []):
            if field.get("Field") == "resources.type" and "AWS::Lambda::Function" in strings(field.get("Equals") or []):
                return True
    return False


@install("aws.c2b.lambda.invoke_cloudtrail_logged", "lambda_function", "Lambda function Invoke API calls are recorded by a CloudTrail data event selector",
    _fn(), _fn(), rows=[P + "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled"], severity="low", control="AU-2",
    remediation="Add a CloudTrail data event selector for AWS::Lambda::Function (all functions or this function ARN).",
    docs=["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"], dependencies=["lambda_function", "cloudtrail"],
    extra={"pass_index": _trails([{"DataResources": [{"Type": "AWS::Lambda::Function", "Values": ["arn:aws:lambda"]}]}]),
           "fail_index": _trails([{"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}]),
           "advanced_pass": _fn(), "advanced_pass_index": _trails(advanced=[{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]}]}])},
    note="Prowler: a basic selector value equal to the function ARN or exactly arn:<partition>:lambda, or an advanced selector with Field resources.type Equals AWS::Lambda::Function. Evaluated over the audited region's trails (multi-region trails appear as shadow trails); different from the steampipe variant aws.cb.lambda.cloudtrail_data_events (slash stripping, any field).")
def lambda_invoke_trail(item, index):
    arn = get(item, "FunctionArn", str)
    partition = arn.split(":")[1] if arn.count(":") >= 5 else "aws"
    covered = [get(t, "Name", str) for t in complete_items(index, "cloudtrail") if _prowler_trail_covers(t, arn, partition)]
    return result(not covered, trails=covered)


_PUBLIC = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction", "Resource": FN}]}
_SERVICE = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "lambda:InvokeFunction", "Resource": FN,
                           "Condition": {"ArnLike": {"AWS:SourceArn": "arn:aws:s3:::b"}}}]}


@install("aws.c2b.lambda.policy_not_public", "lambda_function", "Lambda function resource-based policy does not allow public access",
    _fn(Policy={"Policy": _SERVICE, "RevisionId": "r"}), _fn(Policy={"Policy": _PUBLIC, "RevisionId": "r"}),
    rows=[P + "awslambda_function_not_publicly_accessible"], severity="critical", category="exposure", control="AC-3",
    remediation="Remove public principals from the function policy or restrict them with aws:SourceAccount/aws:SourceArn/aws:PrincipalOrgID conditions.",
    docs=["https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html"],
    extra={"index": CTX, "not_applicable": _fn()},
    note="Prowler is_policy_public(policy, audited_account, is_cross_account_allowed=True); functions without a policy are skipped (NOT_APPLICABLE).")
def lambda_public(item, index):
    statements = lambda_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    public = is_policy_public(statements, account(index), True)
    return result(public, public_policy=public)


@install("aws.c2b.lambda.url_cors_no_wildcard", "lambda_function", "Lambda function URL CORS does not allow the wildcard origin",
    _fn(FunctionUrl={"FunctionUrl": "https://x.lambda-url.us-east-1.on.aws/", "Cors": {"AllowOrigins": ["https://app.example.test"]}}),
    _fn(FunctionUrl={"FunctionUrl": "https://x.lambda-url.us-east-1.on.aws/", "Cors": {"AllowOrigins": ["https://app.example.test", "*"]}}),
    rows=[P + "awslambda_function_url_cors_policy"], severity="medium", category="exposure", control="AC-4",
    remediation="Replace the * origin in the function URL CORS AllowOrigins with the specific trusted origins.",
    docs=["https://docs.aws.amazon.com/lambda/latest/api/API_Cors.html"],
    extra={"not_applicable": _fn(), "no_cors_pass": _fn(FunctionUrl={"FunctionUrl": "https://x.lambda-url.us-east-1.on.aws/"})},
    note="Prowler: '*' in allow_origins (membership); aws.b.lambda.url_cors_single_wildcard is the steampipe exact-list equality variant. No URL is NOT_APPLICABLE; no CORS block means no allowed origins.")
def lambda_cors(item, index):
    url = detail(item, "FunctionUrl")
    if url is None:
        return "NOT_APPLICABLE", {"function_url": None}
    get(url, "FunctionUrl", str)
    origins = strings(absent_or(url, "FunctionUrl", "Cors.AllowOrigins", [], list))
    return result("*" in origins, allow_origins=origins)


@install("aws.c2b.lambda.no_cross_account_layers", "lambda_function", "Lambda function uses only layers owned by the audited account",
    _fn(Layers=[{"Arn": "arn:aws:lambda:us-east-1:111111111111:layer:l:1"}]), _fn(Layers=[{"Arn": "arn:aws:lambda:us-east-1:222222222222:layer:l:3"}]),
    rows=[P + "awslambda_function_using_cross_account_layers"], severity="high", control="SR-3",
    remediation="Replace layers published by other accounts with layers built and published in this account, or verify the publisher.",
    docs=["https://docs.aws.amazon.com/lambda/latest/api/API_Layer.html"], extra={"index": CTX, "no_layers_pass": _fn()},
    note="Prowler: no layers PASS; any layer ARN account different from the audited account FAIL.")
def lambda_layers(item, index):
    layers = list_of_objects(absent_or(item, "FunctionArn", "Layers", [], list))
    me = account(index)
    foreign = []
    for layer in layers:
        arn = get(layer, "Arn", str)
        parts = arn.split(":")
        if len(parts) < 7:
            raise Unavailable("malformed layer ARN")
        if parts[4] != me:
            foreign.append(arn)
    return result(bool(foreign), cross_account_layers=foreign)


OBSOLETE = ("java8", "go1.x", "provided", "python3.6", "python2.7", "python3.7", "python3.8", "nodejs4.3", "nodejs4.3-edge", "nodejs6.10", "nodejs", "nodejs8.10",
            "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "dotnet5.0", "dotnet6", "dotnet7", "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
            "ruby2.5", "ruby2.7")


@install("aws.c2b.lambda.runtime_not_obsolete", "lambda_function", "Lambda function runtime is not in the pinned obsolete runtime list",
    _fn(Runtime="python3.12"), _fn(Runtime="nodejs16.x"), rows=[P + "awslambda_function_using_supported_runtimes"], severity="medium", control="SI-2",
    remediation="Upgrade the function to a currently supported Lambda runtime.", docs=["https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"],
    extra={"not_applicable": {k: v for k, v in _fn(PackageType="Image").items() if k != "Runtime"}},
    note="Prowler default obsolete_lambda_runtimes list (pinned, reproduced verbatim); functions without a runtime (container images) are skipped.")
def lambda_runtime(item, index):
    runtime = absent_or(item, "FunctionArn", "Runtime", None, str)
    if not runtime:
        return "NOT_APPLICABLE", {"runtime": None}
    return result(runtime in OBSOLETE, runtime=runtime)


# =========================================================================== ECS task definitions
D_ECS_CD = "https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html"
D_ECS_TD = "https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_TaskDefinition.html"
TD = "arn:aws:ecs:us-east-1:111111111111:task-definition/t:1"


def _td(containers, **fields):
    return {"taskDefinitionArn": TD, "Definition": {"collection_status": "collected", "taskDefinition": {"taskDefinitionArn": TD, "containerDefinitions": containers, **fields}}}


def task(item):
    definition = get(item, "Definition.taskDefinition", dict)
    containers = list_of_objects(get(definition, "containerDefinitions", list))
    if not containers:
        raise Unavailable("task definition has no container definitions")
    for row in containers:
        get(row, "name", str)
    return definition, containers


@install("aws.c2b.ecs.host_network_root_user", "ecs_task_definition", "Host-network ECS task definitions run non-privileged containers as an explicit non-root user",
    _td([{"name": "app", "user": "1000"}], networkMode="host"), _td([{"name": "app"}], networkMode="host"),
    rows=[P + "ecs_task_definitions_host_networking_mode_users"], severity="high", control="AC-6",
    remediation="Avoid host network mode, or set a non-root user on every non-privileged container of the task definition.",
    docs=[D_ECS_CD, "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#network_mode"],
    extra={"bridge_pass": _td([{"name": "app"}], networkMode="awsvpc"), "uid0": _td([{"name": "app", "user": "0:0"}], networkMode="host"), "uid0_expect": "FAIL"},
    note="Prowler: in host network mode a non-privileged container whose user is root or empty (absent) fails; other network modes PASS. UID 0 is also treated as root (corrected; same identity).")
def ecs_host_user(item, index):
    definition, containers = task(item)
    mode = optional(definition, "networkMode", None, str)
    if mode != "host":
        return result(False, network_mode=mode)
    failed = []
    for row in containers:
        privileged = optional(row, "privileged", False, bool)
        user = optional(row, "user", "", str)
        if not privileged and (user.split(":", 1)[0] in ("root", "", "0")):
            failed.append(row["name"])
    return result(bool(failed), network_mode=mode, root_containers=failed)


@install("aws.c2b.ecs.all_containers_logging", "ecs_task_definition", "Every container of the ECS task definition has a log driver configured",
    _td([{"name": "app", "logConfiguration": {"logDriver": "awslogs"}}]), _td([{"name": "app", "logConfiguration": {"logDriver": "awslogs"}}, {"name": "sidecar"}]),
    rows=[P + "ecs_task_definitions_logging_enabled"], severity="high", control="AU-12",
    remediation="Add a logConfiguration with a logDriver (for example awslogs) to every container definition.", docs=[D_ECS_CD, "https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-9"],
    note="Prowler universal predicate (every container); aws.b.ecs.some_logging_configuration is the steampipe existential variant.")
def ecs_all_logging(item, index):
    _, containers = task(item)
    missing = []
    for row in containers:
        log = optional(row, "logConfiguration", None, dict)
        if log is None or not optional(log, "logDriver", None, str):
            missing.append(row["name"])
    return result(bool(missing), containers_without_log_driver=missing)


def _log_settings(*values):
    return inventory("ecs_account_setting", [{"name": "defaultLogDriverMode", "value": v} for v in values])


@install("aws.c2b.ecs.logging_non_blocking", "ecs_task_definition", "ECS container logging uses non-blocking delivery mode",
    _td([{"name": "app", "logConfiguration": {"logDriver": "awslogs", "options": {"mode": "non-blocking"}}}]),
    _td([{"name": "app", "logConfiguration": {"logDriver": "awslogs", "options": {"mode": "blocking"}}}]),
    rows=[P + "ecs_task_definitions_logging_block_mode"], severity="low", control="SC-5",
    remediation="Set logConfiguration.options.mode to non-blocking (and size max-buffer-size), or leave it unset with the defaultLogDriverMode account setting at non-blocking.",
    docs=["https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_LogConfiguration.html", "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-account-settings.html#default-log-driver-mode"],
    dependencies=["ecs_task_definition", "ecs_account_setting"],
    extra={"not_applicable": _td([{"name": "app"}]),
           "inherit_pass": _td([{"name": "app", "logConfiguration": {"logDriver": "awslogs"}}]), "inherit_pass_index": _log_settings(),
           "inherit_blocking": _td([{"name": "app", "logConfiguration": {"logDriver": "awslogs"}}]), "inherit_blocking_index": _log_settings("blocking"), "inherit_blocking_expect": "FAIL",
           "inherit_unread": _td([{"name": "app", "logConfiguration": {"logDriver": "awslogs"}}]), "inherit_unread_expect": "UNKNOWN"},
    note="Prowler fails a container with a log driver whose mode option is not non-blocking and skips definitions without logged containers. AWS documents that an unset mode inherits the defaultLogDriverMode account setting and otherwise defaults to non-blocking (since 2025-06-25), so an unset mode is resolved from that setting instead of failing; unreadable setting = UNKNOWN.")
def ecs_log_mode(item, index):
    _, containers = task(item)
    logged, blocking, inherited = [], [], []
    for row in containers:
        log = optional(row, "logConfiguration", None, dict)
        if log is None or not optional(log, "logDriver", None, str):
            continue
        logged.append(row["name"])
        mode = optional(optional(log, "options", {}, dict), "mode", None, str)
        if mode is None:
            inherited.append(row["name"])
        elif mode != "non-blocking":
            blocking.append(row["name"])
    if not logged:
        return "NOT_APPLICABLE", {"containers_with_log_driver": []}
    default = None
    if inherited:
        settings = [s for s in complete_items(index, "ecs_account_setting") if get(s, "name", str) == "defaultLogDriverMode"]
        default = get(settings[0], "value", str) if settings else "non-blocking"
        if default != "non-blocking":
            blocking.extend(inherited)
    return result(bool(blocking), blocking_containers=blocking, inherited_mode=default)


SECRET_NAMES = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA")


@install("aws.c2b.ecs.no_credential_named_env_vars", "ecs_task_definition", "ECS containers do not pass AWS credentials as plain environment variables",
    _td([{"name": "app", "environment": [{"name": "LOG_LEVEL"}]}]), _td([{"name": "app", "environment": [{"name": "AWS_SECRET_ACCESS_KEY"}]}]),
    rows=[C + "ecs_task_definition_container_environment_no_secret", C + "foundational_security_ecs_8"], severity="high", control="IA-5",
    remediation="Move AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and ECS_ENGINE_AUTH_DATA out of environment into secrets (Secrets Manager / Parameter Store) or use the task IAM role.",
    docs=["https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-8", D_ECS_CD],
    extra={"secret_ref_pass": _td([{"name": "app", "environment": [], "secrets": [{"name": "AWS_SECRET_ACCESS_KEY"}]}]),
           "stripped": _td([{"name": "app"}]), "stripped_expect": "UNKNOWN"},
    note="Names only (never values). Security Hub ECS.8 checks environment keys only; the pinned query also matched secrets[] names (the documented secure mechanism) and, via its cross join, never alarmed on containers without a secrets array, so both are corrected. Environment names not collected = UNKNOWN.")
def ecs_env_names(item, index):
    _, containers = task(item)
    hits = []
    for row in containers:
        if "environment" not in row and "environment" not in row.get("_coverage", {}):
            raise Unavailable("container environment names not collected")
        for entry in list_of_objects(get(row, "environment", list)):
            name = get(entry, "name", str)
            if name in SECRET_NAMES:
                hits.append(row["name"] + ":" + name)
    return result(bool(hits), credential_environment_variables=hits)


# =========================================================================== ECS clusters
D_ECS_CL = "https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Cluster.html"
CL = "arn:aws:ecs:us-east-1:111111111111:cluster/c"


def _cl(**fields):
    return {"clusterArn": CL, "Configuration": {"collection_status": "collected", "clusters": [{"clusterArn": CL, **fields}], "failures": []}}


def cluster(item):
    rows = list_of_objects(get(item, "Configuration.clusters", list))
    arn = get(item, "clusterArn", str)
    rows = [r for r in rows if r.get("clusterArn") == arn]
    if len(rows) != 1:
        raise Unavailable("cluster configuration not uniquely collected")
    return rows[0]


def _insights(row):
    settings = list_of_objects(get(row, "settings", list))
    values = [get(s, "value", str) for s in settings if get(s, "name", str) == "containerInsights"]
    return settings, values


@install("aws.c2b.ecs.container_insights", "ecs_cluster", "ECS cluster has Container Insights enabled or enhanced",
    _cl(settings=[{"name": "containerInsights", "value": "enhanced"}]), _cl(settings=[]),
    rows=[P + "ecs_cluster_container_insights_enabled"], severity="medium", control="AU-6",
    remediation="Turn on Container Insights (enabled or enhanced) for the cluster.", docs=[D_ECS_CL, "https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-12"],
    note="Prowler: PASS only when a containerInsights setting is enabled or enhanced; no settings FAIL.")
def ecs_insights(item, index):
    _, values = _insights(cluster(item))
    return result(not any(v in ("enabled", "enhanced") for v in values), container_insights=values)


@install("aws.c2b.ecs.container_insights_setting", "ecs_cluster", "ECS cluster containerInsights setting is turned on",
    _cl(settings=[{"name": "containerInsights", "value": "enabled"}]), _cl(settings=[{"name": "containerInsights", "value": "disabled"}]),
    rows=[C + "ecs_cluster_container_insights_enabled", C + "foundational_security_ecs_12"], severity="medium", control="AU-6",
    remediation="Turn on Container Insights for the cluster.", docs=[D_ECS_CL, "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/deploy-container-insights-ECS-cluster.html"],
    extra={"fail_empty": _cl(settings=[]), "fail_empty_expect": "FAIL",
           "enhanced_pass": _cl(settings=[{"name": "containerInsights", "value": "enhanced"}])},
    note="Native ECS.12 criterion: complete empty settings FAIL; omitted settings are UNKNOWN. Pinned Steampipe produces no row for an empty settings list; enhanced is accepted as enabled coverage.")
def ecs_insights_setting(item, index):
    _, values = _insights(cluster(item))
    return result(not values or any(v not in ("enabled", "enhanced") for v in values), container_insights=values)


@install("aws.c2b.ecs.cluster_has_active_services", "ecs_cluster", "ECS cluster has at least one active service",
    _cl(activeServicesCount=2), _cl(activeServicesCount=0), rows=[C + "ecs_cluster_no_active_services_count"], severity="low", control="CM-8",
    remediation="Delete unused clusters or deploy the intended services to them.", docs=[D_ECS_CL],
    note="Steampipe: activeServicesCount > 0.")
def ecs_active(item, index):
    count = get(cluster(item), "activeServicesCount", int)
    return result(count <= 0, active_services=count)


def _ecs_capacity_mode(strategy):
    """Classify a selected strategy only when every usable provider is Fargate."""
    providers = list_of_objects(strategy)
    active = []
    for provider in providers:
        name = get(provider, "capacityProvider", str)
        weight = optional(provider, "weight", 0, int)
        base = optional(provider, "base", 0, int)
        if weight < 0 or base < 0:
            raise Unavailable("malformed ECS capacity provider strategy")
        if weight or base:
            active.append(name)
    return "FARGATE" if active and all(name in ("FARGATE", "FARGATE_SPOT") for name in active) else "UNKNOWN"


def _ecs_service_mode(service, cluster_row):
    desired = get(service, "desiredCount", int)
    if desired < 0:
        raise Unavailable("malformed ECS service desired count")
    if desired == 0:
        return "IDLE"
    launch = optional(service, "launchType", None, str)
    strategy = optional(service, "capacityProviderStrategy", None, list)
    if launch is not None and strategy:
        return "UNKNOWN"
    if launch in ("EC2", "FARGATE", "EXTERNAL", "MANAGED_INSTANCES"):
        return launch
    if launch is not None:
        return "UNKNOWN"
    if strategy is None or not strategy:
        strategy = optional(cluster_row, "defaultCapacityProviderStrategy", None, list)
    return "UNKNOWN" if strategy is None else _ecs_capacity_mode(strategy)


def _ecs_task_mode(task):
    status = get(task, "lastStatus", str)
    if status == "STOPPED":
        return "IDLE"
    if status not in ("RUNNING", "PENDING", "PROVISIONING", "ACTIVATING"):
        return "UNKNOWN"
    launch = optional(task, "launchType", None, str)
    provider = optional(task, "capacityProviderName", None, str)
    if launch == "EC2":
        return "EC2_DEMAND" if status != "RUNNING" else "UNKNOWN"
    if launch == "FARGATE" and provider not in (None, "FARGATE", "FARGATE_SPOT"):
        return "UNKNOWN"
    if launch == "FARGATE" or (launch is None and provider in ("FARGATE", "FARGATE_SPOT")):
        return "FARGATE"
    return "UNKNOWN"


@install("aws.c2b.ecs.cluster_has_registered_instances", "ecs_cluster", "ECS cluster has registered instances when EC2 service capacity is required",
    _cl(registeredContainerInstancesCount=1), _cl(registeredContainerInstancesCount=0), rows=[C + "ecs_cluster_no_registered_container_instance"], severity="low", control="CM-8",
    remediation="For an EC2 service with desired tasks, investigate missing container instance registration; Fargate-only workloads need no container instances.", docs=[D_ECS_CL, "https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Service.html"],
    dependencies=["ecs_cluster", "ecs_service", "ecs_task"],
    extra={"fail_index": indexes(inventory("ecs_service", [{"clusterArn": CL, "launchType": "EC2", "desiredCount": 1}]), inventory("ecs_task", [])),
           "not_applicable": _cl(registeredContainerInstancesCount=0),
           "not_applicable_index": indexes(inventory("ecs_service", [{"clusterArn": CL, "launchType": "FARGATE", "desiredCount": 1}]), inventory("ecs_task", []))},
    note="Intentional Steampipe correction: zero registered instances is not an EC2 deficit in a proved Fargate-only cluster. Complete cluster-matched service/task facts distinguish actual EC2 demand from Fargate-only, empty, and unresolved configurations; a positive count is registration inventory, not readiness proof.")
def ecs_registered(item, index):
    row = cluster(item)
    count = get(row, "registeredContainerInstancesCount", int)
    if count < 0:
        raise Unavailable("malformed registered container instance count")
    if count > 0:
        return result(False, registered_container_instances=count, readiness="not established by registration count")
    arn = get(item, "clusterArn", str)
    services = [r for r in complete_items(index, "ecs_service") if get(r, "clusterArn", str) == arn]
    tasks = [r for r in complete_items(index, "ecs_task") if get(r, "clusterArn", str) == arn]
    service_modes = [_ecs_service_mode(service, row) for service in services]
    task_modes = [_ecs_task_mode(task) for task in tasks]
    if "EC2" in service_modes or "EC2_DEMAND" in task_modes:
        return result(True, registered_container_instances=0, ec2_services=sum(mode == "EC2" for mode in service_modes),
                      pending_ec2_tasks=sum(mode == "EC2_DEMAND" for mode in task_modes))
    if "UNKNOWN" in service_modes or "UNKNOWN" in task_modes:
        return "UNKNOWN", {"reason": "ECS launch type or capacity provider is unresolved", "registered_container_instances": 0,
                           "service_modes": service_modes, "task_modes": task_modes}
    if "FARGATE" in service_modes or "FARGATE" in task_modes:
        return "NOT_APPLICABLE", {"reason": "observed workloads use Fargate; no EC2 container instance is required",
                                  "registered_container_instances": 0, "service_modes": service_modes, "task_modes": task_modes}
    return "UNKNOWN", {"reason": "no active workload proves container instance capacity is required", "registered_container_instances": 0}


def _ci(**fields):
    return {"containerInstanceArn": "arn:aws:ecs:us-east-1:111111111111:container-instance/c/1", "clusterArn": CL, "ec2InstanceId": "i-1", "status": "ACTIVE", "agentConnected": True, **fields}


def _cluster_instances(index, arn):
    rows = [r for r in complete_items(index, "ecs_container_instance") if get(r, "clusterArn", str) == arn]
    # Both callers invoke this only after a positive registered-instance count.
    # A concurrent list returning no hosts cannot establish agent/volume safety.
    if not rows:
        raise Unavailable("registered ECS container instances missing from inventory")
    return rows


@install("aws.c2b.ecs.container_instance_agents_connected", "ecs_cluster", "Active container instances of the ECS cluster have a connected agent",
    _cl(registeredContainerInstancesCount=1), _cl(registeredContainerInstancesCount=1), rows=[C + "ecs_cluster_container_instance_agent_connected"],
    severity="medium", control="SI-4", remediation="Restore connectivity of the ECS container agent (network path, IAM role, agent version) or deregister the instance.",
    docs=["https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerInstance.html"], dependencies=["ecs_cluster", "ecs_container_instance"],
    extra={"pass_index": inventory("ecs_container_instance", [_ci()]), "fail_index": inventory("ecs_container_instance", [_ci(agentConnected=False)]),
           "not_applicable": _cl(registeredContainerInstancesCount=0)},
    note="Steampipe: skip when no instance is registered; alarm when any ACTIVE container instance of the cluster has agentConnected false.")
def ecs_agents(item, index):
    row = cluster(item)
    if get(row, "registeredContainerInstancesCount", int) == 0:
        return "NOT_APPLICABLE", {"registered_container_instances": 0}
    bad = [get(r, "containerInstanceArn", str) for r in _cluster_instances(index, get(item, "clusterArn", str))
           if get(r, "status", str) == "ACTIVE" and get(r, "agentConnected", bool) is False]
    return result(bool(bad), disconnected_instances=bad)


def _ec2(**fields):
    return {"InstanceId": "i-1", "VpcId": "vpc-1", "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-1"}}], **fields}


def _volumes(encrypted):
    return inventory("ebs_volume", [{"VolumeId": "vol-1", "Encrypted": encrypted}])


def _instance(index, instance_id):
    rows = [r for r in complete_items(index, "instance") if get(r, "InstanceId", str) == instance_id]
    if len(rows) != 1:
        raise Unavailable("container instance EC2 instance not in inventory")
    return rows[0]


@install("aws.c2b.ecs.cluster_instance_volumes_encrypted", "ecs_cluster", "EBS volumes of the ECS cluster's container instances are encrypted",
    _cl(registeredContainerInstancesCount=1), _cl(registeredContainerInstancesCount=1), rows=[C + "ecs_cluster_encryption_at_rest_enabled"],
    severity="medium", control="SC-28", remediation="Use encrypted EBS volumes (or enable EBS encryption by default) for the cluster's container instances.",
    docs=["https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html"], dependencies=["ecs_cluster", "ecs_container_instance", "instance", "ebs_volume"],
    extra={"pass_index": indexes(inventory("ecs_container_instance", [_ci()]), inventory("instance", [_ec2()]), _volumes(True)),
           "fail_index": indexes(inventory("ecs_container_instance", [_ci()]), inventory("instance", [_ec2()]), _volumes(False)),
           "not_applicable": _cl(registeredContainerInstancesCount=0)},
    note="Steampipe joins container instances -> EC2 block device mappings -> EBS volumes; any unencrypted volume alarms; no registered instance is skip. An instance or volume missing from the complete inventories is UNKNOWN.")
def ecs_volumes(item, index):
    row = cluster(item)
    if get(row, "registeredContainerInstancesCount", int) == 0:
        return "NOT_APPLICABLE", {"registered_container_instances": 0}
    volumes = {get(v, "VolumeId", str): v for v in complete_items(index, "ebs_volume")}
    bad = []
    for ci in _cluster_instances(index, get(item, "clusterArn", str)):
        ec2 = _instance(index, get(ci, "ec2InstanceId", str))
        for mapping in list_of_objects(optional(ec2, "BlockDeviceMappings", [], list)):
            ebs = optional(mapping, "Ebs", None, dict)
            if ebs is None:
                continue
            vid = get(ebs, "VolumeId", str)
            if vid not in volumes:
                raise Unavailable("volume not in inventory")
            if get(volumes[vid], "Encrypted", bool) is False:
                bad.append(vid)
    return result(bool(bad), unencrypted_volumes=bad)


@install("aws.c2b.ecs.container_instance_in_vpc", "ecs_container_instance", "ECS EC2 container instance has an observed VPC association",
    _ci(), _ci(), rows=[C + "ecs_cluster_instance_in_vpc"], severity="medium", category="network", control="SC-7",
    remediation="Review the EC2 inventory when an ECS container instance has no readable VPC association; EC2-Classic is retired.", docs=["https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerInstance.html"],
    dependencies=["ecs_container_instance", "instance"],
    extra={"pass_index": inventory("instance", [_ec2()]), "fail_index": inventory("instance", [_ec2(VpcId=None)]), "fail_expect": "UNKNOWN",
           "not_applicable": _ci(ec2InstanceId="mi-0123456789abcdef0")},
    note="Intentional Steampipe correction: null joined VpcId cannot prove an EC2-Classic/network vulnerability after EC2-Classic retirement. Documented mi-* SSM-managed external instances are NOT_APPLICABLE; a real EC2 i-* instance with a collected VPC ID passes, missing/denied/null facts are UNKNOWN.")
def ecs_ci_vpc(item, index):
    instance_id = get(item, "ec2InstanceId", str)
    if re.fullmatch(r"mi-[0-9a-f]{17}", instance_id):
        return "NOT_APPLICABLE", {"ec2_instance_id": instance_id, "reason": "ECS Anywhere SSM-managed external instance"}
    if not instance_id.startswith("i-") or len(instance_id) <= 2:
        return "UNKNOWN", {"reason": "unrecognized ECS container instance host ID", "ec2_instance_id": instance_id}
    vpc = optional(_instance(index, instance_id), "VpcId", None)
    if not isinstance(vpc, str) or not re.fullmatch(r"vpc-[0-9a-f]+", vpc):
        return "UNKNOWN", {"reason": "EC2 VPC association not readable or malformed", "ec2_instance_id": instance_id, "vpc_id": vpc}
    return result(False, ec2_instance_id=instance_id, vpc_id=vpc)


# =========================================================================== ECS services / task sets
D_ECS_SVC = "https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Service.html"
SVC = "arn:aws:ecs:us-east-1:111111111111:service/c/s"


def _svc(assign=None, **fields):
    out = {"serviceArn": SVC, "clusterArn": CL, "taskDefinition": TD, "loadBalancers": [], **fields}
    if assign is not None:
        out["networkConfiguration"] = {"awsvpcConfiguration": {"subnets": ["subnet-1"], "assignPublicIp": assign}}
    return out


def _tds(mode):
    return inventory("ecs_task_definition", [_td([{"name": "app"}], networkMode=mode)])


@install("aws.c2b.ecs.awsvpc_service_no_public_ip", "ecs_service", "awsvpc-mode ECS service does not automatically assign public IP addresses",
    _svc("DISABLED"), _svc("ENABLED"),
    rows=[C + "ecs_service_not_publicly_accessible", C + "foundational_security_ecs_2", X + "ecs_service_not_publicly_accessible"],
    severity="high", category="exposure", control="SC-7",
    remediation="Set networkConfiguration.awsvpcConfiguration.assignPublicIp to DISABLED for the service.", docs=[D_ECS_SVC, "https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-2"],
    dependencies=["ecs_service", "ecs_task_definition"],
    extra={"pass_index": _tds("awsvpc"), "fail_index": _tds("awsvpc"), "not_applicable": _svc(), "not_applicable_index": _tds("bridge")},
    note="Steampipe joins the service task definition and evaluates only awsvpc network mode (else skip); assignPublicIp DISABLED is ok. An omitted assignPublicIp inside awsvpcConfiguration is the documented DISABLED default (upstream alarmed on null). A task definition missing from the ACTIVE inventory is UNKNOWN.")
def ecs_svc_awsvpc(item, index):
    arn = get(item, "taskDefinition", str)
    rows = [r for r in complete_items(index, "ecs_task_definition") if get(r, "taskDefinitionArn", str) == arn]
    if len(rows) != 1:
        raise Unavailable("service task definition not in inventory")
    definition, _ = task(rows[0])
    mode = optional(definition, "networkMode", None, str)
    if mode != "awsvpc":
        return "NOT_APPLICABLE", {"network_mode": mode}
    vpc = get(item, "networkConfiguration.awsvpcConfiguration", dict)
    value = optional(vpc, "assignPublicIp", "DISABLED", str)
    return result(value != "DISABLED", assign_public_ip=value)


# The older check asked the same question but reported a non-awsvpc service as
# PASS and could fail without its task definition. Keep its ID for stored scans.
alias_check("aws.c2b.ecs.service_no_public_ip", "aws.c2b.ecs.awsvpc_service_no_public_ip")


LATEST_LINUX, LATEST_WINDOWS = "1.4.0", "1.0.0"


@install("aws.c2b.ecs.fargate_latest_platform", "ecs_service", "ECS Fargate service runs on the latest Fargate platform version",
    _svc(launchType="FARGATE", platformVersion="LATEST", platformFamily="Linux"), _svc(launchType="FARGATE", platformVersion="1.3.0", platformFamily="Linux"),
    rows=[P + "ecs_service_fargate_latest_platform_version", C + "ecs_service_fargate_using_latest_platform_version", C + "foundational_security_ecs_10"],
    severity="medium", control="SI-2", remediation="Update the service to platform version LATEST (or 1.4.0 Linux / 1.0.0 Windows).",
    docs=[D_ECS_SVC, "https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-10", "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform-fargate.html"],
    extra={"not_applicable": _svc(launchType="EC2"), "pinned_pass": _svc(launchType="FARGATE", platformVersion="1.4.0", platformFamily="Linux"),
           "windows_pass": _svc(launchType="FARGATE", platformVersion="LATEST", platformFamily="WINDOWS_SERVER_2019_CORE")},
    note="Security Hub ECS.10 parameters latestLinuxVersion 1.4.0 / latestWindowsVersion 1.0.0. Prowler's operator precedence failed Windows services on LATEST and the steampipe query alarmed on an explicit current version (1.4.0); both are corrected to: LATEST or the documented latest version passes. Services without a launchType (capacity provider strategy) are NOT_APPLICABLE; an unknown platform family is UNKNOWN.")
def ecs_fargate(item, index):
    launch = absent_or(item, "serviceArn", "launchType", None, str)
    if launch != "FARGATE":
        return "NOT_APPLICABLE", {"launch_type": launch}
    version = get(item, "platformVersion", str)
    if version == "LATEST":
        return result(False, platform_version=version)
    family = get(item, "platformFamily", str)
    if family.upper() == "LINUX":
        return result(version != LATEST_LINUX, platform_version=version, platform_family=family)
    if family.upper().startswith("WINDOWS"):
        return result(version != LATEST_WINDOWS, platform_version=version, platform_family=family)
    raise Unavailable("unrecognized Fargate platform family")


@install("aws.c2b.ecs.service_load_balancer_attached", "ecs_service", "ECS service is attached to a load balancer",
    _svc(loadBalancers=[{"targetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/t/1"}]), _svc(),
    rows=[C + "ecs_service_load_balancer_attached"], severity="low", control="CP-10",
    remediation="Attach the service to an Elastic Load Balancing target group when it serves traffic.", docs=[D_ECS_SVC],
    note="Steampipe: an empty loadBalancers list alarms.")
def ecs_svc_lb(item, index):
    lbs = list_of_objects(get(item, "loadBalancers", list))
    return result(not lbs, load_balancers=len(lbs))


def _ts(assign=None):
    out = {"taskSetArn": "arn:aws:ecs:us-east-1:111111111111:task-set/c/s/ecs-svc/1"}
    if assign is not None:
        out["networkConfiguration"] = {"awsvpcConfiguration": {"subnets": ["subnet-1"], "assignPublicIp": assign}}
    return out


@install("aws.c2b.ecs.task_set_no_public_ip", "ecs_task_set", "ECS task set does not automatically assign public IP addresses",
    _ts("DISABLED"), _ts("ENABLED"), rows=[P + "ecs_task_set_no_assign_public_ip"], severity="high", category="exposure", control="SC-7",
    remediation="Set the task set awsvpcConfiguration.assignPublicIp to DISABLED.",
    docs=["https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_TaskSet.html", "https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-16"],
    extra={"no_network_pass": _ts()}, note="Prowler / Security Hub ECS.16: FAIL when assignPublicIp is ENABLED.")
def ecs_ts_ip(item, index):
    value = absent_or(item, "taskSetArn", "networkConfiguration.awsvpcConfiguration.assignPublicIp", "DISABLED", str)
    return result(value == "ENABLED", assign_public_ip=value)


# =========================================================================== EKS
D_EKS = "https://docs.aws.amazon.com/eks/latest/APIReference/API_Cluster.html"
EKS_ARN = "arn:aws:eks:us-east-1:111111111111:cluster/k"


def _eks(vpc=None, **fields):
    return {"name": "k", "Cluster": {"collection_status": "collected", "cluster": {"arn": EKS_ARN, "name": "k", "version": "1.30", "platformVersion": "eks.6",
            "resourcesVpcConfig": {"endpointPublicAccess": False, "endpointPrivateAccess": True, "publicAccessCidrs": [], "securityGroupIds": [],
                                   "clusterSecurityGroupId": "sg-01234567", **(vpc or {})}, **fields}}}


def eks(item):
    row = get(item, "Cluster.cluster", dict)
    get(row, "arn", str)
    return row


def eks_vpc(item):
    return get(eks(item), "resourcesVpcConfig", dict)


@install("aws.c2b.eks.endpoint_not_world_open", "eks_cluster", "EKS public API endpoint is not open to 0.0.0.0/0",
    _eks({"endpointPublicAccess": True, "publicAccessCidrs": ["203.0.113.0/24"]}), _eks({"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]}),
    rows=[P + "eks_cluster_not_publicly_accessible", C + "eks_cluster_endpoint_public_access_restricted"], severity="high", category="exposure", control="SC-7",
    remediation="Disable public endpoint access or restrict publicAccessCidrs to trusted ranges.",
    docs=[D_EKS, "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html"], extra={"private_pass": _eks()},
    note="Prowler and steampipe: FAIL only when endpointPublicAccess is true and publicAccessCidrs contains the literal 0.0.0.0/0 (aws.b.eks.disable_public_endpoint also treats ::/0 and is a different query).")
def eks_world(item, index):
    vpc = eks_vpc(item)
    public = get(vpc, "endpointPublicAccess", bool)
    if not public:
        return result(False, endpoint_public_access=False)
    cidrs = strings(get(vpc, "publicAccessCidrs", list))
    return result("0.0.0.0/0" in cidrs, public_access_cidrs=cidrs)


@install("aws.c2b.eks.endpoint_not_public", "eks_cluster", "EKS cluster API endpoint is not publicly accessible",
    _eks(), _eks({"endpointPublicAccess": True, "publicAccessCidrs": ["203.0.113.0/24"]}), rows=[X + "eks_cluster_endpoint_prohibit_public_access"],
    severity="high", category="exposure", control="SC-7", remediation="Disable endpointPublicAccess and use the private endpoint.",
    docs=[D_EKS, "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html"], note="aws-perimeter: endpointPublicAccess true alarms regardless of CIDRs.")
def eks_public(item, index):
    public = get(eks_vpc(item), "endpointPublicAccess", bool)
    return result(public, endpoint_public_access=public)


@install("aws.c2b.eks.single_security_group", "eks_cluster", "EKS cluster does not attach multiple additional security groups",
    _eks({"securityGroupIds": ["sg-a"]}), _eks({"securityGroupIds": ["sg-a", "sg-b"]}), rows=[C + "eks_cluster_no_multiple_security_groups"],
    severity="low", category="network", control="SC-7", remediation="Consolidate the cluster's additional security groups into one reviewed group.", docs=[D_EKS],
    note="Steampipe: more than one entry in resourcesVpcConfig.securityGroupIds alarms.")
def eks_sgs(item, index):
    groups = strings(absent_or(eks_vpc(item), "endpointPublicAccess", "securityGroupIds", [], list))
    return result(len(groups) > 1, security_group_ids=groups)


def _version(row):
    value = get(row, "version", str)
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.\d+)?", value)
    if not match:
        raise Unavailable("malformed Kubernetes version")
    return value, (int(match.group(1)), int(match.group(2)))


@install("aws.c2b.eks.version_at_least_1_19", "eks_cluster", "EKS cluster Kubernetes version is at least 1.19 (pinned steampipe floor)",
    _eks(), _eks(version="1.18"), rows=[C + "eks_cluster_with_latest_kubernetes_version", C + "foundational_security_eks_2"], severity="high", control="SI-2",
    remediation="Upgrade the cluster to a Kubernetes version in EKS standard support.", docs=["https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html"],
    note="Pinned steampipe floor 1.19 (version::decimal >= 1.19). Compared as (major, minor) so 1.9 is correctly older than 1.19.")
def eks_119(item, index):
    value, parsed = _version(eks(item))
    return result(parsed < (1, 19), version=value, oldest_supported="1.19")


@install("aws.c2b.eks.version_at_least_1_28", "eks_cluster", "EKS cluster Kubernetes version is at least 1.28 (prowler default floor)",
    _eks(), _eks(version="1.27"), rows=[P + "eks_cluster_uses_a_supported_version"], severity="high", control="SI-2",
    remediation="Upgrade the cluster to a Kubernetes version in EKS standard support.", docs=["https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html"],
    note="Prowler default eks_cluster_oldest_version_supported 1.28 (different threshold from the steampipe 1.19 floor).")
def eks_128(item, index):
    value, parsed = _version(eks(item))
    return result(parsed < (1, 28), version=value, oldest_supported="1.28")


@install("aws.c2b.eks.deletion_protection", "eks_cluster", "EKS cluster has deletion protection enabled",
    _eks(deletionProtection=True), _eks(deletionProtection=False), rows=[P + "eks_cluster_deletion_protection_enabled"], severity="high", control="CP-9",
    remediation="Enable deletionProtection on the cluster (UpdateClusterConfig).", docs=[D_EKS],
    note="Prowler fails only an explicit false; an unreported deletionProtection member is UNKNOWN.")
def eks_deletion(item, index):
    value = get(eks(item), "deletionProtection", bool)
    return result(value is False, deletion_protection=value)


@install("aws.c2b.eks.secrets_encryption_configured", "eks_cluster", "EKS cluster has an encryptionConfig (KMS envelope encryption) configured",
    _eks(encryptionConfig=[{"resources": ["secrets"], "provider": {"keyArn": "arn:aws:kms:us-east-1:111111111111:key/k"}}]), _eks(),
    rows=[P + "eks_cluster_kms_cmk_encryption_in_secrets_enabled"], severity="medium", control="SC-28",
    remediation="Associate a KMS key for secrets envelope encryption (AssociateEncryptionConfig).", docs=[D_EKS, "https://docs.aws.amazon.com/eks/latest/userguide/envelope-encryption.html"],
    note="Prowler: non-empty encryptionConfig PASS regardless of version (aws.eks.secrets_encryption accepts the 1.28+ default and is a different predicate). DescribeCluster omits encryptionConfig when none is configured.")
def eks_kms(item, index):
    configs = absent_or(eks(item), "arn", "encryptionConfig", [], list)
    return result(not configs, encryption_config=len(configs))


@install("aws.c2b.eks.cluster_security_group_present", "eks_cluster", "EKS DescribeCluster reports a cluster security group ID",
    _eks(), _eks({"clusterSecurityGroupId": ""}), rows=[P + "eks_cluster_network_policy_enabled"], severity="high", category="network", control="SC-7",
    remediation="Inspect the cluster version, platform and VPC configuration; review its actual security group associations and rules with the cluster owner.",
    docs=[D_EKS, "https://docs.aws.amazon.com/eks/latest/APIReference/API_VpcConfigResponse.html",
          "https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html",
          "https://docs.aws.amazon.com/eks/latest/best-practices/network-security.html"],
    extra={"fail_expect": "UNKNOWN", "not_applicable": _eks({"clusterSecurityGroupId": ""}, version="1.14", platformVersion="eks.2")},
    note="Pinned Prowler equates clusterSecurityGroupId truthiness with Kubernetes NetworkPolicy, but AWS defines it as the EKS-created cluster SG ID, "
         "not a pod policy. A plausible observed SG ID passes only this presence fact. Missing/empty/malformed modern IDs are UNKNOWN, not proof of "
         "insecure networking or a reason to replace the cluster. Documented pre-1.14-eks.3 legacy clusters used a separate SG model; only a "
         "provably older current version/platform is NOT_APPLICABLE. The 1.14-eks.3 boundary and upgraded historical clusters remain UNKNOWN when the ID is absent.")
def eks_cluster_sg(item, index):
    row = eks(item)
    value = optional(get(row, "resourcesVpcConfig", dict), "clusterSecurityGroupId", None, str)
    if value:
        if not re.fullmatch(r"sg-(?:[0-9a-f]{8}|[0-9a-f]{17})", value):
            return unknown("malformed cluster security group ID", cluster_security_group_id=value)
        return result(False, cluster_security_group_id=value,
                      observed_fact="EKS DescribeCluster returned a cluster SG ID; rules and Kubernetes NetworkPolicy were not evaluated")
    version, parsed = _version(row)
    if parsed < (1, 14):
        return "NOT_APPLICABLE", {"version": version, "reason": "historical pre-1.14 EKS security group model; review separate control-plane and node groups"}
    if parsed == (1, 14):
        platform = get(row, "platformVersion", str)
        match = re.fullmatch(r"eks\.(\d+)", platform)
        if not match:
            raise Unavailable("malformed EKS platform version")
        if int(match.group(1)) < 3:
            return "NOT_APPLICABLE", {"version": version, "platform_version": platform,
                                      "reason": "historical pre-eks.3 EKS security group model; review separate control-plane and node groups"}
    return unknown("EKS cluster security group ID absent or empty in DescribeCluster; actual association is unverified", version=version)


def _cni(values=None):
    addon = {"addonName": "vpc-cni", "addonVersion": "v1.18.0-eksbuild.1"}
    if values is not None:
        addon["configurationValues"] = values
    return {**_eks(), "VpcCniAddon": {"collection_status": "collected", "addon": addon}}


@install("aws.c2b.eks.vpc_cni_network_policy", "eks_cluster", "EKS Amazon VPC CNI managed add-on enforces Kubernetes network policies",
    _cni('{"enableNetworkPolicy": "true"}'), _cni('{"enableNetworkPolicy": "false"}'),
    rows=[P + "eks_cluster_vpc_cni_network_policy_enforced"], severity="medium", category="network", control="SC-7",
    remediation="Set enableNetworkPolicy to true in the vpc-cni add-on configurationValues (or document the third-party policy engine in use).",
    docs=["https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy-configure.html", "https://docs.aws.amazon.com/eks/latest/APIReference/API_Addon.html"],
    extra={"no_addon": {**_eks(), "VpcCniAddon": ABSENT}, "no_addon_expect": "MANUAL", "unset": _cni(), "unset_expect": "MANUAL",
           "bool_pass": _cni('{"enableNetworkPolicy": true}')},
    note="Prowler: enableNetworkPolicy true PASS, false FAIL; no managed add-on, unreadable or unset configuration is MANUAL (third-party engines and self-managed CNI are invisible to the EKS API).")
def eks_cni(item, index):
    eks(item)
    container = detail(item, "VpcCniAddon")
    if container is None:
        return "MANUAL", {"reason": "cluster does not use the Amazon VPC CNI managed add-on"}
    addon = get(container, "addon", dict)
    raw = optional(addon, "configurationValues", "", str)
    try:
        values = json.loads(raw) if raw else {}
    except ValueError:
        values = None
    if not isinstance(values, dict):
        return "MANUAL", {"reason": "add-on configurationValues is not a JSON object"}
    setting = values.get("enableNetworkPolicy")
    if isinstance(setting, str) and setting.strip().lower() in ("true", "false"):
        setting = setting.strip().lower() == "true"
    if not isinstance(setting, bool):
        return "MANUAL", {"reason": "enableNetworkPolicy not set"}
    return result(not setting, enable_network_policy=setting)


# =========================================================================== EC2 Auto Scaling
D_ASG = "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_AutoScalingGroup.html"
D_LC = "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_LaunchConfiguration.html"
ASG = "arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:1:autoScalingGroupName/g"


def _asg(**fields):
    return {"AutoScalingGroupARN": ASG, "AutoScalingGroupName": "g", "AvailabilityZones": ["us-east-1a", "us-east-1b"], "LoadBalancerNames": [], "TargetGroupARNs": [],
            "HealthCheckType": "EC2", **fields}


def _lc(**fields):
    return {"LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:111111111111:launchConfiguration:1:launchConfigurationName/lc", "LaunchConfigurationName": "lc", **fields}


@install("aws.c2b.autoscaling.multiple_az", "autoscaling_group", "Auto Scaling group spans more than one Availability Zone",
    _asg(), _asg(AvailabilityZones=["us-east-1a"]),
    rows=[P + "autoscaling_group_multiple_az", C + "autoscaling_group_multiple_az_configured", C + "foundational_security_autoscaling_2"],
    severity="medium", control="CP-10", remediation="Configure the group with subnets in at least two Availability Zones.",
    docs=[D_ASG, "https://docs.aws.amazon.com/securityhub/latest/userguide/autoscaling-controls.html"], note="Prowler and steampipe: len(AvailabilityZones) > 1.")
def asg_az(item, index):
    zones = strings(get(item, "AvailabilityZones", list))
    return result(len(zones) < 2, availability_zones=zones)


@install("aws.c2b.autoscaling.uses_launch_template", "autoscaling_group", "Auto Scaling group uses an EC2 launch template",
    _asg(LaunchTemplate={"LaunchTemplateId": "lt-1", "Version": "$Latest"}), _asg(LaunchConfigurationName="lc"),
    rows=[P + "autoscaling_group_using_ec2_launch_template", C + "autoscaling_group_uses_ec2_launch_template", C + "foundational_security_autoscaling_9"],
    severity="medium", control="CM-2", remediation="Migrate the group from a launch configuration to an EC2 launch template.",
    docs=[D_ASG, "https://docs.aws.amazon.com/securityhub/latest/userguide/autoscaling-controls.html"],
    extra={"mixed_pass": _asg(MixedInstancesPolicy={"LaunchTemplate": {"LaunchTemplateSpecification": {"LaunchTemplateId": "lt-1"}}})},
    note="Prowler: LaunchTemplate or MixedInstancesPolicy launch template passes. The steampipe launch_template_id column misses mixed-instances groups, which AWS documents as using a launch template; corrected to the prowler/Security Hub semantics.")
def asg_lt(item, index):
    direct = absent_or(item, "AutoScalingGroupARN", "LaunchTemplate", None, dict)
    mixed = absent_or(item, "AutoScalingGroupARN", "MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification", None, dict)
    return result(not direct and not mixed, launch_template=bool(direct), mixed_instances_launch_template=bool(mixed))


def _lbs(item):
    lbs = strings(absent_or(item, "AutoScalingGroupARN", "LoadBalancerNames", [], list))
    tgs = strings(absent_or(item, "AutoScalingGroupARN", "TargetGroupARNs", [], list))
    return lbs, tgs


TG = "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/t/1"


@install("aws.c2b.autoscaling.elb_health_check", "autoscaling_group", "Auto Scaling group attached to a load balancer uses ELB health checks",
    _asg(TargetGroupARNs=[TG], HealthCheckType="ELB"), _asg(TargetGroupARNs=[TG]),
    rows=[P + "autoscaling_group_elb_health_check_enabled", C + "autoscaling_group_with_lb_use_health_check", C + "foundational_security_autoscaling_1"],
    severity="low", control="CP-10", remediation="Set HealthCheckType to ELB on groups attached to load balancers or target groups.",
    docs=[D_ASG, "https://docs.aws.amazon.com/securityhub/latest/userguide/autoscaling-controls.html"], extra={"not_applicable": _asg()},
    note="Security Hub AutoScaling.1 applies to groups associated with a load balancer. Corrected applicability: any classic load balancer or target group (prowler required both, steampipe alarmed on groups without any). PASS when HealthCheckType includes ELB.")
def asg_health(item, index):
    lbs, tgs = _lbs(item)
    if not lbs and not tgs:
        return "NOT_APPLICABLE", {"load_balancers": [], "target_groups": []}
    kind = get(item, "HealthCheckType", str)
    return result("ELB" not in kind, health_check_type=kind)


@install("aws.c2b.autoscaling.capacity_rebalance", "autoscaling_group", "Auto Scaling group behind load balancers has Capacity Rebalancing enabled",
    _asg(LoadBalancerNames=["clb"], TargetGroupARNs=[TG], CapacityRebalance=True), _asg(LoadBalancerNames=["clb"], TargetGroupARNs=[TG], CapacityRebalance=False),
    rows=[P + "autoscaling_group_capacity_rebalance_enabled"], severity="medium", control="CP-10",
    remediation="Enable CapacityRebalance so Spot capacity is replaced proactively.", docs=[D_ASG, "https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-capacity-rebalancing.html"],
    extra={"not_applicable": _asg(TargetGroupARNs=[TG])},
    note="Prowler applicability reproduced: only groups with both classic load balancers and target groups are evaluated; CapacityRebalance omitted = false.")
def asg_rebalance(item, index):
    lbs, tgs = _lbs(item)
    if not (lbs and tgs):
        return "NOT_APPLICABLE", {"load_balancers": lbs, "target_groups": tgs}
    value = absent_or(item, "AutoScalingGroupARN", "CapacityRebalance", False, bool)
    return result(not value, capacity_rebalance=value)


def _inst(az, kind):
    return {"InstanceId": "i-%s-%s" % (az, kind), "AvailabilityZone": az, "InstanceType": kind}


@install("aws.c2b.autoscaling.instance_types_per_az", "autoscaling_group", "Auto Scaling group runs at least two instance types in each of several Availability Zones",
    _asg(Instances=[_inst("a", "m5.large"), _inst("a", "m6i.large"), _inst("b", "m5.large"), _inst("b", "m6i.large")]),
    _asg(Instances=[_inst("a", "m5.large"), _inst("b", "m5.large")]),
    rows=[P + "autoscaling_group_multiple_instance_types"], severity="medium", control="CP-10",
    remediation="Use a mixed instances policy with several instance types across at least two Availability Zones.", docs=[D_ASG],
    extra={"not_applicable": _asg(Instances=[])},
    note="Prowler groups running Instances by AvailabilityZone: PASS when more than one zone and every zone has two or more instance types. A group with no running instances is NOT_APPLICABLE (prowler failed it; the running-instance facts do not exist).")
def asg_types(item, index):
    instances = list_of_objects(get(item, "Instances", list))
    if not instances:
        return "NOT_APPLICABLE", {"instances": 0}
    zones = {}
    for row in instances:
        zones.setdefault(get(row, "AvailabilityZone", str), set()).add(get(row, "InstanceType", str))
    failing = sorted(z for z, kinds in zones.items() if len(kinds) < 2)
    return result(bool(failing) or len(zones) < 2, zones={z: sorted(k) for z, k in zones.items()}, failing_zones=failing)


def _mixed(*overrides):
    return _asg(MixedInstancesPolicy={"LaunchTemplate": {"LaunchTemplateSpecification": {"LaunchTemplateId": "lt-1"}, "Overrides": list(overrides)}})


@install("aws.c2b.autoscaling.mixed_policy_multiple_types", "autoscaling_group", "Auto Scaling group mixed instances policy overrides more than one instance type",
    _mixed({"InstanceType": "m5.large"}, {"InstanceType": "m6i.large"}), _mixed({"InstanceType": "m5.large"}),
    rows=[C + "autoscaling_use_multiple_instance_types_in_multiple_az", C + "foundational_security_autoscaling_6"], severity="medium", control="CP-10",
    remediation="Add several instance types to the mixed instances policy overrides.", docs=[D_ASG, "https://docs.aws.amazon.com/securityhub/latest/userguide/autoscaling-controls.html"],
    extra={"no_mixed": _asg(), "no_mixed_expect": "FAIL", "attribute": _mixed({"InstanceRequirements": {"VCpuCount": {"Min": 2}}}), "attribute_expect": "UNKNOWN"},
    note="Steampipe: count of distinct MixedInstancesPolicy.LaunchTemplate.Overrides[].InstanceType > 1, else alarm (no policy alarms). Attribute-based overrides (InstanceRequirements) have no InstanceType and are UNKNOWN rather than FAIL.")
def asg_mixed(item, index):
    overrides = list_of_objects(absent_or(item, "AutoScalingGroupARN", "MixedInstancesPolicy.LaunchTemplate.Overrides", [], list))
    kinds = set()
    for row in overrides:
        kind = optional(row, "InstanceType", None, str)
        if kind is None:
            if "InstanceRequirements" in row:
                raise Unavailable("attribute-based instance type selection")
            continue
        kinds.add(kind)
    return result(len(kinds) < 2, instance_types=sorted(kinds))


@install("aws.c2b.autoscaling.no_suspended_processes", "autoscaling_group", "Auto Scaling group has no suspended scaling processes",
    _asg(SuspendedProcesses=[]), _asg(SuspendedProcesses=[{"ProcessName": "Launch", "SuspensionReason": "User suspended"}]),
    rows=[C + "autoscaling_group_no_suspended_process"], severity="low", control="CP-10",
    remediation="Resume suspended processes (ResumeProcesses) once maintenance is complete.", docs=[D_ASG],
    note="Steampipe: suspended_processes present alarms; an empty list means none are suspended.")
def asg_suspended(item, index):
    rows = list_of_objects(absent_or(item, "AutoScalingGroupARN", "SuspendedProcesses", [], list))
    return result(bool(rows), suspended=[r.get("ProcessName") for r in rows])


@install("aws.c2b.autoscaling.tags_propagate", "autoscaling_group", "Auto Scaling group tags propagate to launched EC2 instances",
    _asg(Tags=[{"Key": "env", "Value": "p", "PropagateAtLaunch": True}]), _asg(Tags=[{"Key": "env", "Value": "p", "PropagateAtLaunch": False}]),
    rows=[C + "autoscaling_group_propagate_tags_to_ec2_instance_enabled"], severity="low", control="CM-8",
    remediation="Set PropagateAtLaunch true on the group's tags.", docs=["https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_TagDescription.html"],
    note="Steampipe: any tag with PropagateAtLaunch false alarms; no tags is ok.")
def asg_tags(item, index):
    tags = list_of_objects(absent_or(item, "AutoScalingGroupARN", "Tags", [], list))
    bad = [get(t, "Key", str) for t in tags if get(t, "PropagateAtLaunch", bool) is False]
    return result(bool(bad), non_propagating_tags=bad)


def _group_lc(item, index):
    name = absent_or(item, "AutoScalingGroupARN", "LaunchConfigurationName", None, str)
    if not name:
        return None
    rows = [r for r in complete_items(index, "launch_configuration") if get(r, "LaunchConfigurationName", str) == name]
    if len(rows) != 1:
        raise Unavailable("group launch configuration not in inventory")
    return rows[0]


@install("aws.c2b.autoscaling.group_lc_no_public_ip", "autoscaling_group", "Auto Scaling group launch configuration does not assign public IP addresses",
    _asg(LaunchConfigurationName="lc"), _asg(LaunchConfigurationName="lc"), rows=[P + "autoscaling_group_launch_configuration_no_public_ip"],
    severity="high", category="exposure", control="SC-7", remediation="Use a launch template or configuration with AssociatePublicIpAddress false.",
    docs=[D_LC], dependencies=["autoscaling_group", "launch_configuration"],
    extra={"pass_index": inventory("launch_configuration", [_lc(AssociatePublicIpAddress=False)]), "fail_index": inventory("launch_configuration", [_lc(AssociatePublicIpAddress=True)]),
           "not_applicable": _asg(LaunchTemplate={"LaunchTemplateId": "lt-1"})},
    note="Prowler: groups using a launch configuration; AssociatePublicIpAddress true FAIL. An omitted value inherits subnet public-IP assignment and cannot prove disabled exposure. Groups without a launch configuration are NOT_APPLICABLE.")
def asg_lc_ip(item, index):
    lc = _group_lc(item, index)
    if lc is None:
        return "NOT_APPLICABLE", {"launch_configuration": None}
    value = get(lc, "AssociatePublicIpAddress", bool)
    return result(value, associate_public_ip_address=value)


def _imds(lc):
    get(lc, "LaunchConfigurationARN", str)
    endpoint = absent_or(lc, "LaunchConfigurationARN", "MetadataOptions.HttpEndpoint", None, str)
    tokens = absent_or(lc, "LaunchConfigurationARN", "MetadataOptions.HttpTokens", None, str)
    return endpoint, tokens


@install("aws.c2b.autoscaling.group_lc_imdsv2", "autoscaling_group", "Auto Scaling group launch configuration requires IMDSv2 or disables the metadata service",
    _asg(LaunchConfigurationName="lc"), _asg(LaunchConfigurationName="lc"), rows=[P + "autoscaling_group_launch_configuration_requires_imdsv2"],
    severity="high", control="AC-3", remediation="Set MetadataOptions HttpTokens required (or HttpEndpoint disabled) in the group's launch template/configuration.",
    docs=[D_LC, "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-new-instances.html"], dependencies=["autoscaling_group", "launch_configuration"],
    extra={"pass_index": inventory("launch_configuration", [_lc(MetadataOptions={"HttpEndpoint": "enabled", "HttpTokens": "required"})]),
           "fail_index": inventory("launch_configuration", [_lc(MetadataOptions={"HttpEndpoint": "enabled", "HttpTokens": "optional"})]),
           "not_applicable": _asg(LaunchTemplate={"LaunchTemplateId": "lt-1"})},
    note="Prowler: PASS when endpoint enabled with tokens required, or endpoint disabled. An unset HttpTokens may inherit the account-level IMDS defaults (ec2:GetInstanceMetadataDefaults), so it is UNKNOWN rather than FAIL.")
def asg_lc_imds(item, index):
    lc = _group_lc(item, index)
    if lc is None:
        return "NOT_APPLICABLE", {"launch_configuration": None}
    endpoint, tokens = _imds(lc)
    if endpoint == "disabled":
        return result(False, http_endpoint=endpoint)
    if tokens is None:
        raise Unavailable("HttpTokens unset; account IMDS default applies")
    return result(tokens != "required", http_endpoint=endpoint or "enabled", http_tokens=tokens)


flag("aws.c2b.autoscaling.lc_no_public_ip", "launch_configuration", "Launch configuration does not associate public IP addresses", "AssociatePublicIpAddress",
    rows=[C + "autoscaling_launch_config_public_ip_disabled", C + "foundational_security_autoscaling_5", X + "autoscaling_launch_config_public_ip_disabled"],
    severity="high", category="exposure", control="SC-7", remediation="Create a replacement launch configuration/template with AssociatePublicIpAddress false.",
    sentinel="LaunchConfigurationARN", good=False, bad=True, docs=[D_LC],
    note="Steampipe/perimeter: associate_public_ip_address true alarms. An omitted value inherits subnet public-IP assignment and cannot prove disabled exposure.")


@install("aws.c2b.autoscaling.lc_imdsv2_required", "launch_configuration", "Launch configuration requires IMDSv2 (HttpTokens required)",
    _lc(MetadataOptions={"HttpTokens": "required"}), _lc(MetadataOptions={"HttpTokens": "optional"}),
    rows=[C + "autoscaling_launch_config_requires_imdsv2", C + "foundational_security_autoscaling_3"], severity="high", control="AC-3",
    remediation="Create a replacement launch configuration/template with MetadataOptions HttpTokens required.",
    docs=[D_LC, "https://docs.aws.amazon.com/securityhub/latest/userguide/autoscaling-controls.html"],
    extra={"unset": _lc(), "unset_expect": "UNKNOWN"},
    note="Steampipe: metadata_options_http_tokens = required is ok, else alarm. An unset HttpTokens may inherit account-level IMDS defaults, so it is UNKNOWN rather than FAIL.")
def lc_imds(item, index):
    _, tokens = _imds(item)
    if tokens is None:
        raise Unavailable("HttpTokens unset; account IMDS default applies")
    return result(tokens != "required", http_tokens=tokens)


@install("aws.c2b.autoscaling.lc_hop_limit", "launch_configuration", "Launch configuration metadata response hop limit is not greater than 1",
    _lc(MetadataOptions={"HttpPutResponseHopLimit": 1}), _lc(MetadataOptions={"HttpPutResponseHopLimit": 2}),
    rows=[C + "autoscaling_launch_config_hop_limit", C + "foundational_security_autoscaling_4"], severity="medium", control="AC-3",
    remediation="Use HttpPutResponseHopLimit 1 in the launch configuration/template.", docs=[D_LC, "https://docs.aws.amazon.com/securityhub/latest/userguide/autoscaling-controls.html"],
    extra={"absent": _lc()}, note="Steampipe: unset hop limit is ok (documented default 1); > 1 alarms.")
def lc_hop(item, index):
    value = absent_or(item, "LaunchConfigurationARN", "MetadataOptions.HttpPutResponseHopLimit", None, int)
    return result(value is not None and value > 1, hop_limit=value)


# =========================================================================== AppStream
D_AS = "https://docs.aws.amazon.com/appstream2/latest/APIReference/API_Fleet.html"
FLEET = {"Arn": "arn:aws:appstream:us-east-1:111111111111:fleet/f", "Name": "f", "EnableDefaultInternetAccess": False,
         "MaxUserDurationInSeconds": 3600, "DisconnectTimeoutInSeconds": 300, "IdleDisconnectTimeoutInSeconds": 600}

flag("aws.c2b.appstream.no_default_internet", "appstream_fleet", "AppStream fleet default internet access is disabled", "EnableDefaultInternetAccess",
     rows=[P + "appstream_fleet_default_internet_access_disabled", C + "appstream_fleet_default_internet_access_disabled"], severity="medium", category="network",
     control="SC-7", remediation="Disable default internet access and route fleet traffic through a NAT gateway with controlled egress.",
     sentinel="Arn", base=FLEET, good=False, bad=True, docs=[D_AS], note="Prowler and steampipe: EnableDefaultInternetAccess true fails. A response that omits the field cannot prove the configured value.")


def _fleet(**fields):
    return {**FLEET, **fields}


@install("aws.c2b.appstream.max_user_duration_under_10h", "appstream_fleet", "AppStream fleet maximum user session duration is under 10 hours",
    _fleet(), _fleet(MaxUserDurationInSeconds=36000), rows=[P + "appstream_fleet_maximum_session_duration", C + "appstream_fleet_max_user_duration_36000_seconds"],
    severity="medium", control="AC-12", remediation="Set MaxUserDurationInSeconds below 36000.", docs=[D_AS],
    note="Prowler default max_session_duration_seconds 36000 and steampipe: MaxUserDurationInSeconds < 36000.")
def fleet_duration(item, index):
    value = get(item, "MaxUserDurationInSeconds", int)
    return result(value >= 36000, max_user_duration_seconds=value)


@install("aws.c2b.appstream.disconnect_timeout_5m", "appstream_fleet", "AppStream fleet disconnect timeout is 5 minutes or less",
    _fleet(), _fleet(DisconnectTimeoutInSeconds=900), rows=[P + "appstream_fleet_session_disconnect_timeout", C + "appstream_fleet_session_disconnect_timeout_300_seconds"],
    severity="medium", control="AC-12", remediation="Set DisconnectTimeoutInSeconds to 300 or less.", docs=[D_AS],
    note="Prowler default max_disconnect_timeout_in_seconds 300 and steampipe: DisconnectTimeoutInSeconds <= 300.")
def fleet_disconnect(item, index):
    value = get(item, "DisconnectTimeoutInSeconds", int)
    return result(value > 300, disconnect_timeout_seconds=value)


@install("aws.c2b.appstream.idle_disconnect_10m", "appstream_fleet", "AppStream fleet idle disconnect timeout is enabled and 10 minutes or less",
    _fleet(), _fleet(IdleDisconnectTimeoutInSeconds=1800), rows=[P + "appstream_fleet_session_idle_disconnect_timeout", C + "appstream_fleet_idle_disconnect_timeout_600_seconds"],
    severity="medium", control="AC-11", remediation="Set IdleDisconnectTimeoutInSeconds between 60 and 600.", docs=[D_AS],
    extra={"disabled": _fleet(IdleDisconnectTimeoutInSeconds=0), "disabled_expect": "FAIL"},
    note="Prowler: a non-zero value <= 600 passes. AWS documents 0 (or omission) as idle disconnect turned off, which the steampipe '<= 600' comparison accepted; corrected to the prowler semantics.")
def fleet_idle(item, index):
    value = absent_or(item, "Arn", "IdleDisconnectTimeoutInSeconds", 0, int)
    return result(not (0 < value <= 600), idle_disconnect_timeout_seconds=value)


# =========================================================================== Elastic Beanstalk
D_EB = "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"
EB_LOGS = ("aws:elasticbeanstalk:cloudwatch:logs", "StreamLogs")
EB_MANAGED = ("aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled")
EB_HEALTH = ("aws:elasticbeanstalk:healthreporting:system", "SystemType")


def _eb(*options):
    return {"EnvironmentArn": "arn:aws:elasticbeanstalk:us-east-1:111111111111:environment/a/e", "EnvironmentName": "e", "ApplicationName": "a",
            "Configuration": {"collection_status": "collected", "ConfigurationSettings": [{"EnvironmentName": "e", "OptionSettings": [
                {"Namespace": ns, "OptionName": name, "Value": value} for (ns, name), value in options]}]}}


def eb_option(item, key):
    get(item, "EnvironmentArn", str)
    container = get(item, "Configuration", dict)
    if container.get("collection_status") not in (None, "collected"):
        raise Unavailable("configuration settings not collected")
    settings = list_of_objects(get(container, "ConfigurationSettings", list))
    if not settings:
        raise Unavailable("no configuration settings returned")
    values = [get(o, "Value", str) for s in settings for o in list_of_objects(get(s, "OptionSettings", list))
              if o.get("Namespace") == key[0] and o.get("OptionName") == key[1] and "Value" in o]
    if not values:
        raise Unavailable("option not reported: " + ":".join(key))
    return values


@install("aws.c2b.elasticbeanstalk.stream_logs", "elastic_beanstalk_environment", "Elastic Beanstalk environment streams instance logs to CloudWatch Logs",
    _eb((EB_LOGS, "true")), _eb((EB_LOGS, "false")),
    rows=[P + "elasticbeanstalk_environment_cloudwatch_logging_enabled", C + "elastic_beanstalk_environment_logs_to_cloudwatch", C + "foundational_security_elasticbeanstalk_3",
          C + "cis_compute_service_v100_6_2"],
    severity="high", control="AU-9", remediation="Set aws:elasticbeanstalk:cloudwatch:logs StreamLogs to true.",
    docs=[D_EB, "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/AWSHowTo.cloudwatchlogs.html"],
    note="Prowler and steampipe: option StreamLogs = 'true' (the CIS 6.2 row uses the same pinned query). An option not reported by DescribeConfigurationSettings is UNKNOWN.")
def eb_logs(item, index):
    values = eb_option(item, EB_LOGS)
    return result("true" not in [v.lower() for v in values], stream_logs=values)


@install("aws.c2b.elasticbeanstalk.managed_updates", "elastic_beanstalk_environment", "Elastic Beanstalk environment has managed platform updates enabled",
    _eb((EB_MANAGED, "true")), _eb((EB_MANAGED, "false")),
    rows=[P + "elasticbeanstalk_environment_managed_updates_enabled", C + "elastic_beanstalk_environment_managed_updates_enabled"],
    severity="high", control="SI-2", remediation="Set aws:elasticbeanstalk:managedactions ManagedActionsEnabled to true and configure a maintenance window.",
    docs=[D_EB, "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environment-platform-update-managed.html"],
    note="Prowler and steampipe: option ManagedActionsEnabled = 'true'.")
def eb_managed(item, index):
    values = eb_option(item, EB_MANAGED)
    return result("true" not in [v.lower() for v in values], managed_actions=values)


@install("aws.c2b.elasticbeanstalk.enhanced_health", "elastic_beanstalk_environment", "Elastic Beanstalk environment uses enhanced health reporting",
    _eb((EB_HEALTH, "enhanced")), _eb((EB_HEALTH, "basic")),
    rows=[P + "elasticbeanstalk_environment_enhanced_health_reporting", C + "elastic_beanstalk_enhanced_health_reporting_enabled", C + "foundational_security_elasticbeanstalk_1"],
    severity="low", control="SI-4", remediation="Set aws:elasticbeanstalk:healthreporting:system SystemType to enhanced.",
    docs=[D_EB, "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/health-enhanced.html"],
    note="Prowler reads SystemType = enhanced. The steampipe query infers the same setting from DescribeEnvironments HealthStatus/Health being returned; the configuration option is the authoritative fact for the same question.")
def eb_health(item, index):
    values = eb_option(item, EB_HEALTH)
    return result("enhanced" not in values, system_type=values)
