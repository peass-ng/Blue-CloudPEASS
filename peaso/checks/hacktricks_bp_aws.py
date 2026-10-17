"""HackTricks Cloud Best Practices: AWS checks not covered by Prowler/Powerpipe.

Each predicate reads a field the collectors already keep and is derived from the
cited HackTricks Cloud attack-technique page. Missing or unreadable details are
UNKNOWN; documented API-omission defaults are applied only inside a collected
detail response.
"""
from __future__ import annotations

import re

from . import result
from .facts import Unavailable, get, list_of_objects, optional
from .fixtures import CASES
from .hacktricks_bp_common import ht_register

AWS = "pentesting-cloud/aws-security/"


# ---------------------------------------------------------------- Cognito
@ht_register("aws.htbp.cognito.identity_pool_classic_flow_disabled", "aws", "least_privilege", "cognito_identity_pool",
             "Cognito identity pool disables the basic (classic) authentication flow", "medium", "AC-6",
             "Set AllowClassicFlow to false so credentials are only issued through the enhanced flow and its "
             "Cognito-applied scope-down policy.",
             pages=[AWS + "aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum/README.md",
                    AWS + "aws-persistence/aws-cognito-persistence/README.md"])
def classic_flow(item, index):
    configuration = get(item, "Configuration", dict)
    get(configuration, "IdentityPoolId", str)
    enabled = optional(configuration, "AllowClassicFlow", False, bool)
    return result(enabled, allow_classic_flow=enabled,
                  allow_unauthenticated_identities=optional(configuration, "AllowUnauthenticatedIdentities", None),
                  semantics="Basic flow lets a client call sts:AssumeRoleWithWebIdentity directly with the Cognito OpenID "
                            "token, bypassing the enhanced-flow scope-down policy (AWS omits the field when false)")


_POOL = {"IdentityPoolId": "eu-west-1:1111", "IdentityPoolName": "app"}
CASES["aws.htbp.cognito.identity_pool_classic_flow_disabled"] = {
    "pass": {"IdentityPoolId": "eu-west-1:1111", "Configuration": {**_POOL, "AllowUnauthenticatedIdentities": False}},
    "fail": {"IdentityPoolId": "eu-west-1:1111", "Configuration": {**_POOL, "AllowClassicFlow": True, "AllowUnauthenticatedIdentities": True}},
    "missing": {"IdentityPoolId": "eu-west-1:1111"},
    "malformed": {"IdentityPoolId": "eu-west-1:1111", "Configuration": {**_POOL, "AllowClassicFlow": "yes"}}}

# Custom attribute names that applications commonly use for authorization decisions.
PRIVILEGE_ATTRIBUTE = re.compile(r"(?i)role|admin|group|tenant|perm|priv|scope|acl|entitle|is_?staff|superuser|(?:^|[_-])plan(?:$|[_-])")


@ht_register("aws.htbp.cognito.client_no_writable_authorization_attributes", "aws", "least_privilege", "cognito_user_pool",
             "Cognito app clients cannot write authorization-like custom attributes", "medium", "AC-6",
             "Give every app client an explicit WriteAttributes allowlist that excludes authorization-like custom "
             "attributes, including plan; review self-signup and IdP mappings, reassert existing claims from a "
             "trusted administrator, and authorize on server-controlled data.",
             pages=[AWS + "aws-privilege-escalation/aws-cognito-user-pools-privesc/README.md",
                    AWS + "aws-unauthenticated-enum-access/aws-cognito-user-pool-unauthenticated-access/README.md"])
def writable_privilege_attributes(item, index):
    clients = item.get("Clients")
    if not isinstance(clients, dict) or not isinstance(clients.get("items"), list):
        raise Unavailable("missing or malformed client inventory")
    state = clients.get("collection_status")
    if state == "empty" and not clients["items"]:
        return "NOT_APPLICABLE", {"reason": "complete client inventory is empty", "clients_evaluated": 0}
    pool_detail = get(item, "Configuration", dict)
    if get(pool_detail, "collection_status", str) != "collected":
        raise Unavailable("incomplete user-pool detail")
    pool = get(pool_detail, "UserPool", dict)
    pool_id = get(pool, "Id", str)
    schema = list_of_objects(get(pool, "SchemaAttributes", list))
    risky_schema = {}
    schema_incomplete = not schema
    for row in schema:
        try:
            name = get(row, "Name", str)
            if not name.startswith("custom:") or not PRIVILEGE_ATTRIBUTE.search(name[7:]):
                continue
            if name in risky_schema:
                schema_incomplete = True
                continue
            risky_schema[name] = get(row, "Mutable", bool)
        except Unavailable:
            schema_incomplete = True
    incomplete = schema_incomplete or state != "collected" or not clients["items"]
    exposed = []
    evaluated = 0
    for client in clients["items"]:
        try:
            client_id = get(client, "ClientId", str)
            detail = get(client, "Configuration", dict)
            if get(detail, "collection_status", str) != "collected":
                raise Unavailable("incomplete app-client detail")
            configuration = get(detail, "UserPoolClient", dict)
            if (get(configuration, "ClientId", str) != client_id or
                    get(configuration, "UserPoolId", str) != pool_id):
                raise Unavailable("client detail identity mismatch")
            # Cognito's broad default omits WriteAttributes from DescribeUserPoolClient.
            # A field marked unavailable in coverage is never treated as that default.
            writable = optional(configuration, "WriteAttributes", None, list)
            if writable is not None and any(not isinstance(name, str) for name in writable):
                raise Unavailable("malformed WriteAttributes")
            if writable == []:
                # The API may omit a default broad write set after an empty
                # update request. No primary source proves [] is no-write.
                raise Unavailable("empty WriteAttributes has unverified semantics")
        except Unavailable:
            incomplete = True
            continue
        evaluated += 1
        candidates = set(risky_schema) if writable is None else {
            name for name in writable if name.startswith("custom:") and PRIVILEGE_ATTRIBUTE.search(name[7:])}
        risky = []
        for name in sorted(candidates):
            mutable = risky_schema.get(name)
            if mutable is True:
                risky.append(name)
            elif mutable is False:
                # Immutable values can still be set at self-service SignUp.
                try:
                    admin_only = get(pool, "AdminCreateUserConfig.AllowAdminCreateUserOnly", bool)
                except Unavailable:
                    incomplete = True
                    continue
                if admin_only is False:
                    risky.append(name)
                else:
                    # Federation and existing claim provenance are not collected here.
                    incomplete = True
            else:
                incomplete = True
        if risky:
            exposed.append({"client_id": client_id, "attributes": risky,
                            "write_attributes_defaulted": writable is None})
    evidence = {"clients": exposed, "clients_evaluated": evaluated, "coverage_incomplete": incomplete,
                "semantics": "Names are authorization heuristics, not proof of application use. Omitted WriteAttributes "
                             "means broad default access; immutable custom values can be supplied at self-service signup."}
    if exposed:
        return "FAIL", evidence
    if incomplete:
        return "UNKNOWN", {**evidence, "reason": "client or schema evidence is incomplete"}
    return "PASS", evidence


def _user_pool(write):
    pool_id = "eu-west-1_abc"
    client = {"ClientId": "c1", "Configuration": {"collection_status": "collected", "UserPoolClient": {
        "UserPoolId": pool_id, "ClientId": "c1", **({"WriteAttributes": write} if write is not None else {})}}}
    return {"Id": pool_id, "Configuration": {"collection_status": "collected", "UserPool": {"Id": pool_id,
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": False}, "SchemaAttributes": [
        {"Name": "email", "Mutable": True}, {"Name": "custom:role", "Mutable": True},
        {"Name": "custom:plan", "Mutable": True}, {"Name": "custom:nickname", "Mutable": True}]}},
        "Clients": {"collection_status": "collected", "items": [client]}}


CASES["aws.htbp.cognito.client_no_writable_authorization_attributes"] = {
    "pass": _user_pool(["email", "custom:nickname"]), "fail": _user_pool(["email", "custom:role"]),
    "missing": {"Id": "eu-west-1_abc", "Configuration": {"UserPool": {"Id": "eu-west-1_abc"}}},
    "malformed": _user_pool("custom:role")}


# ---------------------------------------------------------------- EKS
@ht_register("aws.htbp.eks.access_entries_authentication", "aws", "least_privilege", "eks_cluster",
             "EKS cluster authenticates IAM principals through access entries, not only the aws-auth ConfigMap", "medium", "AC-2",
             "Switch accessConfig.authenticationMode to API (or API_AND_CONFIG_MAP while migrating), move aws-auth mappings "
             "to access entries, and remove the hidden cluster-creator system:masters binding.",
             pages=[AWS + "aws-post-exploitation/aws-eks-post-exploitation/README.md"])
def eks_authentication_mode(item, index):
    access = get(item, "Cluster.cluster.accessConfig", dict)
    mode = get(access, "authenticationMode", str)
    evidence = {"authentication_mode": mode,
                "bootstrap_cluster_creator_admin": optional(access, "bootstrapClusterCreatorAdminPermissions", None)}
    if mode == "API_AND_CONFIG_MAP":
        return "MANUAL", {**evidence, "reason": "aws-auth ConfigMap mappings are still honored; review them or finish the migration to API"}
    if mode not in ("API", "CONFIG_MAP"):
        raise Unavailable("unrecognized EKS authentication mode")
    return result(mode == "CONFIG_MAP", **evidence,
                  semantics="CONFIG_MAP mode grants the creating principal hidden system:masters access that does not appear in aws-auth")


def _eks(mode):
    return {"name": "prod", "Cluster": {"cluster": {"name": "prod", "accessConfig": {"authenticationMode": mode, "bootstrapClusterCreatorAdminPermissions": True}}}}


CASES["aws.htbp.eks.access_entries_authentication"] = {
    "pass": _eks("API"), "fail": _eks("CONFIG_MAP"), "manual": _eks("API_AND_CONFIG_MAP"),
    "unknown": _eks("FUTURE_MODE"), "missing": {"name": "prod", "Cluster": {"cluster": {"name": "prod"}}},
    "malformed": {"name": "prod", "Cluster": {"cluster": {"accessConfig": {"authenticationMode": 1}}}}}


# ---------------------------------------------------------------- ECS
@ht_register("aws.htbp.ecs.exec_session_logging_not_disabled", "aws", "hardening", "ecs_cluster",
             "ECS cluster does not disable ECS Exec session logging", "low", "AU-12",
             "Set executeCommandConfiguration.logging to OVERRIDE with a CloudWatch Logs group or S3 bucket (or DEFAULT with "
             "awslogs task logging) so ECS Exec session transcripts are retained.",
             pages=[AWS + "aws-post-exploitation/aws-ecs-post-exploitation/README.md",
                    AWS + "aws-privilege-escalation/aws-ecs-privesc/README.md"])
def ecs_exec_logging(item, index):
    clusters = list_of_objects(get(item, "Configuration.clusters", list))
    if len(clusters) != 1:
        raise Unavailable("describe_clusters did not return exactly the requested cluster")
    configuration = optional(clusters[0], "configuration", {}, dict)
    execute = optional(configuration, "executeCommandConfiguration", {}, dict)
    logging = optional(execute, "logging", "DEFAULT", str)
    if logging not in ("NONE", "DEFAULT", "OVERRIDE"):
        raise Unavailable("unrecognized ECS Exec logging mode")
    return result(logging == "NONE", exec_logging=logging,
                  semantics="Only an explicit NONE is a failure; DEFAULT depends on each task's awslogs configuration")


def _ecs_cluster(logging):
    cluster = {"clusterArn": "arn:aws:ecs:eu-west-1:111122223333:cluster/app", "clusterName": "app"}
    if logging is not None:
        cluster["configuration"] = {"executeCommandConfiguration": {"logging": logging}}
    return {"clusterArn": cluster["clusterArn"], "Configuration": {"clusters": [cluster], "failures": []}}


CASES["aws.htbp.ecs.exec_session_logging_not_disabled"] = {
    "pass": _ecs_cluster("OVERRIDE"), "fail": _ecs_cluster("NONE"), "unknown": _ecs_cluster("SOMETIMES"),
    "missing": {"clusterArn": "arn:aws:ecs:eu-west-1:111122223333:cluster/app"},
    "malformed": {"clusterArn": "x", "Configuration": {"clusters": "app"}}}

# Host paths whose bind-mount gives a container control of the container host (EC2 launch type).
SENSITIVE_HOST_PATHS = {"/", "/var/run/docker.sock", "/run/docker.sock", "/var/run/containerd/containerd.sock",
                        "/run/containerd/containerd.sock", "/var/run", "/run", "/var/lib/docker", "/var/lib/containerd",
                        "/var/lib/ecs", "/etc", "/proc", "/root", "/var/log/ecs"}


@ht_register("aws.htbp.ecs.no_sensitive_host_mounts", "aws", "hardening", "ecs_task_definition",
             "ECS task definition does not mount the container runtime socket or sensitive host paths", "high", "AC-6",
             "Remove host volumes for the Docker/containerd socket and host system paths; agents that need them (monitoring, "
             "logging) should run as vetted daemon services with read-only mounts.",
             pages=[AWS + "aws-privilege-escalation/aws-ecs-privesc/README.md",
                    AWS + "aws-post-exploitation/aws-ecs-post-exploitation/README.md"])
def ecs_host_mounts(item, index):
    definition = get(item, "Definition.taskDefinition", dict)
    containers = list_of_objects(get(definition, "containerDefinitions", list))
    sensitive = {}
    for volume in list_of_objects(optional(definition, "volumes", [], list)):
        host = optional(volume, "host", {}, dict)
        path = optional(host, "sourcePath", None)
        if path is None:
            continue
        if not isinstance(path, str):
            raise Unavailable("malformed host sourcePath")
        normalized = path.rstrip("/") or "/"
        if normalized in SENSITIVE_HOST_PATHS:
            sensitive[get(volume, "name", str)] = normalized
    mounted = []
    for container in containers:
        for mount in list_of_objects(optional(container, "mountPoints", [], list)):
            name = get(mount, "sourceVolume", str)
            if name in sensitive:
                mounted.append({"container": get(container, "name", str), "volume": name, "host_path": sensitive[name],
                                "read_only": optional(mount, "readOnly", False)})
    return result(bool(mounted), sensitive_mounts=mounted,
                  semantics="Declared host volumes mounted by a container; a writable runtime socket is equivalent to host root")


def _task(path, mounted=True):
    container = {"name": "app", "image": "app:1", **({"mountPoints": [{"sourceVolume": "v", "containerPath": "/x"}]} if mounted else {})}
    return {"taskDefinitionArn": "arn:aws:ecs:eu-west-1:111122223333:task-definition/app:1",
            "Definition": {"taskDefinition": {"containerDefinitions": [container], "volumes": [{"name": "v", "host": {"sourcePath": path}}]}}}


CASES["aws.htbp.ecs.no_sensitive_host_mounts"] = {
    "pass": _task("/data/app"), "fail": _task("/var/run/docker.sock"),
    "missing": {"taskDefinitionArn": "arn:aws:ecs:eu-west-1:111122223333:task-definition/app:1"},
    "malformed": {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app"}], "volumes": [{"name": "v", "host": {"sourcePath": 7}}]}}}}


# ---------------------------------------------------------------- SageMaker
@ht_register("aws.htbp.sagemaker.notebook_imdsv2_required", "aws", "hardening", "sagemaker_notebook_instance",
             "SageMaker notebook instance requires IMDSv2", "medium", "SC-7",
             "Set InstanceMetadataServiceConfiguration.MinimumInstanceMetadataServiceVersion to 2 so SSRF or code in the "
             "notebook cannot read the execution-role credentials with tokenless IMDSv1 requests.",
             pages=[AWS + "aws-persistence/aws-sagemaker-persistence/README.md"])
def notebook_imds(item, index):
    version = get(item, "InstanceMetadataServiceConfiguration.MinimumInstanceMetadataServiceVersion", str)
    if version not in ("1", "2"):
        raise Unavailable("unrecognized IMDS version")
    return result(version == "1", minimum_imds_version=version)


CASES["aws.htbp.sagemaker.notebook_imdsv2_required"] = {
    "pass": {"NotebookInstanceName": "nb", "InstanceMetadataServiceConfiguration": {"MinimumInstanceMetadataServiceVersion": "2"}},
    "fail": {"NotebookInstanceName": "nb", "InstanceMetadataServiceConfiguration": {"MinimumInstanceMetadataServiceVersion": "1"}},
    "unknown": {"NotebookInstanceName": "nb", "InstanceMetadataServiceConfiguration": {"MinimumInstanceMetadataServiceVersion": "3"}},
    "missing": {"NotebookInstanceName": "nb"},
    "malformed": {"NotebookInstanceName": "nb", "InstanceMetadataServiceConfiguration": {"MinimumInstanceMetadataServiceVersion": 1}}}


# ---------------------------------------------------------------- Glue
@ht_register("aws.htbp.glue.dev_endpoint_not_public", "aws", "exposure", "glue_dev_endpoint",
             "Glue development endpoint has no public SSH address", "high", "SC-7",
             "Delete legacy Glue development endpoints or recreate them inside a VPC subnet with a restrictive security "
             "group; anyone with glue:UpdateDevEndpoint can install an SSH key and run code as the endpoint role.",
             pages=[AWS + "aws-privilege-escalation/aws-glue-privesc/README.md"])
def glue_dev_endpoint(item, index):
    get(item, "EndpointName", str)
    public = optional(item, "PublicAddress", None)
    private = optional(item, "PrivateAddress", None)
    if public is not None and not isinstance(public, str) or private is not None and not isinstance(private, str):
        raise Unavailable("malformed endpoint address")
    if not public and not private:
        raise Unavailable("endpoint address not collected (endpoint may still be provisioning)")
    return result(bool(public), public_address=public or None, private_address=private or None, vpc_id=item.get("VpcId"),
                  role_arn=item.get("RoleArn"))


CASES["aws.htbp.glue.dev_endpoint_not_public"] = {
    "pass": {"EndpointName": "dev", "PrivateAddress": "10.0.1.5", "VpcId": "vpc-1"},
    "fail": {"EndpointName": "dev", "PublicAddress": "ec2-203-0-113-5.compute.amazonaws.com"},
    "missing": {"EndpointName": "dev", "Status": "PROVISIONING"},
    "malformed": {"EndpointName": "dev", "PublicAddress": ["x"]}}


# ---------------------------------------------------------------- AppSync
@ht_register("aws.htbp.appsync.no_api_key_additional_auth", "aws", "least_privilege", "appsync_graphql_api",
             "AppSync GraphQL API does not accept API keys as an additional authorization mode", "medium", "IA-2",
             "Remove API_KEY from additionalAuthenticationProviders (aws.c2b.appsync.graphql_no_api_key covers the default "
             "mode) and use IAM, Cognito, OIDC or Lambda authorization.",
             pages=[AWS + "aws-persistence/aws-appsync-persistence/README.md",
                    AWS + "aws-post-exploitation/aws-appsync-post-exploitation/README.md"])
def appsync_additional_api_key(item, index):
    get(item, "apiId", str)
    api_type = optional(item, "apiType", "GRAPHQL", str)
    if api_type != "GRAPHQL":
        return "NOT_APPLICABLE", {"api_type": api_type}
    get(item, "authenticationType", str)
    providers = list_of_objects(optional(item, "additionalAuthenticationProviders", [], list))
    types = [get(provider, "authenticationType", str) for provider in providers]
    return result("API_KEY" in types, additional_authentication_types=types,
                  semantics="Field-level @aws_api_key directives decide which fields an API key can reach")


_GQL = {"apiId": "g1", "name": "gql", "authenticationType": "AMAZON_COGNITO_USER_POOLS"}
CASES["aws.htbp.appsync.no_api_key_additional_auth"] = {
    "pass": {**_GQL, "additionalAuthenticationProviders": [{"authenticationType": "AWS_IAM"}]},
    "fail": {**_GQL, "additionalAuthenticationProviders": [{"authenticationType": "API_KEY"}]},
    "missing": {"apiId": "g1"}, "malformed": {**_GQL, "additionalAuthenticationProviders": "API_KEY"}}
