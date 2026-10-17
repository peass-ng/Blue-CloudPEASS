"""Container/build/cache/identity configuration checks using native SDK envelopes."""
from . import result, unknown
from .facts import get, list_of_objects, optional, Unavailable
from .aws_b_core import install, scalar, SOURCES


def task(item):
    definition = get(item, "Definition.taskDefinition", dict)
    containers = list_of_objects(get(definition, "containerDefinitions", list))
    if not containers:
        raise ValueError("task definition has no container specifications")
    for row in containers:
        get(row, "name", str)
    return definition, containers


@install("aws.b.ecs.no_privileged_containers", "ecs_task_definition", "ECS task definition has no privileged containers", {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app", "privileged": False}]}}}, {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app", "privileged": True}]}}}, query="ecs_task_definition_container_non_privileged")
def privileges(item, index):
    _, rows = task(item)
    privileged = []
    for row in rows:
        value = optional(row, "privileged", False)
        if type(value) is not bool:
            return unknown("malformed privileged flag")
        if value:
            privileged.append(row["name"])
    return result(bool(privileged), privileged_containers=privileged)


@install("aws.b.ecs.some_logging_configuration", "ecs_task_definition", "ECS task definition declares at least one container log configuration", {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app", "logConfiguration": {"logDriver": "awslogs"}}]}}}, {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app"}]}}}, query="ecs_task_definition_logging_enabled")
def logging(item, index):
    _, rows = task(item)
    configured = []
    for row in rows:
        log = optional(row, "logConfiguration", None)
        if log is not None and not isinstance(log, dict):
            return unknown("malformed log configuration")
        if log is not None:
            configured.append(row["name"])
    return result(not configured, containers_with_log_configuration=configured, semantics="Exact source existential predicate; unlogged sibling containers are not silently claimed covered.")


@install("aws.b.ecs.no_host_pid", "ecs_task_definition", "ECS task definition avoids host PID namespace", {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app"}], "pidMode": "task"}}}, {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app"}], "pidMode": "host"}}}, query="ecs_task_definition_no_host_pid_mode")
def host_pid(item, index):
    definition, _ = task(item)
    pid = optional(definition, "pidMode", None)
    if pid not in (None, "host", "task"):
        return unknown("unknown PID mode")
    return result(pid == "host", pid_mode=pid or "container_default")


@install("aws.b.ecs.all_readonly_roots", "ecs_task_definition", "Every ECS container declares a read-only root filesystem", {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app", "readonlyRootFilesystem": True}]}}}, {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app", "readonlyRootFilesystem": True}, {"name": "sidecar", "readonlyRootFilesystem": False}]}}}, query="_corrected:ecs_task_definition_container_readonly_root_filesystem")
def readonly_roots(item, index):
    _, rows = task(item)
    writable = []
    for row in rows:
        value = optional(row, "readonlyRootFilesystem", False)
        if type(value) is not bool:
            return unknown("malformed filesystem flag")
        if not value:
            writable.append(row["name"])
    return result(bool(writable), writable_root_containers=writable, semantics="Corrected universal control; pinned SQL only requires one matching container and is not equivalent.")


for _field, _suffix, _query in [("AtRestEncryptionEnabled", "at_rest", "elasticache_replication_group_encryption_at_rest_enabled"), ("TransitEncryptionEnabled", "in_transit", "elasticache_replication_group_encryption_in_transit_enabled")]:
    scalar("aws.b.elasticache." + _suffix, "elasticache_replication_group", _field, True, False, "ElastiCache replication group enables " + _suffix.replace("_", " ") + " encryption", _query)
scalar("aws.b.elasticache.automatic_minor_upgrade", "elasticache_cluster", "AutoMinorVersionUpgrade", True, False, "ElastiCache cluster enables automatic minor version upgrades", "elasticache_cluster_auto_minor_version_upgrade_enabled")
scalar("aws.b.elasticache.automatic_failover", "elasticache_replication_group", "AutomaticFailover", "enabled", "disabled", "ElastiCache replication group enables automatic failover", "elasticache_replication_group_auto_failover_enabled", allowed={"enabled", "disabled", "enabling", "disabling"})
scalar("aws.b.cognito.no_guest_identities", "cognito_identity_pool", "Configuration.AllowUnauthenticatedIdentities", False, True, "Cognito identity pool restricts unauthenticated identities", "cognito_identity_pools_restrict_unauthenticated_identities")


_COGNITO_GOOD = {"Configuration": {"UserPool": {"Policies": {"PasswordPolicy": {"MinimumLength": 8, "RequireLowercase": True, "RequireUppercase": True, "RequireNumbers": True, "RequireSymbols": True, "TemporaryPasswordValidityDays": 7}}}}}
_COGNITO_BAD = {"Configuration": {"UserPool": {"Policies": {"PasswordPolicy": {"MinimumLength": 8, "RequireLowercase": True, "RequireUppercase": True, "RequireNumbers": True, "RequireSymbols": True, "TemporaryPasswordValidityDays": 8}}}}}
@install("aws.b.cognito.password_policy", "cognito_user_pool", "Cognito user pool meets the pinned compound password policy", _COGNITO_GOOD, _COGNITO_BAD, query="cognito_user_pool_password_policy_with_strong_configuration")
def passwords(item, index):
    policy = get(item, "Configuration.UserPool.Policies.PasswordPolicy", dict)
    length = get(policy, "MinimumLength", int)
    temporary = policy.get("TemporaryPasswordValidityDays", 0)
    if type(temporary) is not int or temporary < 0 or length < 0:
        return unknown("malformed password length/validity")
    flags = {}
    for key in ("RequireLowercase", "RequireUppercase", "RequireNumbers", "RequireSymbols"):
        value = policy.get(key, False)
        if type(value) is not bool:
            return unknown("malformed password requirement", field=key)
        flags[key] = value
    return result(length < 8 or temporary > 7 or not all(flags.values()), minimum_length=length, temporary_password_validity_days=temporary, requirements=flags, semantics="Exact pinned policy/defaults; passkeys and passwordless workload requirements are outside this legacy-password condition.")


def project(item):
    rows = list_of_objects(get(item, "Configuration.projects", list))
    if len(rows) != 1:
        raise ValueError("project response must contain one matched configuration")
    return rows[0]


@install("aws.b.codebuild.nonprivileged", "codebuild_project", "CodeBuild project disables privileged environment mode", {"Configuration": {"projects": [{"environment": {"privilegedMode": False}}]}}, {"Configuration": {"projects": [{"environment": {"privilegedMode": True}}]}}, query="codebuild_project_environment_privileged_mode_disabled")
def build_privileged(item, index):
    value = get(project(item), "environment.privilegedMode", bool)
    return result(value, privileged_environment=value)


@install("aws.b.codebuild.logs_enabled", "codebuild_project", "CodeBuild project enables CloudWatch or S3 logs", {"Configuration": {"projects": [{"logsConfig": {"cloudWatchLogs": {"status": "ENABLED"}, "s3Logs": {"status": "DISABLED"}}}]}}, {"Configuration": {"projects": [{"logsConfig": {"cloudWatchLogs": {"status": "DISABLED"}, "s3Logs": {"status": "DISABLED"}}}]}}, query="codebuild_project_logging_enabled")
def build_logs(item, index):
    logs = get(project(item), "logsConfig", dict)
    known = []
    for key in ("cloudWatchLogs", "s3Logs"):
        block = optional(logs, key, None)
        if block is None:
            known.append("DISABLED")
            continue
        status = get(block, "status", str)
        if status not in ("ENABLED", "DISABLED"):
            return unknown("unknown log status")
        known.append(status)
    return result("ENABLED" not in known, cloudwatch_status=known[0], s3_status=known[1])


@install("aws.b.codebuild.artifact_encryption", "codebuild_project", "CodeBuild primary and secondary artifacts retain encryption", {"Configuration": {"projects": [{"artifacts": {"encryptionDisabled": False}, "secondaryArtifacts": []}]}}, {"Configuration": {"projects": [{"artifacts": {"encryptionDisabled": False}, "secondaryArtifacts": [{"encryptionDisabled": True}]}]}}, query="codebuild_project_artifact_encryption_enabled")
def artifacts(item, index):
    data = project(item)
    observed = _observed_project(item, data)
    artifact = get(data, "artifacts", dict)
    primary = _artifact_setting(artifact, observed, None)
    secondary = list_of_objects(data.get("secondaryArtifacts", []))
    values = [_artifact_setting(artifact, observed, None) for artifact in secondary]
    return result(primary is not False or any(value is True for value in values),
                  primary_encryption_disabled=primary, secondary_encryption_disabled=values,
                  semantics="Literal pinned source: primary must explicitly declare false; only explicitly true secondary flags alarm. This includes non-S3 artifact types; S3-only defensive applicability is a separate check.")


def _observed_project(item, data):
    configuration = get(item, "Configuration", dict)
    if configuration.get("collection_status") != "collected":
        return False
    try:
        return bool(get(data, "name", str))
    except Unavailable:
        return False


def _artifact_setting(artifact, observed, default):
    if observed:
        value = optional(artifact, "encryptionDisabled", default)
        if value is not None and type(value) is not bool:
            raise ValueError("malformed artifact encryption setting")
        return value
    return get(artifact, "encryptionDisabled", bool)


@install("aws.b.codebuild.s3_artifact_encryption", "codebuild_project", "CodeBuild S3 artifacts retain default or explicit encryption",
         {"Configuration": {"projects": [{"artifacts": {"type": "S3", "encryptionDisabled": False}}]}},
         {"Configuration": {"projects": [{"artifacts": {"type": "NO_ARTIFACTS"}, "secondaryArtifacts": [{"type": "S3", "encryptionDisabled": True}]}]}},
         query="_corrected:codebuild_project_artifact_encryption_enabled",
         extra={"not_applicable": {"Configuration": {"projects": [{"artifacts": {"type": "NO_ARTIFACTS"}}]}}})
def s3_artifacts(item, index):
    data = project(item)
    observed = _observed_project(item, data)
    artifacts = [get(data, "artifacts", dict)] + list_of_objects(data.get("secondaryArtifacts", []))
    settings, types = [], []
    for position, artifact in enumerate(artifacts):
        kind = get(artifact, "type", str)
        if kind not in {"NO_ARTIFACTS", "S3", "CODEPIPELINE"} or (position and kind == "CODEPIPELINE"):
            return unknown("unknown or invalid native artifact type", artifact_type=kind)
        types.append(kind)
        if kind == "S3":
            settings.append(_artifact_setting(artifact, observed, False))
    if not settings:
        return "NOT_APPLICABLE", {"artifact_types": types, "reason": "No S3 artifacts are configured; CodePipeline encryption is assessed by its owning artifact store.",
            "official_reference": "https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectArtifacts.html"}
    return result(any(settings), s3_encryption_disabled=settings, artifact_types=types,
                  official_reference="https://docs.aws.amazon.com/codebuild/latest/userguide/security-encryption.html",
                  semantics="Separate defensive S3-only variant. Known successful detail omission retains AWS default encryption; no artifact contents are read.")


@install("aws.b.codebuild.s3_log_encryption", "codebuild_project", "CodeBuild S3 log configuration retains encryption", {"Configuration": {"projects": [{"logsConfig": {"s3Logs": {"encryptionDisabled": False}}}]}}, {"Configuration": {"projects": [{"logsConfig": {"s3Logs": {"encryptionDisabled": True}}}]}}, query="codebuild_project_s3_logs_encryption_enabled")
def build_s3(item, index):
    disabled = get(project(item), "logsConfig.s3Logs.encryptionDisabled", bool)
    return result(disabled, s3_log_encryption_disabled=disabled)


@install("aws.b.ecs.declared_nonroot_users", "ecs_task_definition", "ECS containers explicitly declare non-root users", {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app", "user": "1000:1000"}]}}}, {"Definition": {"taskDefinition": {"containerDefinitions": [{"name": "app", "user": "0:1000"}]}}}, query="_corrected:ecs_task_definition_no_root_user")
def nonroot_users(item, index):
    _, rows = task(item)
    root, inherited = [], []
    for row in rows:
        user = optional(row, "user", None)
        if user is None or user == "":
            inherited.append(row["name"])
            continue
        if not isinstance(user, str):
            return unknown("malformed user declaration")
        if user.count(":") > 1:
            return unknown("malformed user declaration")
        identity = user.split(":", 1)[0]
        if not identity:
            return unknown("user declaration does not identify a user")
        if identity == "root" or identity.isascii() and identity.isdecimal() and int(identity) == 0:
            root.append(row["name"])
    if root:
        return result(True, root_user_containers=root, inherited_image_users=inherited)
    if inherited:
        return unknown("user inherited from uninspected image metadata", containers=inherited)
    return result(False, explicitly_nonroot_containers=[row["name"] for row in rows], semantics="Declared user names/UIDs; image name-to-UID resolution is not independently inspected.")


@install("aws.b.ecs.host_network_nonprivileged", "ecs_task_definition", "Host-network ECS task containers avoid privilege and explicitly use non-root users", {"Definition": {"taskDefinition": {"networkMode": "host", "containerDefinitions": [{"name": "app", "privileged": False, "user": "1000"}]}}}, {"Definition": {"taskDefinition": {"networkMode": "host", "containerDefinitions": [{"name": "app", "privileged": True, "user": "1000"}]}}}, query="_corrected:ecs_task_definition_user_for_host_mode_check", extra={"not_applicable": {"Definition": {"taskDefinition": {"networkMode": "awsvpc", "containerDefinitions": [{"name": "app"}]}}}})
def host_user(item, index):
    definition, _ = task(item)
    mode = get(definition, "networkMode", str)
    if mode not in {"none", "bridge", "host", "awsvpc"}:
        return unknown("unrecognized network mode")
    if mode != "host":
        return "NOT_APPLICABLE", {"network_mode": mode}
    status, evidence = privileges(item, index)
    if status != "PASS":
        return status, {**evidence, "network_mode": mode}
    status, evidence = nonroot_users(item, index)
    return status, {**evidence, "network_mode": mode}
