"""AWS-B config metadata plugin; all I/O uses the main shared read scheduler.

No resource creation, secret-value API, function code, document content, object
contents or server-side execution is requested. Response configuration literals
that can carry credentials are discarded before any snapshot construction.
"""
from __future__ import annotations
import copy
import json

SPECS = {
    "rest_api_stage": ("apigateway", "get_stages", "item"),
    "http_api_stage": ("apigatewayv2", "get_stages", "Items"),
    "ecr_registry_scanning_configuration": ("ecr", "get_registry_scanning_configuration", None),
    "rds_event_subscription": ("rds", "describe_event_subscriptions", "EventSubscriptionsList"),
    "rds_proxy": ("rds", "describe_db_proxies", "DBProxies"),
    "rds_cluster_snapshot": ("rds", "describe_db_cluster_snapshots", "DBClusterSnapshots"),
    "rds_certificate": ("rds", "describe_certificates", "Certificates"),
    "acm_certificate": ("acm", "list_certificates", "CertificateSummaryList"),
    "cloudfront_distribution": ("cloudfront", "list_distributions", "DistributionList.Items || `[]`"),
    "ecs_cluster": ("ecs", "list_clusters", "clusterArns"),
    "ecs_task_definition": ("ecs", "list_task_definitions", "taskDefinitionArns"),
    "elasticache_cluster": ("elasticache", "describe_cache_clusters", "CacheClusters"),
    "elasticache_replication_group": ("elasticache", "describe_replication_groups", "ReplicationGroups"),
    "memorydb_cluster": ("memorydb", "describe_clusters", "Clusters"),
    "dms_replication_instance": ("dms", "describe_replication_instances", "ReplicationInstances"),
    "redshift_cluster": ("redshift", "describe_clusters", "Clusters"),
    "redshift_snapshot": ("redshift", "describe_cluster_snapshots", "Snapshots"),
    "neptune_cluster": ("neptune", "describe_db_clusters", "DBClusters"),
    "docdb_cluster": ("docdb", "describe_db_clusters", "DBClusters"),
    "docdb_instance": ("docdb", "describe_db_instances", "DBInstances"),
    "backup_plan": ("backup", "list_backup_plans", "BackupPlansList"),
    "backup_report_plan": ("backup", "list_report_plans", "ReportPlans"),
    "inspector_organization_configuration": ("inspector2", "describe_organization_configuration", None),
    "backup_vault": ("backup", "list_backup_vaults", "BackupVaultList"),
    "backup_protected_resource": ("backup", "list_protected_resources", "Results"),
    "backup_region_settings": ("backup", "describe_region_settings", None),
    "efs_file_system": ("efs", "describe_file_systems", "FileSystems"),
    "fsx_file_system": ("fsx", "describe_file_systems", "FileSystems"),
    "cognito_user_pool": ("cognito-idp", "list_user_pools", "UserPools"),
    "cognito_identity_pool": ("cognito-identity", "list_identity_pools", "IdentityPools"),
    "route53_zone": ("route53", "list_hosted_zones", "HostedZones"),
    "route53_health_check": ("route53", "list_health_checks", "HealthChecks"),
    "codebuild_project": ("codebuild", "list_projects", "projects"),
    "codepipeline_pipeline": ("codepipeline", "list_pipelines", "pipelines"),
    "glue_job": ("glue", "get_jobs", "Jobs"),
    "glue_security_configuration": ("glue", "get_security_configurations", "SecurityConfigurations"),
    "mq_broker": ("mq", "list_brokers", "BrokerSummaries"),
    "ssm_document_metadata": ("ssm", "list_documents", "DocumentIdentifiers"),
    "ssm_managed_instance": ("ssm", "describe_instance_information", "InstanceInformationList"),
    "ssm_parameter_metadata": ("ssm", "describe_parameters", "Parameters"),
    "ssm_service_settings": ("ssm", "get_service_setting", None),
}
NATIVE_IDS = {
    "rest_api_stage": "id", "http_api_stage": "id",
    "ecr_registry_scanning_configuration": "registryId",
    "rds_event_subscription": "EventSubscriptionArn", "rds_proxy": "DBProxyArn", "rds_cluster_snapshot": "DBClusterSnapshotArn", "rds_certificate": "CertificateIdentifier",
    "acm_certificate": "CertificateArn", "cloudfront_distribution": "ARN", "ecs_cluster": "clusterArn", "ecs_task_definition": "taskDefinitionArn",
    "elasticache_cluster": "ARN", "elasticache_replication_group": "ARN", "memorydb_cluster": "ARN", "dms_replication_instance": "ReplicationInstanceArn",
    "redshift_cluster": "ClusterIdentifier", "redshift_snapshot": "SnapshotIdentifier", "neptune_cluster": "DBClusterArn", "docdb_cluster": "DBClusterArn", "docdb_instance": "DBInstanceArn",
    "backup_plan": "BackupPlanArn", "backup_report_plan": "ReportPlanArn", "inspector_organization_configuration": "id", "backup_vault": "BackupVaultArn", "backup_protected_resource": "ResourceArn", "backup_region_settings": "id",
    "efs_file_system": "FileSystemArn", "fsx_file_system": "ResourceARN", "cognito_user_pool": "Id", "cognito_identity_pool": "IdentityPoolId",
    "route53_zone": "Id", "route53_health_check": "Id", "codebuild_project": "name", "codepipeline_pipeline": "name", "glue_job": "Name",
    "glue_security_configuration": "Name", "mq_broker": "BrokerArn", "ssm_document_metadata": "Name", "ssm_managed_instance": "InstanceId", "ssm_parameter_metadata": "Name", "ssm_service_settings": "id",
}
GLOBAL_TYPES = {"cloudfront_distribution", "route53_zone", "route53_health_check"}
READ_ACTIONS = {(service, operation) for service, operation, expression in SPECS.values()}
READ_ACTIONS.update({
    ("ecr", "describe_repositories"), ("acm", "describe_certificate"), ("cloudfront", "get_distribution_config"),
    ("ecs", "describe_clusters"), ("ecs", "describe_task_definition"), ("ecs", "list_services"), ("ecs", "describe_services"),
    ("backup", "get_backup_plan"), ("backup", "list_backup_selections"), ("backup", "get_backup_selection"), ("backup", "describe_backup_vault"), ("backup", "get_backup_vault_access_policy"),
    ("lambda", "get_function_concurrency"), ("lambda", "get_function_configuration"),
    ("dynamodb", "describe_continuous_backups"), ("dynamodb", "describe_table_replica_auto_scaling"),
    ("elasticache", "describe_cache_parameters"), ("elasticache", "describe_users"),
    ("rds", "describe_db_parameters"), ("rds", "describe_db_cluster_parameters"), ("rds", "describe_option_groups"),
    ("redshift", "describe_logging_status"), ("redshift", "describe_cluster_parameters"),
    ("cognito-idp", "describe_user_pool"), ("cognito-idp", "list_user_pool_clients"), ("cognito-idp", "describe_user_pool_client"),
    ("cognito-identity", "describe_identity_pool"), ("route53", "get_query_logging_config"), ("route53", "list_query_logging_configs"),
    ("codebuild", "batch_get_projects"), ("mq", "describe_broker"),
    ("efs", "describe_backup_policy"), ("efs", "describe_file_system_policy"),
    ("ssm", "describe_document_permission"), ("ssm", "get_service_setting"),
    ("apigateway", "get_stages"), ("apigatewayv2", "get_stages"),
})

# These are configuration literals capable of carrying secrets/code. Resource
# policy declarations, password POLICY requirements and names remain metadata.
_OMIT = {"environmentvariables", "variables", "command", "entrypoint", "userdata", "code", "clientsecret", "secretstring", "secretbinary", "password", "masteruserpassword",
    "authparameters", "connectionstring", "authorizationtoken", "parameters", "defaultarguments", "nonoverridablearguments", "protectedsettings", "customheaders", "auth", "repositorycredentials", "secrets", "secretoptions"}


def _metadata(value):
    if isinstance(value, list):
        return [_metadata(item) for item in value]
    if not isinstance(value, dict):
        return value
    output = {}
    for key, item in value.items():
        if key.lower() in _OMIT or (key.lower() == "environment" and not isinstance(item, dict)):
            continue
        output[key] = _metadata(item)
    return output


def _read_list(requests, session, region, service, operation, expression, **arguments):
    read = requests.pages(session, service, region, operation, expression, **arguments)
    result = {"collection_status": read.status, "items": _metadata(read.items)}
    if read.error:
        result["error"] = read.error
    return result


def _detail(requests, session, region, service, operation, **arguments):
    return _metadata(requests.detail(session, service, region, operation, **arguments))


def _single(requests, session, region, service, operation, **arguments):
    from .aws import _single as single
    read = single(requests, session, region, service, operation, **arguments)
    read.items = _metadata(read.items)
    return read


def _single_settings(requests, session, region, account):
    return _single(requests, session, region, "ssm", "get_service_setting", SettingId=f"arn:aws:ssm:{region}:{account}:servicesetting/ssm/documents/console/public-sharing-permission")


def _cognito_pools(service, operation, expression, size):
    def fetch(requests, session, region, account):
        return requests.pages(session, service, region, operation, expression, MaxResults=size)
    return fetch


def _self_documents(requests, session, region, account):
    return requests.pages(session, "ssm", region, "list_documents", "DocumentIdentifiers", Filters=[{"Key": "Owner", "Values": ["Self"]}])


def _api_stages(service, parent_op, parent_expr, parent_key, child_expr, argument):
    def fetch(requests, session, region, account):
        from .aws import ReadResult
        parents = requests.pages(session, service, region, parent_op, parent_expr)
        if parents.status not in ("collected", "empty"):
            return ReadResult([], parents.status, parents.error)
        items, failures = [], []
        for parent in parents.items:
            api_id = parent.get(parent_key)
            if not isinstance(api_id, str):
                return ReadResult(items, "partial" if items else "malformed", {"code": "malformed_parent_api"})
            children = requests.pages(session, service, region, "get_stages", child_expr, **{argument: api_id})
            if children.status not in ("collected", "empty"):
                failures.append(children)
            for child in children.items:
                name = child.get("stageName") if service == "apigateway" else child.get("StageName")
                if not isinstance(name, str):
                    return ReadResult(items, "partial" if items else "malformed", {"code": "malformed_stage"})
                row = _metadata(child)
                row["ParentApiId"] = api_id
                row["id"] = f"arn:aws:apigateway:{region}::/apis/{api_id}/stages/{name}"
                row["_provenance"] = {"source_operation": "get_stages", "parent_api_id": api_id, "read_only": True}
                items.append(row)
        if failures:
            return ReadResult(items, "partial" if items else failures[0].status, failures[0].error)
        return ReadResult(items, "collected" if items else "empty")
    return fetch


FETCHERS = {
    "rest_api_stage": _api_stages("apigateway", "get_rest_apis", "items", "id", "item", "restApiId"),
    "http_api_stage": _api_stages("apigatewayv2", "get_apis", "Items", "ApiId", "Items", "ApiId"),
    "ssm_service_settings": _single_settings, "ssm_document_metadata": _self_documents,
    "cognito_user_pool": _cognito_pools("cognito-idp", "list_user_pools", "UserPools", 60),
    "cognito_identity_pool": _cognito_pools("cognito-identity", "list_identity_pools", "IdentityPools", 60)}


def _enricher(kind):
    def enrich(requests, session, region, items):
        output = []
        for item in items:
            item = copy.deepcopy(item)
            if kind == "acm_certificate":
                item["Certificate"] = _detail(requests, session, region, "acm", "describe_certificate", CertificateArn=item["CertificateArn"])
            elif kind == "cloudfront_distribution":
                item["Config"] = _detail(requests, session, region, "cloudfront", "get_distribution_config", Id=item["Id"])
            elif kind == "ecs_cluster":
                item["Configuration"] = _detail(requests, session, region, "ecs", "describe_clusters", clusters=[item["clusterArn"]], include=["SETTINGS", "CONFIGURATIONS"])
                item["Services"] = _read_list(requests, session, region, "ecs", "list_services", "serviceArns", cluster=item["clusterArn"])
            elif kind == "ecs_task_definition":
                item["Definition"] = _detail(requests, session, region, "ecs", "describe_task_definition", taskDefinition=item["taskDefinitionArn"])
            elif kind == "dynamodb_table":
                item["ContinuousBackups"] = _detail(requests, session, region, "dynamodb", "describe_continuous_backups", TableName=item["TableName"])
            elif kind == "lambda_function":
                name = item["FunctionName"]
                item["Concurrency"] = _detail(requests, session, region, "lambda", "get_function_concurrency", FunctionName=name)
                item["Configuration"] = _detail(requests, session, region, "lambda", "get_function_configuration", FunctionName=name)
            elif kind == "backup_plan":
                item["Plan"] = _detail(requests, session, region, "backup", "get_backup_plan", BackupPlanId=item["BackupPlanId"])
                item["Selections"] = _read_list(requests, session, region, "backup", "list_backup_selections", "BackupSelectionsList", BackupPlanId=item["BackupPlanId"])
                if item["Selections"]["collection_status"] in ("collected", "empty"):
                    for selection in item["Selections"]["items"]:
                        selection["Selection"] = _detail(requests, session, region, "backup", "get_backup_selection", BackupPlanId=item["BackupPlanId"], SelectionId=selection["SelectionId"])
            elif kind == "backup_vault":
                name = item["BackupVaultName"]
                item["Configuration"] = _detail(requests, session, region, "backup", "describe_backup_vault", BackupVaultName=name)
                item["Policy"] = _detail(requests, session, region, "backup", "get_backup_vault_access_policy", BackupVaultName=name)
            elif kind == "cognito_user_pool":
                item["Configuration"] = _detail(requests, session, region, "cognito-idp", "describe_user_pool", UserPoolId=item["Id"])
                item["Clients"] = _read_list(requests, session, region, "cognito-idp", "list_user_pool_clients", "UserPoolClients", UserPoolId=item["Id"], MaxResults=60)
                if item["Clients"]["collection_status"] in ("collected", "empty"):
                    for client in item["Clients"]["items"]:
                        client["Configuration"] = _detail(requests, session, region, "cognito-idp", "describe_user_pool_client", UserPoolId=item["Id"], ClientId=client["ClientId"])
            elif kind == "cognito_identity_pool":
                item["Configuration"] = _detail(requests, session, region, "cognito-identity", "describe_identity_pool", IdentityPoolId=item["IdentityPoolId"])
            elif kind == "codebuild_project":
                item["Configuration"] = _detail(requests, session, region, "codebuild", "batch_get_projects", names=[item["name"]])
            elif kind == "mq_broker":
                item["Configuration"] = _detail(requests, session, region, "mq", "describe_broker", BrokerId=item["BrokerId"])
            elif kind == "efs_file_system":
                item["BackupPolicy"] = _detail(requests, session, region, "efs", "describe_backup_policy", FileSystemId=item["FileSystemId"])
                item["Policy"] = _detail(requests, session, region, "efs", "describe_file_system_policy", FileSystemId=item["FileSystemId"])
            elif kind == "ssm_document_metadata":
                item["Permissions"] = _detail(requests, session, region, "ssm", "describe_document_permission", Name=item["Name"], PermissionType="Share")
            elif kind == "rest_api":
                item["Stages"] = _read_list(requests, session, region, "apigateway", "get_stages", "item", restApiId=item["id"])
            elif kind == "http_api":
                item["Stages"] = _read_list(requests, session, region, "apigatewayv2", "get_stages", "Items", ApiId=item["ApiId"])
            output.append(_metadata(item))
        return output
    return enrich


def _ecr_repository_metadata(requests, session, region, items):
    output = []
    for original in items:
        item = copy.deepcopy(original)
        coverage = item.setdefault("_coverage", {})
        if not isinstance(coverage, dict):
            raise ValueError("malformed resource detail coverage")
        source_operation = "describe_repositories/list"
        if "imageTagMutability" not in item:
            name = item.get("repositoryName")
            if not isinstance(name, str) or not name:
                coverage["imageTagMutability"] = {"status": "malformed", "reason": "repository_name_missing"}
                output.append(_metadata(item))
                continue
            details = _detail(requests, session, region, "ecr", "describe_repositories", repositoryNames=[name])
            if details.get("collection_status") not in (None, "collected", "empty"):
                for field in ("imageTagMutability", "imageTagMutabilityExclusionFilters"):
                    coverage[field] = {"status": details["collection_status"], "error": details.get("error", {})}
                output.append(_metadata(item))
                continue
            repositories = details.get("repositories")
            matches = [row for row in repositories if isinstance(row, dict) and row.get("repositoryName") == name] if isinstance(repositories, list) else []
            if len(matches) != 1:
                coverage["imageTagMutability"] = {"status": "malformed", "reason": "repository_configuration_not_unique"}
                output.append(_metadata(item))
                continue
            for field in ("imageTagMutability", "imageTagMutabilityExclusionFilters"):
                if field in matches[0]:
                    item[field] = copy.deepcopy(matches[0][field])
            source_operation = "describe_repositories/detail"
        mode = item.get("imageTagMutability")
        coverage["imageTagMutability"] = {"status": "collected" if isinstance(mode, str) else "malformed", "source_operation": source_operation}
        filters = item.get("imageTagMutabilityExclusionFilters")
        if filters is None and mode in ("MUTABLE", "IMMUTABLE"):
            coverage["imageTagMutabilityExclusionFilters"] = {"status": "empty", "reason": "mode_has_no_exclusion_filters", "source_operation": source_operation}
        elif isinstance(filters, list) and all(isinstance(row, dict) and isinstance(row.get("filterType"), str) and isinstance(row.get("filter"), str) for row in filters):
            coverage["imageTagMutabilityExclusionFilters"] = {"status": "collected" if filters else "empty", "source_operation": source_operation}
        else:
            coverage["imageTagMutabilityExclusionFilters"] = {"status": "unknown" if filters is None else "malformed", "reason": "exclusion_mode_requires_observed_filters"}
        output.append(_metadata(item))
    return output


ENRICHERS = {kind: _enricher(kind) for kind in ["acm_certificate", "cloudfront_distribution", "ecs_cluster", "ecs_task_definition", "lambda_function", "dynamodb_table", "backup_plan", "backup_vault", "cognito_user_pool", "cognito_identity_pool", "codebuild_project", "mq_broker", "efs_file_system", "ssm_document_metadata", "rest_api", "http_api"]}

ENRICHERS["ecr_repository"] = _ecr_repository_metadata
