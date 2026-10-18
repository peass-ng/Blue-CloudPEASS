"""AWS-B native checks with explicit SDK envelopes and frozen snapshot context.

These predicates do not load source runtimes or execute provider calls. Reviewed
source associations are maintained separately; differing thresholds/eligibility
and SQL defects remain separate rather than merged by evaluator hash.
"""
from __future__ import annotations
import re
from datetime import datetime, timezone, timedelta
from . import register, result, unknown
from .facts import get, list_of_objects, guard, optional
from .fixtures import CASES, nest

IDS = []
SOURCES = {}
DOCS = {
    "rds_instance": "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBInstance.html",
    "rds_cluster": "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBCluster.html",
    "rds_event_subscription": "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_EventSubscription.html",
    "lambda_function": "https://docs.aws.amazon.com/lambda/latest/api/API_FunctionConfiguration.html",
    "eks_cluster": "https://docs.aws.amazon.com/eks/latest/APIReference/API_Cluster.html",
    "dynamodb_table": "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DescribeContinuousBackups.html",
    "acm_certificate": "https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html",
}


def install(cid, kind, title, passing, failing, *, query=None, category="hardening", severity="medium", dependencies=None, target="resource", extra=None, empty_applicability_dependencies=()):
    def decorate(function):
        register(cid, "aws", category, kind, title, severity, "CM-6", "Review the configuration against intended workload requirements; remediate the reported setting and retain independent verification evidence.", target=target, dependencies=dependencies, empty_applicability_dependencies=empty_applicability_dependencies)(function)
        IDS.append(cid)
        CASES[cid] = {"pass": passing, "fail": failing, "missing": {}, "malformed": None, **(extra or {})}
        if query:
            SOURCES[query] = [cid]
        return function
    return decorate


def scalar(cid, kind, path, good, bad, title, query, *, allowed=None, category="hardening"):
    @install(cid, kind, title, nest(path, good), nest(path, bad), query=query, category=category)
    def evaluate(item, index):
        value = get(item, path, type(good))
        if allowed is not None and value not in allowed:
            return unknown("unrecognized API enumeration", field=path, configured=value)
        return result(value != good, field=path, configured=value, official_reference=DOCS.get(kind))


def threshold(cid, kind, path, lower, good, bad, title, query):
    @install(cid, kind, title, nest(path, good), nest(path, bad), query=query)
    def evaluate(item, index):
        value = get(item, path, int)
        if value < 0:
            return unknown("negative configuration value", field=path)
        return result(value < lower, field=path, configured=value, minimum=lower, official_reference=DOCS.get(kind))


threshold("aws.b.rds.backup_retention_seven_days", "rds_instance", "BackupRetentionPeriod", 7, 7, 6, "RDS instance retains automatic backups at least seven days", "rds_db_instance_backup_retention_period_less_than_7")
scalar("aws.b.rds.cluster_minor_upgrade", "rds_cluster", "AutoMinorVersionUpgrade", True, False, "RDS cluster enables automatic minor upgrades", "rds_db_cluster_automatic_minor_version_upgrade_enabled")
scalar("aws.b.rds.proxy_tls", "rds_proxy", "RequireTLS", True, False, "RDS proxy requires encrypted connections", "rds_db_proxy_tls_encryption_enabled")
scalar("aws.b.lambda.active_tracing", "lambda_function", "Configuration.TracingConfig.Mode", "Active", "PassThrough", "Lambda active X-Ray tracing is enabled", "lambda_function_tracing_enabled", allowed={"Active", "PassThrough"})
_EKS_VPC = "Cluster.cluster.resourcesVpcConfig"


@install("aws.b.eks.disable_public_endpoint", "eks_cluster", "EKS API endpoint public access is disabled or CIDR-restricted",
         nest(_EKS_VPC, {"endpointPublicAccess": False, "endpointPrivateAccess": True}),
         nest(_EKS_VPC, {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]}),
         query="eks_cluster_endpoint_restrict_public_access", category="exposure",
         extra={"restricted": nest(_EKS_VPC, {"endpointPublicAccess": True, "publicAccessCidrs": ["203.0.113.0/24"]}),
                "unknown": nest(_EKS_VPC, {"endpointPublicAccess": True, "publicAccessCidrs": "0.0.0.0/0"})})
def _eks_public_endpoint(item, index):
    config = get(item, _EKS_VPC, dict)
    public = get(config, "endpointPublicAccess", bool)
    if not public:
        return result(False, field=_EKS_VPC + ".endpointPublicAccess", configured=public, official_reference=DOCS.get("eks_cluster"))
    cidrs = config.get("publicAccessCidrs", ["0.0.0.0/0"])
    if not isinstance(cidrs, list) or any(not isinstance(c, str) for c in cidrs):
        return unknown("malformed publicAccessCidrs", field=_EKS_VPC + ".publicAccessCidrs")
    open_cidrs = [c for c in cidrs if c.strip() in ("0.0.0.0/0", "::/0")] or ([] if cidrs else ["0.0.0.0/0"])
    return result(bool(open_cidrs), endpoint_public_access=True, public_access_cidrs=cidrs, internet_wide_cidrs=open_cidrs,
                  semantics="Public endpoint restricted to authorized CIDRs passes; Kubernetes authentication still applies.",
                  official_reference=DOCS.get("eks_cluster"))
scalar("aws.b.dynamodb.point_in_time_recovery", "dynamodb_table", "ContinuousBackups.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus", "ENABLED", "DISABLED", "DynamoDB table has point-in-time recovery enabled", "dynamodb_table_point_in_time_recovery_enabled", allowed={"ENABLED", "DISABLED"})


for _kind in ("rds_instance", "rds_cluster"):
    def _admin(kind):
        cid = "aws.b." + kind + ".nondefault_admin"
        @install(cid, kind, "RDS master username avoids the source's default admin names", {"MasterUsername": "owner_app"}, {"MasterUsername": "postgres"}, query="rds_db_" + ("instance" if kind == "rds_instance" else "cluster") + "_no_default_admin_name", severity="low")
        def evaluate(item, index):
            name = get(item, "MasterUsername", str)
            return result(name in ("admin", "postgres"), master_username=name, blocked_source_names=["admin", "postgres"], semantics="Declared username policy, not proof of authentication strength.")
    _admin(_kind)


@install("aws.b.rds.engine_log_exports", "rds_instance", "RDS instance exports the source's engine-specific log categories", {"Engine": "postgres", "EnabledCloudwatchLogsExports": ["postgresql", "upgrade"]}, {"Engine": "postgres", "EnabledCloudwatchLogsExports": ["postgresql"]}, query="rds_db_instance_logging_enabled", extra={"not_applicable": {"Engine": "docdb"}})
def rds_engine_logs(item, index):
    engine = get(item, "Engine", str)
    if engine == "docdb":
        return "NOT_APPLICABLE", {"engine": engine, "reason": "Source explicitly excludes DocumentDB instances."}
    logs = get(item, "EnabledCloudwatchLogsExports", list)
    if any(not isinstance(name, str) for name in logs):
        return unknown("malformed exported log categories")
    if engine == "mariadb" or engine.endswith("mysql"):
        required = {"audit", "error", "general", "slowquery"}
    elif "postgres" in engine:
        required = {"postgresql", "upgrade"}
    elif engine.startswith("oracle"):
        required = {"alert", "audit", "trace", "listener"}
    elif engine == "sqlserver-ex":
        required = {"error"}
    elif engine.startswith("sqlserver"):
        required = {"error", "agent"}
    else:
        return result(True, engine=engine, exports=logs, reason="Engine has no passing branch in the pinned source predicate.")
    return result(not required.issubset(logs), engine=engine, exported_categories=logs, required_categories=sorted(required))


for _source_type, _categories in [("db-cluster", ["failure", "maintenance"]), ("db-instance", ["failure", "maintenance", "configuration change"]), ("db-parameter-group", ["configuration change"]), ("db-security-group", ["configuration change", "failure"] )]:
    def _events(source_type, categories):
        suffix = source_type.removeprefix("db-").replace("-", "_")
        cid = "aws.b.rds." + suffix + "_event_categories"
        query = "rds_db_" + suffix + "_events_subscription"
        @install(cid, "rds_event_subscription", "RDS " + source_type + " subscriptions include the required critical event categories", {"SourceType": source_type, "Enabled": True, "EventCategoriesList": categories}, {"SourceType": source_type, "Enabled": False, "EventCategoriesList": categories}, query=query,
            extra={"not_applicable": {"SourceType": "other"}})
        def evaluate(item, index):
            current = get(item, "SourceType", str)
            if current != source_type:
                return "NOT_APPLICABLE", {"source_type": current, "required_source_type": source_type}
            enabled = get(item, "Enabled", bool)
            present = get(item, "EventCategoriesList", list)
            if any(not isinstance(v, str) for v in present):
                return unknown("malformed event categories")
            return result(not enabled or not set(categories).issubset(present), source_type=current, enabled=enabled, required=categories, present=present)
    _events(_source_type, _categories)


@install("aws.b.lambda.reserved_concurrency", "lambda_function", "Lambda function has a reserved concurrency setting", {"Concurrency": {"ReservedConcurrentExecutions": 0}}, {"Concurrency": {}}, query="lambda_function_concurrent_execution_limit_configured")
def concurrency(item, index):
    configuration = get(item, "Concurrency", dict)
    if "ReservedConcurrentExecutions" not in configuration:
        return result(True, reserved_concurrency="not_configured", semantics="Successful GetFunctionConcurrency response lacks a reservation.")
    value = get(configuration, "ReservedConcurrentExecutions", int)
    if value < 0:
        return unknown("negative reserved concurrency")
    return result(False, reserved_concurrency=value, semantics="Zero is a configured reservation; this control does not claim the workload remains invokable.")


@install("aws.b.lambda.insights_layer", "lambda_function", "Lambda function has the source's Lambda Insights extension layer", {"Configuration": {"Layers": [{"Arn": "arn:aws:lambda:us-east-1:111111111111:layer:LambdaInsightsExtension:1"}]}}, {"Configuration": {"Layers": []}}, query="lambda_function_cloudwatch_insights_enabled")
def insights(item, index):
    configuration = get(item, "Configuration", dict)
    if configuration.get("collection_status") == "collected":
        # Successful native detail plus function identity establishes a known
        # optional-field omission. An absent/unreadable detail cannot do so.
        get(configuration, "FunctionName", str)
        layers = list_of_objects(optional(configuration, "Layers", [], list))
    else:
        layers = list_of_objects(get(configuration, "Layers", list))
    matches = [get(layer, "Arn", str) for layer in layers if ":layer:LambdaInsightsExtension:" in get(layer, "Arn", str)]
    return result(not matches, matching_layer_arns=matches, semantics="Layer declaration only; invocation/log delivery was not inspected.")


@install("aws.b.lambda.url_cors_single_wildcard", "lambda_function", "Lambda URL CORS avoids the source's single wildcard origin list", {"FunctionUrl": {"Cors": {"AllowOrigins": ["https://app.example.test"]}}}, {"FunctionUrl": {"Cors": {"AllowOrigins": ["*"]}}}, query="lambda_function_cors_configuration", category="exposure", extra={"not_applicable": {"FunctionUrl": {"collection_status": "empty", "absent": True}}})
def cors(item, index):
    config = get(item, "FunctionUrl", dict)
    if config.get("collection_status") == "empty" and config.get("absent") is True:
        return "NOT_APPLICABLE", {"reason": "No function URL exists."}
    settings = config.get("Cors", {})
    if not isinstance(settings, dict):
        return unknown("malformed CORS configuration")
    origins = settings.get("AllowOrigins", [])
    if not isinstance(origins, list) or any(not isinstance(v, str) for v in origins):
        return unknown("malformed CORS origins")
    return result(origins == ["*"], allow_origins=origins, semantics="Exact pinned source equality predicate; mixed wildcard lists require separate broader policy review.")


@install("aws.b.eks.audit_log_category", "eks_cluster", "EKS control-plane audit log category is enabled", {"Cluster": {"cluster": {"logging": {"clusterLogging": [{"enabled": True, "types": ["audit"]}]}}}}, {"Cluster": {"cluster": {"logging": {"clusterLogging": [{"enabled": False, "types": ["audit"]}]}}}}, query="eks_cluster_control_plane_audit_logging_enabled")
def audit_logging(item, index):
    logs = list_of_objects(get(item, "Cluster.cluster.logging.clusterLogging", list))
    enabled = False
    for log in logs:
        flag = get(log, "enabled", bool)
        types = get(log, "types", list)
        if any(not isinstance(v, str) for v in types):
            return unknown("malformed EKS log categories")
        enabled |= flag and "audit" in types
    return result(not enabled, audit_logging=enabled, configured_categories=logs)


@install("aws.b.eks.secret_envelope_encryption", "eks_cluster", "EKS secret envelope encryption matches version-dependent source semantics", {"Cluster": {"cluster": {"version": "1.28"}}}, {"Cluster": {"cluster": {"version": "1.27", "encryptionConfig": []}}}, query="eks_cluster_secrets_encrypted")
def secrets_encryption(item, index):
    cluster = get(item, "Cluster.cluster", dict)
    version = get(cluster, "version", str)
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.\d+)?", version)
    if not match:
        return unknown("malformed Kubernetes version")
    major, minor = map(int, match.groups())
    if major > 1 or (major == 1 and minor >= 28):
        return result(False, version=version, encryption="EKS default envelope encryption")
    rows = list_of_objects(get(cluster, "encryptionConfig", list))
    for row in rows:
        resources = get(row, "resources", list)
        if any(not isinstance(v, str) for v in resources):
            return unknown("malformed encrypted resource list")
        if "secrets" in resources:
            return result(False, version=version, declared_encrypted_resources=resources)
    return result(True, version=version, encryption_config=rows)


@install("aws.b.eks.no_default_vpc", "eks_cluster", "EKS cluster does not join a default VPC", {"Cluster": {"cluster": {"resourcesVpcConfig": {"vpcId": "vpc-private"}}}}, {"Cluster": {"cluster": {"resourcesVpcConfig": {"vpcId": "vpc-default"}}}}, query="eks_cluster_no_default_vpc", dependencies=["eks_cluster", "vpc"], extra={"index": {"collections": {"vpc": [{"status": "collected"}]}, "vpc": [{"data": {"VpcId": "vpc-private", "IsDefault": False}}, {"data": {"VpcId": "vpc-default", "IsDefault": True}}]}})
def no_default_vpc(item, index):
    coverage = index.get("collections", {}).get("vpc", [])
    if not coverage or any(c["status"] not in ("collected", "empty") for c in coverage):
        return unknown("VPC join inventory incomplete")
    vid = get(item, "Cluster.cluster.resourcesVpcConfig.vpcId", str)
    matches = [r["data"] for r in index.get("vpc", []) if r["data"].get("VpcId") == vid]
    if len(matches) != 1:
        return unknown("EKS VPC could not be uniquely resolved", vpc_id=vid)
    default = get(matches[0], "IsDefault", bool)
    return result(default, vpc_id=vid, is_default=default)
