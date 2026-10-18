"""Signed defensive AWS compliance predicates for sw43."""
from __future__ import annotations

import base64
import fnmatch
import json
import re
from dataclasses import replace
from datetime import datetime, timezone, timedelta

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, optional

SPECS = {'aws.nist.rds_cluster_member_enhanced_monitoring': {'category': 'hardening',
                                                     'hint': 'Enable Enhanced Monitoring and a '
                                                             'monitoring role on every cluster member '
                                                             'instance.',
                                                     'kind': 'rds_db_cluster',
                                                     'severity': 'medium',
                                                     'sha': 'e03497b2d49a20674136396c376a8e8d1e6b65d8f65f55c3b1c9959f2dc6e80a',
                                                     'title': 'RDS cluster member instances enable '
                                                              'Enhanced Monitoring'},
 'aws.nist.sc_5_2_coverage': {'category': 'compliance',
                              'hint': 'Correct the failing configuration and update the approved scope.',
                              'kind': 'capacity_group',
                              'severity': 'medium',
                              'sha': '2f7d60153ed074ce00af3adabe50dc26b1ae155bc17690c4e887ba6cee21e111',
                              'title': 'Capacity and redundancy meet approved thresholds'},
 'aws_backup_restore_tests_recent': {'category': 'hardening',
                                     'hint': 'Run and schedule AWS Backup restore tests for every '
                                             'protected ResourceArn within its approved interval.',
                                     'kind': 'backup_restore_job',
                                     'severity': 'medium',
                                     'sha': '35a66a25db9ee1c6bbf81da4a41839f2c47044a3aa70c8becea54b76fee32ef8',
                                     'title': 'Backup restore tests meet schedule'},
 'aws_cis_organization_account_guardrails': {'category': 'least_privilege',
                                             'hint': 'Attach scoped SCP guardrails to the root, OU, or '
                                                     'account and verify inheritance.',
                                             'kind': 'organization_account',
                                             'severity': 'high',
                                             'sha': '0555be717ce551ef702902ed5deb87bac1f36bfb5f761414f02412c721d73dd0',
                                             'title': 'Organization accounts have effective '
                                                      'authorization guardrails'},
 'aws_cis_organizations_management_account_workloads': {'category': 'hardening',
                                                        'hint': 'Move workloads to member accounts and '
                                                                'reserve the management account for '
                                                                'governance.',
                                                        'kind': 'organization_account',
                                                        'severity': 'high',
                                                        'sha': 'dddf355470e4453b0d7b12f39bf116effba048c34fbd8420e5fabf57652986a4',
                                                        'title': 'Organizations management account has '
                                                                 'no workloads'},
 'aws_ecr_image_provenance': {'category': 'hardening',
                              'hint': 'Sign deployed image digests and verify signatures before '
                                      'deployment.',
                              'kind': 'ecr_image',
                              'severity': 'high',
                              'sha': 'cac95c79d47220e95314e48bc55c145842e59fa2c5d98e2c5325a397e91886cf',
                              'title': 'Deployed container images have signature provenance'},
 'aws_ecr_sbom_present': {'category': 'hardening',
                          'hint': 'Attach a parseable SPDX or CycloneDX OCI artifact with '
                                  'subject.digest equal to each deployed ECR image digest.',
                          'kind': 'ecr_image',
                          'severity': 'medium',
                          'sha': '97894b9f17fad1408ee8ee7ebafa1e9b4ae868f5d71575ba9135f746bbfa15d4',
                          'title': 'Container images have current SBOM artifacts'},
 'aws_fedramp_rds_cluster_members_enhanced_monitoring': {'category': 'compliance',
                                                         'hint': 'Configure the named AWS resource to '
                                                                 'satisfy the predicate and verify all '
                                                                 'in-scope resources.',
                                                         'kind': 'rds_db_cluster',
                                                         'severity': 'medium',
                                                         'sha': '170bbd233633764f1c76b7c0975173019a7885683c569333cb36677e9341e3bf',
                                                         'title': 'RDS cluster members enable Enhanced '
                                                                  'Monitoring'},
 'aws_g6_efs_effective_backup_plan_selection': {'category': 'hardening',
                                                'hint': 'Add each EFS file system to an effective AWS '
                                                        'Backup selection.',
                                                'kind': 'efs_file_system',
                                                'severity': 'medium',
                                                'sha': 'b8eabd02e9f58a365b35a894f58bffd56bcb0588bba7eedf066482299c88fcbc',
                                                'title': 'EFS file systems belong to AWS Backup plans'},
 'aws_g6_rds_cluster_members_enhanced_monitoring': {'category': 'hardening',
                                                    'hint': 'Enable Enhanced Monitoring with a '
                                                            'monitoring role on each eligible cluster '
                                                            'member.',
                                                    'kind': 'rds_cluster',
                                                    'severity': 'medium',
                                                    'sha': '206c88bba37d48be8d556771398910155342e8c3e941e7c9fb97186853319bca',
                                                    'title': 'RDS cluster members use Enhanced '
                                                             'Monitoring'},
 'aws_nist_apigateway_stage_logging_enabled': {'category': 'compliance',
                                               'hint': 'Configure the resource to satisfy the stated '
                                                       'predicate and review missing inventory or '
                                                       'policy inputs.',
                                               'kind': 'http_api_stage',
                                               'severity': 'medium',
                                               'sha': '5ed202fb10761be0575fcc913500d9389dfc9755c14ccc32fb5dba8307256cf9',
                                               'title': 'API Gateway stage logging should be enabled'},
 'aws_nist_dynamodb_table_encrypted_with_kms': {'category': 'compliance',
                                                'hint': 'Configure the resource to satisfy the stated '
                                                        'predicate and review missing inventory or '
                                                        'policy inputs.',
                                                'kind': 'dynamodb_table',
                                                'severity': 'medium',
                                                'sha': '530ab66a12f4b77c96cdcf2a76154cf5baa630762a42f74d7232be5937c89a42',
                                                'title': 'DynamoDB table should be encrypted with AWS '
                                                         'KMS'},
 'aws_nist_efs_access_point_enforce_root_directory': {'category': 'compliance',
                                                      'hint': 'Configure the resource to satisfy the '
                                                              'stated predicate and review missing '
                                                              'inventory or policy inputs.',
                                                      'kind': 'efs_access_point',
                                                      'severity': 'medium',
                                                      'sha': 'e019a6edffe16ea2937595cdd0ed70fdfc9332fbe33f79f889d6323d5b082c98',
                                                      'title': 'EFS access points should enforce a root '
                                                               'directory'},
 'aws_nist_efs_file_system_in_backup_plan': {'category': 'compliance',
                                             'hint': 'Configure the resource to satisfy the stated '
                                                     'predicate and review missing inventory or policy '
                                                     'inputs.',
                                             'kind': 'efs_file_system',
                                             'severity': 'medium',
                                             'sha': '28e7d8c0d4ed037afcc8343d771f0dc7cc9523c89f89db5a41f7f8d5a65ee161',
                                             'title': 'EFS file systems should be in a backup plan'},
 'aws_nist_rds_db_cluster_aurora_backtracking_enabled': {'category': 'compliance',
                                                         'hint': 'Configure the resource to satisfy the '
                                                                 'stated predicate and review missing '
                                                                 'inventory or policy inputs.',
                                                         'kind': 'rds_cluster',
                                                         'severity': 'medium',
                                                         'sha': 'bfe3fab361cb9a33d4f767257e1e311b1b9260c382c6fdaf7d56f442c7d7ed26',
                                                         'title': 'RDS Aurora clusters should have '
                                                                  'backtracking enabled'}}
PROPOSED_SPEC_SHA256 = {key: value["sha"] for key, value in SPECS.items()}

_ACCOUNT = re.compile(r"[0-9]{12}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]")
_GLOBAL = {"organization_account", "scp_policy", "aws_account_configuration"}
_IDS = {"rds_db_cluster": "DBClusterIdentifier", "rds_cluster": "DBClusterIdentifier",
        "rds_instance": "DBInstanceIdentifier", "efs_file_system": "FileSystemArn",
        "efs_access_point": "AccessPointArn", "dynamodb_table": "TableName",
        "http_api_stage": "id", "rest_api_stage": "id", "rest_api_method": "id", "backup_plan": "BackupPlanArn",
        "backup_selection": "id", "backup_restore_job": "RestoreJobId",
        "ecr_image": "imageDigest", "ecr_oci_artifact": "artifactDigest",
        "organization_account": "Id", "scp_policy": "Id", "capacity_group": "id"}


def _context(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS provider context unavailable")
    scope = get(context, "scope", str)
    account, sep, region = scope.partition("/")
    if not sep or not _ACCOUNT.fullmatch(account) or (region != "global" and not _REGION.fullmatch(region)):
        raise Unavailable("AWS account/Region scope unavailable")
    return context, scope, account, region


def _inventory(index, kind):
    _, scope, account, region = _context(index)
    if (region == "global") != (kind in _GLOBAL):
        raise Unavailable("global/regional collection scope mismatch: " + kind)
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("collection authority unavailable: " + kind)
    envelope = envelopes[0]
    if get(envelope, "type", str) != kind or get(envelope, "scope", str) != scope:
        raise Unavailable("foreign collection: " + kind)
    rows = complete_items(index, kind)
    if get(envelope, "items", list) != rows or (envelope["status"] == "empty" and rows):
        raise Unavailable("collection items disagree with scoped index: " + kind)
    wrappers = get(index, kind, list)
    if len(wrappers) != len(rows):
        raise Unavailable("resource wrapper count mismatch: " + kind)
    seen = set()
    for wrapper, row in zip(wrappers, rows):
        if (get(wrapper, "type", str) != kind or get(wrapper, "scope", str) != scope or
                get(wrapper, "data", dict) != row):
            raise Unavailable("foreign or malformed resource wrapper: " + kind)
        identity = get(row, _IDS[kind], str)
        if not identity or identity in seen:
            raise Unavailable("missing or duplicate resource identity: " + kind)
        seen.add(identity)
        if _IDS[kind].endswith("Arn") or kind in {"http_api_stage", "rest_api_stage"}:
            if identity.startswith("arn:"):
                parts = identity.split(":", 5)
                if len(parts) != 6 or (parts[3] and parts[3] != region) or (parts[4] and parts[4] != account):
                    raise Unavailable("foreign resource ARN: " + kind)
    return rows


def _subject(item, index, kind):
    rows = _inventory(index, kind)
    identity = get(item, _IDS[kind], str)
    matches = [row for row in rows if row[_IDS[kind]] == identity]
    if len(matches) != 1 or matches[0] != item:
        raise Unavailable("item differs from complete scoped inventory")
    return identity


def _policy(index, field, expected):
    context, _, _, _ = _context(index)
    return get(get(context, "metadata", dict), field, expected)


def _nonempty(item, path):
    value = get(item, path, str)
    if not value.strip():
        raise Unavailable("empty identity or required value: " + path)
    return value


def _list(item, path):
    values = get(item, path, list)
    if any(not isinstance(x, dict) for x in values):
        raise Unavailable("malformed object list: " + path)
    return values


def _time(value):
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise Unavailable("malformed timestamp") from exc
    else:
        raise Unavailable("malformed timestamp")
    if timestamp.tzinfo is None:
        raise Unavailable("timezone unavailable")
    return timestamp.astimezone(timezone.utc)


def _rds_members(item, index, kind, *, resource_arn=False):
    cluster_id = _subject(item, index, kind)
    members = _list(item, "DBClusterMembers")
    if not members:
        return unknown("cluster member inventory is empty", cluster_id=cluster_id)
    instances = _inventory(index, "rds_instance")
    by_id = {get(row, "DBInstanceIdentifier", str): row for row in instances}
    seen, failures = set(), []
    for member in members:
        member_id = _nonempty(member, "DBInstanceIdentifier")
        if member_id in seen or member_id not in by_id:
            raise Unavailable("duplicate or unresolved cluster member")
        seen.add(member_id)
        instance = by_id[member_id]
        if get(instance, "DBClusterIdentifier", str) != cluster_id:
            raise Unavailable("RDS member joins a different cluster")
        if resource_arn and get(instance, "DBInstanceClass", str) == "db.m1.small":
            continue
        interval = get(instance, "MonitoringInterval", int)
        if interval < 0:
            raise Unavailable("invalid monitoring interval")
        role = instance.get("MonitoringRoleArn")
        if role is not None and not isinstance(role, str):
            raise Unavailable("malformed monitoring role")
        if role is None and "MonitoringRoleArn" not in instance:
            raise Unavailable("monitoring role field unavailable")
        bad = interval == 0 or not role
        if resource_arn:
            monitoring_arn = instance.get("EnhancedMonitoringResourceArn")
            if monitoring_arn is None and "EnhancedMonitoringResourceArn" not in instance:
                raise Unavailable("enhanced monitoring resource field unavailable")
            if monitoring_arn is not None and not isinstance(monitoring_arn, str):
                raise Unavailable("malformed enhanced monitoring resource ARN")
            bad = bad or not monitoring_arn
        if bad:
            failures.append(member_id)
    return result(bool(failures), cluster_id=cluster_id, failing_members=failures)


def _backtracking(item, index):
    identity = _subject(item, index, "rds_cluster")
    engine = get(item, "Engine", str)
    if engine not in {"aurora", "aurora-mysql"}:
        if engine in {"aurora-postgresql", "mysql", "postgres", "mariadb", "docdb"}:
            return "NOT_APPLICABLE", {"cluster_id": identity, "engine": engine}
        return unknown("unrecognized engine capability", engine=engine)
    if get(item, "BacktrackingSupported", bool) is False:
        return "NOT_APPLICABLE", {"cluster_id": identity, "engine": engine, "reason": "engine version does not support backtracking"}
    if "BacktrackWindow" not in item and "BacktrackWindow" not in item.get("_coverage", {}):
        return result(True, cluster_id=identity, backtrack_window=None)
    window = get(item, "BacktrackWindow", int)
    if window < 0:
        raise Unavailable("negative backtrack window")
    return result(window == 0, cluster_id=identity, backtrack_window=window)


def _dynamodb(item, index):
    name = _subject(item, index, "dynamodb_table")
    table = get(item, "Table", dict)
    if get(table, "collection_status", str) != "collected":
        raise Unavailable("DescribeTable unavailable")
    body = get(table, "Table", dict)
    if get(body, "TableName", str) != name:
        raise Unavailable("DescribeTable identity mismatch")
    if "SSEDescription" not in body and "SSEDescription" not in body.get("_coverage", {}):
        return result(True, table_name=name, reason="SSEDescription absent from complete DescribeTable")
    sse = get(body, "SSEDescription", dict)
    state = get(sse, "Status", str)
    if state not in {"ENABLED", "ENABLING", "DISABLING", "DISABLED", "UPDATING"}:
        raise Unavailable("unrecognized SSE state")
    sse_type = get(sse, "SSEType", str)
    if sse_type not in {"KMS", "AES256"}:
        raise Unavailable("unrecognized SSE type")
    key = sse.get("KMSMasterKeyArn")
    if key is not None and not isinstance(key, str):
        raise Unavailable("malformed KMS key ARN")
    if sse_type == "KMS" and state == "ENABLED" and key and re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/.+", key):
        return result(False, table_name=name, kms_key_arn=key)
    if state in {"ENABLING", "DISABLING", "UPDATING"}:
        return unknown("SSE change in progress", table_name=name, state=state)
    if sse_type == "KMS" and key and not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/.+", key):
        raise Unavailable("malformed KMS key ARN")
    return result(True, table_name=name, sse_type=sse_type, state=state, kms_key_arn=key)


def _efs_root(item, index):
    arn = _subject(item, index, "efs_access_point")
    if "RootDirectory" not in item and "RootDirectory" not in item.get("_coverage", {}):
        return result(True, access_point_arn=arn, path=None)
    root = get(item, "RootDirectory", dict)
    path = root.get("Path")
    if path is None and "Path" not in root:
        return result(True, access_point_arn=arn, path=None)
    if not isinstance(path, str):
        raise Unavailable("malformed root path")
    if path == "" or path == "/":
        return result(True, access_point_arn=arn, path=path)
    if not path.startswith("/") or "//" in path or "/./" in path or "/../" in path:
        raise Unavailable("malformed absolute root path")
    return result(False, access_point_arn=arn, path=path)


def _logging_level(settings, key, inherited=None):
    # GetStages returns sparse method/route overrides; a truly omitted field
    # inherits the default. Explicit null, malformed values and field denial do not.
    level = optional(settings, key, inherited, str)
    if level not in {"OFF", "INFO", "ERROR"}:
        raise Unavailable("logging level unavailable or unrecognized")
    return level


def _stage_bound(stage, family):
    arn = get(stage, "id", str)
    if get(stage, "_provenance.source_operation", str) != "get_stages" or get(stage, "_provenance.read_only", bool) is not True:
        raise Unavailable("GetStages provenance unavailable: " + family)
    api = get(stage, "ParentApiId", str)
    if get(stage, "_provenance.parent_api_id", str) != api or not api:
        raise Unavailable("stage parent API binding unavailable: " + family)
    name = get(stage, "stageName" if family == "REST" else "StageName", str)
    path = "restapis" if family == "REST" else "apis"
    if (not re.fullmatch(r"[a-z0-9]{1,32}", api) or
            not re.fullmatch(r"[A-Za-z0-9_$-]{1,128}", name) or
            not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:apigateway:[a-z0-9-]+::/" +
                             path + "/" + re.escape(api) + "/stages/" + re.escape(name), arn)):
        raise Unavailable("stage ARN parent API binding unavailable: " + family)
    from peaso.collectors.aws_config_account_native import region_partition
    parts = arn.split(":", 5)
    if region_partition(parts[3]) != parts[1]:
        raise Unavailable("stage ARN partition differs from its Region")
    return arn


def _rest_stage(stage, methods):
    arn = _stage_bound(stage, "REST")
    deployment = get(stage, "deploymentId", str)
    if not deployment:
        raise Unavailable("REST deployment binding unavailable")
    canary = optional(stage, "canarySettings", None, dict)
    if canary is not None:
        percent = optional(canary, "percentTraffic", 0)
        if type(percent) not in (int, float) or percent != 0:
            raise Unavailable("REST canary deployment coverage unavailable")
    settings = optional(stage, "methodSettings", {}, dict)
    if not methods:
        raise Unavailable("stage-bound deployed REST method inventory unavailable")
    setting_keys = set(settings) | set(settings.get("_coverage", {}))
    setting_keys.discard("_coverage")
    for key in setting_keys:
        if not isinstance(key, str) or not key:
            raise Unavailable("malformed REST method settings")
        setting = get(settings, key, dict)
        # Read all present levels, including overrides outside this deployment.
        if "loggingLevel" in setting or "loggingLevel" in setting.get("_coverage", {}):
            _logging_level(setting, "loggingLevel")
    wildcard = get(settings, "*/*", dict) if "*/*" in setting_keys else None
    baseline = _logging_level(wildcard, "loggingLevel") if wildcard is not None else None
    disabled, seen = [], set()
    for method in methods:
        if get(method, "stageArn", str) != arn or get(method, "restApiId", str) != get(stage, "ParentApiId", str) or get(method, "deploymentId", str) != deployment:
            raise Unavailable("foreign REST method/deployment binding")
        if (get(method, "_provenance.source_operation", str) != "GetDeployment" or
                get(method, "_provenance.read_only", bool) is not True or
                get(method, "_provenance.embed", str) != "apisummary" or
                get(method, "_provenance.stage_deployment_join_verified", bool) is not True):
            raise Unavailable("REST deployment summary provenance unavailable")
        path, verb = get(method, "resourcePath", str), get(method, "httpMethod", str)
        if not path.startswith("/") or verb not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "ANY"}:
            raise Unavailable("malformed deployed REST method")
        if get(method, "methodSettingKey", str) != path + "/" + verb:
            raise Unavailable("deployed REST method setting key mismatch")
        key = path.replace("~", "~0").replace("/", "~1") + "/" + verb
        if key in seen:
            raise Unavailable("duplicate deployed REST method")
        seen.add(key)
        if key in setting_keys:
            specific = get(settings, key, dict)
            level = _logging_level(specific, "loggingLevel", baseline)
        else:
            if baseline is None:
                raise Unavailable("REST method logging inheritance unavailable")
            level = baseline
        if level == "OFF":
            disabled.append(arn + ":" + key)
    if setting_keys - ({"*/*"} | seen):
        raise Unavailable("REST method setting precedence outside bound deployment unsupported")
    return disabled, len(methods)


def _websocket_stage(stage):
    arn = _stage_bound(stage, "WEBSOCKET")
    if get(stage, "ParentProtocolType", str) != "WEBSOCKET" or get(stage, "_provenance.parent_protocol_source_operation", str) != "get_apis":
        raise Unavailable("WebSocket parent protocol authority unavailable")
    default = get(stage, "DefaultRouteSettings", dict)
    baseline = _logging_level(default, "LoggingLevel")
    overrides = optional(stage, "RouteSettings", {}, dict)
    override_keys = set(overrides) | set(overrides.get("_coverage", {}))
    override_keys.discard("_coverage")
    for key in override_keys:
        if not isinstance(key, str) or not key:
            raise Unavailable("malformed WebSocket route settings")
        setting = get(overrides, key, dict)
        level = _logging_level(setting, "LoggingLevel", baseline)
        if level == "OFF":
            # A configured override is not proof that its route is deployed.
            raise Unavailable("WebSocket override OFF; deployed route binding unavailable")
    if baseline == "OFF":
        # An all-route default is not evidence that any deployed route lacks
        # an effective route-specific override.
        raise Unavailable("WebSocket default OFF; deployed route binding unavailable")
    return arn, len(override_keys)


def _stage_logging(item, index):
    _, scope, _, region = _context(index)
    if region == "global" or get(item, "scope", str) != scope:
        raise Unavailable("stage scope unavailable")
    rest = _inventory(index, "rest_api_stage")
    v2 = _inventory(index, "http_api_stage")
    method_rows = _inventory(index, "rest_api_method")
    by_stage = {get(stage, "id", str): [] for stage in rest}
    for method in method_rows:
        arn = get(method, "stageArn", str)
        if arn not in by_stage:
            raise Unavailable("deployed REST method has no bound stage")
        by_stage[arn].append(method)
    failures, evaluated, websockets, http = [], 0, 0, 0
    for stage in rest:
        arn = get(stage, "id", str)
        disabled, checked = _rest_stage(stage, by_stage[arn])
        failures.extend(disabled)
        evaluated += checked
    for stage in v2:
        _stage_bound(stage, "V2")
        protocol = get(stage, "ParentProtocolType", str)
        if get(stage, "_provenance.parent_protocol_source_operation", str) != "get_apis":
            raise Unavailable("v2 parent protocol authority unavailable")
        if protocol == "HTTP":
            http += 1
        elif protocol == "WEBSOCKET":
            _websocket_stage(stage)
            websockets += 1
        else:
            raise Unavailable("unknown v2 API protocol")
    if not (rest or websockets):
        return "NOT_APPLICABLE", {"reason": "no applicable REST or WebSocket stages; HTTP execution logging unsupported",
                                  "http_not_applicable_stages": http}
    return result(bool(failures), disabled_deployed_rest_methods=failures,
                  evaluated_rest_methods=evaluated, configured_websocket_stages=websockets,
                  http_not_applicable_stages=http)


def _selection_matches(selection, arn, tags, *, require_role):
    guard(selection)
    if require_role and not get(selection, "IamRoleArn", str).strip():
        return False
    resources = get(selection, "Resources", list)
    excluded = get(selection, "NotResources", list)
    if any(not isinstance(x, str) or not x.startswith("arn:") for x in resources + excluded):
        raise Unavailable("malformed backup selection resource patterns")
    if any(fnmatch.fnmatchcase(arn, pattern) for pattern in excluded):
        return False
    direct = any(fnmatch.fnmatchcase(arn, pattern) for pattern in resources)
    tag_rules = get(selection, "ListOfTags", list)
    conditions = get(selection, "Conditions", dict)
    if any(not isinstance(x, dict) for x in tag_rules):
        raise Unavailable("malformed backup tag rules")
    def match(rule):
        key = get(rule, "ConditionKey", str)
        value = get(rule, "ConditionValue", str)
        if get(rule, "ConditionType", str) != "STRINGEQUALS":
            raise Unavailable("unsupported backup tag condition")
        prefix = "aws:ResourceTag/"
        if not key.startswith(prefix) or not key[len(prefix):]:
            raise Unavailable("unsupported backup tag key")
        return tags.get(key[len(prefix):]) == value
    tag_match = any(match(rule) for rule in tag_rules)
    if set(conditions) - {"StringEquals", "StringLike", "StringNotEquals", "StringNotLike"}:
        raise Unavailable("unrecognized backup selection condition")
    positive = []
    for op in ("StringEquals", "StringLike"):
        rules = conditions.get(op, [])
        if not isinstance(rules, list):
            raise Unavailable("malformed backup conditions")
        for rule in rules:
            key = get(rule, "ConditionKey", str)
            value = get(rule, "ConditionValue", str)
            if not key.startswith("aws:ResourceTag/"):
                raise Unavailable("unsupported backup condition key")
            observed = tags.get(key.split("/", 1)[1])
            positive.append(observed == value if op == "StringEquals" else observed is not None and fnmatch.fnmatchcase(observed, value))
    negative_ok = True
    for op in ("StringNotEquals", "StringNotLike"):
        rules = conditions.get(op, [])
        if not isinstance(rules, list):
            raise Unavailable("malformed backup conditions")
        for rule in rules:
            key = get(rule, "ConditionKey", str)
            value = get(rule, "ConditionValue", str)
            if not key.startswith("aws:ResourceTag/"):
                raise Unavailable("unsupported backup condition key")
            observed = tags.get(key.split("/", 1)[1])
            if observed is None:
                negative_ok = False
            else:
                negative_ok &= observed != value if op == "StringNotEquals" else not fnmatch.fnmatchcase(observed, value)
    return negative_ok and (direct or tag_match or (bool(positive) and all(positive)))


def _efs_backup(item, index, *, effective):
    arn = _subject(item, index, "efs_file_system")
    raw_tags = get(item, "Tags", list)
    if any(not isinstance(tag, dict) for tag in raw_tags):
        raise Unavailable("malformed EFS tags")
    tags = {get(tag, "Key", str): get(tag, "Value", str) for tag in raw_tags}
    if len(tags) != len(raw_tags):
        raise Unavailable("duplicate EFS tags")
    plans = _inventory(index, "backup_plan")
    matched = []
    for plan in plans:
        plan_arn = get(plan, "BackupPlanArn", str)
        enabled = get(plan, "Enabled", bool)
        if not enabled:
            continue
        selections = get(plan, "Selections", dict)
        if get(selections, "collection_status", str) not in {"collected", "empty"}:
            raise Unavailable("backup selection inventory incomplete")
        for row in _list(selections, "items"):
            detail = get(row, "Selection", dict)
            if get(detail, "collection_status", str) != "collected":
                raise Unavailable("GetBackupSelection incomplete")
            selection = get(detail, "BackupSelection", dict)
            if _selection_matches(selection, arn, tags, require_role=effective):
                matched.append(plan_arn)
    return result(not matched, file_system_arn=arn, matching_plan_arns=matched)


def _restore_tests(item, index):
    _, scope, _, region = _context(index)
    if region == "global" or get(item, "scope", str) != scope:
        raise Unavailable("restore-test scope unavailable")
    approved = _policy(index, "approved_protected_resources", list)
    if not approved or any(not isinstance(x, dict) for x in approved):
        raise Unavailable("approved protected-resource inventory unavailable")
    now = _time(get(get(index, "context", dict), "created_at"))
    jobs = _inventory(index, "backup_restore_job")
    failures = []
    for resource in approved:
        arn = _nonempty(resource, "ResourceArn")
        parts = arn.split(":", 5)
        _, _, account, region = _context(index)
        if len(parts) != 6 or parts[4] != account or (parts[3] and parts[3] != region):
            raise Unavailable("protected resource belongs to foreign scope")
        interval = get(resource, "IntervalDays", int)
        if interval <= 0:
            raise Unavailable("invalid approved restore-test interval")
        related = [job for job in jobs if get(job, "SourceResourceArn", str) == arn]
        recent = False
        for job in related:
            status = get(job, "Status", str)
            if status not in {"COMPLETED", "FAILED", "ABORTED", "RUNNING", "PENDING"}:
                raise Unavailable("unrecognized restore-job status")
            if status == "COMPLETED":
                plan = get(job, "CreatedBy.RestoreTestingPlanArn", str)
                completed = _time(get(job, "CompletionDate"))
                if plan and now - timedelta(days=interval) <= completed <= now:
                    recent = True
        if not recent:
            failures.append(arn)
    return result(bool(failures), resources_without_recent_restore_test=failures)


def _capacity(item, index):
    identity = _subject(item, index, "capacity_group")
    minimum = get(item, "DocumentedMinimum", int)
    capacity = get(item, "ConfiguredCapacity", int)
    zones = get(item, "AvailabilityZones", list)
    if minimum < 0 or capacity < 0 or any(not isinstance(x, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9][a-z]", x) for x in zones):
        raise Unavailable("malformed approved capacity group")
    if len(zones) != len(set(zones)):
        raise Unavailable("duplicate availability zone")
    _, _, _, region = _context(index)
    if any(zone[:-1] != region for zone in zones):
        raise Unavailable("capacity group has foreign Availability Zone")
    return result(capacity < minimum or len(zones) < 2, group_id=identity,
                  documented_minimum=minimum, configured_capacity=capacity, zones=zones)


def _org_guardrails(item, index):
    account = _subject(item, index, "organization_account")
    state = get(item, "Status", str)
    if state != "ACTIVE":
        if state in {"SUSPENDED", "PENDING_CLOSURE", "CLOSED"}:
            return "NOT_APPLICABLE", {"account_id": account, "status": state}
        raise Unavailable("unrecognized organization account status")
    actions = _policy(index, "prohibited_actions", list)
    if not actions or any(not isinstance(x, str) or not x for x in actions):
        raise Unavailable("approved prohibited actions unavailable")
    attachment = get(item, "EffectiveScpPolicies", dict)
    if get(attachment, "collection_status", str) not in {"collected", "empty"} or get(attachment, "InheritanceComplete", bool) is not True:
        raise Unavailable("SCP inheritance incomplete")
    policies = _list(attachment, "items")
    covered = set()
    guardrail = False
    for policy in policies:
        name = get(policy, "Name", str)
        if name == "FullAWSAccess":
            continue
        guardrail = True
        document = get(policy, "Content", dict)
        statements = get(document, "Statement")
        statements = [statements] if isinstance(statements, dict) else statements
        if not isinstance(statements, list) or any(not isinstance(x, dict) for x in statements):
            raise Unavailable("malformed SCP statements")
        for statement in statements:
            if get(statement, "Effect", str) != "Deny":
                raise Unavailable("SCP allow-list semantics require separate policy analysis")
            if "Condition" in statement or "NotResource" in statement or "NotAction" in statement:
                raise Unavailable("conditional or inverse SCP statement needs separate policy analysis")
            resource = get(statement, "Resource")
            if resource != "*" and resource != ["*"]:
                raise Unavailable("resource-scoped SCP deny does not prove action-wide guardrail")
            patterns = get(statement, "Action")
            patterns = [patterns] if isinstance(patterns, str) else patterns
            if not isinstance(patterns, list) or any(not isinstance(x, str) for x in patterns):
                raise Unavailable("malformed SCP action")
            for action in actions:
                if any(fnmatch.fnmatchcase(action.lower(), pattern.lower()) for pattern in patterns):
                    covered.add(action)
    return result(not guardrail or len(covered) != len(actions), account_id=account,
                  missing_prohibited_actions=sorted(set(actions) - covered), guardrail_attached=guardrail)


def _management_workloads(item, index):
    account = _subject(item, index, "organization_account")
    management = _policy(index, "management_account_id", str)
    if not _ACCOUNT.fullmatch(management):
        raise Unavailable("management account identity unavailable")
    _, _, caller, _ = _context(index)
    if caller != management or account != caller:
        return "NOT_APPLICABLE", {"account_id": account, "management_account_id": management}
    allowlist = _policy(index, "governance_resource_allowlist", list)
    if any(not isinstance(x, str) or not x for x in allowlist):
        raise Unavailable("malformed governance allowlist")
    inventory = get(item, "WorkloadInventory", dict)
    if get(inventory, "collection_status", str) not in {"collected", "empty"} or get(inventory, "account_id", str) != account:
        raise Unavailable("management account workload inventory incomplete")
    rows = _list(inventory, "items")
    allowed_kinds = {"ec2_instance", "rds_instance", "lambda_function", "ecs_service", "eks_cluster"}
    seen, unapproved = set(), []
    for row in rows:
        kind = get(row, "kind", str)
        identity = _nonempty(row, "id")
        if kind not in allowed_kinds or (kind, identity) in seen:
            raise Unavailable("malformed or duplicate workload resource")
        seen.add((kind, identity))
        if identity not in allowlist:
            unapproved.append(identity)
    return result(bool(unapproved), account_id=account, unapproved_workload_ids=unapproved)


def _artifacts(item, index):
    digest = _subject(item, index, "ecr_image")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise Unavailable("malformed image digest")
    designated = _policy(index, "deployed_image_digests", list)
    if any(not isinstance(x, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", x) for x in designated):
        raise Unavailable("deployed image inventory malformed")
    if digest not in designated:
        return digest, None
    return digest, _inventory(index, "ecr_oci_artifact")


def _sbom(item, index):
    digest, artifacts = _artifacts(item, index)
    if artifacts is None:
        return "NOT_APPLICABLE", {"image_digest": digest}
    valid = []
    for artifact in artifacts:
        subject = get(artifact, "subject", dict)
        if get(subject, "digest", str) != digest:
            continue
        artifact_type = get(artifact, "artifactType", str)
        if artifact_type not in {"application/spdx+json", "application/vnd.cyclonedx+json"}:
            continue
        payload = get(artifact, "payload", str)
        try:
            document = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if not isinstance(document, dict):
            continue
        if artifact_type == "application/spdx+json":
            ok = document.get("spdxVersion", "").startswith("SPDX-") and isinstance(document.get("packages"), list)
        else:
            ok = document.get("bomFormat") == "CycloneDX" and isinstance(document.get("components"), list)
        if ok:
            valid.append(get(artifact, "artifactDigest", str))
    return result(not valid, image_digest=digest, matching_sbom_artifacts=valid)


def _verify_signature(payload, signature, pem):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.exceptions import InvalidSignature
    try:
        public = serialization.load_pem_public_key(pem.encode())
        raw_signature = base64.b64decode(signature, validate=True)
        if isinstance(public, ed25519.Ed25519PublicKey):
            public.verify(raw_signature, payload)
        elif isinstance(public, rsa.RSAPublicKey):
            public.verify(raw_signature, payload, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(raw_signature, payload, ec.ECDSA(hashes.SHA256()))
        else:
            raise Unavailable("unsupported approved signing key")
        return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError) as exc:
        raise Unavailable("malformed signing key or signature") from exc


def _signature_constant(value):
    raise ValueError("non-JSON signature constant")


def _signature_object(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate signature member")
        document[key] = value
    return document


def _provenance(item, index):
    digest, artifacts = _artifacts(item, index)
    if artifacts is None:
        return "NOT_APPLICABLE", {"image_digest": digest}
    keys = _policy(index, "approved_signing_public_keys", list)
    if not keys or any(not isinstance(x, dict) for x in keys):
        raise Unavailable("approved signing keys unavailable")
    by_id = {_nonempty(key, "KeyId"): _nonempty(key, "PublicKeyPem") for key in keys}
    if len(by_id) != len(keys):
        raise Unavailable("duplicate approved signing key")
    verified = []
    for artifact in artifacts:
        if get(artifact, "artifactType", str) != "application/vnd.dev.cosign.simplesigning.v1+json":
            continue
        if get(artifact, "subject.digest", str) != digest:
            continue
        payload = get(artifact, "payload", str)
        try:
            body = json.loads(payload, object_pairs_hook=_signature_object, parse_constant=_signature_constant)
        except (ValueError, RecursionError) as exc:
            raise Unavailable("malformed signature payload") from exc
        if not isinstance(body, dict) or set(body) != {"critical", "optional"}:
            raise Unavailable("unsupported signature payload")
        # Cosign emits optional:null when there are no optional claims.
        if body["optional"] is not None and not isinstance(body["optional"], dict):
            raise Unavailable("malformed optional signature claims")
        critical = get(body, "critical", dict)
        identity = get(critical, "identity", dict)
        image = get(critical, "image", dict)
        if (set(critical) != {"type", "identity", "image"}
                or set(identity) != {"docker-reference"}
                or set(image) != {"docker-manifest-digest"}
                or get(critical, "type", str) != "cosign container image signature"):
            raise Unavailable("unsupported critical signature claims")
        # Cosign intentionally ignores docker-reference; trust binds content digest.
        get(identity, "docker-reference", str)
        signed_digest = get(image, "docker-manifest-digest", str)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", signed_digest):
            raise Unavailable("malformed signed image digest")
        if signed_digest != digest:
            continue
        key_id = get(artifact, "keyId", str)
        if key_id in by_id and _verify_signature(payload.encode(), get(artifact, "signature", str), by_id[key_id]):
            verified.append(get(artifact, "artifactDigest", str))
    return result(not verified, image_digest=digest, verified_signature_artifacts=verified)


_EVALUATORS = {
    "aws_backup_restore_tests_recent": (_restore_tests, ["backup_restore_job"], "scope"),
    "aws.nist.rds_cluster_member_enhanced_monitoring": (lambda item, index: _rds_members(item, index, "rds_db_cluster"), ["rds_db_cluster", "rds_instance"], "resource"),
    "aws_fedramp_rds_cluster_members_enhanced_monitoring": (lambda item, index: _rds_members(item, index, "rds_db_cluster"), ["rds_db_cluster", "rds_instance"], "resource"),
    "aws_g6_rds_cluster_members_enhanced_monitoring": (lambda item, index: _rds_members(item, index, "rds_cluster", resource_arn=True), ["rds_cluster", "rds_instance"], "resource"),
    "aws_nist_rds_db_cluster_aurora_backtracking_enabled": (_backtracking, ["rds_cluster"], "resource"),
    "aws_nist_dynamodb_table_encrypted_with_kms": (_dynamodb, ["dynamodb_table"], "resource"),
    "aws_nist_efs_access_point_enforce_root_directory": (_efs_root, ["efs_access_point"], "resource"),
    "aws_nist_apigateway_stage_logging_enabled": (_stage_logging, ["http_api_stage", "rest_api_stage", "rest_api_method"], "scope"),
    "aws_nist_efs_file_system_in_backup_plan": (lambda item, index: _efs_backup(item, index, effective=False), ["efs_file_system", "backup_plan"], "resource"),
    "aws_g6_efs_effective_backup_plan_selection": (lambda item, index: _efs_backup(item, index, effective=True), ["efs_file_system", "backup_plan"], "resource"),
    "aws.nist.sc_5_2_coverage": (_capacity, ["capacity_group"], "resource"),
    "aws_cis_organization_account_guardrails": (_org_guardrails, ["organization_account"], "resource"),
    "aws_cis_organizations_management_account_workloads": (_management_workloads, ["organization_account"], "resource"),
    "aws_ecr_sbom_present": (_sbom, ["ecr_image", "ecr_oci_artifact"], "resource"),
    "aws_ecr_image_provenance": (_provenance, ["ecr_image", "ecr_oci_artifact"], "resource"),
}

for _id, (_evaluator, _dependencies, _target) in _EVALUATORS.items():
    _spec = SPECS[_id]
    @register(_id, "aws", _spec["category"] if _spec["category"] != "compliance" else "hardening", _spec["kind"], _spec["title"],
              _spec["severity"], "CM-6", _spec["hint"], target=_target,
              dependencies=_dependencies)
    def _evaluate(item, index, evaluator=_evaluator):
        return evaluator(item, index)
    _evaluate.__name__ = _id.replace(".", "_")

    # Native registration validates defensive categories; retain the exact signed
    # compliance category on the immutable metadata after wrapping the evaluator.
    if _spec["category"] == "compliance":
        CHECKS[-1] = replace(CHECKS[-1], category="compliance")
