"""Signed AWS compliance predicates for sw47, using strict snapshot authority.
"""
from __future__ import annotations

import json
import re
from dataclasses import replace
from urllib.parse import unquote

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects

SPECS = {'aws_partner_role_external_ids_unique': {'kind': 'iam_role',
                                          'category': 'hardening',
                                          'severity': 'medium',
                                          'title': 'Partner external IDs are unique',
                                          'hint': 'Assign each customer a distinct sts:ExternalId value and '
                                                  'update partner role trust policies accordingly.',
                                          'sha': '8d9894ee3877f537ed29607c8e6b5c991cf7b20256b04c40f607087b5722745c'},
 'aws.pci.cloudtrail.authentication_events': {'kind': 'cloudtrail_trail',
                                              'category': 'logging',
                                              'severity': 'medium',
                                              'title': 'Authentication management events are logged',
                                              'hint': 'Enable a multi-Region CloudTrail trail with read and write '
                                                      'management events in EventSelectors, and start logging.',
                                              'sha': 'd30786b6615e2e7867df0f6d22c3ea00f5105bb357055a6ef78044a7f1fd947c'},
 'aws_fedramp_cloudtrail_cloudwatch_integration': {'kind': 'cloudtrail_trail',
                                                   'category': 'compliance',
                                                   'severity': 'medium',
                                                   'title': 'CloudTrail trails integrate with CloudWatch Logs',
                                                   'hint': 'Configure the named AWS resource to satisfy the '
                                                           'predicate and verify all in-scope resources.',
                                                   'sha': 'eedf8eaa2e7175ff340a7b40242f9920cde1cf50ac1ab3edef468651c21eacf8'},
 'aws_fedramp_cloudtrail_destination_kms': {'kind': 'cloudtrail_trail',
                                            'category': 'compliance',
                                            'severity': 'medium',
                                            'title': 'CloudTrail and linked log groups use customer-managed KMS '
                                                     'keys',
                                            'hint': 'Configure the named AWS resource to satisfy the predicate '
                                                    'and verify all in-scope resources.',
                                            'sha': '6b8df19ecf8a7f6a96cf870ea1c3da7cf07bbf11353bf8c234bd047cf8b5de72'},
 'aws_nist_codebuild_project_plaintext_env_variables_no_sensitive_aws_values': {'kind': 'codebuild_project',
                                                                                'category': 'compliance',
                                                                                'severity': 'medium',
                                                                                'title': 'CodeBuild project '
                                                                                         'plaintext environment '
                                                                                         'variables should not '
                                                                                         'contain sensitive AWS '
                                                                                         'values',
                                                                                'hint': 'Configure the resource '
                                                                                        'to satisfy the stated '
                                                                                        'predicate and review '
                                                                                        'missing inventory or '
                                                                                        'policy inputs.',
                                                                                'sha': '84d6ae0ad08a346f0a55addce1a1e9ce0e4d355b90f9b87ba6271231d91b1e20'},
 'aws_eks_cluster_current_supported_version': {'kind': 'eks_cluster',
                                               'category': 'hardening',
                                               'severity': 'high',
                                               'title': 'EKS cluster meets the current approved Kubernetes '
                                                        'version floor',
                                               'hint': 'Upgrade the EKS cluster Kubernetes version to at least '
                                                       'the configured approved version floor.',
                                               'sha': '12b56c24b4805400d3c697f7176cb221863306403c38a81551c072bc9d2e0187'},
 'aws_eks_cluster_supported_version_catalog': {'kind': 'eks_cluster',
                                               'category': 'compliance',
                                               'severity': 'high',
                                               'title': 'EKS cluster runs a currently supported Kubernetes '
                                                        'version',
                                               'hint': 'Upgrade the cluster to a currently supported EKS '
                                                       'Kubernetes version.',
                                               'sha': '829e03e994eae83147ed622008881464b8b5963927c0668949cc27a55d497ab0'},
 'aws_eks_runtime_image_integrity': {'kind': 'eks_cluster',
                                     'category': 'hardening',
                                     'severity': 'high',
                                     'title': 'EKS images are verified at admission and monitored at runtime',
                                     'hint': 'Install a fail-closed pod CREATE validating webhook backed by the '
                                             'approved image-signature verifier on each designated EKS cluster.',
                                     'sha': '2e6121cbbf19bc25ae1d9602258915265c764ac354c32973b37f6410cc51baa9'},
 'aws_costexplorer_anomaly_alert': {'kind': 'cost_anomaly_monitor',
                                    'category': 'hardening',
                                    'severity': 'medium',
                                    'title': 'Alerts on raised cost anomaly events',
                                    'hint': 'Create a Cost Explorer anomaly monitor and subscription with a '
                                            'nonempty ThresholdExpression and notification subscriber.',
                                    'sha': '7b388dff1e30233c876832cd0ab96cb61d36875545bb2f71192753bcc2d56fae'},
 'aws_costexplorer_prod_anomaly_monitor': {'kind': 'cost_anomaly_monitor',
                                           'category': 'hardening',
                                           'severity': 'medium',
                                           'title': 'Cost anomaly monitors alert for Prod and QA',
                                           'hint': 'Create a Cost Explorer anomaly monitor filtered to the Prod '
                                                   'cost tag and subscribe a notification target with a '
                                                   'threshold.',
                                           'sha': '113f369e12d8cc65d5c9a68e9e7785776e6187bf2c64f9ee59867b9e22cfdb00'},
 'aws_costexplorer_qa_anomaly_monitor': {'kind': 'cost_anomaly_monitor',
                                         'category': 'hardening',
                                         'severity': 'medium',
                                         'title': 'Cost anomaly monitors alert for Prod and QA',
                                         'hint': 'Create a Cost Explorer anomaly monitor filtered to the QA cost '
                                                 'tag and subscribe a notification target with a threshold.',
                                         'sha': '1f8ef40b819bd22137196af849b90e04ae4dd3099024f47e5b069530b8c92209'},
 'aws_cis_beanstalk_persistent_logs_s3': {'kind': 'elastic_beanstalk_environment',
                                          'category': 'hardening',
                                          'severity': 'medium',
                                          'title': 'Elastic Beanstalk publishes persistent logs to S3',
                                          'hint': 'Set Elastic Beanstalk aws:elasticbeanstalk:hostmanager '
                                                  'LogPublicationControl=true and select the S3 log bucket.',
                                          'sha': 'a5bb4978d320a3e912e3aca2faf6c74a4bb5590200afb2a28c4892a919611fd7'},
 'aws_cis_elasticbeanstalk_https_listener': {'kind': 'elastic_beanstalk_environment',
                                             'category': 'network',
                                             'severity': 'high',
                                             'title': 'Elastic Beanstalk load balancers serve HTTPS',
                                             'hint': 'Attach a valid certificate to an HTTPS listener and '
                                                     'redirect HTTP.',
                                             'sha': '55d9b5cdd0e36d9dde39788d162f276294506b45a95b0c0feb83f5148fa3d8e4'},
 'aws_cis_elasticbeanstalk_load_balancer_access_logs': {'kind': 'elastic_beanstalk_environment',
                                                        'category': 'hardening',
                                                        'severity': 'medium',
                                                        'title': 'Elastic Beanstalk load balancers log access',
                                                        'hint': 'Enable access logs on every associated load '
                                                                'balancer.',
                                                        'sha': '5e67b963225e9042791e9a5170c6a8179ffd1005430fdd5601597e12b3af369f'},
 'aws_backup_copy_encrypted': {'kind': 'backup_vault',
                               'category': 'hardening',
                               'severity': 'high',
                               'title': 'Remote backup copies are encrypted',
                               'hint': 'Use an enabled KMS key for every remote backup vault.',
                               'sha': '8e4594a6849ed22188b7cd7538ad99659892ad1bea2c4b6198da52507b9cd432'}}
PROPOSED_SPEC_SHA256 = {key: value["sha"] for key, value in SPECS.items()}

_SCOPE = re.compile(r"^[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]$")
_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12}):(.+)$")
_IDS = {
    "iam_role": "Arn", "cloudtrail_trail": "TrailARN", "codebuild_project": "name",
    "eks_cluster": "name", "cost_anomaly_monitor": "MonitorArn",
    "elastic_beanstalk_environment": "EnvironmentArn", "backup_vault": "BackupVaultArn",
    "backup_recovery_point": "RecoveryPointArn", "kms_key": "KeyArn",
    "cloudwatch_log_group": "arn", "cloudtrail_delivery_permission": "role_arn",
    "cost_anomaly_subscription": "SubscriptionArn", "eks_version_catalog": "region",
    "k8s_admission_policy": "cluster_arn",
}


def _context(index, *, allow_global=False):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS provider authority unavailable")
    scope = get(context, "scope", str)
    if not _SCOPE.fullmatch(scope) and not (allow_global and re.fullmatch(r'[0-9]{12}/global', scope)):
        raise Unavailable("AWS regional scope unavailable")
    return context, scope


def _arn(value, *, service=None, account=None, region=None):
    if not isinstance(value, str):
        raise Unavailable("malformed ARN")
    match = _ARN.fullmatch(value)
    if not match or (service and match.group(2) != service) or (account and match.group(4) != account) or (region and match.group(3) != region):
        raise Unavailable("malformed or foreign ARN")
    return match


def _rows(index, kind, scope, *, global_kind=False):
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("one complete collection required: " + kind)
    envelope = get(envelopes[0], "type", str)
    if envelope != kind:
        raise Unavailable("wrong collection kind: " + kind)
    env = envelopes[0]
    if global_kind:
        if env.get("global") is not True or env.get("account_id") != scope.split("/")[0]:
            raise Unavailable("account-global collection authority unavailable: " + kind)
    elif get(env, "scope", str) != scope or env.get("account_id", scope.split("/")[0]) != scope.split("/")[0]:
        raise Unavailable("foreign collection scope: " + kind)
    native = complete_items(index, kind)
    declared = get(env, "items", list)
    wrappers = get(index, kind, list)
    if (len(native) != len(declared) or len(native) != len(wrappers) or
            (env["status"] == "empty") != (not native)):
        raise Unavailable("collection completeness or projection mismatch: " + kind)
    for row, wrapper in zip(native, wrappers):
        if (get(wrapper, "type", str) != kind or get(wrapper, "data", dict) != row or
                (not global_kind and get(wrapper, "scope", str) != scope) or
                (global_kind and wrapper.get("account_id", scope.split("/")[0]) != scope.split("/")[0])):
            raise Unavailable("collection wrapper mismatch: " + kind)
    key = _IDS[kind]
    identities = [(get(row, "role_arn", str), get(row, "log_group_arn", str))
                  if kind == "cloudtrail_delivery_permission" else get(row, key, str)
                  for row in native]
    if any(not identity or (isinstance(identity, tuple) and not all(identity)) for identity in identities) or len(set(identities)) != len(identities):
        raise Unavailable("missing or duplicate resource identity: " + kind)
    return native


def _subject(item, index, kind, *, global_kind=False):
    context, scope = _context(index, allow_global=global_kind)
    rows = _rows(index, kind, scope, global_kind=global_kind)
    key = _IDS[kind]
    identity = get(item, key, str)
    if sum(get(row, key, str) == identity and row == item for row in rows) != 1:
        raise Unavailable("resource not bound to complete scoped inventory")
    if key.endswith("Arn") or key == "Arn":
        _arn(identity, account=scope.split("/")[0], region=None if global_kind or kind == "cost_anomaly_monitor" else scope.split("/")[1])
    return context, scope, identity


def _policy(context, name):
    policy = get(context, "metadata.compliance_policy." + name, dict)
    if get(policy, "status", str) != "collected":
        raise Unavailable("approved policy unavailable: " + name)
    return policy


def _scope_item(item, index):
    _, scope = _context(index)
    if get(item, "scope", str) != scope:
        raise Unavailable("foreign scope subject")
    return scope


def _document(value):
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value))
        except (ValueError, TypeError) as exc:
            raise Unavailable("malformed IAM trust document") from exc
    if not isinstance(value, dict):
        raise Unavailable("IAM trust document unavailable")
    statements = get(value, "Statement")
    if isinstance(statements, dict):
        statements = [statements]
    return list_of_objects(statements)


def _external_ids(role):
    values = set()
    missing = False
    for statement in _document(get(role, "AssumeRolePolicyDocument")):
        if get(statement, "Effect", str) not in ("Allow", "Deny"):
            raise Unavailable("malformed trust effect")
        if statement["Effect"] != "Allow":
            continue
        principal = get(statement, "Principal", dict)
        aws = get(principal, "AWS")
        if isinstance(aws, str):
            aws = [aws]
        if not isinstance(aws, list) or not aws or any(not isinstance(x, str) or not x for x in aws):
            raise Unavailable("partner principal unavailable")
        if "Condition" not in statement:
            missing = True
            continue
        condition = get(statement, "Condition", dict)
        if "StringEquals" not in condition:
            missing = True
            continue
        equal = get(condition, "StringEquals", dict)
        if "sts:ExternalId" not in equal:
            missing = True
            continue
        external = get(equal, "sts:ExternalId")
        if isinstance(external, str):
            external = [external]
        if not isinstance(external, list) or any(not isinstance(x, str) for x in external):
            raise Unavailable("external ID malformed")
        if not external or any(not x.strip() for x in external):
            missing = True
        values.update(x for x in external if x.strip())
    return values, missing


def _partner(item, index):
    context, scope, identity = _subject(item, index, "iam_role", global_kind=True)
    policy = _policy(context, "partner_roles")
    approved = list_of_objects(get(policy, "customer_roles", list))
    if not approved:
        return "NOT_APPLICABLE", {"reason": "no inventoried customer roles"}
    role_map = {get(role, "Arn", str): role for role in _rows(index, "iam_role", scope, global_kind=True)}
    customer_sets = {}
    selected = set()
    missing = []
    for entry in approved:
        arn = get(entry, "role_arn", str)
        customer = get(entry, "customer_id", str)
        _arn(arn, service="iam", account=scope.split("/")[0])
        if not customer or arn in selected or arn not in role_map:
            raise Unavailable("customer role mapping incomplete or duplicated")
        selected.add(arn)
        ids, bypass = _external_ids(role_map[arn])
        customer_sets.setdefault(customer, set()).update(ids)
        if not ids or bypass:
            missing.append(arn)
    if identity not in selected:
        return "NOT_APPLICABLE", {"reason": "role is outside approved customer-role inventory"}
    owners = {}
    for customer, ids in customer_sets.items():
        for value in ids:
            owners.setdefault(value, set()).add(customer)
    duplicated = sorted(value for value, customers in owners.items() if len(customers) > 1)
    return result(bool(duplicated or missing), role_arn=identity, duplicate_external_ids=duplicated,
                  customer_roles_without_external_id=sorted(missing),
                  semantics="Approved customer-role trust documents; effective assume-role access unassessed")


def _trail_status(trail):
    status = get(trail, "Status", dict)
    if get(status, "collection_status", str) != "collected":
        raise Unavailable("CloudTrail GetTrailStatus unavailable")
    return get(status, "IsLogging", bool)


def _selectors_cover(trail):
    selectors = get(trail, "EventSelectors", dict)
    if get(selectors, "collection_status", str) != "collected":
        raise Unavailable("CloudTrail selectors unavailable")
    if "EventSelectors" not in selectors and "AdvancedEventSelectors" not in selectors:
        raise Unavailable("CloudTrail selector lists unavailable")
    basic = list_of_objects(get(selectors, "EventSelectors", list)) if "EventSelectors" in selectors else []
    advanced = list_of_objects(get(selectors, "AdvancedEventSelectors", list)) if "AdvancedEventSelectors" in selectors else []
    covered = False
    for entry in basic:
        included = get(entry, "IncludeManagementEvents", bool)
        read_write = get(entry, "ReadWriteType", str)
        excluded = get(entry, "ExcludeManagementEventSources", list) if "ExcludeManagementEventSources" in entry else []
        if any(not isinstance(value, str) or not value for value in excluded):
            raise Unavailable("malformed management event exclusion")
        if read_write not in {"All", "ReadOnly", "WriteOnly"}:
            raise Unavailable("unrecognized CloudTrail management selector")
        if included and read_write == "All" and not excluded:
            covered = True
    for entry in advanced:
        fields = list_of_objects(get(entry, "FieldSelectors", list))
        event_category = [row for row in fields if get(row, "Field", str) == "eventCategory"]
        read_only = [row for row in fields if get(row, "Field", str) == "readOnly"]
        if any(get(row, "Field", str) not in {"eventCategory", "readOnly"} for row in fields):
            continue
        if len(event_category) == 1 and get(event_category[0], "Equals", list) == ["Management"] and not read_only:
            covered = True
        if len(event_category) == 1 and get(event_category[0], "Equals", list) == ["Management"] and len(read_only) == 1 and set(get(read_only[0], "Equals", list)) == {"true", "false"}:
            covered = True
    return covered


def _auth_events(item, index):
    scope = _scope_item(item, index)
    context, _ = _context(index)
    enabled = get(context, "metadata.enabled_regions", list)
    if any(not isinstance(x, str) for x in enabled) or scope.split("/")[1] not in enabled:
        raise Unavailable("enabled-Region inventory unavailable")
    trails = _rows(index, "cloudtrail_trail", scope)
    covered = []
    for trail in trails:
        arn = get(trail, "TrailARN", str)
        _arn(arn, service="cloudtrail", account=scope.split("/")[0])
        if _trail_status(trail) and _selectors_cover(trail):
            covered.append(arn)
    return result(not covered, scope=scope, covering_trails=covered,
                  semantics="Management read/write selectors and current logging state; event delivery unassessed")


def _delivery_permission(index, scope, role_arn, log_arn):
    rows = _rows(index, "cloudtrail_delivery_permission", scope)
    matches = [x for x in rows if get(x, "role_arn", str) == role_arn and get(x, "log_group_arn", str) == log_arn]
    if len(matches) != 1:
        raise Unavailable("CloudTrail delivery-role simulation unavailable")
    if get(matches[0], "simulation_context_complete", bool) is not True:
        raise Unavailable("IAM simulation context incomplete")
    if get(matches[0], "trust_valid", bool) is not True:
        return False
    decisions = get(matches[0], "decisions", dict)
    values = []
    for action in ("logs:CreateLogStream", "logs:PutLogEvents"):
        decision = get(decisions, action, str)
        if decision not in ("allowed", "explicitDeny", "implicitDeny"):
            raise Unavailable("unrecognized IAM simulation decision")
        values.append(decision)
    return all(x == "allowed" for x in values)


def _cloudwatch_integration(item, index):
    _, scope, identity = _subject(item, index, "cloudtrail_trail")
    if not _trail_status(item):
        return "NOT_APPLICABLE", {"reason": "trail is not actively logging", "trail_arn": identity}
    destination = get(item, "CloudWatchLogsLogGroupArn", str)
    role = get(item, "CloudWatchLogsRoleArn", str)
    if not destination or not role:
        return result(True, trail_arn=identity, reason="active trail lacks log group or delivery role")
    _arn(destination, service="logs", account=scope.split("/")[0], region=scope.split("/")[1])
    _arn(role, service="iam", account=scope.split("/")[0])
    allowed = _delivery_permission(index, scope, role, destination)
    return result(not allowed, trail_arn=identity, log_group_arn=destination, simulation_allowed=allowed,
                  semantics="IAM simulation for CloudTrail log stream creation and event delivery")


def _key_state(index, scope, key_id):
    keys = _rows(index, "kms_key", scope)
    match = [row for row in keys if get(row, "KeyArn", str) == key_id or get(row, "KeyId", str) == key_id]
    if len(match) != 1:
        raise Unavailable("linked KMS key not in complete regional inventory")
    metadata = get(match[0], "Metadata", dict)
    if get(metadata, "collection_status", str) != "collected":
        raise Unavailable("KMS DescribeKey unavailable")
    key = get(metadata, "KeyMetadata", dict)
    state = get(key, "KeyState", str)
    manager = get(key, "KeyManager", str)
    if state not in {"Enabled", "Disabled", "PendingDeletion", "PendingImport", "Unavailable", "Creating", "Updating"} or manager not in {"CUSTOMER", "AWS"}:
        raise Unavailable("unrecognized KMS key state or manager")
    return state == "Enabled" and manager == "CUSTOMER"


def _destination_kms(item, index):
    _, scope, identity = _subject(item, index, "cloudtrail_trail")
    if not _trail_status(item):
        return "NOT_APPLICABLE", {"reason": "trail is not actively logging", "trail_arn": identity}
    key_id = get(item, "KmsKeyId", str)
    if not key_id:
        return result(True, trail_arn=identity, reason="active trail has no KMS key")
    trail_safe = _key_state(index, scope, key_id)
    if not trail_safe:
        return result(True, trail_arn=identity, reason="trail KMS key is not an enabled customer-managed key")
    log_arn = get(item, "CloudWatchLogsLogGroupArn", str)
    if not log_arn:
        return result(not trail_safe, trail_arn=identity, semantics="No linked CloudWatch log group")
    groups = _rows(index, "cloudwatch_log_group", scope)
    matches = [row for row in groups if get(row, "arn", str).rstrip(":*") == log_arn.rstrip(":*")]
    if len(matches) != 1:
        raise Unavailable("linked CloudWatch log group unavailable")
    log_key = get(matches[0], "kmsKeyId", str)
    if not log_key:
        return result(True, trail_arn=identity, reason="linked log group has no KMS key")
    group_safe = _key_state(index, scope, log_key)
    return result(not (trail_safe and group_safe), trail_arn=identity, log_group_arn=log_arn,
                  semantics="Current customer-managed key metadata, not delivered log events")


def _codebuild(item, index):
    context, _, identity = _subject(item, index, "codebuild_project")
    policy = _policy(context, "codebuild_sensitive_values")
    approved = get(policy, "approved_secret_values", list)
    patterns = get(policy, "sensitive_name_patterns", list)
    if (not approved and not patterns or any(not isinstance(x, str) or not x for x in approved + patterns)):
        raise Unavailable("sensitive value and name policy unavailable")
    try:
        compiled = [re.compile(x, re.I) for x in patterns]
    except re.error as exc:
        raise Unavailable("invalid sensitive name pattern") from exc
    configuration = get(item, "Configuration", dict)
    if get(configuration, "collection_status", str) != "collected":
        raise Unavailable("CodeBuild project detail unavailable")
    projects = list_of_objects(get(configuration, "projects", list))
    if len(projects) != 1 or get(projects[0], "name", str) != identity:
        raise Unavailable("CodeBuild project detail mismatch")
    variables = list_of_objects(get(projects[0], "environment.environmentVariables", list))
    matched = []
    for variable in variables:
        name = get(variable, "name", str)
        typ = get(variable, "type", str)
        if not name or typ not in {"PLAINTEXT", "PARAMETER_STORE", "SECRETS_MANAGER"}:
            raise Unavailable("malformed CodeBuild variable")
        if typ != "PLAINTEXT":
            continue
        value = get(variable, "value", str)
        if value in approved or any(pattern.search(name) for pattern in compiled):
            matched.append(name)
    return result(bool(matched), project_name=identity, sensitive_plaintext_variable_names=sorted(matched),
                  semantics="Approved exact values and configured name patterns; values omitted from finding")


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+", value):
        raise Unavailable("malformed Kubernetes version")
    return tuple(map(int, value.split(".")))


def _eks_version(item, index):
    context, _, identity = _subject(item, index, "eks_cluster")
    cluster = get(item, "Cluster", dict)
    if get(cluster, "collection_status", str) != "collected":
        raise Unavailable("EKS DescribeCluster unavailable")
    detail = get(cluster, "cluster", dict)
    if get(detail, "name", str) != identity:
        raise Unavailable("EKS cluster detail mismatch")
    return context, identity, _version(get(detail, "version", str))


def _eks_floor(item, index):
    context, identity, version = _eks_version(item, index)
    floor = _version(get(_policy(context, "eks_version_floor"), "min_version", str))
    return result(version < floor, cluster_name=identity, version="%d.%d" % version,
                  approved_floor="%d.%d" % floor)


def _eks_catalog(item, index):
    context, identity, version = _eks_version(item, index)
    scope = get(context, "scope", str)
    policy = _policy(context, "eks_version_support")
    allowed = get(policy, "allowed_support_types", list)
    if not allowed or any(x not in {"STANDARD", "EXTENDED"} for x in allowed):
        raise Unavailable("EKS support-mode policy unavailable")
    rows = _rows(index, "eks_version_catalog", scope)
    if len(rows) != 1 or get(rows[0], "region", str) != scope.split("/")[1]:
        raise Unavailable("EKS regional version catalogue unavailable")
    versions = list_of_objects(get(rows[0], "versions", list))
    found = []
    native = rows[0].get('_provenance', {}).get('source_operation') == 'DescribeClusterVersions'
    for row in versions:
        ver = _version(get(row, "clusterVersion", str))
        if native:
            value = get(row, 'versionStatus', str)
            if value not in ('STANDARD_SUPPORT', 'EXTENDED_SUPPORT', 'UNSUPPORTED'):
                raise Unavailable('unrecognized native EKS version status')
            status = 'UNSUPPORTED' if value == 'UNSUPPORTED' else 'SUPPORTED'
            support = {'STANDARD_SUPPORT': 'STANDARD', 'EXTENDED_SUPPORT': 'EXTENDED', 'UNSUPPORTED': None}[value]
        else:
            status = get(row, "status", str)
            support = get(row, "supportType", str)
        if status not in {"SUPPORTED", "UNSUPPORTED"} or (support not in {"STANDARD", "EXTENDED"} and not (native and status == 'UNSUPPORTED')):
            raise Unavailable("unrecognized EKS version catalogue entry")
        if ver == version:
            found.append({'status': status, 'supportType': support})
    if len(found) > 1:
        raise Unavailable("duplicate EKS catalogue version")
    if not found:
        return result(True, cluster_name=identity, reason="cluster version absent from complete EKS catalogue")
    return result(found[0]["status"] != "SUPPORTED" or found[0]["supportType"] not in allowed,
                  cluster_name=identity, version="%d.%d" % version, support_type=found[0]["supportType"])


def _webhook_covers(webhook, approved):
    if get(webhook, "failurePolicy", str) != "Fail":
        return False
    for selector in ("namespaceSelector", "objectSelector"):
        if selector in webhook and get(webhook, selector, dict):
            return False
    if "matchConditions" in webhook and get(webhook, "matchConditions", list):
        return False
    client = get(webhook, "clientConfig", dict)
    if "service" not in client and "url" in client:
        get(client, "url", str)
        return False
    service = get(client, "service", dict)
    name = get(service, "name", str)
    namespace = get(service, "namespace", str)
    if (namespace, name) not in approved:
        return False
    rules = list_of_objects(get(webhook, "rules", list))
    for rule in rules:
        operations = get(rule, "operations", list)
        groups = get(rule, "apiGroups", list)
        versions = get(rule, "apiVersions", list)
        resources = get(rule, "resources", list)
        rule_scope = get(rule, "scope", str) if "scope" in rule else "*"
        if rule_scope not in {"*", "Namespaced", "Cluster"}:
            raise Unavailable("unrecognized admission rule scope")
        if (all(isinstance(x, str) for x in operations + groups + versions + resources) and
                rule_scope != "Cluster" and
                ("CREATE" in operations or "*" in operations) and ("" in groups or "*" in groups) and
                ("v1" in versions or "*" in versions) and ("pods" in resources or "*" in resources)):
            return True
    return False


def _eks_image(item, index):
    context, _, identity = _subject(item, index, "eks_cluster")
    if get(item, "Cluster.collection_status", str) != "collected" or get(item, "Cluster.cluster.name", str) != identity:
        raise Unavailable("EKS cluster detail unavailable or mismatched")
    arn = get(item, "Cluster.cluster.arn", str)
    _arn(arn, service="eks", account=get(context, "scope", str).split("/")[0],
         region=get(context, "scope", str).split("/")[1])
    policy = _policy(context, "eks_image_integrity")
    designated = get(policy, "designated_cluster_arns", list)
    approved_rows = list_of_objects(get(policy, "approved_verifier_services", list))
    approved = {(get(x, "namespace", str), get(x, "name", str)) for x in approved_rows}
    if not approved or any(not x[0] or not x[1] for x in approved) or any(not isinstance(x, str) for x in designated):
        raise Unavailable("approved image verifier inventory unavailable")
    if arn not in designated:
        return "NOT_APPLICABLE", {"reason": "cluster outside designated image-integrity scope"}
    rows = _rows(index, "k8s_admission_policy", get(context, "scope", str))
    matches = [row for row in rows if get(row, "cluster_arn", str) == arn]
    if len(matches) != 1:
        raise Unavailable("cluster admission policy inventory unavailable")
    configurations = list_of_objects(get(matches[0], "validating_webhook_configurations", list))
    covers = []
    for config in configurations:
        config_name = get(config, "metadata.name", str)
        for webhook in list_of_objects(get(config, "webhooks", list)):
            if _webhook_covers(webhook, approved):
                covers.append(config_name)
    return result(not covers, cluster_name=identity, covering_webhooks=sorted(set(covers)),
                  semantics="Admission signature-verifier routing only; runtime monitoring remains manual")

def _subscriptions(index, scope):
    subscriptions = _rows(index, "cost_anomaly_subscription", scope, global_kind=True)
    for sub in subscriptions:
        monitors = get(sub, "MonitorArnList", list)
        subscribers = list_of_objects(get(sub, "Subscribers", list))
        threshold = get(sub, "ThresholdExpression", dict)
        if (not all(isinstance(x, str) and x for x in monitors) or len(set(monitors)) != len(monitors) or
                any(not get(x, "Address", str) or get(x, "Type", str) not in {"EMAIL", "SNS"} for x in subscribers)):
            raise Unavailable("malformed cost anomaly subscription")
        if "And" in threshold or "Or" in threshold or "Dimensions" in threshold or "Tags" in threshold or "CostCategories" in threshold:
            pass
        elif threshold:
            raise Unavailable("unrecognized threshold expression")
    return subscriptions


def _tag_filter(specification, key, value):
    if not isinstance(specification, dict):
        raise Unavailable("monitor specification unavailable")
    tags = get(specification, "Tags", dict)
    return get(tags, "Key", str) == key and value in get(tags, "Values", list) and get(tags, "MatchOptions", list) in (["EQUALS"], [])


def _cost(item, index, mode):
    scope = _scope_item(item, index)
    context, _ = _context(index)
    monitors = _rows(index, "cost_anomaly_monitor", scope, global_kind=True)
    subscriptions = _subscriptions(index, scope)
    policy = _policy(context, "cost_anomaly_alerts")
    approved = get(policy, "approved_recipients", list)
    if not approved or any(not isinstance(x, str) or not x for x in approved):
        raise Unavailable("approved cost-alert recipient inventory unavailable")
    candidates = []
    if mode in {"prod", "qa"}:
        key = get(policy, "cost_allocation_tag_key", str)
        value = get(policy, mode + "_tag_value", str)
        if not key or not value:
            raise Unavailable("approved cost-allocation tag unavailable")
    for monitor in monitors:
        arn = get(monitor, "MonitorArn", str)
        _arn(arn, service="ce", account=scope.split("/")[0])
        # GetAnomalyMonitors lists existing monitors; it has no Status member.
        if mode in {"prod", "qa"}:
            if get(monitor, "MonitorType", str) != "CUSTOM":
                continue
            if not _tag_filter(get(monitor, "MonitorSpecification", dict), key, value):
                continue
        candidates.append(arn)
    valid = []
    for sub in subscriptions:
        monitor_arns = get(sub, "MonitorArnList", list)
        subscribers = list_of_objects(get(sub, "Subscribers", list))
        threshold = get(sub, "ThresholdExpression", dict)
        if not threshold or not subscribers:
            continue
        if mode == "alert" and not all(get(recipient, "Address", str) in approved for recipient in subscribers):
            continue
        if mode in {"prod", "qa"} and not any(get(recipient, "Address", str) in approved for recipient in subscribers):
            continue
        valid.extend(arn for arn in monitor_arns if arn in candidates)
    return result(not valid, scope=scope, matching_active_monitors=sorted(set(candidates)),
                  thresholded_subscribed_monitors=sorted(set(valid)),
                  semantics="Complete Cost Explorer configuration and approved subscriber inventory; raised events unassessed")


def _beanstalk(item, index):
    _, scope, arn = _subject(item, index, "elastic_beanstalk_environment")
    status = get(item, "Status", str)
    if status not in {"Launching", "Updating", "Ready", "Terminating", "Terminated"}:
        raise Unavailable("unrecognized Beanstalk environment state")
    if status in {"Terminating", "Terminated"}:
        return scope, arn, False
    return scope, arn, True


def _persistent_logs(item, index):
    _, arn, active = _beanstalk(item, index)
    if not active:
        return "NOT_APPLICABLE", {"reason": "environment is terminating or terminated"}
    configuration = get(item, "Configuration", dict)
    if get(configuration, "collection_status", str) != "collected":
        raise Unavailable("Beanstalk configuration unavailable")
    settings = list_of_objects(get(configuration, "ConfigurationSettings", list))
    if len(settings) != 1 or get(settings[0], "EnvironmentName", str) != get(item, "EnvironmentName", str):
        raise Unavailable("Beanstalk environment configuration mismatch")
    if get(configuration, "hostmanager_options_complete", bool) is not True:
        raise Unavailable("hostmanager option inventory incomplete")
    options = list_of_objects(get(settings[0], "OptionSettings", list))
    selected = [get(option, "Value", str) for option in options if
                get(option, "Namespace", str) == "aws:elasticbeanstalk:hostmanager" and
                get(option, "OptionName", str) == "LogPublicationControl"]
    if len(selected) > 1 or (selected and selected[0] not in {"true", "false"}):
        raise Unavailable("LogPublicationControl unavailable")
    if not selected or selected[0] == "false":
        return result(True, environment_arn=arn, reason="log publication disabled")
    destination = get(item, "S3LogDestination", dict)
    if get(destination, "collection_status", str) != "collected":
        raise Unavailable("S3 log destination resolution unavailable")
    bucket = get(destination, "bucket", str)
    prefix = get(destination, "prefix", str)
    resolved = get(destination, "resolved", bool)
    if not bucket or prefix.startswith("/"):
        raise Unavailable("malformed S3 log destination")
    return result(not resolved, environment_arn=arn, log_bucket=bucket, log_prefix=prefix,
                  semantics="Configured publication and S3 destination resolution; retention not measured")


def _load_balancers(item, index):
    _, arn, active = _beanstalk(item, index)
    if not active:
        return arn, None
    resources = get(item, "EnvironmentResources", dict)
    if get(resources, "collection_status", str) != "collected":
        raise Unavailable("Beanstalk load-balancer association unavailable")
    lbs = list_of_objects(get(resources, "LoadBalancers", list))
    names = [get(lb, "Name", str) for lb in lbs]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise Unavailable("malformed or duplicate load balancer association")
    details = list_of_objects(get(item, "AssociatedLoadBalancers", list))
    by_name = {get(lb, "Name", str): lb for lb in details}
    if len(by_name) != len(details) or set(names) != set(by_name):
        raise Unavailable("load-balancer detail association incomplete")
    return arn, list(by_name.values())


def _https_listener(item, index):
    arn, lbs = _load_balancers(item, index)
    if lbs is None or not lbs:
        return "NOT_APPLICABLE", {"reason": "no active associated load balancer"}
    failing = []
    for lb in lbs:
        name = get(lb, "Name", str)
        kind = get(lb, "Type", str)
        if kind not in {"application", "network", "classic"}:
            raise Unavailable("unrecognized load balancer type")
        listeners = list_of_objects(get(lb, "Listeners", list))
        if not listeners:
            failing.append(name)
            continue
        tls = False
        plain_without_redirect = False
        for listener in listeners:
            protocol = get(listener, "Protocol", str)
            if protocol in {"HTTPS", "TLS"} or (kind == "classic" and protocol == "SSL"):
                if kind == "classic":
                    tls |= bool(get(listener, "SSLCertificateId", str))
                else:
                    certs = list_of_objects(get(listener, "Certificates", list))
                    tls |= any(bool(get(cert, "CertificateArn", str)) for cert in certs)
            elif protocol in {"HTTP", "TCP"}:
                actions = list_of_objects(get(listener, "DefaultActions", list))
                if not any(get(action, "Type", str) == "redirect" and
                           get(action, "RedirectConfig.Protocol", str) == "HTTPS" for action in actions):
                    plain_without_redirect = True
            else:
                raise Unavailable("unrecognized listener protocol")
        if not tls or plain_without_redirect:
            failing.append(name)
    return result(bool(failing), environment_arn=arn, noncompliant_load_balancers=sorted(failing),
                  semantics="Associated listener configuration; certificate validity and actual routing unassessed")


def _lb_access_logs(item, index):
    arn, lbs = _load_balancers(item, index)
    if lbs is None or not lbs:
        return "NOT_APPLICABLE", {"reason": "no active associated load balancer"}
    disabled = []
    for lb in lbs:
        kind = get(lb, "Type", str)
        if kind not in {"application", "network", "classic"}:
            raise Unavailable("unrecognized load balancer type")
        if kind == "classic":
            enabled = get(lb, "LoadBalancerAttributes.AccessLog.Enabled", bool)
        else:
            attrs = list_of_objects(get(lb, "Attributes", list))
            matches = [get(attr, "Value", str) for attr in attrs if
                       get(attr, "Key", str) == "access_logs.s3.enabled"]
            if len(matches) != 1 or matches[0] not in {"true", "false"}:
                raise Unavailable("access-log attribute unavailable")
            enabled = matches[0] == "true"
        if not enabled:
            disabled.append(get(lb, "Name", str))
    return result(bool(disabled), environment_arn=arn, disabled_access_log_load_balancers=sorted(disabled))


def _backup(item, index):
    context, scope, arn = _subject(item, index, "backup_vault")
    policy = _policy(context, "remote_backup_vaults")
    designated = get(policy, "vault_arns", list)
    if not designated or any(not isinstance(x, str) or not x for x in designated):
        raise Unavailable("designated remote backup vault inventory unavailable")
    for candidate in designated:
        _arn(candidate, service="backup", account=scope.split("/")[0], region=scope.split("/")[1])
    if arn not in designated:
        return "NOT_APPLICABLE", {"reason": "vault is outside designated remote-copy inventory"}
    configuration = get(item, "Configuration", dict)
    if get(configuration, "collection_status", str) != "collected":
        raise Unavailable("backup vault configuration unavailable")
    if get(configuration, "BackupVaultArn", str) != arn:
        raise Unavailable("backup vault detail identity mismatch")
    key_id = get(configuration, "EncryptionKeyArn", str)
    if not key_id:
        return result(True, backup_vault_arn=arn, reason="designated vault has no KMS key")
    key_safe = _key_state(index, scope, key_id)
    if not key_safe:
        return result(True, backup_vault_arn=arn, reason="vault KMS key is not enabled and customer-managed")
    points = _rows(index, "backup_recovery_point", scope)
    bad = []
    for point in points:
        point_vault = get(point, "BackupVaultArn", str)
        _arn(point_vault, service="backup", account=scope.split("/")[0], region=scope.split("/")[1])
        if point_vault != arn:
            continue
        created = get(point, "CreatedBy", dict)
        job = get(created, "CopyJobId", str)
        if job and not get(point, "IsEncrypted", bool):
            bad.append(get(point, "RecoveryPointArn", str))
    return result(not key_safe or bool(bad), backup_vault_arn=arn, unencrypted_copy_points=sorted(bad),
                  semantics="Enabled vault KMS key and copied recovery-point encryption flags")


_EVALUATORS = {
    "aws_partner_role_external_ids_unique": (_partner, ["iam_role"], "resource"),
    "aws.pci.cloudtrail.authentication_events": (_auth_events, ["cloudtrail_trail"], "scope"),
    "aws_fedramp_cloudtrail_cloudwatch_integration": (_cloudwatch_integration, ["cloudtrail_trail", "cloudtrail_delivery_permission"], "resource"),
    "aws_fedramp_cloudtrail_destination_kms": (_destination_kms, ["cloudtrail_trail", "kms_key", "cloudwatch_log_group"], "resource"),
    "aws_nist_codebuild_project_plaintext_env_variables_no_sensitive_aws_values": (_codebuild, ["codebuild_project"], "resource"),
    "aws_eks_cluster_current_supported_version": (_eks_floor, ["eks_cluster"], "resource"),
    "aws_eks_cluster_supported_version_catalog": (_eks_catalog, ["eks_cluster", "eks_version_catalog"], "resource"),
    "aws_eks_runtime_image_integrity": (_eks_image, ["eks_cluster", "k8s_admission_policy"], "resource"),
    "aws_costexplorer_anomaly_alert": (lambda item, index: _cost(item, index, "alert"), ["cost_anomaly_monitor", "cost_anomaly_subscription"], "scope"),
    "aws_costexplorer_prod_anomaly_monitor": (lambda item, index: _cost(item, index, "prod"), ["cost_anomaly_monitor", "cost_anomaly_subscription"], "scope"),
    "aws_costexplorer_qa_anomaly_monitor": (lambda item, index: _cost(item, index, "qa"), ["cost_anomaly_monitor", "cost_anomaly_subscription"], "scope"),
    "aws_cis_beanstalk_persistent_logs_s3": (_persistent_logs, ["elastic_beanstalk_environment"], "resource"),
    "aws_cis_elasticbeanstalk_https_listener": (_https_listener, ["elastic_beanstalk_environment"], "resource"),
    "aws_cis_elasticbeanstalk_load_balancer_access_logs": (_lb_access_logs, ["elastic_beanstalk_environment"], "resource"),
    "aws_backup_copy_encrypted": (_backup, ["backup_vault", "backup_recovery_point", "kms_key"], "resource"),
}

for _id, (_evaluator, _dependencies, _target) in _EVALUATORS.items():
    _spec = SPECS[_id]
    @register(_id, "aws", _spec["category"] if _spec["category"] in {"hardening", "network", "least_privilege", "exposure", "iam_graph"} else "hardening",
              _spec["kind"], _spec["title"], _spec["severity"], "CM-6", _spec["hint"],
              target=_target, dependencies=_dependencies)
    def _evaluate(item, index, evaluator=_evaluator):
        return evaluator(item, index)
    _evaluate.__name__ = _id.replace(".", "_")
    if _spec["category"] not in {"hardening", "network", "least_privilege", "exposure", "iam_graph"}:
        CHECKS[-1] = replace(CHECKS[-1], category=_spec["category"])
