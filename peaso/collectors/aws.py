"""Read-only AWS configuration inventory; all clients remain inside collection.

There is deliberately no legacy scanner import: importing it installs process
signal handlers, and its normal execution may create Access Analyzers.
"""
from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import re
import threading
import time
import math
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import date, datetime
from urllib.parse import unquote


def _bound(options, key, default, minimum=1, maximum=10000):
    value = options.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{key} must be an integer between {minimum} and {maximum}")
    return value


def _optional_limit(options, key):
    value = options.get(key)
    if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
        raise ValueError(f"{key} must be a positive integer or null")
    return value


class ReadFailure(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


def _failure(exc):
    if isinstance(exc, ReadFailure):
        return exc
    response = getattr(exc, "response", None)
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    code = error.get("Code", "") if isinstance(error, dict) else ""
    # Never serialize exception messages: providers sometimes echo request data.
    code = code if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", code) else "read_failed"
    if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "ForbiddenException", "UnrecognizedClientException", "InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException"}:
        status = "denied"
    elif "timeout" in type(exc).__name__.lower() or isinstance(exc, TimeoutError):
        status = "timeout"
    elif isinstance(exc, (ValueError, TypeError, KeyError)):
        status, code = "malformed", "malformed_response"
    else:
        status = "unknown"
    return ReadFailure(status, code)


_SECRET_FIELDS = {"SecretAccessKey", "SessionToken", "Token", "WebIdentityToken", "SecretString", "SecretBinary", "Password", "MasterUserPassword", "PreSharedKey", "CustomerGatewayConfiguration", "ClientSecret", "clientSecret", "PrivateKey", "Base32StringSeed", "QRCodePNG", "aws_secret_access_key", "aws_session_token", "aws_access_key_id", "Credentials", "Environment", "UserData", "Code", "ResponseMetadata", "NextToken", "Marker", "ContinuationToken", "NextContinuationToken"}
_LABEL_CONTAINERS = {"Tags", "tags", "TagSet", "tagSet", "TagList", "tagList", "Labels", "labels", "Annotations", "annotations"}
_ENVIRONMENT_CONTAINERS = {"environment", "environmentVariables", "EnvironmentVariables"}
_PROHIBITED_VALUE_OPERATIONS = {"get_secret_value", "batch_get_secret_value", "get_object", "get_log_events", "filter_log_events", "get_parameter", "get_parameters", "get_parameters_by_path", "get_password_data", "get_authorization_token"}


def _credential_label(label):
    if not isinstance(label, str):
        return False
    normalized = re.sub(r"[^a-z0-9]", "", label.lower())
    fragments = ("password", "passwd", "dbpass", "apikey", "apitoken", "accesskey", "accesstoken", "refreshtoken", "sessiontoken", "securitytoken", "idtoken", "clientsecret", "secretaccesskey", "privatekey", "sshkey", "authorization", "bearer", "credentials")
    return normalized in {"token", "secret", "credential"} or normalized.endswith("secret") or any(fragment in normalized for fragment in fragments)


def _safe(value, *, _labels=False, _environment=False):
    if isinstance(value, dict):
        result = {}
        label = next((value[k] for k in ("Key", "key", "Name", "name", "HeaderName", "headerName") if isinstance(value.get(k), str)), None)
        sensitive_record = _environment or _credential_label(label)
        redacted_fields = []
        for key, val in value.items():
            if key in _SECRET_FIELDS:
                continue
            typed_value = key in {"Value", "value", "HeaderValue", "headerValue"} and sensitive_record
            sensitive_map_value = _labels and _credential_label(key)
            if (typed_value or sensitive_map_value) and not isinstance(val, bool):
                result[key] = "[redacted]"
                redacted_fields.append(key)
                continue
            if key == "AccessKeyId":
                result["AccessKeyFingerprint"] = hashlib.sha256(str(val).encode()).hexdigest()
            else:
                result[key] = _safe(val, _labels=key in _LABEL_CONTAINERS or _labels,
                    _environment=key in _ENVIRONMENT_CONTAINERS or _environment)
        if redacted_fields:
            coverage = result.setdefault("_coverage", {})
            if not isinstance(coverage, dict):
                coverage = result["_coverage"] = {}
            for key in redacted_fields:
                coverage[key] = {"status": "not_collected", "reason": "credential_metadata_redacted"}
        return result
    if isinstance(value, (list, tuple)):
        return [_safe(x, _labels=_labels, _environment=_environment) for x in value]
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, bytes):
        return "[omitted binary]"
    return value


@dataclass
class ReadResult:
    items: list = field(default_factory=list)
    status: str = "collected"
    error: dict | None = None


class Requests:
    """Scan-local, single-flight request cache with one global attempt budget."""
    def __init__(self, options, *, sleep=time.sleep):
        self.max_calls = _optional_limit(options, "max_calls")
        self.max_pages = _optional_limit(options, "max_pages")
        self.max_items = _optional_limit(options, "max_resources")
        self.workers = _bound(options, "service_concurrency", 4, maximum=16)
        self.attempts = _bound(options, "retry_attempts", 3, maximum=5)
        self.timeout = _bound(options, "read_timeout", 15, maximum=120)
        self.connect_timeout = _bound(options, "connect_timeout", 5, maximum=30)
        self.calls = 0
        self.cache_hits = 0
        self._cache, self._clients, self._sessions = {}, {}, {}
        self._lock = threading.RLock()
        self._sleep = sleep
        deadline = options.get("deadline_seconds")
        if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline) or deadline <= 0):
            raise ValueError("deadline_seconds must be a finite positive number")
        self.deadline = time.monotonic() + deadline if deadline is not None else None
        self.cancel_event = options.get("cancel_event")
        if self.cancel_event is not None and not callable(getattr(self.cancel_event, "is_set", None)):
            raise ValueError("cancel_event must expose is_set()")
        self.evidence_generation_wait = _bound(options, "credential_report_wait_seconds", 60, maximum=300)
        self.evidence_generations = 0

    def check_deadline(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ReadFailure("not_collected", "collection_cancelled")
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise ReadFailure("timeout", "intentional_scan_deadline")

    def client(self, session, service, region):
        from botocore.config import Config
        key = (id(session), service, region)
        with self._lock:
            self._sessions[id(session)] = session
            if key not in self._clients:
                self._clients[key] = session.client(service, region_name=region, config=Config(
                    connect_timeout=self.connect_timeout, read_timeout=self.timeout,
                    retries={"total_max_attempts": 1, "mode": "standard"},
                    max_pool_connections=self.workers))
            return self._clients[key]

    def call(self, session, service, region, operation, *, _cache_refresh=False, **arguments):
        credential_exchange = service == "sts" and operation == "assume_role"
        evidence_generation = service == "iam" and operation == "generate_credential_report"
        readonly_name = operation.startswith(("get_", "list_", "describe_", "batch_get_", "batch_describe_"))
        if operation in _PROHIBITED_VALUE_OPERATIONS or (service, operation) not in READ_ACTIONS or not (readonly_name or credential_exchange or evidence_generation):
            raise ReadFailure("not_collected", "non_read_operation")
        key = (id(session), service, region, operation, json.dumps(arguments, sort_keys=True))
        with self._lock:
            if _cache_refresh and key in self._cache and self._cache[key].done():
                self._cache.pop(key)
            future = self._cache.get(key)
            owner = future is None
            if owner:
                future = self._cache[key] = Future()
            else:
                self.cache_hits += 1
        if not owner:
            return copy.deepcopy(future.result())
        try:
            self.check_deadline()
            with self._lock:
                if self.max_calls is not None and self.calls >= self.max_calls:
                    raise ReadFailure("not_collected", "call_limit")
            client = self.client(session, service, region)
            for attempt in range(self.attempts):
                with self._lock:
                    self.check_deadline()
                    if self.max_calls is not None and self.calls >= self.max_calls:
                        raise ReadFailure("not_collected", "call_limit")
                    self.calls += 1
                    if service == "iam" and operation == "generate_credential_report":
                        self.evidence_generations += 1
                try:
                    response = getattr(client, operation)(**arguments)
                    if not isinstance(response, dict):
                        raise ReadFailure("malformed", "malformed_response")
                    future.set_result(response)
                    return copy.deepcopy(response)
                except Exception as exc:
                    failure = _failure(exc)
                    if failure.code not in {"Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded", "SlowDown", "ServiceUnavailable", "InternalError"} or attempt + 1 == self.attempts:
                        raise failure from None
                    self._sleep(min(0.2 * (2 ** attempt), 2))
        except Exception as exc:
            failure = _failure(exc)
            future.set_exception(failure)
            raise failure from None

    def pages(self, session, service, region, operation, expression, **arguments):
        import jmespath
        items, seen = [], set()
        try:
            with self._lock:
                if self.max_calls is not None and self.calls >= self.max_calls and not any(key[:4] == (id(session), service, region, operation) for key in self._cache):
                    raise ReadFailure("not_collected", "call_limit")
            client = self.client(session, service, region)
            # SDK pagination metadata handles IAM Marker, S3 continuation,
            # CloudWatch nextToken, ELB NextMarker and multi-token APIs correctly.
            cfg = client.get_paginator(operation)._pagination_cfg if client.can_paginate(operation) else {}
            input_tokens = cfg.get("input_token", [])
            output_tokens = cfg.get("output_token", [])
            input_tokens = [input_tokens] if isinstance(input_tokens, str) else input_tokens
            output_tokens = [output_tokens] if isinstance(output_tokens, str) else output_tokens
            params = dict(arguments)
            page_number = 0
            while self.max_pages is None or page_number < self.max_pages:
                page_number += 1
                response = self.call(session, service, region, operation, **params)
                if operation == "describe_instances":
                    reservations = response.get("Reservations")
                    if not isinstance(reservations, list) or any(not isinstance(r, dict) or not isinstance(r.get("Instances"), list) for r in reservations):
                        raise ReadFailure("malformed", "malformed_response")
                batch = jmespath.search(expression, response)
                if not isinstance(batch, list):
                    raise ReadFailure("malformed", "malformed_response")
                remaining = self.max_items - len(items) if self.max_items is not None else None
                items.extend(batch[:remaining])
                more = cfg.get("more_results")
                tokens = tuple(jmespath.search(token, response) for token in output_tokens)
                if more and jmespath.search(more, response) and not any(tokens):
                    raise ReadFailure("malformed", "missing_pagination_token")
                has_more = any(tokens) and (not more or jmespath.search(more, response))
                if remaining is not None and (len(batch) > remaining or (len(items) == self.max_items and has_more)):
                    raise ReadFailure("not_collected", "resource_limit")
                if not has_more:
                    return ReadResult(items, "collected" if items else "empty")
                token_key = json.dumps(tokens)
                if token_key in seen:
                    raise ReadFailure("malformed", "repeated_pagination_token")
                seen.add(token_key)
                for name, token in zip(input_tokens, tokens):
                    if token is not None:
                        params[name] = token
            raise ReadFailure("not_collected", "page_limit")
        except Exception as exc:
            failure = _failure(exc)
            return ReadResult(items, "partial" if items else failure.status, {"code": failure.code, "cause_status": failure.status})

    def detail(self, session, service, region, operation, *, absent=(), **arguments):
        try:
            response = _safe(self.call(session, service, region, operation, **arguments))
            response["collection_status"] = "collected"
            return response
        except Exception as exc:
            failure = _failure(exc)
            if failure.code in absent:
                return {"collection_status": "empty", "absent": True, "error": {"code": failure.code}}
            return {"collection_status": failure.status, "error": {"code": failure.code}}


def _session(auth, region):
    """Resolve precisely the selected boto3 chain; never recover via default."""
    import boto3
    key_fields = ("aws_access_key_id", "aws_secret_access_key", "aws_session_token")
    selected_keys = any(auth.get(k) for k in key_fields)
    method = auth.get("method", "default")
    if method not in {"default", "auto", "sdk", "profile", "sso", "access_keys", "web_identity", "container", "instance", "task_role"}:
        raise ValueError("unsupported AWS authentication method")
    if method in {"profile", "sso"} and not auth.get("profile"):
        raise ValueError("selected profile authentication requires profile")
    if method == "access_keys" and not selected_keys:
        raise ValueError("selected access_keys authentication requires explicit credentials")
    if selected_keys and not all(auth.get(k) for k in key_fields[:2]):
        raise ValueError("explicit credentials require access key and secret key")
    if selected_keys and auth.get("profile"):
        raise ValueError("select profile or explicit credentials")
    kwargs = {"region_name": region}
    if selected_keys:
        kwargs.update({k: auth[k] for k in key_fields if auth.get(k)})
    elif auth.get("profile"):
        kwargs["profile_name"] = auth["profile"]
    session = boto3.Session(**kwargs)
    # Freeze the selected context for this bounded scan. This prevents provider
    # refresh/chain changes in concurrently constructed clients.
    provider_names = {"web_identity": "assume-role-with-web-identity", "container": "container-role", "instance": "iam-role"}
    if method == "task_role" and (selected_keys or auth.get("profile")):
        raise ValueError("task_role selects the platform runtime credential context")
    if method in provider_names:
        if selected_keys or auth.get("profile"):
            raise ValueError("selected metadata/web identity provider cannot be combined with keys or profile")
        credentials = session._session.get_component("credential_provider").get_provider(provider_names[method]).load()
    else:
        credentials = session.get_credentials()
    if credentials is None:
        raise ReadFailure("denied", "credentials_unavailable")
    if method == "task_role" and getattr(credentials, "method", None) not in {"env", "container-role", "iam-role", "assume-role-with-web-identity"}:
        raise ReadFailure("denied", "platform_role_credentials_unavailable")
    frozen = credentials.get_frozen_credentials()
    if not frozen.access_key or not frozen.secret_key:
        raise ReadFailure("denied", "credentials_unavailable")
    if method == "task_role" and not frozen.token:
        raise ReadFailure("denied", "platform_role_session_token_required")
    pinned = boto3.Session(aws_access_key_id=frozen.access_key,
        aws_secret_access_key=frozen.secret_key, aws_session_token=frozen.token,
        region_name=region or session.region_name or "us-east-1")
    return pinned, getattr(credentials, "method", "selected")


def _assume(requests, session, region, target, defaults):
    import boto3
    target = {"role_arn": target} if isinstance(target, str) else dict(target)
    arn = target.get("role_arn")
    if not isinstance(arn, str) or not re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/.+", arn):
        raise ValueError("role_arn must be an IAM role ARN")
    name = target.get("role_session_name", defaults.get("role_session_name", "peaso-read-only"))
    if not isinstance(name, str) or not re.fullmatch(r"[\w+=,.@-]{2,64}", name):
        raise ValueError("invalid role_session_name")
    params = {"RoleArn": arn, "RoleSessionName": name}
    external = target.get("external_id", defaults.get("external_id"))
    if external:
        params["ExternalId"] = external
    response = requests.call(session, "sts", region, "assume_role", **params)
    credentials = response.get("Credentials", {})
    if not all(credentials.get(k) for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")):
        raise ReadFailure("malformed", "malformed_assume_role")
    return boto3.Session(aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"], region_name=region)


# type -> (service, list operation, native result path). No resource contents,
# database records, secret values, log events or function code are read.
SPECS = {
    "vpc": ("ec2", "describe_vpcs", "Vpcs"),
    "subnet": ("ec2", "describe_subnets", "Subnets"),
    "route_table": ("ec2", "describe_route_tables", "RouteTables"),
    "security_group": ("ec2", "describe_security_groups", "SecurityGroups"),
    "network_acl": ("ec2", "describe_network_acls", "NetworkAcls"),
    "network_interface": ("ec2", "describe_network_interfaces", "NetworkInterfaces"),
    "instance": ("ec2", "describe_instances", "Reservations[].Instances[]"),
    "ebs_volume": ("ec2", "describe_volumes", "Volumes"),
    "internet_gateway": ("ec2", "describe_internet_gateways", "InternetGateways"),
    "nat_gateway": ("ec2", "describe_nat_gateways", "NatGateways"),
    "vpc_endpoint": ("ec2", "describe_vpc_endpoints", "VpcEndpoints"),
    "vpc_peering": ("ec2", "describe_vpc_peering_connections", "VpcPeeringConnections"),
    "transit_gateway": ("ec2", "describe_transit_gateways", "TransitGateways"),
    "transit_gateway_attachment": ("ec2", "describe_transit_gateway_attachments", "TransitGatewayAttachments"),
    "transit_gateway_route_table": ("ec2", "describe_transit_gateway_route_tables", "TransitGatewayRouteTables"),
    "vpn_connection": ("ec2", "describe_vpn_connections", "VpnConnections"),
    "vpn_gateway": ("ec2", "describe_vpn_gateways", "VpnGateways"),
    "load_balancer": ("elbv2", "describe_load_balancers", "LoadBalancers"),
    "classic_load_balancer": ("elb", "describe_load_balancers", "LoadBalancerDescriptions"),
    "target_group": ("elbv2", "describe_target_groups", "TargetGroups"),
    "kms_key": ("kms", "list_keys", "Keys"),
    "cloudtrail": ("cloudtrail", "describe_trails", "trailList"),
    "config_recorder": ("config", "describe_configuration_recorders", "ConfigurationRecorders"),
    "config_delivery_channel": ("config", "describe_delivery_channels", "DeliveryChannels"),
    "guardduty_detector": ("guardduty", "list_detectors", "DetectorIds"),
    "rds_instance": ("rds", "describe_db_instances", "DBInstances"),
    "rds_cluster": ("rds", "describe_db_clusters", "DBClusters"),
    "rds_snapshot": ("rds", "describe_db_snapshots", "DBSnapshots"),
    "eks_cluster": ("eks", "list_clusters", "clusters"),
    "lambda_function": ("lambda", "list_functions", "Functions"),
    "ecr_repository": ("ecr", "describe_repositories", "repositories"),
    "log_group": ("logs", "describe_log_groups", "logGroups"),
    "cloudwatch_alarm": ("cloudwatch", "describe_alarms", "MetricAlarms"),
    "secret": ("secretsmanager", "list_secrets", "SecretList"),
    "sns_topic": ("sns", "list_topics", "Topics"),
    "sqs_queue": ("sqs", "list_queues", "QueueUrls || `[]`"),
    "rest_api": ("apigateway", "get_rest_apis", "items"),
    "http_api": ("apigatewayv2", "get_apis", "Items"),
    "opensearch_domain": ("opensearch", "list_domain_names", "DomainNames"),
    "dynamodb_table": ("dynamodb", "list_tables", "TableNames"),
}
GLOBAL_TYPES = {"aws_account", "iam_user", "iam_group", "iam_role", "iam_policy", "iam_account_summary", "iam_password_policy", "iam_credential_report", "bucket", "s3_account_public_access_block", "organization_account", "organization_parent", "scp_policy"}
AWS_TYPES = sorted(set(SPECS) | GLOBAL_TYPES)
FETCHERS = {}
ENRICHERS = {}

# Auditable operation allowlist. In particular, GetSecretValue, logs/objects,
# credential report generation and Access Analyzer creation are absent.
_DETAIL_ACTIONS = {
    "sts": "get_caller_identity assume_role",
    "iam": "get_account_authorization_details get_account_summary get_account_password_policy get_credential_report generate_credential_report list_users list_access_keys get_access_key_last_used get_login_profile list_mfa_devices",
    "ec2": "describe_regions",
    "s3": "list_buckets get_bucket_location get_public_access_block get_bucket_policy_status get_bucket_policy get_bucket_encryption get_bucket_versioning get_bucket_acl get_bucket_ownership_controls get_bucket_logging get_bucket_lifecycle_configuration get_bucket_notification_configuration get_bucket_replication get_object_lock_configuration get_bucket_tagging",
    "s3control": "get_public_access_block",
    "organizations": "list_accounts list_policies_for_target describe_policy list_parents",
    "kms": "describe_key get_key_rotation_status get_key_policy",
    "cloudtrail": "get_trail_status get_event_selectors",
    "config": "describe_configuration_recorder_status",
    "guardduty": "get_detector",
    "eks": "describe_cluster",
    "lambda": "get_policy get_function_url_config",
    "ecr": "get_repository_policy get_lifecycle_policy",
    "secretsmanager": "get_resource_policy",
    "sns": "get_topic_attributes",
    "sqs": "get_queue_attributes",
    "elbv2": "describe_load_balancer_attributes describe_listeners describe_target_health",
    "elb": "describe_load_balancer_attributes",
    "rds": "describe_db_snapshot_attributes",
    "opensearch": "describe_domain",
    "dynamodb": "describe_table",
}
READ_ACTIONS = {(service, operation) for service, operations in _DETAIL_ACTIONS.items() for operation in operations.split()}
READ_ACTIONS.update((service, operation) for service, operation, expression in SPECS.values())

_NATIVE_IDS = {
    "aws_account": "Account", "iam_credential_report": "arn",
    "iam_user": "Arn", "iam_group": "Arn", "iam_role": "Arn", "iam_policy": "Arn",
    "bucket": "Name", "vpc": "VpcId", "subnet": "SubnetId", "route_table": "RouteTableId",
    "security_group": "GroupId", "network_acl": "NetworkAclId", "network_interface": "NetworkInterfaceId",
    "instance": "InstanceId", "ebs_volume": "VolumeId", "internet_gateway": "InternetGatewayId",
    "nat_gateway": "NatGatewayId", "vpc_endpoint": "VpcEndpointId", "vpc_peering": "VpcPeeringConnectionId",
    "transit_gateway": "TransitGatewayId", "transit_gateway_attachment": "TransitGatewayAttachmentId",
    "transit_gateway_route_table": "TransitGatewayRouteTableId", "vpn_connection": "VpnConnectionId",
    "vpn_gateway": "VpnGatewayId", "load_balancer": "LoadBalancerArn", "classic_load_balancer": "LoadBalancerName",
    "target_group": "TargetGroupArn", "kms_key": "KeyArn", "cloudtrail": "TrailARN",
    "config_recorder": "name", "config_delivery_channel": "name", "guardduty_detector": "DetectorId",
    "rds_instance": "DBInstanceArn", "rds_cluster": "DBClusterArn", "rds_snapshot": "DBSnapshotArn",
    "eks_cluster": "name", "lambda_function": "FunctionArn", "ecr_repository": "repositoryArn",
    "log_group": "logGroupName", "cloudwatch_alarm": "AlarmArn", "secret": "ARN",
    "sns_topic": "TopicArn", "sqs_queue": "QueueUrl", "rest_api": "id", "http_api": "ApiId",
    "opensearch_domain": "DomainName", "dynamodb_table": "TableName", "organization_account": "Id", "organization_parent": "ChildId", "scp_policy": "Id",
}


def _native_id(kind, item):
    value = item.get(_NATIVE_IDS.get(kind, "id"))
    if isinstance(value, str) and value:
        return value
    from peaso.snapshot import resource_id
    return resource_id("aws", kind, "", _safe(item))


def _policy(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            try:
                value = json.loads(unquote(value))
            except (ValueError, TypeError):
                return {"collection_status": "malformed", "error": {"code": "malformed_policy"}}
    return value


def _enrich(requests, session, region, kind, items):
    def detail(service, operation, **arguments):
        return requests.detail(session, service, region, operation, **arguments)

    output = []
    for original in items:
        if isinstance(original, str):
            names = {"eks_cluster": "name", "guardduty_detector": "DetectorId", "sqs_queue": "QueueUrl", "dynamodb_table": "TableName"}
            item = {names.get(kind, _NATIVE_IDS.get(kind, "Name")): original}
        elif isinstance(original, dict):
            item = copy.deepcopy(original)
        else:
            raise ReadFailure("malformed", "malformed_resource")
        if kind == "kms_key":
            key = item["KeyId"]
            item["Metadata"] = detail("kms", "describe_key", KeyId=key)
            item["Rotation"] = detail("kms", "get_key_rotation_status", KeyId=key)
            item["Policy"] = detail("kms", "get_key_policy", KeyId=key, PolicyName="default")
            if "Policy" in item["Policy"]:
                item["Policy"]["Policy"] = _policy(item["Policy"]["Policy"])
        elif kind == "cloudtrail":
            arn = item.get("TrailARN") or item["Name"]
            home = item.get("HomeRegion", region)
            item["Status"] = requests.detail(session, "cloudtrail", home, "get_trail_status", Name=arn)
            item["EventSelectors"] = requests.detail(session, "cloudtrail", home, "get_event_selectors", TrailName=arn)
        elif kind == "config_recorder":
            item["Status"] = detail("config", "describe_configuration_recorder_status", ConfigurationRecorderNames=[item["name"]])
        elif kind == "guardduty_detector":
            item["Configuration"] = detail("guardduty", "get_detector", DetectorId=item["DetectorId"])
        elif kind == "eks_cluster":
            item["Cluster"] = detail("eks", "describe_cluster", name=item["name"])
        elif kind == "lambda_function":
            name = item["FunctionName"]
            item["Policy"] = requests.detail(session, "lambda", region, "get_policy", FunctionName=name, absent=("ResourceNotFoundException",))
            item["FunctionUrl"] = requests.detail(session, "lambda", region, "get_function_url_config", FunctionName=name, absent=("ResourceNotFoundException",))
            if "Policy" in item["Policy"]:
                item["Policy"]["Policy"] = _policy(item["Policy"]["Policy"])
        elif kind == "ecr_repository":
            name = item["repositoryName"]
            item["Policy"] = requests.detail(session, "ecr", region, "get_repository_policy", repositoryName=name, absent=("RepositoryPolicyNotFoundException",))
            item["LifecyclePolicy"] = requests.detail(session, "ecr", region, "get_lifecycle_policy", repositoryName=name, absent=("LifecyclePolicyNotFoundException",))
            if "policyText" in item["Policy"]:
                item["Policy"]["policyText"] = _policy(item["Policy"]["policyText"])
        elif kind == "secret":
            item["Policy"] = detail("secretsmanager", "get_resource_policy", SecretId=item["ARN"])
            if "ResourcePolicy" in item["Policy"]:
                item["Policy"]["ResourcePolicy"] = _policy(item["Policy"]["ResourcePolicy"])
        elif kind == "sns_topic":
            item["Attributes"] = detail("sns", "get_topic_attributes", TopicArn=item["TopicArn"])
            attrs = item["Attributes"].get("Attributes", {})
            if "Policy" in attrs:
                attrs["Policy"] = _policy(attrs["Policy"])
        elif kind == "sqs_queue":
            item["Attributes"] = detail("sqs", "get_queue_attributes", QueueUrl=item["QueueUrl"], AttributeNames=["All"])
            attrs = item["Attributes"].get("Attributes", {})
            if "Policy" in attrs:
                attrs["Policy"] = _policy(attrs["Policy"])
        elif kind == "load_balancer":
            arn = item["LoadBalancerArn"]
            item["Attributes"] = detail("elbv2", "describe_load_balancer_attributes", LoadBalancerArn=arn)
            listeners = requests.pages(session, "elbv2", region, "describe_listeners", "Listeners", LoadBalancerArn=arn)
            item["Listeners"] = {"collection_status": listeners.status, "items": listeners.items}
            if listeners.error:
                item["Listeners"]["error"] = listeners.error
        elif kind == "classic_load_balancer":
            item["Attributes"] = detail("elb", "describe_load_balancer_attributes", LoadBalancerName=item["LoadBalancerName"])
        elif kind == "target_group":
            item["TargetHealth"] = detail("elbv2", "describe_target_health", TargetGroupArn=item["TargetGroupArn"])
        elif kind == "rds_snapshot":
            item["Attributes"] = detail("rds", "describe_db_snapshot_attributes", DBSnapshotIdentifier=item["DBSnapshotIdentifier"])
        elif kind == "opensearch_domain":
            item["Domain"] = detail("opensearch", "describe_domain", DomainName=item["DomainName"])
        elif kind == "dynamodb_table":
            item["Table"] = detail("dynamodb", "describe_table", TableName=item["TableName"])
        if isinstance(item.get("Policy"), str):
            item["Policy"] = _policy(item["Policy"])
        output.append(item)
    return output


def _iam(requests, session, region, wanted):
    keys = {"iam_user": "UserDetailList", "iam_group": "GroupDetailList", "iam_role": "RoleDetailList", "iam_policy": "Policies"}
    result = {}
    for kind, key in keys.items():
        if kind not in wanted:
            continue
        read = requests.pages(session, "iam", region, "get_account_authorization_details", key)
        # Identical calls for four IAM projections are single-flight cached.
        for item in read.items:
            if "AssumeRolePolicyDocument" in item:
                item["AssumeRolePolicyDocument"] = _policy(item["AssumeRolePolicyDocument"])
            for field_name in ("UserPolicyList", "GroupPolicyList", "RolePolicyList"):
                for inline in item.get(field_name, []):
                    if "PolicyDocument" in inline:
                        inline["PolicyDocument"] = _policy(inline["PolicyDocument"])
            for version in item.get("PolicyVersionList", []):
                if "Document" in version:
                    version["Document"] = _policy(version["Document"])
            item["PolicySources"] = [
                {"source_type": "inline_policy", "attachment": kind.removeprefix("iam_"),
                 "attachment_name": item.get("UserName") or item.get("GroupName") or item.get("RoleName"),
                 "policy_name": policy.get("PolicyName"), "document": policy.get("PolicyDocument")}
                for policy in item.get({"iam_user": "UserPolicyList", "iam_group": "GroupPolicyList", "iam_role": "RolePolicyList"}.get(kind, "_none"), [])]
            item["PolicySources"].extend({"source_type": "managed_policy", "attachment": kind.removeprefix("iam_"),
                 "attachment_name": item.get("UserName") or item.get("GroupName") or item.get("RoleName"),
                 "policy_arn": p.get("PolicyArn"), "policy_name": p.get("PolicyName")}
                 for p in item.get("AttachedManagedPolicies", []))
            if kind == "iam_user":
                name = item["UserName"]
                access = requests.pages(session, "iam", region, "list_access_keys", "AccessKeyMetadata", UserName=name)
                for key_item in access.items:
                    key_item["LastUsed"] = requests.detail(session, "iam", region, "get_access_key_last_used", AccessKeyId=key_item["AccessKeyId"])
                item["AccessKeys"] = {"collection_status": access.status, "items": access.items}
                if access.error:
                    item["AccessKeys"]["error"] = access.error
                item["LoginProfile"] = requests.detail(session, "iam", region, "get_login_profile", UserName=name, absent=("NoSuchEntity",))
                mfa = requests.pages(session, "iam", region, "list_mfa_devices", "MFADevices", UserName=name)
                item["MFADevices"] = {"collection_status": mfa.status, "items": mfa.items}
        result[kind] = read
    return result


def _buckets(requests, session, region):
    result = requests.pages(session, "s3", region, "list_buckets", "Buckets")
    reads = [
        ("PublicAccessBlock", "get_public_access_block", ("NoSuchPublicAccessBlockConfiguration",)),
        ("PolicyStatus", "get_bucket_policy_status", ("NoSuchBucketPolicy",)),
        ("Policy", "get_bucket_policy", ("NoSuchBucketPolicy",)),
        ("Encryption", "get_bucket_encryption", ("ServerSideEncryptionConfigurationNotFoundError",)),
        ("Versioning", "get_bucket_versioning", ()),
        ("Acl", "get_bucket_acl", ()),
        ("OwnershipControls", "get_bucket_ownership_controls", ("OwnershipControlsNotFoundError",)),
        ("Logging", "get_bucket_logging", ()),
        ("Lifecycle", "get_bucket_lifecycle_configuration", ("NoSuchLifecycleConfiguration",)),
        ("Notifications", "get_bucket_notification_configuration", ()),
        ("Replication", "get_bucket_replication", ("ReplicationConfigurationNotFoundError",)),
        ("ObjectLock", "get_object_lock_configuration", ("ObjectLockConfigurationNotFoundError",)),
        ("Tags", "get_bucket_tagging", ("NoSuchTagSet",))]
    for item in result.items:
        name = item["Name"]
        location = requests.detail(session, "s3", region, "get_bucket_location", Bucket=name)
        item["Location"] = location
        selected = location.get("LocationConstraint") or region
        if location.get("collection_status") in (None, "collected"):
            selected = "eu-west-1" if selected == "EU" else selected
            if location.get("LocationConstraint") is None:
                selected = "us-east-1"
        for field_name, operation, absent in reads:
            item[field_name] = requests.detail(session, "s3", selected, operation, Bucket=name, absent=absent)
        if "Policy" in item["Policy"]:
            item["Policy"]["Policy"] = _policy(item["Policy"]["Policy"])
    return result


def network_relationships(collections):
    """Evidence-backed adjacency only; no claim of end-to-end reachability."""
    relationships = []
    for collection in collections:
        if collection["type"] not in {"subnet", "route_table", "security_group", "network_interface", "instance", "load_balancer", "vpc_endpoint", "network_acl", "internet_gateway"}:
            continue
        for item in collection["items"]:
            source = next((item[k] for k in ("NetworkInterfaceId", "InstanceId", "RouteTableId", "SubnetId", "GroupId", "LoadBalancerArn", "VpcEndpointId", "NetworkAclId", "InternetGatewayId") if item.get(k)), None)
            if not source:
                continue
            links = [(k, item[k]) for k in ("VpcId", "SubnetId") if item.get(k)]
            links += [("security_group", group.get("GroupId")) for group in item.get("Groups", []) if isinstance(group, dict)]
            links += [("security_group", group) for group in item.get("SecurityGroups", []) if isinstance(group, str)]
            for association in item.get("Associations", []):
                if association.get("SubnetId"):
                    links.append(("association", association["SubnetId"]))
            for attachment in item.get("Attachments", []):
                if attachment.get("VpcId"):
                    links.append(("attachment", attachment["VpcId"]))
            for route in item.get("Routes", []):
                for key in ("GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId", "NetworkInterfaceId"):
                    if route.get(key):
                        links.append(("route_target", route[key]))
            for relation, target in links:
                if target and target != source:
                    relationships.append({"scope": collection["scope"], "source": source, "target": target,
                        "relation": relation, "evidence_type": collection["type"], "reachability": "unknown"})
    return sorted(relationships, key=lambda x: (x["scope"], x["source"], x["relation"], x["target"]))


def _single(requests, session, region, service, operation, *, absent=(), **arguments):
    try:
        return ReadResult([requests.call(session, service, region, operation, **arguments)])
    except Exception as exc:
        failure = _failure(exc)
        if failure.code in absent:
            return ReadResult([], "empty", {"code": failure.code})
        return ReadResult([], failure.status, {"code": failure.code})


def _credentials_report(requests, session, region):
    unavailable_report_codes = {"ReportNotPresent", "ReportExpired", "ReportInProgress", "CredentialReportNotPresent", "CredentialReportExpired", "CredentialReportNotReady"}
    read = _single(requests, session, region, "iam", "get_credential_report",
        absent=unavailable_report_codes)
    if read.status == "empty" and read.error and read.error.get("code") in unavailable_report_codes:
        # Explicitly authorized evidence generation only. This does not change
        # IAM configuration, credentials, roles or resources.
        try:
            response = requests.call(session, "iam", region, "generate_credential_report")
            if response.get("State") not in {"STARTED", "INPROGRESS", "COMPLETE"}:
                raise ReadFailure("malformed", "malformed_report_generation_state")
            deadline = time.monotonic() + requests.evidence_generation_wait
            while True:
                try:
                    response = requests.call(session, "iam", region, "get_credential_report", _cache_refresh=True)
                    read = ReadResult([response])
                    break
                except Exception as exc:
                    failure = _failure(exc)
                    if failure.code not in unavailable_report_codes:
                        raise failure from None
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ReadFailure("timeout", "credential_report_generation_timeout")
                    requests._sleep(min(1, remaining))
        except Exception as exc:
            failure = _failure(exc)
            return ReadResult([], failure.status, {"code": failure.code})
    if read.items:
        response = read.items[0]
        content = response.get("Content")
        if not isinstance(content, bytes) or response.get("ReportFormat") != "text/csv":
            return ReadResult([], "malformed", {"code": "malformed_credential_report"})
        try:
            read.items = list(csv.DictReader(io.StringIO(content.decode("utf-8"))))
            if any(not row.get("user") or None in row for row in read.items):
                raise ValueError("malformed CSV")
            for row in read.items:
                row["ReportGeneratedTime"] = _safe(response.get("GeneratedTime"))
            read.status = "collected" if read.items else "empty"
        except (ValueError, UnicodeError):
            return ReadResult([], "malformed", {"code": "malformed_credential_report"})
    # Missing/expired report is unavailable evidence, rather than no credentials.
    if read.status == "empty" and read.error:
        read.status = "not_collected"
    return read


def _scp_policies(requests, session, region, account):
    policies, path, seen = {}, [{"Id": account, "Type": "ACCOUNT"}], {account}
    target = path[0]
    failure = None
    while True:
        attached = requests.pages(session, "organizations", region, "list_policies_for_target", "Policies",
            TargetId=target["Id"], Filter="SERVICE_CONTROL_POLICY")
        if attached.status not in {"collected", "empty"}:
            failure = ReadFailure((attached.error or {}).get("cause_status", attached.status), (attached.error or {}).get("code", "scp_attachment_collection_incomplete"))
        for original in attached.items:
            if not isinstance(original, dict) or not isinstance(original.get("Id"), str):
                failure = ReadFailure("malformed", "malformed_scp_policy")
                continue
            policy_id = original["Id"]
            item = policies.setdefault(policy_id, {**original, "TargetId": account, "Attachments": []})
            item["Attachments"].append({"TargetId": target["Id"], "TargetType": target["Type"],
                "Inherited": target["Type"] != "ACCOUNT", "ParentPath": copy.deepcopy(path), "collection_status": "collected"})
            if "Detail" not in item:
                response = requests.detail(session, "organizations", region, "describe_policy", PolicyId=policy_id)
                if response.get("collection_status") not in (None, "collected", "empty"):
                    failure = ReadFailure(response["collection_status"], response.get("error", {}).get("code", "scp_document_unavailable"))
                content = response.get("Policy", {}).get("Content")
                if content is not None:
                    response["Policy"]["Content"] = _policy(content)
                    document = response["Policy"]["Content"]
                    if not isinstance(document, dict) or not isinstance(document.get("Statement"), (list, dict)):
                        failure = ReadFailure("malformed", "malformed_scp_document")
                elif response.get("collection_status") is None:
                    failure = ReadFailure("malformed", "missing_scp_document")
                item["Detail"] = response
        if attached.status not in {"collected", "empty"} or target["Type"] == "ROOT":
            break
        parents = requests.pages(session, "organizations", region, "list_parents", "Parents", ChildId=target["Id"])
        if parents.status not in {"collected", "empty"}:
            failure = ReadFailure((parents.error or {}).get("cause_status", parents.status), (parents.error or {}).get("code", "organization_parent_visibility_incomplete"))
            break
        if len(parents.items) != 1 or not isinstance(parents.items[0], dict):
            failure = ReadFailure("malformed", "missing_or_ambiguous_organization_parent")
            break
        parent = parents.items[0]
        parent_id, parent_type = parent.get("Id"), parent.get("Type")
        valid = isinstance(parent_id, str) and parent_type in {"ORGANIZATIONAL_UNIT", "ROOT"}
        valid = valid and bool(re.fullmatch(r"r-[a-z0-9]+" if parent_type == "ROOT" else r"ou-[a-z0-9]+-[a-z0-9]+", parent_id))
        if not valid:
            failure = ReadFailure("malformed", "malformed_organization_parent")
            break
        if parent_id in seen:
            failure = ReadFailure("malformed", "organization_parent_cycle")
            break
        seen.add(parent_id)
        target = {"Id": parent_id, "Type": parent_type}
        path.append(target)
    complete = failure is None and target["Type"] == "ROOT"
    for item in policies.values():
        item["InheritanceComplete"] = complete
        item["InheritedPolicies"] = {"collection_status": "collected" if complete else (failure.status if failure else "unknown"),
            "ParentPath": copy.deepcopy(path), "complete": complete}
        if failure:
            item["InheritedPolicies"]["error"] = {"code": failure.code}
    items = list(policies.values())
    if failure:
        return ReadResult(items, "partial" if items else failure.status, {"code": failure.code, "cause_status": failure.status})
    return ReadResult(items, "collected" if items else "empty")


def _organization_parents(requests, session, region, account):
    """Observed account/OU parent edges only, with explicit path completeness."""
    child, path, seen, items = account, [account], {account}, []
    failure = None
    while True:
        read = requests.pages(session, "organizations", region, "list_parents", "Parents", ChildId=child)
        if read.status not in {"collected", "empty"}:
            # The provider's typed not-in-use response is known absence, unlike
            # denied visibility. Never infer root from an arbitrary empty list.
            if not items and (read.error or {}).get("code") == "AWSOrganizationsNotInUseException":
                return ReadResult([], "empty", {"code": "AWSOrganizationsNotInUseException"})
            failure = ReadFailure((read.error or {}).get("cause_status", read.status), (read.error or {}).get("code", "organization_parent_visibility_incomplete"))
            break
        if len(read.items) != 1 or not isinstance(read.items[0], dict):
            failure = ReadFailure("malformed", "missing_or_ambiguous_organization_parent")
            break
        parent = read.items[0]
        parent_id, parent_type = parent.get("Id"), parent.get("Type")
        valid = isinstance(parent_id, str) and parent_type in {"ROOT", "ORGANIZATIONAL_UNIT"}
        valid = valid and bool(re.fullmatch(r"r-[a-z0-9]+" if parent_type == "ROOT" else r"ou-[a-z0-9]+-[a-z0-9]+", parent_id))
        if not valid:
            failure = ReadFailure("malformed", "malformed_organization_parent")
            break
        if parent_id in seen:
            failure = ReadFailure("malformed", "organization_parent_cycle")
            break
        seen.add(parent_id)
        path.append(parent_id)
        items.append({**parent, "ChildId": child, "ParentId": parent_id,
            "ParentType": parent_type, "ParentPath": list(path)})
        if parent_type == "ROOT":
            break
        child = parent_id
    for item in items:
        item["InheritanceComplete"] = failure is None
        item["ParentCollection"] = {"collection_status": "collected" if failure is None else failure.status,
            "complete": failure is None}
        if failure:
            item["ParentCollection"]["error"] = {"code": failure.code}
    if failure:
        return ReadResult(items, "partial" if items else failure.status, {"code": failure.code, "cause_status": failure.status})
    return ReadResult(items, "collected" if items else "empty")


def _identity(requests, session, region, expected=None):
    identity = requests.call(session, "sts", region, "get_caller_identity")
    account, arn = identity.get("Account"), identity.get("Arn")
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account) or not isinstance(arn, str) or not arn.startswith("arn:"):
        raise ReadFailure("malformed", "malformed_caller_identity")
    if expected and expected != account:
        raise ReadFailure("denied", "account_identity_mismatch")
    return _safe(identity)


def _selection(connector):
    options, auth = connector.get("options", {}), connector.get("auth", {})
    scopes = connector.get("scopes") or []
    if not isinstance(scopes, list) or any(not isinstance(x, str) for x in scopes):
        raise ValueError("scopes must be a list of account IDs or account/region scopes")
    selected_regions = options.get("regions") or []
    if not isinstance(selected_regions, list):
        raise ValueError("regions must be a list")
    regions = list(selected_regions)
    accounts = []
    for scope in scopes:
        if re.fullmatch(r"[0-9]{12}", scope):
            accounts.append(scope)
        elif re.fullmatch(r"[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]", scope):
            account, region = scope.split("/")
            accounts.append(account)
            regions.append(region)
        elif re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", scope):
            regions.append(scope)
        else:
            raise ValueError("AWS scope must be an account ID, account/region or AWS region")
    regions = list(dict.fromkeys(regions or [auth.get("region_name", "us-east-1")]))
    if any(not isinstance(r, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", r) for r in regions):
        raise ValueError("regions must contain AWS region names")
    return list(dict.fromkeys(accounts)), regions


def collect(connector, requirements=None):
    """Collect only requested facts, with explicit coverage for omitted types.

    Explicit account scopes are an allowlist. Cross-account reads require a
    configured assume_roles target or an organization_role_name opt-in; there
    is never an attempt to guess role names or to fall back after auth failure.
    """
    from peaso.snapshot import make_snapshot

    options, auth = connector.get("options", {}), connector.get("auth", {})
    if not isinstance(options, dict) or not isinstance(auth, dict):
        raise ValueError("auth and options must be objects")
    selected_accounts, regions = _selection(connector)
    explicit_regions = bool(options.get("regions") or auth.get("region_name")) or any(not re.fullmatch(r"[0-9]{12}", scope) for scope in connector.get("scopes") or [])
    discovered_regions = {}
    region_discovery_errors = {}
    # Preserve explicitly selected account/region pairs; account-only scopes
    # use options.regions. Avoid broadening pairs into a Cartesian product.
    plain_accounts = {s for s in (connector.get("scopes") or []) if re.fullmatch(r"[0-9]{12}", s)}
    paired_regions = {}
    for scope in connector.get("scopes") or []:
        if "/" in scope:
            account, region = scope.split("/")
            paired_regions.setdefault(account, []).append(region)

    def regions_for(account):
        if account in paired_regions and account not in plain_accounts:
            return list(dict.fromkeys(paired_regions[account]))
        return discovered_regions.get(account, regions)

    requests = Requests(options)
    scope_workers = _bound(options, "scope_concurrency", 2, maximum=8)
    region_workers = _bound(options, "region_concurrency", 2, maximum=8)
    inventories = options.get("inventories", AWS_TYPES)
    if not isinstance(inventories, list) or any(kind not in AWS_TYPES for kind in inventories):
        raise ValueError("inventories must be supported AWS resource types")
    if requirements is not None and (not isinstance(requirements, list) or any(not isinstance(x, str) for x in requirements)):
        raise ValueError("requirements must be a list of resource types")
    wanted = set(inventories) & (set(requirements) if requirements is not None else set(AWS_TYPES))
    # Caller identity is mandatory even when no resource inventories are chosen.
    wanted.add("aws_account")
    unsupported = set(requirements or []) - set(AWS_TYPES)
    collections, contexts, identities, auth_errors = [], [], [], []
    metadata = {"collection": "read-only", "selected_scopes": list(connector.get("scopes") or []),
        "regions": regions, "supported_inventories": AWS_TYPES,
        "omitted_inventories": sorted(set(AWS_TYPES) - wanted),
        "service_concurrency": requests.workers, "scope_concurrency": scope_workers,
        "region_concurrency": region_workers, "reachability": "unknown"}
    trusted = options.get("trusted_scope_ids", [])
    if not isinstance(trusted, list) or any(not isinstance(x, str) or not re.fullmatch(r"[0-9]{12}", x) for x in trusted):
        raise ValueError("trusted_scope_ids must be explicit AWS account IDs")
    metadata["trusted_scope_ids"] = list(dict.fromkeys(trusted))
    metadata["usage_evidence"] = {"credential_report": "existing_only",
        "access_keys": "AWS last observed use; missing last use is unknown",
        "roles": "AWS RoleLastUsed observation window; missing last use is unknown",
        "policy_usage": "not_collected", "effective_access": "unknown"}
    total_items = 0

    def append(kind, scope, service, read, account=None, region=None):
        nonlocal total_items
        # Deterministic emission order ensures deterministic resource-limit
        # selection despite concurrent API completion.
        unique = {}
        status, error = read.status, read.error
        for original in read.items:
            if not isinstance(original, dict):
                status, error = ("partial" if unique else "malformed"), {"code": "malformed_resource"}
                break
            item = _safe(original)
            singleton = kind in {"iam_account_summary", "iam_password_policy", "s3_account_public_access_block"}
            item.setdefault("id", account if singleton and account else _native_id(kind, item))
            if account:
                item["AccountId"] = account
            if region:
                item["Region"] = region
            rid = _native_id(kind, item)
            if rid in unique:
                continue
            if requests.max_items is not None and total_items >= requests.max_items:
                status, error = ("partial" if unique else "not_collected"), {"code": "resource_limit"}
                break
            unique[rid] = item
            total_items += 1
        envelope = {"type": kind, "scope": scope, "service": service, "status": status, "items": list(unique.values())}
        if account:
            envelope["account_id"] = account
            envelope["global"] = kind in GLOBAL_TYPES
        if error:
            envelope["error"] = error
        collections.append(envelope)

    def failed_scope(scope, failure):
        account = scope.split("/")[0]
        account_regions = regions_for(account)
        for region in account_regions:
            current_scope = f"{account}/{region}"
            kinds = AWS_TYPES if region == account_regions[0] else sorted(set(SPECS) - GLOBAL_TYPES)
            for kind in kinds + sorted(unsupported):
                if any(c["scope"] == current_scope and c["type"] == kind for c in collections):
                    continue
                append(kind, current_scope, SPECS.get(kind, ("iam" if kind.startswith("iam_") else "aws",))[0],
                    ReadResult([], failure.status if kind in wanted or kind in unsupported else "not_collected",
                        {"code": failure.code if kind in wanted or kind in unsupported else "inventory_not_requested"}))

    try:
        session, credential_method = _session(auth, regions[0] if explicit_regions else None)
        if not explicit_regions:
            regions[:] = [session.region_name or "us-east-1"]
        metadata["credential_method"] = credential_method
        chain = auth.get("role_chain", [])
        if not isinstance(chain, list) or len(chain) > 10:
            raise ValueError("role_chain must contain at most 10 role targets")
        if auth.get("role_arn"):
            chain = chain + [{"role_arn": auth["role_arn"]}]
        for target in chain:
            session = _assume(requests, session, regions[0], target, auth)
        identity = _identity(requests, session, regions[0])
        base_account = identity["Account"]
        if not selected_accounts or base_account in selected_accounts:
            contexts.append((session, identity))
            identities.append(identity)
        targets = auth.get("assume_roles", [])
        if not isinstance(targets, list):
            raise ValueError("assume_roles must be a list of role targets")
        targets = list(targets)
        organization_role = options.get("organization_role_name")
        org_inventory = None
        if organization_role:
            if not isinstance(organization_role, str) or not re.fullmatch(r"[\w+=,.@/-]{1,512}", organization_role):
                raise ValueError("invalid organization_role_name")
            org_inventory = requests.pages(session, "organizations", regions[0], "list_accounts", "Accounts")
            metadata["organization_discovery"] = {"status": org_inventory.status,
                "accounts_seen": len(org_inventory.items), "error": org_inventory.error}
            partition = identity["Arn"].split(":")[1]
            for member in org_inventory.items:
                account = member.get("Id")
                if member.get("State", member.get("Status")) != "ACTIVE" or not re.fullmatch(r"[0-9]{12}", str(account)):
                    continue
                if account != base_account and (not selected_accounts or account in selected_accounts):
                    targets.append({"role_arn": f"arn:{partition}:iam::{account}:role/{organization_role}"})
        seen_targets = set()
        metadata["role_target_selection"] = {"requested": len(targets), "scheduled_limit": None, "status": "collected"}
        for target in targets:
            target_info = {"role_arn": target} if isinstance(target, str) else target
            if not isinstance(target_info, dict):
                raise ValueError("assume_roles entries must be role ARNs or objects")
            arn = target_info.get("role_arn", "")
            expected = arn.split(":")[4] if isinstance(arn, str) and len(arn.split(":")) > 4 else None
            if selected_accounts and expected not in selected_accounts:
                continue
            if arn in seen_targets:
                continue
            seen_targets.add(arn)
            try:
                role_session = _assume(requests, session, regions[0], target_info, auth)
                role_identity = _identity(requests, role_session, regions[0], expected)
                if role_identity["Account"] not in {x[1]["Account"] for x in contexts}:
                    contexts.append((role_session, role_identity))
                    identities.append(role_identity)
            except Exception as exc:
                failure = _failure(exc)
                auth_errors.append({"account": expected or "unresolved", "error": {"code": failure.code}, "status": failure.status})
        resolved = {x[1]["Account"] for x in contexts}
        for account in selected_accounts:
            if account not in resolved:
                error = next((x for x in auth_errors if x["account"] == account), None)
                failed_scope(f"{account}/{regions[0]}", ReadFailure(error["status"] if error else "not_collected", error["error"]["code"] if error else "account_role_not_configured"))
        for error in auth_errors:
            if not selected_accounts and error["account"] not in resolved:
                failed_scope(f"{error['account']}/{regions[0]}", ReadFailure(error["status"], error["error"]["code"]))
    except Exception as exc:
        failure = _failure(exc)
        contexts = []
        for account in selected_accounts or ["unresolved"]:
            failed_scope(f"{account}/{regions[0]}", failure)
        org_inventory = None

    if not explicit_regions:
        metadata["region_discovery"] = []
        for account_session, identity in contexts:
            account = identity["Account"]
            read = requests.pages(account_session, "ec2", regions[0], "describe_regions", "Regions", AllRegions=True)
            valid = read.status in {"collected", "empty"} and all(isinstance(row, dict) and isinstance(row.get("RegionName"), str) and row.get("OptInStatus") in {"opt-in-not-required", "opted-in", "not-opted-in"} for row in read.items)
            enabled = sorted({row["RegionName"] for row in read.items if isinstance(row, dict) and row.get("OptInStatus") in {"opt-in-not-required", "opted-in"}}) if valid else []
            if not valid or not enabled:
                failure = ReadFailure(read.status if read.status not in {"collected", "empty"} else "malformed", (read.error or {}).get("code", "enabled_region_discovery_unavailable"))
                region_discovery_errors[account] = failure
                metadata["region_discovery"].append({"account_id": account, "status": failure.status, "error": {"code": failure.code}})
            else:
                discovered_regions[account] = enabled
                metadata["region_discovery"].append({"account_id": account, "status": "collected", "regions": enabled})
        if discovered_regions:
            regions[:] = sorted({region for values in discovered_regions.values() for region in values})
        metadata["regions"] = list(regions)

    def global_job(session, identity, kind):
        account = identity["Account"]
        region = regions_for(account)[0]
        if kind in FETCHERS:
            return FETCHERS[kind](requests, session, region, account)
        if kind == "aws_account":
            return ReadResult([identity])
        if kind == "bucket":
            return _buckets(requests, session, region)
        if kind in {"iam_user", "iam_group", "iam_role", "iam_policy"}:
            return _iam(requests, session, region, {kind})[kind]
        if kind == "iam_account_summary":
            return _single(requests, session, region, "iam", "get_account_summary")
        if kind == "iam_password_policy":
            return _single(requests, session, region, "iam", "get_account_password_policy", absent=("NoSuchEntity",))
        if kind == "iam_credential_report":
            return _credentials_report(requests, session, region)
        if kind == "s3_account_public_access_block":
            return _single(requests, session, region, "s3control", "get_public_access_block", AccountId=account, absent=("NoSuchPublicAccessBlockConfiguration",))
        if kind == "organization_account":
            if org_inventory is not None and account == base_account:
                return org_inventory
            return requests.pages(session, "organizations", region, "list_accounts", "Accounts")
        if kind == "organization_parent":
            return _organization_parents(requests, session, region, account)
        if kind == "scp_policy":
            return _scp_policies(requests, session, region, account)
        return ReadResult([], "not_collected", {"code": "unsupported_inventory"})

    def regional_job(session, identity, region, kind):
        if kind in FETCHERS:
            read = FETCHERS[kind](requests, session, region, identity["Account"])
            if not isinstance(read, ReadResult):
                return ReadResult([], "malformed", {"code": "malformed_extension_result"})
            return read
        service, operation, expression = SPECS[kind]
        args = {"includeShadowTrails": True} if kind == "cloudtrail" else {"MaxResults": 1000} if kind == "sqs_queue" else {}
        read = _single(requests, session, region, service, operation, **args) if expression is None else requests.pages(session, service, region, operation, expression, **args)
        try:
            read.items = _enrich(requests, session, region, kind, read.items)
            if kind == "log_group":
                for item in read.items:
                    item["_provenance"] = {"operation": "logs:DescribeLogGroups", "native_response_complete": True}
            if kind in ENRICHERS:
                read.items = ENRICHERS[kind](requests, session, region, read.items)
        except Exception as exc:
            failure = _failure(exc)
            # Retain original valid dictionary evidence, mark incomplete detail.
            read.items = [x for x in read.items if isinstance(x, dict)]
            read.status = "partial" if read.items else failure.status
            read.error = {"code": failure.code}
        return read

    with ThreadPoolExecutor(max_workers=requests.workers, thread_name_prefix="aws-read") as pool:
        for offset in range(0, len(contexts), scope_workers):
            scope_batch = contexts[offset:offset + scope_workers]
            jobs = []
            for session, identity in scope_batch:
                for kind in sorted(GLOBAL_TYPES):
                    if kind in wanted:
                        jobs.append((kind, identity, regions_for(identity["Account"])[0], session, pool.submit(global_job, session, identity, kind)))
            for kind, identity, region, job_session, future in jobs:
                try:
                    read = future.result()
                    if not isinstance(read, ReadResult):
                        raise ReadFailure("malformed", "malformed_extension_result")
                    if kind in ENRICHERS and read.items:
                        read.items = ENRICHERS[kind](requests, job_session, region, read.items)
                except Exception as exc:
                    failure = _failure(exc)
                    read = ReadResult([], failure.status, {"code": failure.code})
                append(kind, f"{identity['Account']}/{region}", SPECS[kind][0] if kind in SPECS else "sts" if kind == "aws_account" else "s3" if kind == "bucket" else "organizations" if kind in {"organization_account", "organization_parent", "scp_policy"} else "s3control" if kind == "s3_account_public_access_block" else "iam", read, identity["Account"], region)
            for region_offset in range(0, len(regions), region_workers):
                jobs = []
                for session, identity in scope_batch:
                    for region in regions[region_offset:region_offset + region_workers]:
                        if region not in regions_for(identity["Account"]):
                            continue
                        for kind in sorted(set(SPECS) - GLOBAL_TYPES):
                            if kind in wanted:
                                if identity["Account"] in region_discovery_errors:
                                    failure = region_discovery_errors[identity["Account"]]
                                    future = Future()
                                    future.set_result(ReadResult([], failure.status, {"code": failure.code, "reason": "default_region_discovery_incomplete"}))
                                else:
                                    future = pool.submit(regional_job, session, identity, region, kind)
                                jobs.append((kind, identity, region, session, future))
                for kind, identity, region, job_session, future in jobs:
                    try:
                        read = future.result()
                    except Exception as exc:
                        failure = _failure(exc)
                        read = ReadResult([], failure.status, {"code": failure.code})
                    append(kind, f"{identity['Account']}/{region}", SPECS[kind][0], read, identity["Account"], region)
            for session, identity in scope_batch:
                account_regions = regions_for(identity["Account"])
                for region in account_regions:
                    for kind in sorted((set(SPECS) - GLOBAL_TYPES - wanted) | unsupported | ((GLOBAL_TYPES - wanted) if region == account_regions[0] else set())):
                        append(kind, f"{identity['Account']}/{region}", SPECS.get(kind, ("aws",))[0], ReadResult([], "not_collected", {"code": "unsupported_inventory" if kind in unsupported else "inventory_not_requested"}))
    collections.sort(key=lambda c: (c["scope"], c["type"]))
    metadata.update({"calls": requests.calls, "cache_hits": requests.cache_hits,
        "max_calls": requests.max_calls, "max_pages": requests.max_pages,
        "max_resources": requests.max_items, "resource_count": total_items,
        "credential_resolution_calls": "sdk_managed_not_counted",
        "intentional_limits": {key: options[key] for key in ("max_calls", "max_pages", "max_resources", "deadline_seconds") if options.get(key) is not None},
        "authorized_evidence_generation": {"iam_credential_report": True, "generation_requests": requests.evidence_generations},
        "caller_identities": identities, "authentication_errors": auth_errors,
        "network_relationships": network_relationships(collections)})
    scopes = sorted({c["scope"] for c in collections})
    return make_snapshot("aws", scopes, collections, metadata=_safe(metadata))


def _load_metadata_extension():
    """Trusted in-repository read-only specs, sharing the scan request context."""
    from importlib import import_module
    name = "peaso.collectors.aws_b_services"
    try:
        extension = import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:
            raise
        return
    specs = getattr(extension, "SPECS", {})
    for kind, spec in specs.items():
        if not isinstance(kind, str) or not isinstance(spec, tuple) or len(spec) != 3:
            raise ValueError("invalid AWS extension service specification")
        if kind in SPECS and SPECS[kind] != spec:
            raise ValueError("AWS extension cannot replace existing service specification")
    actions = set(getattr(extension, "READ_ACTIONS", set()))
    for service, operation in actions | {(s, o) for s, o, expression in specs.values()}:
        if operation in _PROHIBITED_VALUE_OPERATIONS or not operation.startswith(("get_", "list_", "describe_", "batch_get_", "batch_describe_")):
            raise ValueError("AWS extension includes a prohibited operation")
    SPECS.update(specs)
    READ_ACTIONS.update(actions)
    READ_ACTIONS.update((s, o) for s, o, expression in specs.values())
    _NATIVE_IDS.update(getattr(extension, "NATIVE_IDS", {}))
    GLOBAL_TYPES.update(getattr(extension, "GLOBAL_TYPES", set()))
    FETCHERS.update(getattr(extension, "FETCHERS", {}))
    ENRICHERS.update(getattr(extension, "ENRICHERS", {}))
    AWS_TYPES[:] = sorted(set(SPECS) | GLOBAL_TYPES)


_load_metadata_extension()
