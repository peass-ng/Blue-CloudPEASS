"""Signed AWS compliance predicates; all decisions use scoped snapshot evidence."""
from __future__ import annotations

import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get


SPECS = {
    "aws_route53resolver_query_logs_forwarded": ("resolver_query_log_config_association", "medium", "Send DNS Resolvers queries to SIEM", "07c3c2d7825cd784045279822e2a1af8ea4ebbf99c6da6845f6d9dc00d00a757"),
    "aws_security_logs_central_search": ("cloudwatch_log_group", "medium", "Security logs centralized for search", "74cde307da773d1288b3191edd9336c06dff735df69c58d6b8f6c3286dd7becf"),
    "aws_api_customer_log_delivery": ("apigateway_stage", "medium", "Customer API stages expose security logs", "fc4ad197a5453b52b6431f704af55904bdf241df4d9db29c77603bc166b108fc"),
    "aws.pci.s3.sensitive_auth_data_findings": ("macie_finding", "high", "S3 objects contain no detected sensitive authentication data", "01c5b1aee884764f4a426fd08303e917d04f222590d6ef2e0ed478ccd739de1e"),
    "aws.pci.appsync.waf_web_acl": ("appsync_graphql_api", "medium", "AppSync APIs are associated with WAFv2", "cc14f5c8d6cf851cdd534d89cd649c4e0842ac37688d700b6da8650cce20522f"),
    "aws.pci.fms.web_acl_rule_priority": ("fms_policy", "medium", "Firewall Manager rule groups use approved priorities", "2125b44db506ae9adb204174c76a12dd4f32a77da3c6d0ff3ee5a994d4422808"),
    "aws_cis_organization_units_environment_sensitivity": ("organization_parent", "medium", "Organization units encode environment and sensitivity", "d6c409cf6108dce0a106570a95b0411ab35de2512c3ee8a5add78083a3b5bcc7"),
    "aws_cis_ec2_tag_policy": ("scp_policy", "medium", "Attached tag policy defines required EC2 tags", "f4790e1e1f2bac9f0de17ca916839a270d8951992c29d54ca188c9763c45cce1"),
    "aws_account_non_eu_resource_region_detected": ("aws_data_resource", "medium", "Customer data resources reside in approved EU regions", "6a26cfa11a36cd63b57040d9db6e15a2867e9ca5f6ef41a54ef749bf53dd8953"),
}
SPEC_SHA256 = {key: value[3] for key, value in SPECS.items()}
_SCOPE = re.compile(r"^([0-9]{12})/(global|[a-z]{2}(?:-[a-z]+)+-[0-9])$")
_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12})?:(.+)$")
_REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]$")
_METHOD_PATH = re.compile(r"^~1[A-Za-z0-9~{}+._%-]*$")
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"}


def _context(index, *, global_scope=False):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS context authority unavailable")
    scope = get(context, "scope", str)
    match = _SCOPE.fullmatch(scope)
    if not match or (global_scope is True and match.group(2) != "global") or (global_scope is False and match.group(2) == "global"):
        raise Unavailable("AWS account/Region scope unavailable")
    return context, scope, match.group(1), match.group(2)


def _inventory(index, kind, scope, *, allow_global=False):
    envelopes = get(index, "collections", dict).get(kind)
    account = scope.split("/", 1)[0]
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            get(envelopes[0], "type", str) != kind or
            get(envelopes[0], "scope", str) not in ({scope, account + "/global"} if allow_global else {scope})):
        raise Unavailable("missing or foreign collection authority: " + kind)
    if envelopes[0]["scope"] != scope and (envelopes[0].get("global") is not True or
                                                 envelopes[0].get("account_id") != account):
        raise Unavailable("unproven global collection authority")
    if envelopes[0].get("status") not in {"collected", "empty"}:
        raise Unavailable("incomplete collection: " + kind)
    wrappers = get(index, kind, list)
    if any(not isinstance(wrapper, dict) or wrapper.get("type") != kind or
           wrapper.get("scope") != envelopes[0]["scope"] for wrapper in wrappers):
        raise Unavailable("foreign resource wrapper: " + kind)
    rows = complete_items(index, kind)
    items = get(envelopes[0], "items", list)
    if rows != items or len(rows) != len(wrappers) or (envelopes[0]["status"] == "empty" and items):
        raise Unavailable("collection projection mismatch: " + kind)
    return rows


def _subject(item, scope):
    if get(item, "scope", str) != scope:
        raise Unavailable("foreign scope subject")


def _member(item, rows, key):
    identity = get(item, key, str)
    if not identity or sum(get(row, key, str) == identity for row in rows) != 1:
        raise Unavailable("missing or duplicate resource identity")
    row = next(row for row in rows if row[key] == identity)
    if row != item:
        raise Unavailable("resource differs from scoped inventory")
    return identity


def _strings(value, *, nonempty=True):
    if not isinstance(value, list) or (nonempty and not value) or any(not isinstance(x, str) or not x for x in value) or len(value) != len(set(value)):
        raise Unavailable("missing or malformed approved string list")
    return value


def _policy(index, key, expected):
    metadata = get(index, "context.metadata", dict)
    source = metadata if key in metadata else get(metadata, "parameters", dict)
    return get(source, key, expected)


def _arn(value, *, service=None, account=None, region=None):
    match = _ARN.fullmatch(value) if isinstance(value, str) else None
    if not match or (service and match.group(2) != service) or (account and match.group(4) != account) or (region and match.group(3) != region):
        raise Unavailable("malformed or foreign ARN")
    return match


@register("aws_route53resolver_query_logs_forwarded", "aws", "hardening", "resolver_query_log_config_association",
          "Send DNS Resolvers queries to SIEM", "medium", "AU-12",
          "Associate every VPC with a Resolver query log configuration and subscribe its log group to an approved SIEM forwarder.",
          target="scope", dependencies=["vpc", "resolver_query_log_config_association", "resolver_query_log_config", "resolver_log_subscription"])
def resolver_query_logs(item, index):
    _, scope, account, region = _context(index)
    _subject(item, scope)
    approved = set(_strings(_policy(index, "approved_siem_forwarder_arns", list)))
    for arn in approved:
        _arn(arn, account=account, region=region)
    vpcs = _inventory(index, "vpc", scope)
    associations = _inventory(index, "resolver_query_log_config_association", scope)
    configs = _inventory(index, "resolver_query_log_config", scope)
    subscriptions = _inventory(index, "resolver_log_subscription", scope)
    ids = [_nonempty(get(v, "VpcId", str)) for v in vpcs]
    if len(ids) != len(set(ids)):
        raise Unavailable("duplicate VPC")
    config_by_id = {}
    for config in configs:
        cid = _nonempty(get(config, "Id", str))
        _arn(get(config, "DestinationArn", str), service="logs", account=account, region=region)
        if cid in config_by_id:
            raise Unavailable("duplicate Resolver log configuration")
        config_by_id[cid] = config
    subs_by_group = {}
    for sub in subscriptions:
        group = get(sub, "LogGroupArn", str)
        _arn(group, service="logs", account=account, region=region)
        dest = get(sub, "DestinationArn", str)
        _arn(dest, account=account, region=region)
        subs_by_group.setdefault(group, []).append(dest)
    matched = set()
    for association in associations:
        vpc = _nonempty(get(association, "ResourceId", str))
        if vpc not in ids:
            raise Unavailable("association outside inventoried VPCs")
        status = get(association, "Status", str)
        if status not in {"ACTIVE", "CREATING", "DELETING", "FAILED"}:
            raise Unavailable("unrecognized Resolver association status")
        cid = _nonempty(get(association, "ResolverQueryLogConfigId", str))
        if cid not in config_by_id:
            raise Unavailable("missing Resolver log configuration")
        if status == "ACTIVE" and approved.intersection(subs_by_group.get(config_by_id[cid]["DestinationArn"], [])):
            matched.add(vpc)
    return result(bool(set(ids) - matched), vpc_ids_without_approved_forwarding=sorted(set(ids) - matched),
                  semantics="Subscription configuration only; external receipt unverified")


@register("aws_security_logs_central_search", "aws", "hardening", "cloudwatch_log_group",
          "Security logs centralized for search", "medium", "AU-12",
          "Subscribe each designated security log group to the approved active Firehose delivery stream.",
          target="scope", dependencies=["cloudwatch_log_group", "cloudwatch_subscription_filter", "firehose_delivery_stream"])
def security_logs_central_search(item, index):
    _, scope, account, region = _context(index)
    _subject(item, scope)
    names = set(_strings(_policy(index, "security_log_group_names", list)))
    approved = _policy(index, "approved_central_delivery_stream_arn", str)
    _arn(approved, service="firehose", account=account, region=region)
    groups = _inventory(index, "cloudwatch_log_group", scope)
    filters = _inventory(index, "cloudwatch_subscription_filter", scope)
    streams = _inventory(index, "firehose_delivery_stream", scope)
    known = [_nonempty(get(row, "logGroupName", str)) for row in groups]
    if len(known) != len(set(known)):
        raise Unavailable("duplicate log group")
    streams_by_arn = {}
    for row in streams:
        arn = get(row, "DeliveryStreamARN", str)
        _arn(arn, service="firehose", account=account, region=region)
        status = get(row, "DeliveryStreamStatus", str)
        if status not in {"ACTIVE", "CREATING", "DELETING", "CREATING_FAILED", "DELETING_FAILED"} or arn in streams_by_arn:
            raise Unavailable("ambiguous Firehose stream state")
        streams_by_arn[arn] = status
    if approved not in streams_by_arn:
        raise Unavailable("approved delivery stream inventory unavailable")
    by_group = {}
    for row in filters:
        name = _nonempty(get(row, "logGroupName", str))
        if name not in known:
            raise Unavailable("subscription outside inventoried log groups")
        destination = get(row, "destinationArn", str)
        _arn(destination, account=account, region=region)
        status = get(row, "collection_status", str)
        if status != "collected":
            raise Unavailable("subscription state incomplete")
        by_group.setdefault(name, []).append(destination)
    missing = sorted(name for name in names if name not in known or
                     approved not in by_group.get(name, []) or streams_by_arn[approved] != "ACTIVE")
    return result(bool(missing), log_groups_without_active_central_subscription=missing,
                  semantics="Firehose subscription configuration only; search usability unverified")


def _nonempty(value):
    if not value:
        raise Unavailable("empty required identity")
    return value


@register("aws_api_customer_log_delivery", "aws", "hardening", "apigateway_stage",
          "Customer API stages expose security logs", "medium", "AU-12",
          "Enable stage execution logging and configure a CloudWatch access log destination with requestId, requestTime and status.",
          dependencies=["apigateway_stage"])
def api_customer_log_delivery(item, index):
    _, scope, account, region = _context(index)
    stages = _inventory(index, "apigateway_stage", scope)
    arn = _member(item, stages, "id")
    if not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:apigateway:" + re.escape(region) + r"::/restapis/[A-Za-z0-9]+/stages/[A-Za-z0-9_-]+", arn):
        raise Unavailable("invalid REST API stage ARN")
    if get(item, "_provenance.source_operation", str) != "get_stages" or get(item, "_provenance.read_only", bool) is not True:
        raise Unavailable("stage source unavailable")
    optional_complete = item['_provenance'].get('optional_fields_complete', [])
    if ('accessLogSettings' not in item and isinstance(optional_complete, list) and
            all(isinstance(field, str) for field in optional_complete) and
            'accessLogSettings' in optional_complete and
            'accessLogSettings' not in item.get('_coverage', {})):
        return result(True, stage_arn=arn, access_log_destination_configured=False,
                      semantics='Native complete Stage response omits access log configuration; delivery unverified')
    settings = get(item, "methodSettings", dict)
    if "*/*" not in settings or not isinstance(settings["*/*"], dict):
        raise Unavailable("covering method logging unavailable")
    unsafe = []
    for key, value in settings.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            raise Unavailable("malformed method settings")
        if key != "*/*":
            path, separator, method = key.rpartition("/")
            if not separator or not _METHOD_PATH.fullmatch(path) or method not in _METHODS:
                raise Unavailable("malformed method setting key")
        level = get(value, "loggingLevel", str)
        if level not in {"INFO", "ERROR", "OFF"}:
            raise Unavailable("unrecognized logging level")
        if level == "OFF":
            unsafe.append(key)
    uncovered_wildcard = "*/*" in unsafe
    if "accessLogSettings" not in item:
        if item.get("_coverage", {}).get("accessLogSettings") or item.get("_provenance", {}).get("representation") != "full":
            raise Unavailable("access log settings unavailable")
        access_settings = {}
    else:
        access_settings = get(item, "accessLogSettings", dict)
    if "destinationArn" not in access_settings and (
            "destinationArn" in access_settings.get("_coverage", {}) or
            item.get("_provenance", {}).get("representation") != "full"):
        raise Unavailable("access log destination absence unproven")
    destination = get(access_settings, "destinationArn", str) if "destinationArn" in access_settings else ""
    if destination:
        _arn(destination, service="logs", account=account, region=region)
    if "format" not in access_settings and (
            "format" in access_settings.get("_coverage", {}) or
            item.get("_provenance", {}).get("representation") != "full"):
        raise Unavailable("access log format absence unproven")
    fmt = get(access_settings, "format", str) if "format" in access_settings else ""
    tokens = {"requestId": ("$context.requestId", "$context.extendedRequestId"),
              "requestTime": ("$context.requestTime", "$context.requestTimeEpoch"),
              "status": ("$context.status",)}
    absent = [key for key, variants in tokens.items() if not any(
        re.search(re.escape(token) + r"(?![A-Za-z0-9_])", fmt) for token in variants)]
    if not destination or absent or any(key != "*/*" for key in unsafe):
        return result(True, stage_arn=arn, off_method_settings=sorted(unsafe),
                      missing_access_log_fields=absent, access_log_destination_configured=bool(destination),
                      semantics="Explicit stage configuration weakness; delivery and customer availability unverified")
    if uncovered_wildcard:
        return unknown("OFF wildcard lacks stage-bound deployed method coverage", stage_arn=arn)
    return result(False, stage_arn=arn, off_method_settings=[],
                  missing_access_log_fields=absent, access_log_destination_configured=bool(destination),
                  semantics="Stage configuration only; delivery and customer availability unverified")


@register("aws.pci.s3.sensitive_auth_data_findings", "aws", "hardening", "macie_finding",
          "S3 objects contain no detected sensitive authentication data", "high", "SI-4",
          "Remove prohibited authentication data from authorized S3 objects and verify Macie findings before archiving.",
          target="scope", dependencies=["macie_finding", "macie_scan_coverage"], allow_incomplete_failure=True)
def sensitive_auth_data(item, index):
    _, scope, account, region = _context(index)
    _subject(item, scope)
    identifiers = set(_strings(_policy(index, "prohibited_auth_identifier_names", list)))
    authorized = set(_strings(_policy(index, "authorized_macie_bucket_arns", list)))
    for arn in authorized:
        _arn(arn, service="s3")
    envelopes = get(index, "collections", dict).get("macie_finding")
    partial = (isinstance(envelopes, list) and len(envelopes) == 1 and
               isinstance(envelopes[0], dict) and envelopes[0].get("status") == "partial")
    native = (isinstance(envelopes, list) and len(envelopes) == 1 and
              isinstance(envelopes[0], dict) and envelopes[0].get('service') == 'macie2')
    findings = (_macie_partial_findings(index, scope, account, region, full=not partial)
                if partial or native else _inventory(index, "macie_finding", scope))
    seen, bad = set(), []
    for finding in findings:
        fid = _nonempty(get(finding, "id", str))
        if fid in seen:
            raise Unavailable("duplicate Macie finding")
        seen.add(fid)
        if get(finding, "accountId", str) != account or get(finding, "region", str) != region:
            raise Unavailable("foreign Macie finding")
        bucket = get(finding, "s3Object.bucketArn", str)
        if bucket not in authorized:
            raise Unavailable("Macie finding outside authorized buckets")
        active = get(finding, "archived", bool) is False
        names = set(_strings(get(finding, "customIdentifierNames", list), nonempty=False))
        if active and names.intersection(identifiers):
            bad.append(fid)
    if bad:
        return result(True, active_prohibited_finding_ids=sorted(bad),
                      semantics="Detected custom identifier matches in authorized Macie findings; full scan coverage unverified, object contents unverified")
    if partial:
        return unknown("partial Macie classification cannot establish absence of prohibited data")
    coverage = _inventory(index, "macie_scan_coverage", scope)
    if len(coverage) != 1 or get(coverage[0], "authorized", bool) is not True or get(coverage[0], "complete", bool) is not True:
        raise Unavailable("Macie authorization or full scan coverage unavailable")
    if set(_strings(get(coverage[0], "bucketArns", list))) != authorized:
        raise Unavailable("Macie scan coverage differs from approved buckets")
    return result(False, active_prohibited_finding_ids=[],
                  semantics="Configured custom identifier matches in authorized Macie coverage; object contents unverified")


def _macie_partial_findings(index, scope, account, region, *, full=False):
    """Use only scoped, source-bound native Macie detector and object metadata."""
    from peaso.collectors.aws_macie_findings_native import PROJECTION
    envelope = get(index, 'collections', dict)['macie_finding'][0]
    if (get(envelope, 'type', str) != 'macie_finding' or get(envelope, 'scope', str) != scope
            or envelope.get('status') not in ({'collected', 'empty'} if full else {'partial'})
            or get(envelope, 'service', str) != 'macie2' or envelope.get('global', False) is not False):
        raise Unavailable('partial native Macie collection authority unavailable')
    rows = get(envelope, 'items', list)
    if envelope.get('status') == 'empty' and rows:
        raise Unavailable('empty native Macie inventory retains findings')
    wrappers = get(index, 'macie_finding', list)
    if len(rows) != len(wrappers):
        raise Unavailable('partial native Macie index differs from collection')
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    verified, seen = [], set()
    for row, wrapper in zip(rows, wrappers):
        if (get(wrapper, 'type', str) != 'macie_finding' or get(wrapper, 'scope', str) != scope
                or wrapper.get('provider', 'aws') != 'aws' or get(wrapper, 'data', dict) != row):
            raise Unavailable('partial native Macie wrapper is foreign')
        fid = get(row, 'id', str)
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', fid) or fid in seen:
            raise Unavailable('partial native Macie finding identity ambiguous')
        seen.add(fid)
        if (get(row, 'accountId', str) != account or get(row, 'region', str) != region
                or get(row, 'partition', str) != partition or get(row, 'sample', bool) is not False
                or ('AccountId' in row and get(row, 'AccountId', str) != account)
                or ('Region' in row and get(row, 'Region', str) != region)):
            raise Unavailable('partial native Macie finding scope unavailable')
        proof = get(row, '_provenance', dict)
        if (get(proof, 'read_only', bool) is not True or get(proof, 'audited_scope', str) != scope
                or get(proof, 'metadata_projection', str) != PROJECTION
                or get(proof, 'source_operation', str) != 'macie2:ListFindings+GetFindings'
                or get(proof, 'object_content_or_occurrences_retained', bool) is not False
                or get(proof, 'scan_coverage_established', bool) is not False
                or get(proof, 'finding_time_verified', bool) is not True):
            raise Unavailable('partial native Macie finding provenance unavailable')
        if get(proof, 'category', str) == 'POLICY':
            if get(row, 'detected_identifiers_verified', bool) is True or get(row, 'customIdentifierNames', list):
                raise Unavailable('policy finding cannot assert custom identifier detections')
            continue
        if get(row, 'detected_identifiers_verified', bool) is not True:
            if full:
                raise Unavailable('complete native Macie detector verification unavailable')
            continue  # An incomplete sibling cannot assert any detector match.
        if (get(proof, 'category', str) != 'CLASSIFICATION'
                or get(proof, 'classification_status', str) not in ({'COMPLETE'} if full else {'COMPLETE', 'PARTIAL'})):
            raise Unavailable('partial native Macie detector status unavailable')
        total = get(proof, 'custom_identifier_total_count', int)
        bindings = get(proof, 'custom_identifier_bindings', list)
        if total < 0 or len(bindings) > 1000:
            raise Unavailable('partial native Macie detector counts malformed')
        names, arns, count = set(), set(), 0
        for binding in bindings:
            name, arn, occurrences = get(binding, 'name', str), get(binding, 'arn', str), get(binding, 'count', int)
            if (not 1 <= len(name) <= 128 or any(ord(c) < 32 for c in name) or name in names or arn in arns
                    or occurrences <= 0 or not re.fullmatch('arn:' + re.escape(partition) + ':macie2:' +
                        re.escape(region) + ':' + account + r':custom-data-identifier/[A-Za-z0-9_-]{1,128}', arn)):
                raise Unavailable('partial native Macie detector identity/count unavailable')
            names.add(name); arns.add(arn); count += occurrences
        if count != total or sorted(names) != _strings(get(row, 'customIdentifierNames', list), nonempty=False):
            raise Unavailable('native Macie detector totals or names differ')
        obj = get(row, 's3Object', dict)
        digest = get(obj, 'objectIdentitySha256', str)
        if (get(obj, 'identityAlgorithm', str) != 'sha256-json-bucket-key-version-v1'
                or not re.fullmatch(r'[0-9a-f]{64}', digest)
                or not (('versionId' in obj and isinstance(obj['versionId'], str) and obj['versionId'])
                        or ('eTag' in obj and isinstance(obj['eTag'], str) and obj['eTag']))):
            raise Unavailable('native Macie object version binding unavailable')
        origin = get(row, 'classificationOrigin', dict)
        origin_type = get(origin, 'originType', str)
        if origin_type == 'SENSITIVE_DATA_DISCOVERY_JOB':
            job_id = get(origin, 'jobId', str)
            if (not re.fullmatch(r'[a-fA-F0-9]{32}', job_id)
                    or get(origin, 'jobArn', str) != 'arn:' + partition + ':macie2:' + region + ':' + account + ':classification-job/' + job_id):
                raise Unavailable('native Macie classification job scope unavailable')
        elif origin_type != 'AUTOMATED_SENSITIVE_DATA_DISCOVERY' or 'jobId' in origin or 'jobArn' in origin:
            raise Unavailable('native Macie finding origin unavailable')
        verified.append(row)
    return verified


@register("aws.pci.appsync.waf_web_acl", "aws", "hardening", "appsync_graphql_api",
          "AppSync APIs are associated with WAFv2", "medium", "SC-7",
          "Associate each AppSync GraphQL API with a WAFv2 web ACL.",
          dependencies=["appsync_graphql_api", "wafv2_appsync_association"])
def appsync_waf_web_acl(item, index):
    _, scope, account, region = _context(index)
    apis = _inventory(index, "appsync_graphql_api", scope)
    api_arns = [get(api, "arn", str) for api in apis]
    if len(api_arns) != len(set(api_arns)):
        raise Unavailable("duplicate AppSync API inventory")
    arn = _member(item, apis, "arn")
    _arn(arn, service="appsync", account=account, region=region)
    associations = _inventory(index, "wafv2_appsync_association", scope)
    matches = []
    for row in associations:
        api_arn = get(row, "ResourceArn", str)
        if api_arn not in api_arns:
            raise Unavailable("association outside scoped AppSync inventory")
        acl = get(row, "WebACLArn", str)
        if acl:
            _arn(acl, service="wafv2", account=account, region=region)
        matches.append((api_arn, acl))
    if len(matches) != len(apis) or {resource for resource, _ in matches} != set(api_arns):
        raise Unavailable("per-API WAF association coverage incomplete")
    attached = [acl for resource, acl in matches if resource == arn]
    if len(attached) > 1:
        raise Unavailable("ambiguous AppSync web ACL association")
    return result(not attached or not attached[0], api_arn=arn, web_acl_arn=attached[0] if attached else None)


@register("aws.pci.fms.web_acl_rule_priority", "aws", "hardening", "fms_policy",
          "Firewall Manager rule groups use approved priorities", "medium", "CM-6",
          "Set Firewall Manager rule-group priorities to the approved unique order.",
          dependencies=["fms_policy", "fms_web_acl_rules"])
def fms_web_acl_rule_priority(item, index):
    _, scope, account, region = _context(index)
    policies = _inventory(index, "fms_policy", scope)
    policy_id = _member(item, policies, "PolicyId")
    service_type = get(item, "SecurityServiceType", str)
    if service_type not in {"WAF", "WAFV2", "SECURITY_GROUPS_COMMON", "SECURITY_GROUPS_CONTENT_AUDIT", "SECURITY_GROUPS_USAGE_AUDIT", "SHIELD_ADVANCED", "DNS_FIREWALL", "NETWORK_FIREWALL", "THIRD_PARTY_FIREWALL", "IMPORT_NETWORK_FIREWALL", "NETWORK_ACL_COMMON"}:
        raise Unavailable("unrecognized Firewall Manager policy type")
    if service_type != "WAFV2":
        return "NOT_APPLICABLE", {"policy_id": policy_id, "reason": "policy does not manage WAFv2 web ACLs"}
    approved = get(_policy(index, "approved_fms_rule_priorities", dict), policy_id, list)
    expected = _priority_rows(approved)
    if not expected:
        raise Unavailable("empty approved FMS rule order")
    rules = _inventory(index, "fms_web_acl_rules", scope)
    # Every row belongs to the same complete scoped inventory. Validate its
    # direct ACL identity and policy reference before selecting this policy;
    # a foreign or duplicate peer cannot certify a PASS for the subject.
    policy_ids = [get(policy, "PolicyId", str) for policy in policies]
    if any(not identity.strip() for identity in policy_ids) or len(policy_ids) != len(set(policy_ids)):
        raise Unavailable("empty or duplicate FMS policy identity in scoped inventory")
    policy_ids = set(policy_ids)
    matching = []
    seen_acls = set()
    for acl in rules:
        associated_policy = get(acl, "PolicyId", str)
        acl_arn = get(acl, "WebACLArn", str)
        parsed = _arn(acl_arn, service="wafv2", account=account, region=region)
        if (not associated_policy.strip() or associated_policy not in policy_ids or
                not re.fullmatch(r"(?:regional|global)/webacl/[^/?#%\s\\]+/[^/?#%\s\\]+", parsed.group(5))
                or acl_arn in seen_acls):
            raise Unavailable("foreign, duplicate or malformed FMS web ACL association")
        seen_acls.add(acl_arn)
        if associated_policy == policy_id:
            matching.append(acl)
    if not matching:
        raise Unavailable("FMS managed web ACL rule inventory unavailable")
    observations, bad = {}, []
    incomplete = False
    for acl in matching:
        acl_arn = get(acl, "WebACLArn", str)
        if get(acl, "complete", bool) is not True:
            incomplete = True
            continue
        observed = _priority_rows(get(acl, "Rules", list), allow_duplicates=True)
        if not observed:
            raise Unavailable("empty managed web ACL rules")
        observations[acl_arn] = observed
        if observed != expected or len({priority for _, priority in observed}) != len(observed):
            bad.append(acl_arn)
    if incomplete and not bad:
        raise Unavailable("FMS managed web ACL rule inventory unavailable")
    # Completeness/association remain input requirements. Multiple rows do not
    # establish the managed universe; each supplied complete ACL is evaluated.
    evidence = {"policy_id": policy_id, "web_acl_arns": sorted(observations),
                "observed_by_web_acl": dict(sorted(observations.items())),
                "noncompliant_web_acl_arns": sorted(bad), "approved": expected}
    if len(observations) == 1:
        acl_arn, observed = next(iter(observations.items()))
        evidence.update(web_acl_arn=acl_arn, observed=observed)
    return result(bool(bad), **evidence)


def _priority_rows(rows, *, allow_duplicates=False):
    if not isinstance(rows, list):
        raise Unavailable("malformed priority rows")
    values = []
    for row in rows:
        name = _nonempty(get(row, "Name", str))
        priority = get(row, "Priority", int)
        if priority < 0:
            raise Unavailable("invalid rule priority")
        values.append((name, priority))
    if len({name for name, _ in values}) != len(values) or (not allow_duplicates and len({priority for _, priority in values}) != len(values)):
        raise Unavailable("ambiguous approved or observed rule names/priorities")
    return sorted(values, key=lambda value: value[1])


@register("aws_cis_organization_units_environment_sensitivity", "aws", "hardening", "organization_parent",
          "Organization units encode environment and sensitivity", "medium", "AC-2",
          "Move active member accounts under OUs whose names match approved environment and sensitivity patterns.",
          target="scope", dependencies=["organization_account", "organization_parent"])
def ou_environment_sensitivity(item, index):
    _, scope, account, _ = _context(index, global_scope=None)
    _subject(item, scope)
    management = _policy(index, "organization_management_account_id", str)
    if not re.fullmatch(r"[0-9]{12}", management):
        raise Unavailable("organization management account unavailable")
    environment = _patterns(_policy(index, "approved_environment_ou_patterns", list))
    sensitivity = _patterns(_policy(index, "approved_sensitivity_ou_patterns", list))
    accounts = _inventory(index, "organization_account", scope, allow_global=True)
    parents = _inventory(index, "organization_parent", scope, allow_global=True)
    account_ids = set()
    active = []
    for row in accounts:
        aid = get(row, "Id", str)
        if not re.fullmatch(r"[0-9]{12}", aid) or aid in account_ids:
            raise Unavailable("invalid or duplicate organization account")
        account_ids.add(aid)
        # State is authoritative. Status is the retired, less granular field:
        # AWS documents pending activation as legacy ACTIVE and CLOSED as
        # legacy SUSPENDED. Reject inconsistent dual-field native responses.
        legacy_for_state = {"ACTIVE": "ACTIVE", "PENDING_ACTIVATION": "ACTIVE",
                            "SUSPENDED": "SUSPENDED", "CLOSED": "SUSPENDED",
                            "PENDING_CLOSURE": "PENDING_CLOSURE"}
        if "State" in row or "State" in row.get("_coverage", {}):
            state = get(row, "State", str)
            if state not in legacy_for_state:
                raise Unavailable("unknown organization account state")
            if "Status" in row and get(row, "Status", str) != legacy_for_state[state]:
                raise Unavailable("contradictory organization account State/Status")
        else:
            state = get(row, "Status", str)
            if state not in {"ACTIVE", "SUSPENDED", "PENDING_CLOSURE"}:
                raise Unavailable("unknown legacy organization account status")
        if state == "ACTIVE":
            active.append(aid)
    by_child, organization = {}, None
    ou_pattern = r"ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}"
    for row in parents:
        child = _nonempty(get(row, "ChildId", str))
        parent = _nonempty(get(row, "ParentId", str))
        kind = get(row, "ParentType", str)
        if kind not in {"ROOT", "ORGANIZATIONAL_UNIT"} or child in by_child:
            raise Unavailable("malformed or ambiguous OU parent edge")
        if (not (re.fullmatch(r"[0-9]{12}", child) or re.fullmatch(ou_pattern, child))
                or re.fullmatch(r"[0-9]{12}", child) and child not in account_ids
                or not re.fullmatch(r"r-[0-9a-z]{4,32}" if kind == "ROOT" else ou_pattern, parent)
                or child == parent):
            raise Unavailable("native OU parent identity/type unresolved")
        if ("Id" in row and get(row, "Id", str) != parent
                or "Type" in row and get(row, "Type", str) != kind):
            raise Unavailable("native parent declaration disagrees with projected edge")
        for field in ("Arn", "ParentArn"):
            if field not in row:
                continue
            arn = _arn(get(row, field, str), service="organizations", account=management)
            identity = re.fullmatch(("root" if kind == "ROOT" else "ou") +
                                    r"/(o-[0-9a-z]{10,32})/" + re.escape(parent), arn.group(5))
            if arn.group(3) or not identity:
                raise Unavailable("native parent ARN does not bind its identity/type")
            authority = (arn.group(1), identity.group(1))
            if organization is not None and authority != organization:
                raise Unavailable("parent edges belong to different organizations")
            organization = authority
        name = get(row, "OrganizationalUnitName", str) if kind == "ORGANIZATIONAL_UNIT" else ""
        if kind == "ORGANIZATIONAL_UNIT" and not name:
            raise Unavailable("OU name unavailable")
        by_child[child] = (parent, kind, name)
    bad = []
    for aid in active:
        if aid == management:
            continue  # This predicate covers member accounts only.
        names, seen, cursor = [], set(), aid
        while True:
            if cursor in seen or cursor not in by_child:
                raise Unavailable("incomplete or cyclic member account parent chain")
            seen.add(cursor)
            parent, kind, name = by_child[cursor]
            if kind == "ROOT":
                break
            names.append(name)
            cursor = parent
        if not any(pattern.fullmatch(name) for pattern in environment for name in names) or not any(pattern.fullmatch(name) for pattern in sensitivity for name in names):
            bad.append(aid)
    return result(bool(bad), active_member_accounts_without_approved_ou_path=sorted(bad))


def _patterns(values):
    try:
        return [re.compile(pattern) for pattern in _strings(values)]
    except re.error as exc:
        raise Unavailable("invalid approved OU-name pattern") from exc


@register("aws_cis_ec2_tag_policy", "aws", "hardening", "scp_policy",
          "Attached tag policy defines required EC2 tags", "medium", "CM-8",
          "Attach an Organizations TAG_POLICY containing the approved EC2 tag keys and permitted values.",
          target="scope", dependencies=["organization_tag_policy"])
def ec2_tag_policy(item, index):
    _, scope, _, _ = _context(index, global_scope=None)
    _subject(item, scope)
    approved = _policy(index, "approved_ec2_tag_values", dict)
    if not approved:
        raise Unavailable("approved EC2 tag keys and values absent")
    for key, values in approved.items():
        if not isinstance(key, str) or not key:
            raise Unavailable("malformed EC2 tag key")
        _strings(values)
    policies = _inventory(index, "organization_tag_policy", scope, allow_global=True)
    seen, matching = set(), []
    for row in policies:
        pid = _nonempty(get(row, "Id", str))
        if pid in seen:
            raise Unavailable("duplicate tag policy")
        seen.add(pid)
        if get(row, "PolicyType", str) != "TAG_POLICY":
            raise Unavailable("non-tag policy in tag policy inventory")
        if get(row, "AttachedToAccountPath", bool) is not True:
            continue
        if get(row, "Complete", bool) is not True:
            raise Unavailable("attached tag policy content incomplete")
        if 'TagValueDigests' in row or '_metadata_projection' in row:
            from ..collectors.aws_attached_tag_policy_native import PROJECTION, ARN, validate_assignments, value_digest
            from ..collectors.aws import ReadFailure
            arn = row.get('NativePolicyArn')
            identity = ARN.fullmatch(arn) if isinstance(arn, str) else None
            if (row.get('_metadata_projection') != PROJECTION or identity is None or identity[2] != pid
                    or row.get('AccountId') != scope.split('/', 1)[0]
                    or get(row, '_provenance.read_only', bool) is not True
                    or get(row, '_provenance.source_operation', str) != 'ListPoliciesForTarget+DescribePolicy+ListParents'):
                raise Unavailable('attached policy digest binding invalid')
            try:
                entries = validate_assignments(row['TagValueDigests'])
            except (ValueError, TypeError, ReadFailure):
                raise Unavailable('attached policy digests malformed') from None
            tags = {entry['TagKey']: entry for entry in entries}
            matches = all(key in tags and tags[key]['ConstraintKind'] == 'finite'
                and tags[key]['ValueDigests'] == sorted(value_digest(arn, pid, key, value) for value in set(values))
                for key, values in approved.items())
        else:
            tags = get(row, "Ec2Tags", dict)
            matches = all(set(values) == set(_strings(get(tags, key, list), nonempty=False) if key in tags else ())
                          for key, values in approved.items())
        if matches:
            matching.append(pid)
    return result(not matching, matching_attached_tag_policy_ids=sorted(matching))


@register("aws_account_non_eu_resource_region_detected", "aws", "hardening", "aws_data_resource",
          "Customer data resources reside in approved EU regions", "medium", "SC-28",
          "Move listed data resources to approved EU Regions.",
          target="scope", dependencies=["aws_enabled_region", "aws_data_resource", "aws_data_resource_coverage"],
          allow_incomplete_failure=True)
def data_resource_region(item, index):
    _, scope, account, _ = _context(index, global_scope=None)
    _subject(item, scope)
    approved = set(_strings(_policy(index, "approved_region_names", list)))
    if any(not _REGION.fullmatch(region) or not region.startswith("eu-") for region in approved):
        raise Unavailable("approved EU Region list malformed")
    if "aws_data_region_owner" in get(index, "context.metadata", dict):
        bad = _native_region_counterexamples(index, account, approved)
        if bad:
            return result(True, resources_outside_approved_regions=bad,
                          semantics="Native resource location signal only; customer-data classification unverified")
    regions = _inventory(index, "aws_enabled_region", scope, allow_global=True)
    enabled, seen_regions = set(), set()
    for row in regions:
        region = get(row, "RegionName", str)
        status = get(row, "OptInStatus", str)
        if not _REGION.fullmatch(region) or region in seen_regions or status not in {"opt-in-not-required", "opted-in", "not-opted-in"}:
            raise Unavailable("malformed enabled-region inventory")
        seen_regions.add(region)
        if status != "not-opted-in":
            enabled.add(region)
    if not enabled:
        raise Unavailable("no enabled AWS Regions proven")
    services = {"s3", "rds", "ec2_volume", "dynamodb", "efs", "redshift", "backup"}
    coverage = _inventory(index, "aws_data_resource_coverage", scope, allow_global=True)
    covered = set()
    for row in coverage:
        region, service = get(row, "Region", str), get(row, "Service", str)
        if region not in enabled or service not in services or get(row, "Complete", bool) is not True or (region, service) in covered:
            raise Unavailable("incomplete or duplicate data-service coverage")
        covered.add((region, service))
    if covered != {(region, service) for region in enabled for service in services}:
        raise Unavailable("enabled-region data inventory incomplete")
    resources = _inventory(index, "aws_data_resource", scope, allow_global=True)
    seen, bad = set(), []
    for row in resources:
        rid = _nonempty(get(row, "ResourceId", str))
        region, service = get(row, "Region", str), get(row, "Service", str)
        if get(row, "AccountId", str) != account or rid in seen or region not in enabled or service not in services:
            raise Unavailable("duplicate or foreign data resource")
        seen.add(rid)
        if region not in approved:
            bad.append(rid)
    return result(bool(bad), resources_outside_approved_regions=sorted(bad),
                  semantics="Resource location signal only; customer-data classification unverified")


def _native_region_counterexamples(index, account, approved):
    """Validate positive native facts; never infer completeness from a partial list."""
    from datetime import datetime
    from peaso.collectors.aws_region_data_native import VERSION, CATALOG
    owner = _policy(index, "aws_data_region_owner", dict)
    if (set(owner) != {"scope", "authorized_by", "document_id", "observed_at", "expires_at", "approved_region_names"}
            or get(owner, "scope", str) != account + "/global"
            or set(_strings(get(owner, "approved_region_names", list))) != approved):
        raise Unavailable("native data-region owner binding unavailable")
    for field in ("authorized_by", "document_id"):
        value = get(owner, field, str)
        if not value.strip() or len(value) > 512 or any(ord(c) < 32 for c in value):
            raise Unavailable("native data-region owner identity unavailable")
    at, expires, captured = [datetime.fromisoformat(value.replace("Z", "+00:00")) for value in (
        get(owner, "observed_at", str), get(owner, "expires_at", str), get(index, "context.created_at", str))]
    if any(d.utcoffset() is None for d in (at, expires, captured)) or not at <= captured < expires:
        raise Unavailable("native data-region owner approval is not current")
    envelopes = get(index, "collections", dict).get("aws_data_resource")
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("native data-resource inventory unavailable")
    envelope = envelopes[0]
    native_scope = account + "/global"
    if (get(envelope, "type", str) != "aws_data_resource" or get(envelope, "scope", str) != native_scope
            or get(envelope, "global", bool) is not True or get(envelope, "account_id", str) != account
            or get(envelope, "service", str) != "ec2"
            or get(envelope, "status", str) not in {"collected", "empty", "partial"}):
        raise Unavailable("native data-resource envelope authority unavailable")
    rows, wrappers = get(envelope, "items", list), get(index, "aws_data_resource", list)
    if len(rows) != len(wrappers) or (envelope["status"] == "empty" and rows):
        raise Unavailable("native data-resource projection inconsistent")
    types = {op: (group, service) for group, service, op, _, _ in CATALOG if op != "list_outposts"}
    forms = {
        "list_directory_buckets": r"bucket/[^/]+", "list_table_buckets": r"bucket/[^/]+",
        "list_vector_buckets": r"bucket/[^/]+", "describe_db_instances": r"db:[^:]+",
        "describe_db_clusters": r"cluster:[^:]+", "describe_db_snapshots": r"snapshot:.+",
        "describe_db_cluster_snapshots": r"cluster-snapshot:.+",
        "describe_db_instance_automated_backups": r"auto-backup:.+",
        "describe_db_cluster_automated_backups": r"cluster-auto-backup:.+",
        "describe_volumes": r"volume/vol-(?:[a-f0-9]{8}|[a-f0-9]{17})",
        "describe_snapshots": r"snapshot/snap-(?:[a-f0-9]{8}|[a-f0-9]{17})",
        "list_tables": r"table/[^/]+", "list_backups": r"table/[^/]+/backup/[^/]+",
        "describe_file_systems": r"file-system/fs-[a-f0-9]+", "describe_clusters": r"cluster:.+",
        "describe_cluster_snapshots": r"snapshot:.+", "list_namespaces": r"namespace/[^/]+",
        "list_snapshots": r"snapshot/[^/]+", "list_recovery_points": r"recoverypoint/[^/]+",
        "list_backup_vaults": r"backup-vault:[^:]+",
    }
    seen, bad = set(), []
    for row, wrapper in zip(rows, wrappers):
        if (not isinstance(row, dict) or get(wrapper, "type", str) != "aws_data_resource"
                or get(wrapper, "scope", str) != native_scope or get(wrapper, "data", dict) != row
                or wrapper.get("provider", "aws") != "aws"):
            raise Unavailable("native data-resource wrapper is foreign or inconsistent")
        rid = get(row, "ResourceId", str)
        region, group, kind = get(row, "Region", str), get(row, "Service", str), get(row, "NativeType", str)
        if (not rid or rid in seen or get(row, "id", str) != rid or get(row, "AccountId", str) != account
                or not _REGION.fullmatch(region)):
            raise Unavailable("native data-resource identity malformed or foreign")
        seen.add(rid)
        proof = get(row, "_provenance", dict)
        if (get(proof, "read_only", bool) is not True or get(proof, "catalog_version", str) != VERSION
                or get(proof, "location_only", bool) is not True):
            raise Unavailable("native data-resource location provenance unavailable")
        partition = next((p for prefix, p in (("cn-", "aws-cn"), ("us-gov-", "aws-us-gov"),
            ("us-isob-", "aws-iso-b"), ("us-iso-", "aws-iso"), ("eu-isoe-", "aws-iso-e"),
            ("us-isof-", "aws-iso-f")) if region.startswith(prefix)), "aws")
        arn = _arn(rid)
        if arn.group(1) != partition or any(c in arn.group(5) for c in ("%", "\\", "?", "#")) or re.search(r"\s", rid):
            raise Unavailable("native data-resource ARN partition or path differs")
        if kind == "general-purpose-bucket":
            if (group != "s3" or arn.group(2) != "s3" or arn.group(3) or arn.group(4)
                    or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", arn.group(5))):
                raise Unavailable("native bucket location identity differs")
        else:
            if (kind == "vault-recovery-point" and group == "backup" and arn.group(2) == "ec2"
                    and arn.group(3) == region and arn.group(4) is None
                    and re.fullmatch(r"snapshot/snap-(?:[a-f0-9]{8}|[a-f0-9]{17})", arn.group(5))):
                # The producer validates its vault, but this alias has no ARN
                # owner. It cannot independently establish a partial-list FAIL.
                # The original complete-universe path below remains available.
                continue
            if arn.group(3) != region or arn.group(4) != account:
                raise Unavailable("native data-resource ARN differs from account/Region")
            if kind == "outposts-bucket-control-plane-region":
                expected_group, service, form = "s3", "s3-outposts", r"outpost/op-[a-f0-9]{17}/bucket/[^/]+"
            elif kind == "vault-recovery-point":
                # Backup can return references to service-native snapshots.
                recovery_forms = {"backup": r"recovery-point:.+", "ec2": r"snapshot/snap-(?:[a-f0-9]{8}|[a-f0-9]{17})",
                    "rds": r"(?:snapshot|cluster-snapshot):.+", "dynamodb": r"table/[^/]+/backup/[^/]+",
                    "redshift": r"snapshot:.+", "redshift-serverless": r"snapshot/[^/]+"}
                service = arn.group(2)
                if service not in recovery_forms:
                    raise Unavailable("native recovery-point subtype is not supported")
                expected_group, form = "backup", recovery_forms[service]
            elif kind in types and kind in forms:
                expected_group, service = types[kind]
                form = forms[kind]
            else:
                raise Unavailable("native data-resource subtype is not supported")
            if group != expected_group or arn.group(2) != service or not re.fullmatch(form, arn.group(5)):
                raise Unavailable("native data-resource service/subtype differs from ARN")
        if region not in approved:
            bad.append(rid)
    return sorted(bad)
