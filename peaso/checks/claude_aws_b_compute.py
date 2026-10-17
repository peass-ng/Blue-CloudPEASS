"""claude_aws_b compute: Lambda, Lightsail, SageMaker."""
from __future__ import annotations

from datetime import date, timedelta, timezone

from . import result
from .facts import Unavailable, get, list_of_objects, complete_items
from .claude_aws_b_common import (install, flag, absent_or, strings, clock, policy_document, kms_manager, turbot_public_statements,
    wildcard_allow_statements, scope_of, inventory, indexes, CONTEXT, _as_list)

P, C, X = "prowler.aws.", "aws-compliance.control.", "aws-perimeter.control."
KMS_ARN = "arn:aws:kms:us-east-1:111111111111:key/k1"

# =========================================================================== Lambda
D_LAMBDA = "https://docs.aws.amazon.com/lambda/latest/api/API_FunctionConfiguration.html"
FN = "arn:aws:lambda:us-east-1:111111111111:function:f"
BASE = {"FunctionName": "f", "FunctionArn": FN, "PackageType": "Zip"}
ABSENT = {"collection_status": "empty", "absent": True, "error": {"code": "ResourceNotFoundException"}}


def _fn(policy=None, **fields):
    out = {**BASE, **fields}
    out["Policy"] = ABSENT if policy is None else {"Policy": policy, "RevisionId": "r"}
    return out


def lambda_policy(item):
    container = get(item, "Policy", dict)
    if container.get("collection_status") == "empty" and container.get("absent") is True:
        return None
    return policy_document(get(container, "Policy"))


_PUBLIC = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction", "Resource": FN}]}
_SERVICE = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "lambda:InvokeFunction", "Resource": FN,
                           "Condition": {"ArnLike": {"AWS:SourceArn": "arn:aws:s3:::b"}}}]}


@install("aws.cb.lambda.kms_key_configured", "lambda_function", "Lambda function environment is encrypted with a declared KMS key",
    _fn(KMSKeyArn=KMS_ARN), _fn(), rows=[C + "lambda_function_encryption_enabled"], severity="medium", control="SC-28",
    remediation="Configure KMSKeyArn (a customer managed key) for the function's environment variables.", docs=[D_LAMBDA],
    note="Steampipe: kms_key_arn null alarms. ListFunctions omits KMSKeyArn when the AWS-managed default is used; FunctionArn proves the configuration was read.")
def lambda_kms(item, index):
    value = absent_or(item, "FunctionArn", "KMSKeyArn", None, str)
    return result(not value, kms_key_arn=value)


@install("aws.cb.lambda.logging_config_present", "lambda_function", "Lambda function returns a logging configuration",
    _fn(LoggingConfig={"LogFormat": "JSON", "LogGroup": "/aws/lambda/f"}), _fn(LoggingConfig=None),
    rows=[C + "lambda_function_logging_config_enabled"], severity="low", control="AU-2",
    remediation="Configure the function LoggingConfig (log format, levels and log group).", docs=["https://docs.aws.amazon.com/lambda/latest/api/API_LoggingConfig.html"],
    note="Steampipe: logging_config null alarms. AWS now returns LoggingConfig for every function, so an omitted member is UNKNOWN (not read) rather than FAIL; explicit null fails.")
def lambda_logging(item, index):
    if "LoggingConfig" not in item and "LoggingConfig" not in item.get("_coverage", {}):
        get(item, "FunctionArn", str)
        raise Unavailable("LoggingConfig not reported")
    value = item.get("LoggingConfig")
    if value is not None:
        value = get(item, "LoggingConfig", dict)
    return result(value is None, logging_config=bool(value))


def _subnets(*zones):
    return inventory("subnet", [{"SubnetId": "subnet-%d" % i, "AvailabilityZoneId": z} for i, z in enumerate(zones)])


@install("aws.cb.lambda.vpc_multiple_az", "lambda_function", "VPC-attached Lambda function spans at least two Availability Zones",
    _fn(VpcConfig={"VpcId": "vpc-1", "SubnetIds": ["subnet-0", "subnet-1"]}), _fn(VpcConfig={"VpcId": "vpc-1", "SubnetIds": ["subnet-0", "subnet-2"]}),
    rows=[C + "lambda_function_multiple_az_configured"], severity="medium", control="CP-10", remediation="Attach the function to subnets in at least two Availability Zones.",
    docs=["https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html"], dependencies=["lambda_function", "subnet"],
    extra={"index": _subnets("use1-az1", "use1-az2", "use1-az1"), "not_applicable": _fn(VpcConfig={"VpcId": "", "SubnetIds": []})},
    note="Steampipe skips functions without a VPC and counts distinct subnet AvailabilityZoneId values; a referenced subnet missing from the complete inventory is UNKNOWN.")
def lambda_azs(item, index):
    vpc = absent_or(item, "FunctionArn", "VpcConfig.VpcId", "", str)
    if not vpc:
        return "NOT_APPLICABLE", {"vpc_id": None}
    ids = strings(get(item, "VpcConfig.SubnetIds", list))
    subnets = {get(s, "SubnetId", str): s for s in complete_items(index, "subnet")}
    if any(i not in subnets for i in ids):
        raise Unavailable("function subnet not in subnet inventory")
    zones = sorted({get(subnets[i], "AvailabilityZoneId", str) for i in ids})
    return result(len(zones) < 2, availability_zone_ids=zones)


@install("aws.cb.lambda.policy_no_wildcard_allow", "lambda_function", "Lambda function policy has no wildcard-principal Allow",
    _fn(_SERVICE), _fn(_PUBLIC), rows=[C + "lambda_function_restrict_public_access"], severity="high", category="exposure", control="AC-3",
    remediation="Remove Allow statements for Principal \"*\" from the function resource policy.", docs=["https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html"],
    extra={"absent": _fn()}, note="aws-compliance ignores conditions; a function without a resource policy is ok.")
def lambda_public_c(item, index):
    statements = lambda_policy(item)
    if statements is None:
        return result(False, policy=None)
    hits = wildcard_allow_statements(statements)
    return result(bool(hits), statements=len(hits))


@install("aws.cb.lambda.policy_prohibit_public_access_perimeter", "lambda_function", "Lambda function policy does not allow public access (perimeter)",
    _fn(_SERVICE), _fn(_PUBLIC), rows=[X + "lambda_function_policy_prohibit_public_access"], severity="high", category="exposure", control="AC-3",
    remediation="Remove wildcard principals or add restricting conditions to the function policy.", docs=["https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html"],
    extra={"not_applicable": _fn()}, note="aws-perimeter resource_policy_public_sql; no policy is info (NOT_APPLICABLE).")
def lambda_public_x(item, index):
    statements = lambda_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    hits = turbot_public_statements(statements)
    return result(bool(hits), statements=len(hits))


RUNTIME_POLICY_REVIEWED_AT = "2026-10-12"
# AWS promises at least 180 days' deprecation notice. After that interval a
# fresh provider review is required before this snapshot claims support.
RUNTIME_POLICY_VALID_THROUGH = (date.fromisoformat(RUNTIME_POLICY_REVIEWED_AT) + timedelta(days=180)).isoformat()
# AWS Lambda runtime lifecycle table reviewed on the above date. These are
# deprecation dates, not the later dates on which AWS blocks updates.
RUNTIME_DEPRECATION = {
    "nodejs24.x": "2028-04-30", "nodejs22.x": "2027-04-30", "nodejs20.x": "2026-04-30",
    "nodejs18.x": "2025-09-01", "nodejs16.x": "2024-06-12", "nodejs14.x": "2023-12-04",
    "nodejs12.x": "2023-03-31", "nodejs10.x": "2021-07-30", "nodejs8.10": "2020-03-06",
    "nodejs6.10": "2019-08-12", "nodejs4.3": "2020-03-05", "nodejs4.3-edge": "2020-03-05",
    "nodejs": "2016-08-30", "python3.14": "2029-06-30", "python3.13": "2029-06-30",
    "python3.12": "2028-10-31", "python3.11": "2027-06-30", "python3.10": "2026-10-31",
    "python3.9": "2025-12-15", "python3.8": "2024-10-14", "python3.7": "2023-12-04",
    "python3.6": "2022-07-18", "python2.7": "2021-07-15",
    "java25": "2029-06-30", "java21": "2029-06-30", "java17.al2023": "2029-06-30",
    "java11.al2023": "2029-06-30", "java8.al2023": "2029-06-30",
    "java17": "2027-06-30", "java11": "2027-06-30", "java8.al2": "2027-06-30",
    "java8": "2024-01-08", "dotnet10": "2028-11-14", "dotnet8": "2026-11-10",
    "dotnet6": "2024-12-20", "dotnetcore3.1": "2023-04-03",
    "dotnetcore2.1": "2022-01-05", "dotnetcore2.0": "2019-05-30",
    "dotnetcore1.0": "2019-06-27", "ruby4.0": "2029-03-31",
    "ruby3.4": "2028-03-31", "ruby3.3": "2027-03-31", "ruby3.2": "2026-03-31",
    "ruby2.7": "2023-12-07", "ruby2.5": "2021-07-30", "go1.x": "2024-01-08",
}


@install("aws.cb.lambda.runtime_not_deprecated_list", "lambda_function", "Zip Lambda managed runtime is supported at the captured scan date (AWS lifecycle reviewed 2026-10-12)",
    _fn(Runtime="python3.12"), _fn(Runtime="python3.8"), rows=[C + "lambda_function_use_latest_runtime"], severity="medium", control="SI-2",
    remediation="Upgrade the function to a currently supported Lambda runtime.", docs=["https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"],
    extra={"index": {"context": dict(CONTEXT)}, "not_applicable": _fn(PackageType="Image"), "unlisted": _fn(Runtime="future99.x")},
    note="Semantic correction to pinned aws-compliance latest/deprecated lists: use AWS Lambda runtime deprecation dates reviewed 2026-10-12 and captured scan clock; re-review after the documented 180-day deprecation-notice window. Unlisted runtimes are UNKNOWN; Image/custom runtime support is outside this managed-runtime check.")
def lambda_runtime(item, index):
    package = get(item, "PackageType", str)
    if package == "Image":
        return "NOT_APPLICABLE", {"package_type": package}
    if package != "Zip":
        raise Unavailable("unrecognized Lambda package type")
    runtime = get(item, "Runtime", str)
    if runtime.startswith("provided"):
        return "NOT_APPLICABLE", {"runtime": runtime, "reason": "custom OS-only runtime"}
    deprecation = RUNTIME_DEPRECATION.get(runtime)
    if deprecation is None:
        raise Unavailable("runtime absent from AWS lifecycle snapshot")
    observed = clock(item, index).date().isoformat()
    if observed > RUNTIME_POLICY_VALID_THROUGH:
        raise Unavailable("scan exceeds reviewed AWS runtime lifecycle notice window")
    return result(observed >= deprecation, runtime=runtime, deprecated_on=deprecation,
                  assessed_at=observed, lifecycle_reviewed_at=RUNTIME_POLICY_REVIEWED_AT,
                  lifecycle_valid_through=RUNTIME_POLICY_VALID_THROUGH)


def _trails(selectors=None, advanced=None):
    return inventory("cloudtrail", [{"Name": "t", "TrailARN": "arn:aws:cloudtrail:us-east-1:111111111111:trail/t",
                                     "HomeRegion": "us-east-1", "IsMultiRegionTrail": False,
                                     "Status": {"IsLogging": True},
                                     "EventSelectors": {"EventSelectors": selectors or [], **({"AdvancedEventSelectors": advanced} if advanced else {})}}])


def _trail_covers(trail, arn):
    if not get(trail, "Status.IsLogging", bool):
        return False
    parts = arn.split(":")
    if len(parts) < 7 or parts[2] != "lambda" or not parts[3]:
        raise Unavailable("malformed Lambda function ARN")
    region = parts[3]
    function_account = parts[4]
    trail_arn = get(trail, "TrailARN", str)
    trail_parts = trail_arn.split(":")
    if len(trail_parts) < 6 or trail_parts[2] != "cloudtrail":
        raise Unavailable("malformed CloudTrail ARN")
    if trail_parts[4] != function_account:
        raise Unavailable("cross-account trail scope not verified")
    if not get(trail, "IsMultiRegionTrail", bool) and get(trail, "HomeRegion", str) != region:
        return False
    body = get(trail, "EventSelectors", dict)
    if "EventSelectors" not in body and "AdvancedEventSelectors" not in body:
        raise Unavailable("CloudTrail event selectors not reported")
    basic = list_of_objects(body.get("EventSelectors", []))
    advanced = list_of_objects(body.get("AdvancedEventSelectors", []))
    if basic and advanced:
        raise Unavailable("CloudTrail cannot apply basic and advanced selectors together")
    unread_selector = False
    for selector in basic:
        try:
            if _basic_selector_covers(selector, arn):
                return True
        except Unavailable:
            unread_selector = True
    for selector in advanced:
        try:
            if _advanced_selector_covers(selector, arn):
                return True
        except Unavailable:
            unread_selector = True
    if unread_selector:
        raise Unavailable("one or more CloudTrail selectors are malformed or need event context")
    return False


def _basic_selector_covers(selector, arn):
    mode = selector.get("ReadWriteType", "All")
    if mode not in ("All", "WriteOnly", "ReadOnly"):
        raise Unavailable("malformed CloudTrail ReadWriteType")
    if mode == "ReadOnly":
        return False
    for data in list_of_objects(selector.get("DataResources", [])):
        if get(data, "Type", str) != "AWS::Lambda::Function":
            continue
        if any(_basic_lambda_value_covers(v, arn) for v in strings(get(data, "Values", list))):
            return True
    return False


def _advanced_selector_covers(selector, arn):
    fields = list_of_objects(get(selector, "FieldSelectors", list))
    by_name = {get(f, "Field", str): f for f in fields}
    if len(by_name) != len(fields):
        raise Unavailable("duplicate CloudTrail selector field")
    category = by_name.get("eventCategory")
    if not category:
        raise Unavailable("CloudTrail advanced selector lacks eventCategory")
    _equals_only(category)
    if "Data" not in strings(get(category, "Equals", list)) or not _selector_allows(category, "Data"):
        return False
    resource_type = by_name.get("resources.type")
    if not resource_type:
        raise Unavailable("CloudTrail Data selector lacks resources.type")
    _equals_only(resource_type)
    if "AWS::Lambda::Function" not in strings(get(resource_type, "Equals", list)) or not _selector_allows(resource_type, "AWS::Lambda::Function"):
        return False
    if not _selector_allows(by_name.get("resources.ARN"), arn):
        return False
    if not _selector_allows(by_name.get("eventName"), "Invoke"):
        return False
    if by_name.get("readOnly") is not None:
        _equals_only(by_name["readOnly"])
    if not _selector_allows(by_name.get("readOnly"), "false"):
        return False
    if any(name not in {"eventCategory", "resources.type", "resources.ARN", "eventName", "readOnly"}
           for name in by_name):
        raise Unavailable("additional CloudTrail data selector needs event context")
    return True


def _equals_only(field):
    if set(field) != {"Field", "Equals"}:
        raise Unavailable("CloudTrail selector field requires nonempty Equals only")
    values = strings(get(field, "Equals", list))
    if not values or any(not value for value in values):
        raise Unavailable("CloudTrail selector Equals values are empty")


def _basic_lambda_value_covers(value, arn):
    """CloudTrail DataResource accepts partial ARNs, but full function ARNs are exact."""
    value = value.rstrip("/")
    parts = arn.split(":")
    root = ":".join(parts[:3])
    if value == root or value == arn:
        return True
    # The account/region and function-kind prefixes have token boundaries;
    # a prefix ending inside a function name must not match another function.
    prefixes = {":".join(parts[:4]), ":".join(parts[:5]), ":".join(parts[:6]) + ":"}
    return value in prefixes


def _selector_allows(field, value):
    if field is None:
        return True
    operations = {"Equals": lambda x: value == x, "StartsWith": lambda x: value.startswith(x),
                  "EndsWith": lambda x: value.endswith(x),
                  "NotEquals": lambda x: value == x, "NotStartsWith": lambda x: value.startswith(x),
                  "NotEndsWith": lambda x: value.endswith(x)}
    if not set(field).intersection(operations) or set(field) - set(operations) - {"Field"}:
        raise Unavailable("unrecognized CloudTrail selector operation")
    for key, match in operations.items():
        if key not in field:
            continue
        values = strings(get(field, key, list))
        if not values or any(not entry for entry in values):
            raise Unavailable("empty CloudTrail selector values")
        matches = [match(x) for x in values]
        if key.startswith("Not") and any(matches):
            return False
        if not key.startswith("Not") and not any(matches):
            return False
    return True


@install("aws.cb.lambda.cloudtrail_data_events", "lambda_function", "Lambda function invocations are captured by a CloudTrail data event selector",
    _fn(), _fn(), rows=[C + "lambda_function_cloudtrail_logging_enabled"], severity="low", control="AU-2",
    remediation="Add a CloudTrail data event selector for AWS::Lambda::Function (all functions or this ARN).",
    docs=["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"], dependencies=["lambda_function", "cloudtrail"],
    extra={"pass_index": _trails([{"DataResources": [{"Type": "AWS::Lambda::Function", "Values": ["arn:aws:lambda"]}]}]),
           "fail_index": _trails([{"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}])},
    note="Semantic correction to pinned Steampipe SQL: require an actively logging, region-covering trail and a Lambda Data selector that includes Invoke and this ARN. The pinned query accepted unrelated advanced fields and did not inspect IsLogging; unread status/selectors are UNKNOWN.")
def lambda_trail(item, index):
    arn = get(item, "FunctionArn", str)
    trails = complete_items(index, "cloudtrail")
    covered = []
    unread = False
    for trail in trails:
        try:
            if _trail_covers(trail, arn):
                covered.append(get(trail, "Name", str))
        except Unavailable:
            unread = True
    if not covered and unread:
        raise Unavailable("CloudTrail coverage uncertain for one or more trails")
    return result(not covered, trails=covered)


# =========================================================================== Lightsail
D_LS = "https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_Instance.html"
LS = {"name": "i", "arn": "arn:aws:lightsail:us-east-1:111111111111:Instance/i"}


def _ls(ports=None, **fields):
    return {**LS, "networking": {"ports": ports or []}, **fields}


def _port(low, high, cidrs=(), ipv6=(), protocol="tcp", access="public"):
    return {"fromPort": low, "toPort": high, "protocol": protocol, "cidrs": list(cidrs), "ipv6Cidrs": list(ipv6), "accessType": access}


def _ports(item):
    return list_of_objects(get(item, "networking.ports", list))


@install("aws.cb.lightsail.instance_auto_snapshot", "lightsail_instance", "Lightsail instance has automatic snapshots enabled",
    _ls(addOns=[{"name": "AutoSnapshot", "status": "Enabled"}]), _ls(addOns=[]), rows=[P + "lightsail_instance_automated_snapshots"], severity="medium", control="CP-9",
    remediation="Enable the AutoSnapshot add-on on the instance.", docs=[D_LS])
def ls_snap(item, index):
    addons = list_of_objects(absent_or(item, "arn", "addOns", [], list))
    on = any(a.get("name") == "AutoSnapshot" and a.get("status") == "Enabled" for a in addons)
    return result(not on, auto_snapshot=on)


@install("aws.cb.lightsail.instance_ipv6_disabled", "lightsail_instance", "Lightsail instance has no IPv6 addresses",
    _ls(), _ls(ipv6Addresses=["2600::1"]), rows=[C + "lightsail_instance_ipv6_networking_disabled"], severity="low", category="network", control="SC-7",
    remediation="Disable IPv6 networking on the instance if it is not required.", docs=[D_LS], note="Steampipe: ip_v6_addresses null is ok; an empty list is treated as no addresses.")
def ls_ipv6(item, index):
    value = absent_or(item, "arn", "ipv6Addresses", [], list)
    return result(bool(value), ipv6_addresses=value)


@install("aws.cb.lightsail.instance_not_public", "lightsail_instance", "Lightsail instance with a public IP has no public port ranges",
    _ls([_port(22, 22, access="private")], publicIpAddress="1.2.3.4"), _ls([_port(22, 22, ["0.0.0.0/0"])], publicIpAddress="1.2.3.4"),
    rows=[P + "lightsail_instance_public"], severity="high", category="exposure", control="SC-7", remediation="Close public port ranges or detach the public IP.", docs=[D_LS])
def ls_public(item, index):
    ip = absent_or(item, "arn", "publicIpAddress", "", str)
    public = [p for p in _ports(item) if p.get("accessType") == "public"]
    return result(bool(ip) and bool(public), public_ip=ip, public_ports=len(public))


def _open_ports(item, froms, tos, ipv6=False):
    hits = []
    for p in _ports(item):
        if p.get("protocol") != "tcp" or p.get("fromPort") not in froms or p.get("toPort") not in tos:
            continue
        cidrs = strings(p.get("cidrs") or [])
        v6 = strings(p.get("ipv6Cidrs") or [])
        if "0.0.0.0/0" in cidrs or (ipv6 and "::/0" in v6):
            hits.append(p.get("fromPort"))
    return hits


@install("aws.cb.lightsail.ssh_rdp_http_world_closed", "lightsail_instance", "Lightsail instance does not expose SSH, RDP or HTTP ports to the world",
    _ls([_port(22, 22, ["10.0.0.0/8"])]), _ls([_port(80, 80, ipv6=["::/0"])]), rows=[C + "lightsail_instance_ssh_rdp_http_ports_disabled"], severity="high", category="network", control="SC-7",
    remediation="Restrict ports 22, 3389 and 80 to specific source addresses or close them.", docs=[D_LS],
    note="Semantic correction to pinned Steampipe query's to_port 338 typo: match actual RDP 3389, plus SSH 22 and HTTP 80, TCP, 0.0.0.0/0 or ::/0.")
def ls_world(item, index):
    hits = _open_ports(item, (22, 3389, 80), (22, 3389, 80), ipv6=True)
    return result(bool(hits), open_ports=hits)


for _cid, _port_no, _row, _name in (("aws.cb.lightsail.ssh_restricted", 22, "lightsail_instance_ssh_restricted_ip", "SSH"),
                                   ("aws.cb.lightsail.rdp_restricted", 3389, "lightsail_instance_rdp_restricted_ip", "RDP")):
    def _ls_port(cid, port, row, name):
        @install(cid, "lightsail_instance", "Lightsail instance does not open " + name + " (" + str(port) + ") to 0.0.0.0/0",
            _ls([_port(port, port, ["203.0.113.0/24"])]), _ls([_port(port, port, ["0.0.0.0/0"])]), rows=[C + row], severity="high", category="network", control="SC-7",
            remediation="Restrict " + name + " to specific source IP addresses.", docs=[D_LS])
        def evaluate(item, index):
            hits = _open_ports(item, (port,), (port,))
            return result(bool(hits), open_ports=hits)
    _ls_port(_cid, _port_no, _row, _name)


flag("aws.cb.lightsail.database_not_public", "lightsail_database", "Lightsail database is not publicly accessible", "publiclyAccessible",
     rows=[P + "lightsail_database_public"], severity="high", category="exposure", control="SC-7", remediation="Disable public mode on the Lightsail database.",
     sentinel="arn", base={"name": "d", "arn": "arn:aws:lightsail:us-east-1:111111111111:RelationalDatabase/d"}, good=False, bad=True,
     docs=["https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_RelationalDatabase.html"])
flag("aws.cb.lightsail.static_ip_attached", "lightsail_static_ip", "Lightsail static IP is attached to an instance", "isAttached",
     rows=[P + "lightsail_static_ip_unused"], severity="low", remediation="Attach or release the unused static IP.",
     sentinel="arn", base={"name": "ip", "arn": "arn:aws:lightsail:us-east-1:111111111111:StaticIp/ip"}, docs=["https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_StaticIp.html"])


# =========================================================================== SageMaker
D_NB = "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeNotebookInstance.html"
D_TJ = "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeTrainingJob.html"
D_MODEL = "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeModel.html"
D_EPC = "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeEndpointConfig.html"
NB = {"NotebookInstanceArn": "arn:aws:sagemaker:us-east-1:111111111111:notebook-instance/n"}
TJ = {"TrainingJobArn": "arn:aws:sagemaker:us-east-1:111111111111:training-job/t"}
MODEL = {"ModelArn": "arn:aws:sagemaker:us-east-1:111111111111:model/m"}
EPC = {"EndpointConfigArn": "arn:aws:sagemaker:us-east-1:111111111111:endpoint-config/e"}

# --- notebook instances
flag("aws.cb.sagemaker.notebook_no_direct_internet", "sagemaker_notebook_instance", "SageMaker notebook instance has direct internet access disabled", "DirectInternetAccess",
     rows=[C + "sagemaker_notebook_instance_direct_internet_access_disabled", X + "sagemaker_notebook_instance_direct_internet_access_disabled", P + "sagemaker_notebook_instance_without_direct_internet_access_configured"],
     severity="high", category="network", control="SC-7", remediation="Recreate the notebook instance in a VPC with DirectInternetAccess Disabled.", sentinel="NotebookInstanceArn", base=NB,
     good="Disabled", bad="Enabled", expected=str, docs=[D_NB], note="Unread DirectInternetAccess is UNKNOWN (prowler MANUAL; steampipe would treat null as ok).")


@install("aws.cb.sagemaker.notebook_kms_key", "sagemaker_notebook_instance", "SageMaker notebook instance storage uses a KMS key",
    {**NB, "KmsKeyId": KMS_ARN}, dict(NB), rows=[C + "sagemaker_notebook_instance_encryption_at_rest_enabled", P + "sagemaker_notebook_instance_encryption_enabled"],
    severity="medium", control="SC-28", remediation="Recreate the notebook instance with a KMS key for the ML storage volume.", docs=[D_NB])
def nb_kms(item, index):
    value = absent_or(item, "NotebookInstanceArn", "KmsKeyId", None, str)
    return result(not value, kms_key_id=value)


@install("aws.cb.sagemaker.notebook_cmk", "sagemaker_notebook_instance", "SageMaker notebook instance storage uses a customer managed KMS key",
    {**NB, "KmsKeyId": KMS_ARN}, dict(NB), rows=[C + "sagemaker_notebook_instance_encrypted_with_kms_cmk"], severity="medium", control="SC-28",
    remediation="Recreate the notebook instance with a customer managed KMS key.", docs=[D_NB], dependencies=["sagemaker_notebook_instance", "kms_key"],
    extra={"index": inventory("kms_key", [{"Metadata": {"KeyMetadata": {"Arn": KMS_ARN, "KeyId": "k1", "KeyManager": "CUSTOMER"}}}])})
def nb_cmk(item, index):
    value = absent_or(item, "NotebookInstanceArn", "KmsKeyId", None, str)
    if not value:
        return result(True, kms_key_id=None)
    return result(kms_manager(index, value) != "CUSTOMER", kms_key_id=value)


@install("aws.cb.sagemaker.notebook_in_vpc", "sagemaker_notebook_instance", "SageMaker notebook instance is attached to a VPC subnet",
    {**NB, "SubnetId": "subnet-1"}, dict(NB), rows=[C + "sagemaker_notebook_instance_in_vpc", X + "sagemaker_notebook_instance_in_vpc", P + "sagemaker_notebook_instance_vpc_settings_configured"],
    severity="medium", category="network", control="SC-7", remediation="Recreate the notebook instance with a SubnetId and security groups.", docs=[D_NB])
def nb_vpc(item, index):
    value = absent_or(item, "NotebookInstanceArn", "SubnetId", None, str)
    return result(not value, subnet_id=value)


flag("aws.cb.sagemaker.notebook_root_access_disabled", "sagemaker_notebook_instance", "SageMaker notebook instance root access is disabled", "RootAccess",
     rows=[C + "sagemaker_notebook_instance_root_access_disabled", P + "sagemaker_notebook_instance_root_access_disabled"], severity="medium", control="AC-6",
     remediation="Set RootAccess to Disabled on the notebook instance.", sentinel="NotebookInstanceArn", base=NB, good="Disabled", bad="Enabled", expected=str, docs=[D_NB],
     note="Both sources treat only Disabled as compliant (prowler fails only Enabled, steampipe alarms on anything but Disabled); an unread value is UNKNOWN.")


NB_PLATFORM_POLICY_REVIEWED_AT = date(2026, 10, 12)
# Review cadence for future *supported* claims, not an AWS support-end date.
NB_PLATFORM_POLICY_VALID_THROUGH = NB_PLATFORM_POLICY_REVIEWED_AT + timedelta(days=180)


@install("aws.cb.sagemaker.notebook_supported_platform", "sagemaker_notebook_instance", "SageMaker notebook instance runs a supported platform",
    {**NB, "PlatformIdentifier": "notebook-al2023-v1"}, {**NB, "PlatformIdentifier": "notebook-al2-v3"}, rows=[C + "sagemaker_notebook_instance_supported_platform_version"],
    severity="medium", control="SI-2", remediation="Plan migration of a retired SageMaker notebook platform to notebook-al2023-v1 after checking instance type, lifecycle scripts, kernels, and workload compatibility.",
    docs=[D_NB, "https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-al2.html", "https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-al2023.html"],
    extra={"index": {"context": {**CONTEXT, "created_at": "2026-10-12T00:00:00+00:00"}},
           "unlisted": {**NB, "PlatformIdentifier": "notebook-al2024-v1"}},
    note="Pinned aws-compliance default ['notebook-al2-v3'] was a literal version policy; AWS lifecycle reviewed 2026-10-12 supersedes it. Assess the captured snapshot date: AL2023-v1 launched 2025-10-09, AL2-v3 support ended 2026-06-30, AL2-v1/v2 support ended 2025-06-30, and AL1-v1 support ended 2024-03-31. Supported claims beyond the 180-day review cadence and unlisted versions are UNKNOWN; established retirements remain FAIL.")
def nb_platform(item, index):
    value = get(item, "PlatformIdentifier", str)
    observed = clock(item, index).astimezone(timezone.utc).date()
    # These are documented support boundaries, not a rolling staleness limit.
    # An unlisted identifier requires a new source review before a judgment.
    if value == "notebook-al2023-v1":
        if observed < date(2025, 10, 9):
            raise Unavailable("AL2023 notebook platform predates documented launch")
        retired_on = None
    else:
        retired_on = {
            "notebook-al1-v1": date(2024, 3, 31),
            "notebook-al2-v1": date(2025, 6, 30),
            "notebook-al2-v2": date(2025, 6, 30),
            "notebook-al2-v3": date(2026, 6, 30),
        }.get(value)
        if retired_on is None:
            raise Unavailable("notebook platform absent from reviewed AWS lifecycle")
    if observed > NB_PLATFORM_POLICY_VALID_THROUGH and (retired_on is None or observed < retired_on):
        raise Unavailable("snapshot exceeds reviewed notebook platform lifecycle window")
    return result(retired_on is not None and observed >= retired_on,
                  platform_identifier=value, assessed_at=observed.isoformat(),
                  support_ended_on=retired_on.isoformat() if retired_on else None,
                  lifecycle_reviewed_at=NB_PLATFORM_POLICY_REVIEWED_AT.isoformat(),
                  lifecycle_valid_through=NB_PLATFORM_POLICY_VALID_THROUGH.isoformat())


# --- models
@install("aws.cb.sagemaker.model_vpc_config", "sagemaker_model", "SageMaker model declares a VPC configuration",
    {**MODEL, "VpcConfig": {"Subnets": ["subnet-1"], "SecurityGroupIds": ["sg-1"]}}, dict(MODEL), rows=[C + "sagemaker_model_in_vpc", X + "sagemaker_model_in_vpc"],
    severity="medium", category="network", control="SC-7", remediation="Recreate the model with a VpcConfig.", docs=[D_MODEL])
def model_vpc(item, index):
    value = absent_or(item, "ModelArn", "VpcConfig", None, dict)
    return result(value is None, vpc_config=bool(value))


@install("aws.cb.sagemaker.model_vpc_subnets", "sagemaker_model", "SageMaker model VPC configuration lists subnets",
    {**MODEL, "VpcConfig": {"Subnets": ["subnet-1"]}}, {**MODEL, "VpcConfig": {"Subnets": []}}, rows=[P + "sagemaker_models_vpc_settings_configured"],
    severity="medium", category="network", control="SC-7", remediation="Recreate the model with VpcConfig subnets.", docs=[D_MODEL])
def model_subnets(item, index):
    config = absent_or(item, "ModelArn", "VpcConfig", None, dict)
    subnets = strings(config.get("Subnets") or []) if config else []
    return result(not subnets, subnets=subnets)


flag("aws.cb.sagemaker.model_network_isolation", "sagemaker_model", "SageMaker model enables network isolation", "EnableNetworkIsolation",
     rows=[C + "sagemaker_model_network_isolation_enabled", P + "sagemaker_models_network_isolation_enabled"], severity="medium", category="network", control="SC-7",
     remediation="Recreate the model with EnableNetworkIsolation true.", sentinel="ModelArn", base=MODEL, docs=[D_MODEL], default=False)

# --- training jobs
@install("aws.cb.sagemaker.training_vpc_config", "sagemaker_training_job", "SageMaker training job declares a VPC configuration",
    {**TJ, "VpcConfig": {"Subnets": ["subnet-1"]}}, dict(TJ), rows=[C + "sagemaker_training_job_in_vpc", X + "sagemaker_training_job_in_vpc"],
    severity="medium", category="network", control="SC-7", remediation="Run training jobs with a VpcConfig.", docs=[D_TJ])
def tj_vpc(item, index):
    value = absent_or(item, "TrainingJobArn", "VpcConfig", None, dict)
    return result(value is None, vpc_config=bool(value))


@install("aws.cb.sagemaker.training_vpc_subnets", "sagemaker_training_job", "SageMaker training job VPC configuration lists subnets",
    {**TJ, "VpcConfig": {"Subnets": ["subnet-1"]}}, dict(TJ), rows=[P + "sagemaker_training_jobs_vpc_settings_configured"],
    severity="medium", category="network", control="SC-7", remediation="Run training jobs with VpcConfig subnets.", docs=[D_TJ])
def tj_subnets(item, index):
    config = absent_or(item, "TrainingJobArn", "VpcConfig", None, dict)
    subnets = strings(config.get("Subnets") or []) if config else []
    return result(not subnets, subnets=subnets)


flag("aws.cb.sagemaker.training_intercontainer_encryption", "sagemaker_training_job", "SageMaker training job encrypts inter-container traffic", "EnableInterContainerTrafficEncryption",
     rows=[C + "sagemaker_training_job_inter_container_traffic_encryption_enabled", P + "sagemaker_training_jobs_intercontainer_encryption_enabled"], severity="medium", control="SC-8",
     remediation="Run training jobs with EnableInterContainerTrafficEncryption true.", sentinel="TrainingJobArn", base=TJ, docs=[D_TJ], default=False)
flag("aws.cb.sagemaker.training_network_isolation", "sagemaker_training_job", "SageMaker training job enables network isolation", "EnableNetworkIsolation",
     rows=[C + "sagemaker_training_job_network_isolation_enabled", P + "sagemaker_training_jobs_network_isolation_enabled"], severity="medium", category="network", control="SC-7",
     remediation="Run training jobs with EnableNetworkIsolation true.", sentinel="TrainingJobArn", base=TJ, docs=[D_TJ], default=False)


@install("aws.cb.sagemaker.training_output_kms", "sagemaker_training_job", "SageMaker training job output data uses a KMS key",
    {**TJ, "OutputDataConfig": {"KmsKeyId": KMS_ARN, "S3OutputPath": "s3://b"}}, {**TJ, "OutputDataConfig": {"KmsKeyId": "", "S3OutputPath": "s3://b"}},
    rows=[C + "sagemaker_training_job_volume_and_data_encryption_enabled"], severity="medium", control="SC-28", remediation="Set OutputDataConfig.KmsKeyId for training jobs.", docs=[D_TJ],
    note="Steampipe checks OutputDataConfig.KmsKeyId only (null or empty alarms).")
def tj_output(item, index):
    config = get(item, "OutputDataConfig", dict)
    value = absent_or(config, "S3OutputPath", "KmsKeyId", None, str)
    return result(not value, kms_key_id=value)


@install("aws.cb.sagemaker.training_volume_kms", "sagemaker_training_job", "SageMaker training job ML storage volume uses a KMS key",
    {**TJ, "ResourceConfig": {"InstanceType": "ml.m5.large", "VolumeKmsKeyId": KMS_ARN}}, {**TJ, "ResourceConfig": {"InstanceType": "ml.m5.large"}},
    rows=[P + "sagemaker_training_jobs_volume_and_output_encryption_enabled"], severity="medium", control="SC-28", remediation="Set ResourceConfig.VolumeKmsKeyId for training jobs.", docs=[D_TJ],
    note="Prowler checks ResourceConfig.VolumeKmsKeyId only.")
def tj_volume(item, index):
    config = get(item, "ResourceConfig", dict)
    value = absent_or(config, "InstanceType", "VolumeKmsKeyId", None, str)
    return result(not value, volume_kms_key_id=value)


# --- endpoint configurations
@install("aws.cb.sagemaker.endpoint_config_kms", "sagemaker_endpoint_config", "SageMaker endpoint configuration declares a KMS key",
    {**EPC, "KmsKeyId": KMS_ARN}, dict(EPC), rows=[P + "sagemaker_endpoint_config_kms_encryption_enabled", C + "sagemaker_endpoint_configuration_encryption_at_rest_enabled"],
    severity="medium", control="SC-28", remediation="Recreate the endpoint configuration with a KmsKeyId.", docs=[D_EPC])
def epc_kms(item, index):
    value = absent_or(item, "EndpointConfigArn", "KmsKeyId", None, str)
    return result(not value, kms_key_id=value)


def _variants(*counts):
    return {**EPC, "ProductionVariants": [{"VariantName": "v%d" % i, **({"InitialInstanceCount": c} if c is not None else {})} for i, c in enumerate(counts)]}


@install("aws.cb.sagemaker.endpoint_variants_more_than_one", "sagemaker_endpoint_config", "SageMaker endpoint production variants have more than one initial instance (prowler)",
    _variants(2, 3), _variants(2, 1), rows=[P + "sagemaker_endpoint_config_prod_variant_instances"], severity="medium", control="CP-10",
    remediation="Set InitialInstanceCount above 1 for production variants.", docs=[D_EPC], extra={"serverless_pass": _variants(None)},
    note="Prowler fails InitialInstanceCount <= 1. Serverless variants without an instance count are not counted (the prowler model defaults them to 1; here they are not evidence of a single instance).")
def epc_variants_p(item, index):
    variants = list_of_objects(get(item, "ProductionVariants", list))
    bad = [v.get("VariantName") for v in variants if isinstance(v.get("InitialInstanceCount"), int) and v["InitialInstanceCount"] <= 1]
    return result(bool(bad), single_instance_variants=bad)


@install("aws.cb.sagemaker.endpoint_variants_not_exactly_one", "sagemaker_endpoint_config", "SageMaker endpoint production variants do not have exactly one initial instance (steampipe)",
    _variants(2), _variants(1), rows=[C + "sagemaker_endpoint_configuration_prod_instance_count_greater_than_one"], severity="medium", control="CP-10",
    remediation="Set InitialInstanceCount above 1 for production variants.", docs=[D_EPC], note="Steampipe alarms only when InitialInstanceCount = 1 (kept separate from the prowler <= 1 threshold).")
def epc_variants_c(item, index):
    variants = list_of_objects(get(item, "ProductionVariants", list))
    bad = [v.get("VariantName") for v in variants if v.get("InitialInstanceCount") == 1 and type(v.get("InitialInstanceCount")) is int]
    return result(bool(bad), single_instance_variants=bad)


# --- domains
D_DOM = "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeDomain.html"
DOM = {"DomainArn": "arn:aws:sagemaker:us-east-1:111111111111:domain/d"}


@install("aws.cb.sagemaker.domain_sso", "sagemaker_domain", "SageMaker domain uses IAM Identity Center authentication",
    {**DOM, "AuthMode": "SSO", "SingleSignOnApplicationArn": "arn:aws:sso::111111111111:application/a"}, {**DOM, "AuthMode": "IAM"},
    rows=[P + "sagemaker_domain_sso_configured"], severity="medium", control="IA-2", remediation="Create the domain with AuthMode SSO linked to IAM Identity Center.", docs=[D_DOM])
def dom_sso(item, index):
    mode = get(item, "AuthMode", str)
    linked = absent_or(item, "DomainArn", "SingleSignOnManagedApplicationInstanceId", None, str) or absent_or(item, "DomainArn", "SingleSignOnApplicationArn", None, str)
    return result(not (mode == "SSO" and linked), auth_mode=mode, sso_linked=bool(linked))


# --- regional (scope) predicates gated on SageMaker models being present
def _region_models(index):
    return complete_items(index, "sagemaker_model")


_ANCHOR = {"scope": CONTEXT["scope"]}
_MODELS = inventory("sagemaker_model", [dict(MODEL)])
_NO_MODELS = inventory("sagemaker_model", [])


def _regional(cid, title, row, kind, good_rows, bad_rows, evaluate_rows, *, sev, rem, docs, note):
    @install(cid, kind, title, _ANCHOR, _ANCHOR, rows=[P + row], severity=sev, control="SI-4", target="scope", dependencies=["sagemaker_model", kind],
        remediation=rem, docs=docs, note=note,
        extra={"pass_index": indexes(_MODELS, inventory(kind, good_rows)), "fail_index": indexes(_MODELS, inventory(kind, bad_rows)),
               "not_applicable_index": indexes(_NO_MODELS, inventory(kind, bad_rows))})
    def evaluate(item, index):
        scope = scope_of(item)
        if not _region_models(index):
            return "NOT_APPLICABLE", {"scope": scope, "reason": "no SageMaker models in region"}
        return evaluate_rows(scope, complete_items(index, kind))
    return evaluate


def _monitor(scope, rows):
    scheduled = [r.get("MonitoringScheduleName") for r in rows if get(r, "MonitoringScheduleStatus", str) == "Scheduled"]
    return result(not scheduled, scope=scope, scheduled=scheduled)


_regional("aws.cb.sagemaker.monitoring_schedule_active", "Region with SageMaker models has a scheduled model monitor", "sagemaker_models_monitor_enabled",
    "sagemaker_monitoring_schedule", [{"MonitoringScheduleName": "m", "MonitoringScheduleStatus": "Scheduled"}], [{"MonitoringScheduleName": "m", "MonitoringScheduleStatus": "Stopped"}],
    _monitor, sev="medium", rem="Create a SageMaker Model Monitor monitoring schedule for deployed models.",
    docs=["https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ListMonitoringSchedules.html"],
    note="Prowler fails every region without a Scheduled monitoring schedule; regions without SageMaker models are NOT_APPLICABLE here to avoid findings in unused regions.")


def _registry(scope, rows):
    approved = [r.get("ModelPackageGroupName") for r in rows if get(r, "ApprovedPackages", int) > 0]
    return result(not approved, scope=scope, groups=len(rows), groups_with_approved_packages=approved)


_regional("aws.cb.sagemaker.model_registry_approved_package", "Region with SageMaker models uses the Model Registry with an approved package", "sagemaker_models_registry_in_use",
    "sagemaker_model_package_group", [{"ModelPackageGroupName": "g", "ApprovedPackages": 1}], [{"ModelPackageGroupName": "g", "ApprovedPackages": 0}],
    _registry, sev="low", rem="Register models in a model package group and approve a package version.",
    docs=["https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ListModelPackages.html"],
    note="Needs ApprovedPackages = count of ListModelPackages(ModelApprovalStatus=Approved) per group. Regions without models are NOT_APPLICABLE.")


def _clarify(scope, rows):
    jobs = [r.get("ProcessingJobName") for r in rows if "sagemaker-clarify-processing" in (absent_or(r, "ProcessingJobName", "AppSpecification.ImageUri", "", str) or "")]
    return result(not jobs, scope=scope, clarify_jobs=jobs)


_regional("aws.cb.sagemaker.clarify_job_exists", "Region with SageMaker models has a SageMaker Clarify processing job", "sagemaker_clarify_exists",
    "sagemaker_processing_job", [{"ProcessingJobName": "c", "AppSpecification": {"ImageUri": "123.dkr.ecr.us-east-1.amazonaws.com/sagemaker-clarify-processing:1.0"}}],
    [{"ProcessingJobName": "p", "AppSpecification": {"ImageUri": "123.dkr.ecr.us-east-1.amazonaws.com/other:1"}}],
    _clarify, sev="low", rem="Run SageMaker Clarify bias/explainability processing jobs for deployed models.",
    docs=["https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeProcessingJob.html"],
    note="Prowler: any processing job whose AppSpecification.ImageUri contains sagemaker-clarify-processing. Regions without models are NOT_APPLICABLE.")
