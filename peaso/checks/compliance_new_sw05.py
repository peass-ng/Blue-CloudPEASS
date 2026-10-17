"""Signed sw05 AWS checks. All decisions use scoped, complete snapshot facts."""
from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_network
import re
from urllib.parse import urlparse

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, guard

# Static signed metadata is generated from the reviewed ten-field ledger entries.
SPECS = {'aws.nist.apigateway_stage_valid_client_certificate': {'category': 'hardening',
                                                        'kind': 'rest_api_stage',
                                                        'severity': 'medium',
                                                        'sha': '836f5462678dd77014696cfdf962dcc3ac5b891df40938f5f837f38a65322a90',
                                                        'title': 'REST API stages use a valid required '
                                                                 'client certificate'},
 'aws.pci.codepipeline.first_stage_single_deploy': {'category': 'hardening',
                                                    'kind': 'codepipeline_pipeline',
                                                    'severity': 'medium',
                                                    'sha': '2b42bc3c0c86d8523bdd33d0cc97b56912a52a01d81e0061eecb075c04c21a86',
                                                    'title': 'CodePipeline first deployment stage has one '
                                                             'deploy action'},
 'aws.pci.iam.configured_password_policy': {'category': 'hardening',
                                            'kind': 'iam_password_policy',
                                            'severity': 'medium',
                                            'sha': '6dbf612565909f9c8ef6020fa84e84c1e08add52282c32c122913a953a7835ca',
                                            'title': 'IAM password policy meets configured thresholds'},
 'aws.pci.vpc.authorized_igw_attachment': {'category': 'hardening',
                                           'kind': 'internet_gateway',
                                           'severity': 'medium',
                                           'sha': '7dcba265720a684c4db48b6ba5e94e03afbc0ddb50937785d7b4fefc9e2771c1',
                                           'title': 'Internet gateways attach only to authorized VPCs'},
 'aws.pci.vpc.igw_routes_reviewed': {'category': 'hardening',
                                     'kind': 'route_table',
                                     'severity': 'medium',
                                     'sha': 'fff70f680d168e2a0210f02bf0c1147cb80be88efda1650fe776c4e594bab13e',
                                     'title': 'Internet gateway routes are approved'},
 'aws.pci.vpc.peering_dns_resolution': {'category': 'hardening',
                                        'kind': 'vpc_peering_connection',
                                        'severity': 'medium',
                                        'sha': 'befa2b7f74cd08c76208b4e7c7a77593486a95a418fe4719b563068b72ac24b5',
                                        'title': 'VPC peering resolves remote private DNS'},
 'aws.pci.wafv2.rule_group_metrics': {'category': 'hardening',
                                      'kind': 'wafv2_rule_group',
                                      'severity': 'medium',
                                      'sha': '68c0870a052157b9277dc9889347264ae416c566e9b89feb341689648447876b',
                                      'title': 'WAFv2 rule groups publish CloudWatch metrics'},
 'aws.pci.wafv2.rule_group_nonempty': {'category': 'hardening',
                                       'kind': 'wafv2_rule_group',
                                       'severity': 'medium',
                                       'sha': '0c3e8decee40fc7c33a486fc596b80795e8fc95f0894c2817160622b9b5e705e',
                                       'title': 'WAFv2 rule groups are nonempty'},
 'aws_cis_ami_name_policy': {'category': 'hardening',
                             'kind': 'ec2_instance_image',
                             'severity': 'medium',
                             'sha': '3b129ea68273a33e824fcd173cd9a6551f73877f3b2a31fee442a7900887d50c',
                             'title': 'Owned AMIs follow the approved naming convention'},
 'aws_cognito_session_expiry': {'category': 'hardening',
                                'kind': 'cognito_user_pool_client',
                                'severity': 'medium',
                                'sha': '518dfee6072bda5cfc6b2faab035c76902697279ce5d07f4b3d73f2b70dcca25',
                                'title': 'Cognito sessions have bounded token lifetimes'},
 'aws_ecs_task_definition_credential_environment_names': {'category': 'hardening',
                                                          'kind': 'ecs_task_definition',
                                                          'severity': 'medium',
                                                          'sha': '6451f8e9fa6bf49fa3e85968e51d286a19065a8bffdd7f8cbcfb973e2436316d',
                                                          'title': 'ECS.8'},
 'aws_g6_api_stage_valid_client_certificate': {'category': 'hardening',
                                               'kind': 'rest_api_stage',
                                               'severity': 'medium',
                                               'sha': '124db8d822f9c3e1fe01ea1bfb97a080eb1ba987366a42052f4c8470e8de352d',
                                               'title': 'REST API stages reference valid client '
                                                        'certificates'},
 'aws_g6_ecr_public_repositories_absent': {'category': 'exposure',
                                           'kind': 'ecr_public_repository',
                                           'severity': 'high',
                                           'sha': '31ab35b82595e292dcd3e8870c373134ba3fca0fe09f592239783e73eda15d24',
                                           'title': 'Account has no ECR Public repositories'},
 'aws_g6_ecs_all_containers_logging': {'category': 'hardening',
                                       'kind': 'ecs_task_definition',
                                       'severity': 'medium',
                                       'sha': 'c0eff24e0b69214a769efc515adb9323ec3dd81b5c6d1b958d37282b662c71f8',
                                       'title': 'All ECS task containers have logging configured'},
 'aws_g6_elbv2_only_https_tls_listeners': {'category': 'hardening',
                                           'kind': 'load_balancer_v2',
                                           'severity': 'high',
                                           'sha': 'fd4ec56f5bc6040bfb5049b4855233c2143f6dea91d588418a7ea79ef6739bf7',
                                           'title': 'ALB and NLB listeners use only HTTPS or TLS'},
 'aws_log_retention_upper_bound': {'category': 'hardening',
                                   'kind': 'log_group',
                                   'severity': 'medium',
                                   'sha': 'f6e07237ba25700b9c3fba8fda25e08d5aa54155784bd0c6329f4721efa8b472',
                                   'title': 'Log groups do not retain data past approved purpose'},
 'aws_shield_automatic_application_layer_response': {'category': 'hardening',
                                                     'kind': 'shield_protection',
                                                     'severity': 'medium',
                                                     'sha': 'b455e05c2504d8b549acef233d839ff4e2e0d5456631064516345750a075ee3c',
                                                     'title': 'Enable Shield Advanced automatic application '
                                                              'layer DDoS mitigation'},
 'aws_shield_protection_health_checks': {'category': 'hardening',
                                         'kind': 'shield_protection',
                                         'severity': 'medium',
                                         'sha': 'ebe9124bf04ed7b7c4d784fabc4b36d43e7545b389baded606a5835526d0acf1',
                                         'title': 'Configure R53 health checks for all protected resources'},
 'aws_sqs_queue_depth_alarm_present': {'category': 'hardening',
                                       'kind': 'sqs_queue',
                                       'severity': 'medium',
                                       'sha': '45c5b0377488fbf520302abd1999bc09e29e1860de20e0a96b8cbc5b1dd1d605',
                                       'title': 'SQS queue backlog alarm'},
 'aws_vpc_peering_trusted_accounts': {'category': 'hardening',
                                      'kind': 'vpc_peering_connection',
                                      'severity': 'medium',
                                      'sha': '8c5dc76e658ff6eae0cff4102caa08cf1a5df3185a7673cb703c3153e27eb5de',
                                      'title': 'aws-perimeter.control.vpc_peering_connection_cross_account_shared'}}
PROPOSED_SPEC_SHA256 = {cid: spec["sha"] for cid, spec in SPECS.items()}


def _context(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("foreign provider context")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"[0-9]{12}/(?:global|[a-z]{2}(?:-[a-z]+)+-[0-9])", scope):
        raise Unavailable("malformed AWS scope")
    return context, scope


def _inventory(index, kind, item=None):
    _, scope = _context(index)
    global_kind = kind in {"iam_password_policy", "shield_protection"}
    if scope.endswith("/global") != global_kind:
        raise Unavailable("collection global/regional scope mismatch: " + kind)
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("collection scope or pagination unavailable: " + kind)
    envelope = envelopes[0]
    if not isinstance(envelope, dict) or envelope.get("type") != kind or envelope.get("scope") != scope:
        raise Unavailable("foreign collection scope: " + kind)
    if envelope.get("status") not in ("collected", "empty"):
        raise Unavailable("collection incomplete: " + kind)
    raw = get(index, kind, list)
    if any(not isinstance(w, dict) or w.get("type") != kind or w.get("scope") != scope for w in raw):
        raise Unavailable("foreign resource wrapper: " + kind)
    rows = complete_items(index, kind)
    envelope_items = _objects(get(envelope, "items", list))
    if envelope.get("status") == "empty" and envelope_items:
        raise Unavailable("empty collection contains resources: " + kind)
    if len(rows) != len(raw) or len(rows) != len(envelope_items) or any(
            sum(candidate == row for candidate in envelope_items) != 1 for row in rows):
        raise Unavailable("collection item mismatch or duplicate: " + kind)
    if item is not None and sum(row == item for row in rows) != 1:
        raise Unavailable("resource is absent or ambiguous in scoped inventory: " + kind)
    return rows


def _metadata(index, key, expected):
    context, _ = _context(index)
    return get(get(context, "metadata", dict), key, expected)


def _strings(value, *, allow_empty=True):
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value):
        raise Unavailable("malformed configured string set")
    if not allow_empty and not value:
        raise Unavailable("empty configured string set")
    return set(value)


def _objects(value):
    if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
        raise Unavailable("malformed object list")
    return value


def _time(value):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise Unavailable("malformed timestamp")
    if parsed.tzinfo is None:
        raise Unavailable("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _definition(item, index):
    _inventory(index, "ecs_task_definition", item)
    arn = get(item, "taskDefinitionArn", str)
    if get(item, "Definition.collection_status", str) != "collected":
        raise Unavailable("DescribeTaskDefinition detail unavailable")
    definition = get(item, "Definition.taskDefinition", dict)
    _, scope = _context(index)
    if get(definition, "taskDefinitionArn", str) != arn or not arn.startswith(
            "arn:aws:ecs:" + scope.split("/")[1] + ":" + scope[:12] + ":task-definition/"):
        raise Unavailable("ECS task-definition identity or scope mismatch")
    status = get(definition, "status", str)
    if status not in ("ACTIVE", "INACTIVE", "DELETE_IN_PROGRESS"):
        raise Unavailable("unknown ECS task-definition status")
    containers = _objects(get(definition, "containerDefinitions", list))
    names = [get(container, "name", str) for container in containers]
    if not names or any(not name for name in names) or len(names) != len(set(names)):
        raise Unavailable("missing or duplicate ECS container identity")
    return definition, status


@register("aws_ecs_task_definition_credential_environment_names", "aws", "hardening", "ecs_task_definition",
          SPECS["aws_ecs_task_definition_credential_environment_names"]["title"], "medium", "CM-6",
          "Remove credential variables from container environments.", dependencies=["ecs_task_definition"])
def ecs_credential_environment_names(item, index):
    definition, status = _definition(item, index)
    containers = _objects(get(definition, "containerDefinitions", list))
    if not containers:
        return unknown("active task definition has no container definitions")
    flagged = []
    for container in containers:
        name = get(container, "name", str)
        entries = _objects(get(container, "environment", list))
        for entry in entries:
            variable = get(entry, "name", str)
            if not variable:
                raise Unavailable("environment variable name missing")
            if variable in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"}:
                flagged.append((name, variable))
    return result(bool(flagged), credential_environment_names=flagged)


@register("aws_g6_ecs_all_containers_logging", "aws", "hardening", "ecs_task_definition",
          SPECS["aws_g6_ecs_all_containers_logging"]["title"], "medium", "AU-12",
          "Configure a log driver for every container.", dependencies=["ecs_task_definition"])
def ecs_all_containers_logging(item, index):
    definition, status = _definition(item, index)
    if status != "ACTIVE":
        return "NOT_APPLICABLE", {"reason": "task definition is not active"}
    containers = _objects(get(definition, "containerDefinitions", list))
    if not containers:
        return unknown("active task definition has no container definitions")
    missing = []
    for container in containers:
        name = get(container, "name", str)
        if "logConfiguration" not in container and "logConfiguration" not in container.get("_coverage", {}):
            missing.append(name)
            continue
        configuration = get(container, "logConfiguration", dict)
        if "logDriver" not in configuration and "logDriver" not in configuration.get("_coverage", {}):
            missing.append(name)
            continue
        driver = get(configuration, "logDriver", str)
        if not driver:
            missing.append(name)
    return result(bool(missing), containers_without_log_driver=missing)


@register("aws.pci.wafv2.rule_group_metrics", "aws", "hardening", "wafv2_rule_group",
          SPECS["aws.pci.wafv2.rule_group_metrics"]["title"], "medium", "AU-12",
          "Enable CloudWatch metrics for the rule group.", dependencies=["wafv2_rule_group"])
def wafv2_rule_group_metrics(item, index):
    _inventory(index, "wafv2_rule_group", item)
    arn = get(item, "ARN", str)
    group = get(item, "RuleGroup", dict)
    _, scope = _context(index)
    if get(group, "ARN", str) != arn or not arn.startswith(
            "arn:aws:wafv2:" + scope.split("/")[1] + ":" + scope[:12] + ":"):
        raise Unavailable("WAFv2 rule-group identity or scope mismatch")
    enabled = get(group, "VisibilityConfig.CloudWatchMetricsEnabled", bool)
    return result(not enabled, rule_group_arn=arn, cloudwatch_metrics_enabled=enabled)


@register("aws.pci.wafv2.rule_group_nonempty", "aws", "hardening", "wafv2_rule_group",
          SPECS["aws.pci.wafv2.rule_group_nonempty"]["title"], "medium", "CM-6",
          "Add required rules or delete unused groups.", dependencies=["wafv2_rule_group"])
def wafv2_rule_group_nonempty(item, index):
    _inventory(index, "wafv2_rule_group", item)
    arn = get(item, "ARN", str)
    group = get(item, "RuleGroup", dict)
    _, scope = _context(index)
    if get(group, "ARN", str) != arn or not arn.startswith(
            "arn:aws:wafv2:" + scope.split("/")[1] + ":" + scope[:12] + ":"):
        raise Unavailable("WAFv2 rule-group identity or scope mismatch")
    rules = _objects(get(group, "Rules", list))
    names = [get(rule, "Name", str) for rule in rules]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise Unavailable("missing or duplicate WAF rule name")
    return result(not rules, rule_group_arn=arn, rule_count=len(rules))


@register("aws.pci.vpc.authorized_igw_attachment", "aws", "hardening", "internet_gateway",
          SPECS["aws.pci.vpc.authorized_igw_attachment"]["title"], "medium", "AC-4",
          "Detach Internet gateways from unauthorized VPCs.", dependencies=["internet_gateway"])
def authorized_igw_attachment(item, index):
    _inventory(index, "internet_gateway", item)
    approved = _strings(_metadata(index, "approved_vpc_ids", list))
    igw = get(item, "InternetGatewayId", str)
    unauthorized = []
    for attachment in _objects(get(item, "Attachments", list)):
        vpc = get(attachment, "VpcId", str)
        state = get(attachment, "State", str)
        if state not in ("available", "attaching", "detaching", "detached"):
            raise Unavailable("unknown internet-gateway attachment state")
        if state == "available" and vpc not in approved:
            unauthorized.append(vpc)
    return result(bool(unauthorized), internet_gateway_id=igw, unauthorized_vpc_ids=unauthorized)


@register("aws.pci.vpc.igw_routes_reviewed", "aws", "hardening", "route_table",
          SPECS["aws.pci.vpc.igw_routes_reviewed"]["title"], "medium", "AC-4",
          "Remove or approve active Internet gateway routes.", dependencies=["route_table"])
def igw_routes_reviewed(item, index):
    _inventory(index, "route_table", item)
    route_table_id = get(item, "RouteTableId", str)
    approved_raw = _objects(_metadata(index, "approved_public_routes", list))
    approved = set()
    for row in approved_raw:
        destinations = _route_destinations(row)
        if len(destinations) != 1 or not isinstance(destinations[0], str):
            raise Unavailable("malformed approved route destination")
        approved.add((get(row, "RouteTableId", str), destinations[0], get(row, "GatewayId", str)))
    unexpected = []
    for route in _objects(get(item, "Routes", list)):
        state = get(route, "State", str)
        if state not in ("active", "blackhole"):
            raise Unavailable("unknown route state")
        guard(route)
        gateway = get(route, "GatewayId", str) if "GatewayId" in route or "GatewayId" in route.get("_coverage", {}) else None
        if gateway is not None and not isinstance(gateway, str):
            raise Unavailable("malformed GatewayId")
        if state != "active" or not gateway or not gateway.startswith("igw-"):
            continue
        destinations = _route_destinations(route)
        if len(destinations) != 1 or not isinstance(destinations[0], str):
            raise Unavailable("missing or ambiguous IGW destination")
        tuple_ = (route_table_id, destinations[0], gateway)
        if tuple_ not in approved:
            unexpected.append(tuple_)
    return result(bool(unexpected), unapproved_routes=unexpected)


def _route_destinations(row):
    destinations = []
    for key, version in (("DestinationCidrBlock", 4), ("DestinationIpv6CidrBlock", 6)):
        if key not in row and key not in row.get("_coverage", {}):
            continue
        value = get(row, key, str)
        try:
            network = ip_network(value, strict=False)
        except ValueError as exc:
            raise Unavailable("malformed route destination") from exc
        if network.version != version:
            raise Unavailable("route destination address family mismatch")
        destinations.append(value)
    return destinations


@register("aws.pci.vpc.peering_dns_resolution", "aws", "hardening", "vpc_peering_connection",
          SPECS["aws.pci.vpc.peering_dns_resolution"]["title"], "medium", "SC-20",
          "Enable peer DNS resolution at both endpoints.", dependencies=["vpc_peering_connection"])
def peering_dns_resolution(item, index):
    _inventory(index, "vpc_peering_connection", item)
    state = get(item, "Status.Code", str)
    if state not in ("active", "pending-acceptance", "initiating-request", "provisioning", "failed", "expired", "rejected", "deleting", "deleted"):
        raise Unavailable("unknown peering state")
    if state != "active":
        return "NOT_APPLICABLE", {"reason": "peering connection is not active"}
    _, scope = _context(index)
    owners = [get(item, side + ".OwnerId", str) for side in ("RequesterVpcInfo", "AccepterVpcInfo")]
    if any(re.fullmatch(r"[0-9]{12}", owner) is None for owner in owners) or scope[:12] not in owners:
        raise Unavailable("peering endpoint account authority unavailable")
    options = [get(item, "RequesterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc", bool),
               get(item, "AccepterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc", bool)]
    return result(not all(options), dns_resolution=options)


@register("aws_vpc_peering_trusted_accounts", "aws", "hardening", "vpc_peering_connection",
          SPECS["aws_vpc_peering_trusted_accounts"]["title"], "medium", "AC-4",
          "Remove peering connections to untrusted accounts.", dependencies=["vpc_peering_connection"])
def peering_trusted_accounts(item, index):
    _inventory(index, "vpc_peering_connection", item)
    state = get(item, "Status.Code", str)
    if state not in ("active", "pending-acceptance", "initiating-request", "provisioning", "failed", "expired", "rejected", "deleting", "deleted"):
        raise Unavailable("unknown peering state")
    if state != "active":
        return "NOT_APPLICABLE", {"reason": "peering connection is not active"}
    requester = get(item, "RequesterVpcInfo.OwnerId", str)
    accepter = get(item, "AccepterVpcInfo.OwnerId", str)
    if not all(re.fullmatch(r"[0-9]{12}", value) for value in (requester, accepter)):
        raise Unavailable("malformed peering account ID")
    _, scope = _context(index)
    if scope[:12] not in (requester, accepter):
        raise Unavailable("peering connection has no audited-account endpoint")
    if requester == accepter:
        return "NOT_APPLICABLE", {"reason": "peering connection is within one account"}
    trusted = _strings(_metadata(index, "trusted_account_ids", list))
    if any(re.fullmatch(r"[0-9]{12}", account) is None for account in trusted):
        raise Unavailable("malformed trusted account ID")
    return result(requester not in trusted or accepter not in trusted,
                  requester_account=requester, accepter_account=accepter)


@register("aws_g6_elbv2_only_https_tls_listeners", "aws", "hardening", "load_balancer_v2",
          SPECS["aws_g6_elbv2_only_https_tls_listeners"]["title"], "high", "SC-8",
          "Use HTTPS or TLS listeners with certificates.", dependencies=["load_balancer_v2"])
def only_https_tls_listeners(item, index):
    _inventory(index, "load_balancer_v2", item)
    lb_type = get(item, "Type", str)
    if lb_type == "gateway":
        return "NOT_APPLICABLE", {"reason": "not an ALB or NLB"}
    if lb_type not in ("application", "network"):
        raise Unavailable("unknown load balancer type")
    arn = get(item, "LoadBalancerArn", str)
    _, scope = _context(index)
    if not arn.startswith("arn:aws:elasticloadbalancing:" + scope.split("/")[1] + ":" + scope[:12] + ":loadbalancer/"):
        raise Unavailable("foreign load balancer ARN")
    listeners = get(item, "Listeners", dict)
    if get(listeners, "collection_status", str) not in ("collected", "empty"):
        raise Unavailable("listener inventory incomplete")
    rows = _objects(get(listeners, "items", list))
    if listeners["collection_status"] == "empty" and rows:
        raise Unavailable("empty listener status conflicts with records")
    identities = [get(listener, "ListenerArn", str) for listener in rows]
    prefix = arn.replace(":loadbalancer/", ":listener/") + "/"
    if len(set(identities)) != len(identities) or any(not value.startswith(prefix) or not value[len(prefix):] for value in identities):
        raise Unavailable("foreign or duplicate listener identity")
    unsafe = []
    for listener in rows:
        protocol = get(listener, "Protocol", str)
        if protocol not in ("HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP", "GENEVE"):
            raise Unavailable("unknown listener protocol")
        listener_arn = get(listener, "ListenerArn", str)
        if protocol not in ("HTTPS", "TLS"):
            unsafe.append(listener_arn)
            continue
        certificates = _objects(get(listener, "Certificates", list))
        arns = [get(cert, "CertificateArn", str) for cert in certificates]
        if not arns or any(not arn for arn in arns):
            unsafe.append(listener_arn)
    return result(bool(unsafe), unsafe_listener_arns=unsafe)


@register("aws_g6_ecr_public_repositories_absent", "aws", "exposure", "ecr_public_repository",
          SPECS["aws_g6_ecr_public_repositories_absent"]["title"], "high", "AC-3",
          "Remove ECR Public repositories.", target="scope", dependencies=["ecr_public_repository"])
def ecr_public_repositories_absent(item, index):
    rows = _inventory(index, "ecr_public_repository")
    _, scope = _context(index)
    if scope.split("/")[-1] != "us-east-1":
        raise Unavailable("ECR Public registry must be collected in us-east-1")
    for row in rows:
        if not get(row, "repositoryName", str) or not get(row, "repositoryArn", str).startswith(
                "arn:aws:ecr-public::" + scope[:12] + ":repository/"):
            raise Unavailable("malformed or foreign ECR Public repository identity")
    return result(bool(rows), public_repository_arns=[row["repositoryArn"] for row in rows])


@register("aws_sqs_queue_depth_alarm_present", "aws", "hardening", "sqs_queue",
          SPECS["aws_sqs_queue_depth_alarm_present"]["title"], "medium", "AU-5",
          "Create an actionable AWS/SQS visible-message alarm.", dependencies=["sqs_queue", "cloudwatch_alarm"])
def sqs_queue_depth_alarm_present(item, index):
    _inventory(index, "sqs_queue", item)
    alarms = _inventory(index, "cloudwatch_alarm")
    queue_url = get(item, "QueueUrl", str)
    parsed = urlparse(queue_url)
    parts = parsed.path.strip("/").split("/")
    _, scope = _context(index)
    if (parsed.scheme != "https" or parsed.netloc != "sqs." + scope.split("/")[1] + ".amazonaws.com" or
            len(parts) != 2 or parts[0] != scope[:12] or not parts[1]):
        raise Unavailable("malformed or foreign SQS queue URL")
    queue_name = parts[1]
    matches = []
    for alarm in alarms:
        alarm_arn = get(alarm, "AlarmArn", str)
        if not alarm_arn.startswith("arn:aws:cloudwatch:" + scope.split("/")[1] + ":" + scope[:12] + ":alarm:"):
            raise Unavailable("foreign CloudWatch alarm")
        namespace = get(alarm, "Namespace", str)
        metric = get(alarm, "MetricName", str)
        dimensions = _objects(get(alarm, "Dimensions", list))
        dimension_pairs = [(get(d, "Name", str), get(d, "Value", str)) for d in dimensions]
        actions_enabled = get(alarm, "ActionsEnabled", bool)
        actions = get(alarm, "AlarmActions", list)
        if not isinstance(actions, list) or any(not isinstance(action, str) or not action for action in actions):
            raise Unavailable("malformed alarm actions")
        if (namespace == "AWS/SQS" and metric == "ApproximateNumberOfMessagesVisible" and
                ("QueueName", queue_name) in dimension_pairs and actions_enabled and actions):
            matches.append(get(alarm, "AlarmArn", str))
    return result(not matches, queue_url=queue_url, matching_alarm_arns=matches)


@register("aws.pci.codepipeline.first_stage_single_deploy", "aws", "hardening", "codepipeline_pipeline",
          SPECS["aws.pci.codepipeline.first_stage_single_deploy"]["title"], "medium", "CM-3",
          "Keep at most one Deploy action in the first deployment stage.", dependencies=["codepipeline_pipeline"])
def first_stage_single_deploy(item, index):
    _inventory(index, "codepipeline_pipeline", item)
    name = get(item, "name", str)
    if get(item, "Pipeline.collection_status", str) != "collected":
        raise Unavailable("GetPipeline detail unavailable")
    pipeline = get(item, "Pipeline.pipeline", dict)
    if get(pipeline, "name", str) != name:
        raise Unavailable("CodePipeline identity mismatch")
    stages = _objects(get(pipeline, "stages", list))
    first_deploy_count = None
    for stage in stages:
        actions = _objects(get(stage, "actions", list))
        categories = [get(action, "actionTypeId.category", str) for action in actions]
        if any(category not in ("Source", "Build", "Test", "Deploy", "Approval", "Invoke", "Compute") for category in categories):
            raise Unavailable("unknown pipeline action category")
        if "Deploy" in categories:
            first_deploy_count = categories.count("Deploy")
            break
    if first_deploy_count is None:
        return "NOT_APPLICABLE", {"reason": "pipeline has no deployment stage"}
    return result(first_deploy_count > 1, first_deploy_action_count=first_deploy_count)


@register("aws_cognito_session_expiry", "aws", "hardening", "cognito_user_pool_client",
          SPECS["aws_cognito_session_expiry"]["title"], "medium", "AC-12",
          "Limit access, ID and refresh token validity.", dependencies=["cognito_user_pool_client"])
def cognito_session_expiry(item, index):
    _inventory(index, "cognito_user_pool_client", item)
    maximum = _metadata(index, "max_refresh_token_minutes", int)
    if maximum <= 0:
        raise Unavailable("invalid approved refresh-token maximum")
    if get(item, "ClientDetail.collection_status", str) != "collected":
        raise Unavailable("DescribeUserPoolClient detail unavailable")
    client = get(item, "ClientDetail.UserPoolClient", dict)
    for key in ("UserPoolId", "ClientId"):
        if not get(item, key, str) or get(client, key, str) != item[key]:
            raise Unavailable("Cognito client identity mismatch")
    for key in ("AccessTokenValidity", "IdTokenValidity", "RefreshTokenValidity"):
        value = get(client, key, int)
        if value <= 0:
            raise Unavailable("invalid token lifetime")
    units = get(client, "TokenValidityUnits", dict)
    factors = {"seconds": 1 / 60, "minutes": 1, "hours": 60, "days": 1440}
    limits = {"AccessToken": 60, "IdToken": 60, "RefreshToken": maximum}
    minutes = {}
    for token, limit in limits.items():
        unit = get(units, token, str)
        if unit not in factors:
            raise Unavailable("unknown token validity unit")
        minutes[token] = client[token + "Validity"] * factors[unit]
    return result(any(minutes[token] > limit for token, limit in limits.items()), validity_minutes=minutes)


@register("aws_log_retention_upper_bound", "aws", "hardening", "log_group",
          SPECS["aws_log_retention_upper_bound"]["title"], "medium", "AU-11",
          "Set retention within the approved purpose maximum.", dependencies=["log_group"])
def log_retention_upper_bound(item, index):
    _inventory(index, "log_group", item)
    group = get(item, "logGroupName", str)
    purpose = _metadata(index, "log_group_purposes", dict)
    maximum = _metadata(index, "log_retention_max_days_by_purpose", dict)
    if group not in purpose or not isinstance(purpose[group], str) or purpose[group] not in maximum:
        raise Unavailable("log-group purpose or maximum unavailable")
    limit = maximum[purpose[group]]
    if type(limit) is not int or limit <= 0:
        raise Unavailable("invalid retention maximum")
    if "retentionInDays" not in item and "retentionInDays" not in item.get("_coverage", {}):
        provenance = get(item, "_provenance", dict)
        if get(provenance, "operation", str) != "logs:DescribeLogGroups" or get(provenance, "native_response_complete", bool) is not True:
            raise Unavailable("retention omission lacks complete DescribeLogGroups provenance")
        return result(True, log_group_name=group, reason="no retention period configured")
    days = get(item, "retentionInDays", int)
    if days <= 0:
        raise Unavailable("invalid retention period")
    return result(days > limit, log_group_name=group, retention_days=days, approved_maximum_days=limit)


@register("aws_cis_ami_name_policy", "aws", "hardening", "ec2_instance_image",
          SPECS["aws_cis_ami_name_policy"]["title"], "medium", "CM-8",
          "Use the approved organization AMI naming convention.", dependencies=["ec2_instance_image"])
def ami_name_policy(item, index):
    _inventory(index, "ec2_instance_image", item)
    context, scope = _context(index)
    expression = _metadata(index, "organization_ami_name_expression", str)
    if not expression or len(expression) > 512:
        raise Unavailable("invalid AMI name expression")
    try:
        pattern = re.compile(expression)
    except re.error as exc:
        raise Unavailable("invalid AMI name expression") from exc
    owner = get(item, "OwnerId", str)
    if re.fullmatch(r"[0-9]{12}", owner) is None:
        raise Unavailable("malformed AMI owner account")
    if owner != scope[:12]:
        return "NOT_APPLICABLE", {"reason": "AMI is not owned by audited account"}
    name = get(item, "Name", str)
    return result(pattern.fullmatch(name) is None, image_id=get(item, "ImageId", str), image_name=name)


def _stage(item, index):
    _inventory(index, "rest_api_stage", item)
    arn = get(item, "id", str)
    api = get(item, "ParentApiId", str)
    stage = get(item, "stageName", str)
    _, scope = _context(index)
    if (not arn.endswith("/" + api + "/stages/" + stage) or
            not arn.startswith("arn:aws:apigateway:" + scope.split("/")[1] + "::/restapis/")):
        raise Unavailable("REST stage identity or scope mismatch")
    provenance = get(item, "_provenance", dict)
    if get(provenance, "source_operation", str) != "get_stages" or get(provenance, "parent_api_id", str) != api or get(provenance, "read_only", bool) is not True:
        raise Unavailable("GetStages provenance unavailable")
    return arn


def _client_certificate(item, index):
    arn = _stage(item, index)
    certificate_id = get(item, "clientCertificateId", str)
    if not certificate_id:
        return result(True, stage_arn=arn, reason="no client certificate configured")
    detail = get(item, "ClientCertificate", dict)
    state = get(detail, "collection_status", str)
    if get(detail, "clientCertificateId", str) != certificate_id:
        raise Unavailable("client certificate join mismatch")
    if state == "empty" and get(detail, "absent", bool):
        return result(True, stage_arn=arn, reason="client certificate does not exist")
    if state != "collected":
        raise Unavailable("client certificate lookup incomplete")
    expiry = _time(get(detail, "expirationDate"))
    capture = _time(get(index, "context.created_at"))
    return result(expiry <= capture, stage_arn=arn, client_certificate_id=certificate_id,
                  expiration_date=expiry.isoformat())


@register("aws_g6_api_stage_valid_client_certificate", "aws", "hardening", "rest_api_stage",
          SPECS["aws_g6_api_stage_valid_client_certificate"]["title"], "medium", "SC-17",
          "Configure a current REST API client certificate.", dependencies=["rest_api_stage"])
def g6_api_stage_valid_client_certificate(item, index):
    return _client_certificate(item, index)


@register("aws.nist.apigateway_stage_valid_client_certificate", "aws", "hardening", "rest_api_stage",
          SPECS["aws.nist.apigateway_stage_valid_client_certificate"]["title"], "medium", "SC-17",
          "Apply the declared client-certificate requirement.", dependencies=["rest_api_stage"])
def nist_api_stage_valid_client_certificate(item, index):
    required = _metadata(index, "require_client_certificate", bool)
    if required:
        return _client_certificate(item, index)
    arn = _stage(item, index)
    certificate_id = get(item, "clientCertificateId", str)
    return result(bool(certificate_id), stage_arn=arn, client_certificate_id=certificate_id)


@register("aws.pci.iam.configured_password_policy", "aws", "hardening", "iam_password_policy",
          SPECS["aws.pci.iam.configured_password_policy"]["title"], "medium", "IA-5",
          "Set IAM password policy to the approved account thresholds.",
          target="scope", dependencies=["iam_password_policy"])
def configured_password_policy(item, index):
    rows = _inventory(index, "iam_password_policy")
    _, scope = _context(index)
    if not scope.endswith("/global"):
        raise Unavailable("IAM password policy requires account-global scope")
    thresholds = _metadata(index, "password_policy_thresholds", dict)
    fields = ("MinimumPasswordLength", "RequireSymbols", "RequireNumbers",
              "RequireUppercaseCharacters", "RequireLowercaseCharacters", "MaxPasswordAge",
              "PasswordReusePrevention", "HardExpiry")
    if set(thresholds) != set(fields):
        raise Unavailable("complete named password-policy thresholds unavailable")
    for field in fields:
        expected = bool if field.startswith("Require") or field == "HardExpiry" else int
        if type(thresholds[field]) is not expected:
            raise Unavailable("malformed password-policy threshold")
        if expected is int and thresholds[field] <= 0:
            raise Unavailable("invalid password-policy threshold")
    if not rows:
        envelope = get(index, "collections", dict)["iam_password_policy"][0]
        if get(get(envelope, "error", dict), "code", str) != "NoSuchEntity":
            raise Unavailable("absent IAM password policy is not proven")
        return result(True, reason="IAM account has no configured password policy")
    if len(rows) != 1:
        raise Unavailable("ambiguous account password policy")
    policy = get(rows[0], "PasswordPolicy", dict)
    values = {}
    failed = []
    for field in fields:
        expected = bool if field.startswith("Require") or field == "HardExpiry" else int
        value = get(policy, field, expected)
        values[field] = value
        threshold = thresholds[field]
        if expected is bool:
            if threshold and not value:
                failed.append(field)
        elif field == "MaxPasswordAge":
            if value <= 0 or value > threshold:
                failed.append(field)
        elif value < threshold:
            failed.append(field)
    return result(bool(failed), failed_thresholds=failed, configured_policy=values)


# IAM password policy is one account-global decision across selected Regions.
configured_password_policy.evaluation_scope = "aws_account"


@register("aws_shield_automatic_application_layer_response", "aws", "hardening", "shield_protection",
          SPECS["aws_shield_automatic_application_layer_response"]["title"], "medium", "SC-5",
          "Enable Shield automatic application-layer response for applicable protections.",
          dependencies=["shield_protection"])
def shield_automatic_application_layer_response(item, index):
    _inventory(index, "shield_protection", item)
    resource_arn = get(item, "ResourceArn", str)
    _, scope = _context(index)
    account = scope[:12]
    parts = resource_arn.split(":", 5)
    if len(parts) != 6 or parts[:2] != ["arn", "aws"] or parts[4] != account or not parts[5]:
        raise Unavailable("malformed or foreign Shield resource ARN")
    if resource_arn.startswith("arn:aws:cloudfront::"):
        if not resource_arn.startswith("arn:aws:cloudfront::" + account + ":distribution/"):
            raise Unavailable("foreign CloudFront protection")
    elif resource_arn.startswith("arn:aws:elasticloadbalancing:"):
        if not re.fullmatch(r"arn:aws:elasticloadbalancing:[a-z0-9-]+:" + account + r":loadbalancer/(?:app|net)/.+", resource_arn):
            raise Unavailable("foreign or malformed load-balancer protection")
        if ":loadbalancer/app/" not in resource_arn:
            return "NOT_APPLICABLE", {"reason": "Shield application-layer response does not apply to this resource"}
    else:
        return "NOT_APPLICABLE", {"reason": "Shield application-layer response does not apply to this resource"}
    protection_id = get(item, "Id", str)
    detail = get(item, "Protection", dict)
    if get(detail, "collection_status", str) != "collected":
        raise Unavailable("DescribeProtection detail unavailable")
    if get(detail, "Id", str) != protection_id:
        raise Unavailable("Shield protection detail identity mismatch")
    status = get(detail, "ApplicationLayerAutomaticResponse.Status", str)
    if status not in ("ENABLED", "DISABLED"):
        raise Unavailable("unknown Shield application-layer response status")
    return result(status != "ENABLED", protection_id=protection_id, response_status=status)


@register("aws_shield_protection_health_checks", "aws", "hardening", "shield_protection",
          SPECS["aws_shield_protection_health_checks"]["title"], "medium", "SC-5",
          "Associate a valid Route 53 health check with the protection.",
          dependencies=["shield_protection"])
def shield_protection_health_checks(item, index):
    _inventory(index, "shield_protection", item)
    protection_id = get(item, "Id", str)
    resource_arn = get(item, "ResourceArn", str)
    _, scope = _context(index)
    if ":" + scope[:12] + ":" not in resource_arn:
        raise Unavailable("foreign Shield protection resource")
    raw_ids = get(item, "HealthCheckIds", list)
    health_check_ids = _strings(raw_ids)
    if len(health_check_ids) != len(raw_ids):
        raise Unavailable("duplicate health-check ID")
    if not health_check_ids:
        return result(True, protection_id=protection_id, reason="no health checks configured")
    details = _objects(get(item, "HealthChecks", list))
    if len(details) != len(health_check_ids):
        raise Unavailable("health-check lookup coverage incomplete")
    unresolved = []
    for detail in details:
        health_check_id = get(detail, "Id", str)
        if health_check_id not in health_check_ids:
            raise Unavailable("foreign health-check detail")
        state = get(detail, "collection_status", str)
        if state == "empty" and get(detail, "absent", bool):
            unresolved.append(health_check_id)
        elif state == "collected":
            if get(detail, "HealthCheck.Id", str) != health_check_id:
                raise Unavailable("health-check identity mismatch")
        else:
            raise Unavailable("GetHealthCheck result incomplete")
    if len({get(detail, "Id", str) for detail in details}) != len(details):
        raise Unavailable("duplicate health-check lookup")
    return result(bool(unresolved), protection_id=protection_id, unresolved_health_check_ids=unresolved)
