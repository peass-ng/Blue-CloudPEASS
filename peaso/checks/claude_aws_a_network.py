"""claude_aws_a VPC networking: security groups, network ACLs, VPCs, subnets, route
tables, endpoints, peering, VPN, block public access and AWS Network Firewall."""
from __future__ import annotations

from ipaddress import ip_network
import re

from . import result
from .facts import Unavailable, complete_items, get, list_of_objects, optional
from .fixtures import CASES
from .claude_aws_a_common import (install, absent_or, items, account, region, policy_document, wildcard_principal,
    prowler_sg_open, turbot_rule_rows, turbot_port_hit, sg_ingress, sg_egress, sg_enis, sg_in_use, vpc_in_use,
    subnet_in_use, prowler_nacl_open, subnet_route_table, subnet_public_prowler,
    idx, C, P, R, ACCOUNT, REGION)
from .claude_aws_a_ec2 import w, DROP, ENI, SG, SG_OPEN

EC2_API = "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/"
VPC_DOC = "https://docs.aws.amazon.com/vpc/latest/userguide/"
NFW_API = "https://docs.aws.amazon.com/network-firewall/latest/APIReference/"

VPC = {"VpcId": "vpc-1", "OwnerId": ACCOUNT, "IsDefault": False, "CidrBlock": "10.0.0.0/16"}
SUBNET = {"SubnetId": "subnet-1", "VpcId": "vpc-1", "AvailabilityZone": "us-east-1a", "MapPublicIpOnLaunch": False}
RTB_MAIN = {"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Associations": [{"Main": True, "RouteTableAssociationId": "rtbassoc-1"}],
            "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "Origin": "CreateRouteTable"}]}
IN_USE = dict(vpc=[VPC], network_interface=[ENI], subnet=[SUBNET], route_table=[RTB_MAIN])


def world_rule(protocol, low, high, cidr="0.0.0.0/0"):
    rule = {"IpProtocol": protocol, "IpRanges": [], "Ipv6Ranges": []}
    if low is not None:
        rule.update(FromPort=low, ToPort=high)
    if ":" in cidr:
        rule["Ipv6Ranges"] = [{"CidrIpv6": cidr}]
    else:
        rule["IpRanges"] = [{"CidrIp": cidr}]
    return rule


def sg_with(*rules, **extra):
    return w(SG, IpPermissions=list(rules), **extra)


# =========================================================================== Prowler security groups
def in_use_or_na(item, index):
    if not sg_in_use(item, index):
        return "NOT_APPLICABLE", {"reason": "security group or its VPC is not in use"}
    return None


SG_DEPS = ["security_group", "vpc", "network_interface"]
SG_NOTE = "Prowler evaluates in-use groups only (VPC with ENIs and the group attached to an ENI; scan_unused_services off)."
SG_NA = (w(SG, GroupId="sg-unused"), idx(**IN_USE))


@install("aws.claude_a.vpc.sg_no_world_all_traffic", "security_group", "In-use security group does not allow all traffic from 0.0.0.0/0 or ::/0",
    SG, sg_with(world_rule("-1", None, None)), index=idx(**IN_USE),
    rows=[P + "ec2_securitygroup_allow_ingress_from_internet_to_all_ports"], severity="critical", category="exposure", control="SC-7",
    remediation="Remove ingress rules allowing all protocols/ports from 0.0.0.0/0 or ::/0.", docs=[EC2_API + "API_IpPermission.html"],
    dependencies=SG_DEPS, extra={"na": SG_NA, "fail_full_range": (SG_OPEN, idx(**IN_USE))}, note=SG_NOTE)
def sg_all_ports(item, index):
    rules = sg_ingress(item)
    na = in_use_or_na(item, index)
    if na:
        return na
    hit = any(prowler_sg_open(rule, "-1", any_address=True) for rule in rules)
    return result(hit)


_ALLOWED_ENI_TYPES = ("api_gateway_managed", "vpc_endpoint")


@install("aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis", "security_group", "In-use security group open to 0.0.0.0/0 or ::/0 is attached only to AWS-managed interfaces",
    sg_with(world_rule("tcp", 8000, 8000, "10.0.0.0/8")), sg_with(world_rule("tcp", 8000, 8000)), index=idx(**IN_USE),
    rows=[P + "ec2_securitygroup_allow_ingress_from_internet_to_any_port"], severity="high", category="exposure", control="SC-7",
    remediation="Restrict world-open ingress, or attach such groups only to API Gateway/VPC endpoint/ELB-managed interfaces.",
    docs=[EC2_API + "API_IpPermission.html", EC2_API + "API_NetworkInterface.html"], dependencies=SG_DEPS,
    extra={"na": SG_NA, "pass_managed_eni": (sg_with(world_rule("tcp", 8000, 8000)), idx(**dict(IN_USE, network_interface=[w(ENI, InterfaceType="vpc_endpoint")])))},
    note=SG_NOTE + " Prowler (defaults) passes when every ENI is an api_gateway_managed/vpc_endpoint interface or owned by amazon-elb; the all_ports dedupe is not applied.")
def sg_any_port(item, index):
    rules = sg_ingress(item)
    na = in_use_or_na(item, index)
    if na:
        return na
    if not any(prowler_sg_open(rule, "-1", any_address=True, all_ports=True) for rule in rules):
        return result(False)
    bad = []
    for eni in sg_enis(index, item["GroupId"]):
        kind = get(eni, "InterfaceType", str)
        owner = absent_or(eni, "NetworkInterfaceId", "Attachment.InstanceOwnerId", None, str)
        if kind not in _ALLOWED_ENI_TYPES and owner != "amazon-elb":
            bad.append(eni.get("NetworkInterfaceId"))
    return result(bool(bad), customer_enis=bad)


@install("aws.claude_a.vpc.sg_no_public_ip_any_port", "security_group", "In-use security group does not open ports to specific public IP ranges",
    SG, sg_with(world_rule("tcp", 0, 65535, "8.8.8.0/24")), index=idx(**IN_USE),
    rows=[P + "ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip"], severity="high", category="exposure", control="SC-7",
    remediation="Replace public-IP ingress sources with private paths, prefix lists or narrowly scoped addresses.",
    docs=[EC2_API + "API_IpPermission.html"], dependencies=SG_DEPS, extra={"na": SG_NA},
    note=SG_NOTE + " Rules containing only 0.0.0.0/0 or ::/0 are skipped (covered elsewhere); a globally routable CIDR opening any port fails.")
def sg_any_port_from_ip(item, index):
    rules = sg_ingress(item)
    na = in_use_or_na(item, index)
    if na:
        return na
    wild = ("0.0.0.0/0", "::/0")
    for rule in rules:
        specific = any(get(r, "CidrIp", str) not in wild for r in list_of_objects(get(rule, "IpRanges", list))) or \
            any(get(r, "CidrIpv6", str) not in wild for r in list_of_objects(get(rule, "Ipv6Ranges", list)))
        if specific and prowler_sg_open(rule, "-1", any_address=False, all_ports=True):
            return result(True)
    return result(False)


@install("aws.claude_a.vpc.sg_no_world_high_risk_tcp_ports", "security_group", "In-use security group does not expose high-risk TCP ports to 0.0.0.0/0 or ::/0",
    SG, sg_with(world_rule("tcp", 445, 445)), index=idx(**IN_USE),
    rows=[P + "ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports"], severity="critical", category="exposure", control="SC-7",
    remediation="Remove world ingress to TCP 25, 110, 135, 143, 445, 3000, 4333, 5000, 5500, 8080 and 8088.",
    docs=[EC2_API + "API_IpPermission.html"], dependencies=SG_DEPS, extra={"na": SG_NA}, note=SG_NOTE + " Prowler default ec2_high_risk_ports.")
def sg_high_risk(item, index):
    rules = sg_ingress(item)
    na = in_use_or_na(item, index)
    if na:
        return na
    ports = [25, 110, 135, 143, 445, 3000, 4333, 5000, 5500, 8080, 8088]
    open_ports = sorted({p for rule in rules for p in ports if prowler_sg_open(rule, "tcp", [p], any_address=True)})
    return result(bool(open_ports), open_ports=open_ports)


SG_PORTS = {
    "tcp_port_22": ("ssh", [22]), "tcp_port_3389": ("rdp", [3389]),
    "tcp_port_cassandra_7199_9160_8888": ("cassandra", [7199, 9160, 8888]),
    "tcp_port_elasticsearch_kibana_9200_9300_5601": ("elasticsearch_kibana", [9200, 9300, 5601]),
    "tcp_port_ftp_20_21": ("ftp", [20, 21]), "tcp_port_kafka_9092": ("kafka", [9092]),
    "tcp_port_memcached_11211": ("memcached", [11211]), "tcp_port_mongodb_27017_27018": ("mongodb", [27017, 27018]),
    "tcp_port_mysql_3306": ("mysql", [3306]), "tcp_port_oracle_1521_2483": ("oracle", [1521, 2483]),
    "tcp_port_postgres_5432": ("postgres", [5432]), "tcp_port_redis_6379": ("redis", [6379]),
    "tcp_port_sql_server_1433_1434": ("sqlserver", [1433, 1434]), "tcp_port_telnet_23": ("telnet", [23]),
}


def _sg_port_check(ports):
    def evaluate(item, index):
        rules = sg_ingress(item)
        na = in_use_or_na(item, index)
        if na:
            return na
        return result(any(prowler_sg_open(rule, "tcp", ports, any_address=True) for rule in rules), ports=ports)
    return evaluate


for _suffix, (_name, _ports) in SG_PORTS.items():
    install("aws.claude_a.vpc.sg_no_world_%s" % _name, "security_group",
        "In-use security group does not expose TCP %s to 0.0.0.0/0 or ::/0" % ", ".join(map(str, _ports)),
        SG, sg_with(world_rule("tcp", _ports[-1], _ports[-1], "::/0")), index=idx(**IN_USE),
        rows=[P + "ec2_securitygroup_allow_ingress_from_internet_to_" + _suffix], severity="high", category="exposure", control="SC-7",
        remediation="Remove 0.0.0.0/0 and ::/0 ingress to TCP %s; reach the service privately (VPN, SSM, PrivateLink)." % ", ".join(map(str, _ports)),
        docs=[EC2_API + "API_IpPermission.html"], dependencies=SG_DEPS, extra={"na": SG_NA},
        note=SG_NOTE + " Reported even when the all-ports check also fails (Prowler suppresses that duplicate).")(_sg_port_check(_ports))


@install("aws.claude_a.vpc.sg_no_wide_public_ipv4", "security_group", "In-use security group has no public IPv4 rule wider than /24",
    sg_with(world_rule("tcp", 443, 443, "8.8.8.0/24")), sg_with(world_rule("tcp", 443, 443, "8.0.0.0/8")), index=idx(**IN_USE),
    rows=[P + "ec2_securitygroup_allow_wide_open_public_ipv4"], severity="high", category="exposure", control="SC-7",
    remediation="Narrow public IPv4 rule sources to /24 or smaller.", docs=[EC2_API + "API_IpRange.html"],
    dependencies=SG_DEPS, extra={"na": SG_NA, "pass_world": (SG, idx(**IN_USE))},
    note=SG_NOTE + " Ingress and egress IPv4 ranges that are globally routable with 0 < prefix < 24 fail.")
def sg_wide_open(item, index):
    rules = sg_ingress(item) + sg_egress(item)
    na = in_use_or_na(item, index)
    if na:
        return na
    for rule in rules:
        for entry in list_of_objects(get(rule, "IpRanges", list)):
            try:
                net = ip_network(get(entry, "CidrIp", str))
            except ValueError as exc:
                raise Unavailable("malformed CIDR") from exc
            if net.is_global and 0 < net.prefixlen < 24:
                return result(True, cidr=str(net))
    return result(False)


DEFAULT_SG = w(SG, GroupName="default", IpPermissions=[], IpPermissionsEgress=[])


@install("aws.claude_a.vpc.default_sg_in_use_no_rules", "security_group", "In-use default security group has no inbound or outbound rules",
    DEFAULT_SG, w(DEFAULT_SG, IpPermissionsEgress=[world_rule("-1", None, None)]), index=idx(**IN_USE),
    rows=[P + "ec2_securitygroup_default_restrict_traffic"], severity="high", category="network", control="SC-7",
    remediation="Remove all rules from default security groups and use dedicated groups.", docs=[VPC_DOC + "default-security-group.html"],
    dependencies=SG_DEPS, extra={"na": (w(SG, IpPermissions=[]), idx(**IN_USE))}, note="Prowler: default groups that are in use only.")
def default_sg_prowler(item, index):
    name = get(item, "GroupName", str)
    rules = sg_ingress(item), sg_egress(item)
    if name != "default":
        return "NOT_APPLICABLE", {"reason": "not a default security group"}
    na = in_use_or_na(item, index)
    if na:
        return na
    return result(bool(rules[0] or rules[1]), ingress_rules=len(rules[0]), egress_rules=len(rules[1]))


@install("aws.claude_a.vpc.default_sg_no_rules", "security_group", "Default security group has no inbound or outbound rules",
    DEFAULT_SG, w(DEFAULT_SG, IpPermissions=[world_rule("-1", None, None)]),
    rows=[C + "vpc_default_security_group_restricts_all_traffic", C + "foundational_security_ec2_2"], severity="high", category="network", control="SC-7",
    remediation="Remove all inbound and outbound rules from every default security group.", docs=[VPC_DOC + "default-security-group.html"],
    extra={"na": SG})
def default_sg(item, index):
    name = get(item, "GroupName", str)
    rules = sg_ingress(item), sg_egress(item)
    if name != "default":
        return "NOT_APPLICABLE", {"reason": "not a default security group"}
    return result(bool(rules[0] or rules[1]), ingress_rules=len(rules[0]), egress_rules=len(rules[1]))


@install("aws.claude_a.vpc.sg_name_not_launch_wizard", "security_group", "Security group is not a launch-wizard group",
    SG, w(SG, GroupName="launch-wizard-3"), rows=[P + "ec2_securitygroup_from_launch_wizard"], severity="medium", category="network", control="SC-7",
    remediation="Replace launch-wizard security groups with purpose-built least-privilege groups and delete them.",
    docs=[EC2_API + "API_SecurityGroup.html"])
def sg_launch_wizard_name(item, index):
    name = get(item, "GroupName", str)
    return result("launch-wizard" in name, group_name=name)


LAMBDA = {"FunctionName": "fn", "VpcConfig": {"SecurityGroupIds": ["sg-lambda"], "SubnetIds": ["subnet-1"]}}
BATCH = {"computeEnvironmentName": "ce", "computeResources": {"securityGroupIds": ["sg-batch"]}}
UNUSED_DEPS = dict(network_interface=[ENI], security_group=[SG], lambda_function=[LAMBDA], batch_compute_environment=[BATCH])


@install("aws.claude_a.vpc.sg_in_use_anywhere", "security_group", "Non-default security group is used by an ENI, Lambda, Batch or another group",
    SG, w(SG, GroupId="sg-orphan"), index=idx(**UNUSED_DEPS),
    rows=[P + "ec2_securitygroup_not_used"], severity="low", category="network", control="CM-7",
    remediation="Delete security groups that nothing references.", docs=[EC2_API + "API_SecurityGroup.html"],
    dependencies=["security_group", "network_interface", "lambda_function", "batch_compute_environment"],
    extra={"na": DEFAULT_SG, "pass_lambda": (w(SG, GroupId="sg-lambda"), idx(**UNUSED_DEPS)),
           "pass_referenced": (w(SG, GroupId="sg-ref"), idx(**dict(UNUSED_DEPS, security_group=[SG, w(SG, GroupId="sg-x", IpPermissions=[{"IpProtocol": "tcp", "FromPort": 1, "ToPort": 1, "IpRanges": [], "Ipv6Ranges": [], "UserIdGroupPairs": [{"GroupId": "sg-ref"}]}])])))},
    note="Prowler also counts Lambda VpcConfig and Batch computeResources security groups, and groups referenced by other groups' ingress UserIdGroupPairs.")
def sg_not_used(item, index):
    gid, name = get(item, "GroupId", str), get(item, "GroupName", str)
    if name == "default":
        return "NOT_APPLICABLE", {"reason": "default groups cannot be deleted"}
    if sg_enis(index, gid):
        return result(False, used_by="network_interface")
    for fn in items(index, "lambda_function"):
        if gid in optional(optional(fn, "VpcConfig", {}, dict), "SecurityGroupIds", [], list):
            return result(False, used_by="lambda_function")
    for ce in items(index, "batch_compute_environment"):
        if gid in optional(optional(ce, "computeResources", {}, dict), "securityGroupIds", [], list):
            return result(False, used_by="batch_compute_environment")
    for other in items(index, "security_group"):
        for rule in list_of_objects(optional(other, "IpPermissions", [], list)):
            if any(pair.get("GroupId") == gid for pair in list_of_objects(optional(rule, "UserIdGroupPairs", [], list))):
                return result(False, used_by="security_group_reference")
    return result(True, group_id=gid)


@install("aws.claude_a.vpc.sg_rule_count_within_50", "security_group", "Security group has at most 50 ingress and 50 egress rules",
    SG, w(SG, IpPermissions=[world_rule("tcp", p, p, "10.0.0.0/8") for p in range(1, 52)]),
    rows=[P + "ec2_securitygroup_with_many_ingress_egress_rules"], severity="medium", category="network", control="CM-7",
    remediation="Consolidate rules (prefix lists, referenced groups) so each direction has at most 50 entries.", docs=[EC2_API + "API_SecurityGroup.html"],
    note="Prowler default max_security_group_rules=50, counted as IpPermissions entries per direction.")
def sg_many_rules(item, index):
    ingress, egress = len(sg_ingress(item)), len(sg_egress(item))
    return result(ingress > 50 or egress > 50, ingress=ingress, egress=egress)


# =========================================================================== Steampipe security group rules
def _turbot(item, v4=True, v6=False, protocols=None, ports=(), ranges=(), any_port=False):
    hits = []
    for row in turbot_rule_rows(item):
        cidr_ok = (v4 and row["cidr_ipv4"] == "0.0.0.0/0") or (v6 and row["cidr_ipv6"] == "::/0")
        if not cidr_ok:
            continue
        if protocols is not None:
            if row["ip_protocol"] in protocols or (row["ip_protocol"] == "-1" and row["from_port"] is None):
                hits.append(row)
            continue
        if any_port or turbot_port_hit(row, ports, ranges):
            hits.append(row)
    return hits


def _turbot_check(**kw):
    def evaluate(item, index):
        get(item, "GroupId", str)
        hits = _ssh_world_v4_hits(item, index) if kw.get("ssh_v4") else _turbot(item, **kw)
        return result(bool(hits), matching_rules=len(hits))
    return evaluate


COMMON6 = [22, 3389, 21, 20, 3306, 4333]
COMMON20 = COMMON6 + [23, 25, 445, 110, 135, 143, 1433, 1434, 5432, 5500, 5601, 9200, 9300, 8080]
TURBOT_SG = [
    ("sg_world_v4_no_tcp_udp", [C + "vpc_security_group_restrict_ingress_tcp_udp_all", R + "vpc_security_group_restrict_ingress_tcp_udp_all"],
     "Security group allows no TCP/UDP or all-traffic ingress from 0.0.0.0/0", dict(protocols=("tcp", "udp")), world_rule("udp", 53, 53), "high"),
    ("sg_world_v4_common6", [C + "vpc_security_group_restrict_ingress_common_ports_all"],
     "Security group restricts 0.0.0.0/0 ingress to ports 20, 21, 22, 3306, 3389 and 4333", dict(ports=COMMON6), world_rule("tcp", 3306, 3306), "high"),
    ("sg_world_v4_common20", [C + "vpc_security_group_restricted_common_ports", C + "foundational_security_ec2_19"],
     "Security group restricts 0.0.0.0/0 ingress to high-risk common ports", dict(ports=COMMON20), world_rule("tcp", 8080, 8080), "high"),
    ("sg_world_v4_ssh", [C + "vpc_security_group_restrict_ingress_ssh_all"],
     "Security group restricts SSH (22) ingress from 0.0.0.0/0", dict(ports=[22], ssh_v4=True), world_rule("tcp", 22, 22), "high"),
    ("sg_world_v4_rdp", [C + "vpc_security_group_restrict_ingress_rdp_all"],
     "Security group restricts RDP (3389) ingress from 0.0.0.0/0", dict(ports=[3389]), world_rule("tcp", 3389, 3389), "high"),
    ("sg_world_v4_mongodb", [C + "vpc_security_group_allows_ingress_to_mongodb_ports"],
     "Security group restricts MongoDB (27017-27018) ingress from 0.0.0.0/0", dict(ports=[27017, 27018]), world_rule("tcp", 27018, 27018), "high"),
    ("sg_world_v4_cassandra", [C + "vpc_security_group_allows_ingress_to_cassandra_ports"],
     "Security group restricts Cassandra (7199, 8888, 9160) ingress from 0.0.0.0/0", dict(ports=[7199, 9160, 8888]), world_rule("tcp", 9160, 9160), "high"),
    ("sg_world_v4_oracle", [C + "vpc_security_group_allows_ingress_to_oracle_ports"],
     "Security group restricts Oracle (1521, 2483) ingress from 0.0.0.0/0", dict(ports=[1521, 2483]), world_rule("tcp", 1521, 1521), "high"),
    ("sg_world_v4_memcached", [C + "vpc_security_group_allows_ingress_to_memcached_port"],
     "Security group restricts Memcached (11211) ingress from 0.0.0.0/0", dict(ports=[11211]), world_rule("udp", 11211, 11211), "high"),
    ("sg_world_any_redis", [C + "vpc_security_group_restrict_ingress_redis_port"],
     "Security group restricts Redis (6379) ingress from 0.0.0.0/0 and ::/0", dict(v6=True, ports=[6379]), world_rule("tcp", 6379, 6379, "::/0"), "high"),
    ("sg_world_any_kafka", [C + "vpc_security_group_restrict_ingress_kafka_port"],
     "Security group restricts Kafka (9092) ingress from 0.0.0.0/0 and ::/0", dict(v6=True, ports=[9092]), world_rule("tcp", 9092, 9092), "high"),
    ("sg_world_any_kibana", [C + "vpc_security_group_restrict_ingress_kibana_port"],
     "Security group restricts Elasticsearch/Kibana (9200, 5601) ingress from 0.0.0.0/0 and ::/0", dict(v6=True, ports=[9200, 5601]), world_rule("tcp", 5601, 5601, "::/0"), "high"),
    ("sg_world_any_cifs", [C + "vpc_security_group_restrict_ingress_cifs_port_all"],
     "Security group restricts CIFS (445) ingress from 0.0.0.0/0 and ::/0", dict(v6=True, ports=[445]), world_rule("tcp", 445, 445), "high"),
    ("sg_world_any_remote_admin", [C + "vpc_security_group_remote_administration", C + "vpc_security_group_remote_administration_ipv4"],
     "Security group restricts SSH/RDP ingress from 0.0.0.0/0 and ::/0", dict(v6=True, ports=[22, 3389]), world_rule("tcp", 22, 22, "::/0"), "high"),
    ("sg_world_v6_remote_admin", [C + "vpc_security_group_remote_administration_ipv6"],
     "Security group restricts SSH/RDP ingress from ::/0", dict(v4=False, v6=True, ports=[22, 3389]), world_rule("tcp", 3389, 3389, "::/0"), "high"),
]
for _cid, _rows, _title, _kw, _bad_rule, _sev in TURBOT_SG:
    install("aws.claude_a.vpc." + _cid, "security_group", _title, SG if _cid != "sg_world_v4_no_tcp_udp" else w(SG, IpPermissions=[world_rule("icmp", -1, -1)]),
        sg_with(_bad_rule), rows=_rows, severity=_sev, category="exposure", control="SC-7",
        remediation="Remove or narrow the matching ingress rules (source 0.0.0.0/0 or ::/0) on the security group.",
        docs=[EC2_API + "API_IpPermission.html"],
        extra={"fail_all_traffic": sg_with(world_rule("-1", None, None, "::/0" if _kw.get("v4") is False else "0.0.0.0/0"))}, index=idx(security_group=[SG]) if _cid == "sg_world_v4_ssh" else None,
        note=("SSH-only: exact IPv4 world CIDR with TCP/6 port range covering 22, or all-protocol (-1) regardless of serialized port bounds; complete scoped security-group inventory is required. This is a declared ingress rule, not reachability." if _cid == "sg_world_v4_ssh" else "Steampipe aws_vpc_security_group_rule semantics: a rule matches when its CIDR is exactly the world CIDR and it is all-traffic (-1, no port) or its port range covers a listed port; protocol is not filtered."))(_turbot_check(**_kw))


@install("aws.claude_a.vpc.sg_world_v4_only_80_443", "security_group", "Security group IPv4 0.0.0.0/0 ingress is limited to single ports 80 and 443",
    SG, sg_with(world_rule("tcp", 22, 22)), rows=[C + "vpc_security_group_allows_ingress_authorized_ports", C + "foundational_security_ec2_18"],
    severity="high", category="exposure", control="SC-7", remediation="Limit 0.0.0.0/0 ingress to TCP 80/443; remove every other world-open rule.",
    docs=[EC2_API + "API_IpPermission.html"], extra={"fail_all": sg_with(world_rule("-1", None, None))},
    note="IPv4 0.0.0.0/0 only: both FromPort and ToPort must identify exactly TCP 80 or 443.")
def sg_authorized_ports(item, index):
    get(item, "GroupId", str)
    bad = [r for r in turbot_rule_rows(item) if r["cidr_ipv4"] == "0.0.0.0/0"
           and (r["from_port"] is None or r["from_port"] not in (80, 443) or r["to_port"] != r["from_port"])]
    return result(bool(bad), unauthorized_rules=len(bad))


SG_ENI_INDEX = idx(network_interface=[ENI])


@install("aws.claude_a.vpc.sg_attached_to_eni", "security_group", "Security group is attached to at least one network interface",
    SG, w(SG, GroupId="sg-2"), index=SG_ENI_INDEX, rows=[C + "vpc_security_group_associated_to_eni"], severity="low", category="network", control="CM-7",
    remediation="Delete security groups that are not attached to any ENI.", docs=[EC2_API + "API_NetworkInterface.html"],
    dependencies=["security_group", "network_interface"])
def sg_associated_eni(item, index):
    gid = get(item, "GroupId", str)
    return result(not sg_enis(index, gid), group_id=gid)


INSTANCE_SG = {"InstanceId": "i-1", "SecurityGroups": [{"GroupId": "sg-inst", "GroupName": "app"}]}


@install("aws.claude_a.vpc.sg_attached_to_eni_or_instance", "security_group", "Security group is attached to a network interface or instance",
    SG, w(SG, GroupId="sg-2"), index=idx(network_interface=[ENI], instance=[INSTANCE_SG]), rows=[C + "vpc_security_group_unused"],
    severity="low", category="network", control="CM-7", remediation="Delete security groups not attached to any ENI or instance.",
    docs=[EC2_API + "API_NetworkInterface.html"], dependencies=["security_group", "network_interface", "instance"])
def sg_unused_compliance(item, index):
    gid = get(item, "GroupId", str)
    if sg_enis(index, gid):
        return result(False, used_by="network_interface")
    for inst in items(index, "instance"):
        if any(g.get("GroupId") == gid for g in list_of_objects(get(inst, "SecurityGroups", list))):
            return result(False, used_by="instance")
    return result(True, group_id=gid)


WIZ = w(SG, GroupId="sg-w", GroupName="launch-wizard-1")


@install("aws.claude_a.vpc.launch_wizard_sg_not_attached", "security_group", "Launch-wizard security group is not attached to any network interface",
    WIZ, WIZ, index=idx(network_interface=[w(ENI, Groups=[{"GroupId": "sg-1", "GroupName": "web"}])]),
    fail_index=idx(network_interface=[w(ENI, Groups=[{"GroupId": "sg-w", "GroupName": "launch-wizard-1"}])]),
    rows=[C + "vpc_security_group_not_uses_launch_wizard_sg"], severity="medium", category="network", control="SC-7",
    remediation="Detach launch-wizard security groups from ENIs and replace them with least-privilege groups.",
    docs=[EC2_API + "API_SecurityGroup.html"], dependencies=["security_group", "network_interface"], extra={"na": (SG, idx(network_interface=[ENI]))},
    note="Steampipe joins by group name: any ENI group named like the launch-wizard group fails it.")
def sg_launch_wizard_attached(item, index):
    name = get(item, "GroupName", str)
    if not name.startswith("launch-wizard"):
        return "NOT_APPLICABLE", {"reason": "not a launch-wizard group"}
    used = any(g.get("GroupName") == name for eni in items(index, "network_interface") for g in list_of_objects(get(eni, "Groups", list)))
    return result(used, group_name=name)


# =========================================================================== Network ACLs
NACL = {"NetworkAclId": "acl-1", "VpcId": "vpc-1", "IsDefault": False, "Associations": [{"SubnetId": "subnet-1", "NetworkAclAssociationId": "aclassoc-1"}],
        "Entries": [{"RuleNumber": 100, "Egress": False, "Protocol": "6", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 443, "To": 443}},
                    {"RuleNumber": 32767, "Egress": False, "Protocol": "-1", "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"}]}


def nacl_entry(protocol, low=None, high=None, action="allow", cidr="0.0.0.0/0", number=50, egress=False):
    entry = {"RuleNumber": number, "Egress": egress, "Protocol": protocol, "RuleAction": action}
    entry["Ipv6CidrBlock" if ":" in cidr else "CidrBlock"] = cidr
    if low is not None:
        entry["PortRange"] = {"From": low, "To": high}
    return entry


def nacl_with(*entries):
    return w(NACL, Entries=list(entries) + NACL["Entries"])


NACL_INDEX = idx(security_group=[SG])
NACL_NA = (NACL, idx(security_group=[DEFAULT_SG]))


def _nacl_prowler(protocol, port):
    def evaluate(item, index):
        entries = get(item, "Entries", list)
        return result(prowler_nacl_open(entries, protocol, port), protocol=protocol, port=port)
    return evaluate


for _cid, _row, _proto, _port, _title, _bad in [
        ("nacl_no_world_all_ports", "ec2_networkacl_allow_ingress_any_port", "-1", 0, "Network ACL ordered ingress rules do not allow all traffic from 0.0.0.0/0 or ::/0", nacl_entry("-1")),
        ("nacl_no_world_tcp_22", "ec2_networkacl_allow_ingress_tcp_port_22", "6", 22, "Network ACL ordered ingress rules do not allow TCP 22 from 0.0.0.0/0 or ::/0", nacl_entry("6", 22, 22, cidr="::/0")),
        ("nacl_no_world_tcp_3389", "ec2_networkacl_allow_ingress_tcp_port_3389", "6", 3389, "Network ACL ordered ingress rules do not allow TCP 3389 from 0.0.0.0/0 or ::/0", nacl_entry("6", 3380, 3390))]:
    install("aws.claude_a.vpc." + _cid, "network_acl", _title, NACL, nacl_with(_bad), index=NACL_INDEX,
        rows=[P + _row], severity="medium", category="network", control="SC-7",
        remediation="Add lower-numbered deny entries or remove allow entries for this traffic from 0.0.0.0/0 and ::/0.",
        docs=[EC2_API + "API_NetworkAclEntry.html"], dependencies=["network_acl"],
        note="Native all-ACL security criterion: evaluate ordered ingress ACL entries for world access; no security-group applicability gate. Pinned Prowler also requires a non-default security group, so this intentionally differs in scope.")(_nacl_prowler(_proto, _port))


@install("aws.claude_a.vpc.nondefault_nacl_associated", "network_acl", "Non-default network ACL is associated with a subnet",
    NACL, w(NACL, Associations=[]), rows=[P + "ec2_networkacl_unused"], severity="low", category="network", control="CM-7",
    remediation="Delete non-default network ACLs that no subnet uses.", docs=[EC2_API + "API_NetworkAcl.html"], extra={"na": w(NACL, IsDefault=True)})
def nacl_unused_prowler(item, index):
    if get(item, "IsDefault", bool):
        return "NOT_APPLICABLE", {"reason": "default network ACL"}
    assoc = [a for a in list_of_objects(get(item, "Associations", list)) if a.get("SubnetId")]
    return result(not assoc, associations=len(assoc))


@install("aws.claude_a.vpc.nacl_associated", "network_acl", "Network ACL has at least one association",
    NACL, w(NACL, Associations=[]), rows=[C + "vpc_network_acl_unused", C + "foundational_security_ec2_16"], severity="low", category="network", control="CM-7",
    remediation="Delete network ACLs that are not associated with any subnet.", docs=[EC2_API + "API_NetworkAcl.html"])
def nacl_unused(item, index):
    count = len(list_of_objects(get(item, "Associations", list)))
    return result(count < 1, associations=count)


@install("aws.claude_a.vpc.nacl_no_world_remote_admin", "network_acl", "Network ACL does not allow world ingress to SSH/RDP",
    NACL, nacl_with(nacl_entry("17", 3389, 3389, cidr="::/0")), rows=[C + "vpc_network_acl_remote_administration", C + "foundational_security_ec2_21"],
    severity="medium", category="network", control="SC-7", remediation="Remove allow entries for 22/3389 (or all traffic) from 0.0.0.0/0 and ::/0.",
    docs=[EC2_API + "API_NetworkAclEntry.html"], extra={"fail_all": nacl_with(nacl_entry("-1"))},
    note="Steampipe evaluates each allow entry independently (rule order and preceding denies are ignored).")
def nacl_remote_admin(item, index):
    bad = []
    for entry in list_of_objects(get(item, "Entries", list)):
        if get(entry, "Egress", bool) or get(entry, "RuleAction", str) != "allow":
            continue
        if entry.get("CidrBlock") != "0.0.0.0/0" and entry.get("Ipv6CidrBlock") != "::/0":
            continue
        proto, ports = get(entry, "Protocol", str), entry.get("PortRange")
        if proto == "-1" and ports is None:
            bad.append(entry["RuleNumber"])
        elif isinstance(ports, dict) and proto in ("6", "17"):
            low, high = get(ports, "From", int), get(ports, "To", int)
            if any(low <= p <= high for p in (22, 3389)):
                bad.append(entry["RuleNumber"])
    return result(bool(bad), rule_numbers=bad)


# =========================================================================== VPCs and subnets
FLOW = {"FlowLogId": "fl-1", "ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE"}


@install("aws.claude_a.vpc.flow_logs_active", "vpc", "Every declared flow log of an owned VPC is active",
    VPC, w(VPC, VpcId="vpc-2"), index=idx(flow_log=[FLOW]), rows=[C + "vpc_flow_logs_enabled", C + "foundational_security_ec2_6"],
    severity="medium", category="hardening", control="AU-12", remediation="Enable VPC Flow Logs (CreateFlowLogs) for every VPC.",
    docs=[EC2_API + "API_DescribeFlowLogs.html"], dependencies=["vpc", "flow_log"],
    extra={"na": (w(VPC, OwnerId="210987654321"), idx(flow_log=[FLOW])), "fail_inactive": (VPC, idx(flow_log=[FLOW, w(FLOW, FlowLogId="fl-2", FlowLogStatus="FAILED")]))},
    note="Shared VPCs owned by another account are skipped; any non-ACTIVE flow log of the VPC is an alarm row upstream.")
def vpc_flow_logs(item, index):
    vpc_id = get(item, "VpcId", str)
    if get(item, "OwnerId", str) != account(index):
        return "NOT_APPLICABLE", {"reason": "VPC shared from another account"}
    logs = [f for f in items(index, "flow_log") if f.get("ResourceId") == vpc_id]
    statuses = [get(f, "FlowLogStatus", str) for f in logs]
    return result(not statuses or any(s != "ACTIVE" for s in statuses), statuses=statuses)


@install("aws.claude_a.vpc.in_use_vpc_has_flow_log", "vpc", "In-use VPC has a flow log",
    VPC, w(VPC, VpcId="vpc-2"), index=idx(flow_log=[FLOW], network_interface=[ENI, w(ENI, NetworkInterfaceId="eni-2", VpcId="vpc-2")]),
    rows=[P + "vpc_flow_logs_enabled"], severity="medium", category="hardening", control="AU-12",
    remediation="Enable VPC Flow Logs for every VPC with network interfaces.", docs=[EC2_API + "API_DescribeFlowLogs.html"],
    dependencies=["vpc", "flow_log", "network_interface"], extra={"na": (w(VPC, VpcId="vpc-9"), idx(flow_log=[], network_interface=[ENI]))},
    note="Prowler: any flow log with this resource id passes regardless of status; VPCs without ENIs are skipped.")
def vpc_flow_logs_prowler(item, index):
    vpc_id = get(item, "VpcId", str)
    if not vpc_in_use(index, vpc_id):
        return "NOT_APPLICABLE", {"reason": "VPC not in use"}
    return result(not any(f.get("ResourceId") == vpc_id for f in items(index, "flow_log")), vpc_id=vpc_id)


@install("aws.claude_a.vpc.vpc_has_subnets", "vpc", "VPC has at least one subnet",
    VPC, w(VPC, VpcId="vpc-2"), index=idx(subnet=[SUBNET]), rows=[C + "vpc_not_in_use"], severity="low", category="network", control="CM-7",
    remediation="Delete VPCs that have no subnets.", docs=[EC2_API + "API_Subnet.html"], dependencies=["vpc", "subnet"])
def vpc_not_in_use(item, index):
    vpc_id = get(item, "VpcId", str)
    return result(not any(s.get("VpcId") == vpc_id for s in items(index, "subnet")), vpc_id=vpc_id)


TWO_AZ = [SUBNET, w(SUBNET, SubnetId="subnet-2", AvailabilityZone="us-east-1b")]


@install("aws.claude_a.vpc.subnets_in_multiple_azs", "vpc", "VPC has subnets in more than one Availability Zone",
    VPC, VPC, index=idx(subnet=TWO_AZ), fail_index=idx(subnet=[SUBNET]), rows=[C + "vpc_subnet_multi_az_enabled"], severity="medium",
    category="hardening", control="CP-10", remediation="Create subnets in at least two Availability Zones for the VPC.",
    docs=[EC2_API + "API_Subnet.html"], dependencies=["vpc", "subnet"])
def vpc_multi_az(item, index):
    vpc_id = get(item, "VpcId", str)
    zones = {get(s, "AvailabilityZone", str) for s in items(index, "subnet") if s.get("VpcId") == vpc_id}
    return result(len(zones) <= 1, availability_zones=sorted(zones))


@install("aws.claude_a.vpc.in_use_vpc_subnets_multi_az", "vpc", "In-use VPC has subnets in different Availability Zones",
    VPC, VPC, index=idx(subnet=TWO_AZ, network_interface=[ENI]), fail_index=idx(subnet=[SUBNET], network_interface=[ENI]),
    rows=[P + "vpc_subnet_different_az"], severity="medium", category="hardening", control="CP-10",
    remediation="Create subnets in at least two Availability Zones.", docs=[EC2_API + "API_Subnet.html"],
    dependencies=["vpc", "subnet", "network_interface"], extra={"na": (VPC, idx(subnet=TWO_AZ, network_interface=[]))})
def vpc_multi_az_prowler(item, index):
    vpc_id = get(item, "VpcId", str)
    zones = {get(s, "AvailabilityZone", str) for s in items(index, "subnet") if s.get("VpcId") == vpc_id}
    if not vpc_in_use(index, vpc_id):
        return "NOT_APPLICABLE", {"reason": "VPC not in use"}
    return result(len(zones) <= 1, availability_zones=sorted(zones))


def _turbot_access(index, subnet):
    """aws-compliance vpc_subnet_public_and_private access classification."""
    sid, vpc_id = get(subnet, "SubnetId", str), get(subnet, "VpcId", str)

    def public_route(route):
        return route.get("DestinationCidrBlock") == "0.0.0.0/0" and (
            str(route.get("GatewayId") or "").startswith("igw-") or str(route.get("NatGatewayId") or "").startswith("nat-"))
    explicit = public_explicit = implicit_public = False
    for table in items(index, "route_table"):
        assocs = list_of_objects(get(table, "Associations", list))
        routes = list_of_objects(get(table, "Routes", list))
        if any(a.get("SubnetId") == sid for a in assocs):
            explicit = True
            if any(public_route(r) for r in routes):
                public_explicit = True
        if table.get("VpcId") == vpc_id and any(a.get("Main") is True for a in assocs) and any(public_route(r) for r in routes):
            implicit_public = True
    if explicit and not public_explicit:
        return "private"
    return "public" if public_explicit or implicit_public else "private"


PUBLIC_RTB = {"RouteTableId": "rtb-pub", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-2", "Main": False}],
              "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "Origin": "CreateRoute"}]}
MIXED = dict(subnet=[SUBNET, w(SUBNET, SubnetId="subnet-2", MapPublicIpOnLaunch=True)], route_table=[RTB_MAIN, PUBLIC_RTB])


@install("aws.claude_a.vpc.public_and_private_subnets", "vpc", "VPC has both public and private subnets",
    VPC, VPC, index=idx(**MIXED), fail_index=idx(subnet=[SUBNET], route_table=[RTB_MAIN]), rows=[C + "vpc_subnet_public_and_private"],
    severity="medium", category="network", control="SC-7", remediation="Separate internet-facing and internal tiers into public and private subnets.",
    docs=[VPC_DOC + "configure-subnets.html"], dependencies=["vpc", "subnet", "route_table"],
    note="Steampipe classes a subnet public when its explicit (or the VPC main) route table has 0.0.0.0/0 to an igw- or nat- target; a VPC without subnets fails.")
def vpc_public_private(item, index):
    vpc_id = get(item, "VpcId", str)
    access = {_turbot_access(index, s) for s in items(index, "subnet") if s.get("VpcId") == vpc_id}
    return result(access != {"public", "private"}, access=sorted(access))


@install("aws.claude_a.vpc.in_use_vpc_public_and_private_subnets", "vpc", "In-use VPC has both public and private subnets",
    VPC, VPC, index=idx(network_interface=[ENI], **MIXED), fail_index=idx(subnet=[SUBNET], route_table=[RTB_MAIN], network_interface=[ENI]),
    rows=[P + "vpc_subnet_separate_private_public"], severity="medium", category="network", control="SC-7",
    remediation="Separate internet-facing and internal tiers into public and private subnets.", docs=[VPC_DOC + "configure-subnets.html"],
    dependencies=["vpc", "subnet", "route_table", "network_interface"], extra={"na": (VPC, idx(network_interface=[], **MIXED))},
    note="Prowler public = 0.0.0.0/0 to igw- in the subnet's explicit route table, else the VPC main route table.")
def vpc_public_private_prowler(item, index):
    vpc_id = get(item, "VpcId", str)
    subnets = [s for s in items(index, "subnet") if s.get("VpcId") == vpc_id]
    if not vpc_in_use(index, vpc_id):
        return "NOT_APPLICABLE", {"reason": "VPC not in use"}
    flags = {subnet_public_prowler(index, s)[0] for s in subnets}
    return result(flags != {True, False}, public_flags=sorted(flags))


@install("aws.claude_a.vpc.subnet_no_auto_public_ip", "subnet", "Subnet does not auto-assign public IPv4 addresses",
    SUBNET, w(SUBNET, MapPublicIpOnLaunch=True),
    rows=[C + "vpc_subnet_auto_assign_public_ip_disabled", C + "foundational_security_ec2_15", R + "vpc_subnet_auto_assign_public_ip_disabled"],
    severity="medium", category="exposure", control="SC-7", remediation="Disable MapPublicIpOnLaunch on the subnet (ModifySubnetAttribute).",
    docs=[EC2_API + "API_Subnet.html"])
def subnet_auto_public(item, index):
    value = get(item, "MapPublicIpOnLaunch", bool)
    return result(value, map_public_ip_on_launch=value)


@install("aws.claude_a.vpc.in_use_subnet_no_auto_public_ip", "subnet", "In-use subnet does not auto-assign public IPv4 addresses",
    SUBNET, w(SUBNET, MapPublicIpOnLaunch=True), index=idx(network_interface=[ENI]), rows=[P + "vpc_subnet_no_public_ip_by_default"],
    severity="medium", category="exposure", control="SC-7", remediation="Disable MapPublicIpOnLaunch on subnets with workloads.",
    docs=[EC2_API + "API_Subnet.html"], dependencies=["subnet", "network_interface"], extra={"na": (SUBNET, idx(network_interface=[]))})
def subnet_auto_public_prowler(item, index):
    value = get(item, "MapPublicIpOnLaunch", bool)
    if not subnet_in_use(index, get(item, "SubnetId", str)):
        return "NOT_APPLICABLE", {"reason": "subnet not in use"}
    return result(value, map_public_ip_on_launch=value)


ACCOUNT_VPCS = [{"AccountId": ACCOUNT, "Region": "us-east-1", "VpcId": "vpc-1", "IsDefault": False},
                {"AccountId": ACCOUNT, "Region": "eu-west-1", "VpcId": "vpc-9", "IsDefault": False}]


def _account_vpcs(index):
    me = account(index)
    rows = items(index, "vpc_account_inventory")
    for row in rows:
        if get(row, "AccountId", str) != me:
            raise Unavailable("foreign account in VPC inventory")
    return rows


@install("aws.claude_a.vpc.vpcs_in_multiple_regions", "vpc_account_inventory", "Account has VPCs in more than one region",
    {}, {}, target="scope", pass_index=idx(vpc_account_inventory=ACCOUNT_VPCS), fail_index=idx(vpc_account_inventory=ACCOUNT_VPCS[:1]),
    rows=[C + "vpc_in_more_than_one_region"], severity="low", category="hardening", control="CP-10",
    remediation="Deploy workloads across VPCs in at least two regions where resilience requires it.", docs=[EC2_API + "API_DescribeVpcs.html"],
    note="Needs an account-wide (all enabled regions) VPC inventory; regional scopes alone cannot answer it.")
def vpcs_multi_region(context, index):
    regions = {get(r, "Region", str) for r in _account_vpcs(index)}
    return result(len(regions) <= 1, regions=sorted(regions))


@install("aws.claude_a.vpc.nondefault_vpcs_in_multiple_regions", "vpc_account_inventory", "Account has non-default VPCs in more than one region",
    {}, {}, target="scope", pass_index=idx(vpc_account_inventory=ACCOUNT_VPCS),
    fail_index=idx(vpc_account_inventory=[ACCOUNT_VPCS[0], w(ACCOUNT_VPCS[1], IsDefault=True)]),
    rows=[P + "vpc_different_regions"], severity="medium", category="hardening", control="CP-10",
    remediation="Deploy workloads across non-default VPCs in at least two regions where resilience requires it.", docs=[EC2_API + "API_DescribeVpcs.html"],
    extra={"na": ({}, idx(vpc_account_inventory=[]))}, note="Prowler reports only when the account has VPCs; default VPCs are ignored.")
def vpcs_multi_region_prowler(context, index):
    rows = _account_vpcs(index)
    if not rows:
        return "NOT_APPLICABLE", {"reason": "no VPCs"}
    regions = {get(r, "Region", str) for r in rows if not get(r, "IsDefault", bool)}
    return result(len(regions) <= 1, regions=sorted(regions))


IGW = {"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1", "State": "available"}]}


@install("aws.claude_a.vpc.igw_attached", "internet_gateway", "Internet gateway is attached to a VPC",
    IGW, w(IGW, Attachments=[]), rows=[C + "vpc_igw_attached_to_authorized_vpc"], severity="low", category="network", control="CM-7",
    remediation="Delete detached internet gateways, and attach gateways only to approved VPCs.", docs=[EC2_API + "API_InternetGateway.html"],
    note="Upstream only tests that the gateway has an attachment (no authorized-VPC list is evaluated).")
def igw_attached(item, index):
    count = len(list_of_objects(get(item, "Attachments", list)))
    return result(count == 0, attachments=count)


@install("aws.claude_a.vpc.route_table_no_default_igw_route", "route_table", "Route table has no 0.0.0.0/0 route to an internet gateway",
    RTB_MAIN, PUBLIC_RTB, rows=[C + "vpc_route_table_restrict_public_access_to_igw"], severity="medium", category="exposure", control="SC-7",
    remediation="Route internet-bound traffic only from approved public route tables; remove default IGW routes from private tables.",
    docs=[EC2_API + "API_Route.html"], note="Steampipe compares DestinationCidrBlock to 0.0.0.0/0 or ::/0 with GatewayId like igw%.")
def rtb_igw(item, index):
    bad = [r.get("DestinationCidrBlock") for r in list_of_objects(get(item, "Routes", list))
           if r.get("DestinationCidrBlock") in ("0.0.0.0/0", "::/0") and str(r.get("GatewayId") or "").startswith("igw")]
    return result(bool(bad), destinations=bad)


BPA = {"VpcBlockPublicAccessOptions": {"InternetGatewayBlockMode": "block-bidirectional", "State": "default-state"}}


@install("aws.claude_a.vpc.block_public_access_igw", "vpc_block_public_access_options", "VPC Block Public Access blocks internet gateway traffic",
    BPA, {"VpcBlockPublicAccessOptions": {"InternetGatewayBlockMode": "off"}},
    rows=[C + "vpc_block_public_access_restrict_internet_gateway_traffic", C + "foundational_security_ec2_172"], severity="medium", category="exposure", control="SC-7",
    remediation="Enable VPC Block Public Access in block-bidirectional or block-ingress mode (ModifyVpcBlockPublicAccessOptions), with exclusions only where needed.",
    docs=[EC2_API + "API_VpcBlockPublicAccessOptions.html"])
def vpc_bpa(item, index):
    mode = get(item, "VpcBlockPublicAccessOptions.InternetGatewayBlockMode", str)
    return result(mode not in ("block-bidirectional", "block-ingress"), mode=mode)


# =========================================================================== endpoints
EP = {"VpcEndpointId": "vpce-1", "VpcId": "vpc-1", "VpcEndpointType": "Interface", "ServiceName": "com.amazonaws.us-east-1.ec2",
      "SubnetIds": ["subnet-1", "subnet-2"], "PolicyDocument": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}'}
ENDPOINT_SERVICES = [("vpc_endpoint_ec2", "ec2", [C + "vpc_configured_to_use_vpc_endpoints", C + "foundational_security_ec2_10"]),
    ("interface_endpoint_ecr_api", "ecr.api", [C + "vpc_configured_to_use_interface_endpoint_for_ecr_api", C + "foundational_security_ec2_55"]),
    ("interface_endpoint_ecr_dkr", "ecr.dkr", [C + "vpc_configured_to_use_interface_endpoint_for_docker_registry", C + "foundational_security_ec2_56"]),
    ("interface_endpoint_ssm", "ssm", [C + "vpc_configured_to_use_interface_endpoint_for_ssm", C + "foundational_security_ec2_57"]),
    ("interface_endpoint_ssm_contacts", "ssm-contacts", [C + "vpc_configured_to_use_interface_endpoint_for_ssm_contacts", C + "foundational_security_ec2_58"]),
    ("interface_endpoint_ssm_incidents", "ssm-incidents", [C + "vpc_configured_to_use_interface_endpoint_for_ssm_incidents", C + "foundational_security_ec2_60"])]


def _endpoint_check(service):
    def evaluate(item, index):
        vpc_id = get(item, "VpcId", str)
        name = "com.amazonaws.%s.%s" % (region(index), service)
        return result(not any(e.get("VpcId") == vpc_id and e.get("ServiceName") == name for e in items(index, "vpc_endpoint")), service_name=name)
    return evaluate


for _cid, _svc, _rows in ENDPOINT_SERVICES:
    install("aws.claude_a.vpc." + _cid, "vpc", "VPC has a VPC endpoint for com.amazonaws.<region>.%s" % _svc,
        VPC, w(VPC, VpcId="vpc-2"), index=idx(vpc_endpoint=[w(EP, VpcEndpointId="vpce-" + _svc, ServiceName="com.amazonaws.us-east-1." + _svc)]),
        rows=_rows, severity="medium", category="network", control="SC-7",
        remediation="Create a VPC endpoint for com.amazonaws.<region>.%s in the VPC so traffic stays on the AWS network." % _svc,
        docs=[VPC_DOC.replace("vpc/latest/userguide/", "vpc/latest/privatelink/") + "create-interface-endpoint.html"], dependencies=["vpc", "vpc_endpoint"],
        note="Steampipe matches the endpoint service name exactly (LIKE without wildcards); endpoint type and state are not inspected.")(_endpoint_check(_svc))


@install("aws.claude_a.vpc.in_use_vpc_ec2_endpoint", "vpc", "In-use VPC has an EC2 VPC endpoint",
    VPC, w(VPC, VpcId="vpc-2"), index=idx(vpc_endpoint=[EP], network_interface=[ENI, w(ENI, NetworkInterfaceId="eni-2", VpcId="vpc-2")]),
    rows=[P + "vpc_endpoint_for_ec2_enabled"], severity="medium", category="network", control="SC-7",
    remediation="Create an EC2 interface endpoint in VPCs with workloads.", docs=[VPC_DOC.replace("vpc/latest/userguide/", "vpc/latest/privatelink/") + "create-interface-endpoint.html"],
    dependencies=["vpc", "vpc_endpoint", "network_interface"], extra={"na": (w(VPC, VpcId="vpc-9"), idx(vpc_endpoint=[EP], network_interface=[ENI]))},
    note="Prowler: any endpoint of the VPC whose service name contains 'ec2'.")
def vpc_ec2_endpoint_prowler(item, index):
    vpc_id = get(item, "VpcId", str)
    if not vpc_in_use(index, vpc_id):
        return "NOT_APPLICABLE", {"reason": "VPC not in use"}
    return result(not any(e.get("VpcId") == vpc_id and "ec2" in str(e.get("ServiceName", "")) for e in items(index, "vpc_endpoint")))


@install("aws.claude_a.vpc.interface_endpoint_multi_az", "vpc_endpoint", "Interface VPC endpoint spans more than one subnet",
    EP, w(EP, SubnetIds=["subnet-1"]), index=idx(vpc=[VPC]), rows=[P + "vpc_endpoint_multi_az_enabled"], severity="medium",
    category="hardening", control="CP-10", remediation="Add subnets in additional Availability Zones to the interface endpoint.",
    docs=[EC2_API + "API_VpcEndpoint.html"], dependencies=["vpc_endpoint", "vpc"], extra={"na": (w(EP, VpcEndpointType="Gateway"), idx(vpc=[VPC]))},
    note="Prowler: Interface endpoints whose VPC is in the inventory; more than one subnet passes.")
def endpoint_multi_az(item, index):
    kind, vpc_id = get(item, "VpcEndpointType", str), get(item, "VpcId", str)
    if kind != "Interface" or not any(v.get("VpcId") == vpc_id for v in items(index, "vpc")):
        return "NOT_APPLICABLE", {"reason": "not an interface endpoint of an inventoried VPC"}
    subnets = get(item, "SubnetIds", list)
    return result(len(subnets) <= 1, subnets=len(subnets))


GW_EP = w(EP, VpcEndpointType="Gateway", ServiceName="com.amazonaws.us-east-1.s3",
          PolicyDocument='{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::corp/*"}]}')


@install("aws.claude_a.vpc.gateway_endpoint_policy_not_open", "vpc_endpoint", "Gateway VPC endpoint policy does not allow * to everyone unconditionally",
    GW_EP, w(GW_EP, PolicyDocument='{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}'),
    rows=[C + "vpc_gateway_endpoint_restrict_public_access"], severity="medium", category="least_privilege", control="AC-3",
    remediation="Replace the full-access gateway endpoint policy with one scoped to required actions, resources or principals.",
    docs=[VPC_DOC.replace("vpc/latest/userguide/", "vpc/latest/privatelink/") + "vpc-endpoints-access.html"], extra={"na": EP},
    note="Steampipe policy_std: an Allow statement without Condition, wildcard principal and Action exactly ['*'].")
def gateway_endpoint_policy(item, index):
    if get(item, "VpcEndpointType", str) != "Gateway":
        return "NOT_APPLICABLE", {"reason": "not a gateway endpoint"}
    bad = []
    for s in policy_document(get(item, "PolicyDocument")):
        actions = s.get("Action")
        actions = sorted({a.lower() for a in (actions if isinstance(actions, list) else [actions]) if isinstance(a, str)})
        if s.get("Effect") == "Allow" and "Condition" not in s and wildcard_principal(s) and actions == ["*"]:
            bad.append(s.get("Sid"))
    return result(bool(bad), statements=len(bad))


IF_EP = w(EP, ServiceName="com.amazonaws.vpce.us-east-1.vpce-svc-1",
          PolicyDocument={"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "*", "Resource": "*"}]})


def _endpoint_arn_account(value):
    """Read only the ARN account field; role/resource text is never account proof."""
    if not isinstance(value, str):
        raise Unavailable("malformed endpoint principal ARN")
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or not parts[1] or not parts[2] or not parts[5]:
        raise Unavailable("malformed endpoint principal ARN")
    return parts[4]


def _endpoint_direct_arn_account(value):
    """Accept documented AWS identity principal ARN forms, not arbitrary resource ARNs."""
    account_id = _endpoint_arn_account(value)
    _, _, service, region, _, resource = value.split(":", 5)
    if region or not re.fullmatch(r"[0-9]{12}", account_id) or "*" in resource or "?" in resource:
        raise Unavailable("unsupported endpoint identity principal ARN")
    if service == "iam":
        valid = resource == "root" or any(
            resource.startswith(prefix) and all(
                re.fullmatch(r"[A-Za-z0-9+=,.@_-]+", segment)
                for segment in resource[len(prefix):].split("/")
            )
            for prefix in ("user/", "role/")
        )
    elif service == "sts":
        if resource.startswith("assumed-role/"):
            parts = resource.removeprefix("assumed-role/").split("/")
            valid = len(parts) == 2 and all(re.fullmatch(r"[A-Za-z0-9_+=,.@-]+", part) for part in parts)
        else:
            name = resource.removeprefix("federated-user/")
            valid = resource.startswith("federated-user/") and bool(re.fullmatch(r"[A-Za-z0-9_+=,.@-]+", name))
    else:
        valid = False
    if not valid:
        raise Unavailable("unsupported endpoint identity principal ARN")
    return account_id


def _endpoint_condition_arn_binds_account(value, operator, audited_account):
    if _endpoint_arn_account(value) != audited_account:
        return False
    if operator == "StringLike":
        # IAM StringLike matches the whole string, unlike component-wise ArnLike.
        # A wildcard before the account component must not shift the match.
        prefix = value.split(":", 5)[:5]
        return all("*" not in part and "?" not in part for part in prefix)
    return True


def _endpoint_principal_accounts(principal):
    if principal == "*":
        return ["*"]
    if isinstance(principal, str):
        values = [principal]
    elif isinstance(principal, dict) and set(principal) == {"AWS"}:
        aws = principal["AWS"]
        values = aws if isinstance(aws, list) else [aws]
    else:
        raise Unavailable("unsupported endpoint policy principal")
    if not values:
        raise Unavailable("empty endpoint policy principal")
    accounts = []
    for value in values:
        if not isinstance(value, str) or not value:
            raise Unavailable("malformed endpoint policy principal")
        if value == "*" or re.fullmatch(r"[0-9]{12}", value):
            accounts.append(value)
        else:
            accounts.append(_endpoint_direct_arn_account(value))
    return accounts


def _endpoint_condition_binds_account(condition, audited_account):
    """Prove a positive principal-account constraint without inferring it from source keys."""
    if condition is None:
        return False
    if not isinstance(condition, dict) or not condition:
        raise Unavailable("malformed endpoint policy condition")
    bound = False
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict) or not block:
            raise Unavailable("malformed endpoint policy condition")
        for key, raw in block.items():
            if not isinstance(key, str):
                raise Unavailable("malformed endpoint policy condition key")
            values = raw if isinstance(raw, list) else [raw]
            if not values or any(not isinstance(value, str) or not value for value in values):
                raise Unavailable("malformed endpoint policy condition value")
            key = key.lower()
            if operator == "StringEquals" and key == "aws:principalaccount":
                bound |= all(value == audited_account for value in values)
            elif operator in {"StringEquals", "StringLike", "ArnEquals", "ArnLike"} and key == "aws:principalarn":
                try:
                    bound |= all(_endpoint_condition_arn_binds_account(value, operator, audited_account)
                                 for value in values)
                except Unavailable:
                    pass
    return bound


@install("aws.claude_a.vpc.endpoint_policy_trust_boundary", "vpc_endpoint", "VPC endpoint policy Allow principals are bound to the audited account",
    IF_EP, w(IF_EP, PolicyDocument={"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::210987654321:root"}, "Action": "*", "Resource": "*"}]}),
    index=idx(), rows=[P + "vpc_endpoint_connections_trust_boundaries"], severity="high", category="least_privilege", control="AC-3",
    remediation="Restrict endpoint policy Allow principals to the audited account, or add a positive condition that binds aws:PrincipalAccount or the account field of aws:PrincipalArn to it.",
    docs=[VPC_DOC.replace("vpc/latest/userguide/", "vpc/latest/privatelink/") + "vpc-endpoints-access.html"],
    extra={"na": w(IF_EP, PolicyDocument=DROP), "fail_wildcard": w(IF_EP, PolicyDocument={"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]})},
    note="Account-only boundary: exact AWS principal account or positive PrincipalAccount/PrincipalArn condition; other source/VPC restrictions do not prove account membership. Deny interactions and unsupported principals remain UNKNOWN; no trusted_account_ids are configured.")
def endpoint_trust(item, index):
    get(item, "VpcEndpointId", str)
    raw = absent_or(item, "VpcEndpointId", "PolicyDocument", None)
    if raw is None:
        return "NOT_APPLICABLE", {"reason": "endpoint has no policy"}
    me = account(index)
    statements = policy_document(raw)
    has_deny = any(s.get("Effect") == "Deny" for s in statements)
    uncertain = False
    foreign = []
    for statement in statements:
        effect = statement.get("Effect")
        if effect == "Deny":
            continue
        if effect != "Allow":
            uncertain = True
            continue
        if "NotPrincipal" in statement:
            uncertain = True
            continue
        try:
            accounts = _endpoint_principal_accounts(statement.get("Principal"))
            bound = _endpoint_condition_binds_account(statement.get("Condition"), me)
        except Unavailable:
            uncertain = True
            continue
        if all(acct == me for acct in accounts) or bound:
            continue
        if statement.get("Condition") is not None:
            uncertain = True
        else:
            foreign.extend(acct for acct in accounts if acct != me)
    if foreign:
        if has_deny:
            return "UNKNOWN", {"reason": "Deny statements may limit a foreign Allow principal", "principal_accounts": sorted(set(foreign))}
        return result(True, principal_accounts=sorted(set(foreign)))
    if uncertain:
        return "UNKNOWN", {"reason": "endpoint policy does not prove an audited-account principal boundary"}
    return result(False)


SVC = {"ServiceId": "vpce-svc-1", "ServiceName": "com.amazonaws.vpce.us-east-1.vpce-svc-1", "Owner": ACCOUNT, "AcceptanceRequired": True,
       "AllowedPrincipals": ["arn:aws:iam::%s:root" % ACCOUNT]}


@install("aws.claude_a.vpc.endpoint_service_acceptance_required", "vpc_endpoint_service", "Account-owned VPC endpoint service requires connection acceptance",
    SVC, w(SVC, AcceptanceRequired=False), index=idx(), rows=[C + "vpc_endpoint_service_acceptance_required_enabled"], severity="medium", category="network", control="AC-3",
    remediation="Enable AcceptanceRequired on the endpoint service (ModifyVpcEndpointServiceConfiguration).",
    docs=[EC2_API + "API_ServiceConfiguration.html"], extra={"na": w(SVC, Owner="amazon")},
    note="Steampipe lists every available service (including AWS-owned ones the customer cannot configure); only account-owned services are evaluated natively.")
def endpoint_service_acceptance(item, index):
    if get(item, "Owner", str) != account(index):
        return "NOT_APPLICABLE", {"reason": "service not owned by the audited account"}
    value = get(item, "AcceptanceRequired", bool)
    return result(not value, acceptance_required=value)


@install("aws.claude_a.vpc.endpoint_service_principals_trusted", "vpc_endpoint_service", "Account-owned VPC endpoint service allows only the audited account",
    SVC, w(SVC, AllowedPrincipals=["arn:aws:iam::%s:root" % ACCOUNT, "*"]), index=idx(), rows=[P + "vpc_endpoint_services_allowed_principals_trust_boundaries"],
    severity="high", category="least_privilege", control="AC-3", remediation="Remove untrusted or wildcard allowed principals from the endpoint service.",
    docs=[EC2_API + "API_DescribeVpcEndpointServicePermissions.html"], extra={"na": w(SVC, Owner="amazon"), "pass_none": w(SVC, AllowedPrincipals=[])},
    note="AllowedPrincipals comes from DescribeVpcEndpointServicePermissions. Prowler keeps only the last principal's verdict; natively any untrusted principal fails.")
def endpoint_service_principals(item, index):
    me = account(index)
    if get(item, "Owner", str) != me:
        return "NOT_APPLICABLE", {"reason": "service not owned by the audited account"}
    bad = []
    for principal in get(item, "AllowedPrincipals", list):
        if not isinstance(principal, str):
            raise Unavailable("malformed allowed principal")
        acct = principal if principal == "*" or principal.isdigit() else (principal.split(":")[4] if principal.count(":") >= 4 else principal)
        if acct != me:
            bad.append(acct)
    return result(bool(bad), untrusted=bad)


# =========================================================================== peering
PEER = {"VpcPeeringConnectionId": "pcx-1", "Status": {"Code": "active"},
        "RequesterVpcInfo": {"OwnerId": ACCOUNT, "VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"},
        "AccepterVpcInfo": {"OwnerId": ACCOUNT, "VpcId": "vpc-2", "CidrBlock": "10.1.0.0/16"}}


@install("aws.claude_a.vpc.peering_same_account_active", "vpc_peering", "VPC peering connection is active and within one account",
    PEER, w(PEER, AccepterVpcInfo__OwnerId="210987654321"), rows=[C + "vpc_peering_connection_no_cross_account_access"],
    severity="medium", category="network", control="AC-4", remediation="Remove cross-account peering not explicitly approved; delete inactive peering connections.",
    docs=[EC2_API + "API_VpcPeeringConnection.html"], extra={"fail_pending": w(PEER, Status={"Code": "pending-acceptance"})})
def peering_cross_account(item, index):
    code = get(item, "Status.Code", str)
    req, acc = get(item, "RequesterVpcInfo.OwnerId", str), get(item, "AccepterVpcInfo.OwnerId", str)
    return result(code != "active" or req != acc, status=code, requester=req, accepter=acc)


def _cidr_eq(a, b):
    try:
        return a is not None and b is not None and ip_network(a, strict=False) == ip_network(b, strict=False)
    except ValueError as exc:
        raise Unavailable("malformed CIDR") from exc


PEER_RTB = {"RouteTableId": "rtb-p", "VpcId": "vpc-1", "Associations": [],
            "Routes": [{"DestinationCidrBlock": "10.1.5.0/24", "VpcPeeringConnectionId": "pcx-1", "Origin": "CreateRoute"}]}
PEER_RTB_BAD = w(PEER_RTB, Routes=[{"DestinationCidrBlock": "10.0.0.0/16", "VpcPeeringConnectionId": "pcx-1", "Origin": "CreateRoute"}])


@install("aws.claude_a.vpc.peering_routes_least_privilege", "vpc_peering", "Routes over the peering connection do not cover whole VPC CIDRs or the default route",
    PEER, PEER, index=idx(route_table=[PEER_RTB]), fail_index=idx(route_table=[w(PEER_RTB, Routes=[{"DestinationCidrBlock": "10.1.0.0/16", "VpcPeeringConnectionId": "pcx-1", "Origin": "CreateRoute"}])]),
    rows=[C + "vpc_peering_connection_route_table_least_privilege"], severity="medium", category="network", control="AC-4",
    remediation="Route only the specific subnets that need to communicate over the peering connection.", docs=[VPC_DOC.replace("userguide/", "peering/") + "peering-configurations-partial-access.html"],
    dependencies=["vpc_peering", "route_table"],
    note="Steampipe: routes with this VpcPeeringConnectionId and DestinationCidrBlock 0.0.0.0/0, ::/0, or equal (as cidr) to the accepter/requester primary CIDR fail.")
def peering_least_privilege(item, index):
    pcx = get(item, "VpcPeeringConnectionId", str)
    acc, req = optional(get(item, "AccepterVpcInfo", dict), "CidrBlock", None, str), optional(get(item, "RequesterVpcInfo", dict), "CidrBlock", None, str)
    bad = []
    for table in items(index, "route_table"):
        for route in list_of_objects(get(table, "Routes", list)):
            dest = route.get("DestinationCidrBlock")
            if route.get("VpcPeeringConnectionId") != pcx or dest is None:
                continue
            if dest in ("0.0.0.0/0", "::/0") or _cidr_eq(dest, acc) or _cidr_eq(dest, req):
                bad.append(dest)
    return result(bool(bad), destinations=bad)


@install("aws.claude_a.vpc.peering_route_tables_least_privilege", "vpc_peering", "Peering route tables do not route 0.0.0.0/0 or the requester CIDR over peering",
    PEER, PEER, index=idx(route_table=[PEER_RTB]), fail_index=idx(route_table=[PEER_RTB_BAD]),
    rows=[P + "vpc_peering_routing_tables_with_least_privilege"], severity="medium", category="network", control="AC-4",
    remediation="Route only the specific subnets that need to communicate over the peering connection.", docs=[VPC_DOC.replace("userguide/", "peering/") + "peering-configurations-partial-access.html"],
    dependencies=["vpc_peering", "route_table"],
    note="Prowler: in route tables that reference this connection, peering routes (Origin != CreateRouteTable) to 0.0.0.0/0 or the requester CIDR fail. Prowler nulls the accepter CIDR, so it is not compared.")
def peering_least_privilege_prowler(item, index):
    pcx = get(item, "VpcPeeringConnectionId", str)
    req = optional(get(item, "RequesterVpcInfo", dict), "CidrBlock", None, str)
    bad = []
    for table in items(index, "route_table"):
        routes = list_of_objects(get(table, "Routes", list))
        if not any(r.get("VpcPeeringConnectionId") == pcx for r in routes):
            continue
        for route in routes:
            if get(route, "Origin", str) == "CreateRouteTable" or "DestinationCidrBlock" not in route or "VpcPeeringConnectionId" not in route:
                continue
            if route["DestinationCidrBlock"] == "0.0.0.0/0" or route["DestinationCidrBlock"] == req:
                bad.append(route["DestinationCidrBlock"])
    return result(bool(bad), destinations=bad)


# =========================================================================== VPN
VPN = {"VpnConnectionId": "vpn-1", "VgwTelemetry": [{"OutsideIpAddress": "198.51.100.1", "Status": "UP"}, {"OutsideIpAddress": "198.51.100.2", "Status": "UP"}],
       "Options": {"TunnelOptions": [{"LogOptions": {"CloudWatchLogOptions": {"LogEnabled": True}}}, {"LogOptions": {"CloudWatchLogOptions": {"LogEnabled": False}}}]}}


@install("aws.claude_a.vpc.vpn_both_tunnels_up", "vpn_connection", "Site-to-Site VPN connection has both tunnels UP",
    VPN, w(VPN, VgwTelemetry=[{"Status": "UP"}, {"Status": "DOWN"}]),
    rows=[C + "vpc_vpn_tunnel_up", C + "foundational_security_ec2_20", P + "vpc_vpn_connection_tunnels_up"], severity="medium",
    category="hardening", control="CP-8", remediation="Restore the DOWN tunnel (customer gateway configuration, BGP, IKE) so both tunnels are UP.",
    docs=[EC2_API + "API_VgwTelemetry.html"],
    note="A Site-to-Site VPN connection always has exactly two tunnels, so 'at least two UP' (Steampipe) and 'tunnel 1 and 2 UP' (Prowler) coincide; other telemetry shapes are UNKNOWN.")
def vpn_tunnels(item, index):
    telemetry = list_of_objects(get(item, "VgwTelemetry", list))
    if len(telemetry) != 2:
        raise Unavailable("unexpected VPN tunnel telemetry shape")
    statuses = [get(t, "Status", str) for t in telemetry]
    return result(statuses.count("UP") < 2, statuses=statuses)


@install("aws.claude_a.vpc.vpn_tunnel_logging", "vpn_connection", "Site-to-Site VPN connection has tunnel logging enabled",
    VPN, w(VPN, Options={"TunnelOptions": [{"LogOptions": {"CloudWatchLogOptions": {"LogEnabled": False}}}, {}]}),
    rows=[C + "vpc_vpn_connection_logging_enabled", C + "foundational_security_ec2_171"], severity="medium", category="hardening", control="AU-12",
    remediation="Enable CloudWatch Logs tunnel activity logging on the VPN tunnels (ModifyVpnTunnelOptions).",
    docs=[EC2_API + "API_CloudWatchLogOptions.html"], note="Steampipe passes when at least one tunnel has CloudWatch logging enabled.")
def vpn_logging(item, index):
    tunnels = list_of_objects(get(item, "Options.TunnelOptions", list))
    enabled = [((t.get("LogOptions") or {}).get("CloudWatchLogOptions") or {}).get("LogEnabled") is True for t in tunnels]
    return result(not any(enabled), tunnel_logging=enabled)


# =========================================================================== Network Firewall
NFW = {"FirewallArn": "arn:aws:network-firewall:us-east-1:%s:firewall/fw" % ACCOUNT, "FirewallName": "fw", "VpcId": "vpc-1",
       "DeleteProtection": True, "SubnetChangeProtection": True, "SubnetMappings": [{"SubnetId": "subnet-1"}, {"SubnetId": "subnet-2"}],
       "FirewallPolicyArn": "arn:aws:network-firewall:us-east-1:%s:firewall-policy/p" % ACCOUNT,
       "LoggingConfiguration": {"LogDestinationConfigs": [{"LogType": "FLOW", "LogDestinationType": "S3", "LogDestination": {"bucketName": "logs"}}]}}
POLICY = {"FirewallPolicyResponse": {"FirewallPolicyArn": NFW["FirewallPolicyArn"]},
          "FirewallPolicy": {"StatelessDefaultActions": ["aws:forward_to_sfe"], "StatelessFragmentDefaultActions": ["aws:drop"],
                             "StatefulRuleGroupReferences": [{"ResourceArn": "arn:rg"}], "StatelessRuleGroupReferences": []}}
RULE_GROUP = {"RuleGroupResponse": {"Type": "STATELESS", "RuleGroupArn": "arn:rg2"},
              "RuleGroup": {"RulesSource": {"StatelessRulesAndCustomActions": {"StatelessRules": [{"Priority": 1}]}}}}
NFW_DOCS = [NFW_API + "API_Firewall.html"]


@install("aws.claude_a.networkfirewall.deletion_protection", "network_firewall", "Network Firewall has deletion protection enabled",
    NFW, w(NFW, DeleteProtection=False), rows=[C + "networkfirewall_firewall_deletion_protection_enabled", C + "foundational_security_networkfirewall_9", P + "networkfirewall_deletion_protection"],
    severity="medium", category="hardening", control="CM-3", remediation="Enable DeleteProtection on the firewall (UpdateFirewallDeleteProtection).", docs=NFW_DOCS)
def nfw_delete(item, index):
    value = get(item, "DeleteProtection", bool)
    return result(not value, delete_protection=value)


@install("aws.claude_a.networkfirewall.subnet_change_protection", "network_firewall", "Network Firewall has subnet change protection enabled",
    NFW, w(NFW, SubnetChangeProtection=False), rows=[C + "networkfirewall_firewall_subnet_change_protection_enabled", C + "foundational_security_networkfirewall_10"],
    severity="medium", category="hardening", control="CM-3", remediation="Enable SubnetChangeProtection (UpdateSubnetChangeProtection).", docs=NFW_DOCS)
def nfw_subnet(item, index):
    value = get(item, "SubnetChangeProtection", bool)
    return result(not value, subnet_change_protection=value)


@install("aws.claude_a.networkfirewall.in_vpc", "network_firewall", "Network Firewall is deployed in a VPC",
    NFW, w(NFW, VpcId=""), rows=[C + "networkfirewall_firewall_in_vpc"], severity="low", category="network", control="SC-7",
    remediation="Deploy Network Firewall endpoints into the VPC subnets that need inspection.",
    docs=NFW_DOCS + [NFW_API + "API_CreateFirewall.html", NFW_API + "API_VpcEndpoint.html"],
    extra={"na": {"FirewallArn": NFW["FirewallArn"], "TransitGatewayId": "tgw-1", "AvailabilityZoneMappings": [{"AvailabilityZone": "us-east-1a"}]},
           "pass_proxy": {"FirewallArn": NFW["FirewallArn"], "NoSourcePreservation": True,
                          "VpcEndpoint": {"VpcId": "vpc-1", "SubnetMappings": [{"SubnetId": "subnet-1"}]}}},
    note="Pinned SQL alarms on null/empty top-level vpc_id. Current CreateFirewall/DescribeFirewall also support TransitGatewayId+AvailabilityZoneMappings (VPC-only criterion NOT_APPLICABLE) and NoSourcePreservation proxy mode with VpcEndpoint.VpcId/SubnetMappings (PASS). Missing, denied, malformed or conflicting placement facts are UNKNOWN; no valid documented deployment yields a definite placement FAIL, and placement does not prove traffic inspection.")
def nfw_in_vpc(item, index):
    if not get(item, "FirewallArn", str):
        raise Unavailable("missing Network Firewall identity")
    vpc = absent_or(item, "FirewallArn", "VpcId", None, str)
    tgw = absent_or(item, "FirewallArn", "TransitGatewayId", None, str)
    proxy = absent_or(item, "FirewallArn", "NoSourcePreservation", False, bool)
    endpoint = absent_or(item, "FirewallArn", "VpcEndpoint", None, dict)
    zones = absent_or(item, "FirewallArn", "AvailabilityZoneMappings", None, list)
    subnets = absent_or(item, "FirewallArn", "SubnetMappings", None, list)
    if vpc is not None and not re.fullmatch(r"vpc-[0-9a-f]+", vpc):
        raise Unavailable("malformed Network Firewall VpcId")
    if tgw is not None and not re.fullmatch(r"tgw-[0-9a-z]+", tgw):
        raise Unavailable("malformed Network Firewall TransitGatewayId")
    if proxy:
        if vpc is not None or subnets is not None or endpoint is None or (tgw is None and zones is not None):
            raise Unavailable("proxy firewall VPC endpoint is missing or conflicts with top-level VpcId")
        endpoint_vpc = get(endpoint, "VpcId", str)
        if not re.fullmatch(r"vpc-[0-9a-f]+", endpoint_vpc):
            raise Unavailable("malformed proxy firewall endpoint VpcId")
        _nfw_placement_mappings(get(endpoint, "SubnetMappings", list), "SubnetId")
        if tgw is not None:
            _nfw_placement_mappings(zones, "AvailabilityZone")
        return "PASS", {"placement": "proxy_vpc_endpoint", "vpc_id": endpoint_vpc,
                        "transit_gateway_id": tgw}
    if endpoint is not None:
        raise Unavailable("VpcEndpoint without proxy mode")
    if tgw is not None:
        if vpc is not None or subnets is not None:
            raise Unavailable("conflicting firewall VPC and transit gateway placement")
        _nfw_placement_mappings(zones, "AvailabilityZone")
        return "NOT_APPLICABLE", {"placement": "transit_gateway", "transit_gateway_id": tgw}
    if vpc is None:
        raise Unavailable("firewall placement association unavailable")
    if zones is not None:
        raise Unavailable("classic firewall has transit gateway zone mappings")
    _nfw_placement_mappings(subnets, "SubnetId")
    return "PASS", {"placement": "classic_vpc", "vpc_id": vpc}


# No valid documented firewall placement yields a definite FAIL. The old
# empty VpcId fixture is malformed placement evidence and must stay UNKNOWN.
CASES["aws.claude_a.networkfirewall.in_vpc"]["fail_expect"] = "UNKNOWN"


def _nfw_placement_mappings(value, field):
    mappings = list_of_objects(value)
    if not mappings:
        raise Unavailable("firewall placement mappings absent")
    for mapping in mappings:
        value = get(mapping, field, str)
        if field == "SubnetId" and not re.fullmatch(r"subnet-[0-9a-f]+", value):
            raise Unavailable("malformed firewall subnet mapping")
        if field == "AvailabilityZone" and not re.fullmatch(r"\S+", value):
            raise Unavailable("malformed firewall Availability Zone mapping")


@install("aws.claude_a.networkfirewall.logging", "network_firewall", "Network Firewall has a logging destination",
    NFW, w(NFW, LoggingConfiguration={"LogDestinationConfigs": []}),
    rows=[C + "networkfirewall_firewall_logging_enabled", C + "foundational_security_networkfirewall_2", P + "networkfirewall_logging_enabled"],
    severity="medium", category="hardening", control="AU-12", remediation="Configure flow and alert logging (UpdateLoggingConfiguration).",
    docs=[NFW_API + "API_DescribeLoggingConfiguration.html"],
    note="LoggingConfiguration from DescribeLoggingConfiguration; every LogDestinationConfig carries a LogType, so both sources reduce to 'at least one destination'.")
def nfw_logging(item, index):
    configs = list_of_objects(get(item, "LoggingConfiguration.LogDestinationConfigs", list))
    return result(not configs, destinations=len(configs))


@install("aws.claude_a.networkfirewall.multi_az", "network_firewall", "Network Firewall has endpoints in more than one subnet",
    NFW, w(NFW, SubnetMappings=[{"SubnetId": "subnet-1"}]), rows=[P + "networkfirewall_multi_az"], severity="medium",
    category="hardening", control="CP-10", remediation="Add subnet mappings in other Availability Zones (AssociateSubnets).", docs=NFW_DOCS)
def nfw_multi_az(item, index):
    count = len(list_of_objects(get(item, "SubnetMappings", list)))
    return result(count <= 1, subnet_mappings=count)


@install("aws.claude_a.networkfirewall.in_use_vpc_has_firewall", "vpc", "In-use VPC is protected by a Network Firewall",
    VPC, w(VPC, VpcId="vpc-2"), index=idx(network_firewall=[NFW], network_interface=[ENI, w(ENI, NetworkInterfaceId="eni-2", VpcId="vpc-2")]),
    rows=[P + "networkfirewall_in_all_vpc"], severity="medium", category="network", control="SC-7",
    remediation="Deploy AWS Network Firewall (or an approved equivalent) for VPCs with workloads.", docs=NFW_DOCS,
    dependencies=["vpc", "network_firewall", "network_interface"], extra={"na": (w(VPC, VpcId="vpc-9"), idx(network_firewall=[], network_interface=[ENI]))})
def nfw_all_vpc(item, index):
    vpc_id = get(item, "VpcId", str)
    if not vpc_in_use(index, vpc_id):
        return "NOT_APPLICABLE", {"reason": "VPC not in use"}
    return result(not any(f.get("VpcId") == vpc_id for f in items(index, "network_firewall")), vpc_id=vpc_id)


def _actions(policy, key):
    values = get(get(policy, "FirewallPolicy", dict), key, list)
    return [v for v in values if isinstance(v, str)]


for _cid, _key, _rows, _what in [
        ("policy_full_packets_default", "StatelessDefaultActions", [C + "networkfirewall_firewall_policy_default_stateless_action_check_full_packets", C + "foundational_security_networkfirewall_4"], "full packets"),
        ("policy_fragment_default", "StatelessFragmentDefaultActions", [C + "networkfirewall_firewall_policy_default_stateless_action_check_fragmented_packets", C + "foundational_security_networkfirewall_5"], "fragmented packets")]:
    def _policy_eval(item, index, _key=_key):
        actions = _actions(item, _key)
        return result("aws:drop" not in actions and "aws:forward_to_sfe" not in actions, actions=actions)
    install("aws.claude_a.networkfirewall." + _cid, "network_firewall_policy", "Firewall policy default stateless action for %s is drop or forward" % _what,
        POLICY, w(POLICY, **{"FirewallPolicy__" + _key: ["aws:pass"]}), rows=_rows, severity="medium", category="network", control="SC-7",
        remediation="Set the default stateless action for %s to aws:drop or aws:forward_to_sfe." % _what,
        docs=[NFW_API + "API_FirewallPolicy.html"])(_policy_eval)


def _firewall_policy(item, index):
    arn = get(item, "FirewallPolicyArn", str)
    rows = [p for p in items(index, "network_firewall_policy") if get(p, "FirewallPolicyResponse.FirewallPolicyArn", str) == arn]
    if len(rows) != 1:
        raise Unavailable("firewall policy join unresolved")
    return rows[0]


for _cid, _key, _row, _what in [
        ("firewall_full_packets_default", "StatelessDefaultActions", "networkfirewall_policy_default_action_full_packets", "full packets"),
        ("firewall_fragment_default", "StatelessFragmentDefaultActions", "networkfirewall_policy_default_action_fragmented_packets", "fragmented packets")]:
    def _fw_eval(item, index, _key=_key):
        actions = optional(get(_firewall_policy(item, index), "FirewallPolicy", dict), _key, [], list)
        return result("aws:drop" not in actions and "aws:forward_to_sfe" not in actions, actions=actions)
    install("aws.claude_a.networkfirewall." + _cid, "network_firewall", "Network Firewall's policy default stateless action for %s is drop or forward" % _what,
        NFW, NFW, index=idx(network_firewall_policy=[POLICY]), fail_index=idx(network_firewall_policy=[w(POLICY, **{"FirewallPolicy__" + _key: ["aws:pass"]})]),
        rows=[P + _row], severity="medium", category="network", control="SC-7",
        remediation="Set the firewall policy default stateless action for %s to aws:drop or aws:forward_to_sfe." % _what,
        docs=[NFW_API + "API_FirewallPolicy.html"], dependencies=["network_firewall", "network_firewall_policy"],
        note="Prowler evaluates each firewall through its associated policy.")(_fw_eval)


def _has_groups(policy):
    body = get(policy, "FirewallPolicy", dict)
    return bool(optional(body, "StatefulRuleGroupReferences", None) or optional(body, "StatelessRuleGroupReferences", None))


@install("aws.claude_a.networkfirewall.policy_has_rule_groups", "network_firewall_policy", "Firewall policy references at least one rule group",
    POLICY, w(POLICY, FirewallPolicy={"StatelessDefaultActions": ["aws:drop"], "StatelessFragmentDefaultActions": ["aws:drop"]}),
    rows=[C + "networkfirewall_firewall_policy_rule_group_not_empty", C + "foundational_security_networkfirewall_3"], severity="medium",
    category="network", control="SC-7", remediation="Associate stateful or stateless rule groups with the firewall policy.", docs=[NFW_API + "API_FirewallPolicy.html"])
def nfw_policy_groups(item, index):
    return result(not _has_groups(item))


@install("aws.claude_a.networkfirewall.firewall_policy_has_rule_groups", "network_firewall", "Network Firewall's policy references at least one rule group",
    NFW, NFW, index=idx(network_firewall_policy=[POLICY]),
    fail_index=idx(network_firewall_policy=[w(POLICY, FirewallPolicy={"StatelessDefaultActions": ["aws:drop"], "StatelessFragmentDefaultActions": ["aws:drop"]})]),
    rows=[P + "networkfirewall_policy_rule_group_associated"], severity="medium", category="network", control="SC-7",
    remediation="Associate stateful or stateless rule groups with the firewall's policy.", docs=[NFW_API + "API_FirewallPolicy.html"],
    dependencies=["network_firewall", "network_firewall_policy"])
def nfw_firewall_groups(item, index):
    return result(not _has_groups(_firewall_policy(item, index)))


@install("aws.claude_a.networkfirewall.stateless_rule_group_not_empty", "network_firewall_rule_group", "Stateless rule group contains rules",
    RULE_GROUP, w(RULE_GROUP, RuleGroup={"RulesSource": {"StatelessRulesAndCustomActions": {"StatelessRules": []}}}),
    rows=[C + "networkfirewall_stateless_rule_group_not_empty", C + "foundational_security_networkfirewall_6"], severity="medium",
    category="network", control="SC-7", remediation="Add rules to the stateless rule group or delete it.", docs=[NFW_API + "API_RuleGroup.html"],
    extra={"na": w(RULE_GROUP, RuleGroupResponse={"Type": "STATEFUL", "RuleGroupArn": "arn:rg"})})
def nfw_rule_group(item, index):
    kind = get(item, "RuleGroupResponse.Type", str)
    if kind == "STATEFUL":
        return "NOT_APPLICABLE", {"reason": "stateful rule group"}
    source = get(get(item, "RuleGroup", dict), "RulesSource", dict)
    rules = optional(optional(source, "StatelessRulesAndCustomActions", {}, dict), "StatelessRules", None)
    return result(not (isinstance(rules, list) and rules), rules=len(rules) if isinstance(rules, list) else 0)


def _ssh_world_v4_hits(item, index):
    """Keep a definite IPv4 SSH declaration despite malformed sibling ranges."""
    complete_items(index, "security_group")
    hits = []
    unresolved = False
    for permission in sg_ingress(item):
        try:
            proto = get(permission, "IpProtocol", str)
            low = optional(permission, "FromPort", None, int)
            high = optional(permission, "ToPort", None, int)
        except Unavailable:
            unresolved = True
            continue
        for field, cidr_key in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")):
            try:
                ranges = get(permission, field, list)
            except Unavailable:
                unresolved = True
                continue
            for value in ranges:
                try:
                    cidr = get(value, cidr_key, str)
                except Unavailable:
                    unresolved = True
                    continue
                if field != "IpRanges" or cidr != "0.0.0.0/0":
                    continue
                if proto == "-1":
                    hits.append(value)  # EC2 ignores serialized bounds for -1.
                elif proto in ("tcp", "6"):
                    if low is None or high is None or not (0 <= low <= high <= 65535):
                        unresolved = True
                    elif low <= 22 <= high:
                        hits.append(value)
    if unresolved and not hits:
        raise Unavailable("malformed SSH security-group permission")
    return hits
