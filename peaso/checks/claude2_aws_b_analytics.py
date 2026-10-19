"""claude2_aws_b analytics group: EFS, EMR, Elasticsearch (legacy ES API rows on OpenSearch domains), Firehose, RDS snapshots.

Elasticsearch rows evaluate the ``opensearch_domain`` inventory: the legacy ES configuration
API and the OpenSearch API describe the same domains (AWS::Elasticsearch::Domain is the legacy
name of AWS::OpenSearchService::Domain) and the DomainStatus members used here
(LogPublishingOptions, VPCOptions, DomainEndpointOptions, AdvancedSecurityOptions,
AccessPolicies) have the same names and values in both APIs. The Elasticsearch-only member
ElasticsearchClusterConfig is ClusterConfig in OpenSearch; the rows that read it are merged
into the existing natives that read ClusterConfig with the same thresholds.
"""
from __future__ import annotations

import ipaddress
import json

from .claude2_aws_b_common import (  # noqa: F401
    P, C, X, ABSENT, CONTEXT, Unavailable, install, flag, result, get, absent_or, complete_items, list_of_objects,
    detail, policy_document, is_policy_public, account, wildcard_allow_statements, turbot_public_statements,
    subnet_vpc, subnet_is_public_prowler, security_groups, inventory, indexes, strings)

# =========================================================================== documentation
D_EFS_FS = "https://docs.aws.amazon.com/efs/latest/ug/API_FileSystemDescription.html"
D_EFS_BACKUP = "https://docs.aws.amazon.com/efs/latest/ug/API_DescribeBackupPolicy.html"
D_EFS_POLICY = "https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystemPolicy.html"
D_EFS_IAM = "https://docs.aws.amazon.com/efs/latest/ug/iam-access-control-nfs-efs.html"
D_EFS_MT = "https://docs.aws.amazon.com/efs/latest/ug/API_MountTargetDescription.html"
D_EFS_AP = "https://docs.aws.amazon.com/efs/latest/ug/API_AccessPointDescription.html"
D_SUBNET = "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Subnet.html"
D_EMR_CLUSTER = "https://docs.aws.amazon.com/emr/latest/APIReference/API_Cluster.html"
D_EMR_KRB = "https://docs.aws.amazon.com/emr/latest/APIReference/API_KerberosAttributes.html"
D_EMR_SC = "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-create-security-configuration.html"
D_EMR_SC_API = "https://docs.aws.amazon.com/emr/latest/APIReference/API_DescribeSecurityConfiguration.html"
D_EMR_BPA = "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-block-public-access.html"
D_EMR_BPA_API = "https://docs.aws.amazon.com/emr/latest/APIReference/API_BlockPublicAccessConfiguration.html"
D_SH_EMR = "https://docs.aws.amazon.com/securityhub/latest/userguide/emr-controls.html"
D_SG = "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html"
D_OS = "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DomainStatus.html"
D_OS_LOGS = "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createdomain-configure-slow-logs.html"
D_OS_AUDIT = "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html"
D_OS_TLS = "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DomainEndpointOptions.html"
D_OS_VPC = "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html"
D_OS_FGAC = "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html"
D_OS_AC = "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html"
D_SH_ES = "https://docs.aws.amazon.com/securityhub/latest/userguide/es-controls.html"
D_FH = "https://docs.aws.amazon.com/firehose/latest/APIReference/API_DeliveryStreamDescription.html"
D_FH_ENC = "https://docs.aws.amazon.com/firehose/latest/APIReference/API_DeliveryStreamEncryptionConfiguration.html"
D_RDS_CSNAP = "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBClusterSnapshot.html"
D_RDS_SNAP = "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBSnapshot.html"

MERGED = {
    P + "efs_encryption_at_rest_enabled": (["aws.b.efs.at_rest_encryption"], "File system Encrypted true (DescribeFileSystems)."),
    C + "es_domain_cognito_authentication_enabled": (["aws.cb.opensearch.cognito_dashboards_auth"],
        "CognitoOptions.Enabled true; identical to the pinned opensearch_domain_cognito_authentication_enabled_for_kibana query on the same domains."),
    C + "es_domain_data_nodes_min_3": (["aws.cb.opensearch.data_node_fault_tolerance"],
        "Zone awareness enabled and at least three data nodes (ElasticsearchClusterConfig = OpenSearch ClusterConfig)."),
    C + "foundational_security_es_6": (["aws.cb.opensearch.data_node_fault_tolerance"],
        "Zone awareness enabled and at least three data nodes (ElasticsearchClusterConfig = OpenSearch ClusterConfig)."),
    C + "es_domain_dedicated_master_nodes_min_3": (["aws.cb.opensearch.dedicated_master_nodes"],
        "DedicatedMasterEnabled true and DedicatedMasterCount >= 3 (ElasticsearchClusterConfig = OpenSearch ClusterConfig)."),
    C + "foundational_security_es_7": (["aws.cb.opensearch.dedicated_master_nodes"],
        "DedicatedMasterEnabled true and DedicatedMasterCount >= 3 (ElasticsearchClusterConfig = OpenSearch ClusterConfig)."),
    C + "es_domain_encryption_at_rest_enabled": (["aws.cb.opensearch.encryption_at_rest"], "EncryptionAtRestOptions.Enabled true."),
    C + "foundational_security_es_1": (["aws.cb.opensearch.encryption_at_rest"], "EncryptionAtRestOptions.Enabled true."),
    C + "es_domain_node_to_node_encryption_enabled": (["aws.cb.opensearch.node_to_node_encryption_region_skip"],
        "NodeToNodeEncryptionOptions.Enabled true with the same af-south-1/eu-south-1/cn-north-1/cn-northwest-1 skip list."),
    C + "foundational_security_es_3": (["aws.cb.opensearch.node_to_node_encryption_region_skip"],
        "NodeToNodeEncryptionOptions.Enabled true with the same af-south-1/eu-south-1/cn-north-1/cn-northwest-1 skip list."),
}
MANUAL = {}
REJECTED = {}

# Kinds/fields this group reads that peaso/collectors does not collect yet (read-only APIs only).
COLLECTOR_FACTS = [
    {"kind": "efs_file_system (existing)", "api": "efs:DescribeBackupPolicy, efs:DescribeFileSystemPolicy",
     "fields": "BackupPolicy.BackupPolicy.Status; Policy.Policy. Record error PolicyNotFound as the absent marker (absent=('PolicyNotFound',)) instead of an unknown read",
     "checks": ["aws.c2b.efs.backup_not_disabled", "aws.c2b.efs.automatic_backups_enabled", "aws.c2b.efs.policy_not_open_to_vpc_clients",
                "aws.c2b.efs.policy_enforces_ssl", "aws.c2b.efs.policy_no_wildcard_allow", "aws.c2b.efs.policy_prohibit_public_access"]},
    {"kind": "efs_access_point", "api": "efs:DescribeAccessPoints (paginated, no filter = all access points in the region)",
     "fields": "AccessPointId, AccessPointArn, FileSystemId, RootDirectory.Path, PosixUser",
     "checks": ["aws.c2b.efs.access_point_root_directory", "aws.c2b.efs.access_point_user_identity",
                "aws.c2b.efs.access_points_no_root_directory", "aws.c2b.efs.access_points_posix_user"]},
    {"kind": "efs_mount_target", "api": "efs:DescribeMountTargets (per FileSystemId, paginated)",
     "fields": "MountTargetId, FileSystemId, SubnetId",
     "checks": ["aws.c2b.efs.mount_target_subnet_no_auto_public_ip", "aws.c2b.efs.no_public_mount_targets"]},
    {"kind": "emr_cluster", "api": "elasticmapreduce:ListClusters (paginated, all states) + elasticmapreduce:DescribeCluster (per Id, stored under 'Cluster')",
     "fields": "Id, ClusterArn, Status.State; Cluster.Cluster.{Id, SecurityConfiguration, KerberosAttributes (presence only, never KdcAdminPassword/CrossRealmTrustPrincipalPassword/ADDomainJoinPassword), MasterPublicDnsName, Ec2InstanceAttributes.{Ec2SubnetId, EmrManagedMasterSecurityGroup, EmrManagedSlaveSecurityGroup, AdditionalMasterSecurityGroups, AdditionalSlaveSecurityGroups}}",
     "checks": ["aws.c2b.emr.cluster_*", "aws.c2b.emr.master_*", "aws.c2b.emr.cluster_not_publicly_accessible"]},
    {"kind": "emr_security_configuration", "api": "elasticmapreduce:ListSecurityConfigurations + elasticmapreduce:DescribeSecurityConfiguration (per Name, stored under 'Configuration')",
     "fields": "Name; Configuration.SecurityConfiguration (JSON: EncryptionConfiguration.{EnableAtRestEncryption, EnableInTransitEncryption, AtRestEncryptionConfiguration.{S3EncryptionConfiguration.EncryptionMode, LocalDiskEncryptionConfiguration.EncryptionKeyProviderType}})",
     "checks": ["aws.c2b.emr.security_configuration_*", "aws.c2b.emr.cluster_*_encryption*"]},
    {"kind": "emr_block_public_access_configuration", "api": "elasticmapreduce:GetBlockPublicAccessConfiguration (one per region)",
     "fields": "BlockPublicAccessConfiguration.{BlockPublicSecurityGroupRules, PermittedPublicSecurityGroupRuleRanges[].{MinRange, MaxRange}}",
     "checks": ["aws.c2b.emr.block_public_access_enabled", "aws.c2b.emr.block_public_access_only_port_22"]},
    {"kind": "firehose_delivery_stream", "api": "firehose:ListDeliveryStreams + firehose:DescribeDeliveryStream (DeliveryStreamDescription flattened)",
     "fields": "DeliveryStreamARN, DeliveryStreamType, DeliveryStreamEncryptionConfiguration.Status",
     "checks": ["aws.c2b.firehose.encrypted_at_rest_or_msk_source"]},
]


# =========================================================================== EFS
FS_ID = "fs-1"
FS_ARN = "arn:aws:elasticfilesystem:us-east-1:111111111111:file-system/fs-1"
_FS = {"FileSystemId": FS_ID, "FileSystemArn": FS_ARN, "NumberOfMountTargets": 2, "Encrypted": True}


def _fs(backup="ENABLED", policy=None, **fields):
    out = {**_FS, **fields}
    out["BackupPolicy"] = ABSENT if backup is None else {"collection_status": "collected", "BackupPolicy": {"Status": backup}}
    out["Policy"] = ABSENT if policy is None else {"collection_status": "collected", "FileSystemId": FS_ID, "Policy": json.dumps(policy)}
    return out


def _backup_status(item):
    get(item, "FileSystemId", str)
    container = detail(item, "BackupPolicy")
    if container is None:
        return None
    status = get(container, "BackupPolicy.Status", str)
    if status not in ("ENABLED", "ENABLING", "DISABLED", "DISABLING"):
        raise Unavailable("unrecognized EFS automatic-backup status")
    return status


def efs_policy(item):
    """Parsed file system policy statements; None when DescribeFileSystemPolicy reported PolicyNotFound."""
    get(item, "FileSystemId", str)
    container = detail(item, "Policy")
    if container is None:
        return None
    return policy_document(get(container, "Policy", str))


@install("aws.c2b.efs.backup_not_disabled", "efs_file_system", "EFS file system backup policy is not disabled",
    _fs("ENABLED"), _fs("DISABLED"), rows=[P + "efs_have_backup_enabled"], severity="medium", control="CP-9",
    remediation="Enable automatic backups for the file system (PutBackupPolicy Status=ENABLED) or protect it with an AWS Backup plan.",
    docs=[D_EFS_BACKUP], extra={"no_policy": _fs(None), "no_policy_expect": "FAIL", "enabling": _fs("ENABLING"), "enabling_expect": "PASS"},
    note="Prowler: BackupPolicy.Status DISABLED or DISABLING fails; PolicyNotFound is treated as DISABLED; ENABLED/ENABLING pass.")
def efs_backup_prowler(item, index):
    status = _backup_status(item)
    status = "DISABLED" if status is None else status
    return result(status in ("DISABLED", "DISABLING"), backup_policy_status=status)


@install("aws.c2b.efs.automatic_backups_enabled", "efs_file_system", "EFS file system automatic backups are enabled",
    _fs("ENABLED"), _fs("DISABLED"), rows=[C + "efs_file_system_in_backup_plan", C + "foundational_security_efs_7"], severity="medium", control="CP-9",
    remediation="Enable automatic backups for the file system (PutBackupPolicy Status=ENABLED).", docs=[D_EFS_BACKUP],
    extra={"enabling": _fs("ENABLING"), "enabling_expect": "FAIL", "no_policy": _fs(None), "no_policy_expect": "FAIL"},
    note="Steampipe: automatic_backups = 'enabled' passes; any other status (including ENABLING) or no backup policy alarms. Distinct from the prowler DISABLED/DISABLING predicate.")
def efs_backup_turbot(item, index):
    status = _backup_status(item)
    return result(status != "ENABLED", backup_policy_status=status)


_VPC_ONLY = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "elasticfilesystem:ClientMount", "Resource": FS_ARN,
                            "Condition": {"Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"}}}]}
_OPEN = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "elasticfilesystem:ClientMount", "Resource": FS_ARN}]}
_SCOPED = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:role/app"}, "Action": "elasticfilesystem:ClientMount", "Resource": FS_ARN}]}
_SSL = {"Statement": [{"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "*", "Resource": FS_ARN, "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}


@install("aws.c2b.efs.policy_not_open_to_vpc_clients", "efs_file_system", "EFS public Allow statements require access through a mount target",
    _fs(policy=_SCOPED), _fs(policy=_OPEN), rows=[P + "efs_not_publicly_accessible"], severity="medium", category="exposure", control="AC-3",
    remediation="Attach a file system policy that grants access only to specific principals, or that requires elasticfilesystem:AccessedViaMountTarget.",
    docs=[D_EFS_POLICY, D_EFS_IAM], extra={"index": {"context": dict(CONTEXT)}, "no_policy": _fs(), "no_policy_expect": "FAIL",
                                          "mount_target_only": _fs(policy=_VPC_ONLY), "mount_target_only_expect": "PASS"},
    note="A missing policy leaves EFS default anonymous mount-target access. For an observed policy, inspect only public Allow statements for Bool elasticfilesystem:AccessedViaMountTarget=true; an unrelated Deny/nonpublic statement cannot make a constrained public Allow fail. The mount-target condition limits connection path, not approved principals, effective access or internet reachability.")
def efs_vpc_open(item, index):
    statements = efs_policy(item)
    if statements is None:
        return result(True, policy=None)
    public_allows = [statement for statement in statements if is_policy_public([statement], account(index))]

    def via_mount_target(statement):
        condition = statement.get("Condition", {})
        if not isinstance(condition, dict):
            raise Unavailable("malformed EFS policy condition")
        block = condition.get("Bool", {})
        if not isinstance(block, dict):
            raise Unavailable("malformed EFS Bool condition")
        key = "elasticfilesystem:AccessedViaMountTarget"
        if key not in block:
            if any(isinstance(value, dict) and key in value for operator, value in condition.items() if operator != "Bool"):
                raise Unavailable("unsupported EFS mount-target condition operator")
            return False
        value = block[key]
        if type(value) is bool:
            return value
        if type(value) is str:
            if value == "true":
                return True
            if value == "false":
                return False
        raise Unavailable("unrecognized EFS mount-target condition value")

    unconditioned = [statement for statement in public_allows if not via_mount_target(statement)]
    return result(bool(unconditioned), public_allow_statements=len(public_allows),
                  public_allow_without_mount_target_condition=len(unconditioned),
                  semantics="Declared resource policy only; no effective client reachability or approved-principal conclusion")


def _bool_false(values):
    for value in values if isinstance(values, list) else [values]:
        if value is False or (isinstance(value, str) and value.strip().lower() == "false"):
            return True
    return False


def _aws_principal_values(statement):
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        value = principal.get("AWS")
        return value if isinstance(value, list) else ([value] if value is not None else [])
    return []


@install("aws.c2b.efs.policy_enforces_ssl", "efs_file_system", "EFS file system policy denies requests without TLS",
    _fs(policy=_SSL), _fs(policy=_SCOPED), rows=[C + "efs_file_system_enforces_ssl"], severity="medium", control="SC-8",
    remediation="Add a Deny statement for Principal * when aws:SecureTransport is false to the file system policy.",
    docs=[D_EFS_POLICY, "https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html"],
    extra={"no_policy": _fs(), "no_policy_expect": "FAIL"},
    note="Steampipe: OK only when a Deny statement with Principal.AWS containing '*', at least one Action and Condition Bool aws:securetransport = false exists; no policy alarms.")
def efs_ssl(item, index):
    statements = efs_policy(item)
    if statements is None:
        return result(True, policy=None)
    for statement in statements:
        if statement.get("Effect") != "Deny" or "*" not in _aws_principal_values(statement):
            continue
        action = statement.get("Action")
        if not action:
            continue
        condition = statement.get("Condition", {}) or {}
        if not isinstance(condition, dict):
            raise Unavailable("malformed policy condition")
        block = condition.get("Bool", {}) or {}
        if not isinstance(block, dict):
            raise Unavailable("malformed policy condition block")
        if any(str(k).lower() == "aws:securetransport" and _bool_false(v) for k, v in block.items()):
            return result(False, enforces_ssl=True)
    return result(True, enforces_ssl=False)


@install("aws.c2b.efs.policy_no_wildcard_allow", "efs_file_system", "EFS file system policy has no Allow statement for a wildcard principal",
    _fs(policy=_SCOPED), _fs(policy=_VPC_ONLY), rows=[C + "efs_file_system_restrict_public_access"], severity="high", category="exposure", control="AC-3",
    remediation="Replace wildcard principals in the file system policy with specific accounts or roles.", docs=[D_EFS_POLICY],
    extra={"no_policy": _fs(), "no_policy_expect": "PASS"},
    note="Steampipe aws-compliance: any Allow statement with Principal '*' or AWS ['*'] alarms, conditions are not considered; no policy is ok.")
def efs_wildcard(item, index):
    statements = efs_policy(item)
    if statements is None:
        return result(False, policy=None)
    hits = wildcard_allow_statements(statements)
    return result(bool(hits), statements=len(hits))


@install("aws.c2b.efs.policy_prohibit_public_access", "efs_file_system", "EFS file system policy does not allow public access (perimeter)",
    _fs(policy=_SCOPED), _fs(policy=_OPEN), rows=[X + "efs_file_system_policy_prohibit_public_access"], severity="high", category="exposure", control="AC-3",
    remediation="Remove wildcard principals or add restricting conditions (aws:SourceAccount, aws:PrincipalOrgID, aws:PrincipalArn, ...) to the file system policy.",
    docs=[D_EFS_POLICY], extra={"not_applicable": _fs()},
    note="aws-perimeter resource_policy_public_sql; no policy is info (NOT_APPLICABLE).")
def efs_public_x(item, index):
    statements = efs_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    hits = turbot_public_statements(statements)
    return result(bool(hits), statements=len(hits))


@install("aws.c2b.efs.multi_az_mount_targets", "efs_file_system", "EFS file system is Regional (Multi-AZ) with more than one mount target",
    _fs(), _fs(AvailabilityZoneId="use1-az1", AvailabilityZoneName="us-east-1a", NumberOfMountTargets=1),
    rows=[P + "efs_multi_az_enabled"], severity="medium", control="CP-10",
    remediation="Use a Regional (Multi-AZ) file system with mount targets in at least two Availability Zones.", docs=[D_EFS_FS],
    extra={"one_target": _fs(NumberOfMountTargets=1), "one_target_expect": "FAIL"},
    note="Prowler: AvailabilityZoneId present = One Zone file system (FAIL); otherwise NumberOfMountTargets <= 1 fails.")
def efs_multi_az(item, index):
    zone = absent_or(item, "FileSystemId", "AvailabilityZoneId", None, str)
    if zone:
        return result(True, availability_zone_id=zone)
    count = get(item, "NumberOfMountTargets", int)
    return result(count <= 1, number_of_mount_targets=count)


def _mt(subnet="subnet-priv", mt="fsmt-1"):
    return {"MountTargetId": mt, "FileSystemId": FS_ID, "SubnetId": subnet}


_SUBNETS = [{"SubnetId": "subnet-priv", "VpcId": "vpc-1", "MapPublicIpOnLaunch": False}, {"SubnetId": "subnet-pub", "VpcId": "vpc-1", "MapPublicIpOnLaunch": True}]
_TABLES = [{"RouteTableId": "rtb-main", "VpcId": "vpc-1", "Associations": [{"Main": True}], "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}]},
           {"RouteTableId": "rtb-pub", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-pub"}], "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]}]


def _net(*mts):
    return indexes(inventory("efs_mount_target", list(mts)), inventory("subnet", _SUBNETS), inventory("route_table", _TABLES))


def _fs_rows(index, kind, fs_id):
    return [row for row in complete_items(index, kind) if get(row, "FileSystemId", str) == fs_id]


@install("aws.c2b.efs.no_public_mount_targets", "efs_file_system", "EFS file system has no mount targets in public subnets",
    _fs(), _fs(), rows=[P + "efs_mount_target_not_publicly_accessible"], severity="medium", category="network", control="SC-7",
    dependencies=["efs_file_system", "efs_mount_target", "subnet", "route_table"],
    remediation="Move mount targets to private subnets (no 0.0.0.0/0 route to an internet gateway).", docs=[D_EFS_MT, D_SUBNET],
    extra={"pass_index": _net(_mt()), "fail_index": _net(_mt(), _mt("subnet-pub", "fsmt-2"))},
    note="Prowler: a mount target whose subnet's effective route table (explicit, else VPC main) has 0.0.0.0/0 -> igw- is public. Unresolved subnets are UNKNOWN.")
def efs_public_mts(item, index):
    fs_id = get(item, "FileSystemId", str)
    public = [get(mt, "MountTargetId", str) for mt in _fs_rows(index, "efs_mount_target", fs_id) if subnet_is_public_prowler(index, get(mt, "SubnetId", str))]
    return result(bool(public), public_mount_targets=public)


@install("aws.c2b.efs.mount_target_subnet_no_auto_public_ip", "efs_mount_target", "EFS mount target subnet does not auto-assign public IPv4 addresses",
    _mt(), _mt("subnet-pub"), rows=[C + "efs_mount_target_not_publicly_accessible", C + "foundational_security_efs_6"], severity="medium",
    category="network", control="SC-7", dependencies=["efs_mount_target", "subnet"],
    remediation="Create mount targets in subnets with MapPublicIpOnLaunch disabled.", docs=[D_EFS_MT, D_SUBNET],
    extra={"pass_index": _net(), "fail_index": _net()},
    note="Steampipe: joins the mount target subnet; MapPublicIpOnLaunch true alarms. A subnet missing from the complete inventory is UNKNOWN.")
def efs_mt_subnet(item, index):
    subnet_id = get(item, "SubnetId", str)
    get(item, "MountTargetId", str)
    auto = get(subnet_vpc(index, subnet_id), "MapPublicIpOnLaunch", bool)
    return result(auto, subnet_id=subnet_id, map_public_ip_on_launch=auto)


def _ap(path="/data", posix=True, ap="fsap-1"):
    out = {"AccessPointId": ap, "AccessPointArn": "arn:aws:elasticfilesystem:us-east-1:111111111111:access-point/" + ap, "FileSystemId": FS_ID,
           "RootDirectory": {"Path": path}}
    if posix:
        out["PosixUser"] = {"Uid": 1000, "Gid": 1000}
    return out


@install("aws.c2b.efs.access_point_root_directory", "efs_access_point", "EFS access point enforces a non-root directory",
    _ap(), _ap("/"), rows=[C + "efs_access_point_enforce_root_directory", C + "foundational_security_efs_3"], severity="medium", control="AC-6",
    remediation="Recreate the access point with a RootDirectory.Path other than '/'.", docs=[D_EFS_AP],
    note="Steampipe: RootDirectory.Path = '/' alarms (per access point).")
def efs_ap_root(item, index):
    get(item, "AccessPointId", str)
    path = get(item, "RootDirectory.Path", str)
    return result(path == "/", root_directory=path)


@install("aws.c2b.efs.access_point_user_identity", "efs_access_point", "EFS access point enforces a POSIX user identity",
    _ap(), _ap(posix=False), rows=[C + "efs_access_point_enforce_user_identity", C + "foundational_security_efs_4"], severity="medium", control="AC-6",
    remediation="Recreate the access point with a PosixUser (Uid/Gid).", docs=[D_EFS_AP],
    note="Steampipe: posix_user null alarms. DescribeAccessPoints omits PosixUser when none is enforced; AccessPointId proves the record was read.")
def efs_ap_user(item, index):
    user = absent_or(item, "AccessPointId", "PosixUser", None, dict)
    return result(not user, posix_user=bool(user))


def _aps(*aps):
    return inventory("efs_access_point", list(aps))


@install("aws.c2b.efs.access_points_no_root_directory", "efs_file_system", "EFS file system has no access point exposing the root directory",
    _fs(), _fs(), rows=[P + "efs_access_point_enforce_root_directory"], severity="medium", control="AC-6",
    dependencies=["efs_file_system", "efs_access_point"], remediation="Recreate access points that use '/' with a dedicated root directory.", docs=[D_EFS_AP],
    extra={"pass_index": _aps(_ap()), "fail_index": _aps(_ap(), _ap("/", ap="fsap-2")), "not_applicable": _fs(), "not_applicable_index": _aps()},
    note="Prowler: evaluated per file system and only when it has access points; any access point with RootDirectory.Path '/' fails.")
def efs_aps_root(item, index):
    aps = _fs_rows(index, "efs_access_point", get(item, "FileSystemId", str))
    if not aps:
        return "NOT_APPLICABLE", {"access_points": 0}
    bad = [get(ap, "AccessPointId", str) for ap in aps if get(ap, "RootDirectory.Path", str) == "/"]
    return result(bool(bad), root_access_points=bad)


@install("aws.c2b.efs.access_points_posix_user", "efs_file_system", "EFS file system access points all define a POSIX user",
    _fs(), _fs(), rows=[P + "efs_access_point_enforce_user_identity"], severity="medium", control="AC-6",
    dependencies=["efs_file_system", "efs_access_point"], remediation="Recreate access points without a PosixUser with an enforced Uid/Gid.", docs=[D_EFS_AP],
    extra={"pass_index": _aps(_ap()), "fail_index": _aps(_ap(), _ap(posix=False, ap="fsap-2")), "not_applicable": _fs(), "not_applicable_index": _aps()},
    note="Prowler: evaluated per file system and only when it has access points; any access point without PosixUser fails.")
def efs_aps_user(item, index):
    aps = _fs_rows(index, "efs_access_point", get(item, "FileSystemId", str))
    if not aps:
        return "NOT_APPLICABLE", {"access_points": 0}
    bad = [get(ap, "AccessPointId", str) for ap in aps if not absent_or(ap, "AccessPointId", "PosixUser", None, dict)]
    return result(bool(bad), access_points_without_posix_user=bad)


# =========================================================================== EMR
EMR_ARN = "arn:aws:elasticmapreduce:us-east-1:111111111111:cluster/j-1"


def _cluster(state="RUNNING", **cluster):
    body = {"Id": "j-1", "Status": {"State": state},
            "Ec2InstanceAttributes": {"Ec2SubnetId": "subnet-priv", "EmrManagedMasterSecurityGroup": "sg-m", "EmrManagedSlaveSecurityGroup": "sg-s"}}
    body.update(cluster)
    return {"Id": "j-1", "Name": "c", "ClusterArn": EMR_ARN, "Status": {"State": state}, "Cluster": {"collection_status": "collected", "Cluster": body}}


def _sc(name="sc", **encryption):
    config = {"EncryptionConfiguration": encryption} if encryption else {}
    return {"Name": name, "Configuration": {"collection_status": "collected", "Name": name, "SecurityConfiguration": json.dumps(config)}}


def cluster_body(item):
    get(item, "Id", str)
    container = detail(item, "Cluster")
    if container is None:
        raise Unavailable("DescribeCluster returned not found")
    body = get(container, "Cluster", dict)
    get(body, "Id", str)
    return body


def cluster_state(item):
    return get(item, "Status.State", str)


def encryption_of(configuration):
    """EncryptionConfiguration of a DescribeSecurityConfiguration record (None when absent)."""
    get(configuration, "Name", str)
    container = detail(configuration, "Configuration")
    if container is None:
        raise Unavailable("security configuration not found")
    raw = get(container, "SecurityConfiguration", str)
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise Unavailable("malformed security configuration JSON") from exc
    if not isinstance(document, dict):
        raise Unavailable("malformed security configuration document")
    value = document.get("EncryptionConfiguration")
    if value is not None and not isinstance(value, dict):
        raise Unavailable("malformed EncryptionConfiguration")
    return value


def cluster_encryption(item, index):
    """(security configuration name or None, EncryptionConfiguration or None). Unresolved names are UNKNOWN."""
    name = absent_or(cluster_body(item), "Id", "SecurityConfiguration", None, str)
    if not name:
        return None, None
    rows = [row for row in complete_items(index, "emr_security_configuration") if get(row, "Name", str) == name]
    if len(rows) != 1:
        raise Unavailable("security configuration join unresolved: " + name)
    return name, encryption_of(rows[0])


def _path(document, *keys):
    value = document
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


_AT_REST_KMS = {"EnableAtRestEncryption": True, "EnableInTransitEncryption": True,
                "AtRestEncryptionConfiguration": {"S3EncryptionConfiguration": {"EncryptionMode": "SSE-KMS"},
                                                  "LocalDiskEncryptionConfiguration": {"EncryptionKeyProviderType": "Custom"}}}
_AT_REST_CSE = {"EnableAtRestEncryption": True, "AtRestEncryptionConfiguration": {"S3EncryptionConfiguration": {"EncryptionMode": "CSE-Custom"}}}
_NONE_ENC = {"EnableAtRestEncryption": False, "EnableInTransitEncryption": False}


def _scs(*configs):
    return inventory("emr_security_configuration", list(configs))


def emr_join(cid, title, rows, rule, *, good, bad, severity, remediation, note, docs=(D_EMR_SC, D_EMR_SC_API), control="SC-28"):
    """Cluster predicates over the joined security configuration (steampipe left join on the name)."""
    @install(cid, "emr_cluster", title, _cluster(SecurityConfiguration="sc"), _cluster(SecurityConfiguration="sc"), rows=rows, severity=severity,
        remediation=remediation, docs=list(docs), note=note, control=control, dependencies=["emr_cluster", "emr_security_configuration"],
        extra={"pass_index": _scs(_sc(**good)), "fail_index": _scs(_sc(**bad)),
               "no_config": _cluster(), "no_config_index": _scs(), "no_config_expect": "FAIL",
               "unlisted": _cluster(SecurityConfiguration="other"), "unlisted_index": _scs(_sc(**good)), "unlisted_expect": "UNKNOWN"})
    def evaluate(item, index):
        name, encryption = cluster_encryption(item, index)
        if name is None:
            return result(True, security_configuration=None)
        failed, evidence = rule(encryption or {})
        return result(failed, security_configuration=name, **evidence)
    evaluate.__name__ = cid.replace(".", "_")
    return evaluate


def _at_rest(enc):
    value = enc.get("EnableAtRestEncryption")
    return value is not True, {"enable_at_rest_encryption": value}


def _in_transit(enc):
    value = enc.get("EnableInTransitEncryption")
    return value is not True, {"enable_in_transit_encryption": value}


def _s3_mode(mode):
    def rule(enc):
        enabled = enc.get("EnableAtRestEncryption")
        configured = _path(enc, "AtRestEncryptionConfiguration", "S3EncryptionConfiguration", "EncryptionMode")
        if enabled is False:
            return True, {"enable_at_rest_encryption": False, "s3_encryption_mode": configured}
        return configured != mode, {"enable_at_rest_encryption": enabled, "s3_encryption_mode": configured}
    return rule


def _local_disk_cmk(enc):
    local = _path(enc, "AtRestEncryptionConfiguration", "LocalDiskEncryptionConfiguration")
    if local is None:
        return True, {"local_disk_encryption": None}
    provider = local.get("EncryptionKeyProviderType") if isinstance(local, dict) else None
    return provider != "Custom", {"key_provider_type": provider}


def _local_disk_enabled(enc):
    enabled = enc.get("EnableAtRestEncryption")
    local = _path(enc, "AtRestEncryptionConfiguration", "LocalDiskEncryptionConfiguration")
    return not (enabled is True and local is not None), {"enable_at_rest_encryption": enabled, "local_disk_encryption": local is not None}


emr_join("aws.c2b.emr.cluster_at_rest_encryption", "EMR cluster security configuration enables encryption at rest",
    [C + "emr_cluster_encryption_at_rest_enabled"], _at_rest, good=_AT_REST_KMS, bad=_NONE_ENC, severity="medium",
    remediation="Launch the cluster with a security configuration that enables at-rest encryption.",
    note="Steampipe: no security configuration alarms; EncryptionConfiguration.EnableAtRestEncryption true passes.")
emr_join("aws.c2b.emr.cluster_at_rest_cse_custom", "EMR cluster S3 at-rest encryption uses client-side encryption with a custom key (CSE-Custom)",
    [C + "emr_cluster_encryption_at_rest_with_cse_cmk"], _s3_mode("CSE-Custom"), good=_AT_REST_CSE, bad=_AT_REST_KMS, severity="medium",
    remediation="Use a security configuration with S3EncryptionConfiguration EncryptionMode CSE-Custom.",
    note="Steampipe: no security configuration or EnableAtRestEncryption false alarms; S3 EncryptionMode = 'CSE-Custom' passes.")
emr_join("aws.c2b.emr.cluster_at_rest_sse_kms", "EMR cluster S3 at-rest encryption uses SSE-KMS",
    [C + "emr_cluster_encryption_at_rest_with_sse_kms"], _s3_mode("SSE-KMS"), good=_AT_REST_KMS, bad=_AT_REST_CSE, severity="medium",
    remediation="Use a security configuration with S3EncryptionConfiguration EncryptionMode SSE-KMS.",
    note="Steampipe: no security configuration or EnableAtRestEncryption false alarms; S3 EncryptionMode = 'SSE-KMS' passes.")
emr_join("aws.c2b.emr.cluster_in_transit_encryption", "EMR cluster security configuration enables encryption in transit",
    [C + "emr_cluster_encryption_in_transit_enabled"], _in_transit, good=_AT_REST_KMS, bad=_NONE_ENC, severity="medium", control="SC-8",
    remediation="Launch the cluster with a security configuration that enables in-transit encryption.",
    note="Steampipe: no security configuration alarms; EnableInTransitEncryption true passes.")
emr_join("aws.c2b.emr.cluster_local_disk_cmk", "EMR cluster local disks are encrypted with a custom key provider",
    [C + "emr_cluster_local_disk_encrypted_with_cmk"], _local_disk_cmk, good=_AT_REST_KMS, bad=_AT_REST_CSE, severity="medium",
    remediation="This check requires a reviewed Custom local-disk key provider. AwsKms with EBS encryption is a valid separate design; seek an owner-reviewed policy exception instead of switching providers solely to clear this finding.",
    note="Steampipe: no security configuration or no LocalDiskEncryptionConfiguration alarms; EncryptionKeyProviderType = 'Custom' passes (AwsKms alarms, as upstream).")
emr_join("aws.c2b.emr.cluster_local_disk_encryption", "EMR cluster local disk encryption is enabled",
    [C + "emr_cluster_local_disk_encryption_enabled"], _local_disk_enabled, good=_AT_REST_KMS, bad=_AT_REST_CSE, severity="medium",
    remediation="Enable at-rest encryption with a LocalDiskEncryptionConfiguration in the cluster security configuration.",
    note="Steampipe: passes only with EnableAtRestEncryption true and a LocalDiskEncryptionConfiguration present.")




@install("aws.c2b.emr.cluster_kerberos_enabled", "emr_cluster", "EMR cluster uses Kerberos authentication",
    _cluster(KerberosAttributes={"Realm": "EC2.INTERNAL"}), _cluster(), rows=[C + "emr_cluster_kerberos_enabled"], severity="medium", control="IA-2",
    remediation="Launch the cluster with a security configuration that enables Kerberos authentication.", docs=[D_EMR_KRB, D_EMR_CLUSTER],
    note="Steampipe: kerberos_attributes null alarms. DescribeCluster omits KerberosAttributes when Kerberos is not configured; Cluster.Id proves the detail was read.")
def emr_kerberos(item, index):
    value = absent_or(cluster_body(item), "Id", "KerberosAttributes", None, dict)
    return result(value is None, kerberos=value is not None)


@install("aws.c2b.emr.cluster_security_configuration", "emr_cluster", "EMR cluster has a security configuration",
    _cluster(SecurityConfiguration="sc"), _cluster(), rows=[C + "emr_cluster_security_configuration_enabled"], severity="medium", control="CM-6",
    remediation="Launch the cluster with an EMR security configuration.", docs=[D_EMR_CLUSTER, D_EMR_SC],
    note="Steampipe: security_configuration null alarms. DescribeCluster omits SecurityConfiguration when none is attached.")
def emr_secconf(item, index):
    value = absent_or(cluster_body(item), "Id", "SecurityConfiguration", None, str)
    return result(not value, security_configuration=value)


def sc_check(cid, title, rows, rule, good, bad, remediation, note, control):
    @install(cid, "emr_security_configuration", title, _sc(**good), _sc(**bad), rows=rows, severity="medium", control=control,
        remediation=remediation, docs=[D_EMR_SC, D_EMR_SC_API, D_SH_EMR], note=note, extra={"no_config": _sc(), "no_config_expect": "FAIL"})
    def evaluate(item, index):
        failed, evidence = rule(encryption_of(item) or {})
        return result(failed, **evidence)
    evaluate.__name__ = cid.replace(".", "_")
    return evaluate


sc_check("aws.c2b.emr.security_configuration_at_rest", "EMR security configuration enables encryption at rest",
    [C + "emr_security_configuration_encryption_at_rest_enabled", C + "foundational_security_emr_3"], _at_rest, _AT_REST_KMS, _NONE_ENC,
    "Enable at-rest encryption in the security configuration (create a new configuration; they are immutable).",
    "Steampipe / Security Hub EMR.3: EncryptionConfiguration.EnableAtRestEncryption true passes.", "SC-28")
sc_check("aws.c2b.emr.security_configuration_in_transit", "EMR security configuration enables encryption in transit",
    [C + "emr_security_configuration_encryption_in_transit_enabled", C + "foundational_security_emr_4"], _in_transit, _AT_REST_KMS, _NONE_ENC,
    "Enable in-transit encryption in the security configuration (create a new configuration; they are immutable).",
    "Steampipe / Security Hub EMR.4: EncryptionConfiguration.EnableInTransitEncryption true passes.", "SC-8")


_EMR_NET = indexes(inventory("subnet", _SUBNETS))


@install("aws.c2b.emr.master_subnet_no_auto_public_ip", "emr_cluster", "Running EMR cluster primary node subnet does not auto-assign public IPs",
    _cluster(), _cluster(Ec2InstanceAttributes={"Ec2SubnetId": "subnet-pub"}),
    rows=[C + "emr_cluster_master_nodes_no_public_ip", C + "foundational_security_emr_1", X + "emr_cluster_master_nodes_no_public_ip"],
    severity="high", category="network", control="SC-7", dependencies=["emr_cluster", "subnet"],
    remediation="Launch clusters in private subnets with MapPublicIpOnLaunch disabled.", docs=[D_SH_EMR, D_SUBNET, D_EMR_CLUSTER],
    extra={"pass_index": _EMR_NET, "fail_index": _EMR_NET, "not_applicable": _cluster("TERMINATED"), "not_applicable_index": _EMR_NET},
    note="Steampipe: clusters not RUNNING/WAITING are skipped; the Ec2SubnetId subnet with MapPublicIpOnLaunch true alarms. A missing subnet id or a subnet absent from the complete inventory is UNKNOWN (upstream left join would report ok).")
def emr_master_subnet(item, index):
    state = cluster_state(item)
    if state not in ("RUNNING", "WAITING"):
        return "NOT_APPLICABLE", {"state": state}
    subnet_id = get(cluster_body(item), "Ec2InstanceAttributes.Ec2SubnetId", str)
    auto = get(subnet_vpc(index, subnet_id), "MapPublicIpOnLaunch", bool)
    return result(auto, subnet_id=subnet_id, map_public_ip_on_launch=auto)


_TERMINATED = ("TERMINATED", "TERMINATED_WITH_ERRORS")
_PUBLIC_DNS = "ec2-54-1-2-3.compute-1.amazonaws.com"
_PRIVATE_DNS = "ip-10-0-0-1.ec2.internal"


def emr_public(item):
    dns = absent_or(cluster_body(item), "Id", "MasterPublicDnsName", None, str)
    return bool(dns and ".amazonaws.com" in dns), dns


@install("aws.c2b.emr.master_no_public_dns", "emr_cluster", "EMR cluster primary node has no public DNS name",
    _cluster(MasterPublicDnsName=_PRIVATE_DNS), _cluster(MasterPublicDnsName=_PUBLIC_DNS), rows=[P + "emr_cluster_master_nodes_no_public_ip"],
    severity="medium", category="network", control="SC-7", remediation="Launch the cluster in a private subnet without public IP addressing.",
    docs=[D_EMR_CLUSTER, D_SH_EMR], extra={"not_applicable": _cluster("TERMINATED", MasterPublicDnsName=_PUBLIC_DNS)},
    note="Prowler: clusters not TERMINATED/TERMINATED_WITH_ERRORS whose MasterPublicDnsName contains '.amazonaws.com' fail (private names end in .compute.internal / .ec2.internal).")
def emr_master_dns(item, index):
    state = cluster_state(item)
    if state in _TERMINATED:
        return "NOT_APPLICABLE", {"state": state}
    public, dns = emr_public(item)
    return result(public, master_public_dns_name=dns)


def _cidr_public(cidr):
    """Prowler _is_cidr_public(any_address=False): 0.0.0.0/0, ::/0 or any global network."""
    if cidr in ("0.0.0.0/0", "::/0"):
        return True
    if not isinstance(cidr, str):
        raise Unavailable("malformed security group CIDR")
    try:
        return ipaddress.ip_network(cidr).is_global
    except ValueError as exc:
        raise Unavailable("malformed security group CIDR") from exc


def prowler_rule_public_any(rule):
    """Prowler check_security_group(rule, '-1') with no ports and any_address False."""
    v4 = [r.get("CidrIp") for r in list_of_objects(get(rule, "IpRanges", list))]
    v6 = [r.get("CidrIpv6") for r in list_of_objects(get(rule, "Ipv6Ranges", list))]
    if str(rule.get("IpProtocol")) == "-1" and any(_cidr_public(c) for c in v4 + v6):
        return True
    if "FromPort" in rule:
        low, high = rule.get("FromPort"), rule.get("ToPort")
        if not isinstance(low, int) or not isinstance(high, int):
            raise Unavailable("malformed security group port range")
        size = 1 if low == high else high - low + 1
        for cidr in v4 + v6:
            if _cidr_public(cidr):
                return size == 65536
    return False


def _node_groups(attributes, managed, additional):
    groups = []
    extra = attributes.get(additional)
    if extra is not None:
        groups.extend(strings(extra, additional))
    if attributes.get(managed):
        groups.append(attributes[managed])
    return [g for g in dict.fromkeys(groups) if g]


def _sg(gid, cidr):
    return {"GroupId": gid, "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": []}]}


@install("aws.c2b.emr.cluster_not_publicly_accessible", "emr_cluster", "Public EMR cluster has no security group open to the internet",
    _cluster(MasterPublicDnsName=_PUBLIC_DNS), _cluster(MasterPublicDnsName=_PUBLIC_DNS), rows=[P + "emr_cluster_publicly_accesible"],
    severity="medium", category="exposure", control="SC-7", dependencies=["emr_cluster", "security_group"],
    remediation="Remove all-traffic ingress rules from public CIDRs on the primary and core/task security groups, or move the cluster to a private subnet.",
    docs=[D_EMR_CLUSTER, D_SG, D_EMR_BPA],
    extra={"pass_index": inventory("security_group", [_sg("sg-m", "10.0.0.0/8"), _sg("sg-s", "10.0.0.0/8")]),
           "fail_index": inventory("security_group", [_sg("sg-m", "0.0.0.0/0"), _sg("sg-s", "10.0.0.0/8")]),
           "private_pass": _cluster(MasterPublicDnsName=_PRIVATE_DNS), "private_pass_index": {"context": dict(CONTEXT)},
           "not_applicable": _cluster("TERMINATED", MasterPublicDnsName=_PUBLIC_DNS)},
    note="Prowler: only public clusters (MasterPublicDnsName contains .amazonaws.com) are inspected; a primary or core/task security group (managed plus additional) with an ingress rule that allows all traffic from a public CIDR (any global network), or a full 0-65535 port range from one, fails.")
def emr_public_sgs(item, index):
    state = cluster_state(item)
    if state in _TERMINATED:
        return "NOT_APPLICABLE", {"state": state}
    public, dns = emr_public(item)
    if not public:
        return result(False, public=False)
    attributes = get(cluster_body(item), "Ec2InstanceAttributes", dict)
    out = {}
    for label, managed, additional in (("master", "EmrManagedMasterSecurityGroup", "AdditionalMasterSecurityGroups"),
                                       ("slave", "EmrManagedSlaveSecurityGroup", "AdditionalSlaveSecurityGroups")):
        ids = _node_groups(attributes, managed, additional)
        groups = security_groups(index, ids) if ids else []
        out[label] = [get(g, "GroupId", str) for g in groups
                      if any(prowler_rule_public_any(rule) for rule in list_of_objects(get(g, "IpPermissions", list)))]
    return result(bool(out["master"] or out["slave"]), public_master_groups=out["master"], public_slave_groups=out["slave"])


def _bpa(enabled=True, ranges=({"MinRange": 22, "MaxRange": 22},)):
    body = {"BlockPublicSecurityGroupRules": enabled}
    if ranges is not None:
        body["PermittedPublicSecurityGroupRuleRanges"] = list(ranges)
    return {"BlockPublicAccessConfiguration": body, "BlockPublicAccessConfigurationMetadata": {"CreationDateTime": "2026-01-01T00:00:00+00:00"}}


@install("aws.c2b.emr.block_public_access_enabled", "emr_block_public_access_configuration", "EMR block public access is enabled in the region",
    _bpa(), _bpa(False), rows=[P + "emr_cluster_account_public_block_enabled"], severity="high", category="exposure", control="SC-7",
    remediation="Enable EMR block public access (PutBlockPublicAccessConfiguration BlockPublicSecurityGroupRules=true).", docs=[D_EMR_BPA, D_EMR_BPA_API],
    note="Prowler: BlockPublicSecurityGroupRules true passes, port exceptions are not evaluated.")
def emr_bpa(item, index):
    value = get(item, "BlockPublicAccessConfiguration.BlockPublicSecurityGroupRules", bool)
    return result(not value, block_public_security_group_rules=value)


@install("aws.c2b.emr.block_public_access_only_port_22", "emr_block_public_access_configuration", "EMR block public access is enabled with no port exception other than 22",
    _bpa(), _bpa(ranges=({"MinRange": 22, "MaxRange": 22}, {"MinRange": 100, "MaxRange": 101})),
    rows=[C + "emr_account_public_access_blocked", C + "foundational_security_emr_2"], severity="critical", category="exposure", control="SC-7",
    remediation="Enable EMR block public access and remove every permitted port range other than 22.", docs=[D_SH_EMR, D_EMR_BPA, D_EMR_BPA_API],
    extra={"disabled": _bpa(False), "disabled_expect": "FAIL", "no_ranges": _bpa(ranges=()), "no_ranges_expect": "PASS"},
    note="Corrected to Security Hub EMR.2 ('fails if the block public access setting isn't enabled or if any port other than port 22 is allowed'). The pinned steampipe query passes only when an exact 22-22 range exists, so it alarms on the stricter no-exception configuration and passes 22 plus extra ranges; both deviations from EMR.2 are not reproduced.")
def emr_bpa_22(item, index):
    enabled = get(item, "BlockPublicAccessConfiguration.BlockPublicSecurityGroupRules", bool)
    if not enabled:
        return result(True, block_public_security_group_rules=False)
    ranges = list_of_objects(absent_or(item, "BlockPublicAccessConfiguration.BlockPublicSecurityGroupRules",
                                       "BlockPublicAccessConfiguration.PermittedPublicSecurityGroupRuleRanges", [], list))
    other = [r for r in ranges if not (r.get("MinRange") == 22 and r.get("MaxRange") == 22)]
    return result(bool(other), other_permitted_ranges=other)


# =========================================================================== Elasticsearch (opensearch_domain inventory)
def _os(status):
    return {"DomainName": "d", "Domain": {"collection_status": "collected", "DomainStatus": {"ARN": "arn:aws:es:us-east-1:111111111111:domain/d", **status}}}


def domain_status(item):
    get(item, "Domain.DomainStatus.ARN", str)
    return get(item, "Domain.DomainStatus", dict)


def _log_to_cloudwatch(status, kind):
    options = absent_or(status, "ARN", "LogPublishingOptions", None, dict) or {}
    entry = options.get(kind)
    return isinstance(entry, dict) and entry.get("Enabled") is True and entry.get("CloudWatchLogsLogGroupArn") is not None


def _logs(*kinds, group=True):
    return {"LogPublishingOptions": {k: {"Enabled": True, **({"CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:111111111111:log-group:l"} if group else {})} for k in kinds}}


@install("aws.c2b.es.audit_logs_to_cloudwatch", "opensearch_domain", "Elasticsearch domain publishes audit logs to a CloudWatch log group",
    _os(_logs("AUDIT_LOGS")), _os(_logs("AUDIT_LOGS", group=False)), rows=[C + "es_domain_audit_logging_enabled", C + "foundational_security_es_5"],
    severity="medium", control="AU-2", remediation="Enable AUDIT_LOGS publishing to a CloudWatch Logs log group (requires fine-grained access control).",
    docs=[D_SH_ES, D_OS_AUDIT, D_OS], extra={"no_config": _os({}), "no_config_expect": "FAIL"},
    note="Steampipe: AUDIT_LOGS.Enabled true and CloudWatchLogsLogGroupArn not null; distinct from aws.cb.opensearch.audit_logs_enabled (Enabled only).")
def es_audit(item, index):
    ok = _log_to_cloudwatch(domain_status(item), "AUDIT_LOGS")
    return result(not ok, audit_logs_to_cloudwatch=ok)


@install("aws.c2b.es.error_logs_to_cloudwatch", "opensearch_domain", "Elasticsearch domain publishes error logs to a CloudWatch log group",
    _os(_logs("ES_APPLICATION_LOGS")), _os(_logs("SEARCH_SLOW_LOGS")), rows=[C + "es_domain_error_logging_enabled", C + "foundational_security_es_4"],
    severity="medium", control="AU-2", remediation="Enable ES_APPLICATION_LOGS publishing to a CloudWatch Logs log group.", docs=[D_SH_ES, D_OS_LOGS, D_OS],
    extra={"no_config": _os({}), "no_config_expect": "FAIL"},
    note="Steampipe: ES_APPLICATION_LOGS.Enabled true and CloudWatchLogsLogGroupArn not null.")
def es_error_logs(item, index):
    ok = _log_to_cloudwatch(domain_status(item), "ES_APPLICATION_LOGS")
    return result(not ok, error_logs_to_cloudwatch=ok)


@install("aws.c2b.es.all_logs_to_cloudwatch", "opensearch_domain", "Elasticsearch domain publishes error, search slow and index slow logs to CloudWatch",
    _os(_logs("ES_APPLICATION_LOGS", "SEARCH_SLOW_LOGS", "INDEX_SLOW_LOGS")), _os(_logs("ES_APPLICATION_LOGS", "SEARCH_SLOW_LOGS")),
    rows=[C + "es_domain_logs_to_cloudwatch"], severity="low", control="AU-2",
    remediation="Enable ES_APPLICATION_LOGS, SEARCH_SLOW_LOGS and INDEX_SLOW_LOGS publishing to CloudWatch Logs log groups.", docs=[D_OS_LOGS, D_OS],
    note="Steampipe: each of ES_APPLICATION_LOGS, SEARCH_SLOW_LOGS and INDEX_SLOW_LOGS must be Enabled with a CloudWatchLogsLogGroupArn.")
def es_all_logs(item, index):
    status = domain_status(item)
    missing = [k for k in ("ES_APPLICATION_LOGS", "SEARCH_SLOW_LOGS", "INDEX_SLOW_LOGS") if not _log_to_cloudwatch(status, k)]
    return result(bool(missing), missing_log_types=missing)


_TLS12 = ("Policy-Min-TLS-1-2-2019-07", "Policy-Min-TLS-1-2-PFS-2023-10")


@install("aws.c2b.es.tls_1_2_policy", "opensearch_domain", "Elasticsearch domain endpoint requires TLS 1.2",
    _os({"DomainEndpointOptions": {"EnforceHTTPS": True, "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"}}),
    _os({"DomainEndpointOptions": {"EnforceHTTPS": True, "TLSSecurityPolicy": "Policy-Min-TLS-1-0-2019-07"}}),
    rows=[C + "es_domain_encrypted_using_tls_1_2", C + "foundational_security_es_8"], severity="medium", control="SC-8",
    remediation="Set DomainEndpointOptions.TLSSecurityPolicy to Policy-Min-TLS-1-2-PFS-2023-10 (or Policy-Min-TLS-1-2-2019-07).", docs=[D_SH_ES, D_OS_TLS],
    extra={"pfs_pass": _os({"DomainEndpointOptions": {"EnforceHTTPS": True, "TLSSecurityPolicy": "Policy-Min-TLS-1-2-PFS-2023-10"}})},
    note="Pinned steampipe compares with the single literal Policy-Min-TLS-1-2-2019-07, which alarms on the newer Policy-Min-TLS-1-2-PFS-2023-10 that Security Hub ES.8 names as the latest policy. Both TLS 1.2 minimum policies pass here; TLS 1.0 policies fail.")
def es_tls(item, index):
    policy = get(domain_status(item), "DomainEndpointOptions.TLSSecurityPolicy", str)
    return result(policy not in _TLS12, tls_security_policy=policy)


@install("aws.c2b.es.in_vpc", "opensearch_domain", "Elasticsearch domain is deployed in a VPC",
    _os({"VPCOptions": {"VPCId": "vpc-1", "SubnetIds": ["subnet-1"]}}), _os({}),
    rows=[C + "es_domain_in_vpc", C + "foundational_security_es_2", X + "es_domain_in_vpc"], severity="high", category="network", control="SC-7",
    remediation="Create the domain inside a VPC and migrate the data (a public domain cannot be moved into a VPC).", docs=[D_SH_ES, D_OS_VPC],
    note="Steampipe / Security Hub ES.2: VPCOptions.VPCId null alarms; subnet routing is not evaluated (unlike aws.cb.opensearch.in_vpc_private_subnets).")
def es_vpc(item, index):
    status = domain_status(item)
    options = absent_or(status, "ARN", "VPCOptions", None, dict)
    vpc = options.get("VPCId") if isinstance(options, dict) else None
    return result(not vpc, vpc_id=vpc)


@install("aws.c2b.es.internal_user_database_enabled", "opensearch_domain", "Elasticsearch domain has the internal user database enabled",
    _os({"AdvancedSecurityOptions": {"Enabled": True, "InternalUserDatabaseEnabled": True}}), _os({"AdvancedSecurityOptions": {"Enabled": True, "InternalUserDatabaseEnabled": False}}),
    rows=[C + "es_domain_internal_user_database_enabled"], severity="low", control="IA-2",
    remediation="Enable fine-grained access control with the internal user database if the source policy requires it.", docs=[D_OS_FGAC, D_OS],
    note="Steampipe: AdvancedSecurityOptions.InternalUserDatabaseEnabled = true passes (the opposite question of aws.cb.opensearch.internal_user_database_disabled); omitted AdvancedSecurityOptions is not enabled.")
def es_iudb(item, index):
    status = domain_status(item)
    value = absent_or(status, "ARN", "AdvancedSecurityOptions.InternalUserDatabaseEnabled", False, bool)
    return result(value is not True, internal_user_database=value)


_OS_PUB = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "es:*", "Resource": "arn:aws:es:us-east-1:111111111111:domain/d/*"}]})
_OS_PRIV = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"}, "Action": "es:*", "Resource": "*"}]})


@install("aws.c2b.es.policy_prohibit_public_access", "opensearch_domain", "Elasticsearch domain access policy does not allow public access (perimeter)",
    _os({"AccessPolicies": _OS_PRIV}), _os({"AccessPolicies": _OS_PUB}), rows=[X + "elasticsearch_domain_policy_prohibit_public_access"],
    severity="high", category="exposure", control="AC-3",
    remediation="Remove wildcard principals or add restricting conditions (aws:SourceAccount, aws:PrincipalOrgID, aws:PrincipalArn, ...) to the domain access policy.",
    docs=[D_OS_AC, D_OS], extra={"not_applicable": _os({"AccessPolicies": ""})},
    note="aws-perimeter resource_policy_public_sql inlined for aws_elasticsearch_domain; no access policy is info (NOT_APPLICABLE).")
def es_public_x(item, index):
    raw = absent_or(domain_status(item), "ARN", "AccessPolicies", None, str)
    if not raw:
        return "NOT_APPLICABLE", {"policy": None}
    hits = turbot_public_statements(policy_document(raw))
    return result(bool(hits), statements=len(hits))


# =========================================================================== Firehose
def _stream(status="ENABLED", kind="DirectPut"):
    out = {"DeliveryStreamARN": "arn:aws:firehose:us-east-1:111111111111:deliverystream/s", "DeliveryStreamName": "s", "DeliveryStreamType": kind}
    if status is not None:
        out["DeliveryStreamEncryptionConfiguration"] = {"Status": status}
    return out


@install("aws.c2b.firehose.encrypted_at_rest_or_msk_source", "firehose_delivery_stream", "Firehose stream is encrypted at rest (or reads from MSK)",
    _stream(), _stream("DISABLED"), rows=[P + "firehose_stream_encrypted_at_rest"], severity="medium", control="SC-28",
    remediation="Enable server-side encryption on the delivery stream (StartDeliveryStreamEncryption).", docs=[D_FH, D_FH_ENC],
    extra={"msk_pass": _stream(None, "MSKAsSource"), "kinesis_source": _stream(None, "KinesisStreamAsSource"), "kinesis_source_expect": "FAIL"},
    note="Prowler: DeliveryStreamEncryptionConfiguration.Status ENABLED passes (omitted = DISABLED); MSKAsSource streams pass because MSK always encrypts at rest; Kinesis-source and Direct PUT streams without SSE fail. Differs from aws.cb.firehose.server_side_encryption (no MSK exception).")
def firehose_rest(item, index):
    status = absent_or(item, "DeliveryStreamARN", "DeliveryStreamEncryptionConfiguration.Status", "DISABLED", str)
    if status == "ENABLED":
        return result(False, encryption_status=status)
    kind = get(item, "DeliveryStreamType", str)
    return result(kind != "MSKAsSource", encryption_status=status, delivery_stream_type=kind)


# =========================================================================== RDS snapshots
_SNAP_ROWS = [C + "rds_db_snapshot_encrypted_at_rest", C + "foundational_security_rds_4"]
_SNAP_NOTE = ("Steampipe unions aws_rds_db_cluster_snapshot.storage_encrypted (every engine returned by DescribeDBClusterSnapshots, "
              "including DocumentDB/Neptune) and aws_rds_db_snapshot.encrypted; this native evaluates one half.")


@install("aws.c2b.rds.cluster_snapshot_encrypted_any_engine", "rds_cluster_snapshot", "DB cluster snapshot is encrypted (all engines)",
    {"DBClusterSnapshotArn": "arn:aws:rds:us-east-1:111111111111:cluster-snapshot:s", "Engine": "docdb", "StorageEncrypted": True},
    {"DBClusterSnapshotArn": "arn:aws:rds:us-east-1:111111111111:cluster-snapshot:s", "Engine": "docdb", "StorageEncrypted": False},
    rows=_SNAP_ROWS, severity="medium", control="SC-28", remediation="Copy the cluster snapshot with KMS encryption and delete the unencrypted snapshot.",
    docs=[D_RDS_CSNAP], note=_SNAP_NOTE + " Unlike aws.cb.rds.cluster_snapshot_encrypted (prowler, DocumentDB excluded) every engine is in scope.")
def csnap_any(item, index):
    get(item, "DBClusterSnapshotArn", str)
    value = get(item, "StorageEncrypted", bool)
    return result(not value, storage_encrypted=value)


@install("aws.c2b.rds.db_snapshot_encrypted", "rds_snapshot", "DB instance snapshot is encrypted",
    {"DBSnapshotArn": "arn:aws:rds:us-east-1:111111111111:snapshot:s", "Encrypted": True}, {"DBSnapshotArn": "arn:aws:rds:us-east-1:111111111111:snapshot:s", "Encrypted": False},
    rows=_SNAP_ROWS, severity="medium", control="SC-28", remediation="Copy the DB snapshot with KMS encryption and delete the unencrypted snapshot.",
    docs=[D_RDS_SNAP], note=_SNAP_NOTE + " Same field as aws.rds.snapshot_encryption; registered here so the union row is ported as one unit.")
def snap_enc(item, index):
    get(item, "DBSnapshotArn", str)
    value = get(item, "Encrypted", bool)
    return result(not value, encrypted=value)
