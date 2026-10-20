"""Canonical service labels for check targets and their collected inventories.

The manifest is keyed by provider and inventory kind. It is deliberately kept
separate from collection success: an unavailable inventory still has a service.
"""
from functools import lru_cache
import json
from pathlib import Path

CHECK_SERVICE_OVERRIDES = {
    # These checks share an umbrella target kind with controls for a different
    # product. The evaluated control, rather than the inventory wrapper, owns
    # the finding's service label.
    "azure.gap.monitor_log_profile_enabled_for_all_categories": "Microsoft.Insights",
    "azure.gap.audit_diagnostic_setting": "Microsoft.Insights",
    "aws.a.cloudwatch.cross_account_role_absent": "cloudwatch",
    "aws.claude2_a.cloudwatch.cross_account_sharing_role_absent": "cloudwatch",
    "aws.claude2_a.cloudtrail.account_has_logging_trail": "cloudtrail",
    "gcp.reviewed.project.os_login_2fa": "compute",
    "gcp.claude.project.oslogin_enabled": "compute",
    "gcp.claude.project.no_api_keys": "apikeys",
    "gcp.ports.project_no_api_key": "apikeys",
    "gcp.claude.project.storage_vpc_service_controls": "accesscontextmanager",
    "gcp.ports.project_service_cloudasset_api_enabled": "serviceusage",
    "gcp.ports.artifacts_container_analysis_enabled": "serviceusage",
    "gcp.claude.project.container_scanning_api_enabled": "serviceusage",
    "gcp.claude.project.gemini_api_disabled": "serviceusage",
    "gcp.iam.data_access_audit": "logging",
    "gcp.claude.project.storage_data_access_audit_logs": "logging",
    "gcp.claude.project.audit_logs_configured": "logging",
    "gcp_pci_iam_policy_ca1281da7ab2": "logging",
    "gcp_pci_iam_policy_9a8ce875703d": "logging",
    "gcp.logging.access_transparency_entries": "logging",
    "gcp_cloudsql_backup_failure_alert": "monitoring",
    "gcp_kms_key_destroy_alert": "monitoring",
    "gcp_logging_enumeration_alert": "monitoring",
    "gcp_logging_query_rate_alert": "monitoring",
}

CHECK_SERVICE_PREFIXES = (
    ("aws.a.iam.password_policy_", "iam"),
    ("gcp.claude.logging.", "logging"),
    ("gcp.claude2.logging.", "logging"),
    ("gcp.ports.logging_", "logging"),
    ("gcp.htbp.orgpolicy.", "orgpolicy"),
)

# Collector API clients and resource kinds are not always user-facing products.
# Apply these aliases to archived analysis findings, whose check IDs are not in
# the native check registry and whose bounded indexes retain only the service.
SERVICE_ALIASES = {
    "aws": {
        "apigatewayv2": "apigateway",
        "bedrock-agent": "bedrock",
        "elb": "elasticloadbalancing",
        "elbv2": "elasticloadbalancing",
        "redshift-serverless": "redshift",
        "s3control": "s3",
        "waf-regional": "waf",
        "wafv2": "waf",
    },
    "gcp": {"iam/cloudasset": "iam"},
}

# Exposure and network analysis can emit findings for supporting inventories
# that have no standalone native check. Older reports sometimes stored those
# inventory kinds directly as their service labels.
ANALYSIS_KIND_SERVICES = {
    "aws": {
        "ec2_instance_connect_endpoint": "ec2", "managed_prefix_list": "ec2",
        "nat_gateway": "ec2", "target_group": "elasticloadbalancing",
        "transit_gateway_attachment": "ec2", "transit_gateway_route_table": "ec2",
        "transit_gateway_vpc_attachment": "ec2", "vpn_gateway": "ec2",
    },
    "gcp": {
        "address": "compute", "effective_firewall": "compute",
        "firewall_policy": "compute", "firewall_policy_association": "compute",
        "health_check": "compute", "hierarchical_firewall_policy": "compute",
        "instance_group": "compute", "network_firewall_policy": "networksecurity",
        "policy_based_route": "networkconnectivity", "route": "compute",
        "router": "compute", "shared_vpc": "compute", "vpn_gateway": "compute",
        "vpn_tunnel": "compute",
    },
    "azure": {
        "effective_route": "Microsoft.Network", "nat_gateway": "Microsoft.Network",
        "private_endpoint": "Microsoft.Network", "security_admin_rule": "Microsoft.Network",
        "service_tag": "Microsoft.Network", "vnet_peering": "Microsoft.Network",
    },
}


@lru_cache(maxsize=1)
def _manifest():
    return json.loads(Path(__file__).with_name("check_services.json").read_text())


def service_for(provider, kind, observed=None):
    """Return the reviewed service of a check target, including empty scopes."""
    service = _manifest().get(provider, {}).get(kind)
    if service:
        return service
    if observed and observed not in ("azure", kind):
        return canonical_observed_service(provider, observed)
    return "kubernetes" if provider == "k8s" else canonical_observed_service(provider, observed or kind)


def canonical_observed_service(provider, observed):
    """Normalize legacy service labels without guessing from finding titles."""
    if not isinstance(observed, str) or not observed:
        return observed
    if provider == "k8s":
        return "kubernetes"
    return (_manifest().get(provider, {}).get(observed)
            or ANALYSIS_KIND_SERVICES.get(provider, {}).get(observed)
            or SERVICE_ALIASES.get(provider, {}).get(observed)
            or observed)


def service_for_check(check_id, provider, kind, observed=None):
    override = CHECK_SERVICE_OVERRIDES.get(check_id)
    if override:
        return override
    for prefix, service in CHECK_SERVICE_PREFIXES:
        if check_id.startswith(prefix):
            return service
    return service_for(provider, kind, observed)


@lru_cache(maxsize=1)
def _check_kinds():
    from peaso.checks import CHECKS
    return {check.id: (check.provider, check.kind) for check in CHECKS}


def finding_service(finding):
    """Also repair labels in reports created before the service manifest."""
    pair = _check_kinds().get(finding.get("check_id"))
    if pair:
        return service_for_check(finding["check_id"], *pair, finding.get("service"))
    return canonical_observed_service(finding.get("provider"), finding.get("service"))
