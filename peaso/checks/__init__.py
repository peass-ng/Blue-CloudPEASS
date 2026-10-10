"""Native checks: pure functions over facts, with conservative provider semantics."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable
from functools import wraps
from ipaddress import ip_network
from .facts import get, list_of_objects, optional

HACKTRICKS = "HackTricks Cloud Best Practices"
FRAMEWORKS = (HACKTRICKS, "NIST 800-53")
HACKTRICKS_URL = "https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/pentesting-cloud-methodology.md"


@dataclass(frozen=True)
class Check:
    id: str
    provider: str
    category: str
    kind: str
    title: str
    severity: str
    control: str
    remediation: str
    evaluate: Callable
    target: str = "resource"
    declared_dependencies: tuple = ()

    @property
    def evaluation_mode(self):
        return self.target

    @property
    def frameworks(self):
        from .catalog import framework_names_for
        return framework_names_for(self.id)

    @property
    def framework_ids(self):
        from .catalog import framework_ids_for
        return framework_ids_for(self.id)

    @property
    def mapping(self):
        from .catalog import mappings_for
        return mappings_for(self.id, self.category, self.control)

    @property
    def dependencies(self):
        if self.declared_dependencies:
            return list(self.declared_dependencies)
        from sys import modules
        for provider in ("aws", "gcp", "azure", "k8s"):
            module = modules.get("peaso.checks." + provider + "_extended")
            declared = getattr(module, "DEPENDENCIES", {}).get(self.id) if module else None
            if declared is not None:
                return list(declared)
        return [self.kind]

    def public(self):
        from .catalog import provenance_for
        from .facts import FIELD_SPECS
        from .batch import scalar_sql
        return {"id": self.id, "provider": self.provider, "category": self.category, "type": self.kind,
                "title": self.title, "severity": self.severity, "frameworks": self.frameworks,
                "framework_ids": self.framework_ids,
                "mapping": self.mapping, "remediation": self.remediation,
                "dependencies": self.dependencies, "target": self.target, "evaluator_version": "1.0.0",
                "evaluator": {"language": "python", "entrypoint": "peaso.checks:evaluate_check", "check_id": self.id,
                    **({"alternative": {"language": "sql", "backend": "duckdb", "version": "1.0.0", "sql": scalar_sql(self.id)}} if self.id in FIELD_SPECS else {})},
                "sources": provenance_for(self.id),
                "expected_cost": {"cloud_calls": 0, "time": "linear in applicable snapshot facts"},
                "rationale": self.title + "; inspect collected configuration without inferring effective access."}


CHECKS = []


def evaluate_check(check_id, item, index=None):
    check = next((c for c in CHECKS if c.id == check_id), None)
    if check is None:
        raise ValueError("unknown native check ID")
    return check.evaluate(item, {} if index is None else index)


def register(id, provider, category, kind, title, severity, control, remediation, *, target="resource", dependencies=None):
    if target not in ("resource", "scope"):
        raise ValueError("check target must be resource or scope")
    if dependencies is not None and (not isinstance(dependencies, (list, tuple)) or not all(isinstance(x, str) for x in dependencies)):
        raise ValueError("check dependencies must be collection-type strings")
    def decorate(function):
        if any(c.id == id for c in CHECKS):
            raise ValueError("duplicate check id: " + id)
        @wraps(function)
        def safe(item, index):
            from .facts import Unavailable, guard
            try:
                guard(item)
                status, evidence = function(item, index)
                if status not in ("PASS", "FAIL", "UNKNOWN", "DENIED", "MANUAL", "NOT_APPLICABLE", "EMPTY") or not isinstance(evidence, dict):
                    raise ValueError("invalid evaluator result")
                return status, evidence
            except Unavailable as exc:
                return unknown(str(exc))
            except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError) as exc:
                return unknown("malformed or missing native facts", error_type=type(exc).__name__)
        CHECKS.append(Check(id, provider, category, kind, title, severity, control, remediation, safe, target, tuple(dependencies or ())))
        return function
    return decorate


def result(failed, **evidence):
    return ("FAIL" if failed else "PASS"), evidence


def unknown(reason, **evidence):
    return "UNKNOWN", {"reason": reason, **evidence}


def array(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    raise ValueError("expected string or list")


def statements(document):
    if isinstance(document, str):
        import json
        from urllib.parse import unquote
        document = json.loads(unquote(document))
    if not isinstance(document, dict) or "Statement" not in document:
        raise ValueError("missing IAM statements")
    rows = document["Statement"]
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or any(not isinstance(s, dict) for s in rows):
        raise ValueError("malformed IAM statements")
    return rows


def aws_documents(item):
    documents = []
    if "PolicyDocument" in item:
        documents.append(get(item, "PolicyDocument"))
    for version in list_of_objects(get(item, "PolicyVersionList", list) if "PolicyVersionList" in item else []):
        if version.get("IsDefaultVersion"):
            documents.append(version.get("Document"))
    for key in ("UserPolicyList", "RolePolicyList", "GroupPolicyList"):
        documents.extend(x.get("PolicyDocument") for x in item.get(key, []))
    return documents


@register("aws.iam.no_full_admin", "aws", "least_privilege", "iam_policy", "Managed policy has no unconditional full administrator grant", "high", "AC-6", "Replace full administrator grants with the actions and resources required for the workload; review conditions and explicit denies.")
def aws_admin(item, index):
    documents = aws_documents(item)
    if not documents:
        return unknown("default policy document was not collected")
    flagged, conditional = [], []
    for document in documents:
        for statement in statements(document):
            if statement.get("Effect") not in ("Allow", "Deny"):
                return unknown("policy statement has no valid Effect")
            if not any(k in statement for k in ("Action", "NotAction")) or not any(k in statement for k in ("Resource", "NotResource")):
                return unknown("identity policy statement action or resource missing")
            if statement.get("Effect") == "Allow" and "*" in array(statement.get("Action", [])) and "*" in array(statement.get("Resource", [])):
                (conditional if statement.get("Condition") else flagged).append(statement)
    if not flagged and conditional:
        return "MANUAL", {"conditional_admin_statements": conditional, "semantics": "Declared allow only; conditions, denies, SCPs, boundaries and session policies require review."}
    return result(bool(flagged), full_admin_statements=flagged, semantics="Declared policy grants; this is not effective access.")


@register("aws.iam.restrict_public_trust", "aws", "iam_graph", "iam_role", "Role trust avoids an unrestricted public principal", "high", "AC-3", "Limit role trust to intended principals and review trust conditions, organizational controls and federation settings.")
def aws_trust(item, index):
    if "AssumeRolePolicyDocument" not in item:
        return unknown("role trust document missing")
    broad, conditional = [], []
    for statement in statements(item["AssumeRolePolicyDocument"]):
        if statement.get("Effect") not in ("Allow", "Deny"):
            return unknown("trust statement effect missing or invalid")
        if "Principal" not in statement or not any(k in statement for k in ("Action", "NotAction")):
            return unknown("trust principal or action missing")
        principal = statement.get("Principal")
        wildcard = principal == "*" or (isinstance(principal, dict) and any("*" in array(v) for v in principal.values()))
        if statement.get("Effect") == "Allow" and wildcard:
            (conditional if statement.get("Condition") else broad).append(statement)
    if conditional and not broad:
        return "MANUAL", {"conditional_public_trust": conditional, "semantics": "Conditions constrain declared trust; review manually."}
    return result(bool(broad), unrestricted_trust_statements=broad)


@register("aws.iam.console_mfa", "aws", "hardening", "iam_user", "Console users have MFA configured", "high", "IA-2", "Enable MFA for console users; prefer federated short-lived access.")
def aws_mfa(item, index):
    if "LoginProfile" not in item or "MFADevices" not in item:
        return unknown("authorization-details inventory does not establish console login or MFA; add read-only login/MFA evidence")
    from .facts import get, guard
    login = get(item, "LoginProfile")
    devices = get(item, "MFADevices")
    if isinstance(login, dict):
        guard(login)
    if login is None or isinstance(login, dict) and login.get("absent") is True:
        return "NOT_APPLICABLE", {"console_login": False}
    if isinstance(devices, dict):
        guard(devices)
        devices = get(devices, "items", list)
    if not isinstance(login, dict) or not isinstance(devices, list):
        return unknown("malformed MFA devices")
    get(login, "LoginProfile", dict)
    return result(not devices, console_login=True, mfa_device_count=len(devices))


@register("aws.s3.public_access_block", "aws", "exposure", "bucket", "Bucket public access block is fully configured", "high", "AC-3", "Enable all four bucket Public Access Block settings and review account-level policy and ACL controls.")
def aws_bucket_public(item, index):
    config = get(item, "PublicAccessBlock", dict)
    if not isinstance(config, dict) or config.get("collection_status") not in (None, "collected", "empty"):
        return unknown("bucket public access block unavailable", collection=config)
    if config.get("absent"):
        return result(True, bucket_public_access_block="absent", semantics="Missing bucket-level control; account-level controls and effective access were not evaluated.")
    config = config.get("PublicAccessBlockConfiguration")
    names = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    if not isinstance(config, dict) or any(type(config.get(k)) is not bool for k in names):
        return unknown("incomplete public access block fields")
    return result(not all(config[k] for k in names), settings=config, semantics="Bucket-level preventative configuration, not proof of effective public access.")


@register("aws.s3.default_encryption", "aws", "hardening", "bucket", "Bucket default encryption is configured", "medium", "SC-13", "Configure and verify server-side encryption; select an appropriate managed key for sensitive data.")
def aws_bucket_encryption(item, index):
    data = get(item, "Encryption", dict)
    if not isinstance(data, dict) or data.get("collection_status") not in (None, "collected", "empty") or data.get("absent"):
        return unknown("default encryption unavailable; S3 encrypts new objects by default and absent legacy configuration alone is not a failure")
    rules = data.get("ServerSideEncryptionConfiguration", {}).get("Rules")
    if not isinstance(rules, list) or not rules:
        return unknown("default encryption rules missing")
    algorithms = [r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") for r in rules]
    if any(x not in ("AES256", "aws:kms", "aws:kms:dsse") for x in algorithms):
        return unknown("malformed or unrecognized encryption algorithm", algorithms=algorithms)
    return result(False, algorithms=algorithms, semantics="Default configuration; existing object encryption was not collected.")


@register("aws.ec2.restrict_internet_ingress", "aws", "network", "security_group", "Security group avoids broad internet ingress", "high", "SC-7", "Restrict ingress CIDRs and ports to intended clients; confirm routing, attached interfaces and network ACLs separately.")
def aws_ingress(item, index):
    rules = get(item, "IpPermissions", list)
    if not isinstance(rules, list):
        return unknown("ingress rules missing")
    broad = []
    for rule in rules:
        if not isinstance(rule, dict):
            return unknown("malformed ingress rule")
        if not isinstance(rule.get("IpProtocol"), str):
            return unknown("ingress protocol unavailable")
        for ranges, key in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")):
            for source in list_of_objects(rule.get(ranges, [])):
                cidr = get(source, key, str)
                network = ip_network(cidr, strict=False)
                if network.prefixlen == 0:
                    broad.append({"source": cidr, "protocol": rule.get("IpProtocol"), "from_port": rule.get("FromPort"), "to_port": rule.get("ToPort")})
    return result(bool(broad), internet_ingress=broad, semantics="Declared ingress; reachable services are not inferred.")


@register("aws.ec2.imdsv2", "aws", "hardening", "instance", "Instance requires IMDSv2 tokens when metadata is enabled", "medium", "CM-6", "Require IMDSv2 or disable instance metadata if the workload does not need it.")
def aws_imds(item, index):
    metadata = get(item, "MetadataOptions", dict)
    if not isinstance(metadata, dict):
        return unknown("metadata options unavailable")
    if metadata.get("HttpEndpoint") == "disabled":
        return "PASS", {"metadata_endpoint": "disabled"}
    if metadata.get("HttpEndpoint") != "enabled":
        return unknown("metadata endpoint state unavailable")
    if metadata.get("HttpTokens") not in ("optional", "required"):
        return unknown("token requirement unavailable")
    return result(metadata["HttpTokens"] != "required", metadata_options=metadata)


@register("gcp.iam.restrict_public_members", "gcp", "exposure", "iam_policy", "Project IAM avoids public members", "high", "AC-3", "Remove public IAM grants unless explicitly approved; account for binding conditions and inherited policies.")
def gcp_public(item, index):
    bindings = get(item, "bindings", list)
    if not isinstance(bindings, list):
        return unknown("IAM bindings missing")
    public, conditional = [], []
    for binding in bindings:
        if not isinstance(binding, dict) or not isinstance(binding.get("members"), list) or not isinstance(binding.get("role"), str):
            return unknown("malformed IAM binding")
        members = [m for m in binding["members"] if m in ("allUsers", "allAuthenticatedUsers")]
        if members:
            (conditional if binding.get("condition") else public).append({"role": binding.get("role"), "members": members, "condition": binding.get("condition")})
    if conditional and not public:
        return "MANUAL", {"conditional_public_bindings": conditional}
    return result(bool(public), public_bindings=public, semantics="Project policy only; organization/folder inheritance and deny policies were not collected.")


@register("gcp.iam.avoid_basic_roles", "gcp", "least_privilege", "iam_policy", "Project IAM avoids broad owner/editor roles", "high", "AC-6", "Replace basic owner/editor roles with reviewed predefined or custom roles; preserve only approved administrative access.")
def gcp_basic(item, index):
    bindings = get(item, "bindings", list)
    if not isinstance(bindings, list):
        return unknown("IAM bindings missing")
    if any(not isinstance(b, dict) or not isinstance(b.get("role"), str) or not isinstance(b.get("members"), list) for b in bindings):
        return unknown("malformed IAM binding")
    broad = [b for b in bindings if b.get("role") in ("roles/owner", "roles/editor")]
    return result(bool(broad), broad_bindings=broad, semantics="Declared project grants, including conditions; not effective permissions.")


@register("gcp.storage.uniform_access", "gcp", "hardening", "bucket", "Bucket uses uniform bucket-level access", "medium", "AC-3", "Enable uniform bucket-level access after reviewing object ACL dependencies.")
def gcp_uniform(item, index):
    value = get(item, "iamConfiguration.uniformBucketLevelAccess.enabled", bool)
    if type(value) is not bool:
        return unknown("uniform bucket-level access flag missing")
    return result(not value, uniform_bucket_level_access=value)


@register("gcp.storage.public_access_prevention", "gcp", "exposure", "bucket", "Bucket public access prevention is enforced", "high", "AC-3", "Enforce public access prevention or verify the inherited organization policy; review bucket IAM separately.")
def gcp_prevention(item, index):
    value = get(item, "iamConfiguration.publicAccessPrevention", str)
    if value == "inherited":
        return unknown("public access prevention is inherited; organization policy was not collected", configured=value)
    if value != "enforced":
        return unknown("public access prevention setting missing", configured=value)
    return result(False, configured=value, semantics="Preventative setting; bucket IAM and object ACL public access not evaluated.")


@register("gcp.compute.restrict_internet_ingress", "gcp", "network", "firewall", "Firewall avoids broad internet ingress", "high", "SC-7", "Restrict source ranges and service ports; review target tags, service accounts and higher-priority firewall policies.")
def gcp_ingress(item, index):
    if type(item.get("disabled", False)) is not bool or item.get("direction", "INGRESS") not in ("INGRESS", "EGRESS"):
        return unknown("malformed firewall enabled/direction fields")
    if item.get("disabled") is True or item.get("direction", "INGRESS") != "INGRESS" or item.get("denied"):
        return "NOT_APPLICABLE", {"disabled": item.get("disabled", False), "direction": item.get("direction", "INGRESS")}
    allowed = get(item, "allowed", list)
    if not isinstance(allowed, list):
        return unknown("allow rules missing")
    if any(not isinstance(rule, dict) or not isinstance(rule.get("IPProtocol"), str) for rule in allowed):
        return unknown("malformed firewall allow rule")
    # GCP defaults omitted ingress source ranges to 0.0.0.0/0 only when no source tags/SA exists.
    sources = item.get("sourceRanges")
    for field in ("sourceTags", "sourceServiceAccounts"):
        if not isinstance(item.get(field, []), list) or any(not isinstance(value, str) for value in item.get(field, [])):
            return unknown("malformed firewall source selectors")
    if sources is None:
        sources = [] if item.get("sourceTags") or item.get("sourceServiceAccounts") else ["0.0.0.0/0"]
    if not isinstance(sources, list) or any(not isinstance(source, str) for source in sources):
        return unknown("malformed firewall source ranges")
    networks = [ip_network(source, strict=False) for source in sources]
    return result(bool(allowed) and any(network.prefixlen == 0 for network in networks), source_ranges=sources, allowed=allowed,
        target_tags=item.get("targetTags", []), target_service_accounts=item.get("targetServiceAccounts", []), priority=item.get("priority", 1000), semantics="Declared firewall rule only, not effective reachability.")


@register("gcp.compute.no_external_ip", "gcp", "exposure", "instance", "Instance avoids an unreviewed external IP", "medium", "SC-7", "Use private connectivity where possible; review approved public endpoints and firewall restrictions.")
def gcp_ip(item, index):
    interfaces = get(item, "networkInterfaces", list)
    if not isinstance(interfaces, list):
        return unknown("network interfaces missing")
    addresses = []
    for nic in list_of_objects(interfaces):
        for field, key in (("accessConfigs", "natIP"), ("ipv6AccessConfigs", "externalIpv6")):
            for config in list_of_objects(nic.get(field, [])):
                address = get(config, key, str)
                addresses.append(address)
    return result(bool(addresses), external_ips=addresses, semantics="Assigned addresses; no reachability test was performed.")


@register("azure.storage.https_only", "azure", "hardening", "storage_account", "Storage account requires secure transfer", "high", "SC-8", "Enable secure transfer required for the storage account.")
def azure_https(item, index):
    value = get(item, "properties.supportsHttpsTrafficOnly", bool)
    if type(value) is not bool:
        return unknown("secure transfer flag missing")
    return result(not value, supports_https_traffic_only=value)


@register("azure.storage.no_blob_public_access", "azure", "exposure", "storage_account", "Storage account disables anonymous blob access", "high", "AC-3", "Disable account-level anonymous blob access and review existing container access policies.")
def azure_blob(item, index):
    value = get(item, "properties.allowBlobPublicAccess", bool)
    if type(value) is not bool:
        return unknown("anonymous blob access flag missing; omitted API fields are not treated as safe defaults")
    return result(value, allow_blob_public_access=value, semantics="Account-level capability; no container data-plane inventory was collected.")


@register("azure.storage.minimum_tls", "azure", "hardening", "storage_account", "Storage account requires TLS 1.2 or newer", "medium", "SC-8", "Set minimumTlsVersion to TLS1_2 or newer supported policy.")
def azure_tls(item, index):
    value = get(item, "properties.minimumTlsVersion", str)
    if value not in ("TLS1_0", "TLS1_1", "TLS1_2"):
        return unknown("minimum TLS version missing or unknown", configured=value)
    return result(value in ("TLS1_0", "TLS1_1"), minimum_tls_version=value)


@register("azure.iam.review_owner_assignment", "azure", "least_privilege", "role_assignment", "Owner assignments receive least-privilege review", "high", "AC-6", "Review whether the principal requires Owner; replace with a narrower role and time-bound administrative eligibility where appropriate.")
def azure_owner(item, index):
    properties = get(item, "properties", dict)
    role = properties.get("roleDefinitionId")
    if not isinstance(role, str) or not properties.get("principalId"):
        return unknown("role assignment principal or role missing")
    owner = role.lower().endswith("/8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
    return result(owner, principal_id=properties["principalId"], role_definition_id=role,
        assignment_scope=properties.get("scope"), condition=properties.get("condition"), semantics="Declared assignment only; deny assignments, group membership, PIM eligibility and inheritance were not evaluated.")


@register("azure.iam.no_full_custom_role", "azure", "least_privilege", "role_definition", "Custom role avoids unrestricted control-plane actions", "high", "AC-6", "Limit custom-role actions, dataActions and assignable scopes; review notActions and notDataActions exclusions.")
def azure_custom(item, index):
    properties = get(item, "properties", dict)
    if properties.get("type") == "BuiltInRole":
        return "NOT_APPLICABLE", {"role_type": "BuiltInRole"}
    permissions = properties.get("permissions")
    if properties.get("type") != "CustomRole" or not isinstance(permissions, list):
        return unknown("custom role type or permission blocks missing")
    broad = [p for p in permissions if "*" in p.get("actions", []) or "*" in p.get("dataActions", [])]
    if broad and any(p.get("notActions") or p.get("notDataActions") for p in broad):
        return "MANUAL", {"wildcard_blocks_with_exclusions": broad, "semantics": "Exclusions are not denies; review control-plane and data-plane semantics separately."}
    return result(bool(broad), unrestricted_permission_blocks=broad, assignable_scopes=properties.get("assignableScopes", []))


@register("azure.network.restrict_internet_ingress", "azure", "network", "nsg", "NSG avoids broad internet allow rules", "high", "SC-7", "Restrict allow-rule source prefixes and ports; review NSG priority, subnet/NIC attachment and effective routes.")
def azure_ingress(item, index):
    rules = get(item, "properties.securityRules", list)
    if not isinstance(rules, list):
        return unknown("NSG custom rules missing")
    broad = []
    for rule in rules:
        p = rule.get("properties", {})
        if p.get("direction") not in ("Inbound", "Outbound") or p.get("access") not in ("Allow", "Deny"):
            return unknown("malformed NSG rule direction or access")
        if p.get("direction") == "Inbound" and p.get("access") == "Allow":
            sources = p.get("sourceAddressPrefixes") or [p.get("sourceAddressPrefix")]
            if not isinstance(sources, list) or any(not isinstance(source, str) for source in sources):
                return unknown("NSG source prefixes missing or malformed")
            if any(s in ("*", "Internet", "0.0.0.0/0", "::/0") for s in sources):
                broad.append({"name": rule.get("name"), "priority": p.get("priority"), "source": sources,
                    "destination_ports": p.get("destinationPortRanges") or [p.get("destinationPortRange")], "protocol": p.get("protocol")})
    return result(bool(broad), broad_ingress_rules=broad, semantics="Declared custom allow rules; effective priority ordering, defaults and reachability require review.")


@register("k8s.rbac.no_wildcards", "k8s", "least_privilege", "clusterrole", "ClusterRole avoids wildcard rules", "high", "AC-6", "Replace wildcard RBAC grants with specific reviewed API groups, resources and verbs.")
@register("k8s.rbac.role_no_wildcards", "k8s", "least_privilege", "role", "Role avoids wildcard rules", "high", "AC-6", "Replace wildcard RBAC grants with specific reviewed API groups, resources and verbs.")
def k8s_wildcards(item, index):
    rules = get(item, "rules", list)
    if not isinstance(rules, list):
        return unknown("RBAC rules missing; aggregated roles require their resolved rules")
    if any(not isinstance(r, dict) or not isinstance(r.get("verbs"), list) or not r["verbs"] for r in rules):
        return unknown("malformed RBAC policy rule")
    broad = [r for r in rules if any("*" in r.get(k, []) for k in ("verbs", "resources", "apiGroups", "nonResourceURLs"))]
    return result(bool(broad), wildcard_rules=broad, aggregation_rule=item.get("aggregationRule"), semantics="Declared RBAC; bindings and authorization integrations determine effective access.")


@register("k8s.rbac.review_broad_subjects", "k8s", "iam_graph", "clusterrolebinding", "ClusterRoleBinding avoids broad authenticated groups", "high", "AC-3", "Bind reviewed roles to intended users or service accounts and review aggregated role definitions.")
@register("k8s.rbac.review_namespaced_subjects", "k8s", "iam_graph", "rolebinding", "RoleBinding avoids broad authenticated groups", "high", "AC-3", "Bind namespace roles to intended users or service accounts.")
def k8s_subjects(item, index):
    subjects = get(item, "subjects", list)
    if not isinstance(subjects, list) or not isinstance(item.get("roleRef"), dict):
        return unknown("binding subjects or roleRef missing")
    broad = [s for s in subjects if s.get("kind") == "Group" and s.get("name") in ("system:authenticated", "system:unauthenticated", "system:serviceaccounts")]
    return result(bool(broad), broad_subjects=broad, role_ref=item["roleRef"], semantics="Declared binding; grants are not a calculated effective-access claim.")


@register("k8s.pod.no_privileged_containers", "k8s", "hardening", "pod", "Pod avoids privileged containers", "high", "CM-6", "Disable privileged containers and enforce an appropriate Pod Security Admission policy.")
def k8s_privileged(item, index):
    spec = get(item, "spec", dict)
    containers = spec.get("containers")
    if not isinstance(containers, list) or not containers:
        return unknown("pod container specifications missing")
    all_containers = containers + spec.get("initContainers", []) + spec.get("ephemeralContainers", [])
    if any(not isinstance(c, dict) or not isinstance(c.get("securityContext", {}), dict) or type(c.get("securityContext", {}).get("privileged", False)) is not bool for c in all_containers):
        return unknown("malformed container privileged flag")
    privileged = [c.get("name") for c in all_containers if optional(optional(c, "securityContext", {}, dict), "privileged", False, bool) is True]
    return result(bool(privileged), privileged_containers=privileged, semantics="Observed pod spec; admission enforcement not inferred.")


@register("k8s.pod.no_host_namespaces", "k8s", "hardening", "pod", "Pod avoids host namespaces", "high", "CM-6", "Disable hostNetwork, hostPID and hostIPC unless the workload has an approved operational requirement.")
def k8s_host(item, index):
    spec = get(item, "spec", dict)
    if not isinstance(spec, dict):
        return unknown("pod specification missing")
    values = {k: optional(spec, k, False, bool) for k in ("hostNetwork", "hostPID", "hostIPC")}
    if any(type(v) is not bool for v in values.values()):
        return unknown("malformed host namespace flags")
    return result(any(values.values()), host_namespace_flags=values)


@register("k8s.service.review_public_type", "k8s", "exposure", "service", "Service avoids unreviewed external publication", "medium", "SC-7", "Review LoadBalancer, NodePort and externalIPs services against approved ingress and network controls.")
def k8s_service(item, index):
    spec = get(item, "spec", dict)
    if not isinstance(spec, dict):
        return unknown("service specification missing")
    service_type = spec.get("type", "ClusterIP")
    if service_type not in ("ClusterIP", "NodePort", "LoadBalancer", "ExternalName"):
        return unknown("unknown service type")
    if not isinstance(spec.get("externalIPs", []), list) or any(not isinstance(value, str) for value in spec.get("externalIPs", [])):
        return unknown("malformed external IP list")
    return result(service_type in ("LoadBalancer", "NodePort") or bool(spec.get("externalIPs")), service_type=service_type,
        external_ips=spec.get("externalIPs", []), semantics="Publication configuration; internet reachability was not tested.")


@register("k8s.network.namespace_policy_inventory", "k8s", "network", "namespace", "Namespace has NetworkPolicy inventory for review", "medium", "SC-7", "Define reviewed default-deny ingress/egress policies and verify that the cluster network plugin enforces them.")
def k8s_policies(item, index):
    name = item.get("metadata", {}).get("name")
    if not name:
        return unknown("namespace name missing")
    envelopes = index.get("collections", {}).get("networkpolicy", [])
    # Qualified scopes identify a cluster and namespace. A cluster-scoped namespace
    # list must not turn another namespace's missing policy inventory into a FAIL.
    relevant = [c for c in envelopes if c["scope"] in ("*", name) or c["scope"].endswith(("/" + name, "/*"))]
    if not relevant or any(c["status"] not in ("collected", "empty") for c in relevant):
        return unknown("network policy inventory missing or incomplete")
    policies = [r for r in index.get("networkpolicy", []) if r["data"].get("metadata", {}).get("namespace") == name]
    if not policies:
        return result(True, namespace=name, network_policy_count=0, semantics="No policies observed in complete inventory; enforcement and other cluster controls are not known.")
    return "MANUAL", {"namespace": name, "network_policy_count": len(policies), "reason": "Policy presence is not proof of pod coverage, default deny, or CNI enforcement."}


# Registration imports happen after the compatibility helpers are defined.
from . import aws, gcp, azure, k8s  # noqa: E402,F401
from . import k8s_extended  # noqa: E402,F401
from . import gcp_extended  # noqa: E402,F401
from . import aws_extended  # noqa: E402,F401
from . import azure_extended  # noqa: E402,F401
from . import k8s_ports_workloads  # noqa: E402,F401
from . import azure_ports_services  # noqa: E402,F401
from . import aws_a_iam  # noqa: E402,F401
from . import aws_b_core, aws_b_loadbalancing  # noqa: E402,F401
from . import k8s_ports_components  # noqa: E402,F401
from . import aws_b_regional  # noqa: E402,F401
from . import gcp_ports_services  # noqa: E402,F401
from . import aws_b_cloudfront  # noqa: E402,F401
from . import aws_a_regional, azure_ports_defender, k8s_ports_cluster  # noqa: E402,F401
from . import aws_b_storage  # noqa: E402,F401
