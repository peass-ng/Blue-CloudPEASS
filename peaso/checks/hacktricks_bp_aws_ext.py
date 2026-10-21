"""HackTricks Cloud Best Practices: AWS checks over the aws_facts_ext collector kinds.

Trust boundary: the audited account, the collected AWS Organizations member
accounts and the operator-configured context.metadata.trusted_scope_ids. A
principal or destination outside the account while the organization inventory
is unavailable is MANUAL (cannot be proven external), never FAIL. A wildcard
principal without an account/organization-restricting condition is public and
always FAIL. Missing or unreadable detail responses are UNKNOWN.
"""
from __future__ import annotations

import re

from . import result
from .claude_aws_a_common import account, is_condition_block_restrictive, is_condition_block_restrictive_organization
from .facts import Unavailable, complete_items, get, list_of_objects, optional
from .fixtures import CASES
from .hacktricks_bp_common import ht_register

AWS = "pentesting-cloud/aws-security/"
ACCOUNT = "111111111111"
ORG_PEER = "222222222222"
OUTSIDER = "999999999999"
_ACCOUNT = re.compile(r"^[0-9]{12}$")


# ---------------------------------------------------------------- trust boundary helpers
def _boundary(index):
    """(audited account, trusted account set, organization inventory known)."""
    me = account(index)
    trusted = {me}
    configured = (index.get("context", {}).get("metadata") or {}).get("trusted_scope_ids") if isinstance(index, dict) else None
    if isinstance(configured, list):
        trusted |= {value for value in configured if isinstance(value, str) and _ACCOUNT.fullmatch(value)}
    try:
        members = complete_items(index, "organization_account")
    except Unavailable:
        return me, trusted, False
    ids = {row.get("Id") for row in members}
    if any(not isinstance(value, str) or not _ACCOUNT.fullmatch(value) for value in ids):
        raise Unavailable("malformed organization account inventory")
    return me, trusted | ids, bool(ids)


def _principal_account(value):
    """12-digit account of an AWS principal (account id or IAM/STS ARN); None for a service principal."""
    if not isinstance(value, str) or not value:
        raise Unavailable("malformed principal")
    if value == "*":
        return "*"
    if _ACCOUNT.fullmatch(value):
        return value
    if value.startswith("arn:"):
        parts = value.split(":")
        if len(parts) >= 6 and _ACCOUNT.fullmatch(parts[4]):
            return parts[4]
        raise Unavailable("principal ARN without an account")
    if value.endswith(".amazonaws.com") or value.endswith(".amazonaws.com.cn"):
        return None
    raise Unavailable("unrecognized principal form")


def _document(container, key):
    """Parsed policy statements of a collector-parsed policy field; parse failures stay UNKNOWN."""
    value = get(container, key)
    if isinstance(value, dict) and "collection_status" in value:
        raise Unavailable("policy document unreadable: " + str(value.get("collection_status")))
    if not isinstance(value, dict):
        raise Unavailable("malformed policy document")
    statements = value.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        raise Unavailable("malformed policy statements")
    return statements


def _policy_parties(statements, me):
    """Accounts (or "*") granted by unconditioned-or-unrestricted Allow statements."""
    parties = set()
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        if "NotPrincipal" in statement:
            parties.add("*")
            continue
        principal = statement.get("Principal")
        if principal == "*":
            values = ["*"]
        elif isinstance(principal, dict):
            raw = principal.get("AWS", [])
            values = raw if isinstance(raw, list) else [raw]
        elif principal is None:
            continue
        else:
            raise Unavailable("malformed Principal")
        condition = statement.get("Condition")
        if condition is not None and not isinstance(condition, dict):
            raise Unavailable("malformed Condition")
        restricted = bool(condition) and (is_condition_block_restrictive(condition, me)
                                          or is_condition_block_restrictive_organization(condition))
        for value in values:
            party = _principal_account(value)
            if party is None or restricted:
                continue
            parties.add(party)
    return parties


def _verdict(parties, index, **evidence):
    """FAIL on public or proven out-of-boundary accounts; MANUAL when org membership is unknown."""
    me, trusted, org_known = _boundary(index)
    public = "*" in parties
    outside = sorted(party for party in parties if party not in trusted and party != "*")
    evidence = {**evidence, "public": public, "external_accounts": outside, "organization_inventory": org_known}
    if public or (outside and org_known):
        return result(True, **evidence)
    if outside:
        return "MANUAL", {**evidence, "reason": "accounts outside the audited account; organization membership not collected "
                                                "(configure trusted_scope_ids or collect organization_account)"}
    return result(False, **evidence)


def _org_index(org=True, trusted=None):
    context = {"provider": "aws", "Account": ACCOUNT, "scope": ACCOUNT + "/us-east-1"}
    if trusted:
        context["metadata"] = {"trusted_scope_ids": trusted}
    index = {"context": context, "collections": {}}
    if org:
        index["collections"]["organization_account"] = [{"scope": ACCOUNT + "/global", "status": "collected"}]
        index["organization_account"] = [{"data": {"Id": ACCOUNT}}, {"data": {"Id": ORG_PEER}}]
    return index


ORG_INDEX = _org_index()


def _allow(principal, condition=None, action="*"):
    statement = {"Effect": "Allow", "Principal": principal, "Action": action, "Resource": "*"}
    if condition:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


# ---------------------------------------------------------------- Lambda layers
@ht_register("aws.htbp.lambda.layer_version_trust_boundary", "aws", "exposure", "lambda_layer_version",
             "Lambda layer version policy is not public and grants no account outside the organization", "medium", "AC-3",
             "Remove layer version permissions that use principal '*' without an aws:PrincipalOrgID condition or that name "
             "accounts outside the organization (RemoveLayerVersionPermission); layer code and any bundled secrets are "
             "readable by every grantee.",
             pages=[AWS + "aws-persistence/aws-lambda-persistence/aws-lambda-layers-persistence.md"],
             dependencies=["lambda_layer_version", "organization_account"])
def layer_version_policy(item, index):
    get(item, "LayerName", str)
    policy = get(item, "Policy", dict)
    status = get(policy, "collection_status", str)
    if status == "empty" and policy.get("absent"):
        return result(False, policy="none")
    if status != "collected":
        raise Unavailable("layer version policy not collected: " + status)
    return _verdict(_policy_parties(_document(policy, "Policy"), account(index)), index,
                    layer_version_arn=item.get("LayerVersionArn"))


def _layer(policy):
    return {"LayerName": "shared", "LayerVersionArn": "arn:aws:lambda:us-east-1:%s:layer:shared:3" % ACCOUNT, "Version": 3, "Policy": policy}


CASES["aws.htbp.lambda.layer_version_trust_boundary"] = {
    "pass": _layer({"collection_status": "collected", "Policy": _allow({"AWS": "arn:aws:iam::%s:root" % ORG_PEER}, action="lambda:GetLayerVersion")}),
    "fail": _layer({"collection_status": "collected", "Policy": _allow("*", action="lambda:GetLayerVersion")}),
    "pass_org_condition": _layer({"collection_status": "collected", "Policy": _allow("*", {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}})}),
    "pass_no_policy": _layer({"collection_status": "empty", "absent": True}),
    "fail_outsider": _layer({"collection_status": "collected", "Policy": _allow({"AWS": OUTSIDER})}),
    "missing": _layer({"collection_status": "denied", "error": {"code": "AccessDeniedException"}}),
    "malformed": _layer({"collection_status": "collected", "Policy": {"collection_status": "malformed"}}),
    "index": ORG_INDEX}


# ---------------------------------------------------------------- Lambda runtime management
@ht_register("aws.htbp.lambda.runtime_updates_not_pinned_manual", "aws", "hardening", "lambda_function",
             "Lambda function runtime is not pinned with Manual runtime management", "low", "SI-2",
             "Set the runtime management configuration back to Auto (or FunctionUpdate) unless a documented rollback is in "
             "progress; Manual keeps the function on the selected runtime version indefinitely.",
             pages=[AWS + "aws-post-exploitation/aws-lambda-post-exploitation/aws-lambda-runtime-pinning-abuse.md"])
def runtime_pinning(item, index):
    get(item, "FunctionName", str)
    runtime = get(item, "RuntimeManagement", dict)
    status = get(runtime, "collection_status", str)
    if status == "empty" and runtime.get("absent"):
        return "NOT_APPLICABLE", {"reason": runtime.get("reason", "no runtime management configuration")}
    if status != "collected":
        raise Unavailable("runtime management configuration not collected: " + status)
    mode = get(runtime, "UpdateRuntimeOn", str)
    if mode not in ("Auto", "FunctionUpdate", "Manual"):
        raise Unavailable("unrecognized UpdateRuntimeOn")
    return result(mode == "Manual", update_runtime_on=mode, runtime_version_arn=runtime.get("RuntimeVersionArn"))


def _function(runtime):
    return {"FunctionName": "api", "FunctionArn": "arn:aws:lambda:us-east-1:%s:function:api" % ACCOUNT, "RuntimeManagement": runtime}


CASES["aws.htbp.lambda.runtime_updates_not_pinned_manual"] = {
    "pass": _function({"collection_status": "collected", "UpdateRuntimeOn": "Auto"}),
    "fail": _function({"collection_status": "collected", "UpdateRuntimeOn": "Manual",
                       "RuntimeVersionArn": "arn:aws:lambda:us-east-1::runtime:0123"}),
    "not_applicable": _function({"collection_status": "empty", "absent": True, "reason": "container_image_function"}),
    "missing": {"FunctionName": "api"},
    "malformed": _function({"collection_status": "collected", "UpdateRuntimeOn": "Sometimes"})}


# ---------------------------------------------------------------- Lambda environment variable names
# Literal credential names only; references (ARNs, parameter names, IDs, paths) and policy knobs are excluded.
_CREDENTIAL_NAME = re.compile(r"(?i)(SECRET_ACCESS_KEY|PASSWORD|PASSWD|PRIVATE_KEY|CLIENT_SECRET)")
_REFERENCE_NAME = re.compile(r"(?i)(_ARN|_NAME|_ID|_PARAM|_PARAMETER|_PATH|_REF|_SSM|_FILE|_URI|_LENGTH|_POLICY|_MIN|_MAX)$")


@ht_register("aws.htbp.lambda.env_var_names_not_credentials", "aws", "exposure", "lambda_function",
             "Lambda function has no environment variables named like literal credentials", "medium", "IA-5",
             "Move passwords, private keys, client secrets and secret access keys out of Lambda environment variables into "
             "Secrets Manager or Parameter Store and read them at runtime with a narrowly scoped execution role; anyone with "
             "lambda:GetFunctionConfiguration / ListFunctions reads environment values in plaintext.",
             pages=[AWS + "aws-post-exploitation/aws-lambda-function-access-post-exploitation/README.md"])
def env_var_names(item, index):
    get(item, "FunctionName", str)
    names = get(item, "EnvironmentVariableNames", dict)
    status = get(names, "collection_status", str)
    if status not in ("collected", "empty"):
        raise Unavailable("environment variable names not collected: " + status)
    values = get(names, "names", list)
    if any(not isinstance(name, str) for name in values):
        raise Unavailable("malformed environment variable names")
    hits = sorted(name for name in values if _CREDENTIAL_NAME.search(name) and not _REFERENCE_NAME.search(name))
    return result(bool(hits), credential_like_names=hits, variables_evaluated=len(values),
                  semantics="Name heuristic only: values are never collected; confirm the variable holds a literal secret.")


def _env(names, status="collected"):
    return {"FunctionName": "api", "EnvironmentVariableNames": {"collection_status": status, "names": names}}


CASES["aws.htbp.lambda.env_var_names_not_credentials"] = {
    "pass": _env(["DB_PASSWORD_SECRET_ARN", "STAGE", "PASSWORD_MIN_LENGTH"]),
    "pass_empty": _env([], "empty"),
    "fail": _env(["DB_PASSWORD", "STAGE"]),
    "missing": {"FunctionName": "api", "EnvironmentVariableNames": {"collection_status": "denied"}},
    "malformed": _env([1])}


@ht_register("aws.htbp.lambda.exec_wrapper_not_configured", "aws", "hardening", "lambda_function",
             "Lambda function has no execution wrapper configured", "medium", "CM-7",
             "Review the configured wrapper and attached layer against the approved deployment; remove "
             "AWS_LAMBDA_EXEC_WRAPPER when it is unexpected. The inventory reads variable names only, never values.",
             pages=[AWS + "aws-persistence/aws-lambda-persistence/aws-lambda-exec-wrapper-persistence.md"])
def lambda_exec_wrapper(item, index):
    get(item, "FunctionName", str)
    names = get(item, "EnvironmentVariableNames", dict)
    status = get(names, "collection_status", str)
    if status not in ("collected", "empty"):
        raise Unavailable("environment variable names not collected: " + status)
    values = get(names, "names", list)
    if any(not isinstance(name, str) for name in values):
        raise Unavailable("malformed environment variable names")
    present = "AWS_LAMBDA_EXEC_WRAPPER" in values
    return result(present, wrapper_key_present=present,
                  semantics="Name only; inspect approved layer and wrapper behavior to determine intent.")


CASES["aws.htbp.lambda.exec_wrapper_not_configured"] = {
    "pass": _env(["STAGE"]),
    "pass_empty": _env([], "empty"),
    "fail": _env(["AWS_LAMBDA_EXEC_WRAPPER", "STAGE"]),
    "missing": {"FunctionName": "api", "EnvironmentVariableNames": {"collection_status": "denied"}},
    "malformed": _env([7]),
}


# ---------------------------------------------------------------- ECR registry
_ECR_PAGES = [AWS + "aws-persistence/aws-ecr-persistence/README.md"]


@ht_register("aws.htbp.ecr.registry_policy_trust_boundary", "aws", "exposure", "ecr_registry",
             "ECR registry policy is not public and grants no account outside the organization", "high", "AC-3",
             "Restrict the private registry policy (replication / pull-through cache permissions) to organization accounts "
             "or add an aws:PrincipalOrgID condition.",
             pages=_ECR_PAGES,
             dependencies=["ecr_registry", "organization_account"])
def registry_policy(item, index):
    get(item, "registryId", str)
    policy = get(item, "RegistryPolicy", dict)
    status = get(policy, "collection_status", str)
    if status == "empty" and policy.get("absent"):
        return result(False, registry_policy="none")
    if status != "collected":
        raise Unavailable("registry policy not collected: " + status)
    return _verdict(_policy_parties(_document(policy, "policyText"), account(index)), index)


def _registry(**fields):
    return {"id": "ecr-registry/%s/us-east-1" % ACCOUNT, "registryId": ACCOUNT, **fields}


_REPL_ALLOW = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ORG_PEER},
               "Action": ["ecr:ReplicateImage", "ecr:CreateRepository"], "Resource": "*"}
CASES["aws.htbp.ecr.registry_policy_trust_boundary"] = {
    "pass": _registry(RegistryPolicy={"collection_status": "collected", "policyText": {"Statement": [_REPL_ALLOW]}}),
    "fail": _registry(RegistryPolicy={"collection_status": "collected", "policyText": _allow("*", action="ecr:ReplicateImage")}),
    "pass_absent": _registry(RegistryPolicy={"collection_status": "empty", "absent": True}),
    "missing": _registry(RegistryPolicy={"collection_status": "denied"}),
    "malformed": _registry(RegistryPolicy={"collection_status": "collected", "policyText": {"Statement": "x"}}),
    "index": ORG_INDEX}


@ht_register("aws.htbp.ecr.replication_destinations_trust_boundary", "aws", "exposure", "ecr_registry",
             "ECR replication only targets registries inside the organization", "high", "AC-4",
             "Remove replication rules whose destination registryId is outside the organization; cross-account replication "
             "copies every matching image to the destination registry.",
             pages=_ECR_PAGES,
             dependencies=["ecr_registry", "organization_account"])
def replication_destinations(item, index):
    get(item, "registryId", str)
    replication = get(item, "Replication", dict)
    status = get(replication, "collection_status", str)
    if status != "collected":
        raise Unavailable("registry replication configuration not collected: " + status)
    destinations = set()
    for rule in list_of_objects(optional(replication, "rules", [], list)):
        for destination in list_of_objects(get(rule, "destinations", list)):
            registry = get(destination, "registryId", str)
            if not _ACCOUNT.fullmatch(registry):
                raise Unavailable("malformed destination registryId")
            destinations.add(registry)
    return _verdict(destinations, index, destination_registries=sorted(destinations))


CASES["aws.htbp.ecr.replication_destinations_trust_boundary"] = {
    "pass": _registry(Replication={"collection_status": "collected", "rules": [{"destinations": [
        {"region": "eu-west-1", "registryId": ACCOUNT}, {"region": "us-east-1", "registryId": ORG_PEER}]}]}),
    "fail": _registry(Replication={"collection_status": "collected", "rules": [{"destinations": [{"region": "us-east-1", "registryId": OUTSIDER}]}]}),
    "pass_no_rules": _registry(Replication={"collection_status": "collected", "rules": []}),
    "missing": _registry(Replication={"collection_status": "denied"}),
    "malformed": _registry(Replication={"collection_status": "collected", "rules": [{"destinations": [{"registryId": 12}]}]}),
    "index": ORG_INDEX}


@ht_register("aws.htbp.ecr.creation_template_policy_trust_boundary", "aws", "exposure", "ecr_registry",
             "ECR repository creation templates do not attach public or out-of-organization repository policies", "high", "AC-3",
             "Remove or rewrite repository creation templates whose repositoryPolicy grants '*' or accounts outside the "
             "organization; every repository later auto-created under the prefix inherits that policy.",
             pages=_ECR_PAGES,
             dependencies=["ecr_registry", "organization_account"])
def creation_templates(item, index):
    get(item, "registryId", str)
    templates = get(item, "RepositoryCreationTemplates", dict)
    status = get(templates, "collection_status", str)
    if status not in ("collected", "empty"):
        raise Unavailable("repository creation templates not collected: " + status)
    me = account(index)
    parties, prefixes = set(), []
    for template in list_of_objects(get(templates, "items", list)):
        if "repositoryPolicy" not in template:
            continue
        found = _policy_parties(_document(template, "repositoryPolicy"), me)
        if found - {me}:
            prefixes.append(get(template, "prefix", str))
        parties |= found
    return _verdict(parties, index, template_prefixes=sorted(prefixes))


def _templates(policy, status="collected"):
    items = [] if policy is None else [{"prefix": "ptc2", "appliedFor": ["PULL_THROUGH_CACHE"], "repositoryPolicy": policy}]
    return _registry(RepositoryCreationTemplates={"collection_status": status, "items": items})


CASES["aws.htbp.ecr.creation_template_policy_trust_boundary"] = {
    "pass": _templates(_allow({"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, action="ecr:BatchGetImage")),
    "fail": _templates(_allow("*", action=["ecr:BatchGetImage", "ecr:PutImage"])),
    "pass_empty": _templates(None, "empty"),
    "missing": _registry(RepositoryCreationTemplates={"collection_status": "denied", "items": []}),
    "malformed": _templates("not-a-policy"),
    "index": ORG_INDEX}


# ---------------------------------------------------------------- EKS access entries
@ht_register("aws.htbp.eks.access_entry_principal_trust_boundary", "aws", "least_privilege", "eks_access_entry",
             "EKS access entry principal belongs to the organization", "high", "AC-2",
             "Delete access entries whose principalArn belongs to an account outside the organization (DeleteAccessEntry) "
             "and review their associated access policies.",
             pages=[AWS + "aws-persistence/aws-eks-persistence/README.md",
                    AWS + "aws-post-exploitation/aws-eks-post-exploitation/README.md"],
             dependencies=["eks_access_entry", "organization_account"])
def access_entry_principal(item, index):
    get(item, "clusterName", str)
    party = _principal_account(get(item, "principalArn", str))
    if party in (None, "*"):
        raise Unavailable("access entry principal is not an IAM principal ARN")
    policies = item.get("AssociatedAccessPolicies") if isinstance(item.get("AssociatedAccessPolicies"), dict) else {}
    return _verdict({party}, index, principal_arn=item["principalArn"], entry_type=item.get("type"),
                    access_policies=[row.get("policyArn") for row in policies.get("items") or [] if isinstance(row, dict)])


def _entry(principal):
    return {"clusterName": "prod", "principalArn": principal, "type": "STANDARD",
            "AssociatedAccessPolicies": {"collection_status": "collected", "items": [
                {"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"}]}}


CASES["aws.htbp.eks.access_entry_principal_trust_boundary"] = {
    "pass": _entry("arn:aws:iam::%s:role/admins" % ACCOUNT),
    "fail": _entry("arn:aws:iam::%s:role/backdoor" % OUTSIDER),
    "missing": {"clusterName": "prod"},
    "malformed": _entry("arn:aws:iam::not-an-account:role/x"),
    "index": ORG_INDEX}


# ---------------------------------------------------------------- KMS grants
@ht_register("aws.htbp.kms.grant_grantee_trust_boundary", "aws", "least_privilege", "kms_grant",
             "KMS grant on a customer managed key names no grantee outside the organization", "high", "AC-3",
             "Revoke grants (RevokeGrant / RetireGrant) whose GranteePrincipal belongs to an account outside the organization; "
             "grants are not shown in the key policy and keep working until revoked.",
             pages=[AWS + "aws-persistence/aws-kms-persistence/README.md",
                    AWS + "aws-privilege-escalation/aws-kms-privesc/README.md"],
             dependencies=["kms_grant", "organization_account"])
def kms_grant(item, index):
    get(item, "GrantId", str)
    party = _principal_account(get(item, "GranteePrincipal", str))
    operations = get(item, "Operations", list)
    if party is None:
        return result(False, grantee="service_principal", grantee_principal=item["GranteePrincipal"])
    return _verdict({party}, index, grantee_principal=item["GranteePrincipal"], operations=operations,
                    key_arn=item.get("KeyArn"), constrained=bool(item.get("ConstraintKeys")))


def _grant(grantee):
    return {"GrantId": "g" * 64, "KeyId": "k1", "KeyArn": "arn:aws:kms:us-east-1:%s:key/k1" % ACCOUNT,
            "GranteePrincipal": grantee, "Operations": ["Decrypt"], "IssuingAccount": "arn:aws:iam::%s:root" % ACCOUNT}


CASES["aws.htbp.kms.grant_grantee_trust_boundary"] = {
    "pass": _grant("arn:aws:iam::%s:role/app" % ACCOUNT),
    "pass_service": _grant("dynamodb.us-east-1.amazonaws.com"),
    "fail": _grant("arn:aws:iam::%s:role/x" % OUTSIDER),
    "missing": {"GrantId": "g" * 64, "KeyId": "k1"},
    "malformed": _grant(["arn:aws:iam::%s:role/app" % ACCOUNT]),
    "index": ORG_INDEX}


# ---------------------------------------------------------------- OpenSearch cross-cluster connections
_LIVE = {"PENDING_ACCEPTANCE", "VALIDATING", "APPROVED", "PROVISIONING", "ACTIVE"}
_ENDED = {"VALIDATION_FAILED", "REJECTING", "REJECTED", "DELETING", "DELETED"}


@ht_register("aws.htbp.opensearch.connection_peer_trust_boundary", "aws", "exposure", "opensearch_connection",
             "OpenSearch cross-cluster connection peers with a domain inside the organization", "medium", "AC-4",
             "Delete or reject cross-cluster connections whose peer domain owner is outside the organization "
             "(DeleteOutboundConnection / RejectInboundConnection).",
             pages=[AWS + "aws-post-exploitation/aws-opensearch-cross-account-post-exploitation/README.md"],
             dependencies=["opensearch_connection", "organization_account"])
def opensearch_connection(item, index):
    direction = get(item, "Direction", str)
    if direction not in ("inbound", "outbound"):
        raise Unavailable("unrecognized connection direction")
    status = get(item, "StatusCode", str)
    if status in _ENDED:
        return "NOT_APPLICABLE", {"status": status}
    if status not in _LIVE:
        raise Unavailable("unrecognized connection status")
    # The connection goes from LocalDomainInfo (requester) to RemoteDomainInfo (acceptor) in both listings.
    peer = get(item, ("RemoteDomainInfo" if direction == "outbound" else "LocalDomainInfo") + ".AWSDomainInformation", dict)
    owner = get(peer, "OwnerId", str)
    if not _ACCOUNT.fullmatch(owner):
        raise Unavailable("malformed peer OwnerId")
    return _verdict({owner}, index, direction=direction, status=status, peer_domain=peer.get("DomainName"),
                    connection_mode=item.get("ConnectionMode"))


def _connection(owner, status="ACTIVE", direction="outbound"):
    local = {"AWSDomainInformation": {"OwnerId": ACCOUNT, "DomainName": "logs", "Region": "us-east-1"}}
    remote = {"AWSDomainInformation": {"OwnerId": owner, "DomainName": "peer", "Region": "us-east-1"}}
    if direction == "inbound":
        local, remote = remote, local
    return {"ConnectionId": "conn-0123456789", "Direction": direction, "StatusCode": status,
            "LocalDomainInfo": local, "RemoteDomainInfo": remote, "ConnectionMode": "DIRECT"}


CASES["aws.htbp.opensearch.connection_peer_trust_boundary"] = {
    "pass": _connection(ORG_PEER),
    "fail": _connection(OUTSIDER, "PENDING_ACCEPTANCE"),
    "fail_inbound": _connection(OUTSIDER, direction="inbound"),
    "not_applicable": _connection(OUTSIDER, "DELETED"),
    "missing": {"ConnectionId": "conn-0123456789", "Direction": "outbound", "StatusCode": "ACTIVE"},
    "malformed": _connection("attacker"),
    "index": ORG_INDEX}
