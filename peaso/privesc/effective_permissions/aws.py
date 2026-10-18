"""AWS effective permissions from get_account_authorization_details snapshots.

Semantics implemented (identity-based evaluation within an account):
  * inline + managed policies, inherited from IAM groups for users,
  * Action / NotAction and Resource / NotResource with case-insensitive action
    globbing and case-sensitive resource globbing,
  * explicit Deny beats Allow; a Deny with a Condition makes the edge conditional,
  * Allow with a Condition (or a policy variable) -> conditional,
  * permissions boundaries (intersection) and SCPs at every level of the
    account's organization path (account, OUs, root) when the snapshot carries the
    OU parents / inherited policies; otherwise only the directly attached SCPs are
    evaluated and edges stay conditional (inherited_scps_not_evaluated),
  * resource control policies (rcp_policy, or scp_policy items typed RESOURCE_CONTROL_POLICY): their Deny
    statements apply to requests for resources of the attached account / OUs / root, for the RCP-supported
    services only; not collected -> coverage note only (RCPs are rare and deny-only),
  * session policies are not modelled: they only narrow an assumed session, and the attacker who
    controls a principal can obtain a session without one,
  * resource-based policies where collected (lambda, s3, kms, sns, sqs, secrets
    manager, ecr): same-account grants may come from either side, cross-account
    needs both, KMS needs the key policy to grant or delegate to the account, and an
    explicit Deny on either side wins,
  * role trust policies for selectors, plus the same-account trust policy grant
    for sts:AssumeRole when the trust names the source ARN directly.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import re
from urllib.parse import unquote, urlsplit

from . import (ANY, AllTargets, Grant, Model, Node, as_list, combine, downgrade, glob_match, inventory_status,
               items, unavailable)
from . import best as _BEST
from .aws_conditions import (ABSENT, CHOSEN, Context, evaluate as evaluate_condition, principal_dependent, resource_dependent,
                             substitute)
from ..schema import flatten_requirements

ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
BUILTIN_MANAGED = {
    # Used only when an attached AWS-managed policy document is absent from the snapshot.
    ADMIN_POLICY: [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    "arn:aws:iam::aws:policy/IAMFullAccess": [{"Effect": "Allow", "Action": ["iam:*", "organizations:DescribeAccount",
        "organizations:DescribeOrganization", "organizations:DescribeOrganizationalUnit", "organizations:DescribePolicy",
        "organizations:ListAccounts", "organizations:ListAWSServiceAccessForOrganization", "organizations:ListDelegatedAdministrators",
        "organizations:ListPolicies", "organizations:ListPoliciesForTarget", "organizations:ListRoots", "organizations:ListTargetsForPolicy"],
        "Resource": "*"}],
    "arn:aws:iam::aws:policy/PowerUserAccess": [
        {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["iam:CreateServiceLinkedRole", "iam:DeleteServiceLinkedRole", "iam:ListRoles",
         "organizations:DescribeOrganization", "account:ListRegions", "account:GetAccountInformation"], "Resource": "*"}],
}
SERVICE_PRINCIPALS = {"ecs": "ecs-tasks.amazonaws.com", "apprunner": "tasks.apprunner.amazonaws.com",
                      "cognito-identity": "cognito-identity.amazonaws.com", "emr": "elasticmapreduce.amazonaws.com",
                      "elasticbeanstalk": "elasticbeanstalk.amazonaws.com", "datapipeline": "datapipeline.amazonaws.com"}
ASSUME_ACTIONS = {"sts:assumerole", "sts:tagsession", "sts:setsourceidentity"}
HOST_KIND = {"lambda": "lambda_function", "lambda_function": "lambda_function", "ec2": "ec2_instance",
             "ec2_instance": "ec2_instance", "servicecatalog_product": "servicecatalog_product",
             "codebuild": "codebuild_project", "codebuild_project": "codebuild_project", "glue_job": "glue_job",
             "glue": "glue_job", "redshift_cluster": "redshift_cluster", "rds_db_instance": "rds_instance",
             "sagemaker_notebook_instance": "sagemaker_notebook_instance",
             "redshift_serverless_workgroup": "redshift_serverless_workgroup",
             "imagebuilder_pipeline": "imagebuilder_pipeline", "sagemaker_user_profile": "sagemaker_user_profile",
             "sagemaker_cluster": "sagemaker_cluster", "cognito_identity_pool": "cognito_identity_pool"}
# Collected workload inventories: collection type -> host kind (see AwsModel._load_workload_hosts).
WORKLOAD_HOSTS = {"codebuild_project": "codebuild_project", "glue_job": "glue_job",
                  "redshift_cluster": "redshift_cluster", "rds_instance": "rds_instance",
                  "sagemaker_notebook_instance": "sagemaker_notebook_instance",
                  "imagebuilder_pipeline": "imagebuilder_pipeline", "sagemaker_user_profile": "sagemaker_user_profile",
                  "sagemaker_cluster": "sagemaker_cluster"}
# Selector -> host map (role -> resource ARNs, see AwsModel._load_ext_hosts) deciding the selector and its
# {target.attached_resource_arn}.
SELECTOR_HOSTS = {"cognito_user_pool_group_role_covered_by": "cognito_user_pool_group",
                  "cognito_user_pool_covered_by": "cognito_user_pool_identity_pool",
                  "codedeploy_group_instance_role_covered_by": "codedeploy_deployment_group",
                  "rolesanywhere_profile_includes_target": "rolesanywhere_profile"}
# service_plane value -> collected inventory of that application plane (aws_service_plane_admin targets).
SERVICE_PLANES = {"connect": "connect_instance", "grafana": "grafana_workspace", "quicksight": "quicksight_user",
                  "scn": "supplychain_instance", "amplifybackend": "amplify_app"}
# Resource types whose roles may trust any of several service principals.
# Services supported by resource control policies (AWS Organizations RCPs).
RCP_SERVICES = frozenset({"s3", "sts", "kms", "sqs", "secretsmanager", "ecr", "aoss", "cognito-identity", "dynamodb", "logs"})
RESOURCE_TYPE_SERVICES = {"redshift_serverless_workgroup": ("redshift.amazonaws.com", "redshift-serverless.amazonaws.com")}
# Redshift Serverless namespace iamRoles entries are ARNs or "IamRole(applyStatus=..., iamRoleArn=arn:...)" strings.
_IAM_ROLE_RE = re.compile(r"arn:aws[\w-]*:iam::\d{12}:role/[\w+=,.@/-]+")
EKS_ACCESS_ENTRY_MODES = ("API", "API_AND_CONFIG_MAP")

# A reviewed IAM-user access key has the user's full effective rights. STS and
# application sessions are deliberately excluded: their session policy may narrow
# the subject's rights, so they cannot be represented by an aws_role edge here.
_EXACT_USER_CREDENTIAL_ACTIONS = {
    "aws-apprunner-plaintext-credential": ("apprunner", frozenset({"apprunner:describeservice"})),
    "aws-lambda-getconfig-secret-identity": ("lambda", frozenset({"lambda:getfunctionconfiguration"})),
    "aws-codebuild-plaintext-env-credential": ("codebuild", frozenset({"codebuild:batchgetprojects", "codebuild:batchgetbuilds"})),
}


def _doc(value):
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value))
        except (ValueError, TypeError):
            return None
    return value if isinstance(value, dict) else None


def _account(arn, default=""):
    parts = str(arn).split(":")
    return parts[4] if len(parts) > 5 and parts[4] else default


_DICT_VALUES = type({}.values())
_GLOB_START = re.compile(r"[*?]|\$\{")
_SCOPE_PH = re.compile(r"\{([a-z_.]+)\}")


class Statement:
    __slots__ = ("effect", "actions", "notaction", "resources", "notresource", "conditional", "ref", "principals",
                 "condition", "variables", "principal_dep", "resource_dep", "_rcache")

    def __init__(self, raw, ref):
        self.effect = str(raw.get("Effect", "")).lower()
        self.notaction = "NotAction" in raw
        self.actions = [str(a) for a in as_list(raw.get("NotAction" if self.notaction else "Action"))]
        self.notresource = "NotResource" in raw
        self.resources = [str(r) for r in as_list(raw.get("NotResource" if self.notresource else "Resource", "*"))]
        self.variables = any("${" in r for r in self.resources)
        self.condition = raw.get("Condition") or None
        # conditional: the statement has a Condition or a policy variable; it is EVALUATED per request context
        # (aws_conditions) and only the undecidable remainder keeps an edge conditional.
        self.conditional = bool(self.condition) or self.variables
        self.principal_dep = self.conditional and principal_dependent(self.condition, self.resources if self.variables else ())
        self.resource_dep = bool(self.condition) and resource_dependent(self.condition)
        self.ref = ref
        self.principals = raw.get("Principal", raw.get("NotPrincipal"))
        self._rcache = {}  # resource -> match; statements are shared by every principal of a policy

    def action_matches(self, action):
        hit = any(glob_match(p, action) for p in self.actions)
        return not hit if self.notaction else hit

    def resource_matches(self, resource):
        if resource is ANY:
            return True
        hit = self._rcache.get(resource)
        if hit is None:
            hit = any(_resource_glob(p, resource) for p in self.resources)
            hit = self._rcache[resource] = not hit if self.notresource else hit
        return hit

    def match(self, resource, ctx):
        """True / False / None (a ${variable} in Resource could not be resolved for this principal)."""
        if resource is ANY:
            return True
        if not self.variables:
            return self.resource_matches(resource)
        unresolved, patterns = False, []
        for pattern in self.resources:
            got = substitute(pattern, ctx) if "${" in pattern else pattern
            if got is None:
                unresolved, got = True, pattern
            patterns.append(got)
        hit = any(_resource_glob(p, resource) for p in patterns)
        hit = not hit if self.notresource else hit
        return None if unresolved and (hit or self.notresource) else hit

    def covers_all_resources(self):
        return not self.notresource and "*" in self.resources and not self.conditional


def _resource_glob(pattern, resource):
    if "${" in pattern:
        pattern = re.sub(r"\$\{[^}]*\}", "*", pattern)
    if pattern == "*":
        return True
    if "*" in resource or "?" in resource:  # requirement is itself a pattern: overlap test
        return glob_match(pattern, resource, False) or glob_match(resource, pattern, False)
    return glob_match(pattern, resource, False)


class Policy:
    __slots__ = ("id", "name", "statements", "_by_action", "keys", "universal", "customer_managed", "_indexed")

    def __init__(self, pid, name, document, kind):
        self.id, self.name = pid, name
        doc = _doc(document) or {}
        self.statements = [Statement(s, {"policy": pid, "policy_name": name, "policy_type": kind, "statement": i,
                                         "sid": s.get("Sid"), "effect": s.get("Effect")})
                           for i, s in enumerate(as_list(doc.get("Statement"))) if isinstance(s, dict)]
        self._by_action = {}
        self.keys, self.universal = set(), False
        self.customer_managed = kind == "managed" and ":aws:policy/" not in pid
        self._indexed = False

    def for_action(self, action):
        if action not in self._by_action:
            self._by_action[action] = [s for s in self.statements if s.action_matches(action)]
        return self._by_action[action]


class AwsModel(Model):
    provider = "aws"
    entity_kinds = ("aws_account_admin", "aws_identity_center_permission_set", "k8s_cluster_admin", "aws_directory_domain_admin",
                    "aws_service_plane_admin", "aws_verified_authority")

    def __init__(self, snapshot, catalog_keys=()):
        super().__init__(snapshot, catalog_keys)
        self.policies, self.accounts = {}, set()
        self.policy_versions = {}
        self.roles_by_name = {}
        self.trust = {}            # role arn -> list[Statement]
        self.trust_by_service, self.trust_by_arn, self.trust_by_account, self.trust_public = {}, {}, {}, {}
        self.trust_by_federated = {}
        self._trust_st = {}        # (role arn, statement index) -> conditional trust Statement
        self.tags = {}             # resource arn -> {tag key: value} (None when Tags were not collected)
        self.hosts = {}            # role arn -> {host kind: [resource arns]}
        self.host_status = {}      # (account, host kind) -> status
        self.scp = {}              # account -> list[Policy]
        self.scp_status = {}
        self.scp_by_target = {}    # account / OU / root id -> list[Policy]
        self.rcp_by_target = {}    # account / OU / root id -> list[Policy] (resource control policies)
        self.rcp_status = {}
        self.org_parent = {}       # account / OU id -> parent id
        self.inherited = {}        # account -> (status, set of OU/root ids carrying inherited SCPs)
        self.resource_policies = {}  # resource arn -> (account, [Statement], kind)
        self.ecr = {}              # account -> [(repository arn, imageTagMutability)]
        self.ecr_status = {}
        self._stmt_cache, self._possible_cache = {}, {}
        self._load()
        from .aws_s3_self_grant import load as load_s3_self_grant
        self.s3_self_grant_targets, self.s3_self_grant_records = load_s3_self_grant(self)
        from .aws_s3_access_grants import load as load_s3_access_grants
        self.s3_access_grant_targets, self.s3_access_grant_records = load_s3_access_grants(self)
        from .aws_scoped_grants import load as load_scoped_grants
        self.scoped_grants = load_scoped_grants(self)
        for account in sorted(self.accounts):
            for foothold in ("anonymous", "runtime", "local", "application", "endpoint"):
                source_id = f"aws_challenge_foothold:{account}:{foothold}"
                self.principals[source_id] = Node(source_id, "aws_challenge_foothold", "aws", account,
                    f"Unverified {foothold} foothold in {account}",
                    attrs={"account": account, "policy_ids": []}, perm_key=source_id)
        # These records are deliberately absent from ordinary AWS snapshots. A future collector or
        # reviewed external evidence importer must name the exact source, target and technique.
        self.challenge_evidence = {}
        self.bounded_evidence_records = {}
        # These v4 credential paths reach an IAM user only when a reviewed record
        # identifies the actual access-key subject and the resource that exposed it.
        # Keep every record: conflicting attestations must not be last-write-wins.
        self.credential_evidence = {}
        for scope, item in items(snapshot, "aws_privesc_challenge_evidence"):
            if not isinstance(item, dict):
                continue
            technique, source, kind, target = (item.get(k) for k in
                ("TechniqueId", "SourceArn", "TargetKind", "TargetId"))
            if not all(isinstance(x, str) and x for x in (technique, source, kind, target)):
                continue
            if kind not in ("aws_role", "aws_user", "aws_verified_authority"):
                continue
            account = scope.split("/")[0]
            if kind == "aws_verified_authority" and item.get("TargetAccount") != account:
                continue
            if kind in ("aws_role", "aws_user") and _account(target) != account:
                continue
            key = (technique, source, kind, target)
            self.challenge_evidence[key] = item
            self.bounded_evidence_records.setdefault(key, []).append((scope, item))
            if technique in _EXACT_USER_CREDENTIAL_ACTIONS:
                self.credential_evidence.setdefault(key, []).append((scope, item))
        self.require_collections(("iam_user", "iam_group", "iam_role", "iam_policy"), {
            "iam_user": "Users and their inherited permissions are unknown", "iam_group": "Group-inherited permissions are unknown",
            "iam_role": "Role targets and trust policies are unknown", "iam_policy": "Managed policy documents are unknown"})
        for account in sorted(self.accounts):
            status = self.scp_status.get(account, "not_collected")
            if status not in ("collected", "empty"):
                self.add_coverage("guardrail", account, status, "scp_policy not evaluated",
                                  "Edges are conditional: service control policies may deny them")
            elif status == "collected" and not self._scp_levels(account)[1]:
                self.add_coverage("guardrail", account, "partial", "only directly attached SCPs evaluated",
                                  "Edges are conditional: SCPs inherited from OUs/root were not collected "
                                  "(needs organization_parent {ChildId, ParentId} or scp_policy.InheritedPolicies)")
            if status == "collected" and self.rcp_status.get(account) not in ("collected", "empty"):
                self.add_coverage("guardrail", account, self.rcp_status.get(account, "not_collected"), "rcp_policy not evaluated",
                                  "Resource control policies (S3, STS, KMS, SQS, Secrets Manager, ...) may deny "
                                  "edges; they are assumed absent")

    # ------------------------------------------------------------------ load
    def _load(self):
        snap = self.snapshot
        for scope, item in items(snap, "iam_policy"):
            arn = item.get("Arn")
            if not arn:
                continue
            default = next((v.get("Document") for v in as_list(item.get("PolicyVersionList"))
                            if isinstance(v, dict) and v.get("IsDefaultVersion")), None)
            self.policies[arn] = Policy(arn, item.get("PolicyName", arn), default, "managed")
            self.policy_versions[arn] = item.get("PolicyVersionList")
        groups = {}
        for scope, item in items(snap, "iam_group"):
            node = self._principal(item, "aws_group", scope, item.get("GroupName"), "GroupPolicyList")
            if node:
                groups[(node.scope, item.get("GroupName"))] = node
        for scope, item in items(snap, "iam_role"):
            node = self._principal(item, "aws_role", scope, item.get("RoleName"), "RolePolicyList")
            if not node:
                continue
            node.attrs["instance_profiles"] = ([p.get("Arn") for p in as_list(item.get("InstanceProfileList")) if isinstance(p, dict)]
                                               if "InstanceProfileList" in item else None)
            node.attrs["path"] = item.get("Path", "/")
            self.roles_by_name[(node.scope, item.get("RoleName"))] = node
            self._index_trust(node, _doc(item.get("AssumeRolePolicyDocument")))
        for scope, item in items(snap, "iam_user"):
            node = self._principal(item, "aws_user", scope, item.get("UserName"), "UserPolicyList")
            if not node:
                continue
            member_of = [groups.get((node.scope, g)) for g in as_list(item.get("GroupList"))]
            node.attrs["groups"] = [g.id for g in member_of if g]
            for name, group in zip(as_list(item.get("GroupList")), member_of):
                if group is None:
                    node.incomplete.append(f"group {name} not collected")
                else:
                    node.attrs["policy_ids"] = node.attrs["policy_ids"] + group.attrs["policy_ids"]
                    node.incomplete.extend(group.incomplete)
            login = item.get("LoginProfile")
            node.attrs["login_profile"] = (None if not isinstance(login, dict) else False if login.get("absent")
                                           else True if "LoginProfile" in login else None)
        for node in self.principals.values():
            node.attrs["policy_ids"] = tuple(dict.fromkeys(node.attrs["policy_ids"]))
            node.perm_key = (node.attrs["policy_ids"], node.attrs.get("boundary"), node.scope)
        # Workload attachments (hosts of a role), when collected.
        profile_roles = {}
        for role in self.principals.values():
            for profile in role.attrs.get("instance_profiles") or []:
                profile_roles.setdefault(profile, []).append(role.id)
        for scope, item in items(snap, "lambda_function"):
            role = item.get("Role")
            if role:
                self.hosts.setdefault(role, {}).setdefault("lambda_function", []).append(item.get("FunctionArn"))
        self.instances = {}        # instance arn -> (account, region, instance id, state name or None)
        for scope, item in items(snap, "instance"):
            profile = (item.get("IamInstanceProfile") or {}).get("Arn")
            account = item.get("AccountId") or scope.split("/")[0]
            region = item.get("Region") or (scope.split("/")[1] if "/" in scope else "*")
            arn = f"arn:aws:ec2:{region}:{account}:instance/{item.get('InstanceId')}"
            state = item.get("State")
            state = state.get("Name") if isinstance(state, dict) else state
            self.instances[arn] = (account, region, item.get("InstanceId"), str(state).lower() if state else None)
            self.tags[arn] = _tags(item.get("Tags"))
            for role in profile_roles.get(profile, []):
                self.hosts.setdefault(role, {}).setdefault("ec2_instance", []).append(arn)
        self.ssm_managed = {}      # (account, instance id) -> PingStatus
        for scope, item in items(snap, "ssm_managed_instance"):
            if item.get("InstanceId"):
                account = item.get("AccountId") or scope.split("/")[0]
                self.ssm_managed[(account, item["InstanceId"])] = str(item.get("PingStatus") or "Online")
        self.region_status = {kind: inventory_status(snap, kind) for kind in
                              ("instance", "ssm_managed_instance", "ecs_cluster", "ecs_task_definition", "eks_cluster")}
        self._load_ecs(snap)
        self._load_eks(snap)
        self._load_org(snap)
        self._load_federation_and_catalog(snap)
        partial = self._load_workload_hosts(snap) | self._load_serverless_hosts(snap) | self._load_ext_hosts(snap)
        for kind, host in (("lambda_function", "lambda_function"), ("instance", "ec2_instance"), *WORKLOAD_HOSTS.items(),
                           ("redshiftserverless_workgroup", "redshift_serverless_workgroup"),
                           ("redshiftserverless_namespace", "redshift_serverless_workgroup")):
            for scope, status in inventory_status(snap, kind).items():
                # Regions are separate collections: any unavailable region makes the account's inventory partial.
                key = (scope.split("/")[0], host)
                if self.host_status.get(key) in (None, "collected", "empty"):
                    self.host_status[key] = "partial" if key in partial else status
        for scope, status in inventory_status(snap, "scp_policy").items():
            self.scp_status[scope.split("/")[0]] = status
        for scope, status in inventory_status(snap, "rcp_policy").items():
            self.rcp_status[scope.split("/")[0]] = status
        for kind in ("rcp_policy", "scp_policy"):
            for scope, item in items(snap, kind):
                summary = (item.get("Detail") or {}).get("Policy", {}).get("PolicySummary") or {}
                if kind == "scp_policy" and "RESOURCE_CONTROL" not in str(item.get("Type") or summary.get("Type") or "").upper():
                    continue
                content = ((item.get("Detail") or {}).get("Policy") or {}).get("Content") or item.get("Content")
                target = str(item.get("TargetId") or scope.split("/")[0])
                bucket = self.rcp_by_target.setdefault(target, [])
                pid = "rcp:" + str(item.get("Id"))
                if all(p.id != pid for p in bucket):
                    bucket.append(Policy(pid, item.get("Name", item.get("Id")), content, "rcp"))
                if kind == "scp_policy":
                    self.rcp_status.setdefault(scope.split("/")[0], "collected")
        for scope, item in items(snap, "scp_policy"):
            summary = (item.get("Detail") or {}).get("Policy", {}).get("PolicySummary") or {}
            if "RESOURCE_CONTROL" in str(item.get("Type") or summary.get("Type") or "").upper():
                continue
            account = item.get("TargetId") or scope.split("/")[0]
            content = ((item.get("Detail") or {}).get("Policy") or {}).get("Content")
            policy = Policy("scp:" + str(item.get("Id")), item.get("Name", item.get("Id")), content, "scp")
            self.scp.setdefault(account, []).append(policy)
            self.scp_by_target.setdefault(str(account), []).append(policy)
            inherited = item.get("InheritedPolicies")
            if isinstance(inherited, dict):
                owner = scope.split("/")[0]
                status = inherited.get("collection_status", "collected" if "items" in inherited else "unknown")
                previous = self.inherited.get(owner, (status, set()))
                ok = previous[0] in ("collected", "empty") and status in ("collected", "empty")
                levels = previous[1]
                for parent in as_list(inherited.get("items")):
                    if not isinstance(parent, dict) or not parent.get("TargetId"):
                        continue
                    pcontent = parent.get("Content") or ((parent.get("Detail") or {}).get("Policy") or {}).get("Content")
                    pid = "scp:" + str(parent.get("Id"))
                    bucket = self.scp_by_target.setdefault(str(parent["TargetId"]), [])
                    if all(p.id != pid for p in bucket):
                        bucket.append(Policy(pid, parent.get("Name", parent.get("Id")), pcontent, "scp"))
                    levels.add(str(parent["TargetId"]))
                self.inherited[owner] = (status if ok or owner not in self.inherited else "partial", levels)
        for scope, item in items(snap, "organization_parent"):
            child, parent = item.get("ChildId") or item.get("Id"), item.get("ParentId")
            if child and parent:
                self.org_parent[str(child)] = str(parent)
        for scope, item in items(snap, "organization_account"):
            parents = item.get("Parents")
            parents = parents.get("items") if isinstance(parents, dict) else parents
            parent = item.get("ParentId") or next((p.get("Id") for p in as_list(parents) if isinstance(p, dict) and p.get("Id")), None)
            if item.get("Id") and parent:
                self.org_parent.setdefault(str(item["Id"]), str(parent))
        self._load_resource_policies(snap)
        for node in self.principals.values():
            # Policies whose outcome depends on who the principal is (aws:PrincipalArn/Tag, ${aws:username}, ...)
            # cannot be shared between principals with the same policy set.
            if self._principal_dependent(node):
                node.perm_key = tuple(node.perm_key) + (node.id,)
        self._index_resource_grantees()

    def _load_resource_policies(self, snap):
        def add(arn, account, document, kind):
            doc = _doc(document.get("Policy") if isinstance(document, dict) and "Statement" not in document else document)
            if not arn or not doc:
                return
            statements = [Statement(raw, {"policy": f"{arn}#resource-policy", "policy_type": "resource", "statement": i,
                                          "sid": raw.get("Sid"), "effect": raw.get("Effect"),
                                          **({"not_principal": True} if "NotPrincipal" in raw else {})})
                          for i, raw in enumerate(as_list(doc.get("Statement"))) if isinstance(raw, dict)]
            self.resource_policies[arn] = (account, statements, kind)

        for scope, item in items(snap, "lambda_function"):
            add(item.get("FunctionArn"), scope.split("/")[0], (item.get("Policy") or {}).get("Policy"), "lambda")
        for scope, item in items(snap, "bucket"):
            if item.get("Name"):
                add(f"arn:aws:s3:::{item['Name']}", scope.split("/")[0], (item.get("Policy") or {}).get("Policy"), "s3")
        for scope, item in items(snap, "kms_key"):
            arn = item.get("KeyArn") or (((item.get("Metadata") or {}).get("KeyMetadata") or {}).get("Arn"))
            add(arn, scope.split("/")[0], (item.get("Policy") or {}).get("Policy"), "kms")
        for scope, item in items(snap, "sns_topic"):
            attrs = (item.get("Attributes") or {}).get("Attributes") or {}
            add(item.get("TopicArn") or attrs.get("TopicArn"), scope.split("/")[0], attrs.get("Policy"), "sns")
        for scope, item in items(snap, "sqs_queue"):
            attrs = (item.get("Attributes") or {}).get("Attributes") or {}
            add(attrs.get("QueueArn"), scope.split("/")[0], attrs.get("Policy"), "sqs")
        for scope, item in items(snap, "secret"):
            add(item.get("ARN"), scope.split("/")[0], (item.get("Policy") or {}).get("ResourcePolicy"), "secretsmanager")
        for scope, item in items(snap, "ecr_repository"):
            arn = item.get("repositoryArn")
            add(arn, scope.split("/")[0], (item.get("Policy") or {}).get("policyText"), "ecr")
            if arn:
                self.ecr.setdefault(scope.split("/")[0], []).append((arn, str(item.get("imageTagMutability") or "MUTABLE").upper()))
        for scope, status in inventory_status(snap, "ecr_repository").items():
            account = scope.split("/")[0]
            if self.ecr_status.get(account) in (None, "collected", "empty"):
                self.ecr_status[account] = status

    # ---------------------------------------------------- workload inventories
    def _load_ecs(self, snap):
        """ECS clusters, EC2-capable task definitions per task role and (when collected) task placement."""
        self.ecs_clusters, self.ecs_task_definitions = {}, {}
        self.ecs_cluster_info = {}     # cluster arn -> {account, count, instances: {ci arn: ec2 id}|None, tasks: [..]|None}
        self.ecs_task_roles = {}       # role arn -> [(account, task definition arn, ec2 capable)]
        self.ecs_taskdef_role = {}     # task definition arn -> task role arn
        for scope, item in items(snap, "ecs_task_definition"):
            account = item.get("AccountId") or scope.split("/")[0]
            self.ecs_task_definitions[account] = self.ecs_task_definitions.get(account, 0) + 1
            td = (item.get("Definition") or {}).get("taskDefinition") if isinstance(item.get("Definition"), dict) else None
            td = td or item.get("taskDefinition") or item
            role, tdarn = td.get("taskRoleArn"), td.get("taskDefinitionArn") or item.get("taskDefinitionArn") or item.get("id")
            compat = [str(c).upper() for c in as_list(td.get("compatibilities")) or as_list(td.get("requiresCompatibilities"))]
            ec2 = not compat or "EC2" in compat or "EXTERNAL" in compat  # no compatibility list: EC2 is the default launch type
            if tdarn and role:
                self.ecs_taskdef_role[str(tdarn)] = str(role)
            if role:
                self.ecs_task_roles.setdefault(str(role), []).append((account, tdarn, ec2))
        extra_ci, extra_tasks = {}, {}
        for scope, item in items(snap, "ecs_container_instance"):
            if item.get("clusterArn"):
                extra_ci.setdefault(item["clusterArn"], []).append(item)
        for scope, item in items(snap, "ecs_task"):
            if item.get("clusterArn"):
                extra_tasks.setdefault(item["clusterArn"], []).append(item)
        ci_status = inventory_status(snap, "ecs_container_instance")
        task_status = inventory_status(snap, "ecs_task")
        for scope, item in items(snap, "ecs_cluster"):
            account = item.get("AccountId") or scope.split("/")[0]
            count = _container_instances(item)
            self.ecs_clusters.setdefault(account, []).append(count)
            arn = item.get("clusterArn") or item.get("id")
            if not arn:
                continue
            instances = _sub_items(item, "ContainerInstances")
            if instances is None and arn in extra_ci:
                instances = extra_ci[arn]
            if instances is None and ci_status.get(scope) in ("collected", "empty"):
                instances = []
            tasks = _sub_items(item, "Tasks")
            if tasks is None and arn in extra_tasks:
                tasks = extra_tasks[arn]
            if tasks is None and task_status.get(scope) in ("collected", "empty"):
                tasks = []
            self.ecs_cluster_info[arn] = {
                "account": account, "count": count,
                "instances": None if instances is None else {
                    str(ci.get("containerInstanceArn")): str(ci.get("ec2InstanceId") or "") for ci in instances if isinstance(ci, dict)},
                "tasks": None if tasks is None else [t for t in tasks if isinstance(t, dict)]}

    def _load_eks(self, snap):
        self.eks = {}                  # cluster arn -> {name, account, region, mode, endpoint}
        for scope, item in items(snap, "eks_cluster"):
            detail = item.get("Cluster") if isinstance(item.get("Cluster"), dict) else {}
            cluster = detail.get("cluster") if isinstance(detail.get("cluster"), dict) else (item.get("cluster") or {})
            account = item.get("AccountId") or scope.split("/")[0]
            region = item.get("Region") or (scope.split("/")[1] if "/" in scope else "*")
            name = cluster.get("name") or item.get("name")
            arn = cluster.get("arn") or item.get("arn") or (name and f"arn:aws:eks:{region}:{account}:cluster/{name}")
            if not arn:
                continue
            mode = (cluster.get("accessConfig") or {}).get("authenticationMode") if isinstance(cluster.get("accessConfig"), dict) else None
            self.eks[arn] = {"name": name or arn.rsplit("/", 1)[-1], "account": _account(arn, account), "region": region,
                             "mode": str(mode).upper() if mode else None, "endpoint": cluster.get("endpoint")}
        self.eks_status = inventory_status(snap, "eks_cluster")
        self.related_eks = {}          # cluster arn -> K8s snapshot cluster id

    def _load_org(self, snap):
        """Organization accounts (organizations:ListAccounts) -> member accounts, management account, org id."""
        self.org_accounts, self.org_id, self.org_management = {}, None, None
        for scope, item in items(snap, "organization_account"):
            match = re.match(r"arn:[^:]+:organizations::(\d{12}):account/(o-[a-z0-9]+)/(\d{12})", str(item.get("Arn") or ""))
            if match:
                self.org_management, self.org_id = match.group(1), match.group(2)
            aid = str(item.get("Id") or (match.group(3) if match else ""))
            if aid:
                self.org_accounts[aid] = str(item.get("State") or item.get("Status") or "ACTIVE").upper()
        self.org_status = inventory_status(snap, "organization_account")

    def _org_known(self):
        return bool(self.org_status) and not unavailable(self.org_status) and self.org_management is not None

    def _load_federation_and_catalog(self, snap):
        """Optional inventories: IAM identity providers, EMR clusters, Service Catalog portfolios."""
        self.idp_status = {kind: inventory_status(snap, kind) for kind in ("iam_saml_provider", "iam_oidc_provider")}
        self.idps = {kind: {str(item.get("Arn")) for _, item in items(snap, kind) if item.get("Arn")}
                     for kind in ("iam_saml_provider", "iam_oidc_provider")}
        # Roles named directly in other roles' trust policies (role arn -> [trusted principal norm arns]).
        self.trust_names = {}
        for norm, roles in self.trust_by_arn.items():
            for rid in roles:
                self.trust_names.setdefault(rid, []).append(norm)
        self.emr_status = inventory_status(snap, "emr_cluster")
        self.emr_runtime_profiles = set()  # instance-profile names/ARNs of EMR clusters with a security configuration
        for _, item in items(snap, "emr_cluster"):
            cluster = (item.get("Cluster") or {}).get("Cluster") if isinstance(item.get("Cluster"), dict) else None
            cluster = cluster or item.get("Cluster") or item
            if not isinstance(cluster, dict) or not cluster.get("SecurityConfiguration"):
                continue
            profile = (cluster.get("Ec2InstanceAttributes") or {}).get("IamInstanceProfile")
            if profile:
                self.emr_runtime_profiles.add(str(profile).rsplit("/", 1)[-1])
        self.sc_status = inventory_status(snap, "servicecatalog_portfolio")
        self.sc_portfolios = {}        # launch role arn -> [portfolio arns]
        for scope, item in items(snap, "servicecatalog_portfolio"):
            detail = item.get("PortfolioDetail") if isinstance(item.get("PortfolioDetail"), dict) else item
            parn = detail.get("ARN") or detail.get("Arn")
            account = item.get("AccountId") or scope.split("/")[0]
            for constraint in as_list((item.get("Constraints") or {}).get("items") if isinstance(item.get("Constraints"), dict)
                                      else item.get("Constraints")):
                if not isinstance(constraint, dict) or str(constraint.get("Type", "")).upper() != "LAUNCH":
                    continue
                params = _doc(constraint.get("ConstraintParameters") or constraint.get("Parameters")) or {}
                role = params.get("RoleArn") or (params.get("LocalRoleName") and f"arn:aws:iam::{account}:role/{params['LocalRoleName']}")
                if role and parn:
                    self.sc_portfolios.setdefault(_norm_arn(role), []).append(parn)
                    product = constraint.get("ProductArn") or (constraint.get("ProductId") and
                                                               f"arn:aws:catalog:{scope.split('/')[1] if '/' in scope else '*'}:{account}:product/{constraint['ProductId']}")
                    if product:
                        for node in self.principals.values():
                            if node.kind == "aws_role" and _norm_arn(node.id) == _norm_arn(role):
                                self.hosts.setdefault(node.id, {}).setdefault("servicecatalog_product", []).append(product)
        for scope, status in self.sc_status.items():
            key = (scope.split("/")[0], "servicecatalog_product")
            if self.host_status.get(key) in (None, "collected", "empty"):
                self.host_status[key] = status
        # Cognito user pools and Roles Anywhere trust anchors: their absence is decisive when the finer joins
        # (_load_ext_hosts: group RoleArns, identity-pool role mappings, Roles Anywhere profiles) were not collected.
        self.presence_status, self.presence, self.trust_anchors = {}, {}, {}
        for kind in ("cognito_user_pool", "rolesanywhere_trust_anchor"):
            self.presence_status[kind] = inventory_status(snap, kind)
            for scope, item in items(snap, kind):
                account = str(item.get("AccountId") or scope.split("/")[0])
                self.presence.setdefault(kind, {}).setdefault(account, 0)
                self.presence[kind][account] += 1
                if kind == "rolesanywhere_trust_anchor" and item.get("trustAnchorArn") and item.get("enabled") is not False:
                    self.trust_anchors.setdefault(account, []).append(item["trustAnchorArn"])

    def _principal_dependent(self, node):
        policies = [self.policies[pid] for pid in node.attrs["policy_ids"]]
        boundary = self.policies.get(node.attrs.get("boundary") or "")
        if boundary is not None:
            policies.append(boundary)
        policies.extend(self.scp.get(node.scope, []))
        for level in self._scp_levels(node.scope)[0][1:]:
            policies.extend(self.scp_by_target.get(level, []))
        if self.rcp_by_target:  # RCPs of any account may apply to this principal's requests
            policies.extend(p for bucket in self.rcp_by_target.values() for p in bucket)
        return any(st.principal_dep for policy in policies for st in policy.statements)

    def _scp_levels(self, account):
        """(organization levels whose SCPs apply to the account, complete flag)."""
        inherited = self.inherited.get(account)
        if inherited and inherited[0] in ("collected", "empty"):
            return [account, *sorted(inherited[1])], True
        chain, node, seen = [account], account, {account}
        while node in self.org_parent:
            node = self.org_parent[node]
            if node in seen:
                break
            seen.add(node)
            chain.append(node)
            if node.startswith("r-"):
                return chain, True
        return [account], False

    def _resource_key(self, ref):
        if not isinstance(ref, str) or not self.resource_policies:
            return None
        if ref in self.resource_policies:
            return ref
        if ref.startswith("arn:aws:s3:::"):
            key = "arn:aws:s3:::" + ref[13:].split("/", 1)[0]
            return key if key in self.resource_policies else None
        if ":lambda:" in ref and ":function:" in ref:
            key = ":".join(ref.split(":")[:7])
            return key if key in self.resource_policies else None
        return None

    def _principal(self, item, kind, scope, name, inline_key):
        arn = item.get("Arn")
        if not arn or not name:
            return None
        account = item.get("AccountId") or _account(arn, scope.split("/")[0])
        self.accounts.add(account)
        ids, incomplete = [], []
        for inline in as_list(item.get(inline_key)):
            if isinstance(inline, dict):
                pid = f"{arn}#inline/{inline.get('PolicyName')}"
                self.policies[pid] = Policy(pid, inline.get("PolicyName"), inline.get("PolicyDocument"), "inline")
                ids.append(pid)
        for attached in as_list(item.get("AttachedManagedPolicies")):
            parn = attached.get("PolicyArn") if isinstance(attached, dict) else None
            if not parn:
                continue
            if parn not in self.policies:
                if parn in BUILTIN_MANAGED:
                    self.policies[parn] = Policy(parn, attached.get("PolicyName", parn), {"Statement": BUILTIN_MANAGED[parn]}, "managed")
                else:
                    incomplete.append(f"managed policy {parn} not collected")
                    continue
            ids.append(parn)
        boundary = (item.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
        tags = _tags(item.get("Tags")) if "Tags" in item else None
        node = Node(arn, kind, "aws", account, name, attrs={"arn": arn, "name": name, "account": account,
                    "policy_ids": ids, "boundary": boundary, "tags": tags}, incomplete=incomplete)
        self.tags[arn] = tags
        self.principals[arn] = node
        return node

    def _index_trust(self, role, doc):
        statements = []
        for i, raw in enumerate(as_list((doc or {}).get("Statement"))):
            if not isinstance(raw, dict):
                continue
            st = Statement(raw, {"policy": role.id + "#trust", "policy_type": "trust", "statement": i, "sid": raw.get("Sid"), "effect": raw.get("Effect")})
            statements.append(st)
            if st.effect != "allow" or not any(st.action_matches(a) for a in ("sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML")):
                continue
            principal = st.principals
            conf = "conditional" if st.conditional or "NotPrincipal" in raw else "derived"
            if st.conditional:
                self._trust_st[(role.id, i)] = st
            if principal == "*":
                principal = {"AWS": "*"}
            if not isinstance(principal, dict):
                continue
            service_conf = conf
            if st.condition and "NotPrincipal" not in raw and principal.get("Service"):
                # A service assumes the role on behalf of a resource the attacker creates in the role's account:
                # aws:SourceAccount is that account; aws:SourceArn names a specific resource (undecided).
                verdict, _ = evaluate_condition(st.condition, Context(action="sts:assumerole", resource=role.id, overrides={
                    "aws:sourceaccount": [role.scope], "aws:sourceowner": [role.scope]}))
                service_conf = None if verdict is False else "derived" if verdict is True else "conditional"
            for value in as_list(principal.get("Service")):
                if service_conf is None:
                    continue
                self.trust_by_service.setdefault(str(value).lower(), {})[role.id] = (service_conf, st.ref)
            for value in as_list(principal.get("Federated")):
                self.trust_by_federated.setdefault(str(value).lower(), {})[role.id] = (conf, st.ref)
                raw = self.__dict__.setdefault("trust_federated_raw", {}).setdefault(role.id, [])
                if str(value) not in raw:
                    raw.append(str(value))
            for value in as_list(principal.get("AWS")):
                value = str(value)
                if value == "*":
                    self.trust_public[role.id] = (conf, st.ref)
                elif re.fullmatch(r"\d{12}", value) or value.endswith(":root"):
                    self.trust_by_account.setdefault(_account(value, value), {})[role.id] = (conf, st.ref)
                else:
                    match = re.match(r"arn:[^:]+:sts::(\d{12}):assumed-role/([^/]+)", value)
                    if match:
                        value = f"arn:aws:iam::{match.group(1)}:role/{match.group(2)}"
                    self.trust_by_arn.setdefault(_norm_arn(value), {})[role.id] = (conf, st.ref)
        self.trust[role.id] = statements

    # ------------------------------------------------------------- interface
    def requirement_key(self, req):
        return str(req.get("action", "")).lower()

    def requirement_template(self, req):
        value = req.get("resource")
        return None if value in (None, "*") else value

    def possible(self, principal):
        key = principal.perm_key
        if key not in self._possible_cache:
            keys, universal = set(), False
            for pid in principal.attrs["policy_ids"]:
                policy = self.policies[pid]
                self._policy_keys(policy)
                keys |= policy.keys
                universal = universal or policy.universal
            for policy in self._rp_grants.get(principal.id, ()) + self._rp_public:
                # Resource policies that name the principal (or everyone) can grant without an identity policy.
                self._policy_keys(policy)
                keys |= policy.keys
            self._possible_cache[key] = (frozenset(keys), universal)
        return self._possible_cache[key]

    def _index_resource_grantees(self):
        """Principals named directly by a resource-policy Allow: their checks differ from principals with the
        same identity policies, so they get their own permission key; '*' grants reach everyone's prefilter."""
        by_norm = {}
        for node in self.principals.values():
            by_norm.setdefault(_norm_arn(node.id), []).append(node)
        named, public = {}, []
        for arn, (_account_id, statements, _kind) in self.resource_policies.items():
            for st in statements:
                if st.effect != "allow":
                    continue
                value = st.principals
                aws = [] if not isinstance(value, dict) else [str(v) for v in as_list(value.get("AWS"))]
                if value == "*" or "*" in aws or st.ref.get("not_principal"):
                    public.append(st)
                    continue
                for entry in aws:
                    for node in by_norm.get(_norm_arn(entry), ()):
                        named.setdefault(node.id, []).append(st)
        self._rp_grants = {}
        for pid, statements in named.items():
            policy = Policy(f"resource-grants:{pid}", "resource policy grants", None, "resource")
            policy.statements = statements
            self._rp_grants[pid] = (policy,)
            node = self.principals[pid]
            node.perm_key = tuple(node.perm_key) + (pid,)
        self._rp_public = ()
        if public:
            policy = Policy("resource-grants:*", "public resource policy grants", None, "resource")
            policy.statements = public
            self._rp_public = (policy,)

    def _policy_keys(self, policy):
        if policy._indexed:
            return
        by_service = getattr(self, "_keys_by_service", None)
        if by_service is None:
            by_service = self._keys_by_service = {}
            for key in self.catalog_keys:
                by_service.setdefault(key.split(":", 1)[0], set()).add(key)
        for st in policy.statements:
            if st.effect != "allow":
                continue
            if st.notaction:
                excluded = {k for k in self.catalog_keys if any(glob_match(p, k) for p in st.actions)}
                policy.keys |= set(self.catalog_keys) - excluded
                continue
            for pattern in st.actions:
                low = pattern.lower()
                if low in ("*", "*:*"):
                    policy.universal = True
                    continue
                service, _, action = low.partition(":")
                if "*" in service or "?" in service:
                    policy.keys |= {k for k in self.catalog_keys if glob_match(low, k)}
                elif "*" in action or "?" in action:
                    policy.keys |= {k for k in by_service.get(service, ()) if glob_match(low, k)}
                elif low in self.catalog_keys:
                    policy.keys.add(low)
        policy._indexed = True

    def _statements(self, principal, action):
        key = (principal.perm_key, action)
        if key not in self._stmt_cache:
            allows, denies = [], []
            for pid in principal.attrs["policy_ids"]:
                for st in self.policies[pid].for_action(action):
                    (allows if st.effect == "allow" else denies).append(st)
            self._stmt_cache[key] = (allows, denies)
        return self._stmt_cache[key]

    def _cond(self, st, ctx, effect):
        """(True | False | None, reasons) for a statement's Condition under the request context."""
        if not st.condition:
            return True, []
        if ctx is None:
            return None, ["condition_not_evaluated"]
        return evaluate_condition(st.condition, ctx, effect)

    def _deny_applies(self, deny, resource, ctx):
        """True (denies), False (does not apply) or None (undecidable) for one Deny statement."""
        if resource is ANY:
            if deny.notresource or "*" not in deny.resources:
                return False
            matched = True
        else:
            matched = deny.match(resource, ctx)
            if matched is False:
                return False
        verdict, _ = self._cond(deny, ctx, "deny")
        if verdict is False:
            return False
        return True if verdict is True and matched is True else None

    def _evaluate(self, allows, denies, resource, ctx=None):
        """Identity-style evaluation of one statement set; returns Grant or None.

        Conditions are evaluated (aws_conditions): an Allow whose condition provably fails does not grant, a Deny
        whose condition provably fails does not apply, and the cited statement is the one that actually grants
        (a proven one first, else the first undecided one)."""
        chosen, undecided = None, None
        for st in allows:
            matched = st.match(resource, ctx)
            if matched is False:
                continue
            verdict, why = self._cond(st, ctx, "allow")
            if verdict is False:
                continue
            if matched is None:
                verdict, why = None, list(why) + ["resource_variable_unresolved"]
            if verdict is True:
                chosen = (st, why)
                break
            if undecided is None:
                undecided = (st, why)
        if chosen is None and undecided is None:
            return None
        proven = chosen is not None
        best_allow, why = chosen or undecided
        ref = best_allow.ref
        if best_allow.conditional:
            ref = {**ref, "condition_evaluated": "satisfied" if proven else "undecided"}
        conf, conditions = ("derived", []) if proven else ("conditional", ["allow_statement_has_condition", *why[:3]])
        refs = [ref]
        for deny in denies:
            if resource is ANY and not (not deny.notresource and "*" in deny.resources):
                # Only a resource-wide deny removes "the permission on some resource" (or one covering the allow).
                if not best_allow.notresource and not deny.variables and all(
                        any(_resource_glob(d, r) for d in deny.resources) for r in best_allow.resources):
                    verdict, _ = self._cond(deny, ctx, "deny")
                    if verdict is True:
                        return None
                    if verdict is None:
                        conf = "conditional"
                        conditions.append("conditional_explicit_deny")
                        refs.append(deny.ref)
                continue
            applies = self._deny_applies(deny, resource, ctx)
            if applies is False:
                continue
            if applies is True:
                return None
            conf = "conditional"
            conditions.append("conditional_explicit_deny")
            refs.append(deny.ref)
        return Grant(conf, refs, conditions)

    # ----------------------------------------------------------- request context
    def _passed_to(self):
        """Services the current technique passes a role to (iam:PassedToService candidates)."""
        entry = self.current_entry or {}
        key = entry.get("id")
        cache = self.__dict__.setdefault("_passed_cache", {})
        if key not in cache:
            selector = self.current_selector or ((entry.get("target") or {}).get("selector") or {})
            services = [str(v).lower() for v in as_list(selector.get("trust_allows_service"))]
            for value in as_list(selector.get("attached_to_service")) + as_list(selector.get("via_resource_type")):
                low = str(value).lower()
                services.extend(RESOURCE_TYPE_SERVICES.get(low, (_service_principal(low),)))
                host = HOST_KIND.get(low)
                if host == "ec2_instance":
                    services.append("ec2.amazonaws.com")
                elif host == "lambda_function":
                    services.append("lambda.amazonaws.com")
            if entry.get("service") and not services:
                services.append(_service_principal(str(entry["service"]).lower()))
            cache[key] = tuple(dict.fromkeys(s for s in services if s))
        return cache[key]

    def _ctx(self, principal, action, ref):
        resource = None if ref is ANY or not isinstance(ref, str) else ref
        tags = self.tags.get(resource) if resource else None
        org = self.org_id if principal is not None and principal.scope in self.org_accounts else None
        return Context(principal=principal, action=action, resource=resource,
                       passed_to=self._passed_to() if action == "iam:passrole" else (), resource_tags=tags, org_id=org,
                       overrides=self._ctx_override)

    # ---------------------------------------------------- request_context (schema extension)
    _ctx_override = None  # {lower-cased condition key: [values] | ABSENT | CHOSEN} of the requirement being checked

    @staticmethod
    def request_context_key(req):
        """Hashable form of a requirement's request_context (None when absent)."""
        ctx = req.get("request_context") if isinstance(req, dict) else None
        if not ctx:
            return None
        return tuple(sorted((str(k).lower(), repr(v)) for k, v in ctx.items()))

    @staticmethod
    def request_context_choices(req):
        """Every override dict the requester can produce: a list value is a choice of ONE value, so the product of
        the list-valued keys is enumerated (schema caps it at MAX_CONTEXT_CHOICES)."""
        ctx = req.get("request_context") or {}
        options = [{}]
        for key, value in ctx.items():
            low = str(key).lower()
            if isinstance(value, dict):
                if value.get("absent"):
                    alts = [ABSENT]
                elif value.get("chosen"):
                    alts = [CHOSEN]
                else:
                    alts = [[str(v) for v in value.get("values") or []]]
            elif isinstance(value, list):
                alts = [[str(v)] for v in value]
            else:
                alts = [[str(value)]]
            options = [{**o, low: a} for o in options for a in alts]
        return options

    def _with_context(self, req, fn):
        """best() of fn() over the requirement's request-context choices (fn() alone without request_context)."""
        if not (isinstance(req, dict) and req.get("request_context")):
            return fn()
        previous, winner = self._ctx_override, None
        try:
            for choice in self.request_context_choices(req):
                self._ctx_override = choice
                got = fn()
                if got is not None and not isinstance(got, (dict, AllTargets)):
                    got = Grant(got.confidence, got.refs, got.conditions + ("request_context_" + _ctx_label(choice),))
                winner = _merge_choice(winner, got)
        finally:
            self._ctx_override = previous
        return winner

    # Verdicts that depend on the source only through (perm_key, kind) - perm_key carries the account, and the
    # principal id when its policies or a trust policy test principal keys or name it (see source_memo_key).
    memo_safe_selectors = frozenset({
        "resource_permission_covers_target", "attached_resource_covered_by", "any_principal_in_scope",
        "trust_allows_principal_of_source", "source_kind",
        "precondition:target_in_other_account", "precondition:source_in_org_management_account"})

    def source_memo_key(self, source):
        """perm_key already carries the principal id when its policies test principal keys or a resource policy
        names it; trust policies naming it (or testing principal keys) also make its verdicts its own."""
        if source.perm_key is None:
            return None
        named = self.__dict__.get("_trust_named")
        if named is None:
            named = self._trust_named = (set(self.trust_by_arn),
                                         any(st.principal_dep for st in self._trust_st.values()))
        if named[1] or _norm_arn(source.id) in named[0]:
            return (source.perm_key, source.kind, source.id)
        return (source.perm_key, source.kind)

    def cached_check(self, principal, req, ref):
        action = self.requirement_key(req)
        key = (principal.perm_key if principal.perm_key is not None else principal.id, action, ref,
               self._passed_to() if action == "iam:passrole" else None, self.request_context_key(req))
        if key not in self._check_cache:
            self._check_cache[key] = self.check(principal, req, ref)
        return self._check_cache[key]

    def check(self, principal, req, ref):
        action = self.requirement_key(req)
        return self._with_context(req, lambda: self._check_action(principal, action, ref))

    def check_bound(self, principal, reqs, templates):
        """Bound requirements (schema `bind`): find ONE concrete resource ARN every requirement holds on.

        Candidate ARNs are built from the requirement patterns and the Resource patterns of the Allow statements
        granting the actions (field-wise unification of ARN segments, remaining wildcards filled with a token).
        A candidate proven for every requirement keeps the combined grant; when no candidate is proven but each
        requirement holds on its own pattern the result stays conditional (bound_resource_not_verified), exactly
        as the provider-neutral default."""
        patterns, req_refs = [], []
        for req, template in zip(reqs, templates):
            refs, floor = self.resolve(template, principal, None, selector=self.current_selector)
            if floor is not None:
                return Model.check_bound(self, principal, reqs, templates)
            req_refs.append([r for r in refs if r is not ANY])
            patterns.extend(r for r in refs if r is not ANY)
            allows, _ = self._statements(principal, self.requirement_key(req))
            for st in allows:
                if not st.notresource and not st.variables:
                    patterns.extend(p for p in st.resources if p != "*")
        patterns = list(dict.fromkeys(patterns))[:40]
        candidates = []
        for a in patterns:
            candidates.append(_instantiate(a))
            for b in patterns:
                if a is not b:
                    merged = _unify_arn(a, b)
                    if merged is not None:
                        candidates.append(_instantiate(merged))
        candidates = [c for c in dict.fromkeys(candidates)
                      if all(not refs or any(glob_match(r, c, False) for r in refs) for refs in req_refs)][:200]
        winner = None
        for cand in candidates:
            grants = []
            for req in reqs:
                got = self.cached_check(principal, req, cand)
                if got is None:
                    break
                grants.append(got)
            else:
                got = combine(*grants)
                winner = _BEST(winner, Grant(got.confidence, ({"bound_resource": cand},) + got.refs, got.conditions))
                if winner.confidence == "derived":
                    break
        if winner is not None:
            return winner
        return Model.check_bound(self, principal, reqs, templates)

    def _check_action(self, principal, action, ref):
        ctx = self._ctx(principal, action, ref)
        allows, denies = self._statements(principal, action)
        grant = self._evaluate(allows, denies, ref, ctx)
        rkey = self._resource_key(ref)
        if rkey is not None:
            grant = self._with_resource_policy(principal, action, ref, rkey, grant, denies, ctx)
        if grant is None:
            return None
        return self._guardrails(principal, action, ref, grant, ctx)

    def _with_resource_policy(self, principal, action, ref, rkey, identity, denies, ctx=None):
        account, statements, kind = self.resource_policies[rkey]
        direct, delegated, conditions = None, False, []
        for st in statements:
            if not st.action_matches(action) or st.match(ref, ctx) is False:
                continue
            match = _resource_principal(st, principal)
            if st.ref.get("not_principal"):
                match = None if match else "direct"  # NotPrincipal applies to everyone except the listed principals
            if match is None:
                continue
            verdict, _ = self._cond(st, ctx, st.effect)
            if verdict is False:
                continue
            if st.effect == "deny":
                if verdict is True:
                    return None
                conditions.append("resource_policy_conditional_deny")
            elif st.effect == "allow":
                if match == "direct":
                    conf = "derived" if verdict is True else "conditional"
                    direct = _best(direct, Grant(conf, [st.ref], ["granted_by_resource_policy"] +
                                                 (["resource_policy_condition"] if conf != "derived" else [])))
                else:
                    delegated = True
        if kind == "kms" and not delegated:
            identity = None  # the key policy does not delegate to IAM: identity policies do not count
        if account and account != principal.scope:
            # Cross-account: identity policy AND resource policy (direct or delegating to the source account).
            if identity is None or (direct is None and not delegated):
                return None
            grant = combine(identity, direct) if direct else identity
        else:
            if identity is None and direct is not None and any(self._deny_applies(d, ref, ctx) is True for d in denies):
                return None  # identity explicit deny beats a resource-policy allow
            grant = _best(identity, direct)
        if grant is not None and conditions:
            grant = downgrade(grant, "conditional", conditions[0])
        return grant

    def _guardrails(self, principal, action, ref, grant, ctx=None):
        ctx = ctx if ctx is not None else self._ctx(principal, action, ref)
        boundary = principal.attrs.get("boundary")
        if boundary:
            policy = self.policies.get(boundary)
            if policy is None:
                grant = downgrade(grant, "conditional", "permissions_boundary_not_collected")
            else:
                st = policy.for_action(action)
                limit = self._evaluate([s for s in st if s.effect == "allow"], [s for s in st if s.effect == "deny"], ref, ctx)
                if limit is None:
                    return None
                grant = combine(grant, Grant(limit.confidence, [], limit.conditions))
        account = principal.scope
        status = self.scp_status.get(account, "not_collected")
        if status == "collected":
            levels, complete = self._scp_levels(account)
            for level in levels:
                scps = self.scp.get(account, []) if level == account else self.scp_by_target.get(level, [])
                if not scps:
                    complete = complete and level == account
                    continue
                allowed = None
                for policy in scps:
                    st = policy.for_action(action)
                    for deny in (s for s in st if s.effect == "deny"):
                        applies = self._deny_applies(deny, ref, ctx)
                        if applies is True:
                            return None
                        if applies is None:
                            grant = downgrade(grant, "conditional", "scp_conditional_deny")
                    allowed = allowed or self._evaluate([s for s in st if s.effect == "allow"], [], ref, ctx)
                if allowed is None:
                    return None  # every level of the organization path must allow the action
            if not complete:
                grant = downgrade(grant, "conditional", "inherited_scps_not_evaluated")
        elif status != "empty":
            grant = downgrade(grant, "conditional", "scp_not_evaluated")
        if self.rcp_by_target and action.split(":", 1)[0] in RCP_SERVICES:
            grant = self._rcp(action, ref, grant, ctx, principal)
            if grant is None:
                return None
        if principal.incomplete:
            grant = downgrade(grant, grant.confidence, None)
        return grant

    def _rcp(self, action, ref, grant, ctx, principal):
        """Resource control policy denies for the resource's account (and its OUs / root)."""
        account = None
        if isinstance(ref, str) and ref.count(":") >= 5:
            account = ref.split(":")[4] or None
        account = account or principal.scope
        levels = [account] + [lvl for lvl in self._scp_levels(account)[0] if lvl != account]
        for level in levels:
            for policy in self.rcp_by_target.get(level, ()):
                for deny in (s for s in policy.for_action(action) if s.effect == "deny"):
                    applies = self._deny_applies(deny, ref, ctx)
                    if applies is True:
                        return None
                    if applies is None:
                        grant = downgrade(Grant(grant.confidence, list(grant.refs) + [deny.ref], grant.conditions),
                                          "conditional", "rcp_conditional_deny")
        return grant

    def localizable(self, req):
        return False

    def allowed_scopes(self, rule, source):
        if rule == "same_account":
            return {source.scope}
        if rule == "cluster":
            # EKS has no resource-based policies: a principal manages only the clusters of its own account.
            cache = self.__dict__.setdefault("_cluster_scopes", {})
            if source.scope not in cache:
                cache[source.scope] = {arn for arn, info in self.eks.items() if info["account"] == source.scope}
            return cache[source.scope]
        return None

    def check_targets(self, principal, req, template, candidates, localized=False):
        if isinstance(req, dict) and req.get("request_context"):
            # No fast paths: every candidate is checked with the requirement's request context (cached_check).
            result = {}
            for target in candidates:
                refs, floor = self.resolve(template, principal, target, selector=self.current_selector)
                grant = None
                for ref in refs:
                    grant = _best(grant, self.cached_check(principal, req, ref))
                if target.kind == "aws_role" and self.requirement_key(req) in ASSUME_ACTIONS and template == "{target.arn}":
                    grant = _best(grant, self._with_context(
                        req, lambda: self._trust_grant(principal, target, self.requirement_key(req))))
                if grant is not None:
                    result[target.id] = downgrade(grant, floor[0], floor[1]) if floor else grant
            return result
        action = self.requirement_key(req)
        if template in ("{target.arn}",):
            allows, denies = self._statements(principal, action)
            ctx = self._ctx(principal, action, ANY)
            wide = next((s for s in allows if self._wide(s, ctx)), None)
            if wide is not None and not denies:
                ref = wide.ref if not wide.conditional else {**wide.ref, "condition_evaluated": "satisfied"}
                grant = self._guardrails(principal, action, "*", Grant("derived", [ref]), ctx)
                boundary = principal.attrs.get("boundary")
                if grant is not None and (not boundary or (self.policies.get(boundary) and any(
                        self._wide(s, ctx) for s in self.policies[boundary].for_action(action) if s.effect == "allow"))):
                    return AllTargets(grant)
        result = {}
        by_arn = template == "{target.arn}"
        # Per-target short-circuits (exactly what _check_action / _trust_grant would conclude, without building a
        # request context): no identity Allow covers the ARN and no resource policy exists -> not granted; trust
        # grants exist only for roles whose trust names this principal.
        allows, _ = self._statements(principal, action)
        # Statements with ${policy variables} in Resource are matched on this principal's substituted patterns
        # (an unresolvable variable stays a wildcard, and NotResource is kept): a superset of _check_action.
        ctx = self._ctx(principal, action, ANY) if any(st.variables for st in allows) else None
        loose = any(st.variables and st.notresource for st in allows)
        substituted = [[(substitute(p, ctx) or p) if "${" in p else p for p in st.resources]
                       for st in allows if st.variables and not st.notresource]

        def may_match(ref):
            return loose or any(st.resource_matches(ref) for st in allows if not st.variables) \
                or any(_resource_glob(p, ref) for pats in substituted for p in pats)

        trusted = (self.trust_by_arn.get(_norm_arn(principal.id)) or {}) if action in ASSUME_ACTIONS and by_arn else {}
        narrow = self._uniform_outside(principal, action) if by_arn and not trusted and allows else None
        if narrow is not None:
            # Every '*' statement on the path (identity, boundary, SCPs) ignores the resource, so a target that no
            # narrower Resource/NotResource pattern names gets the same verdict as any other such target: one
            # representative check stands for all of them, and only the named targets are checked one by one
            # (an MFA-conditioned "iam:* on *" next to a ${aws:username} statement no longer costs one check per
            # target and source).
            listed = list(candidates)
            cset = self.current_cset
            whole = cset is not None and type(candidates) is _DICT_VALUES and len(listed) == len(cset.members)
            if listed and not (self._arn_index(cset)[2] if whole else
                               any(t.entity or self._resource_key(t.id) is not None for t in listed)):
                named = self._named_by(narrow, listed, candidates)
                rest = [t for t in listed if t.id not in named] if named else listed
                shared = self.cached_check(principal, req, rest[0].id) if rest else None
                if not named:
                    return AllTargets(shared) if shared is not None else {}
                out = dict.fromkeys((t.id for t in rest), shared) if shared is not None else {}
                for t in listed:
                    if t.id in named:
                        got = self.cached_check(principal, req, t.id)
                        if got is not None:
                            out[t.id] = got
                return out
        cset = self.current_cset
        if by_arn and not loose and cset is not None and type(candidates) is _DICT_VALUES \
                and len(candidates) == len(cset.members) and len(candidates) > 64:
            # Whole candidate set: only targets inside an Allow pattern's literal ARN prefix (plus entities,
            # targets with a resource policy and trusting roles) can be granted; find them by bisection instead
            # of testing every target against every pattern.
            ids, pos, special = self._arn_index(cset)
            pick = set(special)
            for pattern in [p for st in allows if not st.variables for p in st.resources] + [p for pats in substituted for p in pats]:
                prefix = _GLOB_START.split(pattern, maxsplit=1)[0]
                if not prefix:
                    pick = None
                    break
                pick.update(ids[bisect.bisect_left(ids, prefix):bisect.bisect_left(ids, prefix + "\U0010ffff")])
            if pick is not None:
                pick.update(t for t in trusted if t in pos)
                candidates = [cset.members[t] for t in sorted(pick, key=pos.__getitem__)]
        for target in candidates:
            if by_arn and not target.entity:
                refs, floor = [target.id], None  # resolve() fast path: the target's own ARN
            else:
                refs, floor = self.resolve(template, principal, target, selector=self.current_selector)
            grant = None
            for ref in refs:
                if ref is not ANY and not may_match(ref) and self._resource_key(ref) is None:
                    continue
                grant = _best(grant, self.cached_check(principal, req, ref))
            if target.id in trusted and target.kind == "aws_role":
                grant = _best(grant, self._trust_grant(principal, target, action))
            if grant is not None:
                result[target.id] = downgrade(grant, floor[0], floor[1]) if floor else grant
        return result

    def scope_only(self, req, template, localized):
        """`arn:aws:iam::{target.account}:user/*`-style requirements: one check per account stands for its targets."""
        if localized or not template or "{" not in template:
            return False
        cset = self.current_cset
        if cset is None or cset.kind == "k8s_cluster_admin":
            return False
        return set(_SCOPE_PH.findall(template)) <= {"target.account", "target.scope"} and template.count("{") == len(_SCOPE_PH.findall(template))

    def _arn_index(self, cset):
        cache = self.__dict__.setdefault("_arn_indexes", {})
        if cset.id not in cache:
            ids = sorted(cset.members)
            pos = {tid: i for i, tid in enumerate(cset.members)}
            special = [tid for tid, n in cset.members.items()
                       if n.entity or "*" in tid or "?" in tid or self._resource_key(tid) is not None]
            cache[cset.id] = (ids, pos, special)
        return cache[cset.id]

    def _uniform_outside(self, principal, action):
        """Glob patterns outside of which every target gets the same verdict, or None.

        None when a statement covering every resource ('*') depends on the resource (aws:ResourceTag, ...). The
        patterns are those of the narrower statements (Resource or NotResource, ${variables} substituted for this
        principal, unresolvable ones widened to '*'): a target matching none of them is untouched by every narrow
        statement and covered identically by every '*' statement."""
        key = (principal.perm_key if principal.perm_key is not None else principal.id, principal.scope, principal.id
               if any(st.variables for st in self._statements(principal, action)[0]) else None, action)
        cache = self.__dict__.setdefault("_uniform", {})
        if key in cache:
            return cache[key]
        ctx = None
        patterns = []

        def take(statements):
            nonlocal ctx
            for st in statements:
                if "*" in st.resources:
                    if not st.notresource and st.resource_dep:
                        return False
                    continue  # covers every resource (or, NotResource '*', none)
                for p in st.resources:
                    if "${" in p:
                        ctx = ctx or self._ctx(principal, action, ANY)
                        p = substitute(p, ctx) or re.sub(r"\$\{[^}]*\}", "*", p)
                    patterns.append(p)
            return True
        allows, denies = self._statements(principal, action)
        ok = take(allows) and take(denies)
        boundary = principal.attrs.get("boundary")
        if ok and boundary and self.policies.get(boundary) is not None:
            ok = take(self.policies[boundary].for_action(action))
        if ok and self.scp_status.get(principal.scope) == "collected":
            levels, _ = self._scp_levels(principal.scope)
            for level in levels:
                scps = self.scp.get(principal.scope, []) if level == principal.scope else self.scp_by_target.get(level, [])
                if not all(take(policy.for_action(action)) for policy in scps):
                    ok = False
                    break
        cache[key] = result = tuple(dict.fromkeys(patterns)) if ok else None
        return result

    def _named_by(self, patterns, listed, candidates):
        """Ids of the targets matching any pattern (bisection on the candidate set's ARN index when possible)."""
        if not patterns:
            return set()
        cset = self.current_cset
        if cset is not None and type(candidates) is _DICT_VALUES and len(listed) == len(cset.members) and len(listed) > 64:
            ids, _, _ = self._arn_index(cset)
            out = set()
            for p in patterns:
                prefix = _GLOB_START.split(p, maxsplit=1)[0]
                if prefix == p:
                    if p in cset.members:
                        out.add(p)
                    continue
                lo, hi = bisect.bisect_left(ids, prefix), bisect.bisect_left(ids, prefix + "\U0010ffff")
                out.update(t for t in ids[lo:hi] if _resource_glob(p, t))
            return out
        return {t.id for t in listed if any(_resource_glob(p, t.id) for p in patterns)}

    def _wide(self, st, ctx):
        """Statement grants on every resource for this principal/technique (condition proven, target-independent)."""
        if st.notresource or "*" not in st.resources:
            return False
        if not st.conditional:
            return True
        return not st.variables and not st.resource_dep and self._cond(st, ctx, "allow")[0] is True

    def _trust_grant(self, principal, role, action):
        """Same-account trust policy naming the source ARN grants AssumeRole without identity policy."""
        if principal.scope != role.scope:
            return None
        entry = self.trust_by_arn.get(_norm_arn(principal.id), {}).get(role.id)
        if not entry:
            return None
        allows, denies = self._statements(principal, action)
        ctx = self._ctx(principal, action, role.id)
        for deny in denies:
            if self._deny_applies(deny, role.id, ctx) is True:
                return None
        conf = self._trust_verdict(principal, role.id, entry)
        if conf is None:
            return None
        grant = Grant(conf, [entry[1]], ["granted_by_trust_policy"] + (["trust_condition"] if conf != "derived" else []))
        status = self.scp_status.get(principal.scope, "not_collected")
        return downgrade(grant, "conditional", "scp_not_evaluated") if status not in ("collected", "empty") else grant

    # ----------------------------------------------------------- placeholders
    def placeholder_values(self, name, source, target, selector):
        owner, _, attr = name.partition(".")
        if not attr:
            owner, attr = "source", owner
        node = target if owner == "target" else source
        if node is None:
            return None
        if owner == "target" and node.entity and attr in ("role_arn", "location_arn"):
            value = node.attrs.get(attr)
            return [value] if isinstance(value, str) and value else None
        if node.entity and attr in ("resource_arn", "attached_resource_arn", "arn", "id") and node.attrs.get("resource_arn"):
            return [node.attrs["resource_arn"]]  # collected application-plane resource (aws_service_plane_admin)
        if node.entity and attr in ("amplifybackend_token_arn", "amplifybackend_backend_arn"):
            # Amplify Admin (amplifybackend) resources of the collected app (Service Authorization Reference):
            # token /backend/{AppId}/challenge/*, backend /backend/{AppId}/*.
            match = re.match(r"arn:(aws[\w-]*):amplify:([^:]+):(\d{12}):apps/([^/]+)$", str(node.attrs.get("resource_arn") or ""))
            tail = "/challenge/*" if attr == "amplifybackend_token_arn" else "/*"
            return [f"arn:{match.group(1)}:amplifybackend:{match.group(2)}:{match.group(3)}:/backend/{match.group(4)}{tail}"] if match else None
        if attr == "consumer_input_arn" and str((selector or {}).get("consumer_input_writable_via") or "").lower().startswith("imagebuilder:"):
            # Version-wildcard, account-owned recipe components as arn:...:component/<name>/* (a new version is a new ARN
            # under the name); a pipeline whose recipe components were not collected falls back to its Region's component/*.
            pipelines = self.hosts.get(node.id, {}).get("imagebuilder_pipeline", [])
            ib = getattr(self, "ib_components", {})
            values = sorted({c for p in pipelines for c in (ib.get(p) if ib.get(p) is not None else
                             ([p.split(":image-pipeline/")[0] + ":component/*"] if ":image-pipeline/" in p else []))})
            if values:
                return values
            return [] if self.host_status.get((node.scope, "imagebuilder_pipeline")) in ("collected", "empty") else None
        if node.kind == "k8s_cluster_admin" and node.provider == "aws":
            got = {"scope": node.scope, "cluster": node.scope, "arn": node.scope, "id": node.scope, "account": node.attrs.get("account"),
                   "name": node.attrs.get("name"), "region": node.attrs.get("region")}.get(attr)
            return [got] if got else None
        if attr in ("arn", "id"):
            if owner == "target" and node.entity:
                return None
            return [node.id]
        if attr in ("account", "scope", "project"):
            return [node.scope]
        if attr == "name":
            return [node.label]
        if attr == "attached_policy_arn":
            return [pid for pid in node.attrs.get("policy_ids", ()) if self.policies[pid].customer_managed] or []
        if attr == "group_arn":
            return list(node.attrs.get("groups", []))
        if attr == "assumable_role_arn":
            return self._assumable(node)
        if attr == "assumable_role_attached_policy_arn":
            if self._v2_policy_inventory_unknown(node):
                return None
            return sorted({pid for role in self._v2_assumable_roles(node)
                           for pid in role.attrs.get("policy_ids", ())
                           if pid in self.policies and self.policies[pid].customer_managed})
        if attr in ("attached_resource_arn", "resource_arn", "host_resource"):
            hosts = self.hosts.get(node.id, {})
            wanted = [HOST_KIND.get(str(v)) for v in as_list(selector.get("via_resource_type")) + as_list(selector.get("attached_to_service"))]
            wanted = [w for w in wanted if w] + [SELECTOR_HOSTS[k] for k in selector if k in SELECTOR_HOSTS]
            if not wanted:
                return None
            values = [arn for w in wanted for arn in hosts.get(w, [])]
            if values:
                return values
            known = all(self.host_status.get((node.scope, w)) in ("collected", "empty") for w in wanted)
            return [] if known else None
        derived = {"codebuild_sandbox_arn": ("codebuild_project", ":project/", ":sandbox/", ":*"),
                   "redshift_dbuser_arn": ("redshift_cluster", ":cluster:", ":dbuser:", "/*")}
        if attr in derived:
            # Sandbox / dbuser ARNs of the collected project / cluster carrying the role (ids and user names unknown).
            host, old, new, suffix = derived[attr]
            values = [arn.replace(old, new, 1) + suffix for arn in self.hosts.get(node.id, {}).get(host, []) if old in arn]
            if values:
                return values
            return [] if self.host_status.get((node.scope, host)) in ("collected", "empty") else None
        if attr == "rolesanywhere_profile_arn":
            # Enabled Roles Anywhere profiles listing the role (rolesanywhere:ListProfiles roleArns).
            values = self.hosts.get(node.id, {}).get("rolesanywhere_profile", [])
            if values:
                return list(values)
            return [] if self.host_status.get((node.scope, "rolesanywhere_profile")) in ("collected", "empty") else None
        if attr == "trust_anchor_arn":
            # Any enabled trust anchor of the account can issue sessions for its profiles.
            if self.trust_anchors.get(node.scope):
                return list(self.trust_anchors[node.scope])
            return [] if self._collected(self.presence_status.get("rolesanywhere_trust_anchor", {}), node.scope) else None
        if attr == "saml_provider_arn":
            return [arn for arn in self._federated(node) if ":saml-provider/" in arn] or []
        if attr == "oidc_provider_arn":
            return [arn for arn in self._federated(node) if ":oidc-provider/" in arn] or []
        if attr == "portfolio_arn":
            if not self.sc_status or unavailable({s: st for s, st in self.sc_status.items() if s.split("/")[0] == node.scope}):
                return None
            return list(dict.fromkeys(self.sc_portfolios.get(_norm_arn(node.id), [])))
        return None

    def _assumable(self, source):
        """Roles the source can already assume: trust admits it and (unless the trust names its ARN in the same
        account) its identity policy allows sts:AssumeRole on the role."""
        cache = self.__dict__.setdefault("_assumable_cache", {})
        if source.id not in cache:
            direct = self.trust_by_arn.get(_norm_arn(source.id), {})
            cache[source.id] = sorted(rid for rid in self._trusting(source)
                                      if (rid in direct and self.principals.get(rid) is not None
                                          and self.principals[rid].scope == source.scope)
                                      or self._check_action(source, "sts:assumerole", rid) is not None)
        return list(cache[source.id])

    def _v2_policy_inventory_unknown(self, source):
        cache = self.__dict__.setdefault("_v2_inventory_unknown_cache", {})
        if source.scope in cache:
            return cache[source.scope]
        unknown = False
        for kind in ("iam_role", "iam_policy"):
            states = [st for s, st in inventory_status(self.snapshot, kind).items()
                      if s.split("/")[0] == source.scope]
            if not states or any(st not in ("collected", "empty") for st in states):
                unknown = True
                break
        if not unknown:
            unknown = any("AttachedManagedPolicies" not in role or "AssumeRolePolicyDocument" not in role
                          for scope, role in items(self.snapshot, "iam_role") if scope.split("/")[0] == source.scope)
        if not unknown:
            # A successful ListPolicies collection does not prove that every policy
            # referenced by a role was fetched. Such a policy may be editable and
            # must not turn an unresolved join into a definitive non-match.
            unknown = any(
                isinstance(attached, dict) and attached.get("PolicyArn")
                and attached["PolicyArn"] not in self.policies
                for scope, role in items(self.snapshot, "iam_role")
                if scope.split("/")[0] == source.scope
                for attached in as_list(role.get("AttachedManagedPolicies"))
            )
        cache[source.scope] = unknown
        return unknown

    def _v2_assumable_roles(self, source):
        for rid, (trust_conf, _) in self._trusting(source).items():
            role = self.principals.get(rid)
            if role is None or role.kind != "aws_role" or role.scope != source.scope:
                continue
            assume = self._check_action(source, "sts:assumerole", rid)
            if assume is not None:
                yield role

    def _v2_policy_admin(self, source):
        """Decide the joined role/policy mutation without mixing policies across roles."""
        if self._v2_policy_inventory_unknown(source):
            return ("unknown", "assumable_role_policy_inventory_not_collected")
        conditional = False
        for role in self._v2_assumable_roles(source):
            assume = self._check_action(source, "sts:assumerole", role.id)
            trust = self._trusting(source).get(role.id)
            for pid in role.attrs.get("policy_ids", ()):
                policy = self.policies.get(pid)
                if policy is None or not policy.customer_managed:
                    continue
                edit_reqs = [r for r in flatten_requirements((self.current_entry or {}).get("requires") or {})
                             if r.get("action") == "iam:CreatePolicyVersion"
                             and r.get("resource") == "{source.assumable_role_attached_policy_arn}"]
                edit = None
                for req in edit_reqs:
                    edit = _BEST(edit, self.cached_check(source, req, pid))
                if edit is None:
                    continue
                versions = self.policy_versions.get(pid)
                versions_known = (isinstance(versions, list) and 0 < len(versions) <= 5
                                  and all(isinstance(v, dict) and v.get("VersionId")
                                          and isinstance(v.get("IsDefaultVersion"), bool) for v in versions)
                                  and sum(v["IsDefaultVersion"] for v in versions) == 1)
                if versions_known and len(versions) >= 5:
                    if not any(v.get("IsDefaultVersion") is False and v.get("VersionId")
                               for v in versions if isinstance(v, dict)):
                        continue
                    delete = self._check_action(source, "iam:deletepolicyversion", pid)
                    if delete is None:
                        continue
                else:
                    delete = None
                grant = self._guardrails(role, "iam:attachuserpolicy", ANY, Grant("derived", []))
                if grant is None:
                    continue
                boundary = role.attrs.get("boundary")
                # The new version supplies Allow *; existing explicit Denies and limiting
                # boundary/SCP allow lists still prevent full account administration.
                role_policies = [self.policies[p] for p in role.attrs.get("policy_ids", ()) if p != pid and p in self.policies]
                guards = [self.policies[boundary]] if boundary in self.policies else []
                if self.scp_status.get(role.scope) == "collected":
                    levels, complete = self._scp_levels(role.scope)
                    for level in levels:
                        guards.extend(self.scp.get(role.scope, ()) if level == role.scope
                                      else self.scp_by_target.get(level, ()))
                else:
                    complete = self.scp_status.get(role.scope) == "empty"
                if any(st.effect == "deny" and not st.conditional for p in role_policies + guards
                       for st in p.statements):
                    continue
                if any(not any(st.effect == "allow" and not st.notaction and not st.notresource
                               and any(a in ("*", "*:*") for a in st.actions)
                               and "*" in st.resources for st in p.statements)
                       for p in guards):
                    continue
                restricted = any(st.effect == "deny" or st.effect == "allow" and st.conditional
                                 for p in role_policies + guards for st in p.statements)
                if (trust[0] != "derived" or assume.confidence != "derived" or edit.confidence != "derived" or
                        (delete is not None and delete.confidence != "derived") or grant.confidence != "derived" or
                        not versions_known or not complete or restricted or role.incomplete or
                        boundary and boundary not in self.policies):
                    conditional = True
                    continue
                return None
        return ("conditional", "assumable_role_policy_conditions_or_capacity") if conditional else False

    def resolve_for(self, template, source, target):
        return self.resolve(template, source, target, selector=self.current_selector)

    def blocker(self, blocker, source, compiled):
        if blocker != "ecr_tag_immutability":
            return None
        account = source.scope
        if self.ecr_status.get(account) not in ("collected", "empty"):
            return None
        action = str((compiled.get("selector") or {}).get("consumer_input_writable_via") or "ecr:PutImage").lower()
        if not action.startswith("ecr:"):
            return "clear"  # ECR Public has no tag immutability
        writable = [(arn, mut) for arn, mut in self.ecr.get(account, []) if self._check_action(source, action, arn)]
        if not writable:
            return "blocked"
        if any(mut != "IMMUTABLE" for _, mut in writable):
            return "clear"  # MUTABLE or *_WITH_EXCLUSION tags can be overwritten
        if any(self._check_action(source, "ecr:putimagetagmutability", arn) for arn, _ in writable):
            return "clear"  # the source can switch immutability off first
        return "blocked"

    # ------------------------------------------------------ related snapshots
    def set_related(self, snapshots):
        """Join K8s snapshots of collected EKS clusters: the AWS-side cluster-admin entity links to the K8s one."""
        self.related_eks = {}
        if not self.eks:
            return
        by_name, by_origin = {}, {}
        for arn, info in self.eks.items():
            by_name.setdefault(info["name"], []).append(arn)
            endpoint = str(info.get("endpoint") or "")
            if endpoint:
                parts = urlsplit(endpoint)
                origin = parts.scheme.lower() + "://" + parts.netloc.lower() + parts.path.rstrip("/")
                by_origin["k8s-cluster:" + hashlib.sha256(origin.encode()).hexdigest()] = arn
        for snapshot in snapshots or ():
            if (snapshot or {}).get("provider") != "k8s":
                continue
            ids = set()
            meta = snapshot.get("metadata") or {}
            if meta.get("cluster_id"):
                ids.add(str(meta["cluster_id"]))
            for collection in snapshot.get("collections", []):
                for item in collection.get("items", [])[:50]:
                    prov = item.get("provenance") if isinstance(item, dict) else None
                    if isinstance(prov, dict) and prov.get("cluster_id"):
                        ids.add(str(prov["cluster_id"]))
            for cid in ids:
                arn = cid if cid in self.eks else by_origin.get(cid)
                if arn is None and len(by_name.get(cid, ())) == 1:
                    arn = by_name[cid][0]
                if arn is not None:
                    self.related_eks[arn] = cid

    def cross_edges(self):
        out = []
        for arn, cid in sorted(self.related_eks.items()):
            node = self.eks_entity(arn)
            target = {"id": f"k8s_cluster_admin:{cid}", "label": f"cluster-admin of {cid}", "type": "k8s_cluster_admin",
                      "provider": "k8s", "scope": cid, "kind": "entity", "attrs": {"related_snapshot": True, "provider": "k8s"}}
            if target["id"] == node.id:
                continue  # the K8s snapshot already uses the cluster ARN: same node id, no join edge needed
            out.append((node, target, Grant("derived", [{"join": "eks_cluster", "cluster_arn": arn, "k8s_cluster_id": cid}])))
        return out

    def _federated(self, role):
        """Federated principals (original case) named by the role's trust policy Allow statements."""
        return list(self.__dict__.get("trust_federated_raw", {}).get(role.id, ()))

    # ------------------------------------------------------------------ pivots
    PIVOT_SERVICES = {"aws_stackset_administration_role": "cloudformation.amazonaws.com"}

    @property
    def pivot_is_conditional(self):
        return (self.current_entry or {}).get("pivot_resource_type") not in self.PIVOT_SERVICES

    def pivot_candidates(self, source):
        """Existing roles of the entry's pivot type (a role trusting the service) or None when not modelled."""
        service = self.PIVOT_SERVICES.get((self.current_entry or {}).get("pivot_resource_type"))
        if service is None:
            return None
        roles = sorted(rid for rid in self.trust_by_service.get(service, {}) if rid in self.principals)
        if not roles and unavailable(inventory_status(self.snapshot, "iam_role")):
            return None
        return roles

    def resolve(self, template, source, target, pivot=None, selector=None):
        if template is None:
            return [ANY], None
        names = re.findall(r"(?<!\$)\{([^{}]+)\}", template)
        if not names:
            return [template], None
        values = {}
        for name in names:
            if name == "pivot" and pivot is not None:
                values[name] = [pivot]
                continue
            if name == "pivot":
                return [ANY], ("conditional", "pivot_resource_not_verified")
            got = self.placeholder_values(name, source, target, selector or {})
            if got is None:
                return [ANY], ("unknown", f"placeholder_{name}_not_in_snapshot")
            values[name] = got
        refs = [template]
        for name, options in values.items():
            refs = [r.replace("{" + name + "}", v) for r in refs for v in options][:200]
        return refs, None

    # --------------------------------------------------------------- targets
    SERVICE_MANAGED_PATHS = ("/aws-service-role/",)

    def service_managed(self, node):
        """Service-linked roles (/aws-service-role/) are assumable only by their own service and cannot be passed,
        assumed or have their trust/permissions edited by customers. (/aws-reserved/ Identity Center roles stay:
        they are reachable through the Identity Center SAML provider.)"""
        if node.kind != "aws_role":
            return False
        cache = self.__dict__.setdefault("_service_managed_cache", {})
        hit = cache.get(node.id)
        if hit is None:
            path = str(node.attrs.get("path") or "")
            arn = str(node.id)
            hit = cache[node.id] = any(p in path or p in arn for p in self.SERVICE_MANAGED_PATHS)
        return hit

    def targets(self, kind):
        if kind in ("aws_role", "aws_user", "aws_group"):
            return [n for n in self.principals.values() if n.kind == kind]
        if kind == "aws_account_admin":
            # Accounts with collected principals plus organization member accounts (organizations:ListAccounts).
            accounts = set(self.accounts) | {a for a, state in self.org_accounts.items() if state not in ("SUSPENDED", "CLOSED", "PENDING_CLOSURE")}
            return [self.entity(kind, account) for account in sorted(accounts)]
        if kind == "k8s_cluster_admin":
            return [self.eks_entity(arn) for arn in sorted(self.eks)]
        return []

    def _credential_fact_bound(self, technique, scope, fact):
        """Check the identity/resource join before a credential record can name a principal target."""
        service, actions = _EXACT_USER_CREDENTIAL_ACTIONS[technique]
        scope_parts = str(scope).split("/")
        account = scope_parts[0]
        target = fact.get("TargetId")
        resource = fact.get("CredentialResourceArn")
        action = fact.get("AccessAction")
        return (fact.get("TargetKind") == "aws_user"
                and isinstance(target, str) and target.startswith(f"arn:aws:iam::{account}:user/")
                and fact.get("CredentialSubjectArn") == target
                and fact.get("CredentialKind") == "aws_iam_user_access_key"
                and fact.get("TargetAccount") == account
                and isinstance(resource, str) and resource.startswith(f"arn:aws:{service}:")
                and len(resource.split(":", 5)) == 6 and resource.split(":", 5)[4] == account
                and (len(scope_parts) < 2 or resource.split(":", 5)[3] == scope_parts[1])
                and isinstance(action, str) and action.lower() in actions)

    def targets_for(self, kind, selector):
        selector = selector or {}
        if kind == "aws_verified_authority" and any(key in self.scoped_grants and selector.get(key)
                                                 for key in self.scoped_grants):
            key = next(key for key in self.scoped_grants if selector.get(key))
            return list(self.scoped_grants[key][0].values())
        if kind == "aws_verified_authority" and selector.get("aws_s3_policy_self_grant"):
            return list(self.s3_self_grant_targets.values())
        if kind == "aws_verified_authority" and selector.get("aws_s3_access_grants_self_grant"):
            return list(self.s3_access_grant_targets.values())
        technique = selector.get("aws_challenge_fact")
        if technique in _EXACT_USER_CREDENTIAL_ACTIONS:
            if kind != "aws_user":
                return []
            return [self.principals[target] for (tid, _, fact_kind, target), records
                    in self.credential_evidence.items()
                    if tid == technique and fact_kind == kind and target in self.principals
                    and any(self._credential_fact_bound(tid, scope, item)
                            for scope, item in records)]
        if kind == "aws_verified_authority":
            technique = selector.get("aws_challenge_fact")
            targets = {}
            for (tid, _, target_kind, resource), item in self.challenge_evidence.items():
                if tid != technique or target_kind != kind:
                    continue
                account = item["TargetAccount"]
                node_id = f"aws_verified_authority:{tid}:{resource}"
                targets[node_id] = Node(node_id, kind, "aws", account,
                    f"Verified {tid} authority ({resource})",
                    attrs={"account": account, "resource_arn": resource, "arn": resource}, entity=True)
            return list(targets.values())
        plane = str(selector.get("service_plane"))
        if kind == "aws_service_plane_admin" and plane in SERVICE_PLANES:
            return [self._plane_entity(plane, account, arn) for account, arn in self.planes.get(plane, [])]
        if kind == "aws_identity_center_permission_set" and selector.get("assigned_to_identity_center_group"):
            out = []
            for account, count in sorted(self.ic_group_assignments.items()):
                node = self.entity(kind, account)
                node.attrs["group_assignments"] = count
                out.append(node)
            return out
        return self.targets(kind)

    def _plane_entity(self, plane, account, arn):
        cache = self.__dict__.setdefault("_entities", {})
        key = ("aws_service_plane_admin", plane, arn or account)
        if key not in cache:
            cache[key] = Node(f"aws_service_plane_admin:{plane}:{arn or account}", "aws_service_plane_admin", "aws", account,
                              f"{plane} application administrator ({arn or account})",
                              attrs={"account": account, "service_plane": plane, "resource_arn": arn}, entity=True)
        return cache[key]

    def eks_entity(self, arn):
        cache = self.__dict__.setdefault("_entities", {})
        key = ("k8s_cluster_admin", arn)
        if key not in cache:
            info = self.eks[arn]
            cache[key] = Node(f"k8s_cluster_admin:{arn}", "k8s_cluster_admin", "aws", arn,
                              f"EKS cluster {info['name']} (cluster-admin)",
                              attrs={"account": info["account"], "region": info["region"], "name": info["name"], "cluster": arn,
                                     "arn": arn, "authentication_mode": info["mode"]}, entity=True)
        return cache[key]

    def entity(self, kind, scope):
        key = (kind, scope)
        cache = self.__dict__.setdefault("_entities", {})
        if key not in cache:
            label = {"aws_account_admin": f"Administrator of AWS account {scope}",
                     "aws_identity_center_permission_set": f"IAM Identity Center permission sets ({scope})",
                     "aws_directory_domain_admin": f"Active Directory domain administrator reachable from AWS account {scope}",
                     "aws_service_plane_admin": f"Managed-service application administrator in AWS account {scope}"}.get(kind, f"{kind} {scope}")
            cache[key] = Node(f"{kind}:{scope}", kind, "aws", scope, label, attrs={"account": scope}, entity=True)
        return cache[key]

    def unknown_target_scopes(self, kind):
        if (self.current_selector or {}).get("aws_s3_policy_self_grant") or (self.current_selector or {}).get("aws_s3_access_grants_self_grant") or any(
                (self.current_selector or {}).get(key) for key in self.scoped_grants):
            return {}
        if (self.current_selector or {}).get("aws_challenge_fact") in _EXACT_USER_CREDENTIAL_ACTIONS:
            # A read permission alone does not imply that the service contains
            # another IAM user's key. Only an exact reviewed subject is a target.
            return {}
        if kind == "aws_verified_authority":
            return {scope: f"review_evidence_{status}" for scope, status in
                    self._plane_unknown(None, "aws_privesc_challenge_evidence").items()}
        types = {"aws_role": "iam_role", "aws_user": "iam_user", "aws_group": "iam_group"}
        if kind in types:
            return {s.split("/")[0]: st for s, st in unavailable(inventory_status(self.snapshot, types[kind])).items()}
        selector = self.current_selector or {}
        if kind == "aws_service_plane_admin" and str(selector.get("service_plane")) in SERVICE_PLANES:
            plane = str(selector["service_plane"])
            return self._plane_unknown(plane, SERVICE_PLANES[plane])
        if kind == "aws_identity_center_permission_set" and selector.get("assigned_to_identity_center_group"):
            return self._plane_unknown(None, "aws_identity_center_account_assignment")
        if kind in ("aws_identity_center_permission_set", "aws_identity_center_user", "aws_directory_domain_admin",
                    "aws_service_plane_admin"):
            # aws_directory_domain_admin: pca-connector-ad connectors / directory registrations are not collected.
            # aws_service_plane_admin: application-plane resources (Connect instances, Grafana workspaces, QuickSight
            # accounts, Supply Chain instances, Amplify backends) are not collected: one placeholder per account and plane.
            return {account: "not_collected" for account in sorted(self.accounts)}
        if kind == "k8s_cluster_admin":
            return dict(unavailable(self.eks_status))
        return {}

    def _plane_unknown(self, plane, inventory):
        """{account: status} of accounts whose plane inventory is not fully collected."""
        statuses, out = inventory_status(self.snapshot, inventory), {}
        for account in sorted(self.accounts):
            mine = [st for scope, st in statuses.items() if scope.split("/")[0] == account]
            if plane == "quicksight" and "collected" in mine:
                continue  # Users live in the identity Region only; other Regions deny ListUsers.
            bad = [st for st in mine if st not in ("collected", "empty")]
            if not mine or bad:
                out[account] = bad[0] if bad else "not_collected"
            elif account in self.plane_partial.get(plane, ()):
                out[account] = "partial"
        return out

    def _trusting(self, source):
        """{role arn: (confidence, trust statement ref)} of roles whose trust admits the source; trust conditions are
        evaluated with the source's request context (a provably failing condition drops the role)."""
        cache = self.__dict__.setdefault("_trusting_cache", {})
        if source.id in cache:
            return cache[source.id]
        found = {}
        for table in (self.trust_by_arn.get(_norm_arn(source.id), {}), self.trust_by_account.get(source.scope, {}), self.trust_public):
            for rid, value in table.items():
                if rid == source.id or rid in found:
                    continue
                conf = self._trust_verdict(source, rid, value)
                if conf is not None:
                    found[rid] = (conf, value[1])
        cache[source.id] = found
        return found

    def _trust_verdict(self, source, rid, value):
        conf, ref = value
        if conf == "derived":
            return conf
        st = self._trust_st.get((rid, ref.get("statement")))
        if st is None or st.ref.get("not_principal") or not st.condition:
            return conf
        org = self.org_id if source is not None and source.scope in self.org_accounts else None
        verdict, _ = evaluate_condition(st.condition, Context(principal=source, action="sts:assumerole", resource=rid, org_id=org))
        return None if verdict is False else "derived" if verdict is True and not st.variables else "conditional"

    def selector(self, key, value, candidates, source, pivot=None):
        if key in self.scoped_grants:
            if source is None:
                return None
            records = self.scoped_grants[key][1]
            return {target_id: ("conditional", "reviewed_exact_scoped_permission_grant")
                    for target_id in candidates
                    if (record := records.get(target_id)) and record["SourceArn"] == source.id}
        if key == "aws_s3_access_grants_self_grant":
            if source is None:
                return None
            return {target_id: ("conditional", "reviewed_s3_access_grants_scoped_session")
                    for target_id in candidates
                    if (record := self.s3_access_grant_records.get(target_id))
                    and record["SourceArn"] == source.id}
        if key == "aws_s3_policy_self_grant":
            if source is None:
                return None
            return {target_id: ("conditional", "reviewed_s3_bucket_policy_self_grant")
                    for target_id in candidates
                    if (record := self.s3_self_grant_records.get(target_id))
                    and record["SourceArn"] == source.id}
        if key == "aws_challenge_fact":
            statuses = inventory_status(self.snapshot, "aws_privesc_challenge_evidence")
            if not statuses or any(st not in ("collected", "empty") for st in statuses.values()):
                return {} if value in _EXACT_USER_CREDENTIAL_ACTIONS else None
            if source is None:
                return None
            if value in _EXACT_USER_CREDENTIAL_ACTIONS:
                out = {}
                for candidate_id, node in candidates.items():
                    if node.kind != "aws_user" or candidate_id == source.id:
                        continue
                    records = self.credential_evidence.get((value, source.id, node.kind, candidate_id), ())
                    if len(records) != 1:
                        continue
                    scope, fact = records[0]
                    if not self._credential_fact_bound(value, scope, fact):
                        continue
                    if fact.get("Status") == "disproven":
                        continue
                    if (fact.get("Status") != "verified" or fact.get("VerifiedPreconditions") is not True
                            or fact.get("CredentialUsable") is not True
                            or not isinstance(fact.get("EvidenceRef"), str) or not fact["EvidenceRef"]):
                        continue
                    permission = self._check_action(source, fact["AccessAction"].lower(),
                                                    fact["CredentialResourceArn"])
                    if permission is not None and permission.confidence != "unknown":
                        out[candidate_id] = ("conditional", "exact_credential_subject_and_resource")
                return out
            out = {}
            for candidate_id, node in candidates.items():
                target_id = node.attrs.get("resource_arn") if node.kind == "aws_verified_authority" else node.id
                fact = self.challenge_evidence.get((value, source.id, node.kind, target_id))
                if not fact:
                    continue
                state = fact.get("Status")
                from .principal_evidence import CONTRACT as principal_contract, valid as principal_valid, check_bindings, TRUST_SERVICES
                if value in principal_contract:
                    records = self.bounded_evidence_records.get((value, source.id, node.kind, target_id), ())
                    statuses = inventory_status(self.snapshot, "aws_privesc_challenge_evidence")
                    if (len(records) == 1 and statuses.get(records[0][0]) in ("collected", "empty") and not node.incomplete
                            and (value not in TRUST_SERVICES or node.id in self.trust_by_service.get(TRUST_SERVICES[value], {}))
                            and principal_valid(self.snapshot, value, fact, source.id, node.id, node.scope)
                            and check_bindings(self, value, fact, source)):
                        out[candidate_id] = ("conditional", "exact_full_principal_authority_verified")
                    elif state != "disproven":
                        out[candidate_id] = ("unknown", "full_principal_authority_or_resource_binding_unverified")
                    continue
                from .bounded_evidence import CONTRACT as bounded_contract, valid as bounded_valid
                bounded_records = self.bounded_evidence_records.get((value, source.id, node.kind, target_id), ())
                bounded_status = inventory_status(self.snapshot, "aws_privesc_challenge_evidence")
                if value in bounded_contract and (len(bounded_records) != 1 or bounded_status.get(bounded_records[0][0]) not in ("collected", "empty") or not bounded_valid(value, fact, source.id, target_id, node.scope)):
                    if state != "disproven": out[candidate_id] = ("unknown", "bounded_effect_evidence_incomplete")
                    continue
                if state == "verified" and fact.get("VerifiedPreconditions") is True:
                    out[candidate_id] = ("conditional", "exact_challenge_evidence")
                elif state != "disproven":
                    out[candidate_id] = ("unknown", "challenge_preconditions_incomplete")
            return out
        """Return {target id: (confidence, condition)|None} or None when the key is unsupported."""
        if key == "trust_allows_service":
            out = {}
            for svc in as_list(value):
                for rid, (conf, _) in self.trust_by_service.get(str(svc).lower(), {}).items():
                    if rid in candidates:
                        out[rid] = None if conf == "derived" else (conf, "trust_condition")
            return out
        if key == "trust_allows_federated":
            out = {}
            for fed in as_list(value):
                for rid, (conf, _) in self.trust_by_federated.get(str(fed).lower(), {}).items():
                    if rid in candidates:
                        out[rid] = None if conf == "derived" else (conf, "trust_condition")
            return out
        if key == "trust_allows_saml_provider_covered_by":
            return {rid: None for rid in candidates if any(":saml-provider/" in f for f in self._federated(candidates[rid]))}
        if key == "trust_allows_principal_of_source":
            out = {}
            for rid, (conf, _) in self._trusting(source).items():
                if rid in candidates:
                    public = rid in self.trust_public and rid not in self.trust_by_arn.get(_norm_arn(source.id), {})
                    out[rid] = None if conf == "derived" and not public else ("conditional", "trust_condition") if conf != "derived" else None
            return out
        if key == "has_instance_profile":
            out = {}
            for rid, n in candidates.items():
                profiles = n.attrs.get("instance_profiles")
                if profiles is None:
                    out[rid] = ("unknown", "instance_profiles_not_collected")
                elif bool(profiles) == bool(value):
                    out[rid] = None
            return out
        if key == "has_login_profile":
            out = {}
            for rid, n in candidates.items():
                state = n.attrs.get("login_profile")
                if state is None:
                    out[rid] = ("unknown", "login_profile_not_collected")
                elif state == bool(value):
                    out[rid] = None
            return out
        if key == "name_prefix":
            return {rid: None for rid, n in candidates.items() if str(n.label).startswith(str(value))}
        if key in ("attached_to_service", "via_resource_type"):
            if key == "attached_to_service" and HOST_KIND.get(str(value).lower()) is None and any(
                    HOST_KIND.get(str(v).lower()) for v in as_list((self.current_selector or {}).get("via_resource_type"))):
                # A collected via_resource_type host (e.g. sagemaker_notebook_instance) decides the attachment.
                return dict.fromkeys(candidates)
            out = {}
            for rid, n in candidates.items():
                verdict = self._attached(n, value)
                if verdict is not False:
                    out[rid] = verdict
            return out
        if key == "source_kind":
            return dict.fromkeys(candidates) if source.kind in as_list(value) else {}
        if key == "same_as_source":
            if candidates and next(iter(candidates.values())).entity:
                return {rid: None for rid, n in candidates.items() if n.scope == source.scope}
            return {source.id: None} if source.id in candidates else {}
        if key == "source_group_covered_by":
            return dict.fromkeys(candidates) if source.attrs.get("groups") else {}
        if key == "source_attached_policy_covered_by":
            return dict.fromkeys(candidates) if any(self.policies[p].customer_managed for p in source.attrs.get("policy_ids", ())) else {}
        if key == "via_assumable_role_covered_by":
            # {source.assumable_role_arn} already restricts the requirement to roles the source can assume.
            return dict.fromkeys(candidates) if self._assumable(source) else {}
        if key == "via_assumable_role_attached_policy_covered_by":
            verdict = self._v2_policy_admin(source)
            return {rid: verdict for rid, node in candidates.items() if node.scope == source.scope} if verdict is not False else {}
        if key == "assumable_by_pivot_role":
            if pivot is None:
                return None
            out = {}
            for pid in pivot:
                node = self.principals.get(pid)
                if node is None:
                    continue
                for rid in self._assumable(node):
                    if rid in candidates and rid not in pivot:
                        conf = self._trusting(node).get(rid, ("derived",))[0]
                        verdict = None if conf == "derived" else (conf, "trust_condition")
                        if rid not in out or out[rid] is not None:
                            out[rid] = verdict
            return out
        if key in ("any_principal_in_scope", "resource_permission_covers_target", "attached_resource_covered_by"):
            return dict.fromkeys(candidates)
        return self._selector_ext(key, value, candidates, source)

    # ------------------------------------------------- inventory-backed selectors
    def _collected(self, statuses, account):
        """True when every region of `account` in a {scope: status} map was collected (or empty)."""
        mine = [st for scope, st in statuses.items() if scope.split("/")[0] == account]
        return bool(mine) and all(st in ("collected", "empty") for st in mine)

    def _roles_by_norm(self, norm):
        index = self.__dict__.get("_norm_roles")
        if index is None:
            index = self._norm_roles = {}
            for node in self.principals.values():
                if node.kind == "aws_role":
                    index.setdefault(_norm_arn(node.id), []).append(node)
        return index.get(norm, ())

    def _org_root(self):
        return next((p for p in self.org_parent.values() if str(p).startswith("r-")), None)

    def _selector_ext(self, key, value, candidates, source):
        out = {}
        if key == "consumer_input_writable_via" and str(value).lower().startswith("imagebuilder:"):
            # Recipe component ARNs (GetImageRecipe) decide membership: a version-wildcard account-owned component is derived;
            # fully pinned / AWS-owned components only exclude the role; an uncollected recipe stays conditional.
            ib = getattr(self, "ib_components", {})
            for rid, n in candidates.items():
                pipelines = self.hosts.get(rid, {}).get("imagebuilder_pipeline")
                if pipelines:
                    comps = [ib.get(p) for p in pipelines]
                    if any(c is None for c in comps):
                        out[rid] = ("conditional", "imagebuilder_recipe_components_not_collected")
                    elif any(comps):
                        out[rid] = None
                elif self.host_status.get((n.scope, "imagebuilder_pipeline")) not in ("collected", "empty"):
                    out[rid] = ("unknown", "imagebuilder_pipelines_not_collected")
            return out
        if key == "service_plane":
            # Application-plane entities carry attrs.service_plane once collected; none are today (placeholders only).
            return {tid: None for tid, n in candidates.items() if n.attrs.get("service_plane") == value}
        if key == "assigned_to_identity_center_group":
            return {tid: None for tid, n in candidates.items() if bool(n.attrs.get("group_assignments")) == bool(value)}
        if key in SELECTOR_HOSTS:
            # Collected joins decide membership; accounts without a complete join keep the fallback below.
            host, pending = SELECTOR_HOSTS[key], {}
            for rid, n in candidates.items():
                if self.hosts.get(rid, {}).get(host):
                    out[rid] = None
                elif self.host_status.get((n.scope, host)) not in ("collected", "empty"):
                    pending[rid] = n
            if key == "codedeploy_group_instance_role_covered_by":
                if not any(self.host_status.get((n.scope, host)) for n in candidates.values()):
                    return None  # codedeploy_deployment_group never collected: not evaluated
                out.update({rid: ("unknown", "codedeploy_group_instances_not_collected") for rid in pending})
                return out
            candidates = pending
        absent_when_empty = {"cognito_user_pool_covered_by": ("cognito_user_pool", "cognito_identity_pool_roles_not_collected"),
                             "cognito_user_pool_group_role_covered_by": ("cognito_user_pool", "cognito_user_pool_groups_not_collected"),
                             "rolesanywhere_profile_includes_target": ("rolesanywhere_trust_anchor", "rolesanywhere_profiles_not_collected")}
        if key in absent_when_empty:
            # Dropped only when the account's inventory was fully collected with no pool / trust anchor; otherwise
            # the role mapping is not collected and the match stays unknown.
            kind, why = absent_when_empty[key]
            for rid, n in candidates.items():
                if not (self._collected(self.presence_status.get(kind, {}), n.scope) and not self.presence.get(kind, {}).get(n.scope)):
                    out[rid] = ("unknown", why)
            return out
        if key == "eks_authentication_mode":
            wanted = {str(v).upper() for v in as_list(value)}
            for tid, n in candidates.items():
                mode = n.attrs.get("authentication_mode")
                if mode is None:
                    out[tid] = ("unknown", "eks_authentication_mode_not_collected")
                elif mode in wanted:
                    out[tid] = None
            return out
        if key == "trust_allows_oidc_provider_covered_by":
            for rid, n in candidates.items():
                confs = [self.trust_by_federated.get(f.lower(), {}).get(rid, ("conditional",))[0]
                         for f in self._federated(n) if ":oidc-provider/" in f]
                if confs:
                    out[rid] = None if "derived" in confs else ("conditional", "trust_condition")
            return out
        if key == "trust_federated_provider_missing":
            kinds = {"saml": ("iam_saml_provider", ":saml-provider/"), "oidc": ("iam_oidc_provider", ":oidc-provider/")}
            for rid, n in candidates.items():
                for wanted in as_list(value):
                    kind, marker = kinds.get(str(wanted).lower(), (None, None))
                    if kind is None:
                        continue
                    providers = [f for f in self._federated(n) if marker in f and _account(f) == n.scope]
                    if not providers:
                        continue
                    if not self._collected(self.idp_status.get(kind, {}), n.scope):
                        if rid not in out:
                            out[rid] = ("unknown", f"{kind}_not_collected")
                    elif any(f not in self.idps[kind] for f in providers):
                        out[rid] = None
            return out
        if key == "trust_allows_principal_org":
            root = self._org_root()
            for rid, n in candidates.items():
                for st in self.trust.get(rid, ()):
                    if st.effect != "allow" or not st.condition or not st.action_matches("sts:AssumeRole"):
                        continue
                    principal = st.principals
                    aws = ["*"] if principal == "*" else [str(v) for v in as_list((principal or {}).get("AWS"))] if isinstance(principal, dict) else []
                    text = json.dumps(st.condition).lower()
                    if "*" not in aws or ("aws:principalorgid" not in text and "aws:principalorgpaths" not in text):
                        continue
                    if self.org_id is None:
                        verdict = ("unknown", "organization_id_not_collected")
                    else:
                        overrides = {"aws:principalorgid": [self.org_id]}
                        if root:
                            overrides["aws:principalorgpaths"] = [f"{self.org_id}/{root}/"]  # CreateAccount places the account in the root
                        got, _ = evaluate_condition(st.condition, Context(action="sts:assumerole", resource=rid, overrides=overrides))
                        if got is False:
                            continue
                        verdict = None if got is True else ("conditional", "trust_condition")
                    if rid not in out or verdict is None or (out[rid] and out[rid][0] == "unknown"):
                        out[rid] = verdict
            return out
        if key == "org_member_account":
            for tid, n in candidates.items():
                account = n.attrs.get("account", n.scope)
                if not self._org_known():
                    out[tid] = ("unknown", "organization_accounts_not_collected")
                elif account in self.org_accounts and account != self.org_management:
                    out[tid] = None
            return out
        if key == "emr_runtime_role_of_cluster":
            ec2 = self.trust_by_service.get("ec2.amazonaws.com", {})
            for rid, n in candidates.items():
                hosts = [h for norm in self.trust_names.get(rid, ()) for h in self._roles_by_norm(norm)
                         if h.id != rid and h.id in ec2 and h.attrs.get("instance_profiles")]
                if not hosts:
                    continue
                if not self._collected(self.emr_status, n.scope):
                    out[rid] = ("unknown", "emr_cluster_not_collected")
                elif any(str(p).rsplit("/", 1)[-1] in self.emr_runtime_profiles for h in hosts for p in h.attrs["instance_profiles"]):
                    out[rid] = None
            return out
        if key == "trust_allows_emr_containers_oidc":
            for rid, n in candidates.items():
                for st in self.trust.get(rid, ()):
                    if st.effect != "allow" or not isinstance(st.principals, dict):
                        continue
                    if any(":oidc-provider/oidc.eks." in str(f) for f in as_list(st.principals.get("Federated"))) and \
                            "emr-containers-sa-" in json.dumps(st.condition or {}).lower():
                        out[rid] = None
            return out
        if key == "instance_profile_name_prefix_or_path":
            for rid, n in candidates.items():
                profiles = n.attrs.get("instance_profiles")
                if profiles is None:
                    out[rid] = ("unknown", "instance_profiles_not_collected")
                    continue
                for arn in profiles:
                    rest = str(arn).split(":instance-profile/", 1)[-1]
                    path, _, name = rest.rpartition("/")
                    path = f"/{path}/" if path else "/"
                    if any((str(v).startswith("/") and str(v) in path) or (not str(v).startswith("/") and name.startswith(str(v)))
                           for v in as_list(value)):
                        out[rid] = None
                        break
            return out
        if key == "portfolio_of_target_product_covered_by":
            for rid, n in candidates.items():
                if not self._collected(self.sc_status, n.scope):
                    out[rid] = ("unknown", "servicecatalog_portfolio_not_collected")
                elif self.sc_portfolios.get(_norm_arn(rid)):
                    out[rid] = None
            return out
        if key == "ecs_task_role_on_ec2_capacity":
            for rid, n in candidates.items():
                verdict = self._ecs_task_role_verdict(n)
                if verdict is not False:
                    out[rid] = verdict
            return out
        if key == "ecs_container_instance_role_in_cluster_covered_by":
            for rid, n in candidates.items():
                verdict = self._ecs_node_verdict(n)
                if verdict is not False:
                    out[rid] = verdict
            return out
        if key == "ecs_task_colocated_with_source_container_instance":
            if source is None or source.kind != "aws_role" or source.attrs.get("instance_profiles") == [] or \
                    source.id not in self.trust_by_service.get("ec2.amazonaws.com", {}):
                return {}  # only an EC2 container-instance role can poll the agent channel of its instance
            for rid, n in candidates.items():
                verdict = self._ecs_colocated(source, n)
                if verdict is not False:
                    out[rid] = verdict
            return out
        return None

    # ------------------------------------------------------------------- ECS
    def _ecs_account(self, account):
        """(clusters of the account, True when every region's cluster inventory and instance counts were collected)."""
        clusters = [c for c in self.ecs_cluster_info.values() if c["account"] == account]
        complete = self._account_status("ecs_cluster", account) == "collected" and all(c["count"] is not None for c in clusters)
        return clusters, complete

    def _ecs_task_def_roles(self, role):
        defs = self.ecs_task_roles.get(role.id)
        if defs is None:
            norm = _norm_arn(role.id)
            defs = [d for arn, ds in self.ecs_task_roles.items() if _norm_arn(arn) == norm for d in ds]
        return defs

    def _ec2_task_role(self, role):
        """True: the role is the task role of an EC2/EXTERNAL-capable task definition; False: provably not; None: unknown."""
        if any(d[2] for d in self._ecs_task_def_roles(role)):
            return True
        return False if self._account_status("ecs_task_definition", role.scope) == "collected" else None

    def _task_role(self, task):
        return (task.get("overrides") or {}).get("taskRoleArn") or self.ecs_taskdef_role.get(str(task.get("taskDefinitionArn")))

    def _placement_known(self, clusters, complete):
        return complete and all(c["instances"] is not None and c["tasks"] is not None for c in clusters)

    def _ec2_tasks(self, clusters):
        for c in clusters:
            for task in c["tasks"] or ():
                if str(task.get("launchType") or "EC2").upper() in ("EC2", "EXTERNAL"):
                    yield c, task

    def _ecs_task_role_verdict(self, role):
        clusters, complete = self._ecs_account(role.scope)
        norm = _norm_arn(role.id)
        if any(_norm_arn(self._task_role(t) or "") == norm for _, t in self._ec2_tasks(clusters)):
            return None
        ec2 = self._ec2_task_role(role)
        if ec2 is False:
            return False
        if complete and not any(c["count"] for c in clusters):
            return False  # no cluster of the account has EC2 container instances
        if ec2 is None:
            return ("unknown", "ecs_task_definition_not_collected") if role.id in self.trust_by_service.get("ecs-tasks.amazonaws.com", {}) else False
        if not complete:
            return ("unknown", "ecs_container_instances_not_collected")
        return ("conditional", "ecs_task_placement_not_collected")

    def _ecs_node_verdict(self, role):
        clusters, complete = self._ecs_account(role.scope)
        if complete and not any(c["count"] for c in clusters):
            return False
        instance_role = bool(role.attrs.get("instance_profiles")) and role.id in self.trust_by_service.get("ec2.amazonaws.com", {})
        task_role = self._ec2_task_role(role)
        if not instance_role and (task_role is False or (task_role is None and
                                                          role.id not in self.trust_by_service.get("ecs-tasks.amazonaws.com", {}))):
            return False
        if not self._placement_known(clusters, complete):
            return ("unknown", "ecs_container_instances_not_collected")
        ec2_ids = {iid for c in clusters for iid in c["instances"].values() if iid}
        if instance_role and any(a.rsplit("/", 1)[-1] in ec2_ids for a in self.hosts.get(role.id, {}).get("ec2_instance", ())):
            return None
        norm = _norm_arn(role.id)
        if any(_norm_arn(self._task_role(t) or "") == norm and t.get("containerInstanceArn") for _, t in self._ec2_tasks(clusters)):
            return None
        return False

    def _ecs_colocated(self, source, role):
        if role.scope != source.scope:
            return False
        clusters, complete = self._ecs_account(role.scope)
        ec2 = self._ec2_task_role(role)
        if ec2 is False or (complete and not any(c["count"] for c in clusters)):
            return False
        if self._placement_known(clusters, complete):
            mine = {a.rsplit("/", 1)[-1] for a in self.hosts.get(source.id, {}).get("ec2_instance", ())}
            cis = {ci for c in clusters for ci, iid in c["instances"].items() if iid in mine}
            norm = _norm_arn(role.id)
            hit = any(t.get("containerInstanceArn") in cis and _norm_arn(self._task_role(t) or "") == norm
                      for _, t in self._ec2_tasks(clusters))
            return None if hit else False
        if ec2 is None:
            return ("unknown", "ecs_task_definition_not_collected")
        return ("unknown", "ecs_task_placement_not_collected")

    def _load_workload_hosts(self, snap):
        """CodeBuild projects, Glue jobs, Redshift clusters and RDS instances with the roles they carry. Returns the
        (account, host) keys whose inventory is partial because an item's role could not be read."""
        by_name = {}
        for pid, node in self.principals.items():
            if ":role/" in str(pid):
                by_name.setdefault((node.scope, str(pid).rsplit("/", 1)[-1]), pid)
        partial = set()
        self.ib_components = {}  # pipeline arn -> hijackable component name prefixes (component/<name>/*), None = recipe not collected
        by_profile = {}  # (account, instance profile name) -> role arns
        for pid, node in self.principals.items():
            for profile in node.attrs.get("instance_profiles") or []:
                by_profile.setdefault((node.scope, str(profile).rsplit("/", 1)[-1]), []).append(pid)

        def role_arn(value, account):
            value = str(value or "")
            return value if value.startswith("arn:") else by_name.get((account, value), f"arn:aws:iam::{account}:role/{value}")

        for kind, host in WORKLOAD_HOSTS.items():
            for scope, item in items(snap, kind):
                account = str(item.get("AccountId") or scope.split("/")[0])
                region = item.get("Region") or (scope.split("/")[1] if "/" in scope else "*")
                found = []  # (role arn or None, resource arn)
                if kind == "codebuild_project":
                    config = item.get("Configuration") or {}
                    projects = config.get("projects") if isinstance(config, dict) else None
                    if not isinstance(projects, list) or config.get("collection_status") not in (None, "collected"):
                        found.append((None, None))
                    for project in projects if isinstance(projects, list) else ():
                        found.append((project.get("serviceRole"), project.get("arn")))
                elif kind == "glue_job":
                    found.append((item.get("Role"), item.get("Name") and f"arn:aws:glue:{region}:{account}:job/{item['Name']}"))
                elif kind == "redshift_cluster":
                    arn = item.get("ClusterIdentifier") and f"arn:aws:redshift:{region}:{account}:cluster:{item['ClusterIdentifier']}"
                    found += [((r or {}).get("IamRoleArn"), arn) for r in as_list(item.get("IamRoles"))]
                elif kind == "sagemaker_notebook_instance":
                    # RoleArn comes from the describe_notebook_instance merge; a failed detail read leaves it absent.
                    found.append((item.get("RoleArn"), item.get("NotebookInstanceArn")))
                elif kind == "imagebuilder_pipeline":
                    # Build instances run with the infrastructure configuration's instance profile.
                    name = item.get("InstanceProfileName")
                    if not name:
                        found.append((None, None))
                    found += [(role, item.get("arn")) for role in by_profile.get((account, str(name)), [])] if name else []
                    if item.get("arn"):
                        self.ib_components[item["arn"]] = _ib_wildcard_components(item.get("RecipeComponents"), account)
                elif kind == "sagemaker_user_profile":
                    arn = item.get("UserProfileArn") or (item.get("DomainId") and item.get("UserProfileName") and
                                                         f"arn:aws:sagemaker:{region}:{account}:user-profile/{item['DomainId']}/{item['UserProfileName']}")
                    if "ExecutionRole" not in item:
                        found.append((None, arn))
                    elif item["ExecutionRole"]:
                        found.append((item["ExecutionRole"], arn))
                elif kind == "sagemaker_cluster":
                    groups = item.get("InstanceGroups")
                    if not isinstance(groups, list):
                        found.append((None, None))
                    found += [((g or {}).get("ExecutionRole"), item.get("ClusterArn")) for g in groups or []]
                else:
                    found += [((r or {}).get("RoleArn"), item.get("DBInstanceArn")) for r in as_list(item.get("AssociatedRoles"))]
                for role, resource in found:
                    if not role or not resource:
                        partial.add((account, host))
                        continue
                    listed = self.hosts.setdefault(role_arn(role, account), {}).setdefault(host, [])
                    if resource not in listed:
                        listed.append(resource)
        return partial

    def _load_serverless_hosts(self, snap):
        """Redshift Serverless workgroups carry the IAM roles of their namespace (iamRoles / defaultIamRoleArn).
        Returns the partial (account, host) keys (a workgroup whose namespace was not listed)."""
        host, partial, namespaces = "redshift_serverless_workgroup", set(), {}
        for scope, item in items(snap, "redshiftserverless_namespace"):
            account = str(item.get("AccountId") or scope.split("/")[0])
            region = scope.split("/")[1] if "/" in scope else "*"
            roles = [m for r in as_list(item.get("iamRoles")) + [item.get("defaultIamRoleArn")]
                     for m in _IAM_ROLE_RE.findall(str((r or {}).get("iamRoleArn") if isinstance(r, dict) else r or ""))]
            namespaces[(account, region, item.get("namespaceName"))] = list(dict.fromkeys(roles))
        for scope, item in items(snap, "redshiftserverless_workgroup"):
            account = str(item.get("AccountId") or scope.split("/")[0])
            region = scope.split("/")[1] if "/" in scope else "*"
            roles = namespaces.get((account, region, item.get("namespaceName")))
            if roles is None or not item.get("workgroupArn"):
                partial.add((account, host))
                continue
            for role in roles:
                listed = self.hosts.setdefault(role, {}).setdefault(host, [])
                if item["workgroupArn"] not in listed:
                    listed.append(item["workgroupArn"])
        return partial

    def _load_ext_hosts(self, snap):
        """aws_facts_ext joins: Cognito user-pool group roles and identity-pool roles of federated user pools, CodeDeploy
        deployment groups -> tag-matched EC2 instance roles, Roles Anywhere profiles; application planes and Identity
        Center group assignments. Returns the partial (account, host) keys."""
        ok, partial = ("collected", "empty"), set()

        def add(role, host, resource):
            listed = self.hosts.setdefault(role, {}).setdefault(host, [])
            if resource not in listed:
                listed.append(resource)

        def where(scope, item):
            return str(item.get("AccountId") or scope.split("/")[0]), (scope.split("/")[1] if "/" in scope else "*")

        for scope, item in items(snap, "cognito_user_pool"):
            account, region = where(scope, item)
            arn = item.get("Arn") or f"arn:aws:cognito-idp:{region}:{account}:userpool/{item.get('Id')}"
            groups = item.get("Groups")
            if not isinstance(groups, dict) or groups.get("collection_status") not in ok:
                partial.add((account, "cognito_user_pool_group"))
                continue
            for group in as_list(groups.get("items")):
                if isinstance(group, dict) and group.get("RoleArn"):
                    add(group["RoleArn"], "cognito_user_pool_group", arn)
        for scope, item in items(snap, "cognito_identity_pool"):
            account, region = where(scope, item)
            config, roles = item.get("Configuration") or {}, item.get("Roles")
            # Identity pool -> its authenticated / unauthenticated roles (cognito-identity:GetIdentityPoolRoles Roles.Roles).
            if isinstance(roles, dict) and roles.get("collection_status") in ok and item.get("IdentityPoolId"):
                pool_arn = f"arn:aws:cognito-identity:{region}:{account}:identitypool/{item['IdentityPoolId']}"
                for role in (roles.get("Roles") or {}).values() if isinstance(roles.get("Roles"), dict) else ():
                    if isinstance(role, str) and role:
                        add(role, "cognito_identity_pool", pool_arn)
            else:
                partial.add((account, "cognito_identity_pool"))
            if (not isinstance(roles, dict) or roles.get("collection_status") not in ok
                    or not isinstance(config, dict) or config.get("collection_status") not in (None, "collected")):
                partial.add((account, "cognito_user_pool_identity_pool"))
                continue
            mappings = roles.get("RoleMappings") or {}
            for provider in as_list(config.get("CognitoIdentityProviders")):
                name = str((provider or {}).get("ProviderName") or "")
                match = re.fullmatch(r"cognito-idp\.([a-z0-9-]+)\.amazonaws\.com/([\w-]+)", name)
                if not match:
                    continue
                pool = f"arn:aws:cognito-idp:{match.group(1)}:{account}:userpool/{match.group(2)}"
                mapped = [m for key, m in mappings.items() if key.startswith(name)] if isinstance(mappings, dict) else []
                reachable = [(roles.get("Roles") or {}).get("authenticated")]
                reachable += [r.get("RoleARN") for m in mapped for r in as_list(((m or {}).get("RulesConfiguration") or {}).get("Rules"))
                              if isinstance(r, dict)]
                for role in reachable:
                    if role:
                        add(role, "cognito_user_pool_identity_pool", pool)
        # CodeDeploy EC2/on-premises deployment groups: instances matched by tag filters / tag sets / Auto Scaling groups.
        roles_of = {}
        for role, hosts in self.hosts.items():
            for arn in hosts.get("ec2_instance", ()):
                roles_of.setdefault(arn, []).append(role)

        def tag_match(rule, tags):
            key, value, kind = rule.get("Key"), rule.get("Value"), str(rule.get("Type") or "KEY_AND_VALUE")
            return (key in tags if kind == "KEY_ONLY" else value in tags.values() if kind == "VALUE_ONLY"
                    else key in tags and tags[key] == value)

        for scope, item in items(snap, "codedeploy_deployment_group"):
            account, region = where(scope, item)
            if str(item.get("computePlatform") or "Server") != "Server":
                continue
            if not any(k in item for k in ("ec2TagFilters", "ec2TagSet", "autoScalingGroups")) or not self._region_ok("instance", account, region):
                partial.add((account, "codedeploy_deployment_group"))
                continue
            arn = f"arn:aws:codedeploy:{region}:{account}:deploymentgroup:{item.get('applicationName')}/{item.get('deploymentGroupName')}"
            filters = [f for f in as_list(item.get("ec2TagFilters")) if isinstance(f, dict)]
            sets = [[f for f in as_list(group) if isinstance(f, dict)]
                    for group in as_list((item.get("ec2TagSet") or {}).get("ec2TagSetList"))]
            asgs = {str((g or {}).get("name") if isinstance(g, dict) else g) for g in as_list(item.get("autoScalingGroups"))}
            for instance, (owner, where_region, _, _) in self.instances.items():
                if owner != account or where_region != region:
                    continue
                tags = self.tags.get(instance)
                if tags is None:
                    partial.add((account, "codedeploy_deployment_group"))
                    continue
                hit = (any(tag_match(f, tags) for f in filters) or (bool(sets) and all(any(tag_match(f, tags) for f in g) for g in sets))
                       or tags.get("aws:autoscaling:groupName") in asgs)
                for role in roles_of.get(instance, []) if hit else ():
                    add(role, "codedeploy_deployment_group", arn)
        for scope, item in items(snap, "rolesanywhere_profile"):
            if item.get("enabled") is False or not item.get("profileArn"):
                continue
            for role in as_list(item.get("roleArns")):
                add(role, "rolesanywhere_profile", item["profileArn"])
        for host, kind in (("cognito_user_pool_group", "cognito_user_pool"), ("cognito_user_pool_identity_pool", "cognito_identity_pool"),
                           ("codedeploy_deployment_group", "codedeploy_deployment_group"), ("rolesanywhere_profile", "rolesanywhere_profile"),
                           ("cognito_identity_pool", "cognito_identity_pool")):
            for scope, status in inventory_status(snap, kind).items():
                key = (scope.split("/")[0], host)
                if self.host_status.get(key) in (None, "collected", "empty"):
                    self.host_status[key] = "partial" if key in partial else status
        # Application planes (aws_service_plane_admin targets) and Identity Center group assignments.
        self.planes, self.plane_partial, self.ic_group_assignments = {}, {}, {}
        for plane, kind in SERVICE_PLANES.items():
            seen = set()
            for scope, item in items(snap, kind):
                account, _ = where(scope, item)
                if plane == "quicksight":
                    arn = f"arn:aws:quicksight:*:{account}:user/*"  # users live in the (unrecorded) identity Region
                elif plane == "amplifybackend":
                    backends = item.get("BackendEnvironments")
                    if not isinstance(backends, dict) or backends.get("collection_status") not in ok:
                        self.plane_partial.setdefault(plane, set()).add(account)
                        continue
                    if not backends.get("items"):
                        continue  # Gen 2 / frontend-only apps have no Amplify Studio backend.
                    arn = item.get("appArn")
                else:
                    arn = item.get("Arn") or item.get("arn")
                if (account, arn) not in seen:
                    seen.add((account, arn))
                    self.planes.setdefault(plane, []).append((account, arn))
        for scope, item in items(snap, "aws_identity_center_account_assignment"):
            if str(item.get("PrincipalType")) == "GROUP":
                account = scope.split("/")[0]
                self.ic_group_assignments[account] = self.ic_group_assignments.get(account, 0) + 1
        return partial

    def _attached(self, role, service):
        """None (attachment derived from inventory), (conf, why) or False (not attached)."""
        service = str(service)
        low = service.lower()
        host = HOST_KIND.get(low)
        if host:
            if self.hosts.get(role.id, {}).get(host):
                return None
            if self.host_status.get((role.scope, host)) in ("collected", "empty"):
                return False
        principals = RESOURCE_TYPE_SERVICES.get(low, (_service_principal(low),))
        if any(role.id in self.trust_by_service.get(p, {}) for p in principals):
            return ("unknown", f"{low}_attachment_not_collected")
        if low == "cognito_identity_pool" and role.id in self.trust_by_federated.get("cognito-identity.amazonaws.com", {}):
            return ("unknown", "cognito_identity_pool_roles_not_collected")  # identity-pool roles trust a Federated principal
        return False

    # ------------------------------------------------------------ preconditions
    RUNNING_STATES = ("pending", "running")

    def _account_status(self, kind, account):
        """'collected' when every region of the account was collected (or empty), else the worst status / None."""
        statuses = [st for scope, st in self.region_status.get(kind, {}).items() if scope.split("/")[0] == account]
        if not statuses:
            return None
        bad = [st for st in statuses if st not in ("collected", "empty")]
        return bad[0] if bad else "collected"

    def _region_ok(self, kind, account, region):
        status = self.region_status.get(kind, {}).get(f"{account}/{region}")
        return status in ("collected", "empty")

    def precondition(self, pid, candidates, source):
        out = {}
        if pid == "target_in_other_account":
            return {tid: None for tid, n in candidates.items() if source is None or n.scope != source.scope}
        if pid in ("ec2_instance_running", "ssm_managed_instance"):
            for rid, node in candidates.items():
                verdict = self._instance_fact(pid, node)
                if verdict is not False:
                    out[rid] = verdict
            return out
        if pid == "ecs_container_instance_exists":
            for tid, node in candidates.items():
                counts = self.ecs_clusters.get(node.scope, [])
                status = self._account_status("ecs_cluster", node.scope)
                if any(c for c in counts if c):
                    out[tid] = None
                elif status != "collected" or any(c is None for c in counts):
                    out[tid] = ("unknown", "ecs_container_instances_not_collected")
            return out
        if pid == "eks_cluster_exists":
            for tid, node in candidates.items():
                account = node.attrs.get("account", node.scope)
                if any(info["account"] == account for info in self.eks.values()):
                    out[tid] = None
                elif self._account_status("eks_cluster", account) != "collected":
                    out[tid] = ("unknown", "eks_cluster_not_collected")
            return out
        if pid == "source_in_org_management_account":
            if source is None:
                return None
            if not self._org_known():
                return {tid: ("unknown", "organization_accounts_not_collected") for tid in candidates}
            return dict.fromkeys(candidates) if source.scope == self.org_management else {}
        if pid == "ecs_task_definition_exists":
            for tid, node in candidates.items():
                if self.ecs_task_definitions.get(node.scope):
                    out[tid] = None
                elif self._account_status("ecs_task_definition", node.scope) != "collected":
                    out[tid] = ("unknown", "ecs_task_definition_not_collected")
            return out
        return None

    def _instance_fact(self, pid, role):
        """None (proven), ("unknown", why) or False for the instance preconditions of one role."""
        arns = self.hosts.get(role.id, {}).get("ec2_instance", [])
        complete = role.attrs.get("instance_profiles") is not None and self._account_status("instance", role.scope) == "collected"
        states = [self.instances.get(a) for a in arns]
        running = [s for s in states if s and s[3] in self.RUNNING_STATES]
        if any(s and s[3] is None for s in states):
            return ("unknown", "instance_state_not_collected")
        if not running:
            return False if complete else ("unknown", "instance_inventory_not_collected")
        if pid == "ec2_instance_running":
            return None
        unknown = False
        for account, region, iid, _ in running:
            if (account, iid) in self.ssm_managed and self.ssm_managed[(account, iid)].lower() == "online":
                return None
            if not self._region_ok("ssm_managed_instance", account, region):
                unknown = True
        return ("unknown", "ssm_managed_instance_not_collected") if unknown else False

    # ------------------------------------------------------------------ admin
    def admin_targets(self, principal):
        ctx = Context(principal=principal, action="*", resource=None)
        grant = None
        for pid in principal.attrs["policy_ids"]:
            for st in self.policies[pid].statements:
                if st.effect == "allow" and not st.notaction and any(a in ("*", "*:*") for a in st.actions) and \
                        not st.notresource and "*" in st.resources:
                    verdict = self._cond(st, ctx, "allow")[0] if st.conditional else True
                    if verdict is False:
                        continue
                    proven = verdict is True and not st.resource_dep
                    g = Grant("derived" if proven else "conditional", [st.ref], [] if proven else ["allow_statement_has_condition"])
                    grant = _best(grant, g)
        if grant is None:
            return []
        for pid in principal.attrs["policy_ids"]:
            for st in self.policies[pid].statements:
                if st.effect == "deny":
                    verdict = self._cond(st, ctx, "deny")[0]
                    if verdict is False:
                        continue
                    if any(a in ("*", "*:*") for a in st.actions) and "*" in st.resources and verdict is True and not st.notaction:
                        return []
                    grant = downgrade(grant, "conditional", "explicit_deny_present")
        grant = self._guardrails(principal, "iam:attachuserpolicy", ANY, grant)
        if grant is None:
            return []
        boundary = principal.attrs.get("boundary")
        if boundary and self.policies.get(boundary):
            if not any(st.effect == "allow" and any(a in ("*", "*:*") for a in st.actions) and "*" in st.resources
                       for st in self.policies[boundary].statements):
                return []
        return [(self.entity("aws_account_admin", principal.scope), grant)]

    def scope_within(self, inner, outer):
        return inner == outer


RESOURCE_TYPE_SERVICE = {
    "ecs_task": "ecs-tasks.amazonaws.com", "ssm_automation_document": "ssm.amazonaws.com",
    "glue_job": "glue.amazonaws.com", "glue_dev_endpoint": "glue.amazonaws.com", "glue_session": "glue.amazonaws.com",
    "emr_cluster": "ec2.amazonaws.com", "elasticbeanstalk_environment": "ec2.amazonaws.com",
    "sagemaker_notebook_instance": "sagemaker.amazonaws.com", "sagemaker_user_profile": "sagemaker.amazonaws.com",
    "stepfunctions_state_machine": "states.amazonaws.com", "fis_experiment_template": "fis.amazonaws.com",
    "synthetics_canary": "lambda.amazonaws.com", "servicecatalog_product": "servicecatalog.amazonaws.com",
    "rds_db_instance": "rds.amazonaws.com", "redshift_cluster": "redshift.amazonaws.com",
    "redshift_serverless_workgroup": "redshift.amazonaws.com", "transfer_user": "transfer.amazonaws.com",
    # Image Builder pipelines run builds as their infrastructure configuration's EC2 instance-profile role.
    "imagebuilder_pipeline": "ec2.amazonaws.com", "sagemaker_cluster": "sagemaker.amazonaws.com",
    "stepfunctions": "states.amazonaws.com", "cloudformation": "cloudformation.amazonaws.com",
}


_ARN_TOKEN = "peasobound"

def _instantiate(pattern):
    """A concrete resource name matching the glob (wildcards filled with a token)."""
    return pattern.replace("*", _ARN_TOKEN).replace("?", "x")

def _unify_arn(a, b):
    """Field-wise unification of two ARN patterns (a '*' field takes the other's field); None when not ARNs."""
    if not (a.startswith("arn:") and b.startswith("arn:")):
        return None
    fa, fb = a.split(":", 5), b.split(":", 5)
    if len(fa) != 6 or len(fb) != 6:
        return None
    out = []
    for x, y in zip(fa, fb):
        if x == y or y in ("*", ""):
            out.append(x)
        elif x in ("*", ""):
            out.append(y)
        elif "*" in x or "?" in x:
            out.append(y if glob_match(x, y, False) else x)
        else:
            out.append(x)
    return ":".join(out)

def _ctx_label(choice):
    parts = []
    for key, value in sorted(choice.items()):
        shown = "absent" if value is ABSENT else "chosen" if value is CHOSEN else ",".join(value)
        parts.append(f"{key}={shown}")
    return ";".join(parts)

def _merge_choice(winner, got):
    """best() across request-context choices for single grants; per-target dicts / AllTargets are not mixed."""
    if got is None:
        return winner
    if winner is None:
        return got
    if isinstance(winner, Grant) and isinstance(got, Grant):
        return _BEST(winner, got)
    return winner

def _service_principal(service):
    if service in RESOURCE_TYPE_SERVICE:
        return RESOURCE_TYPE_SERVICE[service]
    if service in SERVICE_PRINCIPALS:
        return SERVICE_PRINCIPALS[service]
    if "." in service:
        return service
    return f"{service.split('_', 1)[0]}.amazonaws.com"


def _resource_principal(st, principal):
    """'direct' when a resource-policy statement names the principal (or everyone), 'account' when it names
    the principal's account (delegation to IAM), else None."""
    if st.principals is None:
        return None
    value = st.principals
    if value == "*":
        return "direct"
    if not isinstance(value, dict):
        return None
    for entry in as_list(value.get("AWS")):
        entry = str(entry)
        if entry == "*":
            return "direct"
        if entry == principal.id or _norm_arn(entry) == _norm_arn(principal.id):
            return "direct"
        if entry == principal.scope or entry.endswith(f"::{principal.scope}:root"):
            return "account"
    return None


def _best(a, b):
    return _BEST(a, b)



_IB_COMPONENT_RE = re.compile(r"^(arn:aws[\w-]*:imagebuilder:[^:]+:(\d{12}|aws):component/[^/]+)/([^/]+)(?:/[^/]+)?$")


def _ib_wildcard_components(recipe, account):
    """component/<name>/* prefixes of a recipe's account-owned components referenced by a version wildcard (x)."""
    if not isinstance(recipe, dict) or recipe.get("collection_status") != "collected" or not isinstance(recipe.get("items"), list):
        return None
    out = []
    for arn in recipe["items"]:
        match = _IB_COMPONENT_RE.match(str(arn))
        if match and match.group(2) == str(account) and "x" in match.group(3).lower():
            out.append(match.group(1) + "/*")
    return sorted(set(out))


def _norm_arn(arn):
    """Trust policies name roles/users without path; compare on account + type + final name."""
    match = re.match(r"arn:[^:]+:iam::(\d{12}):(role|user)/(?:.*/)?([^/]+)$", str(arn))
    return f"{match.group(1)}:{match.group(2)}:{match.group(3)}" if match else str(arn)


def _tags(value):
    """{key: value} from an AWS Tags list/dict ({} when there are none)."""
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    out = {}
    for tag in as_list(value):
        if isinstance(tag, dict) and "Key" in tag:
            out[str(tag["Key"])] = str(tag.get("Value", ""))
    return out


def _sub_items(item, key):
    """Items of an optional nested collection ({"collection_status", "items"} or a list); None when not collected."""
    value = item.get(key)
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if value.get("collection_status", "collected") not in ("collected", "empty"):
            return None
        for name in ("items", "containerInstances", "tasks"):
            if isinstance(value.get(name), list):
                return value[name]
        return [] if value.get("collection_status") == "empty" else None
    return None


def _container_instances(item):
    """Registered container instances of an ecs_cluster item (describe_clusters), None when not collected."""
    for key in ("registeredContainerInstancesCount",):
        if isinstance(item.get(key), int):
            return item[key]
    config = item.get("Configuration")
    if isinstance(config, dict):
        clusters = config.get("clusters")
        if clusters is None and isinstance(config.get("items"), list):
            clusters = config["items"]
        if clusters is None and "registeredContainerInstancesCount" in config:
            clusters = [config]
        for cluster in as_list(clusters):
            if isinstance(cluster, dict) and isinstance(cluster.get("registeredContainerInstancesCount"), int):
                return cluster["registeredContainerInstancesCount"]
    return None
