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
  * resource-based policies where collected (lambda, s3, kms, sns, sqs, secrets
    manager, ecr): same-account grants may come from either side, cross-account
    needs both, KMS needs the key policy to grant or delegate to the account, and an
    explicit Deny on either side wins,
  * role trust policies for selectors, plus the same-account trust policy grant
    for sts:AssumeRole when the trust names the source ARN directly.
"""
from __future__ import annotations

import json
import re
from urllib.parse import unquote

from . import (ANY, AllTargets, Grant, Model, Node, as_list, combine, downgrade, glob_match, inventory_status,
               items, unavailable)

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
             "ec2_instance": "ec2_instance"}


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


class Statement:
    __slots__ = ("effect", "actions", "notaction", "resources", "notresource", "conditional", "ref", "principals")

    def __init__(self, raw, ref):
        self.effect = str(raw.get("Effect", "")).lower()
        self.notaction = "NotAction" in raw
        self.actions = [str(a) for a in as_list(raw.get("NotAction" if self.notaction else "Action"))]
        self.notresource = "NotResource" in raw
        self.resources = [str(r) for r in as_list(raw.get("NotResource" if self.notresource else "Resource", "*"))]
        variables = any("${" in r for r in self.resources)
        self.conditional = bool(raw.get("Condition")) or variables
        self.ref = ref
        self.principals = raw.get("Principal", raw.get("NotPrincipal"))

    def action_matches(self, action):
        hit = any(glob_match(p, action) for p in self.actions)
        return not hit if self.notaction else hit

    def resource_matches(self, resource):
        if resource is ANY:
            return True
        hit = any(_resource_glob(p, resource) for p in self.resources)
        return not hit if self.notresource else hit

    def covers_all_resources(self):
        return not self.notresource and "*" in self.resources and not self.conditional


def _resource_glob(pattern, resource):
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
    entity_kinds = ("aws_account_admin", "aws_identity_center_permission_set")

    def __init__(self, snapshot, catalog_keys=()):
        super().__init__(snapshot, catalog_keys)
        self.policies, self.accounts = {}, set()
        self.roles_by_name = {}
        self.trust = {}            # role arn -> list[Statement]
        self.trust_by_service, self.trust_by_arn, self.trust_by_account, self.trust_public = {}, {}, {}, {}
        self.trust_by_federated = {}
        self.hosts = {}            # role arn -> {host kind: [resource arns]}
        self.host_status = {}      # (account, host kind) -> status
        self.scp = {}              # account -> list[Policy]
        self.scp_status = {}
        self.scp_by_target = {}    # account / OU / root id -> list[Policy]
        self.org_parent = {}       # account / OU id -> parent id
        self.inherited = {}        # account -> (status, set of OU/root ids carrying inherited SCPs)
        self.resource_policies = {}  # resource arn -> (account, [Statement], kind)
        self.ecr = {}              # account -> [(repository arn, imageTagMutability)]
        self.ecr_status = {}
        self._stmt_cache, self._possible_cache = {}, {}
        self._load()
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
        groups = {}
        for scope, item in items(snap, "iam_group"):
            node = self._principal(item, "aws_group", scope, item.get("GroupName"), "GroupPolicyList")
            if node:
                groups[(node.scope, item.get("GroupName"))] = node
        for scope, item in items(snap, "iam_role"):
            node = self._principal(item, "aws_role", scope, item.get("RoleName"), "RolePolicyList")
            if not node:
                continue
            node.attrs["instance_profiles"] = [p.get("Arn") for p in as_list(item.get("InstanceProfileList")) if isinstance(p, dict)]
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
            for profile in role.attrs.get("instance_profiles", []):
                profile_roles.setdefault(profile, []).append(role.id)
        for scope, item in items(snap, "lambda_function"):
            role = item.get("Role")
            if role:
                self.hosts.setdefault(role, {}).setdefault("lambda_function", []).append(item.get("FunctionArn"))
        for scope, item in items(snap, "instance"):
            profile = (item.get("IamInstanceProfile") or {}).get("Arn")
            account = item.get("AccountId") or scope.split("/")[0]
            arn = f"arn:aws:ec2:{item.get('Region', '*')}:{account}:instance/{item.get('InstanceId')}"
            for role in profile_roles.get(profile, []):
                self.hosts.setdefault(role, {}).setdefault("ec2_instance", []).append(arn)
        for kind, host in (("lambda_function", "lambda_function"), ("instance", "ec2_instance")):
            for scope, status in inventory_status(snap, kind).items():
                # Regions are separate collections: any unavailable region makes the account's inventory partial.
                key = (scope.split("/")[0], host)
                if self.host_status.get(key) in (None, "collected", "empty"):
                    self.host_status[key] = status
        for scope, status in inventory_status(snap, "scp_policy").items():
            self.scp_status[scope.split("/")[0]] = status
        for scope, item in items(snap, "scp_policy"):
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
        node = Node(arn, kind, "aws", account, name, attrs={"arn": arn, "name": name, "account": account,
                    "policy_ids": ids, "boundary": boundary}, incomplete=incomplete)
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
            if principal == "*":
                principal = {"AWS": "*"}
            if not isinstance(principal, dict):
                continue
            for value in as_list(principal.get("Service")):
                self.trust_by_service.setdefault(str(value).lower(), {})[role.id] = (conf, st.ref)
            for value in as_list(principal.get("Federated")):
                self.trust_by_federated.setdefault(str(value).lower(), {})[role.id] = (conf, st.ref)
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

    def _evaluate(self, allows, denies, resource):
        """Identity-style evaluation of one statement set; returns Grant or None."""
        hits = [s for s in allows if s.resource_matches(resource)]
        if not hits:
            return None
        best_allow = next((s for s in hits if not s.conditional), hits[0])
        conf, conditions = ("conditional", ["allow_statement_has_condition"]) if best_allow.conditional else ("derived", [])
        refs = [best_allow.ref]
        for deny in denies:
            if resource is ANY:
                # Only a resource-wide deny removes "the permission on some resource".
                if not deny.notresource and "*" in deny.resources:
                    if not deny.conditional:
                        if all(_resource_glob(d, r) for d in deny.resources for r in best_allow.resources) or "*" in deny.resources:
                            return None
                    conf = "conditional"
                    conditions.append("conditional_explicit_deny")
                    refs.append(deny.ref)
                elif not deny.conditional and not best_allow.notresource and all(
                        any(_resource_glob(d, r) for d in deny.resources) for r in best_allow.resources):
                    return None
                continue
            if deny.resource_matches(resource):
                if not deny.conditional:
                    return None
                conf = "conditional"
                conditions.append("conditional_explicit_deny")
                refs.append(deny.ref)
        return Grant(conf, refs, conditions)

    def check(self, principal, req, ref):
        return self._check_action(principal, self.requirement_key(req), ref)

    def _check_action(self, principal, action, ref):
        allows, denies = self._statements(principal, action)
        grant = self._evaluate(allows, denies, ref)
        rkey = self._resource_key(ref)
        if rkey is not None:
            grant = self._with_resource_policy(principal, action, ref, rkey, grant, denies)
        if grant is None:
            return None
        return self._guardrails(principal, action, ref, grant)

    def _with_resource_policy(self, principal, action, ref, rkey, identity, denies):
        account, statements, kind = self.resource_policies[rkey]
        direct, delegated, conditions = None, False, []
        for st in statements:
            if not st.action_matches(action) or not st.resource_matches(ref):
                continue
            match = _resource_principal(st, principal)
            if st.ref.get("not_principal"):
                match = None if match else "direct"  # NotPrincipal applies to everyone except the listed principals
            if match is None:
                continue
            if st.effect == "deny":
                if not st.conditional:
                    return None
                conditions.append("resource_policy_conditional_deny")
            elif st.effect == "allow":
                if match == "direct":
                    conf = "conditional" if st.conditional else "derived"
                    direct = _best(direct, Grant(conf, [st.ref], ["granted_by_resource_policy"] +
                                                 (["resource_policy_condition"] if st.conditional else [])))
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
            if identity is None and direct is not None and any(d.resource_matches(ref) and not d.conditional for d in denies):
                return None  # identity explicit deny beats a resource-policy allow
            grant = _best(identity, direct)
        if grant is not None and conditions:
            grant = downgrade(grant, "conditional", conditions[0])
        return grant

    def _guardrails(self, principal, action, ref, grant):
        boundary = principal.attrs.get("boundary")
        if boundary:
            policy = self.policies.get(boundary)
            if policy is None:
                grant = downgrade(grant, "conditional", "permissions_boundary_not_collected")
            else:
                st = policy.for_action(action)
                limit = self._evaluate([s for s in st if s.effect == "allow"], [s for s in st if s.effect == "deny"], ref)
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
                        if deny.resource_matches(ref) or (ref is ANY and "*" in deny.resources):
                            if not deny.conditional:
                                return None
                            grant = downgrade(grant, "conditional", "scp_conditional_deny")
                    allowed = allowed or self._evaluate([s for s in st if s.effect == "allow"], [], ref)
                if allowed is None:
                    return None  # every level of the organization path must allow the action
            if not complete:
                grant = downgrade(grant, "conditional", "inherited_scps_not_evaluated")
        elif status != "empty":
            grant = downgrade(grant, "conditional", "scp_not_evaluated")
        if principal.incomplete:
            grant = downgrade(grant, grant.confidence, None)
        return grant

    def localizable(self, req):
        return False

    def allowed_scopes(self, rule, source):
        return {source.scope} if rule == "same_account" else None

    def check_targets(self, principal, req, template, candidates, localized=False):
        action = self.requirement_key(req)
        if template in ("{target.arn}",):
            allows, denies = self._statements(principal, action)
            wide = next((s for s in allows if s.covers_all_resources()), None)
            if wide is not None and not denies:
                grant = self._guardrails(principal, action, "*", Grant("derived", [wide.ref]))
                boundary = principal.attrs.get("boundary")
                if grant is not None and (not boundary or (self.policies.get(boundary) and any(
                        s.covers_all_resources() for s in self.policies[boundary].for_action(action) if s.effect == "allow"))):
                    return AllTargets(grant)
        result = {}
        for target in candidates:
            refs, floor = self.resolve(template, principal, target, selector=self.current_selector)
            grant = None
            for ref in refs:
                grant = _best(grant, self.cached_check(principal, req, ref))
            if action in ASSUME_ACTIONS and target.kind == "aws_role" and template == "{target.arn}":
                grant = _best(grant, self._trust_grant(principal, target, action))
            if grant is not None:
                result[target.id] = downgrade(grant, floor[0], floor[1]) if floor else grant
        return result

    def _trust_grant(self, principal, role, action):
        """Same-account trust policy naming the source ARN grants AssumeRole without identity policy."""
        if principal.scope != role.scope:
            return None
        entry = self.trust_by_arn.get(_norm_arn(principal.id), {}).get(role.id)
        if not entry:
            return None
        allows, denies = self._statements(principal, action)
        for deny in denies:
            if deny.resource_matches(role.id) and not deny.conditional:
                return None
        grant = Grant(entry[0], [entry[1]], ["granted_by_trust_policy"] + (["trust_condition"] if entry[0] != "derived" else []))
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
        if attr in ("attached_resource_arn", "resource_arn", "host_resource"):
            hosts = self.hosts.get(node.id, {})
            wanted = [HOST_KIND.get(str(v)) for v in as_list(selector.get("via_resource_type")) + as_list(selector.get("attached_to_service"))]
            wanted = [w for w in wanted if w]
            if not wanted:
                return None
            values = [arn for w in wanted for arn in hosts.get(w, [])]
            if values:
                return values
            known = all(self.host_status.get((node.scope, w)) in ("collected", "empty") for w in wanted)
            return [] if known else None
        if attr == "saml_provider_arn":
            return [arn for arn in self._federated(node) if ":saml-provider/" in arn] or []
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

    def _federated(self, role):
        return [p for p, roles in self.trust_by_federated.items() if role.id in roles]

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
    def targets(self, kind):
        if kind in ("aws_role", "aws_user", "aws_group"):
            return [n for n in self.principals.values() if n.kind == kind]
        if kind == "aws_account_admin":
            return [self.entity(kind, account) for account in sorted(self.accounts)]
        return []

    def entity(self, kind, scope):
        key = (kind, scope)
        cache = self.__dict__.setdefault("_entities", {})
        if key not in cache:
            label = {"aws_account_admin": f"Administrator of AWS account {scope}",
                     "aws_identity_center_permission_set": f"IAM Identity Center permission sets ({scope})"}.get(kind, f"{kind} {scope}")
            cache[key] = Node(f"{kind}:{scope}", kind, "aws", scope, label, attrs={"account": scope}, entity=True)
        return cache[key]

    def unknown_target_scopes(self, kind):
        types = {"aws_role": "iam_role", "aws_user": "iam_user", "aws_group": "iam_group"}
        if kind in types:
            return {s.split("/")[0]: st for s, st in unavailable(inventory_status(self.snapshot, types[kind])).items()}
        if kind in ("aws_identity_center_permission_set", "aws_identity_center_user"):
            return {account: "not_collected" for account in sorted(self.accounts)}
        return {}

    def _trusting(self, source):
        found = {}
        for table in (self.trust_by_arn.get(_norm_arn(source.id), {}), self.trust_by_account.get(source.scope, {}), self.trust_public):
            for rid, value in table.items():
                if rid != source.id and rid not in found:
                    found[rid] = value
        return found

    def selector(self, key, value, candidates, source, pivot=None):
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
            return {rid: None for rid, n in candidates.items() if bool(n.attrs.get("instance_profiles")) == bool(value)}
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
            if not self._trusting(source):
                return {}
            return {rid: ("conditional", "same_assumable_role_not_verified") for rid in candidates}
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
        return None

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
        principal = _service_principal(low)
        if role.id in self.trust_by_service.get(principal, {}):
            return ("unknown", f"{low}_attachment_not_collected")
        return False

    # ------------------------------------------------------------------ admin
    def admin_targets(self, principal):
        grant = None
        for pid in principal.attrs["policy_ids"]:
            for st in self.policies[pid].statements:
                if st.effect == "allow" and not st.notaction and any(a in ("*", "*:*") for a in st.actions) and \
                        not st.notresource and "*" in st.resources:
                    g = Grant("conditional" if st.conditional else "derived", [st.ref],
                              ["allow_statement_has_condition"] if st.conditional else [])
                    grant = _best(grant, g)
        if grant is None:
            return []
        for pid in principal.attrs["policy_ids"]:
            for st in self.policies[pid].statements:
                if st.effect == "deny":
                    if any(a in ("*", "*:*") for a in st.actions) and "*" in st.resources and not st.conditional and not st.notaction:
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
    "stepfunctions": "states.amazonaws.com", "cloudformation": "cloudformation.amazonaws.com",
}


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
    from . import best
    return best(a, b)


def _norm_arn(arn):
    """Trust policies name roles/users without path; compare on account + type + final name."""
    match = re.match(r"arn:[^:]+:iam::(\d{12}):(role|user)/(?:.*/)?([^/]+)$", str(arn))
    return f"{match.group(1)}:{match.group(2)}:{match.group(3)}" if match else str(arn)
