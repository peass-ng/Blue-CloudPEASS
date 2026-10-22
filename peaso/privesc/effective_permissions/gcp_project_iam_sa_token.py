"""A project IAM writer can grant Token Creator over a named service account."""

from __future__ import annotations

from . import Grant, inventory_status, items


TECHNIQUE = "gcp-resourcemanager-projects-setiampolicy-sa-token"
WRITE = "resourcemanager.projects.setIamPolicy"
TOKEN = "iam.serviceAccounts.getAccessToken"
ROLE = "roles/iam.serviceAccountTokenCreator"
MEMBER_CONSTRAINTS = {"iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"}


def select(model, candidates, source):
    if (source is None or source.kind not in ("gcp_user", "gcp_service_account")
            or (model.current_entry or {}).get("id") != TECHNIQUE):
        return {}
    out = {}
    for target_id, target in candidates.items():
        if target.kind != "gcp_service_account" or target.id == source.id or target.attrs.get("disabled"):
            continue
        project = model._norm_scope(target.scope)
        resource = model._norm_scope(target.attrs.get("resource"))
        email = target.attrs.get("email")
        if (not project.startswith("projects/") or project.count("/") != 1
                or not isinstance(email, str)
                or resource != f"{project}/serviceAccounts/{email}"):
            continue
        writer = model.check(source, {"action": WRITE}, project)
        if writer is None:
            continue
        prior = model.check(source, {"action": TOKEN}, resource)
        if prior is not None:
            if prior.confidence != "derived":
                out[target_id] = ("unknown", "prior_service_account_token_access_unresolved")
            continue
        deny = model._deny(source, TOKEN, resource, Grant())
        if deny is None:
            continue
        projects = [row for scope, row in items(model.snapshot, "project")
                    if model._norm_scope(scope) == project
                    and row.get("projectId") == project.split("/", 1)[1]]
        accounts = [row for scope, row in items(model.snapshot, "service_account")
                    if model._norm_scope(scope) == project
                    and row.get("email") == email
                    and model._norm_scope(row.get("name")) == resource]
        project_policies = [row for scope, row in items(model.snapshot, "iam_policy")
                            if model._norm_scope(scope) == project
                            and model._norm_scope(row.get("name")) == project]
        ancestors = [scope for scope in model.ancestors(project)
                     if scope.startswith(("folders/", "organizations/")) and scope.count("/") == 1]
        policy_scopes = (project, *ancestors)
        pab_scopes = set(policy_scopes)
        if source.kind == "gcp_service_account":
            home = source.attrs.get("project") or source.scope
            if isinstance(home, str) and home.startswith("projects/"):
                pab_scopes.add(home)
                pab_scopes.update(scope for scope in model.ancestors(home)
                                  if scope.startswith(("folders/", "organizations/")))
        role = model.roles.get(ROLE)
        role_row = model.collected_role_rows.get(ROLE)
        constraints = [row for scope, row in items(model.snapshot, "org_policy_effective")
                       if model._norm_scope(scope) == project
                       and row.get("constraint") in MEMBER_CONSTRAINTS]
        restrictive_or_unknown = any(
            not isinstance(row.get("spec"), dict)
            or not isinstance(row["spec"].get("rules", []), list)
            or any(not isinstance(rule, dict) or rule.get("allowAll") is not True
                   for rule in row["spec"].get("rules", [])) for row in constraints)
        pab = any(row.get("policyKind") == "PRINCIPAL_ACCESS_BOUNDARY"
                  for scope, row in items(model.snapshot, "policy_binding")
                  if model._norm_scope(scope) in pab_scopes)
        inherited_policies = [row for scope, row in items(model.snapshot, "iam_policy")
                              if model._norm_scope(scope) in policy_scopes]
        if len(accounts) == 1 and isinstance(accounts[0].get("iamPolicy"), dict):
            inherited_policies.append(accounts[0]["iamPolicy"])
        group_binding = any(
            isinstance(member, str) and member.startswith("group:")
            for policy in inherited_policies
            for binding in (policy.get("bindings") if isinstance(policy.get("bindings"), list) else [])
            if isinstance(binding, dict)
            for member in (binding.get("members") if isinstance(binding.get("members"), list) else []))
        group_scopes = [scope for scope in policy_scopes if scope.startswith("organizations/")]
        uncertain = (writer.confidence != "derived" or deny.confidence != "derived"
                     or len(projects) != 1 or projects[0].get("state") != "ACTIVE"
                     or inventory_status(model.snapshot, "project").get(project) != "collected"
                     or len(accounts) != 1 or accounts[0].get("disabled") is True
                     or inventory_status(model.snapshot, "service_account").get(project) != "collected"
                     or not isinstance(accounts[0].get("iamPolicy"), dict)
                     or not isinstance((accounts[0].get("iamPolicy") or {}).get("bindings"), list)
                     or ((accounts[0].get("_coverage") or {}).get("iamPolicy") or {}).get("status") != "collected"
                     or len(project_policies) != 1
                     or project_policies[0].get("_representation") != "full"
                     or not isinstance(project_policies[0].get("bindings"), list)
                     or role is None or role.confidence != "derived" or not role.has(TOKEN.lower())
                     or not isinstance(role_row, dict)
                     or inventory_status(model.snapshot, "iam_role_builtin").get(project) != "collected"
                     or inventory_status(model.snapshot, "org_policy_effective").get(project)
                     not in ("collected", "empty") or restrictive_or_unknown or pab
                     or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                            or (scope.startswith(("projects/", "organizations/"))
                                and model.iam_role_inventory_status.get(scope) not in ("collected", "empty"))
                            or model.deny_status.get(scope) not in ("collected", "empty")
                            or inventory_status(model.snapshot, "policy_binding").get(scope)
                            not in ("collected", "empty") for scope in policy_scopes)
                     or any(inventory_status(model.snapshot, "policy_binding").get(scope)
                            not in ("collected", "empty") for scope in pab_scopes)
                     or any(inventory_status(model.snapshot, "principal_access_boundary_policy").get(scope)
                            not in ("collected", "empty") for scope in pab_scopes
                            if scope.startswith("organizations/"))
                     or (group_binding and (not group_scopes or any(
                         model.group_membership_status.get(scope) not in ("collected", "empty")
                         or inventory_status(model.snapshot, "group").get(scope)
                         not in ("collected", "empty") for scope in group_scopes))))
        out[target_id] = (("unknown", "project_token_self_grant_evidence_incomplete") if uncertain else
                          ("conditional", "project_policy_can_grant_token_creator_for_exact_service_account"))
    return out
