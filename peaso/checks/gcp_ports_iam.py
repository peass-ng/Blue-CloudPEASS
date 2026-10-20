"""IAM posture declarations preserve conditions; they never compute effective access."""
import re
from . import register, result, unknown
from .facts import get, optional, complete_items, list_of_objects, Unavailable
from .fixtures import CASES

IDS, REFERENCE_SPECS = [], {}


def rule(query, kind, function, good, bad, dependencies=None):
    cid = "gcp.ports." + query
    IDS.append(cid)
    register(cid, "gcp", "least_privilege", kind, query.replace("_", " "), "medium", "AC-6",
        "Review declared role assignments and their scope/conditions against the organization's least-privilege policy. Deny, PAB and inherited conditions require separate authorization evidence.",
        dependencies=dependencies)(function)
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None}
    REFERENCE_SPECS[query] = cid
    return cid


def bindings(item):
    rows = list_of_objects(get(item, "bindings", list))
    for row in rows:
        get(row, "role", str)
        members = get(row, "members", list)
        if any(not isinstance(member, str) for member in members):
            raise Unavailable("malformed IAM principal declaration")
        if "condition" in row:
            get(row, "condition", dict)
    return rows


def project_policy(item):
    name = get(item, "name", str)
    return bool(re.fullmatch(r"projects/[^/]+", name))


def duty(query, admin_role, use_roles):
    def evaluate(item, index):
        if not project_policy(item):
            return "NOT_APPLICABLE", {"reason": "Exact source project-root declaration scope"}
        users = {}
        for row in bindings(item):
            for member in row["members"]:
                if member.startswith("user:"):
                    users.setdefault(member, []).append({"role": row["role"], "condition": row.get("condition")})
        findings = []
        for member, declarations in users.items():
            roles = {row["role"] for row in declarations}
            if admin_role in roles and roles.intersection(use_roles):
                findings.append({"principal": member, "declarations": declarations})
        return result(bool(findings), project=get(item, "name", str), overlapping_role_declarations=findings,
            semantics="Same-root role assignment separation policy, including conditions as evidence; does not assert simultaneous permission or flatten deny/PAB")
    good = {"name": "projects/p", "bindings": [{"role": admin_role, "members": ["user:a@example.com"]}]}
    bad = {"name": "projects/p", "bindings": good["bindings"] + [{"role": use_roles[0], "members": ["user:a@example.com"]}]}
    rule(query, "iam_policy", evaluate, good, bad)


duty("kms_key_separation_of_duties_enforced", "roles/cloudkms.admin", ["roles/cloudkms.cryptoKeyEncrypterDecrypter", "roles/cloudkms.cryptoKeyEncrypter", "roles/cloudkms.cryptoKeyDecrypter"])
duty("iam_user_separation_of_duty_scoped", "roles/iam.serviceAccountAdmin", ["roles/iam.serviceAccountUser"])


def project_identity_roles(item, index):
    if not project_policy(item):
        return "NOT_APPLICABLE", {"reason": "Source is project-root assignment, not resource-level or ancestor policy"}
    findings = []
    for row in bindings(item):
        if row["role"] in ("roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"):
            for member in row["members"]:
                if not member.endswith("iam.gserviceaccount.com"):
                    findings.append({"principal": member, "role": row["role"], "condition": row.get("condition")})
    return result(bool(findings), broad_project_role_declarations=findings,
        semantics="Exact source non-IAM-service-account suffix assignment criterion; not proof that a principal can impersonate any identity")


rule("iam_user_not_assigned_service_account_user_role_project_level", "iam_policy", project_identity_roles,
    {"name": "projects/p", "bindings": []},
    {"name": "projects/p", "bindings": [{"role": "roles/iam.serviceAccountUser", "members": ["user:a@example.com"]}]})


def corporate(item, index):
    if not project_policy(item):
        return "NOT_APPLICABLE", {"reason": "Project-root corporate login declaration policy"}
    policy = get(index, "context.metadata", dict)
    if policy.get("trusted_domains_explicit") is False:
        return unknown("Corporate domain policy was not explicitly configured")
    approved = get(policy, "trusted_domains", list)
    if not approved and policy.get("trusted_domains_explicit") is not True:
        return unknown("Empty corporate domain policy lacks explicit operator applicability")
    if any(not isinstance(value, str) or not value or "@" in value for value in approved):
        raise Unavailable("malformed operator-approved corporate domain policy")
    violations = []
    for row in bindings(item):
        for member in row["members"]:
            if member.startswith("user:"):
                email = member[5:]
                if email.count("@") != 1:
                    return unknown("malformed user email principal")
                if email.rsplit("@", 1)[1].lower() not in {value.lower() for value in approved}:
                    violations.append(member)
    return result(bool(violations), principals_outside_declared_domains=sorted(set(violations)),
        semantics="Explicit operator-approved domain policy, which may include verified secondary/alias domains; no organization-display-name identity inference")


cid = rule("iam_corporate_domain_declaration", "iam_policy", corporate,
    {"name": "projects/p", "bindings": [{"role": "roles/viewer", "members": ["user:a@secondary.example"]} ]},
    {"name": "projects/p", "bindings": [{"role": "roles/viewer", "members": ["user:a@other.example"]} ]})
CASES[cid]["index"] = {"context": {"metadata": {"trusted_domains": ["primary.example", "secondary.example"]}}}


def project_roots(item, index):
    scope = get(item, "_provenance.scope", str)
    if (get(index, "context.provider", str) != "gcp" or get(index, "context.scope", str) != scope
            or not re.fullmatch(r"projects/[^/]+", scope)):
        raise Unavailable("selected project scope is missing or contradictory")
    projects = complete_items(index, "project")
    if len(projects) != 1:
        raise Unavailable("project metadata relation missing or ambiguous")
    project = projects[0]
    project_id, project_name = get(project, "projectId", str), get(project, "name", str)
    if (not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id)
            or not re.fullmatch(r"projects/[1-9][0-9]{0,18}", project_name)
            or int(project_name.split("/")[1]) > 9223372036854775807):
        raise Unavailable("native CRM project ID/number pair is malformed")
    roots = {project_name, "projects/" + project_id}
    if scope not in roots or get(project, "_provenance.scope", str) != scope:
        raise Unavailable("native CRM project identity does not bind the selected scope")
    number = optional(project, "projectNumber", None, str)
    if number is not None and "projects/" + number != project_name:
        raise Unavailable("contradictory native project number")
    if "projectId" in item or "projectId" in item.get("_coverage", {}):
        if get(item, "projectId", str) != project_id:
            raise Unavailable("resource project ID differs from native CRM identity")
    if "name" in item:
        name = get(item, "name", str)
        if name.startswith("projects/") and "/".join(name.split("/")[:2]) not in roots:
            raise Unavailable("resource name belongs to a different project")
    ancestors = list_of_objects(get(project, "_ancestry", list))
    if not ancestors:
        raise Unavailable("complete project ancestry unavailable")
    parents, seen, organization_seen = [], set(), False
    for position, ancestor in enumerate(ancestors):
        resource = get(ancestor, "resourceId", dict)
        kind, identifier = get(resource, "type", str), get(resource, "id", str)
        if position == 0:
            if kind != "project" or "projects/" + identifier not in roots:
                raise Unavailable("project ancestry root differs from native CRM identity")
            continue
        if (kind not in ("folder", "organization") or not re.fullmatch(r"[1-9][0-9]{0,18}", identifier)
                or int(identifier) > 9223372036854775807 or organization_seen):
            raise Unavailable("malformed project ancestor")
        parent = kind + "s/" + identifier
        if parent in seen:
            raise Unavailable("duplicate project ancestor")
        seen.add(parent)
        parents.append(parent)
        organization_seen = kind == "organization"
    parent = optional(project, "parent", None, str)
    if parent is not None and (not parents or parent != parents[0]):
        raise Unavailable("native project parent contradicts ancestry")
    roots.update(parents)
    for kind in ("project", "iam_policy"):
        for envelope in list_of_objects(get(index, "collections", dict).get(kind, [])):
            if (envelope.get("coverage_status", envelope.get("status")) not in ("collected", "empty")
                    or get(envelope, "scope", str) not in ({scope} if kind == "project" else roots)):
                raise Unavailable("dependency coverage incomplete: " + kind)
    policies = complete_items(index, "iam_policy")
    selected = [policy for policy in policies if get(policy, "name", str) in roots]
    identities = [project_name if policy["name"] in (project_name, "projects/" + project_id) else policy["name"]
                  for policy in selected]
    if len(identities) != len(set(identities)):
        raise Unavailable("duplicate root policy identity")
    # Folder/organization root policies are collected at their own scopes; the
    # collector materializes them on the project only when every ancestor's
    # getIamPolicy document was read.
    inherited = optional(project, "_inherited_iam_policies", None, list)
    if inherited is not None:
        coverage = get(project, "_coverage._inherited_iam_policies", dict)
        if (get(coverage, "status", str) != "collected"
                or optional(coverage, "collection_status", "collected", str) != "collected"
                or optional(coverage, "ancestors", parents, list) != parents):
            raise Unavailable("inherited IAM coverage contradicts complete ancestry")
        present = {policy["name"] for policy in selected}
        inherited_names = set()
        for policy in list_of_objects(inherited):
            name = get(policy, "name", str)
            if name not in parents or name in inherited_names or optional(policy, "ancestor", name, str) != name:
                raise Unavailable("foreign or duplicate inherited IAM root")
            inherited_names.add(name)
            if name not in present:
                selected.append(policy)
                present.add(name)
            elif any(policy.get(field) != next(p for p in selected if p["name"] == name).get(field)
                     for field in ("bindings", "etag", "version")):
                raise Unavailable("contradictory inherited IAM policy")
    # Every actual ancestor plus one project alias must be represented.
    expected_parents = {root for root in roots if root.startswith(("folders/", "organizations/"))}
    actual = {policy["name"] for policy in selected}
    if not expected_parents.issubset(actual) or not any(root.startswith("projects/") for root in actual):
        raise Unavailable("root/ancestor policy evidence incomplete")
    return selected


def matching_definitions(roles, name):
    """Coalesced reads of the same role can appear under several evidence scopes."""
    matches = {}
    for role in roles:
        if get(role, "name", str) != name:
            continue
        permissions = get(role, "includedPermissions", list)
        if any(not isinstance(permission, str) for permission in permissions):
            raise Unavailable("malformed role permission metadata")
        # Exact role owner/name, permission set and version evidence, not suffix
        # or resource-name hash equivalence across unrelated project roles.
        signature = (name, tuple(sorted(set(permissions))), optional(role, "etag", None, str), optional(role, "deleted", False, bool))
        matches.setdefault(signature, role)
    return list(matches.values())


def account_mutations(item, index):
    email = get(item, "email", str)
    if not re.fullmatch(r"[^@]+@[^@]+\.iam\.gserviceaccount\.com", email):
        return "NOT_APPLICABLE", {"reason": "Source excludes Google-managed identity domain"}
    policies = project_roots(item, index)
    roles = complete_items(index, "iam_role")
    findings = []
    for policy in policies:
        for row in bindings(policy):
            if "serviceAccount:" + email not in row["members"]:
                continue
            definitions = matching_definitions(roles, row["role"])
            if len(definitions) != 1:
                return unknown("actual role definition unavailable or ambiguous", role=row["role"])
            permissions = get(definitions[0], "includedPermissions", list)
            if any(not isinstance(permission, str) for permission in permissions):
                raise Unavailable("malformed role permission metadata")
            mutating = [permission for permission in permissions if permission.rsplit(".", 1)[-1] in ("create", "update", "delete", "setIamPolicy")]
            if mutating:
                findings.append({"role": row["role"], "policy": policy["name"], "condition": row.get("condition"), "mutating_permission_count": len(mutating)})
    return result(bool(findings), mutating_role_declarations=findings,
        semantics="Declared role definitions with mutation verbs for least-privilege review; not an admin/effective-access decision, conditions/deny/PAB are not flattened")


cid = rule("service_account_mutating_role_declarations", "service_account", account_mutations,
    {"email": "reader@p.iam.gserviceaccount.com", "_provenance": {"scope": "projects/p"}},
    {"email": "writer@p.iam.gserviceaccount.com", "_provenance": {"scope": "projects/p"}}, ["service_account", "project", "iam_policy", "iam_role"])
CASES[cid]["index"] = {"collections": {kind: [{"status": "collected"}] for kind in ("project", "iam_policy", "iam_role")},
    "project": [{"data": {"name": "projects/p", "projectId": "p", "_ancestry": []}}],
    "iam_policy": [{"data": {"name": "projects/p", "bindings": [{"role": "projects/p/roles/harmlessAdmin", "members": ["serviceAccount:reader@p.iam.gserviceaccount.com"]}, {"role": "projects/p/roles/writer", "members": ["serviceAccount:writer@p.iam.gserviceaccount.com"]}]}}],
    "iam_role": [{"data": {"name": "projects/p/roles/harmlessAdmin", "includedPermissions": ["storage.buckets.get"]}}, {"data": {"name": "projects/p/roles/writer", "includedPermissions": ["storage.buckets.update"]}}]}


def function_roles(query, mode):
    def evaluate(item, index):
        email = get(item, "serviceConfig.serviceAccountEmail", str)
        policies = project_roots(item, index)
        definitions = complete_items(index, "iam_role")
        findings = []
        for policy in policies:
            for row in bindings(policy):
                if "serviceAccount:" + email not in row["members"]:
                    continue
                if mode == "basic":
                    match = row["role"] in ("roles/editor", "roles/owner")
                else:
                    roles = matching_definitions(definitions, row["role"])
                    if len(roles) != 1:
                        return unknown("role definition missing or ambiguous", role=row["role"])
                    permissions = get(roles[0], "includedPermissions", list)
                    if any(not isinstance(permission, str) for permission in permissions):
                        raise Unavailable("malformed role definition")
                    prefix = "logging." if mode == "logging" else "deploymentmanager."
                    verbs = {"delete", "update"} if mode == "logging" else {"create", "update"}
                    match = any(permission.startswith(prefix) and permission.rsplit(".", 1)[-1] in verbs for permission in permissions)
                if match:
                    findings.append({"role": row["role"], "policy": policy["name"], "condition": row.get("condition")})
        return result(bool(findings), role_assignment_declarations=findings,
            semantics="Function identity role declarations and definitions; no effective authorization, deployment, logging mutation or privilege-chain evaluation")
    cid = rule(query, "function", evaluate,
        {"serviceConfig": {"serviceAccountEmail": "reader@p.iam.gserviceaccount.com"}, "_provenance": {"scope": "projects/p"}},
        {"serviceConfig": {"serviceAccountEmail": "writer@p.iam.gserviceaccount.com"}, "_provenance": {"scope": "projects/p"}},
        ["function", "project", "iam_policy", "iam_role"])
    from copy import deepcopy
    fixture = deepcopy(CASES[REFERENCE_SPECS["service_account_mutating_role_declarations"]]["index"])
    writer = fixture["iam_policy"][0]["data"]["bindings"][1]
    if mode == "basic":
        writer["role"] = "roles/editor"
    else:
        fixture["iam_role"][1]["data"]["includedPermissions"] = ["logging.sinks.update" if mode == "logging" else "deploymentmanager.deployments.update"]
    CASES[cid]["index"] = fixture


function_roles("function_basic_role_declarations", "basic")
function_roles("function_logging_mutation_declarations", "logging")
function_roles("function_legacy_deployment_role_declarations", "deployment")
