"""Declared IAM facts and conditional risk review; never an access simulator."""
from __future__ import annotations

import copy
import json
import hashlib
from functools import lru_cache
from urllib.parse import unquote

from .common import (RANK, as_list, derived, externality, finding, native_id, node, node_id,
                     relationship, source, stable_id, usage)

IAM_TYPES = {"iam_user", "iam_group", "iam_role", "iam_policy", "iam_binding", "service_account",
             "iam_role_definition", "directory_user", "directory_group", "directory_service_principal", "directory_application",
             "directory_role_assignment", "directory_role_definition", "directory_membership", "deny_assignment", "iam_deny_policy",
             "role_assignment", "role_definition", "principal", "user", "group", "service_principal",
             "role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount"}


def document(value):
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value))
        except (ValueError, TypeError):
            return None
    return value if isinstance(value, dict) and isinstance(value.get("Statement"), (dict, list)) else None


def policy_documents(data):
    wrappers = {"Policy", "policy", "Attributes", "Domain", "Table", "PolicyDetails", "ResourcePolicy", "AccessPolicy", "AccessPolicies", "policyText"}
    def nested(value, path, depth):
        if depth > 4 or not isinstance(value, dict):
            return
        for key, current in value.items():
            if key not in wrappers:
                continue
            doc = document(current)
            if doc is not None:
                yield f"{path}.{key}", doc
            else:
                yield from nested(current, f"{path}.{key}", depth + 1)
    for key in ("PolicyDocument", "Document", "Policy", "policy", "AssumeRolePolicyDocument"):
        doc = document(data.get(key))
        if doc is not None:
            yield key, doc
    for key in wrappers:
        value = data.get(key)
        if document(value) is None:
            yield from nested(value, key, 0)
        elif key not in {"Policy", "policy"}:
            yield key, document(value)
    for key in ("UserPolicyList", "GroupPolicyList", "RolePolicyList", "PolicyVersionList", "PolicySources"):
        for i, item in enumerate(as_list(data.get(key))):
            if not isinstance(item, dict):
                continue
            if key == "PolicyVersionList" and item.get("IsDefaultVersion") is not True:
                continue
            doc = document(item.get("PolicyDocument", item.get("Document", item.get("document"))))
            if doc is not None:
                yield f"{key}[{i}]", doc


@lru_cache(maxsize=4)
def _rulepack_revision(provider):
    if provider not in {"aws", "gcp", "azure"}:
        return None
    try:
        from scripts.cloud_permission_risks import _bundled_rules_path
        # The shared resolver chooses source-checkout or installed package data.
        # Guard the actual file before invoking the classifier's loader.
        path = _bundled_rules_path(provider)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (ImportError, OSError, ValueError):
        return None


def permission_severity(provider, permission):
    revision = _rulepack_revision(provider)
    return _permission_severity(provider, permission, revision) if revision else None


@lru_cache(maxsize=16384)
def _permission_severity(provider, permission, revision):
    """Reuse the audited standalone classifier, with no multi-grant combinations.

    Guard bundled data before import so its optional remote fallback is unreachable.
    Missing installations produce unknown, never an invented low severity.
    """
    try:
        from scripts.cloud_permission_risks import classify_permission
        low = classify_permission(provider, permission, unknown_default="low", offline=True)
        high = classify_permission(provider, permission, unknown_default="high", offline=True)
        # The shared API exposes fallback uncertainty through its default.
        # If only changing the fallback changes the classification, no rule
        # recognized this permission and low must not be asserted.
        return low if low == high else None
    except (ImportError, OSError, ValueError):
        return None


def grants(resource):
    return derived(resource, "grants", lambda: _grants(resource))


def _grants(resource):
    """Retain native constraints, not effective permission/target combinations."""
    data, provider = resource["data"], resource["provider"]
    result = []
    if provider == "aws":
        for path, doc in policy_documents(data):
            if path == "AssumeRolePolicyDocument":
                continue
            for i, statement in enumerate(as_list(doc.get("Statement"))):
                if not isinstance(statement, dict):
                    continue
                permissions = as_list(statement.get("Action"))
                levels = [permission_severity(provider, p) for p in permissions if isinstance(p, str)]
                broad = any("*" in p for p in permissions if isinstance(p, str)) or "NotAction" in statement
                result.append({"path": f"{path}.Statement[{i}]", "native_grant": copy.deepcopy(statement),
                    "severity": "high" if broad else min((x for x in levels if x), key=RANK.get, default="info"),
                    "criticality_state": "unknown" if not levels or all(x is None for x in levels) else "partial" if any(x is None for x in levels) else "rule_based",
                    "broad": broad, "allowed_declaration": statement.get("Effect") == "Allow",
                    "conditional": bool(statement.get("Condition")), "effective_access": "unknown"})
    elif provider == "gcp":
        policy = data.get("policy", data.get("iamPolicy", data))
        if not isinstance(policy, dict):
            return []
        for i, binding in enumerate(as_list(policy.get("bindings"))):
            if not isinstance(binding, dict):
                continue
            role = binding.get("role", "")
            broad = role in {"roles/owner", "roles/editor"}
            result.append({"path": f"bindings[{i}]", "native_grant": copy.deepcopy(binding),
                "severity": "high" if broad else "info", "broad": broad,
                "allowed_declaration": True, "conditional": bool(binding.get("condition")),
                "effective_access": "unknown", "permission_definition": "not inferred from role name"})
        for i, permission in enumerate(as_list(data.get("includedPermissions"))):
            result.append({"path": f"includedPermissions[{i}]", "native_grant": permission,
                "severity": permission_severity(provider, permission) or "info", "broad": "*" in permission,
                "criticality_state": "rule_based" if permission_severity(provider, permission) else "unknown",
                "allowed_declaration": True, "conditional": False, "effective_access": "unknown"})
    elif provider == "azure":
        props = data.get("properties", data)
        for i, permission in enumerate(as_list(props.get("permissions"))):
            if not isinstance(permission, dict):
                continue
            actions = as_list(permission.get("actions")) + as_list(permission.get("dataActions"))
            levels = [permission_severity(provider, p) for p in actions if isinstance(p, str)]
            broad = any("*" in p for p in actions if isinstance(p, str))
            result.append({"path": f"properties.permissions[{i}]", "native_grant": copy.deepcopy(permission),
                "severity": "high" if broad else min((x for x in levels if x), key=RANK.get, default="info"),
                "criticality_state": "unknown" if not levels or all(x is None for x in levels) else "partial" if any(x is None for x in levels) else "rule_based",
                "broad": broad, "allowed_declaration": True,
                "conditional": bool(permission.get("notActions") or permission.get("notDataActions")),
                "effective_access": "unknown"})
    elif provider == "k8s":
        for i, rule in enumerate(as_list(data.get("rules"))):
            if not isinstance(rule, dict):
                continue
            broad = any("*" in as_list(rule.get(k)) for k in ("verbs", "resources", "apiGroups", "nonResourceURLs"))
            levels = []
            try:
                from bluepeass.k8s_risks import PermissionKey, classify_permission
                # Resource and verb declarations are individually classified;
                # no graph expansion into escalation prerequisites or targets.
                for verb in as_list(rule.get("verbs")):
                    for group in as_list(rule.get("apiGroups", [""])):
                        for res in as_list(rule.get("resources")):
                            base, _, sub = res.partition("/")
                            level, _ = classify_permission(PermissionKey(verb, group=group, resource=base,
                                subresource=sub, namespace=data.get("metadata", {}).get("namespace", "")))
                            levels.append(level)
            except (ImportError, OSError, ValueError):
                pass
            result.append({"path": f"rules[{i}]", "native_grant": copy.deepcopy(rule),
                "severity": "high" if broad else min(levels, key=RANK.get, default="info"),
                "broad": broad, "allowed_declaration": True,
                "conditional": bool(rule.get("resourceNames")), "effective_access": "unknown"})
    return result


def principals(resource):
    data = resource["data"]
    for path, doc in policy_documents(data):
        for i, statement in enumerate(as_list(doc.get("Statement"))):
            if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal", {})
            if isinstance(principal, dict):
                values = [(kind, value) for kind, value in principal.items()]
            else:
                values = [("principal", principal)]
            for kind, value in values:
                for identity in as_list(value):
                    if isinstance(identity, str):
                        yield identity, f"{path}.Statement[{i}].Principal", statement, kind
    policy = data.get("policy", data.get("iamPolicy", data))
    for i, binding in enumerate(as_list(policy.get("bindings")) if isinstance(policy, dict) else []):
        if isinstance(binding, dict):
            for member in as_list(binding.get("members")):
                if isinstance(member, str):
                    yield member, f"bindings[{i}].members", binding, "member"
    for i, subject in enumerate(as_list(data.get("subjects"))):
        if isinstance(subject, dict):
            name = subject.get("name", "")
            identity = f"system:serviceaccount:{subject.get('namespace', data.get('metadata', {}).get('namespace', 'default'))}:{name}" if subject.get("kind") == "ServiceAccount" else name
            yield identity, f"subjects[{i}]", subject, subject.get("kind", "subject")
    props = data.get("properties", data)
    if resource["provider"] == "azure" and props.get("principalId"):
        yield props["principalId"], "properties.principalId", props, props.get("principalType", "principal")


def review_findings(snapshot, resources):
    output = []
    for resource in resources:
        declared = grants(resource)
        uncertain = [g for g in declared if g.get("criticality_state") in {"unknown", "partial"} and not g["broad"] and g["allowed_declaration"]]
        if uncertain:
            output.append(finding(snapshot, resource, "least_privilege", "analysis.coverage",
                "Permission criticality context incomplete", "info", {"source": source(snapshot, resource, "grants"),
                    "unclassified_grants": uncertain, "risk_state": "unknown", "reason": "permission_criticality_unknown"}, status="UNKNOWN"))
        high = [g for g in declared if g["allowed_declaration"] and RANK[g["severity"]] <= RANK["high"]]
        if high:
            severity = min((g["severity"] for g in high), key=RANK.get)
            evidence = {"source": source(snapshot, resource, "grants"), "grants": high,
                "usage": usage(snapshot, resource), "risk_state": "conditional", "effective_access": "unknown",
                "missing_context": ["Effective denies, inherited grants, boundaries/SCPs, runtime conditions, and owner-approved business need must be reviewed"],
                "restrictions": {k: copy.deepcopy(v) for k, v in resource["data"].items()
                    if k in {"PermissionsBoundary", "DenyPolicies", "PolicySources", "denyAssignments"}},
                "criticality_source": "Bundled Blue-CloudPEASS standalone HackTricks permission criticality; combinations are not evaluated"}
            output.append(finding(snapshot, resource, "least_privilege", "analysis.grant_review",
                "Review high-impact or broad declared grants", severity, evidence))
        telemetry = usage(snapshot, resource)
        if resource["type"] in IAM_TYPES and telemetry["inactive_observation"]:
            output.append(finding(snapshot, resource, "least_privilege", "analysis.inactive_identity",
                "Review identity with no activity in the observed window", "low",
                {"source": source(snapshot, resource, "usage"), "usage": telemetry, "risk_state": "unknown"}))
        suspicious = []
        for identity, path, fact, kind in principals(resource):
            state = externality(snapshot, identity, tenant=fact.get("tenantId"))
            if state != "allowlisted" and kind != "Service":
                suspicious.append({"principal": identity, "classification": state,
                    "source": source(snapshot, resource, path), "native_grant": copy.deepcopy(fact),
                    "condition": copy.deepcopy(fact.get("Condition", fact.get("condition"))),
                    "principal_kind": kind})
        if suspicious:
            public = any(x["classification"] == "public" for x in suspicious)
            known = public or any(x["classification"] in {"external", "everyone_authenticated"} for x in suspicious)
            output.append(finding(snapshot, resource, "exposure", "analysis.principal_exposure",
                "Review public or external principal declarations", "high" if known else "info",
                {"principals": suspicious, "risk_state": "conditional" if known else "unknown",
                 "effective_access": "unknown", "trusted_scope_ids": snapshot.get("metadata", {}).get("trusted_scope_ids", []),
                 "uncertainty": "Allow declarations do not prove effective access; resource restrictions, deny precedence, identity affiliation, and provider conditions remain relevant."},
                status="MANUAL" if known else "UNKNOWN"))
    return output


def build_iam(snapshot, resources):
    selected = [r for r in resources if r["type"] in IAM_TYPES or list(principals(r))
                or (r["type"] == "pod" and r["data"].get("spec", {}).get("serviceAccountName"))]
    nodes = {node_id(r): node(r) for r in selected}
    edges = []
    observed_bindings = {}
    lookup = {}
    for resource in selected:
        data = resource["data"]
        meta = data.get("metadata", {})
        names = [native_id(resource), data.get("UserName"), data.get("GroupName"), data.get("RoleName"), data.get("name"), data.get("email"), data.get("id"),
                 f"{meta.get('namespace', '_cluster')}/{meta['name']}" if meta.get("name") else None]
        for name in names:
            if name:
                lookup[(resource["scope"], resource["type"], str(name))] = node_id(resource)

    def reference(resource, kind, rid, *, refscope=None, classification="unknown"):
        scope = refscope or resource["scope"]
        key = (scope, kind, str(rid))
        target = lookup.get(key)
        if target:
            return target
        if kind == "principal":
            raw = str(rid)
            if raw.startswith("system:serviceaccount:"):
                parts = raw.split(":")
                alias = f"{parts[2]}/{parts[3]}" if len(parts) == 4 else raw
                principal_kinds = {"serviceaccount"}
            else:
                alias = raw.split(":", 1)[1] if raw.startswith(("user:", "group:", "serviceAccount:")) else raw
                principal_kinds = {"iam_user", "iam_role", "iam_group", "service_account", "directory_user", "directory_group", "directory_service_principal"}
            candidates = {value for lk, value in lookup.items() if lk[1] in principal_kinds and lk[2] == alias}
            if len(candidates) == 1:
                return candidates.pop()
        if (kind == "iam_policy" and str(rid).startswith("arn:")) or kind in {"role_definition", "iam_role"}:
            candidates = {value for lookup_key, value in lookup.items() if lookup_key[1:] == (kind, str(rid))}
            if len(candidates) == 1:
                return candidates.pop()
        target = stable_id(snapshot["provider"], scope, kind, rid)
        nodes.setdefault(target, {"id": target, "label": str(rid), "resource_id": str(rid),
            "type": kind, "provider": snapshot["provider"], "scope": scope,
            "evidence": {"inventory_status": "reference_only"},
            "risk_annotations": [{"state": "unknown" if classification == "unknown" else
                                  "observed" if classification == "allowlisted" else "conditional",
                                  "classification": classification}]})
        return target

    for resource in selected:
        src, data = node_id(resource), resource["data"]
        card = nodes[src]
        card["card"] = {"source_grants": grants(resource), "trust": copy.deepcopy(data.get("AssumeRolePolicyDocument")),
                        "usage": usage(snapshot, resource), "effective_access": "unknown",
                        "restrictions": {k: copy.deepcopy(data[k]) for k in ("PermissionsBoundary", "denyAssignments", "DenyPolicies", "condition") if k in data}}
        if any(g["allowed_declaration"] and RANK[g["severity"]] <= 1 for g in card["card"]["source_grants"]):
            card["risk_annotations"].append({"state": "conditional", "type": "high_risk_grant"})
        if card["card"]["usage"]["inactive_observation"]:
            card["risk_annotations"].append({"state": "observed", "type": "inactive_identity",
                "meaning": "No activity observed within the supplied window; removal remains owner-reviewed"})
        for i, group in enumerate(as_list(data.get("GroupList"))):
            dst = reference(resource, "iam_group", group)
            edges.append(relationship(src, dst, "member_of", source(snapshot, resource, f"GroupList[{i}]")))
        for i, member in enumerate(as_list(data.get("members"))):
            if isinstance(member, dict):
                member = member.get("id", member.get("name"))
            if member:
                dst = reference(resource, "principal", member)
                edges.append(relationship(dst, src, "member_of", source(snapshot, resource, f"members[{i}]")))
        for i, policy in enumerate(as_list(data.get("AttachedManagedPolicies"))):
            if isinstance(policy, dict) and policy.get("PolicyArn"):
                dst = reference(resource, "iam_policy", policy["PolicyArn"])
                edges.append(relationship(src, dst, "attached_policy", source(snapshot, resource, f"AttachedManagedPolicies[{i}]")))
        for path, doc in policy_documents(data):
            if path == "AssumeRolePolicyDocument" or path in {"Document", "PolicyDocument"}:
                continue
            dst = reference(resource, "policy_document", stable_id(native_id(resource), path))
            nodes[dst]["evidence"] = {"source": source(snapshot, resource, path), "native_document": copy.deepcopy(doc)}
            edges.append(relationship(src, dst, "inline_policy", source(snapshot, resource, path)))
        props = data.get("properties", data)
        if resource["type"] == "pod" and data.get("spec", {}).get("serviceAccountName"):
            name = f"{data.get('metadata', {}).get('namespace', 'default')}/{data['spec']['serviceAccountName']}"
            dst = reference(resource, "serviceaccount", name)
            edges.append(relationship(src, dst, "workload_identity", source(snapshot, resource, "spec.serviceAccountName")))
        if resource["type"] == "directory_membership" and "/groups/" in resource["scope"]:
            group_id = resource["scope"].split("/groups/", 1)[1]
            group = reference(resource, "principal", group_id)
            member = reference(resource, "principal", data.get("id", native_id(resource)))
            edges.append(relationship(member, group, "member_of", source(snapshot, resource, "id")))
        if props.get("roleDefinitionId"):
            definition_kind = "directory_role_definition" if resource["type"] == "directory_role_assignment" else "role_definition"
            dst = reference(resource, definition_kind, props["roleDefinitionId"])
            edges.append(relationship(src, dst, "role_definition", source(snapshot, resource, "properties.roleDefinitionId")))
        if resource["type"] in {"role_assignment", "directory_role_assignment"}:
            scope = props.get("scope", props.get("directoryScopeId"))
            if scope:
                dst = reference(resource, "authorization_scope", scope)
                nodes[dst]["evidence"] = {"source": source(snapshot, resource, "properties.scope"),
                    "native_scope": scope, "effective_access": "unknown"}
                edges.append(relationship(src, dst, "declared_scope", source(snapshot, resource, "properties.scope")))
        if resource["provider"] == "gcp":
            for i, binding in enumerate(as_list(data.get("bindings"))):
                if isinstance(binding, dict) and binding.get("role"):
                    dst = reference(resource, "iam_role", binding["role"])
                    edges.append(relationship(src, dst, "role_definition", source(snapshot, resource, f"bindings[{i}].role")))
        role = data.get("roleRef", {})
        if role.get("name"):
            kind = "clusterrole" if role.get("kind") == "ClusterRole" else "role"
            name = f"{data.get('metadata', {}).get('namespace', '_cluster')}/{role['name']}" if kind == "role" else f"_cluster/{role['name']}"
            refscope = resource["scope"]
            if kind == "clusterrole":
                candidates = [(key[0], value) for key, value in lookup.items() if key[1:] == (kind, name)]
                if len(candidates) == 1:
                    refscope = candidates[0][0]
            dst = reference(resource, kind, name, refscope=refscope)
            edges.append(relationship(src, dst, "role_binding", source(snapshot, resource, "roleRef")))
        for identity, path, fact, kind in principals(resource):
            classification = externality(snapshot, identity, tenant=fact.get("tenantId"))
            everyone = classification in {"public", "everyone_authenticated"}
            dst = reference(resource, "everyone" if everyone else "principal", identity, classification=classification)
            risk_state = "unknown" if classification == "unknown" else "conditional" if classification != "allowlisted" else "observed"
            evidence = {"source": source(snapshot, resource, path), "native_fact": copy.deepcopy(fact),
                "classification": classification, "risk_state": risk_state, "effective_access": "unknown"}
            kind = "trust" if "AssumeRolePolicyDocument" in path else "declared_grant"
            edges.append(relationship(dst, src, kind, evidence))
            observed_bindings.setdefault(dst, []).append({"resource_node": src, "type": kind,
                "source": copy.deepcopy(evidence["source"]), "native_fact": copy.deepcopy(fact)})
            if classification in {"external", "public", "everyone_authenticated"}:
                card["risk_annotations"].append({"state": "conditional", "type": "external_trust", "classification": classification})
    # Propagate only a conditional review marker along observed attachment /
    # membership facts. This is not transitive permission or chain discovery.
    for nid, facts in observed_bindings.items():
        card = nodes[nid].setdefault("card", {"source_grants": [], "trust": None,
            "usage": {"observations": {}, "window": snapshot.get("metadata", {}).get("usage_window", snapshot.get("metadata", {}).get("activity_window")),
                      "completeness": "unknown", "safe_to_remove": False,
                      "uncertainty": "Principal telemetry is not established by policy or binding evidence"},
            "effective_access": "unknown"})
        card["observed_bindings"] = facts
    declared_high = {nid for nid, current in nodes.items()
                     if any(x.get("type") == "high_risk_grant" and x.get("state") == "conditional"
                            for x in current.get("risk_annotations", []))}
    for edge in edges:
        if edge["type"] not in {"attached_policy", "member_of", "role_definition", "role_binding", "declared_grant"}:
            continue
        target = nodes[edge["target"]]
        if edge["target"] in declared_high:
            nodes[edge["source"]]["risk_annotations"].append({"state": "derived", "type": "high_risk_grant",
                "basis": edge["id"], "effective_access": "unknown"})
            nodes[edge["source"]].setdefault("card", {}).setdefault("referenced_grants", []).append(
                {"source_node": target["id"], "edge_ref": edge["id"],
                 "grants": copy.deepcopy(target.get("card", {}).get("source_grants", []))})
    return {"nodes": list(nodes.values()), "edges": edges,
            "semantics": "Observed declarations and conditional risk review; no effective-access or exploit-chain claims"}
