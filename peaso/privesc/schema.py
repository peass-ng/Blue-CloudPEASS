"""Privilege-escalation catalog loader and strict schema validator.

The registries in this module are the single source of truth for which target
kinds, selector keys, scopes, requirement fields and placeholders the evaluator
implements. The validator rejects anything the evaluator would not understand,
so an unknown selector key can never silently widen or narrow a target set.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

PROVIDERS = ("aws", "gcp", "azure", "k8s")
CATALOG_DIR = Path(__file__).resolve().parent / "catalog"
HACKTRICKS_CLOUD = Path("/Users/carlospolop/git/hacktricks-cloud")

# kind -> (provider, node class). "principal" kinds are real identities that can
# act as sources; "entity" kinds are collapsed control objects (account admin,
# scope owner, cluster-admin, a directory role) that are terminal privileges.
TARGET_KINDS = {
    "aws_role": ("aws", "principal"),
    "aws_user": ("aws", "principal"),
    "aws_group": ("aws", "principal"),
    "aws_identity_center_permission_set": ("aws", "entity"),
    "aws_account_admin": ("aws", "entity"),
    "gcp_service_account": ("gcp", "principal"),
    "gcp_user": ("gcp", "principal"),
    "gcp_workspace_user": ("gcp", "principal"),
    "gcp_scope_owner": ("gcp", "entity"),
    "azure_managed_identity": ("azure", "principal"),
    "azure_service_principal": ("azure", "principal"),
    "azure_user": ("azure", "principal"),
    "azure_scope_owner": ("azure", "entity"),
    "entra_role": ("azure", "entity"),
    "k8s_service_account": ("k8s", "principal"),
    "k8s_user": ("k8s", "principal"),
    "k8s_group": ("k8s", "principal"),
    "k8s_node": ("k8s", "principal"),
    "k8s_cluster_admin": ("k8s", "entity"),
    "cloud_identity": ("k8s", "principal"),
}
ADMIN_KINDS = ("aws_account_admin", "gcp_scope_owner", "azure_scope_owner", "k8s_cluster_admin", "entra_role")

# selector key -> (providers, value kind, description). Value kinds: bool_true,
# string, string_or_list, namespace, action, role.
SELECTOR_KEYS = {
    "trust_allows_service": (("aws",), "string_or_list",
        "Role trust policy has an Allow for sts:AssumeRole* whose Principal.Service includes the value."),
    "trust_allows_principal_of_source": (("aws",), "bool_true",
        "Role trust policy allows the source principal ARN, the source account (root/ID) or '*'."),
    "has_instance_profile": (("aws",), "bool",
        "Role is in at least one instance profile (InstanceProfileList)."),
    "attached_to_service": (("aws", "gcp", "azure"), "string_or_list",
        "Identity is attached to a collected resource of that service (Lambda Role, EC2 instance profile, "
        "GCE/GKE service account, Azure resource identity). Uncollected services fall back to trust/all "
        "identities with unknown confidence."),
    "same_as_source": (PROVIDERS, "bool_true",
        "Target is the source itself (self-escalation); for entity kinds the source's own scope."),
    "resource_permission_covers_target": (PROVIDERS, "action",
        "The source must also hold this action on the target resource ({target.arn}/{target.email}/{target.scope}/{target.namespace})."),
    "gcp_actas_granted_on_target": (("gcp",), "bool_true",
        "Source holds iam.serviceAccounts.actAs on the target SA (SA policy or project/folder/org inheritance)."),
    "gcp_sa_in_scope_of_permission": (("gcp",), "bool_true",
        "Requirements with resource '*' must hold on the target SA's project (or the SA / an ancestor)."),
    "azure_identity_assignable_in_scope": (("azure",), "bool_true",
        "Requirements with scope '*' must hold on a scope that contains the identity's attached resource "
        "(or the user-assigned identity resource)."),
    "entra_role_assignable": (("azure",), "string_or_list",
        "Target is the named Entra directory role (display name, template ID or '*' for any)."),
    "k8s_sa_in_namespace": (("k8s",), "namespace",
        "Target service account namespace: '{source.namespace}', '*', or a literal namespace."),
    "k8s_node_hosting_pods_with_sa": (("k8s",), "bool_true",
        "Service account is mounted by a scheduled pod (k8s_service_account) or node hosts pods (k8s_node)."),
    "any_principal_in_scope": (("gcp", "azure", "k8s", "aws"), "bool_true",
        "Entity target covering every principal of the scope where the requirement holds (scope owner / cluster-admin / account admin)."),
}
SCOPES = ("same_account", "same_project", "inherited_scope", "same_namespace", "cluster", "tenant", "org", "any")
CONFIDENCES = ("derived", "conditional", "unknown")
SEVERITIES = ("critical", "high", "medium", "low", "info")
REQUIREMENT_FIELDS = {
    "aws": {"action", "resource", "notes"},
    "gcp": {"action", "permission", "resource", "notes"},
    "azure": {"action", "data_action", "scope", "entra_permission", "entra_role", "directory_scope", "notes"},
    "k8s": {"verb", "resource", "subresource", "api_group", "namespace", "resource_name", "notes"},
}
PLACEHOLDERS = {"target.arn", "target.email", "target.id", "target.scope", "target.namespace", "target.name",
                "target.account", "target.project", "source.account", "source.arn", "source.id", "source.email",
                "source.namespace", "source.name", "source.scope", "account", "project", "scope", "namespace"}
ENTRY_FIELDS = {"id", "provider", "service", "title", "source", "source_revision", "summary", "requires", "target",
                "conditions", "blockers", "confidence", "severity", "mitigation", "references", "notes"}
REQUIRED_FIELDS = ("id", "provider", "service", "title", "source", "summary", "requires", "target", "severity", "mitigation")
KNOWN_BLOCKERS = {"scp_or_boundary_deny", "scp_deny", "permission_boundary", "explicit_deny", "deny_policy",
                  "gcp_deny_policy", "azure_deny_assignment", "abac_condition"}
_ID = re.compile(r"^(aws|gcp|azure|k8s|entra)-[a-z0-9]+(?:-[a-z0-9]+)*$")
_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")
# Execution content is forbidden: entries describe preconditions, not steps.
_COMMANDS = re.compile(r"(^|\s)(aws|gcloud|az|kubectl|curl|wget|python3?|bash)\s+[a-z-]+\s+[a-z-]+", re.I)


class CatalogError(ValueError):
    pass


def _placeholders(value):
    return set(_PLACEHOLDER.findall(value)) if isinstance(value, str) else set()


def _validate_requirement(item, provider, where, errors):
    if not isinstance(item, dict):
        errors.append(f"{where}: requirement must be a mapping")
        return
    allowed = REQUIREMENT_FIELDS[provider]
    unknown = set(item) - allowed
    if unknown:
        errors.append(f"{where}: unknown requirement fields {sorted(unknown)}")
    if provider == "aws":
        if not isinstance(item.get("action"), str) or ":" not in item["action"]:
            errors.append(f"{where}: aws requirement needs action 'service:Action'")
        elif any(c in item["action"] for c in "*?"):
            errors.append(f"{where}: requirement action must be concrete (no wildcards)")
    elif provider == "gcp":
        permission = item.get("permission", item.get("action"))
        if not isinstance(permission, str) or permission.count(".") < 2 or "*" in permission:
            errors.append(f"{where}: gcp requirement needs a concrete permission 'service.resource.verb'")
    elif provider == "azure":
        kinds = [k for k in ("action", "entra_permission", "entra_role") if k in item]
        if len(kinds) != 1 or not isinstance(item[kinds[0]], str) or not item[kinds[0]]:
            errors.append(f"{where}: azure requirement needs exactly one of action/entra_permission/entra_role")
        if "data_action" in item and not isinstance(item["data_action"], bool):
            errors.append(f"{where}: data_action must be a boolean")
    elif provider == "k8s":
        if not isinstance(item.get("verb"), str) or not isinstance(item.get("resource"), str):
            errors.append(f"{where}: k8s requirement needs verb and resource")
        if "/" in str(item.get("resource", "")):
            errors.append(f"{where}: use subresource instead of resource 'a/b'")
    for key, value in item.items():
        if key == "notes":
            continue
        if not isinstance(value, (str, bool)):
            errors.append(f"{where}: field {key} must be a string or boolean")
        bad = _placeholders(value) - PLACEHOLDERS
        if bad:
            errors.append(f"{where}: unknown placeholders {sorted(bad)}")


def validate_entry(entry, *, expected_provider=None, hacktricks_root=None):
    """Return (errors, warnings) for one technique."""
    errors, warnings = [], []
    if not isinstance(entry, dict):
        return ["entry must be a mapping"], warnings
    ident = entry.get("id", "<missing id>")
    where = str(ident)
    for field in REQUIRED_FIELDS:
        if field not in entry:
            errors.append(f"{where}: missing field {field}")
    unknown = set(entry) - ENTRY_FIELDS
    if unknown:
        errors.append(f"{where}: unknown fields {sorted(unknown)}")
    if not isinstance(entry.get("id"), str) or not _ID.match(entry.get("id", "")):
        errors.append(f"{where}: id must be kebab-case and provider-prefixed")
    provider = entry.get("provider")
    if provider not in PROVIDERS:
        errors.append(f"{where}: provider must be one of {PROVIDERS}")
        return errors, warnings
    prefix = str(entry.get("id", "")).split("-", 1)[0]
    if prefix != provider and not (prefix == "entra" and provider == "azure"):
        errors.append(f"{where}: id prefix must match provider {provider}")
    if expected_provider and provider != expected_provider:
        errors.append(f"{where}: provider {provider} does not match catalog directory {expected_provider}")
    for field in ("service", "title", "summary", "mitigation", "source"):
        if field in entry and (not isinstance(entry[field], str) or not entry[field].strip()):
            errors.append(f"{where}: {field} must be a non-empty string")
    for field in ("title", "summary", "mitigation", "notes"):
        if isinstance(entry.get(field), str) and _COMMANDS.search(entry[field]):
            warnings.append(f"{where}: {field} looks like it contains a command; entries must not contain how-to steps")
    source = entry.get("source")
    if isinstance(source, str):
        if not source.startswith("src/"):
            errors.append(f"{where}: source must be a hacktricks-cloud path starting with src/")
        root = Path(hacktricks_root) if hacktricks_root else HACKTRICKS_CLOUD
        if root.is_dir() and not (root / source.split("#", 1)[0]).is_file():
            errors.append(f"{where}: source file not found in hacktricks-cloud: {source.split('#', 1)[0]}")
    requires = entry.get("requires")
    groups = 0
    if not isinstance(requires, dict) or set(requires) - {"all_of", "any_of"}:
        errors.append(f"{where}: requires must be a mapping with all_of/any_of")
    else:
        all_of = requires.get("all_of") or []
        any_of = requires.get("any_of") or []
        if not isinstance(all_of, list) or not isinstance(any_of, list):
            errors.append(f"{where}: all_of and any_of must be lists")
        else:
            for i, item in enumerate(all_of):
                _validate_requirement(item, provider, f"{where}.requires.all_of[{i}]", errors)
            for i, group in enumerate(any_of):
                if not isinstance(group, list) or not group:
                    errors.append(f"{where}: any_of[{i}] must be a non-empty list of requirements")
                    continue
                for j, item in enumerate(group):
                    _validate_requirement(item, provider, f"{where}.requires.any_of[{i}][{j}]", errors)
            groups = len(all_of) + len(any_of)
        if groups == 0:
            errors.append(f"{where}: at least one requirement is needed")
    target = entry.get("target")
    if not isinstance(target, dict):
        errors.append(f"{where}: target must be a mapping")
    else:
        unknown = set(target) - {"kind", "selector", "scope", "aggregate_as"}
        if unknown:
            errors.append(f"{where}: unknown target fields {sorted(unknown)}")
        kind = target.get("kind")
        if kind not in TARGET_KINDS:
            errors.append(f"{where}: unknown target kind {kind!r}")
        elif TARGET_KINDS[kind][0] != provider:
            errors.append(f"{where}: target kind {kind} is not a {provider} kind")
        selector = target.get("selector") or {}
        if not isinstance(selector, dict):
            errors.append(f"{where}: selector must be a mapping")
            selector = {}
        for key, value in selector.items():
            if key not in SELECTOR_KEYS:
                errors.append(f"{where}: unknown selector key {key!r}")
                continue
            providers, value_kind, _ = SELECTOR_KEYS[key]
            if provider not in providers:
                errors.append(f"{where}: selector {key} is not supported for {provider}")
            if value_kind == "bool_true" and value is not True:
                errors.append(f"{where}: selector {key} must be true")
            elif value_kind == "bool" and not isinstance(value, bool):
                errors.append(f"{where}: selector {key} must be a boolean")
            elif value_kind in ("string", "action", "namespace") and not isinstance(value, str):
                errors.append(f"{where}: selector {key} must be a string")
            elif value_kind == "string_or_list" and not (isinstance(value, str) or (
                    isinstance(value, list) and value and all(isinstance(x, str) for x in value))):
                errors.append(f"{where}: selector {key} must be a string or list of strings")
            bad = set().union(*(_placeholders(x) for x in (value if isinstance(value, list) else [value]))) - PLACEHOLDERS
            if bad:
                errors.append(f"{where}: selector {key} has unknown placeholders {sorted(bad)}")
        if target.get("scope", "any") not in SCOPES:
            errors.append(f"{where}: target scope must be one of {SCOPES}")
        if "aggregate_as" in target and not isinstance(target["aggregate_as"], str):
            errors.append(f"{where}: aggregate_as must be a string")
        if kind == "k8s_service_account" and isinstance(requires, dict):
            text = repr(requires) + repr(selector)
            if "{target.namespace}" not in text and "k8s_sa_in_namespace" not in selector and target.get("scope") != "same_namespace":
                warnings.append(f"{where}: k8s service-account target without a namespace restriction reaches every namespace")
    conditions = entry.get("conditions", [])
    if not isinstance(conditions, list):
        errors.append(f"{where}: conditions must be a list")
    else:
        for i, condition in enumerate(conditions):
            if isinstance(condition, str):
                continue
            if not isinstance(condition, dict) or not isinstance(condition.get("id"), str) or set(condition) - {"id", "description"}:
                errors.append(f"{where}: conditions[{i}] must be {{id, description}}")
    blockers = entry.get("blockers", [])
    if not isinstance(blockers, list) or any(not isinstance(x, (str, dict)) for x in blockers):
        errors.append(f"{where}: blockers must be a list of strings")
    for field, allowed in (("confidence", CONFIDENCES), ("severity", SEVERITIES)):
        if field in entry and entry[field] not in allowed:
            errors.append(f"{where}: {field} must be one of {allowed}")
    if "references" in entry and (not isinstance(entry["references"], list) or any(not isinstance(x, str) for x in entry["references"])):
        errors.append(f"{where}: references must be a list of URLs")
    if "notes" in entry and not isinstance(entry["notes"], str):
        errors.append(f"{where}: notes must be a string")
    return errors, warnings


def validate_excluded(items, where):
    errors = []
    if items is None:
        return errors
    if not isinstance(items, list):
        return [f"{where}: _excluded.yaml must be a list"]
    for i, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("source"), str) or not isinstance(item.get("reason"), str):
            errors.append(f"{where}[{i}]: excluded entries need source and reason strings")
    return errors


def catalog_files(catalog_dir=None):
    root = Path(catalog_dir) if catalog_dir else CATALOG_DIR
    return sorted(p for p in root.rglob("*.y*ml") if p.is_file())


def load_catalog(catalog_dir=None, *, strict=False, hacktricks_root=None):
    """Load every technique. Returns {entries, errors, warnings, files, excluded}.

    Invalid entries are dropped (never half-evaluated) and reported; strict mode
    raises CatalogError instead.
    """
    root = Path(catalog_dir) if catalog_dir else CATALOG_DIR
    entries, errors, warnings, files, excluded = [], [], [], [], 0
    seen = {}
    for path in catalog_files(root):
        rel = str(path.relative_to(root))
        provider = path.relative_to(root).parts[0] if len(path.relative_to(root).parts) > 1 else None
        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            errors.append(f"{rel}: YAML parse error: {str(exc).splitlines()[0]}")
            files.append({"file": rel, "entries": 0, "valid": 0})
            continue
        if path.name.startswith("_excluded"):
            errors.extend(validate_excluded(data, rel))
            excluded += len(data or [])
            files.append({"file": rel, "entries": 0, "excluded": len(data or [])})
            continue
        if data is None:
            data = []
        if not isinstance(data, list):
            errors.append(f"{rel}: catalog file must be a YAML list")
            continue
        valid = 0
        for index, entry in enumerate(data):
            entry_errors, entry_warnings = validate_entry(entry, expected_provider=provider if provider in PROVIDERS else None,
                                                          hacktricks_root=hacktricks_root)
            ident = entry.get("id") if isinstance(entry, dict) else None
            if ident in seen:
                entry_errors.append(f"{ident}: duplicate id (also in {seen[ident]})")
            elif ident:
                seen[ident] = rel
            errors.extend(f"{rel}[{index}] {e}" for e in entry_errors)
            warnings.extend(f"{rel}[{index}] {w}" for w in entry_warnings)
            if not entry_errors:
                item = dict(entry)
                item["_file"] = rel
                entries.append(item)
                valid += 1
        files.append({"file": rel, "entries": len(data), "valid": valid})
    if strict and errors:
        raise CatalogError("; ".join(errors[:20]))
    return {"entries": entries, "errors": errors, "warnings": warnings, "files": files, "excluded": excluded}
