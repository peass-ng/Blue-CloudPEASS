"""Read-only Kubernetes RBAC and service-account inventory analysis."""

from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import parse_qs, urlsplit


KINDS = {
    "clusterroles": False,
    "clusterrolebindings": False,
    "roles": True,
    "rolebindings": True,
    "serviceaccounts": True,
    "pods": True,
    "deployments": True,
    "daemonsets": True,
    "statefulsets": True,
    "jobs": True,
    "cronjobs": True,
    "secrets": True,
}
BROAD_SUBJECTS = {"system:authenticated", "system:serviceaccounts"}
CRITICAL_RESOURCES = {"secrets", "serviceaccounts/token", "pods/exec", "pods/attach", "pods/ephemeralcontainers", "nodes/proxy", "certificatesigningrequests/approval"}
WORKLOAD_IDENTITY_ANNOTATIONS = {"eks.amazonaws.com/role-arn", "iam.gke.io/gcp-service-account", "azure.workload.identity/client-id"}
RBAC_RESOURCES = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}
WORKLOAD_KINDS = ("pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs")
WORKLOAD_RESOURCE_GROUPS = {"pods": "core", "deployments": "apps", "daemonsets": "apps", "statefulsets": "apps", "jobs": "batch", "cronjobs": "batch"}
CLUSTER_SCOPED_RESOURCES = {
    "apiservices", "certificatesigningrequests", "clusterrolebindings", "clusterroles",
    "csidrivers", "csinodes", "customresourcedefinitions", "gatewayclasses",
    "ingressclasses", "mutatingadmissionpolicies", "mutatingwebhookconfigurations",
    "namespaces", "nodes", "persistentvolumes", "priorityclasses", "runtimeclasses",
    "storageclasses", "validatingadmissionpolicies", "validatingadmissionpolicybindings",
    "validatingwebhookconfigurations", "volumeattachments",
}
NAMESPACE_SCOPED_CLUSTER_ROLE_VERBS = {"bind"}


def _qualified_resource(name: str) -> str:
    resource, _, group = name.partition(".")
    return f"{group or 'core'}:{resource}"


def fetch_snapshot(kubectl: str = "kubectl", context: str | None = None) -> dict[str, Any]:
    """Fetch each kind separately so denied optional reads do not hide RBAC results."""
    prefix = [kubectl]
    if context:
        prefix += ["--context", context]
    if not context:
        proc = subprocess.run(prefix + ["config", "current-context"], capture_output=True, text=True)
        if proc.returncode:
            raise RuntimeError(proc.stderr.strip() or "Could not determine kubectl context")
        context = proc.stdout.strip()
        prefix += ["--context", context]
    snapshot: dict[str, Any] = {"context": context, "resources": {}, "errors": []}
    discovery: dict[str, list[str]] = {}
    for namespaced in (True, False):
        scope = "namespaced" if namespaced else "cluster_scoped"
        cmd = prefix + ["api-resources", f"--namespaced={'true' if namespaced else 'false'}", "-o", "name"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except OSError as exc:
            snapshot["errors"].append({"resource": f"api-resources/{scope}", "message": str(exc)})
            continue
        if proc.returncode:
            snapshot["errors"].append({"resource": f"api-resources/{scope}", "message": proc.stderr.strip() or "API discovery failed"})
            continue
        discovery[scope] = sorted({_qualified_resource(line.strip()) for line in proc.stdout.splitlines() if line.strip()})
    snapshot["discovery"] = discovery
    for kind, namespaced in KINDS.items():
        cmd = prefix + ["get", kind]
        if namespaced:
            cmd.append("--all-namespaces")
        if kind == "secrets":
            cmd.append("--field-selector=type=kubernetes.io/service-account-token")
        cmd += ["-o", "json", "--chunk-size=500"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except OSError as exc:
            snapshot["errors"].append({"resource": kind, "message": str(exc)})
            continue
        if proc.returncode:
            snapshot["errors"].append({"resource": kind, "message": proc.stderr.strip() or "kubectl get failed"})
            continue
        try:
            payload = json.loads(proc.stdout)
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise ValueError("expected a Kubernetes List with items")
            if kind == "secrets":
                for secret in payload["items"]:
                    if isinstance(secret, dict):
                        secret.pop("data", None)
                        secret.pop("stringData", None)
            snapshot["resources"][kind] = payload["items"]
        except (ValueError, TypeError) as exc:
            snapshot["errors"].append({"resource": kind, "message": f"Invalid JSON response: {exc}"})
    return snapshot


def _meta(item: dict) -> dict:
    return item.get("metadata") or {}


def _name(item: dict) -> str:
    return str(_meta(item).get("name") or "")


def _namespace(item: dict) -> str:
    return str(_meta(item).get("namespace") or "default")


def _subject(subject: dict, binding_namespace: str | None) -> tuple[str, str]:
    kind, name = subject.get("kind"), subject.get("name")
    if kind == "ServiceAccount":
        return "serviceaccount", f"{subject.get('namespace') or binding_namespace or 'default'}/{name}"
    if kind == "Group":
        return "group", str(name)
    return "user", str(name)


def _principal_id(kind: str, name: str) -> str:
    return f"{kind}:{name}"


def _permission(api_group: str, resource: str, verb: str, resource_names: tuple[str, ...] = ()) -> str:
    group = api_group or "core"
    suffix = f"[names={','.join(resource_names)}]" if resource_names else ""
    return f"{group}:{resource}:{verb}{suffix}"


def _permission_records(rules: list[dict]) -> list[dict]:
    records: dict[str, dict] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        verbs = rule.get("verbs") or []
        names = tuple(sorted(str(x) for x in rule.get("resourceNames") or []))
        for group in rule.get("apiGroups") or [""]:
            for resource in rule.get("resources") or []:
                for verb in verbs:
                    key = _permission(str(group), str(resource), str(verb), names)
                    records[key] = {"permission": key, "api_group": str(group), "resource": str(resource), "verb": str(verb), "resource_names": list(names)}
        for url in rule.get("nonResourceURLs") or []:
            for verb in verbs:
                key = _permission("nonResourceURL", str(url), str(verb))
                records[key] = {"permission": key, "api_group": "nonResourceURL", "resource": str(url), "verb": str(verb), "resource_names": []}
    return list(records.values())


def _rolebinding_grants(record: dict, discovery: dict) -> bool:
    """A RoleBinding cannot grant API paths or ordinary cluster-resource requests."""
    if record["api_group"] == "nonResourceURL":
        return False
    if record["verb"] in NAMESPACE_SCOPED_CLUSTER_ROLE_VERBS and record["resource"] == "clusterroles":
        return True
    resource = record["resource"].split("/", 1)[0]
    group = record["api_group"]
    if resource == "*":
        return True
    cluster_scoped = discovery.get("cluster_scoped") or set()
    namespaced = discovery.get("namespaced") or set()
    if cluster_scoped and namespaced:
        if group == "*":
            return not (any(item.endswith(f":{resource}") for item in cluster_scoped) and not any(item.endswith(f":{resource}") for item in namespaced))
        key = f"{group or 'core'}:{resource}"
        return key not in cluster_scoped or key in namespaced
    return resource not in CLUSTER_SCOPED_RESOURCES


def classify_permission(record: dict) -> tuple[str, str]:
    """Classify declared grants; wildcard grants are not expanded against discovery."""
    group = record["api_group"]
    resource = record["resource"]
    verb = record["verb"]
    if verb == "*" or resource == "*" or group == "*":
        return "critical", "Wildcard grant"
    if verb in {"escalate", "bind", "impersonate", "approve", "sign"}:
        return "critical", "Privilege boundary operation"
    if group == "nonResourceURL":
        return ("high", "Write access to API path") if verb not in {"get"} else ("low", "Read API path")
    if resource in CRITICAL_RESOURCES and verb in {"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}:
        return "critical", "Credential, execution, or node access"
    if resource in {"pods/portforward", "pods/proxy"} and verb in {"create", "get"}:
        return "high", "Access to workload network endpoint"
    if resource in RBAC_RESOURCES and verb in {"create", "update", "patch", "delete", "deletecollection"}:
        return "critical", "RBAC policy modification"
    if resource in {"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"} and verb in {"create", "update", "patch"}:
        return "high", "Workload modification"
    if resource in {"mutatingwebhookconfigurations", "validatingwebhookconfigurations", "customresourcedefinitions", "nodes", "namespaces", "serviceaccounts"} and verb in {"create", "update", "patch", "delete", "deletecollection"}:
        return "high", "Sensitive resource modification"
    if verb in {"create", "update", "patch", "delete", "deletecollection", "connect", "proxy"}:
        return "medium", "Write operation"
    return "low", "Read operation"


def _workload_spec(kind: str, item: dict) -> dict:
    spec = item.get("spec") or {}
    if kind in {"deployments", "daemonsets", "statefulsets", "jobs"}:
        return ((spec.get("template") or {}).get("spec") or {})
    if kind == "cronjobs":
        return (((((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")) or {})
    return spec


def read_audit_log(path: str):
    """Stream Kubernetes audit events from a JSON-lines audit log."""
    with open(path, encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError as exc:
                raise ValueError(f"Invalid audit JSON at line {line_number}: {exc}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"Audit line {line_number} must be a JSON object")
            yield event


def _audit_subject(username: str) -> str:
    if username.startswith("system:serviceaccount:"):
        parts = username.split(":", 3)
        if len(parts) == 4:
            return f"serviceaccount:{parts[2]}/{parts[3]}"
    return f"user:{username}"


def _audit_permission_matches(event: dict, record: dict) -> bool:
    verb = str(event.get("verb") or "")
    if record["verb"] not in {"*", verb}:
        return False
    obj = event.get("objectRef") or {}
    if record["api_group"] == "nonResourceURL":
        if obj.get("resource"):
            return False
        path = str(event.get("requestURI") or "").split("?", 1)[0]
        return fnmatchcase(path, record["resource"])
    if not obj.get("resource"):
        return False
    group = str(obj.get("apiGroup") or "")
    if record["api_group"] not in {"*", group}:
        return False
    resource = str(obj["resource"])
    if obj.get("subresource"):
        resource += "/" + str(obj["subresource"])
    if record["resource"] not in {"*", resource}:
        return False
    names = record.get("resource_names") or []
    if not names or obj.get("name") in names:
        return True
    if verb not in {"list", "watch"}:
        return False
    selectors = parse_qs(urlsplit(str(event.get("requestURI") or "")).query).get("fieldSelector") or []
    return any(
        part.split("=", 1)[1].lstrip("=") in names
        for selector in selectors
        for part in selector.split(",")
        if part.startswith("metadata.name=")
    )


def _audit_activity(effective: dict, events, min_unused_days: int) -> dict:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=min_unused_days)
    by_subject: dict[str, list[tuple[str, dict[str, dict]]]] = defaultdict(list)
    for (subject, scope), permissions in effective.items():
        by_subject[subject].append((scope, permissions))
    seen: dict[tuple[str, str, str], datetime] = {}
    considered = 0
    earliest = None
    latest = None
    for event in events:
        if event.get("stage") not in {None, "ResponseComplete"}:
            continue
        decision = (event.get("annotations") or {}).get("authorization.k8s.io/decision")
        status = (event.get("responseStatus") or {}).get("code")
        if decision != "allow" and not (isinstance(status, int) and 200 <= status < 400):
            continue
        raw_time = event.get("stageTimestamp") or event.get("requestReceivedTimestamp")
        try:
            timestamp = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00")).astimezone(timezone.utc)
        except (TypeError, ValueError):
            continue
        earliest = min(earliest, timestamp) if earliest else timestamp
        latest = max(latest, timestamp) if latest else timestamp
        if timestamp < cutoff or timestamp > now:
            continue
        considered += 1
        user = event.get("user") or {}
        subjects = {_audit_subject(str(user.get("username") or ""))}
        subjects.update(f"group:{group}" for group in user.get("groups") or [])
        namespace = (event.get("objectRef") or {}).get("namespace")
        for subject in subjects:
            for scope, permissions in by_subject.get(subject, []):
                if scope != "cluster" and scope != namespace:
                    continue
                for permission, record in permissions.items():
                    if _audit_permission_matches(event, record):
                        key = (subject, scope, permission)
                        seen[key] = max(seen.get(key, timestamp), timestamp)
    unobserved_permissions = []
    unobserved_principals = []
    for (subject, scope), permissions in effective.items():
        unobserved = sorted(permission for permission in permissions if (subject, scope, permission) not in seen)
        if unobserved:
            unobserved_permissions.append({"principal": subject, "scope": scope, "permissions": unobserved})
        if permissions and len(unobserved) == len(permissions):
            unobserved_principals.append({"principal": subject, "scope": scope})
    return {
        "permissions_not_observed": unobserved_permissions,
        "principals_not_observed": unobserved_principals,
        "coverage": {"events_considered": considered, "earliest_event": earliest.isoformat() if earliest else None, "latest_event": latest.isoformat() if latest else None, "window_days": min_unused_days, "window_start": cutoff.isoformat(), "source_complete": False},
    }


def analyze_snapshot(snapshot: dict[str, Any], risk_levels: set[str] | None = None, *, audit_events=None, min_unused_days: int = 90) -> dict[str, Any]:
    if min_unused_days < 1:
        raise ValueError("min_unused_days must be positive")
    risk_levels = risk_levels or {"high", "critical"}
    resources = snapshot.get("resources") or {}
    if not isinstance(resources, dict):
        raise ValueError("snapshot.resources must be an object")
    errors = list(snapshot.get("errors") or [])
    raw_discovery = snapshot.get("discovery") or {}
    discovery = {scope: set(raw_discovery.get(scope) or []) for scope in ("namespaced", "cluster_scoped")}
    missing = [kind for kind in KINDS if kind not in resources]
    roles: dict[tuple[str, str, str], dict] = {}
    for kind in ("roles", "clusterroles"):
        for role in resources.get(kind) or []:
            scope = _namespace(role) if kind == "roles" else "cluster"
            roles[(kind, scope, _name(role))] = role
    role_permissions = {key: _permission_records(role.get("rules") or []) for key, role in roles.items()}

    grants: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)
    bindings: list[dict] = []
    referenced_roles: set[tuple[str, str, str]] = set()
    broad_trusts: list[dict] = []
    dangling_bindings: list[dict] = []
    unresolved_bindings: list[dict] = []
    for kind in ("rolebindings", "clusterrolebindings"):
        for binding in resources.get(kind) or []:
            ns = _namespace(binding) if kind == "rolebindings" else "cluster"
            ref = binding.get("roleRef") or {}
            ref_kind = str(ref.get("kind") or "")
            ref_scope = ns if ref_kind == "Role" else "cluster"
            role_key = (ref_kind.lower() + "s", ref_scope, str(ref.get("name") or ""))
            role = roles.get(role_key) if ref_kind in {"Role", "ClusterRole"} and (kind != "clusterrolebindings" or ref_kind == "ClusterRole") else None
            binding_id = f"{kind}/{ns}/{_name(binding)}"
            subjects = []
            for raw_subject in binding.get("subjects") or []:
                subject_kind, subject_name = _subject(raw_subject, ns if kind == "rolebindings" else None)
                subject_id = _principal_id(subject_kind, subject_name)
                subjects.append(subject_id)
                is_public = (subject_kind == "user" and subject_name == "system:anonymous") or (subject_kind == "group" and subject_name == "system:unauthenticated")
                is_broad = subject_kind == "group" and (subject_name in BROAD_SUBJECTS or subject_name.startswith("system:serviceaccounts:"))
                if is_public or is_broad:
                    broad_trusts.append({"binding": binding_id, "subject": subject_id, "role": ref.get("name"), "scope": ns, "public": is_public})
                if role:
                    for record in role_permissions[role_key]:
                        if kind == "rolebindings" and not _rolebinding_grants(record, discovery):
                            continue
                        p = grants[(subject_id, ns)].setdefault(record["permission"], {**record, "sources": []})
                        p["sources"].append({"binding": binding_id, "role": f"{ref_kind}/{ref_scope}/{ref.get('name')}"})
            entry = {"binding": binding_id, "scope": ns, "role": f"{ref_kind}/{ref_scope}/{ref.get('name')}", "subjects": subjects, "resolved": bool(role)}
            bindings.append(entry)
            if role and subjects:
                referenced_roles.add(role_key)
            elif not role:
                if role_key[0] in resources:
                    dangling_bindings.append(entry)
                else:
                    unresolved_bindings.append(entry)

    accounts = {_namespace(sa) + "/" + _name(sa): sa for sa in resources.get("serviceaccounts") or []}
    workloads: list[dict] = []
    used_accounts: set[str] = set()
    for kind in WORKLOAD_KINDS:
        for item in resources.get(kind) or []:
            spec = _workload_spec(kind, item)
            account = f"{_namespace(item)}/{spec.get('serviceAccountName') or 'default'}"
            used_accounts.add(account)
            mount = spec.get("automountServiceAccountToken")
            if mount is None:
                mount = (accounts.get(account) or {}).get("automountServiceAccountToken")
            workloads.append({"kind": kind, "namespace": _namespace(item), "name": _name(item), "service_account": account, "token_mounted": mount is not False})

    # Kubernetes automatically adds these groups to service-account identities.
    effective: dict[tuple[str, str], dict[str, dict]] = {key: dict(value) for key, value in grants.items()}
    group_grants: dict[str, list[tuple[str, dict[str, dict]]]] = defaultdict(list)
    for (subject, scope), permissions in grants.items():
        if subject.startswith("group:"):
            group_grants[subject].append((scope, permissions))
    for account in accounts:
        namespace = account.split("/", 1)[0]
        identity = _principal_id("serviceaccount", account)
        groups = ("system:serviceaccounts", f"system:serviceaccounts:{namespace}", "system:authenticated")
        for group in groups:
            for scope, permissions in group_grants.get(_principal_id("group", group), []):
                for permission, record in permissions.items():
                    inherited = {**record, "sources": [{**source, "via_group": group} for source in record["sources"]]}
                    current = effective.setdefault((identity, scope), {}).setdefault(permission, {**inherited, "sources": []})
                    current["sources"].extend(inherited["sources"])

    # Anonymous requests belong to system:unauthenticated, when the API server allows them.
    for (subject, scope), permissions in grants.items():
        if subject == "group:system:unauthenticated":
            for permission, record in permissions.items():
                current = effective.setdefault(("user:system:anonymous", scope), {}).setdefault(permission, {**record, "sources": []})
                current["sources"].extend({**source, "via_group": "system:unauthenticated"} for source in record["sources"])

    principal_findings: list[dict] = []
    all_principals: list[dict] = []
    for (subject, scope), permissions in sorted(effective.items()):
        classified = []
        flagged: dict[str, list[str]] = {level: [] for level in ("critical", "high", "medium", "low")}
        for record in sorted(permissions.values(), key=lambda x: x["permission"]):
            level, reason = classify_permission(record)
            classified.append({**record, "risk": level, "reason": reason})
            if level in risk_levels:
                flagged[level].append(record["permission"])
        entry = {"principal": subject, "scope": scope, "permissions": classified, "flagged_permissions": {k: v for k, v in flagged.items() if v}}
        all_principals.append(entry)
        if entry["flagged_permissions"]:
            principal_findings.append(entry)

    unused_roles = []
    if "rolebindings" in resources and "clusterrolebindings" in resources:
        for key, role in sorted(roles.items()):
            if key in referenced_roles or not (role.get("rules") or []):
                continue
            if key[0] == "clusterroles" and (_name(role).startswith("system:") or (_meta(role).get("labels") or {}).get("kubernetes.io/bootstrapping") == "rbac-defaults"):
                continue
            unused_roles.append({"kind": key[0], "scope": key[1], "name": key[2]})

    token_secrets = []
    inactive_tokens = []
    invalid_tokens = []
    referenced_secrets = {
        (_namespace(sa), ref.get("name"))
        for sa in resources.get("serviceaccounts") or []
        for ref in sa.get("secrets") or []
        if isinstance(ref, dict)
    }
    today = datetime.now(timezone.utc).date()
    for secret in resources.get("secrets") or []:
        if secret.get("type") == "kubernetes.io/service-account-token":
            labels = _meta(secret).get("labels") or {}
            last_used = labels.get("kubernetes.io/legacy-token-last-used")
            invalid_since = labels.get("kubernetes.io/legacy-token-invalid-since")
            entry = {"namespace": _namespace(secret), "name": _name(secret), "service_account": (_meta(secret).get("annotations") or {}).get("kubernetes.io/service-account.name"), "created_at": _meta(secret).get("creationTimestamp"), "last_used": last_used, "invalid_since": invalid_since, "auto_generated": (_namespace(secret), _name(secret)) in referenced_secrets if "serviceaccounts" in resources else None}
            token_secrets.append(entry)
            if invalid_since:
                invalid_tokens.append(entry)
            if isinstance(last_used, str):
                try:
                    days_since = (today - date.fromisoformat(last_used)).days
                except ValueError:
                    continue
                if days_since >= min_unused_days:
                    inactive_tokens.append({**entry, "days_since_last_use": days_since})

    unused_accounts = sorted(account for account in accounts if account not in used_accounts) if all(kind in resources for kind in WORKLOAD_KINDS) else []
    risky_by_identity_scope: dict[tuple[str, str], set[str]] = {}
    for key, records in effective.items():
        risky_by_identity_scope[key] = {record["permission"] for record in records.values() if classify_permission(record)[0] in risk_levels}
    workload_risks = []
    for workload in workloads:
        identity = _principal_id("serviceaccount", workload["service_account"])
        risky = sorted(risky_by_identity_scope.get((identity, "cluster"), set()) | risky_by_identity_scope.get((identity, workload["namespace"]), set()))
        if risky:
            workload_risks.append({**workload, "flagged_permissions": risky})
    workload_creation_paths = []
    risky_accounts_by_namespace: dict[str, list[tuple[str, set[str]]]] = defaultdict(list)
    for account in accounts:
        namespace = account.split("/", 1)[0]
        identity = _principal_id("serviceaccount", account)
        target_rights = risky_by_identity_scope.get((identity, "cluster"), set()) | risky_by_identity_scope.get((identity, namespace), set())
        if target_rights:
            risky_accounts_by_namespace[namespace].append((account, target_rights))
    for (subject, scope), records in effective.items():
        creatable = sorted({
            resource
            for record in records.values()
            for resource, group in WORKLOAD_RESOURCE_GROUPS.items()
            if record["resource"] in {resource, "*"}
            and (record["api_group"] or "core") in {group, "*"}
            and record["verb"] in {"create", "*"}
            and not record["resource_names"]
        })
        if not creatable:
            continue
        namespaces = risky_accounts_by_namespace if scope == "cluster" else {scope: risky_accounts_by_namespace.get(scope, [])}
        for namespace, targets in namespaces.items():
            for account, target_rights in targets:
                workload_creation_paths.append({"principal": subject, "grant_scope": scope, "namespace": namespace, "service_account": account, "workload_resources": creatable, "service_account_flagged_permissions": sorted(target_rights)})
    identity_trusts = []
    for account, sa in accounts.items():
        annotations = _meta(sa).get("annotations") or {}
        for annotation in sorted(WORKLOAD_IDENTITY_ANNOTATIONS):
            if annotation in annotations:
                identity_trusts.append({"service_account": account, "annotation": annotation, "target": annotations[annotation]})
    role_definitions = []
    for (kind, scope, name), role in sorted(roles.items()):
        role_definitions.append({"kind": kind, "scope": scope, "name": name, "permissions": [{**record, "risk": classify_permission(record)[0]} for record in role_permissions[(kind, scope, name)]], "aggregation_rule": role.get("aggregationRule")})
    audit = _audit_activity(effective, audit_events, min_unused_days) if audit_events is not None else None
    return {
        "context": snapshot.get("context"),
        "inventory": {kind: len(resources.get(kind) or []) for kind in KINDS if kind in resources},
        "coverage": {"available": sorted(resources), "missing": missing, "api_discovery_available": bool(discovery["namespaced"] and discovery["cluster_scoped"]), "unused_permissions_available": False, "unused_roles_available": "rolebindings" in resources and "clusterrolebindings" in resources, "workload_references_available": all(kind in resources for kind in WORKLOAD_KINDS), "aggregated_roles_without_rules": [f"{r['scope']}/{r['name']}" for r in role_definitions if r["aggregation_rule"] and not r["permissions"]], "audit_activity": audit["coverage"] if audit else None, "reason": "Kubernetes RBAC does not provide permission last-used data. Supplied audit events show observed activity, not exhaustive proof of unused grants."},
        "principals": all_principals,
        "findings": {
            "principals_flagged": principal_findings,
            "unused_custom_definitions": unused_roles,
            "service_accounts_without_workloads": unused_accounts,
            "token_secrets": token_secrets,
            "inactive_token_secrets": inactive_tokens,
            "invalid_token_secrets": invalid_tokens,
            "external_trusts": broad_trusts,
            "workload_identity_trusts": identity_trusts,
            "workloads_with_flagged_service_accounts": workload_risks,
            "workload_creation_paths_to_flagged_service_accounts": workload_creation_paths,
            "dangling_bindings": dangling_bindings,
            "unresolved_bindings": unresolved_bindings,
            "permissions_not_observed": audit["permissions_not_observed"] if audit else [],
            "principals_not_observed": audit["principals_not_observed"] if audit else [],
        },
        "bindings": bindings,
        "role_definitions": role_definitions,
        "workloads": workloads,
        "errors": errors,
    }
